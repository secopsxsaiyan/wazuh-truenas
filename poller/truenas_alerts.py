#!/usr/bin/env python3
"""Poll the TrueNAS alert system and append NEW / RE-OCCURRED / CLEARED alerts as JSON lines for
the Wazuh manager (<localfile> log_format json -> rules 101454-101461 in truenas_rules.xml).

Why: pool scrub results, SMART test results, disk temperature, failed tasks, replication errors,
update notices etc. are raised by the TrueNAS alert system ("bell" icon) and often never appear in
syslog. This poller makes them Wazuh alerts.

How: JSON-RPC 2.0 over a websocket (`wss://<host>:<port>/api/current`, TrueNAS SCALE 25.04+):
`auth.login_with_api_key` -> `alert.list`. Each run is diffed against the previous run's state:
  new         alert uuid not seen before (the very first run baselines every open alert as new)
  reoccurred  same uuid, `last_occurrence` changed (not for one_shot alerts)
  cleared     uuid present last run, gone now
  poll_error  login/list failed (no secret is ever included in the message)

Configuration (environment variables override the config file; secrets NEVER on argv):
  TRUENAS_HOST              TrueNAS hostname or IP (required)
  TRUENAS_PORT              HTTPS port of the TrueNAS UI/API (default 443)
  TRUENAS_API_KEY           API key of a READ-ONLY TrueNAS user (required; prefer the config file)
  TRUENAS_API_PATH          websocket path (default /api/current)
  TRUENAS_VERIFY_TLS        true (default) | false. false disables certificate AND hostname checks
                            (self-signed UI cert) and prints a warning on every run. Prefer
                            TRUENAS_CA_FILE to trust a self-signed certificate instead.
  TRUENAS_CA_FILE           PEM CA bundle / self-signed cert to verify the TrueNAS cert against
  TRUENAS_ALERTS_OUT        output JSON-lines file the manager reads
                            (default /var/log/truenas-alerts.json)
  TRUENAS_ALERTS_STATE_DIR  where the previous-run state is kept
                            (default $XDG_STATE_HOME/truenas-alerts or ~/.local/state/truenas-alerts)
  TRUENAS_SKIP_KLASS        comma-separated, case-insensitive substrings of alert classes to drop
                            (default: none), e.g. "Certificate" if cert expiry is monitored elsewhere
  TRUENAS_TIMEOUT           socket timeout in seconds (default 20)

Config file: KEY=VALUE lines (# comments allowed). Path from --config PATH, else
$TRUENAS_ALERTS_CONFIG, else /etc/truenas-alerts.conf if it exists. The file must be owned by the
user running the poller and must not be readable by group/other (chmod 600), otherwise the poller
refuses to start.

stdlib only (no websocket module needed): minimal RFC 6455 client.
"""
import argparse
import base64
import json
import os
import socket
import ssl
import stat
import struct
import sys
import time

DEFAULT_CONFIG = "/etc/truenas-alerts.conf"
DEFAULT_OUT = "/var/log/truenas-alerts.json"
INTEGRATION = "truenas-alerts"
KEYS = ("TRUENAS_HOST", "TRUENAS_PORT", "TRUENAS_API_KEY", "TRUENAS_API_PATH", "TRUENAS_VERIFY_TLS",
        "TRUENAS_CA_FILE", "TRUENAS_ALERTS_OUT", "TRUENAS_ALERTS_STATE_DIR", "TRUENAS_SKIP_KLASS",
        "TRUENAS_TIMEOUT")


class ConfigError(Exception):
    pass


# ----------------------------------------------------------------------------------- config ----

def parse_config_text(text):
    """KEY=VALUE lines -> dict. Blank lines and # comments ignored; optional surrounding quotes."""
    d = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k.startswith("export "):
            k = k[len("export "):].strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        d[k] = v
    return d


def check_secret_file_mode(st_mode, st_uid, uid):
    """Raise ConfigError unless the file is owned by `uid` and has no group/other permissions."""
    if st_uid != uid:
        raise ConfigError("config file must be owned by the user running the poller")
    if stat.S_IMODE(st_mode) & 0o077:
        raise ConfigError("config file permissions too open (%04o); run: chmod 600 <file>"
                          % stat.S_IMODE(st_mode))


def read_config_file(path):
    st = os.stat(path)
    check_secret_file_mode(st.st_mode, st.st_uid, os.getuid())
    with open(path) as f:
        return parse_config_text(f.read())


def truthy(v, default=True):
    if v is None or str(v).strip() == "":
        return default
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise ConfigError("not a boolean: %r" % v)


def default_state_dir(environ):
    base = environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "truenas-alerts")


def build_settings(file_cfg, environ):
    """Merge config file + environment (env wins) into validated settings."""
    raw = {k: v for k, v in file_cfg.items() if k in KEYS}
    raw.update({k: environ[k] for k in KEYS if environ.get(k)})
    if not raw.get("TRUENAS_HOST"):
        raise ConfigError("TRUENAS_HOST is not set")
    if not raw.get("TRUENAS_API_KEY"):
        raise ConfigError("TRUENAS_API_KEY is not set")
    try:
        port = int(raw.get("TRUENAS_PORT") or 443)
        timeout = float(raw.get("TRUENAS_TIMEOUT") or 20)
    except ValueError as e:
        raise ConfigError("bad numeric setting: %s" % e)
    skip = tuple(s.strip().lower() for s in (raw.get("TRUENAS_SKIP_KLASS") or "").split(",") if s.strip())
    return {
        "host": raw["TRUENAS_HOST"],
        "port": port,
        "api_key": raw["TRUENAS_API_KEY"],
        "path": raw.get("TRUENAS_API_PATH") or "/api/current",
        "verify_tls": truthy(raw.get("TRUENAS_VERIFY_TLS"), True),
        "ca_file": raw.get("TRUENAS_CA_FILE") or None,
        "out": raw.get("TRUENAS_ALERTS_OUT") or DEFAULT_OUT,
        "state_dir": raw.get("TRUENAS_ALERTS_STATE_DIR") or default_state_dir(environ),
        "skip_klass": skip,
        "timeout": timeout,
    }


# ------------------------------------------------------------------------------ pure logic ----

def skipped(alert, skip_klass):
    k = (alert.get("klass") or "").lower()
    return any(s in k for s in skip_klass)


def alert_key(alert):
    u = alert.get("uuid") or alert.get("id")
    if u:
        return str(u)
    return "%s:%s" % (alert.get("klass"), json.dumps(alert.get("key"), sort_keys=True))


def ts(v):
    """TrueNAS returns datetimes as {"$date": <epoch ms>}; render ISO-8601 UTC."""
    if isinstance(v, dict) and "$date" in v:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(v["$date"] / 1000))
    return v


def build_event(alert, status):
    return {"integration": INTEGRATION, "truenas_alert": {
        "status": status, "uuid": alert.get("uuid"), "klass": alert.get("klass"),
        "source": alert.get("source"), "level": alert.get("level"), "node": alert.get("node"),
        "formatted": (alert.get("formatted") or "")[:2000], "dismissed": bool(alert.get("dismissed")),
        "datetime": ts(alert.get("datetime")), "last_occurrence": ts(alert.get("last_occurrence"))}}


def error_event(msg):
    return {"integration": INTEGRATION, "truenas_alert": {"status": "poll_error", "error": str(msg)[:300]}}


def diff_alerts(prev, alerts, skip_klass=()):
    """Compare the current alert.list result with the previous state.

    prev: dict from the last run ({key: {"last": <json>, "a": <alert>}}) or None on first run.
    Returns (events, new_state) where events is a list of (status, alert)."""
    events, cur = [], {}
    for a in alerts:
        if skipped(a, skip_klass):
            continue
        u = alert_key(a)
        cur[u] = {"last": json.dumps(a.get("last_occurrence"), sort_keys=True), "a": a}
        if prev is None or u not in prev:
            events.append(("new", a))
        elif prev[u].get("last") != cur[u]["last"] and not a.get("one_shot"):
            events.append(("reoccurred", a))
    for u, p in (prev or {}).items():
        if u not in cur:
            events.append(("cleared", p.get("a") or {}))
    return events, cur


def redact(msg, secret):
    msg = str(msg)
    return msg.replace(secret, "<redacted>") if secret else msg


# ------------------------------------------------------------------------------- websocket ----

def tls_context(verify, ca_file=None):
    if verify:
        return ssl.create_default_context(cafile=ca_file)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def encode_frame(data, mask, opcode=0x1):
    """Client->server frame (always masked, FIN set)."""
    h = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        h.append(0x80 | n)
    elif n < 65536:
        h.append(0x80 | 126)
        h += struct.pack(">H", n)
    else:
        h.append(0x80 | 127)
        h += struct.pack(">Q", n)
    h += mask
    return bytes(h) + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


class WS:
    def __init__(self, sock):
        self.s = sock

    @classmethod
    def connect(cls, host, port, path, ctx, timeout):
        raw = socket.create_connection((host, port), timeout=timeout)
        ws = cls(ctx.wrap_socket(raw, server_hostname=host))
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
        ws.s.sendall(req.encode())
        hdr = b""
        while b"\r\n\r\n" not in hdr:
            c = ws.s.recv(1)
            if not c:
                raise IOError("websocket handshake: connection closed")
            hdr += c
            if len(hdr) > 65536:
                raise IOError("websocket handshake: oversized response")
        status = hdr.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise IOError("websocket handshake failed: " + status.decode(errors="replace"))
        return ws

    def send(self, obj):
        self.s.sendall(encode_frame(json.dumps(obj).encode(), os.urandom(4)))

    def _read(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise IOError("websocket closed")
            b += c
        return b

    def recv(self):
        msg = b""
        while True:
            b1, b2 = self._read(2)
            op, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            if b2 & 0x80:                       # server frames should not be masked; tolerate
                m = self._read(4)
                payload = bytes(x ^ m[i % 4] for i, x in enumerate(self._read(n)))
            else:
                payload = self._read(n)
            if op == 0x9:                       # ping -> pong with the same payload
                self.s.sendall(encode_frame(payload, os.urandom(4), opcode=0xA))
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                raise IOError("websocket closed by server")
            msg += payload
            if b1 & 0x80:
                return json.loads(msg)

    def call(self, rid, method, params):
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while True:
            r = self.recv()
            if isinstance(r, dict) and r.get("id") == rid:
                if "error" in r:
                    err = r["error"]
                    raise IOError("%s: %s" % (method, err.get("message", err) if isinstance(err, dict) else err))
                return r.get("result")

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def fetch_alerts(cfg):
    ws = WS.connect(cfg["host"], cfg["port"], cfg["path"], tls_context(cfg["verify_tls"], cfg["ca_file"]),
                    cfg["timeout"])
    try:
        if not ws.call(1, "auth.login_with_api_key", [cfg["api_key"]]):
            raise IOError("auth.login_with_api_key returned false (wrong/revoked key?)")
        alerts = ws.call(2, "alert.list", [])
        if not isinstance(alerts, list):
            raise IOError("alert.list returned %s, expected a list" % type(alerts).__name__)
        return alerts
    finally:
        ws.close()


# ------------------------------------------------------------------------------------ main ----

def load_state(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None                             # first run: baseline everything as "new"


def save_state(path, state):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


def write_lines(path, events):
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")


def main(argv=None, environ=None, fetch=fetch_alerts):
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description="Poll TrueNAS alerts into a Wazuh JSON-lines feed. "
                                 "Secrets come from the environment or a mode-600 config file only.")
    ap.add_argument("--config", help="KEY=VALUE config file (default $TRUENAS_ALERTS_CONFIG or %s)"
                    % DEFAULT_CONFIG)
    args = ap.parse_args(argv)

    path = args.config or environ.get("TRUENAS_ALERTS_CONFIG")
    if not path and os.path.exists(DEFAULT_CONFIG):
        path = DEFAULT_CONFIG
    try:
        cfg = build_settings(read_config_file(path) if path else {}, environ)
    except (ConfigError, OSError) as e:
        print("config error: %s" % e, file=sys.stderr)
        return 2
    if not cfg["verify_tls"]:
        print("WARNING: TRUENAS_VERIFY_TLS=false - the TrueNAS certificate is NOT verified; the API "
              "key can be intercepted by anyone able to impersonate %s. Prefer TRUENAS_CA_FILE."
              % cfg["host"], file=sys.stderr)

    os.makedirs(cfg["state_dir"], mode=0o700, exist_ok=True)
    state_path = os.path.join(cfg["state_dir"], "truenas_alerts.state.json")
    prev = load_state(state_path)
    try:
        alerts = fetch(cfg)
    except Exception as e:                      # never include the key in output
        msg = redact(e, cfg["api_key"])
        write_lines(cfg["out"], [error_event(msg)])
        print("poll_error: %s" % msg[:300], file=sys.stderr)
        return 1
    events, cur = diff_alerts(prev, alerts, cfg["skip_klass"])
    write_lines(cfg["out"], [build_event(a, status) for status, a in events])
    save_state(state_path, cur)
    print("ok: %d alerts, %d after klass filter, %d events" % (len(alerts), len(cur), len(events)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
