# TrueNAS SCALE → Wazuh: custom decoders, alert rules & dashboard

Custom Wazuh content that ingests **TrueNAS SCALE** security telemetry over syslog, classifies it
into Wazuh alerts (with MITRE ATT&CK tags and noise suppression), and ships a ready-made
**"TrueNAS Audit & Threats"** dashboard.

It decodes two TrueNAS syslog streams (forwarded by your TrueNAS host; the decoders use its syslog
hostname token, shown in examples as `true` — replace with yours), and optionally polls a third
source, the TrueNAS **alert system**:

1. **Middleware audit (`@cee:{"TNAUDIT":...}`)** — the TrueNAS audit framework: logins,
   authentication, privilege escalation, credential checks, and `METHOD_CALL` API actions
   (account/key/config/service/share/dataset/app/replication operations). Also carries sudo
   `@cee:{"sudo":...}` accept/reject records.
2. **General syslog** — `sshd-session` (real remote SSH logins/failures, with canonical
   `srcip`/`srcuser`), `smartd` / `zed` / `kernel` lines for ZFS & disk **storage health** (zed
   lines are decoded into class / pool / vdev fields), and `MIDDLEWARE` job failures
   (replication / snapshot / cloud-sync).
3. **Alert system (optional poller)** — `poller/truenas_alerts.py` reads `alert.list` over the
   TrueNAS API with a **read-only** API key and writes new / re-occurred / cleared alerts as JSON
   lines for Wazuh. This is where scrub results, SMART test results, disk temperature, failed
   tasks and similar alerts live; many of them never reach syslog.

> No agent. TrueNAS pushes syslog (RFC5424 over TCP/514); Wazuh decodes it. The poller is a small
> stdlib-only Python script run from cron on any host that can reach the TrueNAS API.

## Why TrueNAS needs its own decoders

TrueNAS sends RFC5424 with **octet-counting framing** and an **ISO-8601 timestamp**. Wazuh's
default pre-decoder can't parse that header, so `hostname`/`program_name` come back **empty** and
**the stock `sshd`/`sudo`/`smartd` decoders never match**. These decoders re-parse the raw line
(anchored on the `<octet> <PRI>1 <ts> true <app>` token sequence). Existing working content is
reused, not rebuilt: the stock generic error rule `1002` is chained off for storage errors, and
the original `truenas` / `truenas-tnaudit` decoders are unchanged; a dedicated `truenas-zed`
decoder is placed in front of the generic one only for ZFS event-daemon lines.

## Contents

```
custom_rules/
  truenas_decoders.xml   # @cee JSON (TNAUDIT + sudo) + sshd-session canonical srcip/srcuser + zed fields + general syslog app-name
  truenas_rules.xml      # classification + alerting rules (ID ranges below)
dashboards/
  gen_truenas_dashboard.py        # generator for the "TrueNAS Audit & Threats" dashboard (stdlib only)
  wazuh_truenas_dashboard.ndjson  # pre-generated saved-objects export (import this)
poller/
  truenas_alerts.py               # TrueNAS alert-system poller -> JSON lines (stdlib only)
  truenas-alerts.conf.example     # config template (copy, fill in, chmod 600)
  tests/test_truenas_alerts.py    # unit tests (no network): python3 -m unittest discover -s poller/tests
```

**Rule IDs used:** `100340–100359`, `100361`, `100363–100385`, `100395`, `101443`,
`101454–101461`, `101466`. Check for collisions with your existing custom rules before installing:

```bash
docker exec wazuh.manager sh -c "grep -rlE 'rule id=\"(1003(4[0-9]|5[0-9]|61|6[3-9]|7[0-9]|8[0-5]|95)|101443|10145[4-9]|10146[01]|101466)\"' \
  /var/ossec/etc/rules/ | grep -v '/truenas_rules.xml$'"   # expect no output
```
(Any file listed already uses one of these IDs — renumber one side.)

## Key facts ground-truthed from real data (1,194 audit events + general syslog)

- `event=GENERIC` is **97%** of the audit feed (internal middleware, all localhost) → suppressed to L0.
- `TNAUDIT.addr` is `127.0.0.1` for all but one event (middleware loopback self-view), so canonical
  `srcip` is mapped from the **SSH** stream (real routable IPs) where MISP/GeoIP correlation matters.
- `TNAUDIT.event_data` / `svc_data` are double-encoded JSON **strings** (NOT dotted fields) → rules
  regex-match the whole string (e.g. `"method":\s*"pool\.dataset\.delete"`).
- `METHOD_CALL` carries `{"method":"<api>", ...}`; `ESCALATION` carries the executed binary in
  `proctitle`; MIDDLEWARE auth carries the credential type in `"credentials"` (`UNIX_SOCKET` =
  internal/de-rated, `API_KEY`/`TOKEN` = elevated).

## Alert rules

`100340–100359` cover base events, GENERIC/kernel/container/cron suppression, CREDENTIAL,
ESCALATION, auth success/failure + brute force, logout (`100353`, L2), external credential
failures, and remote API calls. SSH, sudo, METHOD_CALL categories and storage health:

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100363 | 5 | SSH login accepted (canonical srcip/srcuser) | T1021.004 / T1078 |
| 100364 | 5 | SSH authentication failure | T1110.001 |
| 100365 | 10 | SSH brute force (5+ fails/120s, same source) | T1110.001/.003 |
| 100366 | 7 | sudo **rejected** | T1548.003 |
| 100367 | 5 | sudo accepted (privilege used) | T1548.003 |
| 100368 | 10 | sudo to **shell / destructive** command | T1548.003 / T1059.004 |
| 100370 | 8 | account / group lifecycle change | T1136 / T1098 |
| 100371 | 10 | **API key / token** create/modify/delete | T1098.001 / T1552.001 |
| 100372 | 8 | system / network / certificate config change | T1562.001 / T1553.004 |
| 100373 | 8 | service start/stop/update (defense impairment) | T1562.001 |
| 100374 | 10 | **DATA DESTRUCTION** — dataset/snapshot/pool delete (successful call) | T1485 / T1490 |
| 100395 | 8 | **failed** destructive call (attempt, not destruction) | T1485 / T1490 |
| 100375 | 8 | file-share change (SMB/NFS/iSCSI) | T1135 / T1039 |
| 100376 | 7 | app / container lifecycle change | T1610 |
| 100377 | 8 | replication / cloud-sync change (egress risk) | T1537 / T1020 |
| 100378 | 7 | boot environment / update / power state | T1542 / T1529 |
| 100379 | 2 | routine per-login escalation (`systemctl --user`, suppressed) | |
| 100380 | 10 | high-risk audit escalation to shell/destructive | T1548 / T1059.004 |
| 100381 | 2 | internal middleware socket auth (suppressed) | |
| 100382 | 6 | authentication via API key / token | T1078 / T1098.001 |
| 101466 | 3 | expected API-key login of the alert poller (pinned user **and** source IP — edit) | |

### Storage health & data protection

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100383 | 5 | storage health event (smartd/zed/zfs) | |
| 100344 | 3 | zed routine class (config_sync, history, scrub/resilver/trim start+finish, pool import) | |
| 100349 | 10 | zed vdev **checksum / io / data / deadman** error (pool, vdev in description) | |
| 100354 | 12 | ZFS error storm — 20+ of 100349 in 10 min | T1485 |
| 100384 | 10 | critical storage state (DEGRADED/FAULTED/OFFLINE/SMART failure, non-1002 path) | |
| 101443 | 12 | pool/vdev **FAULTED or UNAVAIL** (child of 100384) | T1485 |
| 100385 | 10 | storage / I-O error (smartd/zed/kernel, via stock 1002) | |
| 100361 | 8 | middlewared **replication / snapshot / cloud-sync job failed** (via stock 1002) | T1490 |
| 100369 | 4 | other middlewared error line (via stock 1002) | |

### TrueNAS alert system (poller, JSON feed)

| Rule | Level | Event |
|------|------|-------|
| 101454 | 3 | new / re-occurred alert, level INFO / NOTICE (base) |
| 101455 | 6 | alert level WARNING |
| 101456 | 8 | alert level ERROR |
| 101457 | 10 | alert level CRITICAL |
| 101458 | 12 | alert level ALERT / EMERGENCY |
| 101459 | 3 | alert cleared |
| 101460 | 7 | poller failed (login / API error / unreachable) |
| 101461 | 10 | poller failing for 30+ minutes (6 failures / hour) — alerts are blind |

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Single security events stay
below it; only frequency composites and near-zero-FP events (data destruction, API-key ops, SSH
brute force, shell escalation) reach the gate. Storage **failures** (vdev errors, DEGRADED/FAULTED
pools, SMART failures, CRITICAL TrueNAS alerts) also reach it: losing the pool or its recovery
points is an incident. Routine zed housekeeping is de-rated to L3.

A related rule lives in the companion **wazuh-threat-detection** pack: `101420` (TrueNAS
audit/syslog/alert configuration changed — SIEM blinding, T1562.006) chains off this pack's
`100345`. Install this pack first; without it `101420` is ignored by analysisd (warning only).
The dashboard's data-protection panel queries `101420` and simply shows nothing for it if that
pack is not installed.

**Forward-looking rules:** in a healthy box several rules had no positive sample yet (data
destruction, API-key ops, config/service/share/boot changes, storage health and zed errors, job
failures, SSH brute force).
Their decoder paths are validated with `wazuh-logtest` against synthetic lines; they fire when the
corresponding event first occurs.

## Canonical fields & MISP

The `truenas-sshd-*` decoders map real SSH source addresses to `srcip`/`srcuser`, so MISP IP-IOC
rules **100210/100211** auto-flag known-bad SSH sources and `same_source_ip` frequency rules work
(TNAUDIT `addr` is loopback-only, so it is intentionally **not**
mapped — and Wazuh won't add canonical fields to a JSON-plugin decoder anyway: a child decoder
suppresses the plugin, and combining `<regex>` + `<plugin_decoder>` is a config error.)

## Install / deploy

### 1. Forward TrueNAS syslog to the Wazuh manager
TrueNAS UI → **System Settings → Advanced → Syslog** → set the remote syslog server to
`<WAZUH MANAGER IP>` TCP/514, and enable **audit** export. Ensure the manager accepts syslog on
udp/514 + tcp/514 from your `<LAN CIDR>` (a `<remote><connection>syslog</connection></remote>`
block in the manager config).

### 2. Install the decoders and rules (Docker)
```bash
docker cp truenas_decoders.xml wazuh.manager:/var/ossec/etc/decoders/
docker cp truenas_rules.xml    wazuh.manager:/var/ossec/etc/rules/
docker exec wazuh.manager chown wazuh:wazuh \
  /var/ossec/etc/decoders/truenas_decoders.xml /var/ossec/etc/rules/truenas_rules.xml
docker exec wazuh.manager /var/ossec/bin/wazuh-analysisd -t   # expect no errors
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

### 3. (Optional) TrueNAS alert poller

Requires TrueNAS SCALE **25.04 or later** (JSON-RPC 2.0 websocket API at `/api/current`) and
Python 3.8+ on the host that runs it (stdlib only). The API key is only ever sent over TLS.

**a. Create a read-only account and API key on TrueNAS**
1. **Credentials → Users → Add**: username e.g. `wazuh-ro`, *Disable Password*, shell `nologin`,
   no home directory / SMB access needed.
2. **Credentials → Groups**: add the user to the built-in group that maps to the
   **READONLY_ADMIN** role (`truenas_readonly_administrators`). Do **not** use a full admin.
3. **Credentials → API Keys → Add**: name e.g. `wazuh-alert-poller`, user `wazuh-ro`. Copy the key
   (shown once). Revoke it there at any time.

**b. Install and configure the poller** (on the Wazuh manager host or any host whose output file
the manager can read):
```bash
sudo install -m 755 poller/truenas_alerts.py /usr/local/bin/truenas_alerts.py
sudo install -m 600 -o <POLLER USER> poller/truenas-alerts.conf.example /etc/truenas-alerts.conf
sudoedit /etc/truenas-alerts.conf       # TRUENAS_HOST, TRUENAS_API_KEY, TLS, TRUENAS_ALERTS_OUT
```
Settings can also come from environment variables of the same names (environment wins over the
file). Secrets are **never** accepted on the command line; the only option is `--config PATH`. The
poller refuses a config file that is not owned by its user or is readable by group/other.

**TLS:** certificate verification is **on** by default. TrueNAS ships a self-signed UI certificate:
either install a proper certificate, or export the UI certificate and set
`TRUENAS_CA_FILE=/path/to/truenas.pem` (its SAN must match `TRUENAS_HOST`). As a last resort
`TRUENAS_VERIFY_TLS=false` disables verification; the poller then prints a warning on every run,
and anyone able to impersonate the NAS on your network could capture the (read-only) key.

**c. Cron** (every 5 minutes; 101461 assumes this interval):
```cron
*/5 * * * *  /usr/bin/python3 /usr/local/bin/truenas_alerts.py --config /etc/truenas-alerts.conf >/dev/null 2>>/var/log/truenas-alerts.err
```
The first run baselines every currently open alert as `new`. State is kept in
`TRUENAS_ALERTS_STATE_DIR` (default `~/.local/state/truenas-alerts`). Rotate the output file with
logrotate `copytruncate` (Wazuh follows truncation).

**d. Tell the manager to read the feed** (`ossec.conf`, inside `<ossec_config>`; for the Docker
deployment bind-mount the file's directory into the manager container and use the in-container
path):
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/truenas-alerts.json</location>
</localfile>
```
Restart the manager. Events decode with the stock JSON decoder (`integration: truenas-alerts`,
fields `truenas_alert.{status,uuid,klass,level,formatted,source,node,datetime,last_occurrence}`).

**e. Pin the poller login de-rate:** every poll logs in with the API key, which `100382` reports
at L6 (288/day). Rule `101466` drops that to L3, but only for user `wazuh-ro` **from the poller
host's IP**. It ships pinned to the documentation address `192.0.2.10` (never matches), so edit
both `<field>` values in `101466` to your account name and `<POLLER HOST IP>`.

### 4. Import the dashboard
```bash
docker cp wazuh_truenas_dashboard.ndjson wazuh.dashboard:/tmp/
docker exec wazuh.dashboard curl -sk -u <ADMIN>:<INDEXER_PASSWORD> \
  -X POST "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@/tmp/wazuh_truenas_dashboard.ndjson
```
Regenerate after editing panels: `python3 gen_truenas_dashboard.py` (stdlib only).

## Notes & tuning

- **Validate decoders:** paste a sample into `wazuh-logtest`, e.g. a `@cee:{"TNAUDIT":...}` line or a
  `sshd-session ... Failed password for X from Y port N` line.
- **Brute-force thresholds** (`100365` 5/120s SSH, `100352` 6/180s middleware) are conservative;
  tune to your environment (3/30s if internal-only).
- **Storage health** is forward-looking and depends on TrueNAS forwarding `smartd`/`zed`/`kernel`
  syslog. Storage failures now page at L10/L12; lower `100349`/`100384`/`100385` to L9 if your
  triage queue should stay security-only. Extend the `100344` class list if other routine zed
  classes are noisy on your system.
- **Alert poller:** drop alert classes you monitor elsewhere with `TRUENAS_SKIP_KLASS`
  (comma-separated, case-insensitive substrings, e.g. `Certificate`). If you poll at a different
  interval, adjust the `frequency`/`timeframe` of `101461`.
- **Data-protection job failures** (`100361`) match middlewared lines mentioning
  zettarepl/replication/snapshot/cloud-sync/rsync/scrub that also contain a stock "bad word"
  (`error`, `failed`, ...). Lines without one stay at the generic middleware level.
- **Decoder gotchas** (verified on 4.14.5) are documented inline in `truenas_decoders.xml`: pcre2
  prematch needed for general syslog; a child decoder suppresses a parent's `plugin_decoder`;
  `event_data` is an opaque JSON string.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own
environment before relying on them.
