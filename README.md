# TrueNAS SCALE → Wazuh: custom decoders, alert rules & dashboard

Custom Wazuh content that ingests **TrueNAS SCALE** security telemetry over syslog, classifies it
into Wazuh alerts (with MITRE ATT&CK tags and noise suppression), and ships a ready-made
**"TrueNAS Audit & Threats"** dashboard.

It decodes two TrueNAS syslog streams (forwarded by your TrueNAS host; the decoders use its syslog
hostname token, shown in examples as `true` — replace with yours):

1. **Middleware audit (`@cee:{"TNAUDIT":...}`)** — the TrueNAS audit framework: logins,
   authentication, privilege escalation, credential checks, and `METHOD_CALL` API actions
   (account/key/config/service/share/dataset/app/replication operations). Also carries sudo
   `@cee:{"sudo":...}` accept/reject records.
2. **General syslog** — `sshd-session` (real remote SSH logins/failures, with canonical
   `srcip`/`srcuser`), plus `smartd` / `zed` / `kernel` lines for ZFS & disk **storage health**.

> No agent. TrueNAS pushes syslog (RFC5424 over TCP/514); Wazuh decodes it.

## Why TrueNAS needs its own decoders

TrueNAS sends RFC5424 with **octet-counting framing** and an **ISO-8601 timestamp**. Wazuh's
default pre-decoder can't parse that header, so `hostname`/`program_name` come back **empty** and
**the stock `sshd`/`sudo`/`smartd` decoders never match**. These decoders re-parse the raw line
(anchored on the `<octet> <PRI>1 <ts> true <app>` token sequence). Existing working content is
reused, not rebuilt: the stock generic error rule `1002` is chained off for storage errors, and
the original `truenas` / `truenas-tnaudit` decoders and rules `100340–100359` are unchanged.

## Contents

```
custom_rules/
  truenas_decoders.xml   # @cee JSON (TNAUDIT + sudo) + sshd-session canonical srcip/srcuser + general syslog app-name
  truenas_rules.xml      # classification + alerting rules (IDs 100340–100359 existing, 100363–100385 added)
dashboards/
  gen_truenas_dashboard.py        # generator for the "TrueNAS Audit & Threats" dashboard (stdlib only)
  wazuh_truenas_dashboard.ndjson  # pre-generated saved-objects export (import this)
```

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

Existing (unchanged) `100340–100359` cover base events, GENERIC/kernel/container/cron suppression,
CREDENTIAL, ESCALATION, auth success/failure + brute force, logout, external credential failures,
and remote API calls. Added 2026-06-08 (`100363–100385`):

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
| 100374 | 10 | **DATA DESTRUCTION** — dataset/snapshot/pool delete | T1485 / T1490 |
| 100375 | 8 | file-share change (SMB/NFS/iSCSI) | T1135 / T1039 |
| 100376 | 7 | app / container lifecycle change | T1610 |
| 100377 | 8 | replication / cloud-sync change (egress risk) | T1537 / T1020 |
| 100378 | 7 | boot environment / update / power state | T1542 / T1529 |
| 100379 | 2 | routine per-login escalation (`systemctl --user`, suppressed) | |
| 100380 | 10 | high-risk audit escalation to shell/destructive | T1548 / T1059.004 |
| 100381 | 2 | internal middleware socket auth (suppressed) | |
| 100382 | 6 | authentication via API key / token | T1078 / T1098.001 |
| 100383 | 5 | storage health (smartd/zed/zfs) | |
| 100384 | 9 | critical storage state (DEGRADED/FAULTED, non-1002 path) | |
| 100385 | 9 | storage / I-O error (smartd/zed/kernel, via stock 1002) | |

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Single events stay below it;
only frequency composites and near-zero-FP events (data destruction, API-key ops, SSH brute force,
shell escalation) reach the gate. Storage health is operational (L5/L9, below the gate — tunable).

**Forward-looking rules:** in a healthy box several rules had no positive sample yet (data
destruction, API-key ops, config/service/share/boot changes, storage health, SSH brute force).
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

### 3. Import the dashboard
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
  syslog. Raise `100384`/`100385` to L10 if you want pool failures to page security triage.
- **Decoder gotchas** (verified on 4.14.5) are documented inline in `truenas_decoders.xml`: pcre2
  prematch needed for general syslog; a child decoder suppresses a parent's `plugin_decoder`;
  `event_data` is an opaque JSON string.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own
environment before relying on them.
