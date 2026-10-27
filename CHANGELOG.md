# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-10-26

### Added
- `truenas-zed` decoder for ZFS event-daemon lines: extracts `truenas.zed_class`, `truenas.zed_eid`,
  `truenas.pool`, `truenas.vdev_path`, `truenas.vdev_state` (optional keys via sibling decoders).
- Storage rules on the new zed fields: `100344` routine zed classes (L3), `100349` vdev
  checksum/io/data/deadman error (L10), `100354` ZFS error storm (L12), `101443` pool/vdev
  FAULTED or UNAVAIL (L12).
- `100361` middlewared replication / snapshot / cloud-sync job failure (L8) and `100369` other
  middlewared errors (L4). Both chain off stock `1002`, which previously swallowed these lines at L2.
- `100395` failed destructive API call (dataset/snapshot/pool delete that did not succeed, L8).
- TrueNAS alert-system poller (`poller/truenas_alerts.py`, stdlib only): read-only API key from the
  environment or a mode-600 config file (never argv), TLS verification on by default with an
  optional CA file or explicit opt-out, configurable output/state paths and alert-class filter.
  Includes unit tests and a config template.
- Rules `101454–101461` for the poller feed: alert level mapping INFO/NOTICE L3, WARNING L6,
  ERROR L8, CRITICAL L10, ALERT/EMERGENCY L12; cleared L3; poller error L7; poller failing
  30+ minutes L10.
- `101466` de-rates the poller's own API-key login to L3, pinned to a user **and** source IP
  (ships with a documentation placeholder; edit before use).
- Dashboard: data-protection panel (job failures, destruction, failed destruction, replication
  changes, audit-config changes) and TrueNAS alert-system panel; storage panel includes the new
  zed rules; attack KPI includes `100352`.
- README: poller setup (read-only account, cron, `<localfile>` JSON snippet), ID ranges and a
  collision-check command.

### Changed
- `100374` DATA DESTRUCTION now requires `success=true`; a failed attempt fires `100395` instead.
- Storage failures reach the L10 triage gate: `100384` and `100385` L9 → L10.
- `100353` logout L3 → L2 (high volume, no standalone security value).
- `100383` / `100385` descriptions no longer embed `$(full_log)` (it is already in the alert).

### Versioning note
- Version 1.1.0 of this pack corresponds to the 1.2.0 release of the companion packs
  (wazuh-unifi, wazuh-proxmox); this pack had no previous 1.1.0.

## [1.0.0] — 2026-10-26

- Initial public release: TrueNAS SCALE syslog decoders (TNAUDIT/sudo `@cee` JSON, sshd-session,
  general syslog), classification rules (IDs 100340–100359, 100363–100385), and the
  "TrueNAS Audit & Threats" dashboard.
