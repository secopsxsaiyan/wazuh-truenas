#!/usr/bin/env python3
"""Generate the 'TrueNAS Audit & Threats' dashboard NDJSON.

Mirrors gen_unifi_dashboard.py (same helpers / OSD 2.16 saved-object shapes). Scopes are keyed off
the TrueNAS rule IDs in truenas_rules.xml. Suppressed noise (L0-2: GENERIC 100346, kernel/container
100341/342, internal socket auth 100381, benign per-login escalation 100379) is excluded by the
`rule.level >= 3` master filter, so this board shows the security-relevant subset only.

NOTE on forward-looking panels: in a healthy box several rules have no positive sample yet (data
destruction 100374, API-key ops 100371, config/service/share/boot 100372-378, storage health
100383-385, SSH brute force 100365). Those panels populate when the corresponding event occurs;
the rule paths are validated with wazuh-logtest. SSH source IPs feed the canonical srcip, so the
GeoLocation panel populates once GeoIP is enabled and a routable SSH source appears."""
import json
ALERTS = "wazuh-alerts-*"
OSD = "2.16.0"
objects = []

def ss(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

def viz(vid, title, vistype, aggs, params, query=""):
    # Tables need bucket aggs with schema "bucket" to split rows; "segment"/"group"
    # (right for pie/xy) make a table show only the metric count. Force "bucket".
    if vistype == "table":
        for _a in aggs:
            if _a.get("type") in ("terms", "date_histogram", "histogram") \
                    and _a.get("schema") in ("segment", "group"):
                _a["schema"] = "bucket"
    objects.append({"id": vid, "type": "visualization", "attributes": {
        "title": title, "visState": json.dumps({"title": title, "type": vistype, "aggs": aggs, "params": params}),
        "uiStateJSON": "{}", "description": "", "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": ALERTS}]})
    return vid

def dash(did, title, panels, desc=""):
    pj, refs = [], []
    for i, v in enumerate(panels):
        pi = str(i)
        pj.append({"version": OSD, "gridData": {"x": (i % 2) * 24, "y": (i // 2) * 15, "w": 24, "h": 15, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": "panel_" + pi})
        refs.append({"name": "panel_" + pi, "type": "visualization", "id": v})
    objects.append({"id": did, "type": "dashboard", "attributes": {
        "title": title, "hits": 0, "description": desc, "panelsJSON": json.dumps(pj),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "version": 1, "timeRestore": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
        "references": refs})

def count(i="1"): return {"id": i, "enabled": True, "type": "count", "schema": "metric", "params": {}}
def terms(i, f, n=10, schema="segment"): return {"id": i, "enabled": True, "type": "terms", "schema": schema,
    "params": {"field": f, "orderBy": "1", "order": "desc", "size": n, "otherBucket": False,
               "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}}
def datehist(i): return {"id": i, "enabled": True, "type": "date_histogram", "schema": "segment",
    "params": {"field": "@timestamp", "useNormalizedEsInterval": True, "interval": "auto",
               "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}
def p_table(): return {"perPage": 12, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None}, "showTotal": True, "totalFunc": "sum", "percentageCol": ""}
def p_pie(): return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
def p_metric(sub): return {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
    "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
    "colorsRange": [{"from": 0, "to": 1000000}], "labels": {"show": True}, "invertColors": False,
    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": sub, "fontSize": 40}}}
def p_area():
    return {"type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
            "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
            "style": {}, "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "events"}}],
        "seriesParams": [{"show": True, "type": "area", "mode": "stacked", "data": {"label": "Count", "id": "1"},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True,
            "interpolate": "linear"}], "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {"show": False, "value": 10, "width": 1,
            "style": "full", "color": "#E7664C"}}

# ---- query scopes (rule IDs from truenas_rules.xml; data.* paths are the indexed alert fields) ----
SEC      = "rule.groups: truenas AND rule.level >= 3"        # master: security-relevant (excludes suppressed L0-2)
HIGH     = "rule.groups: truenas AND rule.level >= 7"        # notable + triage
ATTACK   = "rule.id:(100365 or 100358 or 100356 or 100380 or 100368 or 100374 or 100371)"  # high-confidence attack set
DESTRUCT = "rule.id:100374"
AUTHALL  = "rule.id:(100350 or 100359 or 100363 or 100382 or 100351 or 100357 or 100364)"
AUTHFAIL = "rule.id:(100351 or 100357 or 100364 or 100355)"
BRUTE    = "rule.id:(100352 or 100358 or 100365 or 100356 or 100351 or 100357 or 100364)"
SSH      = "rule.id:(100363 or 100364 or 100365)"
ESCAL    = "rule.id:(100348 or 100380 or 100366 or 100367 or 100368)"
ACCOUNT  = "rule.id:(100370 or 100371)"
CONFIG   = "rule.id:(100372 or 100373 or 100375 or 100378)"
EGRESS   = "rule.id:(100374 or 100377)"
APP      = "rule.id:100376"
STORAGE  = "rule.id:(100383 or 100384 or 100385)"

# Row 1 — headline KPIs
viz("tn-kpi-destruct", "Data destruction events (dataset/snapshot/pool delete)", "metric",
    [count("1")], p_metric("T1485/T1490 — near-zero FP"), query=DESTRUCT)
viz("tn-kpi-attacks", "High-confidence attack events", "metric",
    [count("1")], p_metric("brute force / priv-esc / destruction / API-key"), query=ATTACK)
# Row 2 — trend + event mix
viz("tn-timeline", "TrueNAS security events over time (by level)", "area",
    [count("1"), datehist("2"), terms("3", "rule.level", 6, schema="group")], p_area(), query=SEC)
viz("tn-eventtypes", "Audit event types", "pie",
    [count("1"), terms("2", "data.TNAUDIT.event", 10)], p_pie(), query=SEC)
# Row 3 — who (SSH source IPs + auth activity)
viz("tn-ssh-srcips", "SSH source IPs (canonical srcip — feeds MISP IOC + GeoIP)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=SSH)
viz("tn-auth", "Authentication activity (success / failure)", "table",
    [count("1"), terms("2", "rule.description", 12)], p_table(), query=AUTHALL)
# Row 4 — auth failures + privilege escalation
viz("tn-brute", "Auth failures & brute-force sources", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "data.srcuser", 1)], p_table(), query=BRUTE)
viz("tn-priv", "Privilege escalation (sudo + audit ESCALATION)", "table",
    [count("1"), terms("2", "rule.description", 12)], p_table(), query=ESCAL)
# Row 5 — account/credential + config
viz("tn-account", "Account / API-key / credential operations", "table",
    [count("1"), terms("2", "data.TNAUDIT.user", 10), terms("3", "rule.description", 4)], p_table(), query=ACCOUNT)
viz("tn-config", "Configuration & service changes (system / network / service / share / boot)", "table",
    [count("1"), terms("2", "rule.description", 10)], p_table(), query=CONFIG)
# Row 6 — destruction/egress + apps
viz("tn-egress", "Data destruction & replication / cloud-sync (egress risk)", "table",
    [count("1"), terms("2", "data.TNAUDIT.user", 10), terms("3", "rule.description", 4)], p_table(), query=EGRESS)
viz("tn-app", "Application / container lifecycle changes", "table",
    [count("1"), terms("2", "data.TNAUDIT.user", 10)], p_table(), query=APP)
# Row 7 — storage health + MITRE
viz("tn-storage", "Storage health — ZFS / SMART / disk (smartd, zed, kernel)", "table",
    [count("1"), terms("2", "rule.description", 8), terms("3", "rule.level", 3)], p_table(), query=STORAGE)
viz("tn-mitre", "MITRE ATT&CK techniques observed", "pie",
    [count("1"), terms("2", "rule.mitre.id", 15)], p_pie(), query=HIGH)
# Row 8 — recent high-severity table (full width feel; two halves)
viz("tn-high", "High-severity TrueNAS alerts (L>=7)", "table",
    [count("1"), terms("2", "rule.description", 15), terms("3", "rule.level", 1)], p_table(), query=HIGH)
viz("tn-high-users", "High-severity alerts by user", "table",
    [count("1"), terms("2", "data.TNAUDIT.user", 15)], p_table(), query=HIGH)

dash("truenas-audit-threats", "TrueNAS Audit & Threats",
     ["tn-kpi-destruct", "tn-kpi-attacks", "tn-timeline", "tn-eventtypes",
      "tn-ssh-srcips", "tn-auth", "tn-brute", "tn-priv",
      "tn-account", "tn-config", "tn-egress", "tn-app",
      "tn-storage", "tn-mitre", "tn-high", "tn-high-users"],
     "TrueNAS SCALE security from the middleware audit (TNAUDIT) + general syslog: authentication, "
     "privilege escalation (sudo/ESCALATION), account & API-key operations, config/service/share "
     "changes, dataset/snapshot/pool DESTRUCTION (ransomware/anti-recovery), replication egress, "
     "app/container changes, SSH (canonical srcip -> MISP IOC + GeoIP), and ZFS/SMART storage "
     "health. Suppressed noise (GENERIC, kernel/container churn, internal socket auth, routine "
     "per-login escalation) is excluded by the L>=3 filter. Several panels are forward-looking and "
     "populate when the event first occurs.")

with open("wazuh_truenas_dashboard.ndjson", "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print("wrote", len(objects), "objects (1 dashboard,", len(objects) - 1, "visualizations)")
