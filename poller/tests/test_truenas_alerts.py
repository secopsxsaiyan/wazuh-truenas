"""Unit tests for the pure logic of truenas_alerts.py. No network: fetch is stubbed.
Run from the repo root:  python3 -m unittest discover -s poller/tests -v"""
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import truenas_alerts as ta  # noqa: E402


def alert(uuid, klass="ZpoolCapacityWarning", level="WARNING", last=1000, **kw):
    a = {"uuid": uuid, "klass": klass, "level": level, "source": "", "node": "A",
         "formatted": "msg %s" % uuid, "dismissed": False,
         "datetime": {"$date": 1761400000000}, "last_occurrence": {"$date": last}}
    a.update(kw)
    return a


class DiffTests(unittest.TestCase):
    def test_first_run_baselines_all_as_new(self):
        ev, cur = ta.diff_alerts(None, [alert("a"), alert("b")])
        self.assertEqual([(s, a["uuid"]) for s, a in ev], [("new", "a"), ("new", "b")])
        self.assertEqual(set(cur), {"a", "b"})

    def test_unchanged_alert_emits_nothing(self):
        _, st = ta.diff_alerts(None, [alert("a")])
        ev, _ = ta.diff_alerts(st, [alert("a")])
        self.assertEqual(ev, [])

    def test_new_reoccurred_cleared(self):
        _, st = ta.diff_alerts(None, [alert("a"), alert("b")])
        ev, cur = ta.diff_alerts(st, [alert("a", last=2000), alert("c")])
        self.assertEqual(sorted((s, a["uuid"]) for s, a in ev),
                         [("cleared", "b"), ("new", "c"), ("reoccurred", "a")])
        self.assertEqual(set(cur), {"a", "c"})

    def test_one_shot_does_not_reoccur(self):
        _, st = ta.diff_alerts(None, [alert("a", one_shot=True)])
        ev, _ = ta.diff_alerts(st, [alert("a", last=5000, one_shot=True)])
        self.assertEqual(ev, [])

    def test_cleared_carries_previous_alert(self):
        _, st = ta.diff_alerts(None, [alert("a", klass="ScrubFailed", level="CRITICAL")])
        st = json.loads(json.dumps(st))          # state round-trips through JSON on disk
        ev, _ = ta.diff_alerts(st, [])
        self.assertEqual(ev[0][0], "cleared")
        e = ta.build_event(ev[0][1], "cleared")["truenas_alert"]
        self.assertEqual((e["klass"], e["level"]), ("ScrubFailed", "CRITICAL"))

    def test_klass_filter_case_insensitive_substring(self):
        alerts = [alert("a", klass="CertificateExpiring"), alert("b", klass="certificateIsExpired"),
                  alert("c", klass="SMART")]
        ev, cur = ta.diff_alerts(None, alerts, ("certificate",))
        self.assertEqual([a["uuid"] for _, a in ev], ["c"])
        self.assertEqual(set(cur), {"c"})

    def test_filtered_alert_previously_seen_is_cleared_once(self):
        _, st = ta.diff_alerts(None, [alert("a", klass="CertificateExpiring")])
        ev, _ = ta.diff_alerts(st, [alert("a", klass="CertificateExpiring")], ("certificate",))
        self.assertEqual([s for s, _ in ev], ["cleared"])

    def test_no_filter_by_default(self):
        ev, _ = ta.diff_alerts(None, [alert("a", klass="CertificateExpiring")])
        self.assertEqual(len(ev), 1)

    def test_key_fallback_without_uuid(self):
        a = alert(None, key={"pool": "tank"})
        self.assertEqual(ta.alert_key(a), 'ZpoolCapacityWarning:{"pool": "tank"}')
        ev, cur = ta.diff_alerts(None, [a])
        self.assertEqual(len(cur), 1)


class EventTests(unittest.TestCase):
    def test_build_event_shape_and_truncation(self):
        e = ta.build_event(alert("a", formatted="x" * 5000), "new")
        self.assertEqual(e["integration"], "truenas-alerts")
        t = e["truenas_alert"]
        self.assertEqual(t["status"], "new")
        self.assertEqual(len(t["formatted"]), 2000)
        self.assertEqual(t["datetime"], "2025-10-25T13:46:40Z")

    def test_ts_passthrough(self):
        self.assertIsNone(ta.ts(None))
        self.assertEqual(ta.ts("2025-01-01"), "2025-01-01")

    def test_error_event_and_redaction(self):
        msg = ta.redact("login failed for key 1-SECRETKEY", "1-SECRETKEY")
        self.assertNotIn("SECRETKEY", msg)
        e = ta.error_event("x" * 1000)["truenas_alert"]
        self.assertEqual((e["status"], len(e["error"])), ("poll_error", 300))


class ConfigTests(unittest.TestCase):
    def test_parse(self):
        d = ta.parse_config_text("# c\n\nTRUENAS_HOST = nas.example\nexport TRUENAS_API_KEY='k=v'\njunk\n")
        self.assertEqual(d, {"TRUENAS_HOST": "nas.example", "TRUENAS_API_KEY": "k=v"})

    def test_env_overrides_file_and_defaults(self):
        s = ta.build_settings({"TRUENAS_HOST": "a", "TRUENAS_API_KEY": "k", "TRUENAS_PORT": "4443"},
                              {"TRUENAS_HOST": "b", "HOME": "/h"})
        self.assertEqual((s["host"], s["port"], s["api_key"]), ("b", 4443, "k"))
        self.assertTrue(s["verify_tls"])
        self.assertEqual(s["out"], ta.DEFAULT_OUT)
        self.assertEqual(s["skip_klass"], ())
        self.assertEqual(s["path"], "/api/current")

    def test_verify_opt_out_and_skip_list(self):
        s = ta.build_settings({}, {"TRUENAS_HOST": "h", "TRUENAS_API_KEY": "k",
                                   "TRUENAS_VERIFY_TLS": "false", "TRUENAS_SKIP_KLASS": "Certificate, Foo ,"})
        self.assertFalse(s["verify_tls"])
        self.assertEqual(s["skip_klass"], ("certificate", "foo"))

    def test_missing_required(self):
        with self.assertRaises(ta.ConfigError):
            ta.build_settings({}, {"TRUENAS_HOST": "h"})
        with self.assertRaises(ta.ConfigError):
            ta.build_settings({}, {"TRUENAS_API_KEY": "k"})
        with self.assertRaises(ta.ConfigError):
            ta.build_settings({}, {"TRUENAS_HOST": "h", "TRUENAS_API_KEY": "k", "TRUENAS_VERIFY_TLS": "maybe"})

    def test_mode_check(self):
        ta.check_secret_file_mode(stat.S_IFREG | 0o600, 1000, 1000)
        with self.assertRaises(ta.ConfigError):
            ta.check_secret_file_mode(stat.S_IFREG | 0o640, 1000, 1000)
        with self.assertRaises(ta.ConfigError):
            ta.check_secret_file_mode(stat.S_IFREG | 0o600, 0, 1000)

    def test_tls_context(self):
        import ssl
        self.assertEqual(ta.tls_context(True).verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ta.tls_context(True).check_hostname)
        ctx = ta.tls_context(False)
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_NONE, False))


class FrameTests(unittest.TestCase):
    def test_encode_masked_lengths(self):
        m = b"\x01\x02\x03\x04"
        for n, hdr in ((5, 2), (200, 4), (70000, 10)):
            f = ta.encode_frame(b"a" * n, m)
            self.assertEqual(f[0], 0x81)
            self.assertTrue(f[1] & 0x80)
            self.assertEqual(len(f), hdr + 4 + n)

    def test_recv_fragmented_and_ping(self):
        class Sock:
            def __init__(self, data):
                self.data, self.sent = data, b""
            def recv(self, n):
                c, self.data = self.data[:n], self.data[n:]
                return c
            def sendall(self, b):
                self.sent += b
        body = json.dumps({"id": 2, "result": []}).encode()
        frames = bytes([0x89, 0x02]) + b"hi" + bytes([0x01, 5]) + body[:5] + bytes([0x80, len(body) - 5]) + body[5:]
        s = Sock(frames)
        ws = ta.WS(s)
        self.assertEqual(ws.call(2, "alert.list", []), [])
        self.assertEqual(s.sent[0], 0x81)                       # request frame first
        self.assertIn(bytes([0x8A, 0x82]), s.sent)              # masked pong echoing 2-byte ping


class MainTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "out.json")
        self.env = {"TRUENAS_HOST": "192.0.2.1", "TRUENAS_API_KEY": "1-SECRET",
                    "TRUENAS_ALERTS_OUT": self.out, "TRUENAS_ALERTS_STATE_DIR": os.path.join(self.d, "st"),
                    "TRUENAS_SKIP_KLASS": "certificate"}

    def lines(self):
        with open(self.out) as f:
            return [json.loads(l)["truenas_alert"] for l in f]

    def test_two_runs_with_stub(self):
        r1 = [alert("a"), alert("c", klass="CertificateExpired")]
        self.assertEqual(ta.main([], self.env, fetch=lambda cfg: r1), 0)
        self.assertEqual([(l["status"], l["uuid"]) for l in self.lines()], [("new", "a")])
        st = os.path.join(self.d, "st", "truenas_alerts.state.json")
        self.assertEqual(stat.S_IMODE(os.stat(st).st_mode), 0o600)
        self.assertEqual(ta.main([], self.env, fetch=lambda cfg: [alert("b")]), 0)
        self.assertEqual([(l["status"], l["uuid"]) for l in self.lines()][1:], [("new", "b"), ("cleared", "a")])

    def test_poll_error_never_leaks_key(self):
        def boom(cfg):
            raise IOError("auth failed for " + cfg["api_key"])
        self.assertEqual(ta.main([], self.env, fetch=boom), 1)
        l = self.lines()[0]
        self.assertEqual(l["status"], "poll_error")
        self.assertNotIn("SECRET", json.dumps(l))

    def test_config_file_mode_enforced(self):
        p = os.path.join(self.d, "c.conf")
        with open(p, "w") as f:
            f.write("TRUENAS_HOST=h\nTRUENAS_API_KEY=k\n")
        os.chmod(p, 0o644)
        env = {"TRUENAS_ALERTS_OUT": self.out, "TRUENAS_ALERTS_STATE_DIR": self.env["TRUENAS_ALERTS_STATE_DIR"]}
        self.assertEqual(ta.main(["--config", p], env, fetch=lambda cfg: []), 2)
        os.chmod(p, 0o600)
        self.assertEqual(ta.main(["--config", p], env, fetch=lambda cfg: []), 0)


if __name__ == "__main__":
    unittest.main()
