"""Unit tests for the pure parse/sign helpers in sitesentinel-agent.py.

Run from this directory:  python3 -m unittest test_agent -v
Fixtures mirror real `mmcli -J` output shapes (values-as-strings, "--" for
absent metrics).
"""

import hashlib
import hmac
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).parent / "sitesentinel-agent.py"
)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

MODEM_LIST = json.dumps({"modem-list": ["/org/freedesktop/ModemManager1/Modem/3"]})
MODEM_LIST_EMPTY = json.dumps({"modem-list": []})

MODEM_INFO_LTE = json.dumps(
    {
        "modem": {
            "3gpp": {
                "operator-code": "26202",
                "operator-name": "Vodafone.de",
                "registration-state": "home",
            },
            "generic": {"access-technologies": ["lte"], "state": "connected"},
        }
    }
)

MODEM_INFO_UNREGISTERED = json.dumps(
    {
        "modem": {
            "3gpp": {"operator-code": "--", "operator-name": "--"},
            "generic": {"access-technologies": [], "state": "searching"},
        }
    }
)

SIGNAL_LTE = json.dumps(
    {
        "modem": {
            "signal": {
                "5g": {"error-rate": "--", "rsrp": "--", "rsrq": "--", "snr": "--"},
                "lte": {
                    "error-rate": "--",
                    "rssi": "-67.00",
                    "rsrp": "-95.00",
                    "rsrq": "-11.00",
                    "snr": "9.50",
                },
                "refresh": {"rate": "10"},
            }
        }
    }
)

SIGNAL_5G = json.dumps(
    {
        "modem": {
            "signal": {
                "5g": {"rsrp": "-88.00", "rsrq": "-10.50", "snr": "14.00", "error-rate": "--"},
                "lte": {"rssi": "--", "rsrp": "--", "rsrq": "--", "snr": "--"},
                "refresh": {"rate": "10"},
            }
        }
    }
)

SIGNAL_ALL_DASHES = json.dumps(
    {
        "modem": {
            "signal": {
                "lte": {"rssi": "--", "rsrp": "--", "rsrq": "--", "snr": "--"},
                "refresh": {"rate": "10"},
            }
        }
    }
)


class TestParseModemList(unittest.TestCase):
    def test_first_path(self):
        self.assertEqual(agent.parse_modem_list(MODEM_LIST), "/org/freedesktop/ModemManager1/Modem/3")

    def test_empty(self):
        self.assertIsNone(agent.parse_modem_list(MODEM_LIST_EMPTY))

    def test_garbage(self):
        self.assertIsNone(agent.parse_modem_list("not json"))


class TestParseModem(unittest.TestCase):
    def test_lte_carrier(self):
        m = agent.parse_modem(MODEM_INFO_LTE)
        self.assertEqual(m["operator_name"], "Vodafone.de")
        self.assertEqual(m["mcc"], "262")
        self.assertEqual(m["mnc"], "02")
        self.assertEqual(m["access_tech"], "lte")

    def test_unregistered_all_none(self):
        m = agent.parse_modem(MODEM_INFO_UNREGISTERED)
        self.assertIsNone(m["operator_name"])
        self.assertIsNone(m["mcc"])
        self.assertIsNone(m["mnc"])
        self.assertIsNone(m["access_tech"])

    def test_garbage(self):
        self.assertEqual(
            agent.parse_modem("{"),
            {"operator_name": None, "mcc": None, "mnc": None, "access_tech": None},
        )


class TestParseSignal(unittest.TestCase):
    def test_lte(self):
        s = agent.parse_signal(SIGNAL_LTE)
        self.assertEqual(s["rssi_dbm"], -67)
        self.assertEqual(s["rsrp_dbm"], -95)
        self.assertEqual(s["rsrq_db"], -11.0)
        self.assertEqual(s["sinr_db"], 9.5)

    def test_5g_preferred_over_empty_lte(self):
        s = agent.parse_signal(SIGNAL_5G)
        self.assertEqual(s["rsrp_dbm"], -88)
        self.assertEqual(s["sinr_db"], 14.0)
        self.assertIsNone(s["rssi_dbm"])

    def test_all_dashes(self):
        s = agent.parse_signal(SIGNAL_ALL_DASHES)
        self.assertTrue(all(v is None for v in s.values()))

    def test_garbage(self):
        s = agent.parse_signal("nope")
        self.assertTrue(all(v is None for v in s.values()))


class TestSign(unittest.TestCase):
    def test_matches_reference_hmac(self):
        key, ts, body = "a" * 64, 1769300000, '{"cpu_temp_c":52.6}'
        expected = hmac.new(key.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
        self.assertEqual(agent.sign(key, ts, body), expected)

    def test_ts_is_part_of_message(self):
        self.assertNotEqual(agent.sign("k", 1, "b"), agent.sign("k", 2, "b"))


class TestFingerprint(unittest.TestCase):
    def test_is_sha256_of_key(self):
        key = "b" * 64
        self.assertEqual(agent.fingerprint(key), hashlib.sha256(key.encode()).hexdigest())
        self.assertRegex(agent.fingerprint(key), r"^[0-9a-f]{64}$")


class TestParsePing(unittest.TestCase):
    LINUX = (
        "PING example.com (93.184.216.34) 56(84) bytes of data.\n"
        "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
        "rtt min/avg/max/mdev = 12.318/15.612/20.107/3.221 ms\n"
    )

    def test_linux_output(self):
        p = agent.parse_ping(self.LINUX)
        self.assertEqual(p["avg_ms"], 15.612)
        self.assertEqual(p["loss_pct"], 0.0)

    def test_partial_loss(self):
        p = agent.parse_ping("3 packets transmitted, 1 received, 66.6% packet loss, time 2010ms\n")
        self.assertEqual(p["loss_pct"], 66.6)
        self.assertNotIn("avg_ms", p)

    def test_garbage(self):
        self.assertEqual(agent.parse_ping("Request timed out."), {})


class TestExecuteCommand(unittest.TestCase):
    def test_unsupported_type(self):
        results, err = agent.execute_command({"type": "traceroute", "domains": ["example.com"]})
        self.assertEqual(results, {})
        self.assertIn("unsupported", err)

    def test_empty_domains(self):
        results, err = agent.execute_command({"type": "dns", "domains": []})
        self.assertEqual(results, {})
        self.assertIsNone(err)

    def test_domains_normalized_and_capped(self):
        cmd = {"type": "dns", "domains": ["  ", ""]}
        results, err = agent.execute_command(cmd)
        self.assertEqual(results, {})  # blank entries skipped
        self.assertIsNone(err)


class TestUpdateProblem(unittest.TestCase):
    GOOD = {"version": "9.9.9", "url": "https://example.com/agent.py", "sha256": "c" * 64}

    def test_sound_offer_accepted(self):
        self.assertIsNone(agent.update_problem(self.GOOD, "0.1.0"))

    def test_same_version_refused(self):
        self.assertEqual(agent.update_problem(self.GOOD, "9.9.9"), "already on this version")

    def test_http_refused(self):
        offer = {**self.GOOD, "url": "http://example.com/agent.py"}
        self.assertIn("non-https", agent.update_problem(offer, "0.1.0"))

    def test_bad_sha_refused(self):
        self.assertIn("sha256", agent.update_problem({**self.GOOD, "sha256": "zz"}, "0.1.0"))
        self.assertIn("sha256", agent.update_problem({**self.GOOD, "sha256": ""}, "0.1.0"))

    def test_malformed_refused(self):
        self.assertIsNotNone(agent.update_problem(None, "0.1.0"))
        self.assertIsNotNone(agent.update_problem({}, "0.1.0"))

    def test_blocked_version_refused(self):
        self.assertIn("previously failed", agent.update_problem(self.GOOD, "0.1.0", blocked="9.9.9"))
        self.assertIsNone(agent.update_problem(self.GOOD, "0.1.0", blocked="8.8.8"))


class TestTrialRollback(unittest.TestCase):
    """commit_update / rollback_update against throwaway files (explicit target
    so the real agent source is never touched)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.target = self.dir / "agent.py"
        self.target.write_text("print('new version')")
        # Point the module's state paths into the sandbox.
        self._trial, self._blocked = agent.TRIAL_PATH, agent.BLOCKED_PATH
        agent.TRIAL_PATH = self.dir / "update_pending.json"
        agent.BLOCKED_PATH = self.dir / "update_blocked.json"

    def tearDown(self):
        agent.TRIAL_PATH, agent.BLOCKED_PATH = self._trial, self._blocked

    def test_rollback_restores_bak_and_blocks_version(self):
        (self.dir / "agent.py.bak").write_text("print('old version')")
        agent.write_json_atomic(agent.TRIAL_PATH, {"version": "9.9.9", "ts": 1})
        self.assertTrue(agent.rollback_update(self.target))
        self.assertEqual(self.target.read_text(), "print('old version')")
        self.assertFalse((self.dir / "agent.py.bak").exists())
        self.assertFalse(agent.TRIAL_PATH.exists())
        self.assertEqual(json.loads(agent.BLOCKED_PATH.read_text())["version"], "9.9.9")

    def test_rollback_without_bak_is_noop(self):
        agent.write_json_atomic(agent.TRIAL_PATH, {"version": "9.9.9", "ts": 1})
        self.assertFalse(agent.rollback_update(self.target))
        self.assertEqual(self.target.read_text(), "print('new version')")
        self.assertFalse(agent.TRIAL_PATH.exists())  # marker still cleared

    def test_commit_clears_marker_and_bak(self):
        (self.dir / "agent.py.bak").write_text("old")
        agent.write_json_atomic(agent.TRIAL_PATH, {"version": "9.9.9", "ts": 1})
        agent.commit_update(self.target)
        self.assertFalse((self.dir / "agent.py.bak").exists())
        self.assertFalse(agent.TRIAL_PATH.exists())
        self.assertEqual(self.target.read_text(), "print('new version')")

    def test_write_json_atomic_no_tmp_left(self):
        p = self.dir / "state.json"
        agent.write_json_atomic(p, {"a": 1})
        self.assertEqual(json.loads(p.read_text()), {"a": 1})
        self.assertEqual([f.name for f in self.dir.glob("*.tmp")], [])


if __name__ == "__main__":
    unittest.main()
