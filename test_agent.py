"""Unit tests for the pure parse/sign helpers in sitesentinel-agent.py.

Run from this directory:  python3 -m unittest test_agent -v
Fixtures mirror real `mmcli -J` output shapes (values-as-strings, "--" for
absent metrics).
"""

import hashlib
import hmac
import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
