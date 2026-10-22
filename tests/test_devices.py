"""Device history is built from hosts the program already saw. No probes."""

import json
import tempfile
import unittest
from pathlib import Path

from devices import load_roster, mark_offline, observe, remember, roster_view


def host(ip, mac=None, name="", vendor="Example"):
    return {"ip": ip, "mac": mac, "hostname": name, "vendor": vendor, "state": "up"}


class DeviceHistoryTests(unittest.TestCase):
    def test_a_later_check_does_not_drop_devices_the_address_check_saw(self):
        history = observe(
            {},
            [host("192.168.1.20", "aa:bb:cc:dd:ee:20", "phone"), host("192.168.1.21", "aa:bb:cc:dd:ee:21", "tv")],
            "t1",
            True,
        )
        history = observe(history, [host("192.168.1.21", "aa:bb:cc:dd:ee:21", "tv")], "t2", False)
        by_ip = {row["ip"]: row for row in roster_view(history)["history"]}
        self.assertEqual(by_ip["192.168.1.20"]["status"], "Online")
        self.assertEqual(by_ip["192.168.1.20"]["last_seen"], "t1")
        self.assertEqual(by_ip["192.168.1.21"]["status"], "Online")
        self.assertEqual(by_ip["192.168.1.21"]["last_seen"], "t2")

    def test_a_new_address_check_moves_a_missing_device_to_seen_before(self):
        history = observe(
            {},
            [host("192.168.1.20", "aa:bb:cc:dd:ee:20", "phone"), host("192.168.1.21", "aa:bb:cc:dd:ee:21", "tv")],
            "t1",
            True,
        )
        history = observe(history, [host("192.168.1.21", "aa:bb:cc:dd:ee:21", "tv")], "t2", True)
        view = roster_view(history)
        by_ip = {row["ip"]: row for row in view["history"]}
        self.assertEqual(view["last_census_at"], "t2")
        self.assertEqual(by_ip["192.168.1.20"]["status"], "Seen before")
        self.assertEqual(by_ip["192.168.1.21"]["status"], "Online")
        self.assertEqual([row["ip"] for row in view["online"]], ["192.168.1.21"])

    def test_an_empty_address_check_keeps_devices_that_were_online(self):
        history = observe({}, [host("192.168.1.20", "aa:bb:cc:dd:ee:20", "phone")], "t1", True)
        history = observe(history, [], "t2", True)
        self.assertTrue(history["empty_census_kept"])
        self.assertEqual(roster_view(history)["online"][0]["ip"], "192.168.1.20")

    def test_public_and_unseen_hosts_are_not_recorded(self):
        history = observe(
            {},
            [
                {"ip": "8.8.8.8", "state": "up", "hostname": "public"},
                {"ip": "192.168.1.40", "state": "unseen"},
                {"ip": "not-an-ip", "state": "up"},
            ],
            "t1",
            True,
        )
        self.assertEqual(history["devices"], {})

    def test_a_later_mac_replaces_the_ip_only_record(self):
        history = observe({}, [host("192.168.1.50", None, "pc")], "t1", True)
        history = observe(history, [host("192.168.1.50", "aa:bb:cc:dd:ee:ff", "pc")], "t2", False)
        self.assertEqual(list(history["devices"]), ["mac:aa:bb:cc:dd:ee:ff"])
        self.assertEqual(history["devices"]["mac:aa:bb:cc:dd:ee:ff"]["first_seen"], "t1")

    def test_saved_reports_fill_history_and_the_monitor_can_mark_one_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            payload = {
                "generated_at": "2026-01-01T00:00:00+00:00",
                "choices": {"check": "addresses"},
                "hosts": [
                    host("192.168.1.20", "aa:bb:cc:dd:ee:20", "phone"),
                    {"ip": "8.8.8.8", "state": "up", "hostname": "public"},
                ],
            }
            (path / "report_20260101_000000.json").write_text(json.dumps(payload), encoding="utf-8")
            view = load_roster(path)
            self.assertEqual([row["ip"] for row in view["online"]], ["192.168.1.20"])
            self.assertTrue((path / "devices.json").is_file())
            remembered = remember(
                [host("192.168.1.21", "aa:bb:cc:dd:ee:21", "tv")],
                "2026-01-02T00:00:00+00:00",
                False,
                path,
            )
            self.assertEqual({row["ip"] for row in remembered["online"]}, {"192.168.1.20", "192.168.1.21"})
            mark_offline(path, ["mac:aa:bb:cc:dd:ee:20"])
            after = load_roster(path)
            by_ip = {row["ip"]: row["status"] for row in after["history"]}
            self.assertEqual(by_ip["192.168.1.20"], "Seen before")
            self.assertEqual(by_ip["192.168.1.21"], "Online")
            self.assertNotIn("8.8.8.8", by_ip)


if __name__ == "__main__":
    unittest.main()
