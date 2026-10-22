import unittest

from presence import apply_scan, normalize_mac, plan_actions, update_presence


def seen(ip, mac=None, hostname=""):
    return {"ip": ip, "mac": mac, "hostname": hostname, "state": "up"}


class PresenceTests(unittest.TestCase):
    def test_mac_normalizes_unicast_only(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(normalize_mac("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(normalize_mac("01:00:00:00:00:00"))
        self.assertIsNone(normalize_mac("not-a-mac"))

    def test_offline_waits_for_the_threshold_and_fires_once(self):
        devices, events = update_presence({}, [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff")], 3, "t1")
        self.assertEqual([event["type"] for event in events], ["appeared"])
        for moment in ("t2", "t3"):
            devices, events = update_presence(devices, [], 3, moment)
            self.assertEqual(events, [])
            self.assertTrue(devices["mac:aa:bb:cc:dd:ee:ff"]["online"])
        devices, events = update_presence(devices, [], 3, "t4")
        self.assertEqual([event["type"] for event in events], ["offline"])
        devices, events = update_presence(devices, [], 3, "t5")
        self.assertEqual(events, [])
        devices, events = update_presence(devices, [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff")], 3, "t6")
        self.assertEqual([event["type"] for event in events], ["recovered"])
        self.assertEqual(devices["mac:aa:bb:cc:dd:ee:ff"]["misses"], 0)

    def test_dhcp_change_stays_one_device(self):
        devices, _events = update_presence({}, [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff")], 3, "t1")
        devices, events = update_presence(devices, [seen("192.168.1.60", "aa:bb:cc:dd:ee:ff")], 3, "t2")
        self.assertEqual(events, [])
        self.assertEqual(list(devices), ["mac:aa:bb:cc:dd:ee:ff"])
        self.assertEqual(devices["mac:aa:bb:cc:dd:ee:ff"]["ips"], ["192.168.1.50", "192.168.1.60"])

    def test_learning_a_mac_does_not_look_like_a_new_device(self):
        devices, _events = update_presence({}, [seen("192.168.1.50")], 3, "t1")
        devices, events = update_presence(devices, [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff")], 3, "t2")
        self.assertEqual(events, [])
        self.assertNotIn("ip:192.168.1.50", devices)
        self.assertIn("mac:aa:bb:cc:dd:ee:ff", devices)

    def test_empty_scan_does_not_move_counters(self):
        devices, _events = update_presence({}, [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff")], 3, "t1")
        again, events, status = apply_scan(devices, [], 3, "t2")
        self.assertEqual(status, "empty-scan-skipped")
        self.assertEqual(events, [])
        self.assertEqual(again["mac:aa:bb:cc:dd:ee:ff"]["misses"], 0)

    def test_a_remaining_host_still_counts_as_a_miss_for_the_other(self):
        devices, _events = update_presence(
            {},
            [seen("192.168.1.50", "aa:bb:cc:dd:ee:ff"), seen("192.168.1.1", "aa:bb:cc:dd:ee:01")],
            3,
            "t1",
        )
        devices, events, status = apply_scan(devices, [seen("192.168.1.1", "aa:bb:cc:dd:ee:01")], 3, "t2")
        self.assertEqual(status, "ok")
        self.assertEqual(events, [])
        self.assertEqual(devices["mac:aa:bb:cc:dd:ee:ff"]["misses"], 1)

    def test_actions_follow_the_config_switches(self):
        profile = {"desired_wol": "block"}

        def lookup(mac, ip):
            return profile if mac == "aa:bb:cc:dd:ee:ff" else None

        offline = {"type": "offline", "key": "mac:aa:bb:cc:dd:ee:ff", "ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "name": "pc", "misses": 3}
        quiet = plan_actions([offline], {"notify_on_offline": True, "block_magic_packets": False}, lookup)
        self.assertEqual([item["action"] for item in quiet], ["notify", "note"])
        loud = plan_actions([offline], {"notify_on_offline": True, "block_magic_packets": True}, lookup)
        self.assertEqual(loud[1]["action"], "block_hook")
        self.assertEqual(loud[1]["target"], "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
