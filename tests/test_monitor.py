import json
import tempfile
import unittest
from pathlib import Path

from monitor import monitor_loop
from profiles import load_profiles
from scanner import ScanError


class MonitorTests(unittest.TestCase):
    def test_example_profile_is_not_loaded(self):
        self.assertEqual(load_profiles(), {})

    def test_hook_runs_once_after_three_misses(self):
        cycles = [
            [{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "state": "up", "hostname": "pc"}],
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "state": "up", "hostname": "router"}],
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "state": "up", "hostname": "router"}],
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "state": "up", "hostname": "router"}],
        ]
        hooks = []

        def discover():
            return cycles.pop(0)

        def hook_runner(target):
            hooks.append(target)
            return f"hook {target}"

        def ssh_runner(profile, ip):
            return f"ssh-skipped {ip}"

        cfg = {
            "monitor_interval_seconds": 30,
            "missed_checks_before_offline": 3,
            "block_magic_packets": True,
            "notify_on_offline": True,
            "wol_block_list": [],
        }
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            monitor_loop(
                cfg,
                sleep=lambda seconds: None,
                discover=discover,
                profile_for=lambda mac, ip: {"desired_wol": "block"} if mac == "aa:bb:cc:dd:ee:ff" else None,
                state_file=state,
                cycle_limit=4,
                ssh_runner=ssh_runner,
                hook_runner=hook_runner,
                clock=lambda: "t",
            )
            saved = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(hooks, ["aa:bb:cc:dd:ee:ff"])
        self.assertFalse(saved["devices"]["mac:aa:bb:cc:dd:ee:ff"]["online"])

    def test_a_failed_scan_does_not_count_as_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "devices": {
                            "mac:aa:bb:cc:dd:ee:ff": {
                                "mac": "aa:bb:cc:dd:ee:ff",
                                "ips": ["192.168.1.50"],
                                "online": True,
                                "misses": 0,
                                "offline_alerted": False,
                                "last_seen": "t0",
                                "name": "pc",
                                "last_action": "",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            def discover():
                raise ScanError("nmap is missing")

            def boom(_seconds):
                raise AssertionError("sleep should not run when the cycle limit is already met")

            devices = monitor_loop(
                {
                    "monitor_interval_seconds": 30,
                    "missed_checks_before_offline": 3,
                    "block_magic_packets": False,
                    "notify_on_offline": True,
                    "wol_block_list": [],
                },
                sleep=boom,
                discover=discover,
                profile_for=lambda mac, ip: None,
                state_file=state,
                cycle_limit=1,
                clock=lambda: "t",
            )
        self.assertEqual(devices["mac:aa:bb:cc:dd:ee:ff"]["misses"], 0)
        self.assertTrue(devices["mac:aa:bb:cc:dd:ee:ff"]["online"])


if __name__ == "__main__":
    unittest.main()
