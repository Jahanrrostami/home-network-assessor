import tempfile
import unittest
from pathlib import Path

from settings import ConfigError, load_config


class SettingsTests(unittest.TestCase):
    def test_shipped_config_loads_and_stays_private(self):
        cfg = load_config()
        self.assertEqual(cfg["networks"], [])
        self.assertIn(80, cfg["critical_ports"])
        self.assertIn(443, cfg["critical_ports"])
        self.assertIn(23, cfg["critical_ports"])
        self.assertNotIn("--script", cfg["nmap_args"])
        self.assertNotIn("-sC", cfg["nmap_args"])
        self.assertFalse(cfg["lookup_public_ip"])
        self.assertFalse(cfg["block_magic_packets"])
        self.assertGreaterEqual(cfg["missed_checks_before_offline"], 1)

    def test_public_network_and_scripts_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(
                "networks: ['8.8.8.8']\ncritical_ports: [80]\nnmap_args: '-sV --script vuln'\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_script_flag_is_rejected_on_its_own(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(
                "networks: ['192.168.1.0/24']\ncritical_ports: [80]\nnmap_args: '-sV -sC'\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_hand_written_script_on_a_private_network_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(
                "networks: ['192.168.1.0/24']\ncritical_ports: [80]\n"
                "nmap_args: '-sV --script vuln'\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("--script", str(caught.exception))

    def test_unknown_check_and_port_scan_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            check_path = folder / "check.yaml"
            check_path.write_text(
                "networks: ['192.168.1.0/24']\ncritical_ports: [80]\ncheck: exploit\n",
                encoding="utf-8",
            )
            range_path = folder / "range.yaml"
            range_path.write_text(
                "networks: ['192.168.1.0/24']\ncritical_ports: [80]\nport_scan: everything\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(check_path)
            with self.assertRaises(ConfigError):
                load_config(range_path)

    def test_monitor_discovery_line_cannot_be_changed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(
                "networks: ['192.168.1.0/24']\ncritical_ports: [80]\ndiscovery_args: '-sV -T3'\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("-sn -T3", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
