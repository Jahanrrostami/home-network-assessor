import tempfile
import unittest
from pathlib import Path

from assessment import run_scan
from main import main
from scanner import scan_network


class AssessmentTests(unittest.TestCase):
    def test_scan_glues_forwards_into_the_score(self):
        def fake_scan(network, cfg, arguments=None):
            return {
                "hosts": [
                    {
                        "ip": "192.168.1.20",
                        "hostname": "pc",
                        "state": "up",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "vendor": None,
                        "open_ports": [{"port": 3389, "proto": "tcp", "name": "ms-wbt-server", "product": "", "version": "", "extrainfo": ""}],
                    }
                ]
            }

        def fake_exposure(cfg):
            return {
                "public_ip": None,
                "public_ip_note": "off",
                "devices": [],
                "errors": [],
                "mappings": [
                    {
                        "external_port": 3390,
                        "protocol": "TCP",
                        "internal_client": "192.168.1.20",
                        "internal_port": 3389,
                        "enabled": True,
                        "description": "desktop",
                    }
                ],
            }

        report = run_scan(
            {
                "networks": ["192.168.1.0/24"],
                "critical_ports": [3389],
                "check": "routers",
                "port_scan": None,
                "also_services": False,
            },
            scan=fake_scan,
            exposure=fake_exposure,
            gateway=lambda: "192.168.1.1",
        )
        self.assertEqual(report["hosts"][0]["risk_level"], "CRITICAL")
        self.assertEqual(report["summary"]["upnp_mappings"], 1)
        self.assertEqual(report["exposure"]["mappings"][0]["external_port"], 3390)

    def test_main_refuses_a_public_target_before_scanning(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text("networks: ['8.8.8.8']\ncritical_ports: [80]\n", encoding="utf-8")
            code = main(["scan", "--config", str(path)])
        self.assertEqual(code, 2)

    def test_direct_scan_refuses_a_public_target(self):
        from network_guard import GuardError

        with self.assertRaises(GuardError):
            scan_network("8.8.8.8", {"nmap_args": "-sV"})


if __name__ == "__main__":
    unittest.main()
