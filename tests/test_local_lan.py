"""The LAN comes from this computer's adapters. These tests send no packets."""

import tempfile
import unittest
from pathlib import Path

from local_lan import (
    choose_local_networks,
    parse_linux_adapters,
    parse_linux_routes,
    read_local_networks,
)
from main import main
from settings import ConfigError


HOME = [
    {"ip": "192.168.1.25", "prefix": 24, "alias": "Ethernet"},
    {"ip": "10.5.0.2", "prefix": 32, "alias": "NordLynx"},
    {"ip": "192.168.56.1", "prefix": 24, "alias": "VirtualBox Host-Only Network"},
    {"ip": "169.254.83.12", "prefix": 16, "alias": "Wi-Fi"},
    {"ip": "127.0.0.1", "prefix": 8, "alias": "Loopback Pseudo-Interface 1"},
]


class LocalLanTests(unittest.TestCase):
    def test_vpn_and_virtual_adapters_are_not_the_lan(self):
        found = choose_local_networks(
            HOME,
            [{"alias": "NordLynx", "gateway": "10.5.0.1"}],
        )
        self.assertEqual(found, ["192.168.1.0/24"])

    def test_the_default_route_wins_when_two_real_lans_exist(self):
        adapters = [
            {"ip": "192.168.1.25", "prefix": 24, "alias": "Ethernet"},
            {"ip": "192.168.50.20", "prefix": 24, "alias": "Wi-Fi", "gateway": "192.168.50.1"},
        ]
        routes = [{"alias": "Ethernet", "gateway": "192.168.1.1"}]
        self.assertEqual(choose_local_networks(adapters, routes), ["192.168.1.0/24"])

    def test_only_a_vpn_adapter_is_refused(self):
        with self.assertRaises(ConfigError) as caught:
            choose_local_networks(
                [{"ip": "10.5.0.2", "prefix": 16, "alias": "NordLynx"}],
                [{"alias": "NordLynx", "gateway": "10.5.0.1"}],
            )
        self.assertIn("No probes were sent", str(caught.exception))

    def test_a_public_adapter_is_ignored(self):
        with self.assertRaises(ConfigError):
            choose_local_networks([{"ip": "203.0.113.5", "prefix": 24, "alias": "Ethernet"}], [])

    def test_linux_text_selects_the_same_lan(self):
        adapters = parse_linux_adapters(
            "2: eth0: <BROADCAST,UP>\n"
            "    inet 192.168.1.25/24 brd 192.168.1.255 scope global eth0\n"
            "3: nordlynx: <POINTOPOINT,UP>\n"
            "    inet 10.5.0.2/32 scope global nordlynx\n"
        )
        routes = parse_linux_routes("default via 192.168.1.1 dev eth0\n")
        self.assertEqual(choose_local_networks(adapters, routes), ["192.168.1.0/24"])

    def test_a_configured_address_is_not_replaced(self):
        def explode():
            raise AssertionError("adapter lookup ran")

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text("networks: ['192.168.1.9']\ncritical_ports: [80]\n", encoding="utf-8")
            calls = []

            def scan(network, cfg, arguments=None):
                calls.append(network)
                return {"hosts": []}

            code = main(
                ["scan", "--config", str(path), "addresses"],
                output=lambda text: None,
                scan=scan,
                local_networks=explode,
                reports_dir=folder,
            )
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["192.168.1.9"])

    def test_no_local_lan_sends_no_probes(self):
        calls = []

        def scan(network, cfg, arguments=None):
            calls.append(network)
            return {"hosts": []}

        lines = []
        code = main(
            ["scan", "addresses"],
            output=lines.append,
            scan=scan,
            local_networks=lambda: (_ for _ in ()).throw(ConfigError("No private LAN was found. No probes were sent.")),
        )
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])
        self.assertIn("No probes were sent", "\n".join(lines))

    def test_reader_uses_the_supplied_payload(self):
        payload = {
            "adapters": HOME,
            "routes": {"alias": "Ethernet", "gateway": "192.168.1.1"},
        }
        self.assertEqual(read_local_networks(lambda: payload), ["192.168.1.0/24"])


if __name__ == "__main__":
    unittest.main()
