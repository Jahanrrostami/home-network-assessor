import json
import tempfile
import unittest
from pathlib import Path

from reporter import build_report, render_html, write_reports


class ReporterTests(unittest.TestCase):
    def test_html_escapes_device_text_and_blocks_scripts(self):
        report = build_report(
            [
                {
                    "ip": "192.168.1.10",
                    "hostname": "<script>alert(1)</script>",
                    "state": "up",
                    "mac": None,
                    "vendor": None,
                    "open_ports": [
                        {"port": 80, "proto": "tcp", "name": "<b>", "product": "x", "version": "1", "extrainfo": ""}
                    ],
                    "mappings": [],
                    "findings": [{"severity": "LOW", "points": 10, "source": "port:80", "text": "HTTP <is> open"}],
                    "risk_score": 10,
                    "risk_level": "MEDIUM",
                    "internet_exposed": False,
                }
            ],
            {"public_ip": None, "public_ip_note": "off", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.0/24"],
            "2026-10-16T00:00:00+00:00",
        )
        html = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("A quiet result is not proof", html)

    def test_writes_timestamped_and_latest_copies(self):
        report = build_report(
            [],
            {"public_ip": None, "public_ip_note": "off", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.0/24"],
            "2026-10-16T00:00:00+00:00",
        )
        with tempfile.TemporaryDirectory() as folder:
            paths = write_reports(report, Path(folder))
            self.assertTrue(paths["html"].is_file())
            self.assertEqual(paths["latest_html"].read_text(encoding="utf-8"), paths["html"].read_text(encoding="utf-8"))
            saved = json.loads(paths["latest_json"].read_text(encoding="utf-8"))
            self.assertEqual(saved["summary"]["hosts"], 0)
            self.assertIn("The scan saw no hosts", " ".join(saved["notes"]))

    def test_choice_line_and_named_port_sentences(self):
        report = build_report(
            [
                {
                    "ip": "192.168.1.9",
                    "hostname": "gw",
                    "state": "up",
                    "mac": None,
                    "vendor": None,
                    "ports": [
                        {"port": 53, "proto": "udp", "state": "filtered", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 443, "proto": "tcp", "state": "open", "name": "https", "product": "demo", "version": "1", "extrainfo": ""},
                        {"port": 443, "proto": "udp", "state": "closed", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 67, "proto": "udp", "state": "filtered", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 68, "proto": "udp", "state": "filtered", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 123, "proto": "udp", "state": "closed", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 500, "proto": "udp", "state": "filtered", "name": "", "product": "", "version": "", "extrainfo": ""},
                        {"port": 4500, "proto": "udp", "state": "filtered", "name": "", "product": "", "version": "", "extrainfo": ""},
                    ],
                    "findings": [],
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "internet_exposed": False,
                }
            ],
            {"public_ip": None, "public_ip_note": "UPnP was not part of this check.", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.0/24"],
            "2026-10-16T00:00:00+00:00",
            choices={
                "check": "services",
                "port_scan": None,
                "also_services": False,
                "line": "Check: DNS, QUIC, DHCP, NTP, and IPsec. Port scan: n/a. Also services: no",
            },
        )
        html = render_html(report)
        self.assertIn("Check: DNS, QUIC, DHCP, NTP, and IPsec. Port scan: n/a. Also services: no", html)
        self.assertIn("DNS. This is how computers on the LAN ask for names.", html)
        self.assertIn("QUIC / HTTP/3.", html)
        self.assertIn("HTTPS.", html)
        self.assertIn("DHCP server.", html)
        self.assertIn("DHCP client.", html)
        self.assertIn("NTP, the time service.", html)
        self.assertIn("IPsec VPN.", html)
        self.assertIn("This computer did not get a normal answer. That is not the same as safe.", html)
        self.assertIn("Closed from this computer. That is not the same as safe.", html)
        self.assertIn("A quiet result is not proof that a device is safe.", html)
        blob = json.dumps(report)
        self.assertNotIn("safe to ignore", blob)

    def test_address_check_lists_answers_without_port_scores(self):
        report = build_report(
            [
                {
                    "ip": "192.168.1.20",
                    "hostname": "phone",
                    "state": "up",
                    "mac": "aa:bb:cc:dd:ee:20",
                    "vendor": "Example",
                    "ports": [],
                    "findings": [],
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "internet_exposed": False,
                }
            ],
            {"public_ip": None, "public_ip_note": "UPnP was not part of this check.", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.0/24"],
            "2026-10-16T00:00:00+00:00",
            choices={
                "check": "addresses",
                "port_scan": None,
                "also_services": False,
                "line": "Check: IP addresses. Port scan: n/a. Also services: no",
            },
        )
        html = render_html(report)
        self.assertIn("Addresses that answered", html)
        self.assertIn("Online now", html)
        self.assertIn("Device history", html)
        self.assertIn("192.168.1.20", html)
        self.assertIn("phone", html)
        self.assertIn("aa:bb:cc:dd:ee:20", html)
        self.assertNotIn("No reviewed ports were open", html)
        self.assertNotIn("No port forwards were read", html)
        self.assertNotIn("LOW (0)", html)

    def test_router_check_keeps_only_the_router_result(self):
        report = build_report(
            [
                {
                    "ip": "192.168.1.1",
                    "hostname": "",
                    "state": "up",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "vendor": "Example Router",
                    "ports": [
                        {"port": 22, "proto": "tcp", "state": "filtered", "name": "ssh", "product": "", "version": "", "extrainfo": ""},
                        {"port": 80, "proto": "tcp", "state": "open", "name": "http", "product": "example-httpd", "version": "1.0", "extrainfo": ""},
                        {"port": 443, "proto": "tcp", "state": "open", "name": "http", "product": "example-httpd", "version": "1.0", "extrainfo": ""},
                    ],
                    "findings": [{"severity": "LOW", "points": 10, "source": "port:80", "text": "HTTP is open."}],
                    "risk_score": 20,
                    "risk_level": "MEDIUM",
                    "internet_exposed": False,
                }
            ],
            {
                "public_ip": None,
                "public_ip_note": "Public IP lookup is off. Set lookup_public_ip: true in config.yaml to enable it.",
                "devices": [],
                "mappings": [],
                "errors": [],
            },
            ["192.168.1.0/24"],
            "2026-10-16T00:00:00+00:00",
            choices={
                "check": "routers",
                "port_scan": None,
                "also_services": False,
                "line": "Check: routers. Port scan: n/a. Also services: no",
            },
        )
        html = render_html(report)
        self.assertIn("Router 192.168.1.1", html)
        self.assertIn("Example Router", html)
        self.assertIn("example-httpd", html)
        self.assertIn("1.0", html)
        self.assertIn("Did not answer: 22.", html)
        self.assertIn("No port forwards were read.", html)
        self.assertNotIn("Read this before the scores", html)
        self.assertNotIn("lookup_public_ip", html)
        self.assertNotIn("MEDIUM (20)", html)
        self.assertNotIn("not the same as safe", html)
        self.assertNotIn("Device history", html)

    def test_a_quiet_host_says_why_the_level_is_low(self):
        report = build_report(
            [
                {
                    "ip": "192.168.1.30",
                    "hostname": "console",
                    "state": "up",
                    "mac": "aa:bb:cc:dd:ee:30",
                    "vendor": "Example",
                    "ports": [
                        {"port": 22, "proto": "tcp", "state": "closed", "name": "ssh", "product": "", "version": "", "extrainfo": ""}
                    ],
                    "findings": [],
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "internet_exposed": False,
                }
            ],
            {"public_ip": None, "public_ip_note": "UPnP was not part of this check.", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.30"],
            "2026-10-20T12:00:00+00:00",
            choices={
                "check": "open-ports",
                "port_scan": "top10",
                "also_services": False,
                "line": "Check: open ports. Port scan: top 10. Also services: no",
            },
        )
        html = render_html(report)
        self.assertIn("LOW because this scan added no points", html)
        self.assertIn("no vulnerability script reported a problem", html)
        self.assertIn("not proof the device is safe", html)
        medium = build_report(
            [
                {
                    "ip": "192.168.1.1",
                    "hostname": "",
                    "state": "up",
                    "mac": None,
                    "vendor": None,
                    "findings": [{"severity": "LOW", "points": 10, "source": "port:80", "text": "HTTP is open. Confirm it."}],
                    "risk_score": 10,
                    "risk_level": "MEDIUM",
                    "internet_exposed": False,
                }
            ],
            {"public_ip": None, "public_ip_note": "off", "devices": [], "mappings": [], "errors": []},
            ["192.168.1.0/24"],
            "2026-10-20T12:00:00+00:00",
        )
        medium_html = render_html(medium)
        self.assertIn("MEDIUM because the score is 10", medium_html)
        self.assertIn("Cause: HTTP is open. Confirm it. (10 points)", medium_html)
        self.assertIn("10 points: HTTP is open. Confirm it.", medium_html)


if __name__ == "__main__":
    unittest.main()
