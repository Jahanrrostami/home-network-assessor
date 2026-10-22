import json
import unittest

from analyzer import PORT_RULES, analyze_hosts, load_hints


CRITICAL_PORTS = [21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 554, 1883]


def host(ip, ports):
    return {"ip": ip, "hostname": "box", "state": "up", "mac": None, "vendor": None, "open_ports": ports}


def port(number, name="", product="", version=""):
    return {"port": number, "proto": "tcp", "name": name, "product": product, "version": version, "extrainfo": ""}


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.hints = load_hints()

    def test_review_examples_keep_their_meaning(self):
        dangerous = host(
            "192.168.1.10",
            [
                port(23, "telnet"),
                port(445, "microsoft-ds"),
                port(80, "http", "Apache httpd", "2.4.49"),
                port(22, "ssh", "OpenSSH", "7.2p2"),
            ],
        )
        router = host(
            "192.168.1.1",
            [port(80, "http", "router"), port(443, "https")],
        )
        scored = {item["ip"]: item for item in analyze_hosts([dangerous, router], CRITICAL_PORTS, [], self.hints)}

        bad = scored["192.168.1.10"]
        self.assertEqual(bad["risk_level"], "CRITICAL")
        self.assertEqual(bad["risk_score"], 130)
        text = " ".join(item["text"] for item in bad["findings"])
        self.assertIn("CVE-2021-41773", text)
        self.assertIn("older than 8.0", text)
        self.assertIn("Telnet", text)
        self.assertIn("CRITICAL because", bad["level_reason"])
        self.assertIn("Cause:", bad["level_reason"])
        self.assertIn("Telnet", bad["level_reason"])

        home_router = scored["192.168.1.1"]
        self.assertEqual(home_router["risk_level"], "MEDIUM")
        self.assertEqual(home_router["risk_score"], 20)
        self.assertFalse(home_router["internet_exposed"])
        self.assertNotIn("CVE", " ".join(item["text"] for item in home_router["findings"]))
        self.assertIn("MEDIUM because the score is 20", home_router["level_reason"])
        self.assertIn("HTTP is open", home_router["level_reason"])
        self.assertIn("HTTPS is open", home_router["level_reason"])

    def test_builtin_telnet_survives_an_empty_review_list(self):
        scored = analyze_hosts([host("192.168.1.10", [port(23, "telnet")])], [], [], self.hints)
        self.assertEqual(scored[0]["risk_level"], "HIGH")
        self.assertEqual(scored[0]["risk_score"], PORT_RULES[23]["points"])

    def test_extra_review_port_is_optional(self):
        quiet = analyze_hosts([host("192.168.1.10", [port(8080, "http-proxy")])], [80], [], self.hints)
        self.assertEqual(quiet[0]["findings"], [])
        listed = analyze_hosts([host("192.168.1.10", [port(8080, "http-proxy")])], [8080], [], self.hints)
        self.assertEqual(listed[0]["risk_score"], 10)

    def test_apache_fix_version_and_tomcat_are_not_the_httpd_bug(self):
        fixed = analyze_hosts(
            [host("192.168.1.10", [port(80, "http", "Apache httpd", "2.4.51")])],
            [80],
            [],
            self.hints,
        )
        self.assertNotIn("CVE-2021", " ".join(item["text"] for item in fixed[0]["findings"]))
        tomcat = analyze_hosts(
            [host("192.168.1.10", [port(8080, "http", "Apache Tomcat", "2.4.49")])],
            [8080],
            [],
            self.hints,
        )
        self.assertNotIn("CVE-2021", " ".join(item["text"] for item in tomcat[0]["findings"]))

    def test_openssh_bands_do_not_stack(self):
        old = analyze_hosts([host("192.168.1.10", [port(22, "ssh", "OpenSSH", "8.4")])], [22], [], self.hints)
        texts = [item["text"] for item in old[0]["findings"] if item["source"] == "hint:openssh"]
        self.assertEqual(len(texts), 1)
        self.assertIn("older than 9.0", texts[0])
        self.assertNotIn("older than 8.0", texts[0])
        current = analyze_hosts([host("192.168.1.10", [port(22, "ssh", "OpenSSH", "9.6")])], [22], [], self.hints)
        self.assertFalse(any(item["source"] == "hint:openssh" for item in current[0]["findings"]))

    def test_forwarded_remote_desktop_is_critical_even_below_70(self):
        mapping = {
            "external_port": 3389,
            "protocol": "TCP",
            "internal_client": "192.168.1.20",
            "internal_port": 3389,
            "enabled": True,
            "description": "desktop",
        }
        scored = analyze_hosts([host("192.168.1.20", [port(3389, "ms-wbt-server")])], CRITICAL_PORTS, [mapping], self.hints)
        self.assertTrue(scored[0]["internet_exposed"])
        self.assertEqual(scored[0]["risk_level"], "CRITICAL")
        self.assertLess(scored[0]["risk_score"], 70)

    def test_disabled_forward_is_ignored(self):
        mapping = {
            "external_port": 3389,
            "protocol": "TCP",
            "internal_client": "192.168.1.20",
            "internal_port": 3389,
            "enabled": False,
            "description": "",
        }
        scored = analyze_hosts([host("192.168.1.20", [port(3389, "ms-wbt-server")])], [], [mapping], self.hints)
        self.assertFalse(scored[0]["internet_exposed"])
        self.assertEqual(scored[0]["risk_level"], "MEDIUM")

    def test_forward_to_an_unseen_host_is_still_reported(self):
        mapping = {
            "external_port": 3389,
            "protocol": "TCP",
            "internal_client": "192.168.1.40",
            "internal_port": 3389,
            "enabled": True,
            "description": "",
        }
        scored = analyze_hosts([], [], [mapping], self.hints)
        self.assertEqual(scored[0]["ip"], "192.168.1.40")
        self.assertEqual(scored[0]["state"], "unseen")
        self.assertEqual(scored[0]["risk_level"], "CRITICAL")
        self.assertIn("did not see that internal port", scored[0]["findings"][0]["text"])

    def test_exploit_script_text_is_reduced_to_the_name_and_port(self):
        raw = host("192.168.1.10", [])
        raw["ports"] = [
            {
                "port": 80,
                "proto": "tcp",
                "state": "open",
                "name": "http",
                "product": "Demo",
                "version": "1",
                "extrainfo": "",
                "scripts": [{"id": "demo-check", "output": "curl TOKEN123 payload"}],
            }
        ]
        raw["host_scripts"] = [{"id": "demo-host", "output": "GET /admin HTTP/1.1"}]
        scored = analyze_hosts([raw], [80], [], self.hints)
        texts = " ".join(item["text"] for item in scored[0]["findings"])
        self.assertIn("demo-check", texts)
        self.assertIn("80/tcp", texts)
        self.assertIn("Review the vendor advisory", texts)
        self.assertNotIn("TOKEN123", texts)
        self.assertNotIn("curl", texts)
        self.assertNotIn("GET /admin", texts)
        self.assertNotIn("payload", texts.lower())
        self.assertEqual(scored[0]["ports"][0]["scripts"], [])
        self.assertEqual(scored[0]["open_ports"][0]["scripts"], [])
        self.assertEqual(scored[0]["host_scripts"], [])
        stored = json.dumps(scored)
        self.assertNotIn("TOKEN123", stored)
        self.assertNotIn("GET /admin", stored)
        self.assertNotIn("curl", stored)
        self.assertIn("Cause:", scored[0]["level_reason"])
        self.assertIn("demo-check", scored[0]["level_reason"])
        self.assertNotIn("TOKEN123", scored[0]["level_reason"])
        self.assertNotIn("curl", scored[0]["level_reason"])

        quiet_level = analyze_hosts([host("192.168.1.12", [])], CRITICAL_PORTS, [], self.hints)[0]
        self.assertEqual(quiet_level["risk_level"], "LOW")
        self.assertEqual(quiet_level["risk_score"], 0)
        self.assertIn("added no points", quiet_level["level_reason"])
        self.assertIn("no vulnerability script reported a problem", quiet_level["level_reason"])
        self.assertIn("not proof the device is safe", quiet_level["level_reason"])

        quiet = host("192.168.1.11", [])
        quiet["ports"] = [
            {
                "port": 22,
                "proto": "tcp",
                "state": "open",
                "name": "ssh",
                "product": "",
                "version": "",
                "extrainfo": "",
                "scripts": [{"id": "demo-note", "output": "The vendor build looks old."}],
            }
        ]
        noted = analyze_hosts([quiet], [], [], self.hints)[0]
        note = " ".join(item["text"] for item in noted["findings"] if item["source"].startswith("script:"))
        self.assertIn("demo-note", note)
        self.assertIn("upgrade", note)
        self.assertIn("Review the vendor advisory", note)
        self.assertIn("vendor build looks old", note)

    def test_input_list_is_not_mutated(self):
        original = [host("192.168.1.10", [port(23, "telnet")])]
        analyze_hosts(original, [], [], self.hints)
        self.assertNotIn("risk_score", original[0])


if __name__ == "__main__":
    unittest.main()
