"""Fixed profiles, menus, and warnings. These tests send no packets."""

import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from pathlib import Path

from assessment import run_scan
from main import (
    ALSO_PROMPT,
    CHECK_MENU_LINES,
    CHECK_MENU_TITLE,
    DURATION_WARNING,
    RANGE_MENU_LINES,
    RANGE_MENU_TITLE,
    VULN_WARNING,
    main as program_main,
)


def main(*args, **kwargs):
    """The shipped config names no network. Tests supply the stand-in LAN."""
    kwargs.setdefault("local_networks", lambda: ["192.168.1.0/24"])
    return program_main(*args, **kwargs)
from network_guard import GuardError
from reporter import render_html
from scanner import (
    ADDRESSES_ARGUMENTS,
    FIREWALL_ARGUMENTS,
    MONITOR_ARGUMENTS,
    PORT_SCANS,
    ROUTERS_ARGUMENTS,
    SERVICES_ARGUMENTS,
    ScanError,
    allowed_arguments,
    argument_plan,
    discovery_arguments,
    merge_hosts,
    open_ports_arguments,
    parse_default_gateway,
    read_default_gateway,
    scan_network,
)


@contextmanager
def nmap_must_not_run():
    """Replace python-nmap so a regression cannot probe the LAN from a test."""
    sentinel = types.ModuleType("nmap")

    class PortScanner:
        def __init__(self, *args, **kwargs):
            raise AssertionError("nmap was invoked")

        def scan(self, *args, **kwargs):
            raise AssertionError("nmap was invoked")

    sentinel.PortScanner = PortScanner
    previous = sys.modules.get("nmap")
    sys.modules["nmap"] = sentinel
    try:
        yield
    finally:
        if previous is None:
            sys.modules.pop("nmap", None)
        else:
            sys.modules["nmap"] = previous


def scripted(lines):
    pending = iter(lines)
    prompts = []

    def ask(prompt=""):
        prompts.append(prompt)
        try:
            return next(pending)
        except StopIteration as exc:
            raise AssertionError(f"unexpected prompt: {prompt}") from exc

    return ask, prompts


def recording_scan(udp_empty=False):
    calls = []

    def scan(network, cfg, arguments=None):
        calls.append((network, arguments))
        if udp_empty and arguments == SERVICES_ARGUMENTS:
            return {"hosts": []}
        return {
            "hosts": [
                {
                    "ip": "192.168.1.9",
                    "hostname": "pc",
                    "state": "up",
                    "mac": None,
                    "vendor": None,
                    "ports": [
                        {
                            "port": 80,
                            "proto": "tcp",
                            "state": "open",
                            "name": "http",
                            "product": "demo",
                            "version": "1",
                            "extrainfo": "",
                        }
                    ],
                }
            ]
        }

    return scan, calls


def private_config(extra=""):
    return "networks: ['192.168.1.0/24']\ncritical_ports: [80, 443]\n" + extra


class ProfileTests(unittest.TestCase):
    def test_each_check_and_range_uses_its_fixed_arguments(self):
        self.assertEqual(argument_plan("addresses")[0]["arguments"], "-sn -T3")
        self.assertEqual(argument_plan("routers")[0]["arguments"], "-sV -p 22,23,80,443,8080,8443 -T3")
        self.assertEqual(
            argument_plan("services")[0]["arguments"],
            "-sV -sU -p T:53,443,U:53,67,68,123,443,500,4500 -T3",
        )
        self.assertEqual(argument_plan("addresses")[0]["arguments"], ADDRESSES_ARGUMENTS)
        self.assertEqual(argument_plan("routers")[0]["arguments"], ROUTERS_ARGUMENTS)
        self.assertEqual(argument_plan("routers")[0]["target"], "gateway")
        for name in PORT_SCANS:
            firewall = argument_plan("firewalls", name, False)[0]["arguments"]
            opened = argument_plan("open-ports", name, False)[0]["arguments"]
            self.assertEqual(firewall, FIREWALL_ARGUMENTS[name])
            self.assertEqual(opened, firewall + " --script vuln")
            self.assertNotIn("--script", firewall)
            self.assertNotIn("--open", firewall)
            self.assertNotIn("-sU", firewall)
        self.assertEqual(FIREWALL_ARGUMENTS["top10"], "-sV --top-ports 10 -T3")
        self.assertEqual(FIREWALL_ARGUMENTS["top100"], "-sV --top-ports 100 -T3")
        self.assertEqual(FIREWALL_ARGUMENTS["top1000"], "-sV --top-ports 1000 -T3")
        self.assertEqual(FIREWALL_ARGUMENTS["full"], "-sV -p- -T3")

        combined = [step["arguments"] for step in argument_plan("all", "top100", False)]
        self.assertEqual(
            combined,
            [
                ADDRESSES_ARGUMENTS,
                ROUTERS_ARGUMENTS,
                FIREWALL_ARGUMENTS["top100"],
                open_ports_arguments("top100"),
            ],
        )
        self.assertEqual(sum("--script vuln" in item for item in combined), 1)
        for quiet in (ADDRESSES_ARGUMENTS, ROUTERS_ARGUMENTS, SERVICES_ARGUMENTS, *FIREWALL_ARGUMENTS.values()):
            self.assertNotIn("--script", quiet)

    def test_also_services_with_top100_runs_both_profiles(self):
        opened = [step["arguments"] for step in argument_plan("open-ports", "top100", True)]
        self.assertEqual(opened, [open_ports_arguments("top100"), SERVICES_ARGUMENTS])
        walls = [step["arguments"] for step in argument_plan("firewalls", "top100", True)]
        self.assertEqual(walls, [FIREWALL_ARGUMENTS["top100"], SERVICES_ARGUMENTS])
        self.assertNotIn("--script", walls[0])
        whole = [step["arguments"] for step in argument_plan("all", "top100", True)]
        self.assertEqual(whole[-1], SERVICES_ARGUMENTS)
        self.assertIn("--script vuln", whole[-2])

    def test_services_profile_has_no_zone_transfer_or_dhcp_offer(self):
        text = SERVICES_ARGUMENTS.lower()
        self.assertEqual(text, "-sv -su -p t:53,443,u:53,67,68,123,443,500,4500 -t3")
        for banned in ("script", "axfr", "zone", "dhcp-discover", "offer", "ike", "--script-args"):
            self.assertNotIn(banned, text)
        for item in allowed_arguments():
            self.assertNotIn("--script-args", item)
            self.assertNotIn("-sC", item.split())
            self.assertNotIn("-A", item.split())
            self.assertNotIn("-iL", item.split())
            if "--script" in item:
                self.assertTrue(item.endswith("--script vuln"))
                self.assertEqual(item.count("--script"), 1)

    def test_unknown_check_or_range_is_refused_by_the_planner(self):
        with self.assertRaises(ScanError):
            argument_plan("exploit", "top100", False)
        with self.assertRaises(ScanError):
            argument_plan("firewalls", "everything", False)
        with self.assertRaises(ScanError):
            argument_plan("addresses", None, True)

    def test_public_target_is_refused_before_nmap(self):
        with nmap_must_not_run():
            with self.assertRaises(GuardError):
                scan_network("8.8.8.8", {}, arguments=open_ports_arguments("full"))
            with self.assertRaises(ScanError) as caught:
                scan_network(
                    "192.168.1.10",
                    {"nmap_args": "-sV --top-ports 100 -T3"},
                    arguments="-sV --script vuln -T3",
                )
        self.assertIn("fixed profiles", str(caught.exception))

    def test_config_nmap_args_are_not_what_gets_sent(self):
        with nmap_must_not_run():
            with self.assertRaises(ScanError) as caught:
                scan_network("192.168.1.10", {"nmap_args": "-sV --top-ports 100 -T3"}, arguments=None)
        self.assertIn("fixed profiles", str(caught.exception))

    def test_monitor_discovery_stays_a_ping_scan(self):
        self.assertEqual(MONITOR_ARGUMENTS, "-sn -T3")
        self.assertEqual(
            discovery_arguments({"discovery_args": "-sV --script vuln", "port_scan": "full", "check": "all"}),
            "-sn -T3",
        )

    def test_an_empty_udp_result_does_not_drop_the_host(self):
        scan, calls = recording_scan(udp_empty=True)
        report = run_scan(
            {
                "networks": ["192.168.1.0/24"],
                "critical_ports": [80],
                "check": "open-ports",
                "port_scan": "top100",
                "also_services": True,
            },
            scan=scan,
            exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
        )
        self.assertEqual([item[1] for item in calls], [open_ports_arguments("top100"), SERVICES_ARGUMENTS])
        self.assertEqual(report["hosts"][0]["ip"], "192.168.1.9")
        self.assertEqual(report["choices"]["line"], "Check: open ports. Port scan: top 100. Also services: yes")
        html = render_html(report)
        self.assertIn("DNS. This is how computers on the LAN ask for names.", html)
        self.assertIn("This computer did not get a normal answer. That is not the same as safe.", html)
        self.assertIn("demo", html)
        self.assertIn("1", html)
        self.assertEqual(merge_hosts([[{"ip": "192.168.1.8", "ports": [{"port": 22, "proto": "tcp", "state": "open"}]}], []])[0]["ip"], "192.168.1.8")

    def test_routers_reads_upnp_and_a_public_gateway_is_not_scanned(self):
        scan, calls = recording_scan()
        seen = []

        def exposure(cfg):
            seen.append(cfg["check"])
            return {"devices": [], "mappings": [], "errors": [], "public_ip": None, "public_ip_note": "read"}

        report = run_scan(
            {
                "networks": ["192.168.1.0/24"],
                "critical_ports": [80],
                "check": "routers",
                "also_services": False,
            },
            scan=scan,
            exposure=exposure,
            gateway=lambda: "192.168.1.1",
        )
        self.assertEqual(calls, [("192.168.1.1", ROUTERS_ARGUMENTS)])
        self.assertEqual(seen, ["routers"])
        self.assertEqual(report["public_ip_note"], "read")

        blocked = []

        def refuse(network, cfg, arguments=None):
            blocked.append(network)
            return {"hosts": []}

        with self.assertRaises(GuardError):
            run_scan(
                {
                    "networks": ["192.168.1.0/24"],
                    "critical_ports": [80],
                    "check": "routers",
                },
                scan=refuse,
                gateway=lambda: "8.8.8.8",
            )
        self.assertEqual(blocked, [])

    def test_firewall_check_does_not_read_upnp(self):
        scan, calls = recording_scan()
        report = run_scan(
            {
                "networks": ["192.168.1.0/24"],
                "critical_ports": [80],
                "check": "firewalls",
                "port_scan": "top10",
                "also_services": False,
            },
            scan=scan,
            exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
        )
        self.assertEqual(calls, [("192.168.1.0/24", FIREWALL_ARGUMENTS["top10"])])
        self.assertEqual(report["public_ip_note"], "UPnP was not part of this check.")
        self.assertIn("Check: firewalls. Port scan: top 10. Also services: no", report["choices"]["line"])

    def test_gateway_text_is_parsed_without_asking_the_operating_system(self):
        self.assertEqual(parse_default_gateway("default via 192.168.1.1 dev eth0"), "192.168.1.1")
        self.assertEqual(
            parse_default_gateway("0.0.0.0 0.0.0.0 192.168.0.1 192.168.0.5"),
            "192.168.0.1",
        )
        self.assertEqual(read_default_gateway(runner=lambda: "default via 192.168.1.1 dev eth0"), "192.168.1.1")
        with self.assertRaises(GuardError):
            read_default_gateway(runner=lambda: "0.0.0.0 0.0.0.0 8.8.8.8 192.168.1.5")
        with self.assertRaises(ScanError):
            read_default_gateway(runner=lambda: "no route here")


class MenuTests(unittest.TestCase):
    def test_bare_invocation_shows_the_menu_before_any_probe(self):
        ask, prompts = scripted(["4", "1", "2", "", "yes"])
        scan, calls = recording_scan()
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                [],
                input_func=ask,
                output=lines.append,
                scan=scan,
                reports_dir=folder,
                exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            lines[0],
            "[*] No network address is configured. Found 192.168.1.0/24 on this computer. "
            "The check looks for devices that answer there.",
        )
        self.assertLess(lines.index(lines[0]), lines.index(CHECK_MENU_TITLE))
        for line in CHECK_MENU_LINES:
            self.assertIn(line, lines)
        self.assertIn(RANGE_MENU_TITLE, lines)
        for line in RANGE_MENU_LINES:
            self.assertIn(line, lines)
        self.assertEqual(prompts[0], "Choose a number: ")
        self.assertIn("Which address should be probed?", lines)
        self.assertEqual(prompts[3], ALSO_PROMPT)
        self.assertEqual(prompts[4], VULN_WARNING)
        self.assertEqual(calls, [("192.168.1.0/24", open_ports_arguments("top100"))])
        self.assertLess(lines.index(CHECK_MENU_TITLE), len(lines))
        joined = "\n".join(lines)
        self.assertIn("Check: open ports. Port scan: top 100. Also services: no", joined)

    def test_scan_with_nothing_chosen_is_open_ports_top_100_after_the_warning(self):
        ask, prompts = scripted(["no"])
        scan, calls = recording_scan()
        lines = []
        code = main(["scan"], input_func=ask, output=lines.append, scan=scan)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertEqual(prompts, [VULN_WARNING])
        self.assertNotIn(CHECK_MENU_TITLE, lines)
        self.assertIn("Cancelled. No probes were sent.", lines)

        ask, prompts = scripted(["yes"])
        scan, calls = recording_scan()
        with tempfile.TemporaryDirectory() as folder:
            code = main(["scan"], input_func=ask, output=lines.append, scan=scan, reports_dir=folder)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("192.168.1.0/24", open_ports_arguments("top100"))])

    def test_warnings_can_cancel_before_probes(self):
        ask, prompts = scripted(["no"])
        scan, calls = recording_scan()
        lines = []
        code = main(
            ["scan", "open-ports", "--range", "full", "--also", "services"],
            input_func=ask,
            output=lines.append,
            scan=scan,
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertEqual(prompts, [DURATION_WARNING])
        self.assertIn("long time", prompts[0])
        self.assertIn("hours", prompts[0])
        self.assertIn("single address", prompts[0])

        ask, prompts = scripted(["yes", "no"])
        scan, calls = recording_scan()
        code = main(
            ["scan", "all", "--range", "top1000"],
            input_func=ask,
            output=lines.append,
            scan=scan,
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertEqual(prompts[0], DURATION_WARNING)
        self.assertEqual(prompts[1], VULN_WARNING)
        self.assertIn("printer", prompts[1])
        self.assertIn("camera", prompts[1])
        self.assertIn("TV", prompts[1])
        self.assertIn("old router", prompts[1])

    def test_flags_select_both_profiles_without_the_menus(self):
        ask, prompts = scripted(["yes", "yes"])
        scan, calls = recording_scan(udp_empty=True)
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                ["scan", "open-ports", "--range", "full", "--also", "services"],
                input_func=ask,
                output=lines.append,
                scan=scan,
                reports_dir=folder,
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            [item[1] for item in calls],
            [open_ports_arguments("full"), SERVICES_ARGUMENTS],
        )
        self.assertEqual(prompts, [DURATION_WARNING, VULN_WARNING])
        self.assertNotIn(CHECK_MENU_TITLE, lines)
        self.assertNotIn(RANGE_MENU_TITLE, lines)

    def test_command_flag_wins_over_config_and_a_bad_also_is_refused(self):
        scan, calls = recording_scan()

        def boom(prompt=""):
            raise AssertionError(prompt)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(
                private_config("check: addresses\nport_scan: full\n"),
                encoding="utf-8",
            )
            code = main(
                ["scan", "--config", str(path), "firewalls", "--range", "top10"],
                input_func=boom,
                output=lambda text: None,
                scan=scan,
                reports_dir=folder,
            )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("192.168.1.0/24", FIREWALL_ARGUMENTS["top10"])])

        scan, calls = recording_scan()
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text(private_config(), encoding="utf-8")
            code = main(
                ["--config", str(path), "scan", "addresses", "--also", "services"],
                input_func=boom,
                output=lines.append,
                scan=scan,
            )
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])
        self.assertTrue(any("apply only" in line for line in lines))

    def test_unknown_range_is_refused_and_monitor_never_asks(self):
        scan, calls = recording_scan()
        code = main(["scan", "firewalls", "--range", "nope"], scan=scan, output=lambda text: None)
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

        seen = []

        def fake_monitor(cfg):
            seen.append(discovery_arguments(cfg))

        def boom(prompt=""):
            raise AssertionError(prompt)

        code = main(["monitor"], input_func=boom, output=lambda text: None, monitor=fake_monitor, scan=scan)
        self.assertEqual(code, 0)
        self.assertEqual(seen, ["-sn -T3"])
        self.assertEqual(calls, [])

    def test_open_ports_can_target_one_discovered_address(self):
        ask, prompts = scripted(["4", "2", "1", "2", "no", "yes"])
        scan, calls = recording_scan()
        seen = []

        def discover(cfg):
            seen.append(list(cfg["networks"]))
            return [
                {"ip": "8.8.8.8", "hostname": "public"},
                {"ip": "10.1.1.1", "hostname": "elsewhere"},
                {"ip": "192.168.1.50", "hostname": "printer", "vendor": "Example"},
            ]

        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                [],
                input_func=ask,
                output=lines.append,
                scan=scan,
                discover=discover,
                reports_dir=folder,
                exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
            )
        self.assertEqual(code, 0)
        self.assertEqual(seen, [["192.168.1.0/24"]])
        self.assertEqual(calls, [("192.168.1.50", open_ports_arguments("top100"))])
        self.assertIn("--script vuln", calls[0][1])
        joined = "\n".join(lines)
        self.assertIn("192.168.1.50  printer  Example", joined)
        self.assertNotIn("8.8.8.8", joined)
        self.assertNotIn("10.1.1.1", joined)
        self.assertIn("Finding addresses that answer. Vulnerability scripts are not used for this step.", joined)
        self.assertEqual(prompts[-1], VULN_WARNING)

    def test_a_rejected_address_list_sends_no_vulnerability_probes(self):
        ask, _prompts = scripted(["4", "2"])
        scan, calls = recording_scan()

        def discover(cfg):
            return [{"ip": "8.8.8.8"}, {"ip": "10.9.9.9"}]

        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                [],
                input_func=ask,
                output=lines.append,
                scan=scan,
                discover=discover,
                reports_dir=folder,
            )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertIn("No addresses answered. No vulnerability probes were sent.", lines)

    def test_address_list_can_probe_one_host(self):
        ask, prompts = scripted(["1", "1", "2", "no", "yes"])
        scan, calls = recording_scan()
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                [],
                input_func=ask,
                output=lines.append,
                scan=scan,
                reports_dir=folder,
                exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            calls,
            [
                ("192.168.1.0/24", ADDRESSES_ARGUMENTS),
                ("192.168.1.9", open_ports_arguments("top100")),
            ],
        )
        self.assertIn("--script vuln", calls[1][1])
        self.assertNotIn("--script", calls[0][1])
        self.assertEqual(prompts[-1], VULN_WARNING)
        self.assertIn("1. 192.168.1.9  pc", "\n".join(lines))

    def test_declining_the_follow_up_sends_no_vulnerability_probes(self):
        ask, _prompts = scripted(["1", "1", "2", "no", "no"])
        scan, calls = recording_scan()
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main([], input_func=ask, output=lines.append, scan=scan, reports_dir=folder)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("192.168.1.0/24", ADDRESSES_ARGUMENTS)])
        self.assertIn("Cancelled. No vulnerability probes were sent.", lines)

    def test_menu_comes_back_after_one_check_until_quit(self):
        ask, prompts = scripted(["1", "2", "7"])
        scan, calls = recording_scan()
        lines = []
        with tempfile.TemporaryDirectory() as folder:
            code = main(
                [],
                input_func=ask,
                output=lines.append,
                scan=scan,
                reports_dir=folder,
                repeat=True,
                exposure=lambda cfg: (_ for _ in ()).throw(AssertionError("UPnP ran")),
            )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("192.168.1.0/24", ADDRESSES_ARGUMENTS)])
        self.assertEqual(prompts.count("Choose a number: "), 3)
        self.assertIn("Probe one of these hosts with vulnerability scripts?", lines)
        self.assertIn("That check is done. Choose another, or 7 to quit.", lines)
        self.assertIn("7. Quit.", lines)
        self.assertIn("Quit.", lines)

    def test_public_config_is_refused_wherever_the_flag_sits(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.yaml"
            path.write_text("networks: ['8.8.8.8']\ncritical_ports: [80]\n", encoding="utf-8")
            self.assertEqual(main(["--config", str(path), "scan"], scan=recording_scan()[0]), 2)
            self.assertEqual(main(["scan", "--config", str(path)], scan=recording_scan()[0]), 2)


if __name__ == "__main__":
    unittest.main()
