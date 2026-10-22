#!/usr/bin/env python3
"""Home Network Assessor. Scan a private LAN you own, then write a report.

A run is one check from a fixed menu, plus a port range when that check
scans ports. Nothing the user types is passed to Nmap as a flag, a port
list, or a script name.
"""

import argparse
import ipaddress
import sys
from pathlib import Path

from assessment import run_scan
from devices import load_roster, roster_lines
from local_lan import read_local_networks
from monitor import monitor_loop
from network_guard import GuardError, address_is_allowed, assert_private_target
from reporter import write_reports
from scanner import (
    ADDRESSES_ARGUMENTS,
    CHECKS,
    CHECKS_WITH_RANGE,
    PORT_SCANS,
    ABSENT_CHECK,
    ABSENT_PORT_SCAN,
    ScanError,
    choice_line,
    scan_network,
)
from settings import ConfigError, load_config

REPORTS_DIR = Path(__file__).resolve().parent / "reports"

CHECK_MENU_TITLE = "Network Vulnerability Testing"
CHECK_MENU_LINES = (
    "1. IP addresses. Who is online, plus devices seen before. You can then probe one of them.",
    "2. Routers. The gateway, its admin ports, and the read-only UPnP forward list.",
    "3. Firewalls. Which ports look open, closed, or filtered from this computer.",
    "4. Open ports. Choose one address or the whole range, then run vulnerability scripts.",
    "5. All. Run 1 through 4. The port checks can use one address or the whole range.",
    "6. DNS, QUIC, DHCP, NTP, and IPsec. Only that named set.",
)
RANGE_MENU_TITLE = "Port range"
RANGE_MENU_LINES = (
    "1. Top 10",
    "2. Top 100",
    "3. Top 1000",
    "4. Full (TCP 1-65535)",
)
TARGET_CHECKS = frozenset({"open-ports", "all"})
CHECK_BY_NUMBER = {
    1: "addresses",
    2: "routers",
    3: "firewalls",
    4: "open-ports",
    5: "all",
    6: "services",
}
RANGE_BY_NUMBER = {1: "top10", 2: "top100", 3: "top1000", 4: "full"}
ALSO_PROMPT = "Also scan DNS, QUIC, DHCP, NTP, and IPsec? yes/no"
DURATION_WARNING = (
    "A full scan of one computer can take a long time, a full scan of a whole /24 "
    "can take hours, and the first full scan should be a single address in config.yaml. "
    "Continue? yes/no"
)
VULN_WARNING = (
    "These vulnerability probes can upset a printer, camera, TV, or old router, "
    "and the first run should be one address in config.yaml. Continue? yes/no"
)
CANCELLED = "Cancelled. No probes were sent."


class MenuError(RuntimeError):
    """The menu closed without a choice. No probes were sent."""


def _print_summary(report: dict, output) -> None:
    summary = report["summary"]
    output(
        "[*] Hosts: {hosts}  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}  LOW: {low}  Forwards: {upnp_mappings}".format(
            **summary
        )
    )
    check = report.get("choices", {}).get("check")
    if check == "addresses":
        output(f"[*] Online now: {summary['hosts']}")
        for host in report["hosts"]:
            output(f"[*] {host['ip']}  {host.get('hostname') or 'no name'}  {host.get('mac') or 'n/a'}")
        _print_device_roster(report, output, skip_online=True)
        return
    if check == "routers":
        view = report.get("router_view") or {}
        host = view.get("host")
        if not host:
            output("[*] The router did not answer.")
        else:
            output(f"[*] Router {host['ip']}  {host.get('vendor') or 'vendor unknown'}")
            for port in view.get("open_ports") or []:
                service = " ".join(part for part in (port.get("name"), port.get("product"), port.get("version")) if part)
                output(f"[*] Open {port['port']}/{port['proto']}  {service}")
            if view.get("quiet_ports"):
                output(f"[*] Did not answer: {view['quiet_ports']}")
        mappings = view.get("mappings") or []
        if mappings:
            for item in mappings:
                output(
                    f"[*] Forward {item.get('external_port')}/{item.get('protocol')} -> "
                    f"{item.get('internal_client')}:{item.get('internal_port')}"
                )
        else:
            output("[*] No port forwards were read.")
        _print_device_roster(report, output, skip_online=False)
        return
    for host in report["hosts"]:
        output(f"[*] {host['ip']} {host['risk_level']} score {host['risk_score']}")
        if host.get("level_reason"):
            output(f"    {host['level_reason']}")
        for finding in host["findings"][:8]:
            output(f"    - {finding['points']} points: {finding['text']}")
    _print_device_roster(report, output, skip_online=False)


def _print_device_roster(report: dict, output, skip_online: bool) -> None:
    view = report.get("devices_seen") or {}
    history = view.get("history") or []
    online = view.get("online") or []
    output(f"[*] Device history: {len(history)}. Online in that history: {len(online)}.")
    for device in history:
        if skip_online and device.get("online"):
            continue
        output(
            f"[*] {device.get('status') or 'Seen before'}  {device.get('ip') or 'no address'}  "
            f"{device.get('name') or 'no name'}  {device.get('mac') or 'n/a'}  "
            f"last {device.get('last_seen') or 'n/a'}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Assess a home network you own. Refuses any target that is not a private range. "
            "With no command, this shows the check menu and does not probe until you pick. "
            "--config PATH may appear before or after the command."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run one check. Flags choose from the same menus.")
    scan.add_argument(
        "check",
        nargs="?",
        choices=CHECKS,
        help="addresses, routers, firewalls, open-ports, all, or services.",
    )
    scan.add_argument(
        "--range",
        dest="port_scan",
        choices=PORT_SCANS,
        help="top10, top100, top1000, or full. Used by firewalls, open-ports, and all.",
    )
    scan.add_argument(
        "--also",
        choices=("services",),
        help="With firewalls, open-ports, or all, also run the named UDP service profile.",
    )

    sub.add_parser("monitor", help="Ping-scan on a timer. Does not use the port range or vulnerability scripts.")
    return parser


def split_config(argv: list[str]) -> tuple[list[str], str | None]:
    """Pull --config out so it works before or after the subcommand."""
    kept = []
    config = None
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--config":
            if index + 1 >= len(argv):
                raise ConfigError("--config needs a path.")
            config = argv[index + 1]
            index += 2
            continue
        if item.startswith("--config="):
            config = item.split("=", 1)[1]
            if not config:
                raise ConfigError("--config needs a path.")
            index += 1
            continue
        kept.append(item)
        index += 1
    return kept, config


def ask_menu(count: int, input_func, output) -> int:
    while True:
        try:
            answer = input_func("Choose a number: ")
        except EOFError as exc:
            raise MenuError("No choice was entered. No probes were sent.") from exc
        if answer is None:
            raise MenuError("No choice was entered. No probes were sent.")
        text = str(answer).strip()
        if text.isdigit() and int(text) in range(1, count + 1):
            return int(text)
        output(f"Enter a number from 1 to {count}.")


def ask_yes_no(prompt: str, input_func, output, default_no: bool = False) -> bool:
    while True:
        try:
            answer = input_func(prompt)
        except EOFError as exc:
            raise MenuError("No choice was entered. No probes were sent.") from exc
        if answer is None:
            raise MenuError("No choice was entered. No probes were sent.")
        text = str(answer).strip().lower()
        if text in {"yes", "y"}:
            return True
        if text in {"no", "n"}:
            return False
        if text == "" and default_no:
            return False
        output("Enter yes or no.")


def address_in_networks(ip: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for raw in networks:
        try:
            block = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            continue
        if address in block:
            return True
    return False


def usable_addresses(hosts: list, networks: list) -> list:
    """Keep private addresses that sit inside the configured range."""
    kept = []
    seen = set()
    for host in hosts or []:
        ip = str(host.get("ip") or "").strip()
        if not ip or ip in seen or not address_is_allowed(ip):
            continue
        if not address_in_networks(ip, networks):
            continue
        seen.add(ip)
        kept.append(host)
    return kept


def list_answering_addresses(cfg: dict, scan) -> list:
    """Ping the configured range. The address profile sends no vulnerability scripts."""
    found = []
    for network in cfg["networks"]:
        assert_private_target(network)
        result = scan(network, cfg, arguments=ADDRESSES_ARGUMENTS)
        found.extend(result.get("hosts") or [])
    return usable_addresses(found, cfg["networks"])


def _host_choice(number: int, host: dict) -> str:
    name = host.get("hostname") or "no name"
    vendor = host.get("vendor") or ""
    label = f"{name}  {vendor}".strip()
    return f"{number}. {host['ip']}  {label}"


def _choose_networks(cfg, check, input_func, output, discover) -> tuple[list | None, bool]:
    """Ask which address to probe. None means stop before vulnerability scripts."""
    ranges = ", ".join(str(item) for item in cfg["networks"])
    output("Which address should be probed?")
    output(f"1. Every address on {ranges}")
    output("2. One address that answered")
    if check == "all":
        output("The router check still talks to the gateway. Vulnerability scripts use the address you pick.")
    picked = ask_menu(2, input_func, output)
    if picked == 1:
        return list(cfg["networks"]), False

    output("Finding addresses that answer. Vulnerability scripts are not used for this step.")
    hosts = usable_addresses(discover(cfg), cfg["networks"])
    if not hosts:
        return None, True
    output("Choose an address")
    for number, host in enumerate(hosts, start=1):
        output(_host_choice(number, host))
    selected = hosts[ask_menu(len(hosts), input_func, output) - 1]
    ip = str(selected["ip"]).strip()
    assert_private_target(ip)
    if not address_in_networks(ip, cfg["networks"]):
        raise ConfigError("That address is outside the configured private range.")
    return [ip], True


def _offer_probe(hosts: list, cfg: dict, input_func, output) -> dict | None:
    """After the address check, let the user probe one host that answered."""
    found = usable_addresses(hosts, cfg["networks"])
    if not found:
        output("No addresses answered, so there is nothing to probe.")
        return None
    output("Probe one of these hosts with vulnerability scripts?")
    for number, host in enumerate(found, start=1):
        output(_host_choice(number, host))
    skip = len(found) + 1
    output(f"{skip}. No. Return to the menu.")
    picked = ask_menu(skip, input_func, output)
    if picked == skip:
        return None
    ip = str(found[picked - 1]["ip"]).strip()
    assert_private_target(ip)
    if not address_in_networks(ip, cfg["networks"]):
        raise ConfigError("That address is outside the configured private range.")

    port_scan = cfg.get("port_scan")
    showed_range_menu = False
    if port_scan not in PORT_SCANS:
        port_scan = _show_range_menu(input_func, output)
        showed_range_menu = True
    if showed_range_menu:
        also = ask_yes_no(ALSO_PROMPT, input_func, output, default_no=True)
    else:
        also = bool(cfg.get("also_services"))
    if port_scan in {"top1000", "full"} and not ask_yes_no(DURATION_WARNING, input_func, output):
        output("Cancelled. No vulnerability probes were sent.")
        return None
    if not ask_yes_no(VULN_WARNING, input_func, output):
        output("Cancelled. No vulnerability probes were sent.")
        return None
    return {
        "kind": "scan",
        "check": "open-ports",
        "port_scan": port_scan,
        "also_services": also,
        "networks": [ip],
    }


def _show_check_menu(input_func, output, allow_quit: bool = False, roster=()) -> str:
    output(CHECK_MENU_TITLE)
    for line in CHECK_MENU_LINES:
        output(line)
    count = len(CHECK_MENU_LINES)
    if allow_quit:
        count += 1
        output("7. Quit.")
    for line in roster:
        output(line)
    picked = ask_menu(count, input_func, output)
    if allow_quit and picked == count:
        return "quit"
    return CHECK_BY_NUMBER[picked]


def _show_range_menu(input_func, output) -> str:
    output(RANGE_MENU_TITLE)
    for line in RANGE_MENU_LINES:
        output(line)
    return RANGE_BY_NUMBER[ask_menu(len(RANGE_MENU_LINES), input_func, output)]


def resolve_request(
    command,
    cli_check,
    cli_range,
    cli_also,
    cfg,
    input_func,
    output,
    allow_quit: bool = False,
    discover=None,
    ask_target: bool = False,
    roster=(),
):
    """Turn flags, config, and menus into one check. None means the user cancelled.

    Warnings run after the choice is complete. A no answer returns None and
    the caller must not probe.
    """
    if command == "monitor":
        return {"kind": "monitor"}

    cli_also_set = cli_also == "services"
    file_check = cfg.get("check") or None
    file_range = cfg.get("port_scan") or None
    showed_range_menu = False
    networks = None
    discovery_ran = False

    if command is None:
        check = _show_check_menu(input_func, output, allow_quit=allow_quit, roster=roster)
        if check == "quit":
            return {"kind": "quit"}
        port_scan = file_range
        if check in CHECKS_WITH_RANGE and port_scan:
            output(f"Using port_scan from config.yaml: {port_scan}")
    else:
        nothing_chosen = (
            cli_check is None and file_check is None and cli_range is None and file_range is None
        )
        if nothing_chosen:
            check = ABSENT_CHECK
            port_scan = ABSENT_PORT_SCAN
        else:
            check = cli_check if cli_check is not None else file_check
            if check is None:
                check = _show_check_menu(input_func, output, allow_quit=allow_quit, roster=roster)
                if check == "quit":
                    return {"kind": "quit"}
            port_scan = cli_range if cli_range is not None else file_range

    if ask_target and check in TARGET_CHECKS:
        networks, discovery_ran = _choose_networks(cfg, check, input_func, output, discover)
        if networks is None:
            output("No addresses answered. No vulnerability probes were sent.")
            return None

    if check in CHECKS_WITH_RANGE and port_scan not in PORT_SCANS:
        port_scan = _show_range_menu(input_func, output)
        showed_range_menu = True

    if check not in CHECKS_WITH_RANGE:
        if cli_range is not None or cli_also_set:
            raise ConfigError("--range and --also services apply only to firewalls, open-ports, and all.")
        port_scan = None
        also = False
    elif cli_also_set:
        also = True
    elif showed_range_menu:
        also = ask_yes_no(ALSO_PROMPT, input_func, output, default_no=True)
    else:
        also = bool(cfg.get("also_services"))

    def cancel():
        if discovery_ran:
            output("Cancelled. No vulnerability probes were sent.")
        else:
            output(CANCELLED)
        return None

    if port_scan in {"top1000", "full"}:
        if not ask_yes_no(DURATION_WARNING, input_func, output):
            return cancel()
    if check in {"open-ports", "all"}:
        if not ask_yes_no(VULN_WARNING, input_func, output):
            return cancel()

    request = {
        "kind": "scan",
        "check": check,
        "port_scan": port_scan,
        "also_services": also,
    }
    if networks is not None:
        request["networks"] = networks
    return request


def main(
    argv=None,
    input_func=input,
    output=print,
    scan=None,
    exposure=None,
    gateway=None,
    monitor=None,
    reports_dir=None,
    repeat=None,
    discover=None,
    local_networks=None,
) -> int:
    source = list(sys.argv[1:] if argv is None else argv)
    try:
        kept, config_path = split_config(source)
    except ConfigError as exc:
        output(f"[!] {exc}")
        return 2
    try:
        args = build_parser().parse_args(kept)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        try:
            return int(code)
        except (TypeError, ValueError):
            return 2

    try:
        cfg = load_config(config_path or getattr(args, "config", None))
        if not cfg.get("networks"):
            cfg["networks"] = list((local_networks or read_local_networks)())
            output(
                "[*] No network address is configured. Found "
                + ", ".join(cfg["networks"])
                + " on this computer. The check looks for devices that answer there."
            )
    except (ConfigError, GuardError) as exc:
        output(f"[!] {exc}")
        return 2

    if repeat is None:
        repeat = not kept and args.command is None and input_func is input
    loaded = cfg
    pending = None

    while True:
        if pending is not None:
            request = pending
            pending = None
        else:
            try:
                finder = discover or (lambda current: list_answering_addresses(current, scan or scan_network))
                folder = Path(reports_dir) if reports_dir else REPORTS_DIR
                preface = roster_lines(load_roster(folder)) if args.command is None else ()
                request = resolve_request(
                    args.command,
                    getattr(args, "check", None),
                    getattr(args, "port_scan", None),
                    getattr(args, "also", None),
                    loaded,
                    input_func,
                    output,
                    allow_quit=repeat,
                    discover=finder,
                    ask_target=args.command is None,
                    roster=preface,
                )
            except KeyboardInterrupt:
                output("\n[*] Stopped. No probes were sent.")
                return 0
            except (ConfigError, MenuError) as exc:
                output(f"[!] {exc}")
                return 2
        if request is None:
            if repeat:
                output("")
                continue
            return 0
        if request["kind"] == "quit":
            output("Quit.")
            return 0

        if request["kind"] == "monitor":
            try:
                (monitor or monitor_loop)(loaded)
            except KeyboardInterrupt:
                output("\n[*] Monitor stopped.")
            if not repeat:
                return 0
            output("")
            continue

        cfg = dict(loaded)
        cfg["check"] = request["check"]
        cfg["port_scan"] = request["port_scan"]
        cfg["also_services"] = request["also_services"]
        if request.get("networks"):
            cfg["networks"] = list(request["networks"])
        output(choice_line(cfg["check"], cfg["port_scan"], cfg["also_services"]))
        kwargs = {}
        if scan is not None:
            kwargs["scan"] = scan
        if exposure is not None:
            kwargs["exposure"] = exposure
        if gateway is not None:
            kwargs["gateway"] = gateway
        try:
            report = run_scan(cfg, **kwargs)
        except GuardError as exc:
            output(f"[!] {exc}")
            if repeat:
                output("")
                continue
            return 2
        except ScanError as exc:
            output(f"[!] {exc}")
            if repeat:
                output("")
                continue
            return 1
        except KeyboardInterrupt:
            output("\n[*] Stopped.")
            if repeat:
                output("")
                continue
            return 0

        folder = Path(reports_dir) if reports_dir else REPORTS_DIR
        paths = write_reports(report, folder)
        output(f"[+] HTML report: {paths['html']}")
        output(f"[+] JSON report: {paths['json']}")
        output(f"[+] Latest copy: {paths['latest_html']}")
        _print_summary(report, output)
        if args.command is None and cfg["check"] == "addresses":
            try:
                pending = _offer_probe(report["hosts"], loaded, input_func, output)
            except KeyboardInterrupt:
                output("\n[*] Stopped. No probes were sent.")
                return 0
            except (ConfigError, MenuError) as exc:
                output(f"[!] {exc}")
                return 2
            if pending is not None:
                output("")
                continue
        if not repeat:
            return 0
        output("")
        output("That check is done. Choose another, or 7 to quit.")


if __name__ == "__main__":
    raise SystemExit(main())
