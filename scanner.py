"""Run Nmap against a private range and shape the result.

Every scan uses one of the fixed profiles in this file. A hand-written
nmap_args line is never sent. Vulnerability scripts are only in the
open-ports profile, and in the open-ports phase of all.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

from network_guard import GuardError, assert_private_target
from presence import normalize_mac

_MAC_IN_LINE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).{1,40}?(?P<mac>[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
)


class ScanError(RuntimeError):
    """The scan did not run."""


CHECKS = ("addresses", "routers", "firewalls", "open-ports", "all", "services")
PORT_SCANS = ("top10", "top100", "top1000", "full")
CHECKS_WITH_RANGE = ("firewalls", "open-ports", "all")
ABSENT_CHECK = "open-ports"
ABSENT_PORT_SCAN = "top100"

# These strings are the only arguments that may be passed to Nmap.
MONITOR_ARGUMENTS = "-sn -T3"
ADDRESSES_ARGUMENTS = "-sn -T3"
ROUTERS_ARGUMENTS = "-sV -p 22,23,80,443,8080,8443 -T3"
SERVICES_ARGUMENTS = "-sV -sU -p T:53,443,U:53,67,68,123,443,500,4500 -T3"
FIREWALL_ARGUMENTS = {
    "top10": "-sV --top-ports 10 -T3",
    "top100": "-sV --top-ports 100 -T3",
    "top1000": "-sV --top-ports 1000 -T3",
    "full": "-sV -p- -T3",
}
_PORT_STATES = {"open", "closed", "filtered", "open|filtered"}
NAMED_SERVICE_PORTS = (
    (53, "tcp"),
    (53, "udp"),
    (443, "tcp"),
    (443, "udp"),
    (67, "udp"),
    (68, "udp"),
    (123, "udp"),
    (500, "udp"),
    (4500, "udp"),
)
_GATEWAY_VIA = re.compile(r"\bdefault\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\b")


def open_ports_arguments(port_scan: str) -> str:
    """Firewall profile for that range, plus Nmap's vuln category and nothing else."""
    return f"{FIREWALL_ARGUMENTS[port_scan]} --script vuln"


def allowed_arguments() -> frozenset:
    values = {
        MONITOR_ARGUMENTS,
        ADDRESSES_ARGUMENTS,
        ROUTERS_ARGUMENTS,
        SERVICES_ARGUMENTS,
        *FIREWALL_ARGUMENTS.values(),
    }
    values.update(open_ports_arguments(name) for name in PORT_SCANS)
    return frozenset(values)


def discovery_arguments(cfg: dict | None = None) -> str:
    """The monitor always uses this. It does not read the port range or a script."""
    return MONITOR_ARGUMENTS


def argument_plan(check: str, port_scan: str | None = None, also_services: bool = False) -> list:
    """Return the fixed phases, in run order. Each arguments value is one allowed profile."""
    if check not in CHECKS:
        raise ScanError(f"Unknown check {check!r}.")
    if also_services and check not in CHECKS_WITH_RANGE:
        raise ScanError("--also services applies only to firewalls, open-ports, and all.")
    if check in CHECKS_WITH_RANGE and port_scan not in PORT_SCANS:
        raise ScanError("This check needs a port range: top10, top100, top1000, or full.")
    if check not in CHECKS_WITH_RANGE:
        port_scan = None

    def phase(name: str, arguments: str, target: str) -> dict:
        if arguments not in allowed_arguments():
            raise ScanError("Refusing a profile that is not in the fixed list.")
        return {"phase": name, "arguments": arguments, "target": target}

    if check == "addresses":
        return [phase("addresses", ADDRESSES_ARGUMENTS, "network")]
    if check == "routers":
        return [phase("routers", ROUTERS_ARGUMENTS, "gateway")]
    if check == "services":
        return [phase("services", SERVICES_ARGUMENTS, "network")]
    if check == "firewalls":
        steps = [phase("firewalls", FIREWALL_ARGUMENTS[port_scan], "network")]
    elif check == "open-ports":
        steps = [phase("open-ports", open_ports_arguments(port_scan), "network")]
    else:
        steps = [
            phase("addresses", ADDRESSES_ARGUMENTS, "network"),
            phase("routers", ROUTERS_ARGUMENTS, "gateway"),
            phase("firewalls", FIREWALL_ARGUMENTS[port_scan], "network"),
            phase("open-ports", open_ports_arguments(port_scan), "network"),
        ]
    if also_services:
        steps.append(phase("services", SERVICES_ARGUMENTS, "network"))
    return steps


def choice_line(check: str, port_scan: str | None, also_services: bool) -> str:
    labels = {
        "addresses": "IP addresses",
        "routers": "routers",
        "firewalls": "firewalls",
        "open-ports": "open ports",
        "all": "all",
        "services": "DNS, QUIC, DHCP, NTP, and IPsec",
    }
    ranges = {"top10": "top 10", "top100": "top 100", "top1000": "top 1000", "full": "full"}
    range_label = ranges.get(port_scan or "", "n/a")
    also = "yes" if also_services else "no"
    return f"Check: {labels[check]}. Port scan: {range_label}. Also services: {also}"


def parse_default_gateway(text: str) -> str | None:
    """Pull the default gateway out of `ip route` or `route print` text."""
    match = _GATEWAY_VIA.search(text or "")
    if match:
        return match.group(1)
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2]
    return None


def read_default_gateway(runner=None) -> str:
    """Return the private default gateway. A public gateway is refused before any scan."""
    if runner is None:
        if os.name == "nt":
            command = ["route", "print", "-4"]
        else:
            command = ["ip", "route", "show", "default"]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScanError("The default gateway could not be read. No probes were sent.") from exc
        text = completed.stdout or ""
    else:
        text = runner()
    found = parse_default_gateway(text)
    if not found:
        raise ScanError("No default gateway was found. No probes were sent.")
    try:
        assert_private_target(found)
    except GuardError as exc:
        raise GuardError(f"The gateway {found} is not a private address. No probes were sent.") from exc
    return found


def port_from_service(number, proto: str, service: dict) -> dict | None:
    """Keep open, closed, and filtered. Drop anything Nmap did not actually classify."""
    state = str(service.get("state") or "").lower()
    if state not in _PORT_STATES:
        return None
    scripts = []
    raw_scripts = service.get("script") or {}
    if isinstance(raw_scripts, dict):
        for name, output in raw_scripts.items():
            scripts.append({"id": str(name), "output": "" if output is None else str(output)})
    try:
        port_number = int(number)
    except (TypeError, ValueError):
        return None
    return {
        "port": port_number,
        "proto": str(proto or "tcp").lower(),
        "state": state,
        "name": service.get("name") or "",
        "product": service.get("product") or "",
        "version": service.get("version") or "",
        "extrainfo": service.get("extrainfo") or "",
        "scripts": scripts,
    }


def _merge_port(old: dict, new: dict) -> dict:
    rank = {"open": 3, "closed": 2, "filtered": 1, "open|filtered": 1}
    old_rank = rank.get(old.get("state") or "open", 0)
    new_rank = rank.get(new.get("state") or "open", 0)
    if new_rank >= old_rank:
        chosen = dict(new)
        other = old
    else:
        chosen = dict(old)
        other = new
    for field in ("name", "product", "version", "extrainfo"):
        if not chosen.get(field) and other.get(field):
            chosen[field] = other[field]
    scripts = []
    seen = set()
    for source in (chosen, other):
        for script in source.get("scripts") or []:
            key = script.get("id")
            if key in seen:
                continue
            seen.add(key)
            scripts.append(script)
    chosen["scripts"] = scripts
    return chosen


def merge_hosts(groups: list) -> list:
    """Combine phases. A host stays even when a later UDP probe returns nothing."""
    order = []
    by_ip = {}
    for group in groups:
        for host in group or []:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue
            if ip not in by_ip:
                by_ip[ip] = {
                    "ip": ip,
                    "hostname": host.get("hostname") or "",
                    "state": host.get("state") or "up",
                    "mac": host.get("mac"),
                    "vendor": host.get("vendor"),
                    "ports": [],
                    "host_scripts": [],
                }
                order.append(ip)
            current = by_ip[ip]
            if host.get("hostname") and not current["hostname"]:
                current["hostname"] = host["hostname"]
            if host.get("mac") and not current["mac"]:
                current["mac"] = host["mac"]
            if host.get("vendor") and not current["vendor"]:
                current["vendor"] = host["vendor"]
            if host.get("state") == "up":
                current["state"] = "up"
            index_by_key = {
                (int(row["port"]), str(row.get("proto") or "tcp")): index
                for index, row in enumerate(current["ports"])
            }
            incoming = host.get("ports")
            if incoming is None:
                incoming = host.get("open_ports") or []
            for row in incoming:
                try:
                    key = (int(row["port"]), str(row.get("proto") or "tcp").lower())
                except (KeyError, TypeError, ValueError):
                    continue
                normalized = dict(row)
                normalized["port"] = key[0]
                normalized["proto"] = key[1]
                normalized.setdefault("state", "open")
                normalized.setdefault("scripts", [])
                if key in index_by_key:
                    current["ports"][index_by_key[key]] = _merge_port(current["ports"][index_by_key[key]], normalized)
                else:
                    index_by_key[key] = len(current["ports"])
                    current["ports"].append(normalized)
            for script in host.get("host_scripts") or []:
                if script not in current["host_scripts"]:
                    current["host_scripts"].append(script)
    return [by_ip[ip] for ip in order]


def fill_named_unanswered(hosts: list) -> None:
    """After the services profile, a named port that did not answer is filtered, not safe."""
    for host in hosts:
        rows = host.setdefault("ports", [])
        have = {(int(row["port"]), str(row.get("proto") or "tcp").lower()) for row in rows if "port" in row}
        for number, proto in NAMED_SERVICE_PORTS:
            if (number, proto) in have:
                continue
            rows.append(
                {
                    "port": number,
                    "proto": proto,
                    "state": "filtered",
                    "name": "",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "scripts": [],
                }
            )


def nmap_install_hint() -> str:
    if os.name == "nt":
        return (
            "Install Nmap for Windows from https://nmap.org/download.html and open a new "
            "terminal so PATH picks it up."
        )
    return "Install nmap with your package manager, for example: sudo apt install nmap"


def parse_arp_output(text: str) -> dict:
    """Map IPv4 addresses to unicast MACs from `arp -a` on Windows or Linux."""
    found = {}
    for line in text.splitlines():
        if "incomplete" in line.lower():
            continue
        match = _MAC_IN_LINE.search(line)
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if mac:
            found[match.group("ip")] = mac
    return found


def read_arp_table(runner=None) -> dict:
    if runner is None:
        try:
            completed = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        return parse_arp_output(completed.stdout or "")
    return parse_arp_output(runner())


def attach_arp_macs(hosts: list, arp_map: dict) -> list:
    for host in hosts:
        if not host.get("mac"):
            mac = arp_map.get(host.get("ip"))
            if mac:
                host["mac"] = mac
    return hosts


def _host_record(scanner, ip: str) -> dict:
    record = scanner[ip]
    host = {
        "ip": ip,
        "hostname": record.hostname() or "",
        "state": record.state(),
        "mac": None,
        "vendor": None,
        "ports": [],
        "host_scripts": [],
    }
    addresses = record.get("addresses") or {}
    if addresses.get("mac"):
        host["mac"] = normalize_mac(addresses["mac"])
    vendor = record.get("vendor") or {}
    if isinstance(vendor, dict) and vendor:
        host["vendor"] = next(iter(vendor.values()))
    for proto in record.all_protocols():
        for port, service in record[proto].items():
            parsed = port_from_service(port, proto, service)
            if parsed:
                host["ports"].append(parsed)
    for item in record.get("hostscript") or []:
        if isinstance(item, dict) and item.get("id"):
            host["host_scripts"].append({"id": str(item.get("id")), "output": str(item.get("output") or "")})
    return host


def scan_network(network: str, cfg: dict, arguments: str | None = None, arp_reader=None) -> dict:
    """Scan one private range. Raises ScanError or GuardError and sends nothing on refusal."""
    assert_private_target(network)
    args = arguments or ""
    if args not in allowed_arguments():
        raise ScanError("Refusing Nmap arguments that are not one of the fixed profiles. No probes were sent.")
    if shutil.which("nmap") is None:
        raise ScanError(f"nmap was not found on PATH. {nmap_install_hint()}")
    try:
        import nmap
    except ImportError as exc:
        raise ScanError(
            "The python-nmap package is not installed. From this folder run: "
            "python -m pip install -r requirements.txt"
        ) from exc

    print(f"[*] Scanning {network}")
    print(f"[*] Command: nmap {args} {network}")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=network, arguments=args)
    except ScanError:
        raise
    except OSError as exc:
        raise ScanError(f"Nmap failed for {network}: {exc}. {nmap_install_hint()}") from exc
    except Exception as exc:
        raise ScanError(f"Nmap failed for {network}: {exc}. {nmap_install_hint()}") from exc

    hosts = [_host_record(scanner, ip) for ip in scanner.all_hosts()]
    attach_arp_macs(hosts, read_arp_table() if arp_reader is None else arp_reader())
    print(f"[*] {len(hosts)} host(s) returned for {network}")
    if not hosts and os.name == "nt":
        print("[*] No hosts came back. An elevated terminal lets Nmap use ARP and usually sees more devices.")
    return {
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "network": network,
        "arguments": args,
        "hosts": hosts,
    }


if __name__ == "__main__":
    print("Use: python main.py scan")
    raise SystemExit(2)
