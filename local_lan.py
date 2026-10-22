"""Find the private LAN this computer is already on.

Nothing here probes the network. It reads local adapter addresses and the
default route, then ignores VPN, virtual, loopback, and link-local adapters.
The scan that follows is what looks for devices on that LAN.
"""

import json
import os
import re
import subprocess

import ipaddress

from network_guard import GuardError, address_is_allowed, assert_private_target
from settings import ConfigError

_SKIP_ALIAS = re.compile(
    r"nord|vpn|virtualbox|vbox|vethernet|hyper-?v|wsl|loopback|bluetooth|"
    r"tunnel|tap|tun|wireguard|wintun|vmware|host-only",
    re.IGNORECASE,
)
_LINUX_IFACE = re.compile(r"^\d+:\s+(\S+?):")
_LINUX_INET = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
_LINUX_DEFAULT = re.compile(r"^default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)")

_WINDOWS_QUERY = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$adapters = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
  [PSCustomObject]@{
    ip = [string]$_.IPAddress
    prefix = [int]$_.PrefixLength
    alias = [string]$_.InterfaceAlias
  }
})
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    alias = [string]$_.InterfaceAlias
    gateway = [string]$_.NextHop
  }
})
@{ adapters = $adapters; routes = $routes } | ConvertTo-Json -Depth 4 -Compress
"""

NO_LAN = (
    "No private LAN was found on this computer. Connect to the network you own. "
    "VPN, virtual, and link-local adapters are ignored. No probes were sent."
)


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _network_for(ip, prefix) -> str | None:
    try:
        length = int(prefix)
    except (TypeError, ValueError):
        return None
    if not 16 <= length <= 30:
        return None
    try:
        interface = ipaddress.ip_interface(f"{str(ip).strip()}/{length}")
    except ValueError:
        return None
    if interface.version != 4 or interface.ip.is_loopback or interface.ip.is_link_local:
        return None
    if not address_is_allowed(str(interface.ip)):
        return None
    network = interface.network
    try:
        assert_private_target(str(network))
    except GuardError:
        return None
    return str(network)


def choose_local_networks(adapters: list, routes: list | None = None) -> list[str]:
    """Return the private ranges to scan. Raises ConfigError when none qualify."""
    gateway_by_alias = {}
    default_aliases = set()
    for route in routes or []:
        if not isinstance(route, dict):
            continue
        alias = str(route.get("alias") or "")
        gateway = str(route.get("gateway") or "").strip()
        if not alias or gateway in {"", "0.0.0.0", "::"}:
            continue
        gateway_by_alias[alias] = gateway
        default_aliases.add(alias)

    kept = []
    for adapter in adapters or []:
        if not isinstance(adapter, dict):
            continue
        alias = str(adapter.get("alias") or "")
        if _SKIP_ALIAS.search(alias):
            continue
        network = _network_for(adapter.get("ip"), adapter.get("prefix"))
        if network is None:
            continue
        gateway = str(adapter.get("gateway") or gateway_by_alias.get(alias) or "").strip()
        if gateway in {"0.0.0.0", "::"}:
            gateway = ""
        if gateway:
            try:
                assert_private_target(gateway)
            except GuardError:
                continue
        kept.append(
            {
                "network": network,
                "gateway": gateway,
                "default": alias in default_aliases,
            }
        )
    if not kept:
        raise ConfigError(NO_LAN)
    defaulted = [item for item in kept if item["default"] and item["gateway"]]
    routed = [item for item in kept if item["gateway"]]
    pool = defaulted or routed or kept
    found = []
    for item in pool:
        if item["network"] not in found:
            found.append(item["network"])
    return found


def networks_from_os_payload(payload: dict) -> list[str]:
    if not isinstance(payload, dict):
        raise ConfigError("The local adapter list could not be read. No probes were sent.")
    return choose_local_networks(_as_list(payload.get("adapters")), _as_list(payload.get("routes")))


def parse_linux_adapters(text: str) -> list[dict]:
    adapters = []
    alias = ""
    for line in (text or "").splitlines():
        head = _LINUX_IFACE.match(line.strip())
        if head:
            alias = head.group(1)
            continue
        inet = _LINUX_INET.search(line)
        if inet and alias:
            adapters.append({"ip": inet.group(1), "prefix": int(inet.group(2)), "alias": alias})
    return adapters


def parse_linux_routes(text: str) -> list[dict]:
    routes = []
    for line in (text or "").splitlines():
        match = _LINUX_DEFAULT.search(line.strip())
        if match:
            routes.append({"gateway": match.group(1), "alias": match.group(2)})
    return routes


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigError("The local adapter list could not be read. No probes were sent.") from exc
    if completed.returncode != 0 and not (completed.stdout or "").strip():
        raise ConfigError("The local adapter list could not be read. No probes were sent.")
    return completed.stdout or ""


def _read_windows() -> dict:
    text = _run(["powershell", "-NoProfile", "-Command", _WINDOWS_QUERY])
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ConfigError("The local adapter list could not be read. No probes were sent.")
    try:
        payload = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ConfigError("The local adapter list could not be read. No probes were sent.") from exc
    if not isinstance(payload, dict):
        raise ConfigError("The local adapter list could not be read. No probes were sent.")
    return payload


def _read_linux() -> dict:
    return {
        "adapters": parse_linux_adapters(_run(["ip", "-4", "addr", "show"])),
        "routes": parse_linux_routes(_run(["ip", "-4", "route", "show"])),
    }


def read_local_networks(runner=None) -> list[str]:
    """Read this computer's adapters. runner is for tests and must not probe."""
    if runner is not None:
        return networks_from_os_payload(runner())
    if os.name == "nt":
        payload = _read_windows()
    else:
        payload = _read_linux()
    return networks_from_os_payload(payload)
