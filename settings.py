"""Load config.yaml and reject settings this tool will not run."""

from pathlib import Path

import yaml

from network_guard import GuardError, assert_private_target

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

DEFAULTS = {
    "networks": [],
    "critical_ports": [21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 554, 1883],
    "check": None,
    "port_scan": None,
    "also_services": False,
    "nmap_args": "-sV --top-ports 100 -T3",
    "discovery_args": "-sn -T3",
    "monitor_interval_seconds": 300,
    "missed_checks_before_offline": 3,
    "block_magic_packets": False,
    "notify_on_offline": True,
    "lookup_public_ip": False,
    "upnp_timeout_seconds": 4,
    "wol_block_list": [],
}

# Nmap scripts and capture-file flags are rejected. -A is rejected because it
# turns the default scripts on. python-nmap does not use a shell, and this
# check keeps the argument string inside ordinary scan flags.
_BANNED_NMAP = {
    "--script",
    "--script-args",
    "-sC",
    "-A",
    "-iL",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "--resume",
}
_BANNED_CHARS = set("\n\r;&|$`<>")


class ConfigError(ValueError):
    """config.yaml is missing a usable value."""


def assert_safe_nmap_args(arguments: str, field: str) -> str:
    if not isinstance(arguments, str) or not arguments.strip():
        raise ConfigError(f"{field} must be a non-empty string")
    if any(char in arguments for char in _BANNED_CHARS):
        raise ConfigError(f"{field} contains a character this tool does not accept")
    for token in arguments.split():
        name = token.split("=", 1)[0]
        if name in _BANNED_NMAP or name.startswith("--script"):
            raise ConfigError(
                f"{field} uses {name}, which is disabled. A config line cannot choose "
                "Nmap scripts, script arguments, or output files."
            )
    return arguments.strip()


def _bool(value, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be true or false")
    return value


def _ports(value) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ConfigError("critical_ports must be a non-empty list of port numbers")
    ports = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError(f"critical_ports entry {item!r} is not an integer")
        if not 1 <= item <= 65535:
            raise ConfigError(f"critical_ports entry {item} is outside 1-65535")
        if item not in ports:
            ports.append(item)
    return ports


def load_config(path: Path | None = None) -> dict:
    """Read YAML, fill defaults, and refuse a target that is not private."""
    config_path = Path(path) if path else CONFIG_PATH
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    data = yaml.safe_load(raw_text) or {}
    if not isinstance(data, dict):
        raise ConfigError("config.yaml must be a mapping of settings")

    cfg = dict(DEFAULTS)
    cfg.update(data)

    networks = cfg.get("networks")
    if networks in (None, ""):
        networks = []
    if not isinstance(networks, list):
        raise ConfigError("networks must be a list of private addresses, or left unset")
    cleaned_networks = []
    for network in networks:
        if not isinstance(network, str):
            raise ConfigError(f"Network {network!r} must be a string")
        try:
            assert_private_target(network)
        except GuardError as exc:
            raise ConfigError(str(exc)) from exc
        cleaned_networks.append(network.strip())
    cfg["networks"] = cleaned_networks
    cfg["critical_ports"] = _ports(cfg.get("critical_ports"))
    cfg["nmap_args"] = assert_safe_nmap_args(cfg.get("nmap_args"), "nmap_args")
    cfg["discovery_args"] = assert_safe_nmap_args(cfg.get("discovery_args"), "discovery_args")

    from scanner import CHECKS, MONITOR_ARGUMENTS, PORT_SCANS

    check = cfg.get("check")
    if check in (None, ""):
        cfg["check"] = None
    elif check not in CHECKS:
        raise ConfigError(f"check must be one of: {', '.join(CHECKS)}")
    port_scan = cfg.get("port_scan")
    if port_scan in (None, ""):
        cfg["port_scan"] = None
    elif port_scan not in PORT_SCANS:
        raise ConfigError(f"port_scan must be one of: {', '.join(PORT_SCANS)}")
    cfg["also_services"] = _bool(cfg.get("also_services"), "also_services")
    if cfg["discovery_args"] != MONITOR_ARGUMENTS:
        raise ConfigError("discovery_args must stay -sn -T3. The monitor does not take a port range.")

    interval = cfg.get("monitor_interval_seconds")
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 30:
        raise ConfigError("monitor_interval_seconds must be an integer of at least 30")
    misses = cfg.get("missed_checks_before_offline")
    if isinstance(misses, bool) or not isinstance(misses, int) or not 1 <= misses <= 20:
        raise ConfigError("missed_checks_before_offline must be an integer from 1 to 20")
    timeout = cfg.get("upnp_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 15:
        raise ConfigError("upnp_timeout_seconds must be an integer from 1 to 15")

    cfg["block_magic_packets"] = _bool(cfg.get("block_magic_packets"), "block_magic_packets")
    cfg["notify_on_offline"] = _bool(cfg.get("notify_on_offline"), "notify_on_offline")
    cfg["lookup_public_ip"] = _bool(cfg.get("lookup_public_ip"), "lookup_public_ip")

    block_list = cfg.get("wol_block_list")
    if not isinstance(block_list, list):
        raise ConfigError("wol_block_list must be a list")
    cfg["wol_block_list"] = block_list
    cfg["config_path"] = str(config_path)
    return cfg
