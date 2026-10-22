"""Remember private devices this program has already seen.

Online means the latest address check saw the device, or a later check on
this computer got an answer from it. History keeps every private device
recorded from those checks. This module does not probe the network.
"""

import copy
import json
from pathlib import Path

from network_guard import address_is_allowed
from presence import normalize_mac

HISTORY_NAME = "devices.json"


def empty_history() -> dict:
    return {"last_census_at": "", "empty_census_kept": False, "devices": {}}


def _earlier(left, right) -> str:
    if not left:
        return str(right or "")
    if not right:
        return str(left)
    return str(left) if str(left) <= str(right) else str(right)


def _later(left, right) -> str:
    if not left:
        return str(right or "")
    if not right:
        return str(left)
    return str(left) if str(left) >= str(right) else str(right)


def _usable(host: dict) -> dict | None:
    if not isinstance(host, dict):
        return None
    if str(host.get("state") or "up") == "unseen":
        return None
    ip = str(host.get("ip") or "").strip()
    if not ip or not address_is_allowed(ip):
        return None
    if "/" in ip:
        return None
    return {
        "ip": ip,
        "mac": normalize_mac(host.get("mac")),
        "name": str(host.get("hostname") or host.get("name") or "").strip(),
        "vendor": str(host.get("vendor") or "").strip(),
    }


def _absorb_ip_record(devices: dict, mac: str, ip: str) -> None:
    ip_key = f"ip:{ip}"
    mac_key = f"mac:{mac}"
    incoming = devices.get(ip_key)
    if not incoming or ip_key == mac_key:
        return
    devices.pop(ip_key)
    current = devices.get(mac_key)
    if current is None:
        incoming["mac"] = mac
        devices[mac_key] = incoming
        return
    for item in incoming.get("ips") or []:
        if item not in current["ips"]:
            current["ips"].append(item)
    if incoming.get("name") and not current.get("name"):
        current["name"] = incoming["name"]
    if incoming.get("vendor") and not current.get("vendor"):
        current["vendor"] = incoming["vendor"]
    current["first_seen"] = _earlier(current.get("first_seen"), incoming.get("first_seen"))
    current["last_seen"] = _later(current.get("last_seen"), incoming.get("last_seen"))
    current["online"] = bool(current.get("online") or incoming.get("online"))


def _store(devices: dict, parsed: dict, when: str) -> str:
    mac = parsed["mac"]
    ip = parsed["ip"]
    if mac:
        _absorb_ip_record(devices, mac, ip)
        key = f"mac:{mac}"
    else:
        key = f"ip:{ip}"
    current = devices.get(key)
    if current is None:
        devices[key] = {
            "ip": ip,
            "ips": [ip],
            "mac": mac,
            "name": parsed["name"],
            "vendor": parsed["vendor"],
            "online": True,
            "first_seen": when,
            "last_seen": when,
        }
        return key
    if ip and ip not in current["ips"]:
        current["ips"].append(ip)
    if ip:
        current["ip"] = ip
    if mac:
        current["mac"] = mac
    if parsed["name"]:
        current["name"] = parsed["name"]
    if parsed["vendor"]:
        current["vendor"] = parsed["vendor"]
    current["online"] = True
    current["first_seen"] = _earlier(current.get("first_seen"), when)
    current["last_seen"] = _later(current.get("last_seen"), when)
    return key


def observe(history: dict, hosts: list, when: str, census: bool) -> dict:
    """Return an updated copy. census=True is a full address check."""
    history = copy.deepcopy(history or empty_history())
    devices = history.setdefault("devices", {})
    usable = [parsed for host in hosts or [] if (parsed := _usable(host))]
    if census and not usable and any(item.get("online") for item in devices.values()):
        history["empty_census_kept"] = True
        return history
    seen = {_store(devices, parsed, when) for parsed in usable}
    if census:
        history["empty_census_kept"] = False
        history["last_census_at"] = when or history.get("last_census_at") or ""
        for key, device in devices.items():
            device["online"] = key in seen
    return history


def rebuild_from_reports(directory: Path) -> dict:
    """Replay saved reports. Does not probe."""
    history = empty_history()
    folder = Path(directory)
    if not folder.is_dir():
        return history
    rows = []
    for path in folder.glob("report_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        choices = data.get("choices") if isinstance(data.get("choices"), dict) else {}
        rows.append(
            (
                str(data.get("generated_at") or ""),
                path.name,
                str(choices.get("check") or ""),
                data.get("hosts") or [],
            )
        )
    for when, _name, check, hosts in sorted(rows):
        history = observe(history, hosts, when, census=(check == "addresses"))
    return history


def load_history(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("devices"), dict):
        return None
    data.setdefault("last_census_at", "")
    data.setdefault("empty_census_kept", False)
    return data


def _write(path: Path, history: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(history, indent=2), encoding="utf-8")
    temporary.replace(path)


def remember(hosts: list, when: str, census: bool, directory: Path) -> dict:
    """Store hosts and return the roster. A missing file is filled from saved reports."""
    folder = Path(directory)
    path = folder / HISTORY_NAME
    history = load_history(path)
    if history is None:
        history = rebuild_from_reports(folder)
    history = observe(history, hosts, when, census)
    _write(path, history)
    return roster_view(history)


def mark_offline(directory: Path, keys: list[str]) -> None:
    """Mark monitor devices offline. Unknown keys are ignored."""
    path = Path(directory) / HISTORY_NAME
    history = load_history(path)
    if history is None:
        return
    changed = False
    for key in keys:
        device = history["devices"].get(key)
        if device and device.get("online"):
            device["online"] = False
            changed = True
    if changed:
        _write(path, history)


def roster_view(history: dict) -> dict:
    rows = []
    for device in (history or empty_history()).get("devices", {}).values():
        online = bool(device.get("online"))
        rows.append(
            {
                "ip": device.get("ip") or "",
                "name": device.get("name") or "",
                "mac": device.get("mac") or "",
                "vendor": device.get("vendor") or "",
                "online": online,
                "status": "Online" if online else "Seen before",
                "first_seen": device.get("first_seen") or "",
                "last_seen": device.get("last_seen") or "",
            }
        )
    rows.sort(key=lambda row: (not row["online"], row["ip"], row["mac"]))
    return {
        "last_census_at": (history or {}).get("last_census_at") or "",
        "empty_census_kept": bool((history or {}).get("empty_census_kept")),
        "online": [row for row in rows if row["online"]],
        "history": rows,
    }


def load_roster(directory: Path) -> dict:
    """Read the roster. Saved reports fill it once when the file is missing."""
    folder = Path(directory)
    path = folder / HISTORY_NAME
    history = load_history(path)
    if history is None:
        history = rebuild_from_reports(folder)
        if history["devices"]:
            _write(path, history)
    return roster_view(history)


def _format_device(device: dict) -> str:
    return "{ip}  {name}  {mac}  {vendor}".format(
        ip=device.get("ip") or "no address",
        name=device.get("name") or "no name",
        mac=device.get("mac") or "n/a",
        vendor=device.get("vendor") or "n/a",
    )


def roster_lines(view: dict) -> list[str]:
    """Plain lines for the menu. Showing them does not probe."""
    online = list(view.get("online") or [])
    history = list(view.get("history") or [])
    lines = [f"Online now: {len(online)}."]
    if online:
        lines.extend(_format_device(device) for device in online)
    else:
        lines.append("None yet. Option 1 records who answers. Showing this list does not probe.")
    before = [device for device in history if not device.get("online")]
    lines.append(f"Seen before: {len(before)}. History keeps {len(history)} devices.")
    lines.extend(_format_device(device) for device in before)
    when = view.get("last_census_at") or ""
    if when:
        lines.append(f"Latest address check: {when}")
    if view.get("empty_census_kept"):
        lines.append("The last address check saw nobody. Earlier devices were kept.")
    return lines
