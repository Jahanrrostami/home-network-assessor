"""Track which devices are up, without calling the network.

A device is keyed by MAC when we know one, because DHCP changes the IP.
A host is declared offline only after several missed checks.
A scan that sees nobody does not move the counters: an empty result usually
means this computer lost the LAN, not that every device powered off.
"""

import copy
import re


def normalize_mac(value) -> str | None:
    if value is None:
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", str(value))
    if len(digits) != 12:
        return None
    pairs = [digits[index : index + 2] for index in range(0, 12, 2)]
    mac = ":".join(pair.lower() for pair in pairs)
    first = int(pairs[0], 16)
    if first & 1 or mac == "00:00:00:00:00:00":
        return None
    return mac


def _blank_device(mac: str | None) -> dict:
    return {
        "mac": mac,
        "ips": [],
        "online": False,
        "misses": 0,
        "offline_alerted": False,
        "last_seen": None,
        "name": "",
        "last_action": "",
    }


def _merge_device(target: dict, incoming: dict) -> None:
    for ip in incoming.get("ips") or []:
        if ip not in target["ips"]:
            target["ips"].append(ip)
    if incoming.get("name") and not target.get("name"):
        target["name"] = incoming["name"]
    if incoming.get("last_seen") and not target.get("last_seen"):
        target["last_seen"] = incoming["last_seen"]
    if incoming.get("last_action") and not target.get("last_action"):
        target["last_action"] = incoming["last_action"]


def update_presence(devices: dict, seen: list, threshold: int, now: str) -> tuple[dict, list]:
    """Return a new device map and the transition events for this scan."""
    devices = copy.deepcopy(devices)
    events = []
    known_before = set(devices)
    staged = []
    for host in seen:
        if host.get("state", "up") != "up":
            continue
        ip = str(host.get("ip") or "").strip()
        if not ip:
            continue
        staged.append(
            {
                "ip": ip,
                "mac": normalize_mac(host.get("mac")),
                "hostname": str(host.get("hostname") or ""),
            }
        )

    for host in staged:
        mac = host["mac"]
        if not mac:
            continue
        ip_key = f"ip:{host['ip']}"
        mac_key = f"mac:{mac}"
        if ip_key not in devices or ip_key == mac_key:
            continue
        incoming = devices.pop(ip_key)
        if ip_key in known_before:
            known_before.add(mac_key)
        incoming["mac"] = mac
        if mac_key in devices:
            _merge_device(devices[mac_key], incoming)
        else:
            devices[mac_key] = incoming

    seen_this_round = set()
    for host in staged:
        mac = host["mac"]
        ip = host["ip"]
        key = f"mac:{mac}" if mac else f"ip:{ip}"
        already = key in seen_this_round
        seen_this_round.add(key)
        current = devices.get(key)
        is_new = current is None
        if current is None:
            current = _blank_device(mac)
        was_online = bool(current.get("online"))
        ips = [item for item in current.get("ips", []) if item != ip]
        ips.append(ip)
        current["ips"] = ips
        current["mac"] = mac or current.get("mac")
        current["online"] = True
        current["misses"] = 0
        current["offline_alerted"] = False
        current["last_seen"] = now
        if host["hostname"]:
            current["name"] = host["hostname"]
        devices[key] = current
        if already:
            continue
        event = {
            "type": "appeared",
            "key": key,
            "ip": ip,
            "mac": mac,
            "name": current.get("name") or "",
        }
        if is_new or key not in known_before:
            events.append(event)
        elif not was_online:
            event["type"] = "recovered"
            events.append(event)

    for key, current in devices.items():
        if key in seen_this_round:
            continue
        if not current.get("online") and current.get("offline_alerted"):
            continue
        current["misses"] = int(current.get("misses", 0)) + 1
        if current["misses"] >= threshold and not current.get("offline_alerted"):
            current["online"] = False
            current["offline_alerted"] = True
            ips = current.get("ips") or [None]
            events.append(
                {
                    "type": "offline",
                    "key": key,
                    "ip": ips[-1],
                    "mac": current.get("mac"),
                    "name": current.get("name") or "",
                    "misses": current["misses"],
                }
            )
        elif current["misses"] >= threshold:
            current["online"] = False
    return devices, events


def apply_scan(devices: dict, seen: list, threshold: int, now: str) -> tuple[dict, list, str]:
    """Update presence. Skip a scan that saw zero hosts while some were online."""
    up = [host for host in seen if host.get("state", "up") == "up" and host.get("ip")]
    if not up and any(item.get("online") for item in devices.values()):
        return devices, [], "empty-scan-skipped"
    updated, events = update_presence(devices, up, threshold, now)
    return updated, events, "ok"


def plan_actions(events: list, cfg: dict, profile_for) -> list:
    """Describe work for this cycle. The monitor performs it."""
    actions = []
    for event in events:
        profile = profile_for(event.get("mac"), event.get("ip"))
        label = event.get("name") or event.get("ip") or "unknown device"
        if event["type"] == "offline":
            if cfg.get("notify_on_offline", True):
                mac = event.get("mac") or "no mac"
                actions.append(
                    {
                        "action": "notify",
                        "text": (
                            f"[!] Offline: {label} ({event.get('ip')}, {mac}) "
                            f"after {event.get('misses')} missed checks."
                        ),
                    }
                )
            if profile and cfg.get("block_magic_packets"):
                actions.append(
                    {
                        "action": "block_hook",
                        "target": event.get("mac") or event.get("ip"),
                        "ip": event.get("ip"),
                    }
                )
            elif profile:
                actions.append(
                    {
                        "action": "note",
                        "text": (
                            f"[wol] {label} is marked block, and block_magic_packets "
                            "is false. No hook ran."
                        ),
                    }
                )
        elif event["type"] in {"appeared", "recovered"} and profile:
            actions.append(
                {
                    "action": "disable_wol_local",
                    "ip": event.get("ip"),
                    "mac": event.get("mac"),
                    "profile": profile,
                }
            )
    return actions
