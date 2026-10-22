"""Load per-device Wake-on-LAN wishes.

Files whose names start with "example" are documentation and are ignored.
Copy one to a new name, such as living-room.yaml, when you want it to apply.
"""

from pathlib import Path

import yaml

from presence import normalize_mac
from settings import ConfigError

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"


def load_profiles(directory: Path | None = None) -> dict:
    folder = Path(directory) if directory else PROFILES_DIR
    profiles: dict[str, dict] = {}
    if not folder.exists():
        return profiles
    for path in sorted(folder.glob("*.yaml")):
        if path.name.lower().startswith("example"):
            continue
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{path.name} must be a mapping")
        wol = str(data.get("desired_wol", "allow")).lower()
        if wol not in {"allow", "block"}:
            raise ConfigError(f"{path.name} desired_wol must be allow or block")
        data["desired_wol"] = wol
        mac = normalize_mac(data.get("mac")) if data.get("mac") else None
        ip = str(data.get("ip") or "").strip()
        if mac:
            data["mac"] = mac
            profiles[mac] = data
        if ip:
            data["ip"] = ip
            profiles[ip] = data
        if not mac and not ip:
            raise ConfigError(f"{path.name} needs a mac or an ip")
    return profiles


def blocker_lookup(profiles: dict, block_list: list):
    """Return a function that yields a profile when Wake-on-LAN should be blocked."""
    listed = set()
    for item in block_list or []:
        mac = normalize_mac(item)
        listed.add(mac if mac else str(item).strip())

    def profile_for(mac, ip):
        mac = normalize_mac(mac)
        keys = [key for key in (mac, str(ip).strip() if ip else None) if key]
        for key in keys:
            profile = profiles.get(key)
            if profile and profile.get("desired_wol") == "block":
                return profile
            if key in listed:
                return profile or {"desired_wol": "block", "mac": mac, "ip": ip}
        return None

    return profile_for
