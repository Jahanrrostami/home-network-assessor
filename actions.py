"""Optional follow-ups for a device you marked as "block".

Local disable runs one fixed command over SSH:
    ethtool -s <interface> wol d
There is no field for an arbitrary command, and no password is read.

The firewall hook only runs when block_magic_packets is true. The scripts
shipped with this project log the request and do not change a firewall.
"""

import os
import re
import subprocess
from pathlib import Path

from network_guard import address_is_allowed
from presence import normalize_mac

HOOKS_DIR = Path(__file__).resolve().parent / "hooks"
_USER = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,14}$")


class ActionError(ValueError):
    """A follow-up was refused before it ran."""


def hook_target(mac, ip) -> str:
    """Accept a unicast MAC or a private IPv4 address and nothing else."""
    normalized = normalize_mac(mac) if mac else None
    if normalized:
        return normalized
    text = str(ip or "").strip()
    import ipaddress

    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ActionError("The hook target must be a MAC or a private IPv4 address") from exc
    if address.version != 4 or not address_is_allowed(address):
        raise ActionError("The hook target must be a MAC or a private IPv4 address")
    return str(address)


def ssh_problem(profile: dict, ip: str) -> str | None:
    """Return a reason to skip SSH, or None when the fixed command may run."""
    user = str(profile.get("ssh_user") or "").strip()
    identity = str(profile.get("ssh_identity_file") or "").strip()
    interface = str(profile.get("interface") or "").strip()
    if not user and not identity and not interface:
        return (
            f"[wol] {ip} is marked block. Local Wake-on-LAN disable was skipped because "
            "the profile has no ssh_user, ssh_identity_file, and interface."
        )
    missing = [
        name
        for name, value in (("ssh_user", user), ("ssh_identity_file", identity), ("interface", interface))
        if not value
    ]
    if missing:
        return f"[wol] {ip} is missing {', '.join(missing)}. Local disable was skipped."
    if not _USER.match(user):
        return f"[wol] ssh_user {user!r} is not a plain account name. Local disable was skipped."
    if not _INTERFACE.match(interface):
        return f"[wol] interface {interface!r} is not a plain device name. Local disable was skipped."
    identity_path = Path(identity)
    if not identity_path.is_file():
        return f"[wol] SSH key not found at {identity_path}. Local disable was skipped."
    import ipaddress

    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return f"[wol] {ip!r} is not an IP address. Local disable was skipped."
    if not address_is_allowed(address):
        return f"[wol] {ip} is not a private address. Local disable was skipped."
    return None


def disable_wol_over_ssh(profile: dict, ip: str, runner=None) -> str:
    problem = ssh_problem(profile, ip)
    if problem:
        return problem
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
        str(profile["ssh_identity_file"]),
        f"{profile['ssh_user']}@{ip}",
        "ethtool",
        "-s",
        str(profile["interface"]),
        "wol",
        "d",
    ]
    run = runner or subprocess.run
    try:
        completed = run(command, capture_output=True, text=True, timeout=20, check=False)
    except FileNotFoundError:
        return "[wol] ssh was not found. Install the OpenSSH client, or leave the SSH fields empty."
    except subprocess.TimeoutExpired:
        return f"[wol] ssh to {ip} timed out."
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    tail = detail[-1] if detail else "no output"
    if completed.returncode == 0:
        return f"[wol] Wake-on-LAN disabled on {ip} interface {profile['interface']}."
    return f"[wol] ssh to {ip} failed ({completed.returncode}): {tail}"


def run_block_hook(target: str, runner=None) -> str:
    clean = hook_target(target, None) if normalize_mac(target) else hook_target(None, target)
    script = HOOKS_DIR / ("block_magic_packet.ps1" if os.name == "nt" else "block_magic_packet.sh")
    if not script.is_file():
        return f"[hook] {script.name} is missing. No firewall change was made."
    if os.name == "nt":
        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            clean,
        ]
    else:
        command = ["bash", str(script), clean]
    run = runner or subprocess.run
    try:
        completed = run(command, capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError:
        return "[hook] The hook shell was not found. No firewall change was made."
    except subprocess.TimeoutExpired:
        return "[hook] The hook timed out. No further action was taken."
    message = (completed.stdout or completed.stderr or "").strip()
    return f"[hook] exit {completed.returncode}: {message}"
