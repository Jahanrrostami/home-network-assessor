"""Watch the LAN and react when a known device stays missing.

Discovery uses a ping scan, not a version scan. A full version scan every few
minutes is noisy for printers and cameras. The offline decision waits for
several missed checks so one ignored ping is not treated as a powered-off PC.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from actions import disable_wol_over_ssh, run_block_hook
from devices import load_roster, mark_offline, remember
from presence import apply_scan, plan_actions
from profiles import blocker_lookup, load_profiles
from scanner import ScanError, discovery_arguments, scan_network

STATE_PATH = Path(__file__).resolve().parent / "reports" / "presence_state.json"


def running_as_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        broken = path.with_name(path.stem + ".bad.json")
        path.replace(broken)
        print(f"[!] State file was unreadable and was moved to {broken.name}. Starting fresh.")
        return {}
    devices = data.get("devices") if isinstance(data, dict) else None
    if not isinstance(devices, dict):
        return {}
    return devices


def save_state(path: Path, devices: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"devices": devices}, indent=2), encoding="utf-8")
    temporary.replace(path)


def discover_hosts(cfg: dict) -> list:
    hosts = []
    for network in cfg["networks"]:
        result = scan_network(network, cfg, arguments=discovery_arguments(cfg))
        hosts.extend(result["hosts"])
    return hosts


def perform(action: dict, ssh_runner=disable_wol_over_ssh, hook_runner=run_block_hook) -> str:
    kind = action.get("action")
    if kind == "disable_wol_local":
        return ssh_runner(action["profile"], action["ip"])
    if kind == "block_hook":
        try:
            return hook_runner(action.get("target") or "")
        except ValueError as exc:
            return f"[hook] skipped: {exc}"
    return str(action.get("text") or "")


def monitor_loop(
    cfg: dict,
    sleep=time.sleep,
    discover=None,
    profile_for=None,
    state_file: Path | None = None,
    cycle_limit: int | None = None,
    ssh_runner=disable_wol_over_ssh,
    hook_runner=run_block_hook,
    clock=None,
) -> dict:
    state_path = Path(state_file) if state_file else STATE_PATH
    devices = load_state(state_path)
    lookup = profile_for or blocker_lookup(load_profiles(), cfg.get("wol_block_list") or [])
    find = discover or (lambda: discover_hosts(cfg))
    stamp = clock or (lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    interval = int(cfg["monitor_interval_seconds"])
    threshold = int(cfg["missed_checks_before_offline"])
    print(f"[*] Monitor started. Interval {interval}s. Offline after {threshold} missed checks. Ctrl+C stops.")
    if not cfg.get("block_magic_packets"):
        print("[*] Magic-packet hook is off (block_magic_packets: false). Offline devices are only reported.")
    if not running_as_admin():
        print("[*] This terminal is not elevated. Discovery may miss devices that ignore ping. MAC addresses may be incomplete.")
    cycles = 0
    while True:
        try:
            seen = find()
        except ScanError as exc:
            print(f"[!] Discovery failed. Miss counters were not changed. {exc}")
            cycles += 1
            if cycle_limit is not None and cycles >= cycle_limit:
                return devices
            sleep(interval)
            continue
        moment = stamp()
        devices, events, status = apply_scan(devices, seen, threshold, moment)
        if status == "empty-scan-skipped":
            print("[!] Discovery saw nobody. Miss counters were not moved. An empty result usually means this computer lost the LAN.")
        for action in plan_actions(events, cfg, lookup):
            message = perform(action, ssh_runner=ssh_runner, hook_runner=hook_runner)
            if message:
                print(message)
        save_state(state_path, devices)
        if status == "ok":
            remember(seen, moment, False, state_path.parent)
            offline_keys = [event.get("key") for event in events if event.get("type") == "offline" and event.get("key")]
            if offline_keys:
                mark_offline(state_path.parent, offline_keys)
            view = load_roster(state_path.parent)
            pending = sum(1 for item in devices.values() if item.get("online") and item.get("misses"))
            print(
                f"[*] Online now: {len(view['online'])}. Waiting out a miss: {pending}. "
                f"Device history: {len(view['history'])}. Sleeping {interval}s."
            )
            for device in view["online"]:
                print(
                    f"[*] Online {device.get('ip') or 'no address'}  "
                    f"{device.get('name') or 'no name'}  {device.get('mac') or 'n/a'}"
                )
        else:
            pending = sum(1 for item in devices.values() if item.get("online") and item.get("misses"))
            print(f"[*] Online in state: {sum(1 for item in devices.values() if item.get('online'))}. Waiting out a miss: {pending}. Sleeping {interval}s.")
        cycles += 1
        if cycle_limit is not None and cycles >= cycle_limit:
            return devices
        sleep(interval)
    return devices
