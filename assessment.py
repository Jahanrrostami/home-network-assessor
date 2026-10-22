"""One chosen check: run its fixed profiles, score, and build one report."""

from datetime import datetime, timezone

from analyzer import analyze_hosts
from exposure import collect_exposure
from network_guard import assert_private_target
from reporter import build_report
from scanner import (
    argument_plan,
    choice_line,
    fill_named_unanswered,
    merge_hosts,
    read_default_gateway,
    scan_network,
)


def run_scan(cfg: dict, scan=scan_network, exposure=collect_exposure, gateway=None) -> dict:
    check = cfg.get("check")
    port_scan = cfg.get("port_scan")
    also_services = bool(cfg.get("also_services"))
    plan = argument_plan(check, port_scan, also_services)
    groups = []
    gateway_ip = None
    saw_services = False
    reads_router = False
    for step in plan:
        if step["phase"] == "services":
            saw_services = True
        if step["phase"] == "routers":
            reads_router = True
        if step["target"] == "gateway":
            if gateway_ip is None:
                gateway_ip = (gateway or read_default_gateway)()
            assert_private_target(gateway_ip)
            result = scan(gateway_ip, cfg, arguments=step["arguments"])
            groups.append(result["hosts"])
            continue
        for network in cfg["networks"]:
            assert_private_target(network)
            result = scan(network, cfg, arguments=step["arguments"])
            groups.append(result["hosts"])
    hosts = merge_hosts(groups)
    if saw_services:
        fill_named_unanswered(hosts)
    if reads_router:
        seen = exposure(cfg)
    else:
        seen = {
            "devices": [],
            "mappings": [],
            "errors": [],
            "public_ip": None,
            "public_ip_note": "UPnP was not part of this check.",
        }
    analyzed = analyze_hosts(hosts, cfg.get("critical_ports") or [], seen.get("mappings") or [])
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return build_report(
        analyzed,
        seen,
        cfg["networks"],
        generated,
        choices={
            "check": check,
            "port_scan": port_scan,
            "also_services": also_services,
            "line": choice_line(check, port_scan, also_services),
        },
    )
