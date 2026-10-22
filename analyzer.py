"""Turn open ports, version hints, and router forwards into a score.

LAN points answer "what is running inside the house?".
A router forward answers "can the internet reach it?".
Those are different questions, so a normal Windows PC with file sharing is not
treated the same as a PC whose remote desktop is forwarded.

The hint file is a short starter list. No match does not mean the service is safe.
"""

import json
import re
from pathlib import Path

HINTS_PATH = Path(__file__).resolve().parent / "cve_db" / "hints.json"

# always: true means the port is flagged even if you delete it from config.yaml.
# always: false means it is flagged only when it is on your review list.
PORT_RULES = {
    23: {
        "points": 40,
        "always": True,
        "text": "Telnet is open. It sends logins without encryption. Turn the service off.",
    },
    21: {
        "points": 40,
        "always": True,
        "text": "FTP is open. It sends logins without encryption. Turn it off and use a current file-transfer service.",
    },
    5900: {
        "points": 40,
        "always": True,
        "text": "VNC is open. Many setups use a short or empty password. Turn it off unless you are actively using it, and do not forward it from the router.",
    },
    554: {
        "points": 25,
        "always": True,
        "text": "RTSP is open. Home cameras often answer here. Confirm this camera is one you installed, and do not forward the port from the router.",
    },
    1883: {
        "points": 20,
        "always": True,
        "text": "MQTT is open. Home sensors often use this port with no login. Keep it on the LAN, and turn on authentication if the broker offers it.",
    },
    445: {
        "points": 15,
        "always": True,
        "text": "SMB file sharing is open. That is common on a Windows PC. Keep the computer patched, and make sure the router does not forward port 445.",
    },
    3389: {
        "points": 15,
        "always": True,
        "text": "Remote Desktop is open. That is common on a Windows PC you manage. Keep the computer patched, and make sure the router does not forward port 3389.",
    },
    22: {
        "points": 10,
        "always": False,
        "text": "SSH is open. Confirm you meant to run it, and prefer key login.",
    },
    80: {
        "points": 10,
        "always": False,
        "text": "HTTP is open. Router and device admin pages are often here. Do not forward this port unless you have a specific need.",
    },
    443: {
        "points": 10,
        "always": False,
        "text": "HTTPS is open. Confirm the site is one you meant to run, and do not forward the admin page to the internet.",
    },
    8080: {
        "points": 10,
        "always": False,
        "text": "An alternate HTTP port is open. NAS consoles and old dev servers often sit here and get forgotten. Close it if you do not recognize it.",
    },
}

EXPOSURE_POINTS = 30
# Forwarding one of these is CRITICAL even when the LAN-only score is modest.
CRITICAL_IF_EXPOSED = {21, 23, 445, 3389, 5900, 554, 1883}


class HintsError(ValueError):
    """The local hint file cannot be used."""


_REQUEST_LINE = re.compile(r"(?i)\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH|CONNECT)\s+/\S*")
_PAYLOAD = re.compile(r"(?i)\bpayload\b")
_COMMAND = re.compile(
    r"(?i)(\bcurl\b|\bwget\b|\bncat\b|\bnc\s+-|\bbash\s+-c\b|\bsh\s+-c\b|\bpowershell\b|\bcmd(?:\.exe)?\s+/c\b|\bpython\d?\s+-c\b|`[^`]+`)"
)
SCRIPT_POINTS = 30


def text_has_exploit_detail(text: str) -> bool:
    """True when script output contains a command, a payload, or a request line."""
    if not text:
        return False
    return bool(_REQUEST_LINE.search(text) or _PAYLOAD.search(text) or _COMMAND.search(text))


def script_finding(script_id: str, port: int | None, proto: str, output: str) -> dict:
    """Turn one Nmap script result into a finding. Exploit text is not kept."""
    where = f" on port {port}/{proto}" if port else ""
    if text_has_exploit_detail(output):
        text = f"Script {script_id}{where}. Review the vendor advisory."
    else:
        summary = " ".join(str(output or "").split())
        if len(summary) > 180:
            summary = summary[:177] + "..."
        if summary and text_has_exploit_detail(summary):
            summary = ""
        if summary:
            text = (
                f"Script {script_id}{where} reported: {summary} "
                "Review the vendor advisory and upgrade if the vendor has a fix."
            )
        else:
            text = f"Script {script_id}{where}. Review the vendor advisory and upgrade if the vendor has a fix."
    return _finding(SCRIPT_POINTS, text, f"script:{script_id}:{port or 0}/{proto or '-'}")


def _finding(points: int, text: str, source: str) -> dict:
    if points >= 30:
        severity = "HIGH"
    elif points >= 15:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return {"severity": severity, "points": points, "source": source, "text": text}


def level_for(score: int, exposed_ports: set[int]) -> str:
    if exposed_ports & CRITICAL_IF_EXPOSED or score >= 70:
        return "CRITICAL"
    if exposed_ports or score >= 40:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    return "LOW"


def level_reason(level: str, score: int, findings: list, internet_exposed: bool) -> str:
    """Say which rule set the level, and name each finding that added points."""
    causes = []
    for item in findings or []:
        text = " ".join(str(item.get("text") or "").split())
        if not text:
            continue
        causes.append(f"{text} ({item.get('points')} points)")
    if level == "CRITICAL":
        if internet_exposed and score < 70:
            rule = (
                f"CRITICAL because a forwarded port is in the dangerous set "
                f"(21, 23, 445, 3389, 5900, 554, or 1883). The score is {score}."
            )
        elif internet_exposed:
            rule = (
                f"CRITICAL because the score is {score} and a forwarded port is in the dangerous set "
                "(21, 23, 445, 3389, 5900, 554, or 1883). A score of 70 or more, or one of those forwards, is CRITICAL."
            )
        else:
            rule = f"CRITICAL because the score is {score}. A score of 70 or more is CRITICAL."
    elif level == "HIGH":
        if internet_exposed and score < 40:
            rule = f"HIGH because a port is forwarded to this address. The score is {score}. Any forward is at least HIGH."
        elif internet_exposed:
            rule = (
                f"HIGH because the score is {score} and a port is forwarded. "
                "A score of 40 or more, or any forward, is HIGH."
            )
        else:
            rule = f"HIGH because the score is {score}. A score of 40 or more is HIGH."
    elif level == "MEDIUM":
        rule = f"MEDIUM because the score is {score}. A score from 10 to 39 is MEDIUM."
    elif findings:
        rule = f"LOW because the score is {score}, which is under 10, and nothing is forwarded."
    else:
        return (
            "LOW because this scan added no points. No reviewed service was open, "
            "and no vulnerability script reported a problem. Scripts only report on ports that answer, "
            "and this scan only covered the ports you chose. A quiet result is not proof the device is safe."
        )
    if causes:
        return rule + " Cause: " + " ".join(causes)
    return rule


def load_hints(path: Path | None = None) -> list:
    hint_path = Path(path) if path else HINTS_PATH
    try:
        data = json.loads(hint_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HintsError(f"Hint file not found: {hint_path}") from exc
    except json.JSONDecodeError as exc:
        raise HintsError(f"Hint file is not valid JSON: {hint_path}") from exc
    products = data.get("products") if isinstance(data, dict) else None
    if not isinstance(products, list):
        raise HintsError("cve_db/hints.json must contain a products list")
    return products


def _token_in(haystack: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token.lower())}(?![a-z0-9])", haystack) is not None


def _version_key(text: str) -> tuple | None:
    match = re.search(r"(\d+(?:\.\d+){1,3})", text or "")
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _same_version(found: str, wanted: str) -> bool:
    left = _version_key(found)
    right = _version_key(wanted)
    if left is None or right is None:
        return False
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return left == right


def _older_than(found: str, threshold: str) -> bool:
    left = _version_key(found)
    right = _version_key(threshold)
    if left is None or right is None:
        return False
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return left < right


def _matches_product(identity: str, product: dict) -> bool:
    if any(_token_in(identity, token) for token in product.get("exclude_any") or []):
        return False
    return any(_token_in(identity, token) for token in product.get("match_any") or [])


def hint_findings(port: dict, products: list) -> list:
    identity = f"{port.get('name') or ''} {port.get('product') or ''}".lower()
    detail = " ".join(str(port.get(key) or "") for key in ("product", "version", "extrainfo"))
    findings = []
    for product in products:
        if not _matches_product(identity, product):
            continue
        matched = []
        best = 0
        for item in product.get("equals") or []:
            if any(_same_version(detail, version) for version in item.get("versions") or []):
                matched.append(item)
                best = max(best, int(item.get("points") or 0))
        if matched:
            findings.append(_finding(best, " ".join(item["summary"] for item in matched), f"hint:{product['id']}"))
            continue
        band_hit = None
        for band in product.get("older_than") or []:
            if _older_than(detail, band.get("version") or ""):
                if band_hit is None or int(band.get("points") or 0) > int(band_hit.get("points") or 0):
                    band_hit = band
        if band_hit:
            findings.append(_finding(int(band_hit["points"]), band_hit["summary"], f"hint:{product['id']}"))
    return findings


def _port_finding(number: int, critical_ports: set[int]) -> dict | None:
    rule = PORT_RULES.get(number)
    if rule and (rule["always"] or number in critical_ports):
        return _finding(rule["points"], rule["text"], f"port:{number}")
    if number in critical_ports:
        return _finding(
            10,
            f"Port {number} is on your review list in config.yaml. Confirm the program that owns it is one you want running.",
            f"port:{number}",
        )
    return None


def _mapping_enabled(mapping: dict) -> bool:
    enabled = mapping.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    return str(enabled).strip().lower() in {"1", "true", "yes"}


def _exposure_findings(host: dict) -> list:
    open_ports = {int(item["port"]) for item in host.get("open_ports") or [] if "port" in item}
    findings = []
    for mapping in host.get("mappings") or []:
        if not _mapping_enabled(mapping):
            continue
        try:
            internal = int(mapping["internal_port"])
            external = int(mapping["external_port"])
        except (KeyError, TypeError, ValueError):
            continue
        protocol = str(mapping.get("protocol") or "TCP").upper()
        text = (
            f"The router forwards {protocol} port {external} to {host['ip']}:{internal}. "
            "That path reaches this computer from the internet while the mapping stays on. "
            "Remove the mapping if you do not need it."
        )
        if internal not in open_ports:
            text += " The scan did not see that internal port open. The mapping still matters, because the service becomes reachable from the internet as soon as it starts."
        findings.append(_finding(EXPOSURE_POINTS, text, f"upnp:{external}/{protocol}"))
    return findings


def _prepare_hosts(hosts: list, mappings: list) -> list:
    prepared = []
    by_ip = {}
    for host in hosts:
        item = {
            "ip": str(host.get("ip") or ""),
            "hostname": host.get("hostname") or "",
            "state": host.get("state") or "up",
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "ports": [],
            "open_ports": [],
            "host_scripts": [],
            "mappings": [],
        }
        incoming = host.get("ports")
        if incoming is None:
            incoming = host.get("open_ports") or []
        for port in incoming:
            try:
                number = int(port["port"])
            except (KeyError, TypeError, ValueError):
                continue
            state = str(port.get("state") or "open").lower()
            row = {
                "port": number,
                "proto": str(port.get("proto") or "tcp").lower(),
                "state": state,
                "name": port.get("name") or "",
                "product": port.get("product") or "",
                "version": port.get("version") or "",
                "extrainfo": port.get("extrainfo") or "",
                "scripts": [
                    {"id": str(script.get("id") or ""), "output": str(script.get("output") or "")}
                    for script in (port.get("scripts") or [])
                    if script.get("id")
                ],
            }
            item["ports"].append(row)
            if state == "open":
                item["open_ports"].append(row)
        for script in host.get("host_scripts") or []:
            if script.get("id"):
                item["host_scripts"].append({"id": str(script.get("id")), "output": str(script.get("output") or "")})
        if item["ip"]:
            prepared.append(item)
            by_ip[item["ip"]] = item

    for mapping in mappings or []:
        if not _mapping_enabled(mapping):
            continue
        ip = str(mapping.get("internal_client") or "").strip()
        if not ip:
            continue
        host = by_ip.get(ip)
        if host is None:
            host = {
                "ip": ip,
                "hostname": "",
                "state": "unseen",
                "mac": None,
                "vendor": None,
                "ports": [],
                "open_ports": [],
                "host_scripts": [],
                "mappings": [],
            }
            prepared.append(host)
            by_ip[ip] = host
        host["mappings"].append(mapping)
    return prepared


def analyze_hosts(hosts: list, critical_ports: list, mappings: list | None = None, hints: list | None = None) -> list:
    """Return scored copies of the hosts. The caller's list is left as it was."""
    products = load_hints() if hints is None else hints
    wanted = {int(port) for port in critical_ports or []}
    scored = []
    for host in _prepare_hosts(hosts, mappings or []):
        findings = []
        exposed_ports = set()
        for port in sorted(host["open_ports"], key=lambda item: (item["port"], item["proto"])):
            found = _port_finding(port["port"], wanted)
            if found:
                findings.append(found)
            findings.extend(hint_findings(port, products))
        for port in host["ports"]:
            for script in port.get("scripts") or []:
                findings.append(script_finding(script["id"], port["port"], port["proto"], script.get("output") or ""))
            port["scripts"] = []
        for script in host.get("host_scripts") or []:
            findings.append(script_finding(script["id"], None, "", script.get("output") or ""))
        host["host_scripts"] = []
        for found in _exposure_findings(host):
            findings.append(found)
        for mapping in host["mappings"]:
            if _mapping_enabled(mapping):
                try:
                    exposed_ports.add(int(mapping["internal_port"]))
                except (KeyError, TypeError, ValueError):
                    continue
        deduped = []
        seen = set()
        for found in findings:
            key = (found["source"], found["text"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(found)
        score = sum(item["points"] for item in deduped)
        host["findings"] = deduped
        host["risk_score"] = score
        host["risk_level"] = level_for(score, exposed_ports)
        host["internet_exposed"] = bool(exposed_ports)
        host["level_reason"] = level_reason(host["risk_level"], score, deduped, host["internet_exposed"])
        scored.append(host)
    return scored
