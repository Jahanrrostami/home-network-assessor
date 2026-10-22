"""Write the HTML and JSON reports.

The HTML escapes every value that came from the network. A device name is
not allowed to become a script when you open the file in a browser.
"""

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment

from analyzer import level_reason
from devices import remember

REPORTS_DIR = Path(__file__).resolve().parent / "reports"

NOTES = [
    "A quiet result is not proof that a device is safe. The hint list is short, and hosts that ignore probes are missing.",
    "Scores describe services open on your LAN. A service the router forwards is marked separately and weighs more.",
    "This report is sensitive. It lists addresses and software versions. Do not publish it.",
]
ADDRESS_NOTES = [
    "These are the addresses that answered on the configured range.",
    "An address that did not answer is missing. A missing address is not proof that nothing is there.",
    "This report is sensitive. It lists addresses on your LAN. Do not publish it.",
]

_ENV = Environment(autoescape=True)
_TEMPLATE = _ENV.from_string(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'">
  <title>Home Network Assessment</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #111; color: #eee; margin: 2rem; line-height: 1.4; }
    h1, h2 { font-weight: 600; }
    .notes, .host, .panel { border: 1px solid #333; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .notes { background: #2a2416; border-color: #a80; }
    .CRITICAL { border-color: #f44; }
    .HIGH { border-color: #f80; }
    .MEDIUM { border-color: #fc0; }
    .LOW { border-color: #0a0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #444; padding: 0.4rem; text-align: left; vertical-align: top; word-break: break-word; }
    .counts span { display: inline-block; margin-right: 1rem; }
  </style>
</head>
<body>
  {% macro device_history() %}
  <h2>Device history</h2>
  <p>Online means the device answered the latest address check, or a later check from this computer got an answer from it. Seen before means it was recorded earlier and was not in that latest address check. Reading this list does not probe.</p>
  {% if devices_seen.last_census_at %}<p>Latest address check: {{ devices_seen.last_census_at }}</p>{% endif %}
  {% if devices_seen.empty_census_kept %}<p>The last address check saw nobody. Earlier devices were kept, because an empty result often means this computer lost the LAN.</p>{% endif %}
  {% if devices_seen.history %}
  <table>
    <tr><th>Address</th><th>Name</th><th>MAC</th><th>Vendor</th><th>Status</th><th>First seen</th><th>Last seen</th></tr>
    {% for device in devices_seen.history %}
    <tr>
      <td>{{ device.ip }}</td>
      <td>{{ device.name or "no name" }}</td>
      <td>{{ device.mac or "n/a" }}</td>
      <td>{{ device.vendor or "n/a" }}</td>
      <td>{{ device.status }}</td>
      <td>{{ device.first_seen }}</td>
      <td>{{ device.last_seen }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No devices have been recorded.</p>
  {% endif %}
  {% endmacro %}
  <h1>Home Network Assessment</h1>
  <p>Generated {{ generated_at }} | Networks: {{ networks | join(", ") }}</p>
  <p>{{ choices.line }}</p>
  {% if not router_check %}
  <p>{{ public_ip_note }}{% if public_ip %} Address: {{ public_ip }}{% endif %}</p>
  <div class="notes">
    <strong>{{ note_title }}</strong>
    <ul>{% for note in notes %}<li>{{ note }}</li>{% endfor %}</ul>
  </div>
  {% endif %}
  {% if address_check %}
  <p class="counts"><span>Online {{ summary.hosts }}</span></p>
  <h2>Online now</h2>
  <p>Addresses that answered on {{ networks | join(", ") }}. These devices answered this check.</p>
  {% if hosts %}
  <table>
    <tr><th>Address</th><th>Name</th><th>MAC</th><th>Vendor</th></tr>
    {% for host in hosts %}
    <tr>
      <td>{{ host.ip }}</td>
      <td>{{ host.hostname or "no name" }}</td>
      <td>{{ host.mac or "n/a" }}</td>
      <td>{{ host.vendor or "n/a" }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No addresses answered.</p>
  {% endif %}
  {{ device_history() }}
  {% elif router_check %}
  {% if router_view.host %}
  <h2>Router {{ router_view.host.ip }}</h2>
  <p>{{ router_view.host.vendor or "Vendor unknown" }}{% if router_view.host.mac %} | MAC {{ router_view.host.mac }}{% endif %}</p>
  {% else %}
  <h2>Router</h2>
  <p>The router did not answer.</p>
  {% endif %}
  <h2>Admin ports that answered</h2>
  {% if router_view.open_ports %}
  <table>
    <tr><th>Port</th><th>Service</th><th>Version</th></tr>
    {% for port in router_view.open_ports %}
    <tr>
      <td>{{ port.port }}/{{ port.proto }}</td>
      <td>{{ port.name }} {{ port.product }}</td>
      <td>{{ port.version }} {{ port.extrainfo }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No admin ports answered.</p>
  {% endif %}
  {% if router_view.quiet_ports %}
  <p>Did not answer: {{ router_view.quiet_ports }}.</p>
  {% endif %}
  <h2>Forwards</h2>
  {% if router_view.mappings %}
  <table>
    <tr><th>External</th><th>Protocol</th><th>Internal</th><th>Name</th></tr>
    {% for item in router_view.mappings %}
    <tr>
      <td>{{ item.external_port }}</td>
      <td>{{ item.protocol }}</td>
      <td>{{ item.internal_client }}:{{ item.internal_port }}</td>
      <td>{{ item.description }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No port forwards were read.</p>
  {% endif %}
  {% if router_view.errors %}
  <ul>{% for err in router_view.errors %}<li>{{ err }}</li>{% endfor %}</ul>
  {% endif %}
  {% else %}
  <p class="counts">
    <span>Hosts {{ summary.hosts }}</span>
    <span>CRITICAL {{ summary.critical }}</span>
    <span>HIGH {{ summary.high }}</span>
    <span>MEDIUM {{ summary.medium }}</span>
    <span>LOW {{ summary.low }}</span>
    <span>Forwards {{ summary.upnp_mappings }}</span>
  </p>
  {% if choices.check == "routers" or choices.check == "all" %}
  <div class="panel">
    <h2>Router forwards</h2>
    {% if exposure.mappings %}
    <table>
      <tr><th>External</th><th>Protocol</th><th>Internal</th><th>On</th><th>Name</th></tr>
      {% for item in exposure.mappings %}
      <tr>
        <td>{{ item.external_port }}</td>
        <td>{{ item.protocol }}</td>
        <td>{{ item.internal_client }}:{{ item.internal_port }}</td>
        <td>{{ item.enabled }}</td>
        <td>{{ item.description }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No port forwards were read. That can mean the router has UPnP off, hid the list, or did not answer.</p>
    {% endif %}
    {% if exposure.errors %}
      <ul>{% for err in exposure.errors %}<li>{{ err }}</li>{% endfor %}</ul>
    {% endif %}
  </div>
  {% endif %}
  {{ device_history() }}
  {% if hosts %}
    {% for host in hosts %}
    <div class="host {{ host.risk_level }}">
      <h2>{{ host.ip }} ({{ host.hostname or "no name" }}) — {{ host.risk_level }} ({{ host.risk_score }})</h2>
      <p>MAC: {{ host.mac or "n/a" }} | Vendor: {{ host.vendor or "n/a" }} | Internet forwarded: {{ "yes" if host.internet_exposed else "no" }}</p>
      {% if host.level_reason %}<p>{{ host.level_reason }}</p>{% endif %}
      {% if host.findings %}
        <ul>
          {% for item in host.findings %}
          <li>{{ item.points }} points: {{ item.text }}</li>
          {% endfor %}
        </ul>
      {% else %}
        <p>No reviewed ports were open in this scan.</p>
      {% endif %}
      {% if host.closed_hidden %}
      <p>Closed ports not listed: {{ host.closed_hidden }}. A closed or filtered port is not the same as safe.</p>
      {% endif %}
      {% if host.report_ports %}
      <table>
        <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th></tr>
        {% for port in host.report_ports %}
        <tr>
          <td>{{ port.port }}</td>
          <td>{{ port.proto }}</td>
          <td>{{ port.state }}</td>
          <td>{{ port.name }} {{ port.product }}{% if port.sentence %}<div>{{ port.sentence }}</div>{% endif %}{% if port.state_note %}<div>{{ port.state_note }}</div>{% endif %}</td>
          <td>{{ port.version }} {{ port.extrainfo }}</td>
        </tr>
        {% endfor %}
      </table>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <p>No hosts were seen.</p>
  {% endif %}
  {% endif %}
</body>
</html>
"""
)


PORT_SENTENCES = {
    (53, "tcp"): "DNS. This is how computers on the LAN ask for names.",
    (53, "udp"): "DNS. This is how computers on the LAN ask for names.",
    (443, "udp"): "QUIC / HTTP/3.",
    (443, "tcp"): "HTTPS.",
    (67, "udp"): "DHCP server.",
    (68, "udp"): "DHCP client.",
    (123, "udp"): "NTP, the time service.",
    (500, "udp"): "IPsec VPN.",
    (4500, "udp"): "IPsec VPN.",
}


def _state_note(state: str) -> str:
    if state in {"filtered", "open|filtered"}:
        return "This computer did not get a normal answer. That is not the same as safe."
    if state == "closed":
        return "Closed from this computer. That is not the same as safe."
    return ""


def _report_ports(host: dict) -> tuple[list, int]:
    rows = host.get("ports")
    if rows is None:
        rows = host.get("open_ports") or []
    closed = []
    parsed = []
    for row in rows:
        try:
            number = int(row["port"])
        except (KeyError, TypeError, ValueError):
            continue
        proto = str(row.get("proto") or "tcp").lower()
        state = str(row.get("state") or "open").lower()
        parsed.append((number, proto, state, row))
        if state == "closed":
            closed.append((number, proto))
    hide_plain_closed = len(closed) > 40
    shown = []
    hidden = 0
    for number, proto, state, row in sorted(parsed, key=lambda item: (item[0], item[1])):
        named = (number, proto) in PORT_SENTENCES
        if state == "closed" and hide_plain_closed and not named:
            hidden += 1
            continue
        shown.append(
            {
                "port": number,
                "proto": proto,
                "state": "filtered" if state == "open|filtered" else state,
                "name": row.get("name") or "",
                "product": row.get("product") or "",
                "version": row.get("version") or "",
                "extrainfo": row.get("extrainfo") or "",
                "sentence": PORT_SENTENCES.get((number, proto), ""),
                "state_note": _state_note(state),
            }
        )
    return shown, hidden


def router_view(hosts: list, exposure: dict) -> dict:
    """The router page: open admin ports, silent ports, and the forward list."""
    host = hosts[0] if hosts else None
    open_ports = []
    quiet = []
    if host:
        for row in host.get("report_ports") or []:
            if row.get("state") == "open":
                open_ports.append(row)
            else:
                quiet.append(str(row.get("port")))
    return {
        "host": host,
        "open_ports": open_ports,
        "quiet_ports": ", ".join(quiet),
        "mappings": exposure.get("mappings") or [],
        "errors": exposure.get("errors") or [],
    }


def build_report(hosts: list, exposure: dict, networks: list, generated_at: str, choices: dict | None = None) -> dict:
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for host in hosts:
        level = host.get("risk_level") or "LOW"
        if level in levels:
            levels[level] += 1
    report_choices = choices or {
        "check": "open-ports",
        "port_scan": "top100",
        "also_services": False,
        "line": "Check: open ports. Port scan: top 100. Also services: no",
    }
    address_check = report_choices.get("check") == "addresses"
    router_check = report_choices.get("check") == "routers"
    notes = list(ADDRESS_NOTES if address_check else NOTES)
    if not hosts:
        notes.append(
            "The scan saw no hosts. From Windows, an elevated terminal lets Nmap use ARP and usually finds more devices."
        )
    ordered = sorted(hosts, key=lambda host: (-int(host.get("risk_score") or 0), str(host.get("ip"))))
    for host in ordered:
        shown, hidden = _report_ports(host)
        host["report_ports"] = shown
        host["closed_hidden"] = hidden
        host["level_reason"] = level_reason(
            str(host.get("risk_level") or "LOW"),
            int(host.get("risk_score") or 0),
            host.get("findings") or [],
            bool(host.get("internet_exposed")),
        )
    return {
        "generated_at": generated_at,
        "choices": report_choices,
        "networks": list(networks),
        "public_ip": exposure.get("public_ip"),
        "public_ip_note": exposure.get("public_ip_note") or "",
        "summary": {
            "hosts": len(hosts),
            "critical": levels["CRITICAL"],
            "high": levels["HIGH"],
            "medium": levels["MEDIUM"],
            "low": levels["LOW"],
            "upnp_devices": len(exposure.get("devices") or []),
            "upnp_mappings": len(exposure.get("mappings") or []),
        },
        "notes": notes,
        "note_title": "What this list is" if address_check else "Read this before the scores",
        "address_check": address_check,
        "router_check": router_check,
        "router_view": router_view(ordered, exposure) if router_check else None,
        "exposure": {
            "devices": exposure.get("devices") or [],
            "mappings": exposure.get("mappings") or [],
            "errors": exposure.get("errors") or [],
        },
        "hosts": ordered,
        "devices_seen": {
            "last_census_at": "",
            "online": [],
            "history": [],
            "empty_census_kept": False,
        },
    }


def render_html(report: dict) -> str:
    return _TEMPLATE.render(**report)


def write_reports(report: dict, directory: Path | None = None) -> dict:
    folder = Path(directory) if directory else REPORTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    check = str((report.get("choices") or {}).get("check") or "")
    report["devices_seen"] = remember(
        report.get("hosts") or [],
        str(report.get("generated_at") or ""),
        check == "addresses",
        folder,
    )
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html = render_html(report)
    payload = json.dumps(report, indent=2)
    html_path = folder / f"report_{stamp}.html"
    json_path = folder / f"report_{stamp}.json"
    latest_html = folder / "latest.html"
    latest_json = folder / "latest.json"
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(payload, encoding="utf-8")
    latest_html.write_text(html, encoding="utf-8")
    latest_json.write_text(payload, encoding="utf-8")
    return {
        "html": html_path,
        "json": json_path,
        "latest_html": latest_html,
        "latest_json": latest_json,
    }
