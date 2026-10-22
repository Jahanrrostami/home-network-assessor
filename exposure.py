"""See whether the home router is publishing ports.

This module only reads. It sends a UPnP discovery on the LAN and, when the
router answers with a private address, asks for the existing port-forward list.
It never adds or deletes a mapping.

A LOCATION header that is not a private IP is ignored. Discovery responses are
not trusted enough to make this computer request a public URL.
"""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from network_guard import address_is_allowed

SSDP_ADDRESS = ("239.255.255.250", 1900)
ALLOWED_SERVICES = {
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:2",
}
_MAX_BYTES = 1_000_000
_MAX_MAPPINGS = 64
_PUBLIC_IP_URL = "https://api.ipify.org"


class RedirectRefused(Exception):
    """The router tried to send the fetch somewhere else."""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def url_is_safe(url: str) -> bool:
    """True only for http(s) aimed at a private IP, with no userinfo and no DNS name."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.username or parsed.password:
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address_is_allowed(ip)


def assert_safe_http_url(url: str) -> str:
    if not url_is_safe(url):
        raise ValueError(f"Refusing URL that is not a private router address: {url}")
    return url


def parse_ssdp_response(payload: str) -> dict:
    fields = {}
    for line in payload.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        fields[name.strip().lower()] = value.strip()
    return {
        "location": fields.get("location", ""),
        "server": fields.get("server", ""),
        "st": fields.get("st", ""),
        "usn": fields.get("usn", ""),
    }


def discover_ssdp(timeout: float, socket_factory=socket.socket) -> list:
    """Ask the LAN for InternetGatewayDevice responses. Errors come back as data."""
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n"
    )
    found = []
    sock = None
    try:
        sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(message.encode("ascii"), SSDP_ADDRESS)
        while len(found) < 20:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            parsed = parse_ssdp_response(data.decode("utf-8", errors="ignore"))
            parsed["source"] = addr[0]
            found.append(parsed)
    except Exception as exc:
        found.append({"error": str(exc)})
    finally:
        if sock is not None:
            sock.close()
    return found


def _reject_doctype(text: str) -> None:
    folded = text[:2000].upper()
    if "<!DOCTYPE" in folded or "<!ENTITY" in folded:
        raise ValueError("Refusing XML that declares a document type")


def control_urls(description_xml: str, base_url: str) -> list:
    """Return (absolute control URL, service URN) pairs that stay on a private host."""
    _reject_doctype(description_xml)
    root = ET.fromstring(description_xml)
    found = []
    for service in root.iter():
        if _local_name(service.tag) != "service":
            continue
        fields = {_local_name(child.tag): (child.text or "").strip() for child in list(service)}
        urn = fields.get("serviceType", "")
        control = fields.get("controlURL", "")
        if urn not in ALLOWED_SERVICES or not control:
            continue
        absolute = urllib.parse.urljoin(base_url, control)
        if not url_is_safe(absolute):
            continue
        found.append((absolute, urn))
    return found


def soap_body(service_urn: str, index: int) -> str:
    if service_urn not in ALLOWED_SERVICES:
        raise ValueError("Unknown UPnP service")
    if not isinstance(index, int) or index < 0:
        raise ValueError("Bad mapping index")
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:GetGenericPortMappingEntry xmlns:u="{service_urn}">'
        f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
        "</u:GetGenericPortMappingEntry>"
        "</s:Body></s:Envelope>"
    )


def _xml_values(text: str) -> dict:
    _reject_doctype(text)
    root = ET.fromstring(text)
    values = {}
    for element in root.iter():
        values[_local_name(element.tag)] = (element.text or "").strip()
    return values


def parse_error_code(text: str) -> str | None:
    try:
        return _xml_values(text).get("errorCode") or None
    except (ET.ParseError, ValueError):
        return None


def parse_mapping(text: str) -> dict | None:
    try:
        values = _xml_values(text)
    except (ET.ParseError, ValueError):
        return None
    try:
        external = int(values.get("NewExternalPort") or "")
        internal = int(values.get("NewInternalPort") or "")
    except ValueError:
        return None
    if not 1 <= external <= 65535 or not 1 <= internal <= 65535:
        return None
    protocol = (values.get("NewProtocol") or "").upper()
    if protocol not in {"TCP", "UDP"}:
        return None
    client = values.get("NewInternalClient") or ""
    if not address_is_allowed(client):
        return None
    enabled = (values.get("NewEnabled") or "").strip() in {"1", "true", "True", "yes"}
    description = (values.get("NewPortMappingDescription") or "")[:80]
    return {
        "external_port": external,
        "protocol": protocol,
        "internal_client": client,
        "internal_port": internal,
        "enabled": enabled,
        "description": description,
    }


def enumerate_mappings(control_url: str, service_urn: str, soap_post, limit: int = _MAX_MAPPINGS) -> list:
    """Walk mapping index 0, 1, 2... and stop when the router says the list is over."""
    assert_safe_http_url(control_url)
    mappings = []
    for index in range(limit):
        status, text = soap_post(control_url, service_urn, soap_body(service_urn, index))
        if parse_error_code(text) == "713":
            break
        if status != 200:
            break
        item = parse_mapping(text)
        if item is None:
            continue
        mappings.append(item)
    return mappings


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused(newurl)


def _opener():
    return urllib.request.build_opener(_RefuseRedirect)


def _read_limited(response) -> str:
    data = response.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise ValueError("Router response was larger than 1 MB and was dropped")
    return data.decode("utf-8", errors="replace")


def default_http_get(url: str, timeout: float) -> str:
    assert_safe_http_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "home-network-assessor"})
    with _opener().open(request, timeout=timeout) as response:
        return _read_limited(response)


def default_soap_post(url: str, service_urn: str, body: str, timeout: float = 5) -> tuple[int, str]:
    assert_safe_http_url(url)
    request = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        headers={
            "User-Agent": "home-network-assessor",
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{service_urn}#GetGenericPortMappingEntry"',
        },
        method="POST",
    )
    try:
        with _opener().open(request, timeout=timeout) as response:
            return response.status, _read_limited(response)
    except urllib.error.HTTPError as exc:
        payload = exc.read(_MAX_BYTES + 1)
        if len(payload) > _MAX_BYTES:
            return exc.code, ""
        return exc.code, payload.decode("utf-8", errors="replace")


def lookup_public_ip(opener=None) -> tuple[str | None, str]:
    """Ask ipify for this network's public address. Used only when config turns it on."""
    request = urllib.request.Request(_PUBLIC_IP_URL, headers={"User-Agent": "home-network-assessor"})
    try:
        open_func = opener or _opener().open
        with open_func(request, timeout=5) as response:
            data = response.read(64)
        text = data.decode("ascii", errors="strict").strip()
        ipaddress.ip_address(text)
    except Exception:
        return None, "Public IP lookup failed. The rest of the report is still valid."
    return text, "Public address reported by api.ipify.org. That service sees this computer's request."


def collect_exposure(cfg: dict, socket_factory=socket.socket, http_get=None, soap_post=None) -> dict:
    """Discover gateways and read their forwards. Failures are stored, not raised."""
    timeout = int(cfg.get("upnp_timeout_seconds") or 4)
    result = {
        "devices": [],
        "mappings": [],
        "errors": [],
        "public_ip": None,
        "public_ip_note": "",
    }
    if cfg.get("lookup_public_ip"):
        result["public_ip"], result["public_ip_note"] = lookup_public_ip()
    else:
        result["public_ip_note"] = (
            "Public IP lookup is off. Set lookup_public_ip: true in config.yaml to enable it."
        )

    getter = http_get or (lambda url: default_http_get(url, timeout))
    poster = soap_post or (lambda url, urn, body: default_soap_post(url, urn, body, timeout))
    responses = discover_ssdp(timeout, socket_factory=socket_factory)
    for response in responses:
        if response.get("error"):
            result["errors"].append(response["error"])
            continue
        location = response.get("location") or ""
        device = {
            "source": response.get("source") or "",
            "server": (response.get("server") or "")[:120],
            "location": location if url_is_safe(location) else "",
            "status": "seen",
            "detail": "",
        }
        if not location or not url_is_safe(location):
            device["status"] = "skipped"
            device["detail"] = "The discovery response did not include a private LOCATION, so nothing was fetched."
            result["devices"].append(device)
            continue
        try:
            description = getter(location)
            controls = control_urls(description, location)
        except Exception as exc:
            device["status"] = "error"
            device["detail"] = str(exc)
            result["devices"].append(device)
            result["errors"].append(f"{location}: {exc}")
            continue
        if not controls:
            device["status"] = "no-mapping-service"
            device["detail"] = "The device answered, and no WAN mapping service was read."
            result["devices"].append(device)
            continue
        device["status"] = "read"
        for control_url, urn in controls:
            try:
                found = enumerate_mappings(control_url, urn, poster)
            except Exception as exc:
                device["detail"] = str(exc)
                result["errors"].append(f"{control_url}: {exc}")
                continue
            result["mappings"].extend(found)
            device["detail"] = f"{len(found)} mapping(s) from {urn}"
        result["devices"].append(device)
    return result


if __name__ == "__main__":
    print("Use: python main.py scan")
    raise SystemExit(2)
