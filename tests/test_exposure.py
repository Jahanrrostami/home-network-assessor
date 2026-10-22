import socket
import unittest

from exposure import (
    collect_exposure,
    control_urls,
    discover_ssdp,
    enumerate_mappings,
    lookup_public_ip,
    parse_error_code,
    parse_mapping,
    soap_body,
    url_is_safe,
)


DESCRIPTION = """<?xml version="1.0"?>
<root>
  <device>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
      <service>
        <serviceType>urn:evil:service</serviceType>
        <controlURL>http://8.8.8.8/steal</controlURL>
      </service>
    </serviceList>
  </device>
</root>
"""

MAPPING = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>3389</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewInternalPort>3389</NewInternalPort>
      <NewInternalClient>192.168.1.20</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>desktop</NewPortMappingDescription>
    </u:GetGenericPortMappingEntryResponse>
  </s:Body>
</s:Envelope>
"""

PUBLIC_CLIENT = MAPPING.replace("192.168.1.20", "8.8.8.8")

ERROR_713 = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body><s:Fault><detail><UPnPError>
    <errorCode>713</errorCode>
  </UPnPError></detail></s:Fault></s:Body>
</s:Envelope>
"""

SSDP = (
    "HTTP/1.1 200 OK\r\n"
    "LOCATION: http://192.168.1.1/desc.xml\r\n"
    "SERVER: TestGateway\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
).encode()


class FakeSocket:
    instances = []

    def __init__(self, *args, **kwargs):
        self.closed = False
        self.sent = None
        self.queue = [SSDP]
        FakeSocket.instances.append(self)

    def settimeout(self, value):
        self.timeout = value

    def sendto(self, data, address):
        self.sent = (data, address)

    def recvfrom(self, size):
        if not self.queue:
            raise socket.timeout()
        return self.queue.pop(0), ("192.168.1.1", 1900)

    def close(self):
        self.closed = True


class ExposureTests(unittest.TestCase):
    def test_only_private_ip_urls_are_fetched(self):
        self.assertTrue(url_is_safe("http://192.168.1.1/desc.xml"))
        self.assertTrue(url_is_safe("https://192.168.1.1/desc.xml"))
        self.assertTrue(url_is_safe("http://[fe80::1]/desc.xml"))
        for url in (
            "http://8.8.8.8/desc.xml",
            "http://example.com/desc.xml",
            "http://192.168.1.1.example.com/desc.xml",
            "http://user:pass@192.168.1.1/desc.xml",
            "http://192.168.1.1@example.com/desc.xml",
            "file:///desc.xml",
            "http://100.64.0.1/desc.xml",
        ):
            with self.subTest(url=url):
                self.assertFalse(url_is_safe(url))

    def test_description_keeps_only_the_private_mapping_service(self):
        found = control_urls(DESCRIPTION, "http://192.168.1.1/desc.xml")
        self.assertEqual(found, [("http://192.168.1.1/ctl/IPConn", "urn:schemas-upnp-org:service:WANIPConnection:1")])

    def test_public_control_url_is_dropped(self):
        xml = DESCRIPTION.replace("/ctl/IPConn", "http://8.8.8.8/ctl")
        self.assertEqual(control_urls(xml, "http://192.168.1.1/desc.xml"), [])

    def test_doctype_is_refused(self):
        with self.assertRaises(ValueError):
            control_urls("<!DOCTYPE foo [<!ENTITY x 'y'>]><root></root>", "http://192.168.1.1/")

    def test_soap_body_is_the_read_call(self):
        body = soap_body("urn:schemas-upnp-org:service:WANIPConnection:1", 0)
        self.assertIn("GetGenericPortMappingEntry", body)
        self.assertNotIn("AddPortMapping", body)
        self.assertNotIn("DeletePortMapping", body)

    def test_enumerate_skips_a_public_client_and_stops_at_713(self):
        calls = []

        def poster(url, urn, body):
            calls.append(body)
            if len(calls) == 1:
                return 200, PUBLIC_CLIENT
            if len(calls) == 2:
                return 200, MAPPING
            return 500, ERROR_713

        found = enumerate_mappings("http://192.168.1.1/ctl/IPConn", "urn:schemas-upnp-org:service:WANIPConnection:1", poster)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["internal_client"], "192.168.1.20")
        self.assertEqual(len(calls), 3)
        self.assertEqual(parse_error_code(ERROR_713), "713")
        self.assertIsNone(parse_mapping(PUBLIC_CLIENT))

    def test_discovery_closes_the_socket_and_only_multicasts(self):
        FakeSocket.instances = []
        found = discover_ssdp(1, socket_factory=FakeSocket)
        self.assertEqual(found[0]["location"], "http://192.168.1.1/desc.xml")
        self.assertEqual(FakeSocket.instances[0].sent[1], ("239.255.255.250", 1900))
        self.assertTrue(FakeSocket.instances[0].closed)

    def test_socket_failure_does_not_hide_itself(self):
        def boom(*args, **kwargs):
            raise OSError("no network")

        found = discover_ssdp(1, socket_factory=boom)
        self.assertEqual(found, [{"error": "no network"}])

    def test_collect_reads_mappings_without_a_network(self):
        def getter(url):
            self.assertTrue(url_is_safe(url))
            return DESCRIPTION

        def poster(url, urn, body):
            self.assertEqual(url, "http://192.168.1.1/ctl/IPConn")
            self.assertNotIn("AddPortMapping", body)
            if "<NewPortMappingIndex>0</NewPortMappingIndex>" in body:
                return 200, MAPPING
            return 500, ERROR_713

        FakeSocket.instances = []
        result = collect_exposure(
            {"lookup_public_ip": False, "upnp_timeout_seconds": 1},
            socket_factory=FakeSocket,
            http_get=getter,
            soap_post=poster,
        )
        self.assertIsNone(result["public_ip"])
        self.assertIn("off", result["public_ip_note"])
        self.assertEqual(result["mappings"][0]["external_port"], 3389)
        self.assertEqual(result["devices"][0]["status"], "read")

    def test_public_ip_lookup_accepts_only_an_address(self):
        class Response:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return self.payload

        address, note = lookup_public_ip(opener=lambda request, timeout: Response(b"203.0.113.9"))
        self.assertEqual(address, "203.0.113.9")
        self.assertIn("ipify", note)
        missing, _note = lookup_public_ip(opener=lambda request, timeout: Response(b"not an ip"))
        self.assertIsNone(missing)


if __name__ == "__main__":
    unittest.main()
