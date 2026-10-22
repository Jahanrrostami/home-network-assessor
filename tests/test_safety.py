import unittest
from pathlib import Path

from scanner import parse_arp_output

ROOT = Path(__file__).resolve().parents[1]


class SafetyTests(unittest.TestCase):
    def test_hint_file_stays_advisory(self):
        text = (ROOT / "cve_db" / "hints.json").read_text(encoding="utf-8").lower()
        for banned in ("curl ", "/etc/passwd", "../", "exploit", "payload", "shellcode", "meterpreter"):
            self.assertNotIn(banned, text)
        self.assertIn("upgrade", text)

    def test_upnp_code_does_not_write_mappings(self):
        text = (ROOT / "exposure.py").read_text(encoding="utf-8")
        self.assertNotIn("AddPortMapping", text)
        self.assertNotIn("DeletePortMapping", text)
        self.assertIn("GetGenericPortMappingEntry", text)

    def test_docs_point_at_the_entry_and_the_caution_file(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        important = (ROOT / "README-IMPORTANT.md").read_text(encoding="utf-8")
        self.assertIn("python main.py", readme)
        self.assertIn("README-IMPORTANT.md", readme)
        self.assertIn("private", important.lower())

    def test_arp_parser_ignores_broadcast_and_incomplete(self):
        sample = """
Interface: 192.168.1.23 --- 0xc
  192.168.1.1           d4-5d-64-12-34-56     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22                                  static
? (192.168.1.50) at aa:bb:cc:dd:ee:10 [ether] on eth0
? (192.168.1.51) at <incomplete> on eth0
"""
        found = parse_arp_output(sample)
        self.assertEqual(found["192.168.1.1"], "d4:5d:64:12:34:56")
        self.assertEqual(found["192.168.1.50"], "aa:bb:cc:dd:ee:10")
        self.assertNotIn("192.168.1.255", found)
        self.assertNotIn("192.168.1.51", found)


if __name__ == "__main__":
    unittest.main()
