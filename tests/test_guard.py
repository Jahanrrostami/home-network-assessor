import unittest

from network_guard import GuardError, address_is_allowed, assert_private_target


class GuardTests(unittest.TestCase):
    def test_home_ranges_are_allowed(self):
        for target in (
            "192.168.1.0/24",
            "192.168.1.20",
            "10.1.2.0/24",
            "172.16.0.0/12",
            "172.20.1.5",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fd12:3456::/64",
            "fe80::/10",
        ):
            with self.subTest(target=target):
                assert_private_target(target)

    def test_public_and_sloppy_ranges_are_refused(self):
        for target in (
            "8.8.8.8",
            "1.2.3.0/24",
            "0.0.0.0/0",
            "100.64.1.0/24",
            "172.32.0.0/16",
            "10.0.0.0/7",
            "example.com",
            "",
            "192.168.1.0/24; rm",
        ):
            with self.subTest(target=target):
                with self.assertRaises(GuardError):
                    assert_private_target(target)

    def test_single_address_helper(self):
        self.assertTrue(address_is_allowed("192.168.1.1"))
        self.assertFalse(address_is_allowed("8.8.8.8"))
        self.assertFalse(address_is_allowed("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
