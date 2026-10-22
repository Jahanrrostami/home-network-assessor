import tempfile
import unittest
from pathlib import Path

from actions import ActionError, disable_wol_over_ssh, hook_target, run_block_hook


class Result:
    returncode = 0
    stdout = "ok"
    stderr = ""


class ActionTests(unittest.TestCase):
    def test_hook_target_rejects_public_and_junk(self):
        self.assertEqual(hook_target("AA-BB-CC-DD-EE-FF", None), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(hook_target(None, "192.168.1.9"), "192.168.1.9")
        for mac, ip in ((None, "8.8.8.8"), ("not a mac", None), (None, "aa:bb;calc")):
            with self.subTest(mac=mac, ip=ip):
                with self.assertRaises(ActionError):
                    hook_target(mac, ip)

    def test_ssh_is_a_fixed_command_to_a_private_host(self):
        recorded = []

        def runner(command, **kwargs):
            recorded.append((command, kwargs))
            return Result()

        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "id_ed25519"
            key.write_text("not-a-real-key", encoding="utf-8")
            profile = {"ssh_user": "admin", "ssh_identity_file": str(key), "interface": "eth0"}
            message = disable_wol_over_ssh(profile, "192.168.1.50", runner=runner)
        self.assertIn("disabled", message)
        command, kwargs = recorded[0]
        self.assertEqual(command[0], "ssh")
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(command[-5:], ["ethtool", "-s", "eth0", "wol", "d"])
        self.assertNotIn("shell", kwargs)
        self.assertFalse(kwargs["check"])

    def test_bad_interface_never_calls_ssh(self):
        def runner(command, **kwargs):
            raise AssertionError("ssh should not run")

        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "id_ed25519"
            key.write_text("not-a-real-key", encoding="utf-8")
            profile = {"ssh_user": "admin", "ssh_identity_file": str(key), "interface": "eth0;reboot"}
            message = disable_wol_over_ssh(profile, "192.168.1.50", runner=runner)
        self.assertIn("skipped", message)

    def test_public_ssh_target_is_skipped(self):
        def runner(command, **kwargs):
            raise AssertionError("ssh should not run")

        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "id_ed25519"
            key.write_text("not-a-real-key", encoding="utf-8")
            profile = {"ssh_user": "admin", "ssh_identity_file": str(key), "interface": "eth0"}
            message = disable_wol_over_ssh(profile, "8.8.8.8", runner=runner)
        self.assertIn("not a private address", message)

    def test_hook_runner_gets_a_cleaned_argument_list(self):
        recorded = []

        def runner(command, **kwargs):
            recorded.append(command)
            return Result()

        message = run_block_hook("AA-BB-CC-DD-EE-FF", runner=runner)
        self.assertIn("exit 0", message)
        self.assertIn(recorded[0][0], {"powershell", "bash"})
        self.assertEqual(recorded[0][-1], "aa:bb:cc:dd:ee:ff")
        joined = " ".join(recorded[0])
        self.assertNotIn("shell=True", joined)


if __name__ == "__main__":
    unittest.main()
