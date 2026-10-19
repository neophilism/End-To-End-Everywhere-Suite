"""Local vault command boundary tests; no real credentials or CLI process."""
import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).with_name("vault.py")
SPEC = importlib.util.spec_from_file_location("vault", PATH)
vault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vault)


class VaultBoundaryTests(unittest.TestCase):
    def test_new_destination_and_password_stdin(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source = pathlib.Path(root, "input")
            source.write_bytes(b"hello")
            output = pathlib.Path(root, "sealed.e2ed")
            argv = vault.command("e2ee", str(pathlib.Path(root, "state")),
                                 "seal-self-file", "personal-file",
                                 str(source), str(output))
            self.assertEqual(argv[-4:], ["seal-self-file", "personal-file",
                                          str(source), str(output)])
            self.assertIn("--password-stdin", argv)
            output.write_bytes(b"existing")
            with self.assertRaises(vault.VaultError):
                vault.command("e2ee", str(pathlib.Path(root, "state")),
                              "seal-self-file", "personal-file",
                              str(source), str(output))
            self.assertEqual(output.read_bytes(), b"existing")

    def test_invalid_context_and_oversize_import_fail_before_process(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source = pathlib.Path(root, "input")
            source.write_bytes(b"x")
            with self.assertRaises(vault.VaultError):
                vault.command("e2ee", root + "/state", "open-self-file",
                              "bad\ncontext", str(source), root + "/out")
            with patch.object(vault, "MAX_FILE_BYTES", 0):
                with self.assertRaises(vault.VaultError):
                    vault.command("e2ee", root + "/state", "seal-self-file",
                                  "personal-file", str(source), root + "/out")

    def test_passphrase_is_stdin_only_and_cli_diagnostics_are_not_echoed(self):
        result = subprocess.CompletedProcess([], 1, "", "ANCHOR secret")
        with patch.object(vault.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(vault.VaultError, "operation failed") as error:
                vault.execute(["e2ee", "identity"], "private-passphrase")
            self.assertNotIn("secret", str(error.exception))
            self.assertEqual(run.call_args.kwargs["input"], "private-passphrase\n")
            self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_stdin_identity_creation_uses_one_line(self):
        with patch.object(vault.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            vault.execute(["e2ee", "init", "me"], "private-passphrase", initializing=True)
            self.assertEqual(run.call_args.kwargs["input"], "private-passphrase\n")

    def test_identity_creation_rejects_existing_state(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(vault.VaultError):
                vault.command("e2ee", root, "init", endpoint="me")


if __name__ == "__main__":
    unittest.main()
