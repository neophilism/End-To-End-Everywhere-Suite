"""Local vault command boundary tests; no real credentials or CLI process."""
import importlib.util
import pathlib
import subprocess
import sys
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
            argv = vault.command(str(pathlib.Path(sys.executable).resolve()), str(pathlib.Path(root, "state")),
                                 "seal-self-file", "personal-file",
                                 str(source), str(output), password_only=True)
            self.assertEqual(argv[-4:], ["seal-self-file", "personal-file",
                                          str(source), str(output)])
            self.assertIn("--password-stdin", argv)
            output.write_bytes(b"existing")
            with self.assertRaises(vault.VaultError):
                vault.command(str(pathlib.Path(sys.executable).resolve()), str(pathlib.Path(root, "state")),
                              "seal-self-file", "personal-file",
                              str(source), str(output), password_only=True)
            self.assertEqual(output.read_bytes(), b"existing")

    def test_invalid_context_and_oversize_import_fail_before_process(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source = pathlib.Path(root, "input")
            source.write_bytes(b"x")
            with self.assertRaises(vault.VaultError):
                vault.command(str(pathlib.Path(sys.executable).resolve()), root + "/state", "open-self-file",
                              "bad\ncontext", str(source), root + "/out", password_only=True)
            with patch.object(vault, "MAX_FILE_BYTES", 0):
                with self.assertRaises(vault.VaultError):
                    vault.command(str(pathlib.Path(sys.executable).resolve()), root + "/state", "seal-self-file",
                                  "personal-file", str(source), root + "/out", password_only=True)

    def test_passphrase_is_stdin_only_and_cli_diagnostics_are_not_echoed(self):
        result = subprocess.CompletedProcess([], 1, "", "ANCHOR secret")
        with patch.object(vault.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(vault.VaultError, "operation failed") as error:
                vault.execute(["e2ee", "identity"], "private-passphrase")
            self.assertNotIn("secret", str(error.exception))
            self.assertEqual(run.call_args.kwargs["input"], "private-passphrase\n")
            self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_encrypted_delivery_has_its_own_input_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source = pathlib.Path(root, "delivery")
            source.write_bytes(b"encrypted")
            binary = str(pathlib.Path(sys.executable).resolve())
            with patch.object(vault, "MAX_FILE_BYTES", 1):
                vault.command(binary, root + "/state", "open-self-file",
                              "personal-file", str(source), root + "/out",
                              password_only=True)
                with self.assertRaises(vault.VaultError):
                    vault.command(binary, root + "/state", "seal-self-file",
                                  "personal-file", str(source), root + "/out",
                                  password_only=True)

    def test_relative_paths_and_disappearing_input_fail_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            binary = str(pathlib.Path(sys.executable).resolve())
            with self.assertRaises(vault.VaultError):
                vault.command(binary, "relative-state", "init", endpoint="me")
            source = pathlib.Path(root, "gone")
            source.write_bytes(b"x")
            source.unlink()
            with self.assertRaises(vault.VaultError):
                vault.command(binary, root + "/state", "seal-self-file",
                              "personal-file", str(source), root + "/out",
                              password_only=True)
            source.write_bytes(b"x")
            with self.assertRaises(vault.VaultError):
                vault.command(binary, root + "/state", "seal-self-file",
                              "personal-file", str(source), "relative-output",
                              password_only=True)

    def test_path_lookup_and_symlink_program_are_rejected(self):
        with self.assertRaises(vault.VaultError):
            vault.command("e2ee", "/tmp/new-state", "init", endpoint="me")
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            link = pathlib.Path(root, "e2ee")
            link.symlink_to(sys.executable)
            with self.assertRaises(vault.VaultError):
                vault.command(str(link), str(link) + "-state", "init", endpoint="me")

    def test_capability_probe_before_credential_handoff(self):
        good = {"schema_version": 1, "component": "local-cli",
                "features": {"self_encrypted_files": True,
                             "software_password_vault": True,
                             "private_atomic_file_publication": True}}
        with patch.object(vault.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, __import__("json").dumps(good), "")) as run:
            vault.verify_cli("/absolute/e2ee")
            self.assertEqual(run.call_args.args[0], ["/absolute/e2ee", "--capabilities-json"])
            self.assertNotIn("input", run.call_args.kwargs)
        good["features"]["self_encrypted_files"] = False
        with patch.object(vault.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, __import__("json").dumps(good), "")):
            with self.assertRaises(vault.VaultError):
                vault.verify_cli("/absolute/e2ee")

    def test_anchor_is_required_unless_password_only_is_explicit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source = pathlib.Path(root, "input")
            source.write_bytes(b"x")
            args = (str(pathlib.Path(sys.executable).resolve()), root + "/state",
                    "seal-self-file", "personal-file", str(source), root + "/out")
            with self.assertRaises(vault.VaultError):
                vault.command(*args)
            anchored = vault.command(*args, anchor="a" * 140)
            self.assertEqual(anchored[4:6], ["--anchor", "a" * 140])
            with self.assertRaises(vault.VaultError):
                vault.command(*args, anchor="a" * 139)
            with self.assertRaises(vault.VaultError):
                vault.command(*args, anchor="a" * 140, password_only=True)

    def test_created_anchor_is_returned(self):
        anchor = "a" * 140
        result = subprocess.CompletedProcess([], 0, "", "ANCHOR " + anchor + "\n")
        with patch.object(vault.subprocess, "run", return_value=result):
            self.assertEqual(vault.execute(["e2ee", "init", "me"], "private-passphrase"), anchor)

    def test_anchor_on_partial_failure_is_separately_recoverable(self):
        anchor = "b" * 140
        result = subprocess.CompletedProcess([], 1, "", "ANCHOR " + anchor + "\n")
        with patch.object(vault.subprocess, "run", return_value=result):
            with self.assertRaises(vault.VaultError) as raised:
                vault.execute(["e2ee", "init", "me"], "private-passphrase")
            self.assertEqual(raised.exception.anchor, anchor)
            self.assertNotIn(anchor, str(raised.exception))

    def test_stdin_identity_creation_uses_one_line(self):
        with patch.object(vault.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "ANCHOR " + "a" * 140 + "\n")) as run:
            vault.execute(["e2ee", "init", "me"], "private-passphrase")
            self.assertEqual(run.call_args.kwargs["input"], "private-passphrase\n")

    def test_identity_creation_rejects_existing_state(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(vault.VaultError):
                vault.command(str(pathlib.Path(sys.executable).resolve()), root, "init", endpoint="me")


if __name__ == "__main__":
    unittest.main()
