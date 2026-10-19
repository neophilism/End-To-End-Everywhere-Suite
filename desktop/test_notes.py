"""Contract tests for the desktop notes/contact and QR view's security boundary."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from notes_core import (
    ClientError, build_command, compare_qr, parse_qr, run_cli, verify_cli,
)


class DesktopContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / "note.txt"
        self.input.write_text("private\n")
        self.output = self.root / "note.e2ed"
        self.card = self.root / "card.txt"
        self.card.write_text("public card")
        self.binary = str(self.root / "e2ee")
        shutil.copy2(sys.executable, self.binary)
        self.state = str(self.root / "state")
        self.anchor = "a" * 140

    def command(self, action, *arguments):
        return build_command(self.binary, self.state, action, list(arguments), self.anchor)

    def test_qr_canonical_parse_and_explicit_local_comparison(self):
        payload = "e2ee-verify-v1:enroll:desktop-1:" + "ab" * 32
        self.assertEqual(parse_qr(payload).enrollment_id, "enroll:desktop-1")
        self.assertTrue(compare_qr(payload, "enroll:desktop-1", "ab" * 32))
        self.assertFalse(compare_qr(payload, "enroll:desktop-2", "ab" * 32))
        self.assertFalse(compare_qr(payload, "enroll:desktop-1", "cd" * 32))

    def test_qr_rejects_bad_text_and_never_is_a_verify_command(self):
        valid = "e2ee-verify-v1:id:" + "ab" * 32
        for payload in (valid.upper(), valid + " ", valid + "?admin=1",
                        valid.replace("id:", "../id:"), "https://example.org/" + valid,
                        valid + "x", "e2ee-verify-v1:id:123", "x" * 257):
            with self.subTest(payload=payload[:30]), self.assertRaises(ClientError):
                parse_qr(payload)
        with self.assertRaises(ClientError):
            self.command("verify", "peer", "ab" * 32 + "garbage")

    def test_notes_are_new_files_and_use_cli(self):
        argv = self.command("seal-note", "personal-note", str(self.input), str(self.output))
        self.assertEqual(argv[-4:], ["seal-note", "personal-note", str(self.input), str(self.output)])
        self.output.write_text("occupied")
        with self.assertRaises(ClientError):
            self.command("open-note", "personal-note", str(self.input), str(self.output))
        self.output.unlink()
        with self.assertRaises(ClientError):
            self.command("seal-note", "bad context", str(self.input), str(self.output))

    def test_symlink_input_and_oversize_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.input)
        with self.assertRaises(ClientError):
            self.command("seal-note", "notes", str(link), str(self.output))
        self.input.write_bytes(b"1" * (4 * 1024 * 1024 + 1))
        with self.assertRaises(ClientError):
            self.command("seal-note", "notes", str(self.input), str(self.output))

    def test_contact_import_untrusted_then_explicit_fingerprint(self):
        self.assertEqual(self.command("import-card", str(self.card))[-2:], ["import-card", str(self.card)])
        self.assertEqual(self.command("verify", "peer", "bc" * 32)[-3:], ["verify", "peer", "bc" * 32])
        for fingerprint in ("bc" * 31, "bc" * 32 + "x"):
            with self.assertRaises(ClientError):
                self.command("verify", "peer", fingerprint)

    def test_anchored_and_password_only_are_explicit(self):
        with self.assertRaises(ClientError):
            build_command(self.binary, self.state, "identity", [])
        with self.assertRaises(ClientError):
            build_command(self.binary, self.state, "identity", [], self.anchor, True)
        argv = build_command(self.binary, self.state, "contacts", [], password_only=True)
        self.assertIn("--password-only", argv)
        self.assertNotIn("--anchor", argv)

    @patch("notes_core.subprocess.run")
    def test_passphrase_stdin_and_anchor_reconciliation(self, process):
        argv = self.command("import-card", str(self.card))
        process.return_value = SimpleNamespace(returncode=0, stdout="imported\n",
                                               stderr="ANCHOR " + "b" * 140 + "\n")
        self.assertEqual(run_cli(argv, "secret phrase")[1], "b" * 140)
        self.assertEqual(process.call_args.kwargs["input"], "secret phrase\n")
        process.return_value.stderr = ""
        with self.assertRaises(ClientError):
            run_cli(argv, "secret phrase")
        with self.assertRaises(ClientError):
            run_cli(argv, "short")

    @patch("notes_core.subprocess.run")
    def test_failed_operation_does_not_hide_new_anchor(self, process):
        process.return_value = SimpleNamespace(returncode=1, stdout="",
                                               stderr="ANCHOR " + "c" * 140 + "\ne2ee: uncertain\n")
        with self.assertRaises(ClientError) as failure:
            run_cli(self.command("verify", "peer", "bc" * 32), "secret phrase")
        self.assertEqual(failure.exception.anchor, "c" * 140)

    @patch("notes_core.subprocess.run")
    def test_capability_gate(self, process):
        features = {key: True for key in ("encrypted_personal_notes",
                                          "verified_contact_pinning",
                                          "private_atomic_file_publication")}
        process.return_value = SimpleNamespace(returncode=0, stdout=json.dumps({
            "component": "local-cli", "features": features}), stderr="")
        verify_cli(self.binary)
        features["verified_contact_pinning"] = False
        process.return_value.stdout = json.dumps({"component": "local-cli", "features": features})
        with self.assertRaises(ClientError):
            verify_cli(self.binary)


if __name__ == "__main__":
    unittest.main()
