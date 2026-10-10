"""Fail-closed tests for the catalog binding inventory checker."""

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "check_e2eesa_binding.py"
spec = importlib.util.spec_from_file_location("check_e2eesa_binding", MODULE_PATH)
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)

PIN = {
    "source_commit": "a" * 40,
    "status": "compatibility-inventory-only",
    "key_storage_constants": {
        "SOFTWARE_VAULT_PROFILE": "secret-software-vault@0.1.0"
    },
    "message_suite_constant": {"symbol": "E2EESA_MESSAGE_SUITE", "value": "TEST-SUITE"}
}
CATALOG = {
    "profiles": [{
        "profile_id": "secret-software-vault",
        "profile_version": "0.1.0",
        "family_id": "secret-storage",
        "status": "allowed"
    }]
}
ALGORITHMS = {"suites": [{"id": "TEST-SUITE", "status": "recommended"}]}
KEYSTORE = 'pub const SOFTWARE_VAULT_PROFILE: &str = "secret-software-vault@0.1.0";'
MESSAGE = 'pub const E2EESA_MESSAGE_SUITE: &str = "TEST-SUITE";'


class RegistryBindingTests(unittest.TestCase):
    def check(self, pin=PIN, catalog=CATALOG, algorithms=ALGORITHMS,
              keystore=KEYSTORE, message=MESSAGE, commit="a" * 40):
        return checker.check_bindings(pin, catalog, algorithms, keystore, message, commit)

    def test_exact_pin_accepted_without_conformance_claim(self):
        self.assertEqual(self.check(), [])

    def test_wrong_source_commit_rejected(self):
        self.assertTrue(self.check(commit="b" * 40))

    def test_drifted_source_constant_rejected(self):
        self.assertTrue(self.check(keystore=KEYSTORE.replace("@0.1.0", "@0.2.0")))

    def test_unknown_profile_rejected(self):
        self.assertTrue(self.check(catalog={"profiles": []}))

    def test_prohibited_suite_rejected(self):
        self.assertTrue(self.check(algorithms={"suites": [{"id": "TEST-SUITE", "status": "prohibited"}]}))

    def test_mismatched_family_rejected(self):
        self.assertTrue(self.check(catalog={"profiles": [{**CATALOG["profiles"][0], "family_id": "telemetry"}]}))

    def test_duplicate_constant_rejected(self):
        self.assertTrue(self.check(keystore=KEYSTORE + "\n" + KEYSTORE))

    def test_floating_profile_ref_rejected(self):
        bad = {**PIN, "key_storage_constants": {"SOFTWARE_VAULT_PROFILE": "secret-software-vault"}}
        self.assertTrue(self.check(pin=bad))

    def test_no_fake_certification_label(self):
        bad = {**PIN, "status": "certified"}
        self.assertTrue(self.check(pin=bad))


if __name__ == "__main__":
    unittest.main()
