"""Regression tests for a deliberately incomplete E2EESA discovery inventory."""
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate_e2eesa_inventory.py"
spec = importlib.util.spec_from_file_location("validate_e2eesa_inventory", SCRIPT)
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "security/e2eesa-inventory.json").read_text())
        cls.status = json.loads((ROOT / "security/e2eesa-status.json").read_text())

    def check(self, mutate=None, status=None):
        manifest = copy.deepcopy(self.manifest)
        if mutate:
            mutate(manifest)
        return validator.validate(manifest, ROOT, status if status is not None else self.status)

    def test_provisional_inventory_is_valid_without_completeness_claim(self):
        self.assertEqual(self.check(), [])
        self.assertFalse(self.manifest["coverageComplete"])
        self.assertFalse(self.status["inventory"]["reviewed"])

    def test_preliminary_source_discovery_cannot_announce_complete_coverage(self):
        self.assertTrue(self.check(lambda d: d.update(coverageComplete=True)))
        self.assertTrue(self.check(lambda d: d.update(classificationStatus="verified")))

    def test_missing_or_external_evidence_paths_fail_closed(self):
        self.assertTrue(self.check(lambda d: d["components"][0]["paths"].append("../outside")))
        self.assertTrue(self.check(lambda d: d["dataFlows"][0]["evidencePaths"].append("untracked.rs")))

    def test_unknown_or_duplicate_components_and_flows_fail_closed(self):
        self.assertTrue(self.check(lambda d: d["components"].append(copy.deepcopy(d["components"][0]))))
        self.assertTrue(self.check(lambda d: d["dataFlows"][0].update(to="unrecognized-device")))
        self.assertTrue(self.check(lambda d: d["dataFlows"].append(copy.deepcopy(d["dataFlows"][0]))))

    def test_networked_protected_content_is_not_silently_claimed(self):
        def make_protected_networked(d):
            d["dataFlows"][0]["networked"] = True
        self.assertTrue(self.check(make_protected_networked))

    def test_missing_observations_or_malformed_digests_are_rejected(self):
        self.assertTrue(self.check(lambda d: d["sourceObservations"].pop()))
        self.assertTrue(self.check(lambda d: d["sourceObservations"][0].update(blobSha="not-a-git-blob")))

    def test_inventory_cannot_overrule_separate_pending_review_status(self):
        status = copy.deepcopy(self.status)
        status["inventory"]["reviewed"] = True
        self.assertTrue(self.check(status=status))

    def test_trust_boundary_disclaimers_are_required(self):
        self.assertTrue(self.check(lambda d: d["components"][0].update(boundary="")))
        self.assertTrue(self.check(lambda d: d["dataFlows"][0].update(scopeNote="")))

    def test_safe_paths_reject_traversal_and_schemes(self):
        for path in ("../secret", "/etc/passwd", "C:/private", "x//y", "x/./y", "x/../y", "x\\y"):
            self.assertFalse(validator.safe_path(path), path)


if __name__ == "__main__":
    unittest.main()
