"""Regression tests for tools/frost-prior-audit-class-verifier.py (S2)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "frost-prior-audit-class-verifier.py"
DB = REPO / "reference" / "frost_prior_audit_classes.yaml"
FIXTURES = REPO / "tools" / "detectors" / "fixtures" / "s2_frost_class_verifier"


def _load_module():
    """Import the hyphenated CLI script as a module for unit-level access."""
    spec = importlib.util.spec_from_file_location("frost_class_verifier", TOOL)
    assert spec and spec.loader, "could not build spec for tool"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FrostPriorAuditClassVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()
        cls.classes = cls.mod.load_classes(DB)

    # --- DB / --list ----------------------------------------------------
    def test_db_has_at_least_eight_classes(self) -> None:
        self.assertGreaterEqual(
            len(self.classes), 8, "seed DB must define >=8 known FROST classes"
        )

    def test_each_class_has_required_fields(self) -> None:
        required = {
            "class_id",
            "name",
            "description",
            "prior_audit_refs",
            "keywords",
            "severity_class",
            "canonical_fix_pattern",
        }
        for cls in self.classes:
            missing = required - set(cls.keys())
            self.assertFalse(
                missing,
                f"class {cls.get('class_id')!r} missing fields: {missing}",
            )
            self.assertIsInstance(cls["keywords"], list)
            self.assertGreater(
                len(cls["keywords"]), 0, f"empty keywords for {cls['class_id']}"
            )

    def test_class_ids_are_unique(self) -> None:
        ids = [c["class_id"] for c in self.classes]
        self.assertEqual(len(ids), len(set(ids)), "duplicate class_id present")

    def test_list_cli_returns_at_least_eight_classes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--list"],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertGreaterEqual(
            payload["count"],
            8,
            f"--list reported only {payload['count']} classes",
        )
        self.assertEqual(payload["count"], len(payload["classes"]))

    # --- classify -------------------------------------------------------
    def test_positive_nonce_reuse_classifies_as_drop_class_b(self) -> None:
        text = (FIXTURES / "pos_01_nonce_reuse.md").read_text(encoding="utf-8")
        result = self.mod.classify(text, self.classes)
        self.assertEqual(result["verdict"], "DROP-class-b")
        self.assertEqual(
            result["best_match_class_id"], "nonce-reuse-across-signing-sessions"
        )

    def test_positive_threshold_active_set_classifies_as_drop_class_b(self) -> None:
        text = (FIXTURES / "pos_02_threshold_active_set.md").read_text(
            encoding="utf-8"
        )
        result = self.mod.classify(text, self.classes)
        self.assertEqual(result["verdict"], "DROP-class-b")
        self.assertEqual(
            result["best_match_class_id"],
            "threshold-check-against-active-set-only",
        )

    def test_negative_jsonrpc_finding_classifies_as_novel(self) -> None:
        text = (FIXTURES / "neg_01_unrelated_jsonrpc.md").read_text(
            encoding="utf-8"
        )
        result = self.mod.classify(text, self.classes)
        self.assertEqual(
            result["verdict"],
            "NOVEL-CANDIDATE",
            f"unrelated JSON-RPC finding scored {result['score']} for "
            f"{result['best_match_class_id']!r}",
        )

    def test_negative_storage_proof_finding_classifies_as_novel(self) -> None:
        text = (FIXTURES / "neg_02_novel_storage_proof.md").read_text(
            encoding="utf-8"
        )
        result = self.mod.classify(text, self.classes)
        self.assertEqual(
            result["verdict"],
            "NOVEL-CANDIDATE",
            f"novel storage-proof finding scored {result['score']} for "
            f"{result['best_match_class_id']!r}",
        )

    def test_classify_stdin_cli_round_trip(self) -> None:
        text = (FIXTURES / "pos_01_nonce_reuse.md").read_text(encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--classify-stdin"],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "DROP-class-b")
        self.assertIn("top", payload)
        self.assertGreater(len(payload["top"]), 0)


if __name__ == "__main__":
    unittest.main()
