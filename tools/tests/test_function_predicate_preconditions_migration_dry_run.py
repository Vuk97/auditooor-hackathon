from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "function-predicate-preconditions-migration-dry-run.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("function_predicate_preconditions_migration", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class FunctionPredicatePreconditionsMigrationDryRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_flags_supported_function_key_only_when_misplaced_in_preconditions(self) -> None:
        doc = {
            "pattern": "demo-pattern",
            "preconditions": [
                {"contract.source_matches_regex": "Vault"},
                {"function.name_matches": "^withdraw$"},
                {"function.kind": "external_or_public"},
            ],
            "match": [
                {"function.body_contains_regex": "transfer"},
            ],
        }

        candidates = self.tool.scan_doc(Path("demo.yaml"), doc)

        self.assertEqual(len(candidates), 2)
        self.assertEqual([candidate.key for candidate in candidates], ["function.name_matches", "function.kind"])
        self.assertTrue(all(candidate.proposed_relocation == "prepend to match" for candidate in candidates))
        self.assertTrue(all(candidate.confidence == "medium" for candidate in candidates))

    def test_ignores_unsupported_function_keys_and_non_mapping_preconditions(self) -> None:
        doc = {
            "preconditions": [
                {"function.signature_regex": "foo"},
                "function.name_matches: foo",
                {"contract.name_matches": "Vault"},
            ],
            "match": [],
        }

        candidates = self.tool.scan_doc(Path("demo.yaml"), doc)

        self.assertEqual(candidates, [])

    def test_marks_exact_match_duplicates_as_dedupe_review_candidates(self) -> None:
        doc = {
            "pattern": "constructor-duplicate",
            "preconditions": [
                {"function.is_constructor": True},
                {"contract.source_matches_regex": "ERC20Permit"},
            ],
            "match": [
                {"function.is_constructor": True},
                {"function.body_contains_regex": "ERC20Permit"},
            ],
        }

        candidates = self.tool.scan_doc(Path("demo.yaml"), doc)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].key, "function.is_constructor")
        self.assertEqual(candidates[0].confidence, "medium")
        self.assertIn("dedupe review", candidates[0].rationale)


if __name__ == "__main__":
    unittest.main()
