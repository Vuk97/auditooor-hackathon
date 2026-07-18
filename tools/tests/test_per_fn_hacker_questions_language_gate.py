#!/usr/bin/env python3
"""test_per_fn_hacker_questions_language_gate.py

Guard test: Solidity-restricted templates (reentrancy, recipient-nonzero,
deadline-future, access-control-missing) must NOT fire for Go or Rust
functions.  The same templates MUST fire for Solidity functions.

Language-agnostic templates (e.g. amount-nonzero, sum-preserved) must fire
for all languages regardless of the restriction map.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load_tool():
    modname = "per_function_hacker_questions_under_test"
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(
        modname, TOOLS / "per-function-hacker-questions.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_record(language: str, invariant_candidates: list[str]) -> dict:
    return {
        "function": "TestFn",
        "file": "test.ext",
        "language": language,
        "invariant_candidates": invariant_candidates,
    }


class LanguageGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()

    # ------------------------------------------------------------------ helpers
    def _classes(self, language: str, invariants: list[str]) -> set[str]:
        rec = _make_record(language, invariants)
        return {q["question_class"] for q in self.mod.gen_questions(rec)}

    # ------------------------------------------------------------------ reentrancy
    def test_reentrancy_fires_for_solidity(self) -> None:
        classes = self._classes("solidity", ["reentrancy-check"])
        self.assertIn("reentrancy", classes,
                      "reentrancy template must fire for Solidity functions")

    def test_reentrancy_silent_for_go(self) -> None:
        classes = self._classes("go", ["reentrancy-check"])
        self.assertNotIn("reentrancy", classes,
                         "reentrancy template must NOT fire for Go functions")

    def test_reentrancy_silent_for_rust(self) -> None:
        classes = self._classes("rust", ["reentrancy-check"])
        self.assertNotIn("reentrancy", classes,
                         "reentrancy template must NOT fire for Rust functions")

    # ------------------------------------------------------------------ recipient-nonzero
    def test_recipient_nonzero_fires_for_solidity(self) -> None:
        classes = self._classes("solidity", ["recipient-nonzero"])
        self.assertIn("recipient-nonzero", classes)

    def test_recipient_nonzero_silent_for_go(self) -> None:
        classes = self._classes("go", ["recipient-nonzero"])
        self.assertNotIn("recipient-nonzero", classes)

    def test_recipient_nonzero_silent_for_rust(self) -> None:
        classes = self._classes("rust", ["recipient-nonzero"])
        self.assertNotIn("recipient-nonzero", classes)

    # ------------------------------------------------------------------ deadline-future
    def test_deadline_future_fires_for_solidity(self) -> None:
        classes = self._classes("solidity", ["deadline-future"])
        self.assertIn("deadline-future", classes)

    def test_deadline_future_silent_for_go(self) -> None:
        classes = self._classes("go", ["deadline-future"])
        self.assertNotIn("deadline-future", classes)

    # ------------------------------------------------------------------ access-control-missing
    def test_access_control_fires_for_solidity(self) -> None:
        classes = self._classes("solidity", ["access-control-missing"])
        self.assertIn("access-control-missing", classes)

    def test_access_control_silent_for_go(self) -> None:
        classes = self._classes("go", ["access-control-missing"])
        self.assertNotIn("access-control-missing", classes)

    # ------------------------------------------------------------------ language-agnostic
    def test_amount_nonzero_fires_for_go(self) -> None:
        classes = self._classes("go", ["amount-nonzero"])
        self.assertIn("amount-nonzero", classes,
                      "language-agnostic template amount-nonzero must fire for Go")

    def test_amount_nonzero_fires_for_rust(self) -> None:
        classes = self._classes("rust", ["amount-nonzero"])
        self.assertIn("amount-nonzero", classes)

    def test_amount_nonzero_fires_for_solidity(self) -> None:
        classes = self._classes("solidity", ["amount-nonzero"])
        self.assertIn("amount-nonzero", classes)

    # ------------------------------------------------------------------ _language_allows helper
    def test_helper_language_agnostic_always_true(self) -> None:
        # A template key absent from LANGUAGE_ALLOWED_CLASSES is always allowed
        fn = self.mod._language_allows
        self.assertTrue(fn("amount-nonzero", "go"))
        self.assertTrue(fn("amount-nonzero", "solidity"))
        self.assertTrue(fn("amount-nonzero", "rust"))

    def test_helper_solidity_restricted_false_for_go(self) -> None:
        fn = self.mod._language_allows
        for key in ("reentrancy", "recipient-nonzero", "deadline-future",
                    "access-control-missing"):
            self.assertFalse(fn(key, "go"),
                             f"{key} should not be allowed for go")
            self.assertFalse(fn(key, "rust"),
                             f"{key} should not be allowed for rust")

    def test_helper_solidity_restricted_true_for_solidity(self) -> None:
        fn = self.mod._language_allows
        for key in ("reentrancy", "recipient-nonzero", "deadline-future",
                    "access-control-missing"):
            self.assertTrue(fn(key, "solidity"),
                            f"{key} should be allowed for solidity")

    def test_helper_case_insensitive(self) -> None:
        fn = self.mod._language_allows
        # Language tags may arrive with mixed case from upstream parsers
        self.assertFalse(fn("reentrancy", "Go"))
        self.assertFalse(fn("reentrancy", "GO"))
        self.assertTrue(fn("reentrancy", "Solidity"))
        self.assertTrue(fn("reentrancy", "SOLIDITY"))

    # ------------------------------------------------------------------ vyper (EVM-adjacent)
    def test_reentrancy_fires_for_vyper(self) -> None:
        classes = self._classes("vyper", ["reentrancy-check"])
        self.assertIn("reentrancy", classes,
                      "reentrancy must fire for Vyper (EVM-adjacent)")

    # ------------------------------------------------------------------ unknown language
    def test_restricted_template_silent_for_unknown_language(self) -> None:
        classes = self._classes("unknown", ["reentrancy-check"])
        self.assertNotIn("reentrancy", classes,
                         "Solidity-restricted templates must be silent for unknown language")

    def test_agnostic_template_fires_for_unknown_language(self) -> None:
        classes = self._classes("unknown", ["amount-nonzero"])
        self.assertIn("amount-nonzero", classes,
                      "language-agnostic templates must fire even for unknown language")


if __name__ == "__main__":
    unittest.main()
