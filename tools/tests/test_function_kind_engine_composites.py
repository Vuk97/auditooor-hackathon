#!/usr/bin/env python3
"""PR #140 Part 3 — engine extension for pure visibility composites.

Codex's verbatim decision (PR #140 latest comment) for `function.kind:`
composite values:

  1. Extend `_predicate_engine.py` only for pure Solidity visibility
     composites formed from {external, public, internal, private} with
     `_or_` separators, plus normalize the existing pipe typo
     `internal|external_or_public`.
  2. Do NOT treat state-mutability hybrids as visibility. Values like
     `external_or_public_or_internal_view`, `view_or_external`,
     `view_or_internal`, `view_or_pure` must stay lint failures.
  3. Do NOT map non-Solidity / domain markers to `any`. Values like
     `rust_fn_runtime`, `cosmos_msg_handler`, `anchor_instruction`,
     `geth_state_mutator`, `handler`, `type_definition` must stay lint
     failures.

These tests pin those guarantees on both the engine (`check_function_pred`
returns True/False as expected) and the lint
(`is_recognized_function_kind_value` agrees with the engine).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_PATH = REPO_ROOT / "tools" / "detector-lint.py"
ENGINE_PATH = REPO_ROOT / "detectors" / "_predicate_engine.py"


def _load_lint_module():
    spec = importlib.util.spec_from_file_location("detector_lint", LINT_PATH)
    assert spec and spec.loader, f"could not load {LINT_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_engine_module():
    """Import detectors/_predicate_engine.py as a standalone module."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(
        "_predicate_engine_under_test", ENGINE_PATH
    )
    assert spec and spec.loader, f"could not load {ENGINE_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_function(visibility: str):
    """Slither-shaped duck-typed function with just the visibility attr."""
    return SimpleNamespace(visibility=visibility)


class EnginePureVisibilityCompositeTest(unittest.TestCase):
    """Codex decision point 1: pure visibility `_or_` composites are honored."""

    def setUp(self):
        self.engine = _load_engine_module()

    def _check(self, vis, val):
        return self.engine._check_function_pred(_fake_function(vis), "function.kind", val)

    # ----- atomic visibilities (regression: must still work) -----
    def test_atomic_external(self):
        self.assertTrue(self._check("external", "external"))
        self.assertFalse(self._check("internal", "external"))

    # ----- already-special-cased composites (regression) -----
    def test_external_or_public_external(self):
        self.assertTrue(self._check("external", "external_or_public"))
        self.assertTrue(self._check("public", "external_or_public"))
        self.assertFalse(self._check("internal", "external_or_public"))

    def test_any_always_true(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertTrue(self._check(v, "any"))

    # ----- new dynamic dispatch: 3-token composite -----
    def test_external_or_public_or_internal(self):
        for v in ("external", "public", "internal"):
            self.assertTrue(
                self._check(v, "external_or_public_or_internal"),
                f"{v} should match external_or_public_or_internal",
            )
        self.assertFalse(self._check("private", "external_or_public_or_internal"))

    def test_internal_or_external(self):
        self.assertTrue(self._check("internal", "internal_or_external"))
        self.assertTrue(self._check("external", "internal_or_external"))
        self.assertFalse(self._check("public", "internal_or_external"))
        self.assertFalse(self._check("private", "internal_or_external"))

    def test_internal_or_private(self):
        self.assertTrue(self._check("internal", "internal_or_private"))
        self.assertTrue(self._check("private", "internal_or_private"))
        self.assertFalse(self._check("external", "internal_or_private"))
        self.assertFalse(self._check("public", "internal_or_private"))

    def test_internal_or_public(self):
        self.assertTrue(self._check("internal", "internal_or_public"))
        self.assertTrue(self._check("public", "internal_or_public"))
        self.assertFalse(self._check("external", "internal_or_public"))

    def test_internal_or_external_or_public(self):
        for v in ("internal", "external", "public"):
            self.assertTrue(self._check(v, "internal_or_external_or_public"))
        self.assertFalse(self._check("private", "internal_or_external_or_public"))

    def test_internal_or_private_or_public(self):
        for v in ("internal", "private", "public"):
            self.assertTrue(self._check(v, "internal_or_private_or_public"))
        self.assertFalse(self._check("external", "internal_or_private_or_public"))

    def test_public_or_internal(self):
        self.assertTrue(self._check("public", "public_or_internal"))
        self.assertTrue(self._check("internal", "public_or_internal"))
        self.assertFalse(self._check("external", "public_or_internal"))

    # ----- pipe-typo normalization -----
    def test_pipe_typo_internal_pipe_external_or_public(self):
        """Codex point 1: normalize `internal|external_or_public` via split-on-`|`."""
        for v in ("internal", "external", "public"):
            self.assertTrue(
                self._check(v, "internal|external_or_public"),
                f"{v} should match the normalized pipe-typo composite",
            )
        self.assertFalse(self._check("private", "internal|external_or_public"))


class EngineStateMutabilityHybridStaysFalseTest(unittest.TestCase):
    """Codex decision point 2: state-mutability hybrids must NOT be honored."""

    def setUp(self):
        self.engine = _load_engine_module()

    def _check(self, vis, val):
        return self.engine._check_function_pred(_fake_function(vis), "function.kind", val)

    def test_external_or_public_or_internal_view_returns_false(self):
        # The 4-occurrence value Codex called out: contains `view`, must
        # not be treated as visibility composite.
        for v in ("external", "public", "internal", "view"):
            self.assertFalse(
                self._check(v, "external_or_public_or_internal_view"),
                f"{v} must not match a state-mutability hybrid value",
            )

    def test_view_or_external_returns_false(self):
        for v in ("external", "view"):
            self.assertFalse(self._check(v, "view_or_external"))

    def test_view_or_internal_returns_false(self):
        for v in ("internal", "view"):
            self.assertFalse(self._check(v, "view_or_internal"))

    def test_view_or_pure_returns_false(self):
        for v in ("view", "pure", "external", "public", "internal", "private"):
            self.assertFalse(self._check(v, "view_or_pure"))


class EngineNonSolidityMarkerStaysFalseTest(unittest.TestCase):
    """Codex decision point 3: non-Solidity / domain markers must NOT map to `any`."""

    def setUp(self):
        self.engine = _load_engine_module()

    def _check(self, vis, val):
        return self.engine._check_function_pred(_fake_function(vis), "function.kind", val)

    def test_rust_fn_runtime(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "rust_fn_runtime"))

    def test_cosmos_msg_handler(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "cosmos_msg_handler"))

    def test_anchor_instruction(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "anchor_instruction"))

    def test_geth_state_mutator(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "geth_state_mutator"))

    def test_handler_bare(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "handler"))

    def test_type_definition(self):
        for v in ("external", "public", "internal", "private", ""):
            self.assertFalse(self._check(v, "type_definition"))

    def test_constructor_mixed_with_visibility_stays_false(self):
        # `constructor` is not a visibility keyword; this stays fail-loud
        # until rewritten or routed to a backend that knows about constructors.
        for v in ("external", "public", "internal", "private"):
            self.assertFalse(self._check(v, "constructor_or_external_or_public"))


class LintMirrorsEngineTest(unittest.TestCase):
    """The lint's `is_recognized_function_kind_value` must agree with the engine."""

    def setUp(self):
        self.lint = _load_lint_module()

    def test_pure_visibility_composites_are_recognized(self):
        for val in (
            "external_or_public_or_internal",
            "internal_or_external",
            "internal_or_private",
            "internal_or_public",
            "internal_or_external_or_public",
            "internal_or_private_or_public",
            "public_or_internal",
        ):
            self.assertTrue(
                self.lint.is_recognized_function_kind_value(val),
                f"lint should accept pure visibility composite {val!r}",
            )

    def test_pipe_typo_recognized(self):
        self.assertTrue(
            self.lint.is_recognized_function_kind_value("internal|external_or_public")
        )

    def test_state_mutability_hybrids_remain_unrecognized(self):
        for val in (
            "external_or_public_or_internal_view",
            "view_or_external",
            "view_or_internal",
            "view_or_pure",
        ):
            self.assertFalse(
                self.lint.is_recognized_function_kind_value(val),
                f"lint must reject state-mutability hybrid {val!r}",
            )

    def test_non_solidity_markers_remain_unrecognized(self):
        for val in (
            "rust_fn_runtime",
            "rust_fn_circuit",
            "cosmos_msg_handler",
            "anchor_instruction",
            "geth_state_mutator",
            "handler",
            "type_definition",
        ):
            self.assertFalse(
                self.lint.is_recognized_function_kind_value(val),
                f"lint must reject non-Solidity marker {val!r}",
            )

    def test_atomic_visibilities_recognized(self):
        for val in ("external", "public", "internal", "private", "any"):
            self.assertTrue(self.lint.is_recognized_function_kind_value(val))


class LintHintMessagesTest(unittest.TestCase):
    """Lint emits clear category-specific hints (Codex points 2 + 3)."""

    def setUp(self):
        self.lint = _load_lint_module()

    def test_state_mutability_hint(self):
        for val in (
            "external_or_public_or_internal_view",
            "view_or_external",
            "view_or_internal",
            "view_or_pure",
        ):
            hint = self.lint._classify_unknown_function_kind(val)
            self.assertIn("state-mutability", hint)
            self.assertIn("split", hint)

    def test_non_solidity_hint(self):
        for val in (
            "rust_fn_runtime",
            "cosmos_msg_handler",
            "anchor_instruction",
            "type_definition",
        ):
            hint = self.lint._classify_unknown_function_kind(val)
            self.assertIn("non-Solidity", hint)


class EndToEndDSLLintTest(unittest.TestCase):
    """A synthetic DSL fixture exercising the new behaviour end-to-end."""

    def setUp(self):
        self.lint = _load_lint_module()

    def test_pure_composite_passes_lint_hybrid_does_not(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "good_pure_composite.yaml").write_text(
                "pattern: good\nmatch:\n  - function.kind: external_or_public_or_internal\n"
            )
            (tmp / "good_pipe_typo.yaml").write_text(
                "pattern: good_pipe\nmatch:\n  - function.kind: internal|external_or_public\n"
            )
            (tmp / "bad_hybrid.yaml").write_text(
                "pattern: bad_hybrid\nmatch:\n  - function.kind: external_or_public_or_internal_view\n"
            )
            (tmp / "bad_marker.yaml").write_text(
                "pattern: bad_marker\nmatch:\n  - function.kind: rust_fn_runtime\n"
            )
            usages = self.lint.function_kind_usages(dsl_dir=tmp)
            unknown = [
                (p.name, ln, v)
                for p, ln, v in usages
                if not self.lint.is_recognized_function_kind_value(v)
            ]
            unknown_values = {v for _, _, v in unknown}
            self.assertEqual(
                unknown_values,
                {"external_or_public_or_internal_view", "rust_fn_runtime"},
                f"expected only the hybrid + marker to fail, got: {unknown}",
            )


if __name__ == "__main__":
    unittest.main()
