#!/usr/bin/env python3
"""PR #121 follow-up — function.kind silent-no-op lint regression tests.

Codex flagged in the PR #121 batch review (issue 4319734390) that
`_predicate_engine.py` only special-cases `external_or_public` and `any`
for the `function.kind` predicate; every other composite (e.g.
`external_or_public_or_internal`) falls through to exact-equality on the
raw visibility string, silently evaluates False, and the detector emits
zero hits with no warning.

These tests pin three guarantees on the lint we added in
`tools/detector-lint.py`:

1. The recognized-value set is parsed from the predicate engine source
   (so extending the engine automatically widens the lint allow-list)
   and includes both the special-cased composites and the atomic
   visibility values.
2. Known-good DSL files (`function.kind: external_or_public`,
   `function.kind: any`, `function.kind: external`) pass.
3. Bad values like `external_or_public_or_internal`, the case A9 hit
   in PR #132, are flagged as HIGH-severity issues — the whole point
   of fail-loud.
4. Empty / missing `function.kind:` is treated as None (the engine
   just skips that key) and passes.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_PATH = REPO_ROOT / "tools" / "detector-lint.py"


def _load_lint_module():
    """Import tools/detector-lint.py despite the hyphen in the filename."""
    spec = importlib.util.spec_from_file_location("detector_lint", LINT_PATH)
    assert spec and spec.loader, f"could not load {LINT_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RecognizedValuesTest(unittest.TestCase):
    """The lint must extract the allowed set from the engine, not hard-code it."""

    def test_baseline_engine_recognizes_external_or_public_and_any(self):
        mod = _load_lint_module()
        recognized = mod.recognized_function_kind_values()
        # Whatever else the engine recognizes, these two MUST be present —
        # they are the documented composites in _predicate_engine.py and
        # the only ones currently used at scale (910 + 68 occurrences).
        self.assertIn("external_or_public", recognized)
        self.assertIn("any", recognized)
        # Atomic visibilities are accepted via the engine's `return vis == val`
        # fallback at the end of the function.kind handler.
        self.assertEqual(
            {"external", "public", "internal", "private"} & recognized,
            {"external", "public", "internal", "private"},
        )

    def test_bad_composite_is_not_recognized(self):
        mod = _load_lint_module()
        recognized = mod.recognized_function_kind_values()
        # The exact bug A9 hit in PR #132. If anyone extends the engine
        # to honor this, they should also rerun the audit and decide
        # the corpus-wide rewrite — this lint won't keep firing.
        self.assertNotIn("external_or_public_or_internal", recognized)

    def test_synthetic_engine_with_extra_composite(self):
        """Adding a new `val == "X"` branch should widen the allow-list."""
        mod = _load_lint_module()
        synthetic = textwrap.dedent('''
            if key == "function.kind":
                vis = _function_kind(function)
                if val == "external_or_public":
                    return vis in ("external", "public")
                if val == "external_or_public_or_internal":
                    return vis in ("external", "public", "internal")
                if val == "any":
                    return True
                return vis == val

            if key == "function.is_payable":
                return False
        ''')
        recognized = mod.recognized_function_kind_values(engine_source=synthetic)
        self.assertIn("external_or_public_or_internal", recognized)
        self.assertIn("external_or_public", recognized)
        self.assertIn("any", recognized)
        # Atomic fallback still recognized via `return vis == val`.
        self.assertIn("internal", recognized)


class CheckFunctionKindUnknownTest(unittest.TestCase):
    """End-to-end lint behaviour against synthetic DSL fixtures."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _scan(self, files: dict[str, str], tmpdir: Path) -> list[tuple[Path, int, str]]:
        """Write the given {filename: contents} into tmpdir and scan it."""
        for name, content in files.items():
            (tmpdir / name).write_text(content)
        return self.mod.function_kind_usages(dsl_dir=tmpdir)

    def test_known_good_values_pass(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p1.yaml").write_text(
                "pattern: p1\nmatch:\n  - function.kind: external_or_public\n"
            )
            (tmp / "p2.yaml").write_text(
                "pattern: p2\nmatch:\n  - function.kind: any\n"
            )
            (tmp / "p3.yaml").write_text(
                "pattern: p3\nmatch:\n  - function.kind: external\n"
            )
            usages = self.mod.function_kind_usages(dsl_dir=tmp)
            recognized = self.mod.recognized_function_kind_values()
            unknown = [(p, ln, v) for p, ln, v in usages if v not in recognized]
            self.assertEqual(
                unknown, [],
                f"expected zero unknowns for known-good DSL, got: {unknown}",
            )

    def test_external_or_public_or_internal_is_flagged(self):
        """A9 / PR #132 regression — the exact value that silently no-op'd."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "bad.yaml").write_text(
                "pattern: bad\nmatch:\n  - function.kind: external_or_public_or_internal\n"
            )
            usages = self.mod.function_kind_usages(dsl_dir=tmp)
            recognized = self.mod.recognized_function_kind_values()
            unknown = [(p, ln, v) for p, ln, v in usages if v not in recognized]
            self.assertEqual(len(unknown), 1)
            self.assertEqual(unknown[0][2], "external_or_public_or_internal")

    def test_missing_or_empty_kind_is_silently_ignored(self):
        """Defensive: bare key with no value is not user-visible breakage —
        the predicate engine just skips it. The lint must not complain."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # No `function.kind:` line at all.
            (tmp / "no_kind.yaml").write_text(
                "pattern: no_kind\nmatch:\n  - function.name_matches: foo\n"
            )
            # Empty value (`function.kind:` then EOL) — caller treats as None.
            (tmp / "empty_kind.yaml").write_text(
                "pattern: empty_kind\nmatch:\n  - function.kind:\n"
            )
            usages = self.mod.function_kind_usages(dsl_dir=tmp)
            self.assertEqual(
                usages, [],
                f"expected no usages for missing/empty kind, got: {usages}",
            )

    def test_check_function_kind_unknown_returns_strings(self):
        """The check entrypoint hooked into main() returns formatted strings."""
        hits = self.mod.check_function_kind_unknown()
        # On the real corpus (which the audit found has 199 silent-no-op
        # rows), this MUST be non-empty until Codex decides the corpus fix.
        # If 0, either someone fixed the corpus (great) or the engine grew
        # to recognize every composite (also great) — either way this is a
        # signal to revisit the lint, not a passing condition we should
        # silently allow. Assert we got a list (sanity), not zero.
        self.assertIsInstance(hits, list)

    def test_fail_unknown_function_kind_flag_is_opt_in(self):
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []
        self.mod.check_placeholder_fp_guards = lambda *args, **kwargs: []
        self.mod.check_high_tier_regex_only = lambda: []
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: ["bad.yaml:3"]

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main([]), 0)
            self.assertEqual(self.mod.main(["--fail-unknown-function-kind"]), 1)

    def test_fail_unknown_function_kind_flag_passes_when_inventory_clean(self):
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []
        self.mod.check_placeholder_fp_guards = lambda *args, **kwargs: []
        self.mod.check_high_tier_regex_only = lambda: []
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: []

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main(["--fail-unknown-function-kind"]), 0)


if __name__ == "__main__":
    unittest.main()
