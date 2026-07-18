#!/usr/bin/env python3
"""Backend-aware DSL lint regression tests.

The 2026-04-29 Codex handover (PR #459) flagged that 9 DSL rows tripped
`detector-lint.py --fail-unknown-function-kind` even though 8 of them
were intentional non-Solidity domain markers (cosmos / anchor / rust /
geth_runtime / circom). The Solidity Slither-IR engine never picks up
those rows because contract.* preconditions don't match — but the lint
flagged them HIGH anyway, blocking the burn-down gate.

Fix: the lint now reads each YAML's optional `backend:` field at the
root. When `backend:` declares a non-Solidity engine, the function.kind
check skips the row (the value is a domain marker for that backend, not
a Solidity visibility predicate). A separate Check 7b flags
`backend:` values that aren't in the strict allowlist (typos like
`solidty`).

These tests pin:

1. Default behaviour: a YAML with no `backend:` is treated as Solidity.
2. `backend: solidity` (explicit default) behaves identically.
3. Non-Solidity `backend:` values skip the function.kind check.
4. Invalid `backend:` values (typos / unknown engines) are flagged HIGH
   by the new Check 7b.
5. Mixing valid + invalid backend declarations: invalid is flagged,
   valid is silent.
"""
from __future__ import annotations

import importlib.util
import tempfile
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


class YamlBackendParserTest(unittest.TestCase):
    """`yaml_backend(path)` reads the root-level `backend:` field."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _write(self, tmp: Path, name: str, body: str) -> Path:
        p = tmp / name
        p.write_text(body)
        return p

    def test_no_backend_defaults_to_solidity(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = self._write(tmp, "p.yaml", "pattern: p\nseverity: HIGH\n")
            self.assertEqual(self.mod.yaml_backend(p), "solidity")

    def test_explicit_solidity_is_solidity(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = self._write(
                tmp, "p.yaml",
                "pattern: p\nseverity: HIGH\nbackend: solidity\n",
            )
            self.assertEqual(self.mod.yaml_backend(p), "solidity")

    def test_cosmos_backend(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = self._write(
                tmp, "p.yaml",
                "pattern: p\nseverity: HIGH\nbackend: cosmos\n",
            )
            self.assertEqual(self.mod.yaml_backend(p), "cosmos")

    def test_anchor_backend(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = self._write(
                tmp, "p.yaml",
                "pattern: p\nseverity: HIGH\nbackend: anchor\n",
            )
            self.assertEqual(self.mod.yaml_backend(p), "anchor")

    def test_unreadable_file_defaults_to_solidity(self):
        # _read returns "" on missing file; yaml_backend returns
        # "solidity" rather than raising.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self.assertEqual(
                self.mod.yaml_backend(tmp / "missing.yaml"),
                "solidity",
            )

    def test_typo_backend_round_trips_for_lint_to_classify(self):
        """yaml_backend itself never validates — Check 7b does."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = self._write(
                tmp, "p.yaml",
                "pattern: p\nseverity: HIGH\nbackend: solidty\n",
            )
            self.assertEqual(self.mod.yaml_backend(p), "solidty")


class FunctionKindCheckBackendAwareTest(unittest.TestCase):
    """`check_function_kind_unknown` skips non-Solidity backends."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _scan_dir(self, dsl_dir: Path):
        return self.mod.check_function_kind_unknown(dsl_dir=dsl_dir)

    def test_solidity_default_with_unknown_value_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                match:
                  - function.kind: cosmos_msg_handler
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("cosmos_msg_handler", hits[0])

    def test_explicit_solidity_with_unknown_value_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                backend: solidity
                match:
                  - function.kind: cosmos_msg_handler
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(len(hits), 1, hits)

    def test_cosmos_backend_with_cosmos_marker_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                backend: cosmos
                match:
                  - function.kind: cosmos_msg_handler
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(hits, [], hits)

    def test_anchor_backend_with_handler_marker_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                backend: anchor
                match:
                  - function.kind: anchor_instruction
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(hits, [], hits)

    def test_rust_backend_with_type_definition_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                backend: rust
                match:
                  - function.kind: type_definition
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(hits, [], hits)

    def test_solidity_with_known_good_value_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(textwrap.dedent("""
                pattern: p
                severity: HIGH
                match:
                  - function.kind: external_or_public
            """).lstrip())
            hits = self._scan_dir(tmp)
            self.assertEqual(hits, [], hits)


class InvalidBackendCheckTest(unittest.TestCase):
    """Check 7b — typos and unknown backends fail closed."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _scan_dir(self, dsl_dir: Path):
        return self.mod.check_invalid_backend(dsl_dir=dsl_dir)

    def test_no_backend_no_hit(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text("pattern: p\nseverity: HIGH\n")
            self.assertEqual(self._scan_dir(tmp), [])

    def test_valid_backends_no_hit(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for i, b in enumerate(self.mod.VALID_BACKENDS):
                (tmp / f"p{i}.yaml").write_text(
                    f"pattern: p{i}\nseverity: HIGH\nbackend: {b}\n"
                )
            self.assertEqual(self._scan_dir(tmp), [])

    def test_typo_backend_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(
                "pattern: p\nseverity: HIGH\nbackend: solidty\n"
            )
            hits = self._scan_dir(tmp)
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("solidty", hits[0])
            self.assertIn("VALID_BACKENDS", hits[0])

    def test_unknown_backend_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "p.yaml").write_text(
                "pattern: p\nseverity: HIGH\nbackend: my_homebrew_engine\n"
            )
            hits = self._scan_dir(tmp)
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("my_homebrew_engine", hits[0])

    def test_mix_of_valid_and_invalid_only_flags_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "good.yaml").write_text(
                "pattern: g\nseverity: HIGH\nbackend: cosmos\n"
            )
            (tmp / "bad.yaml").write_text(
                "pattern: b\nseverity: HIGH\nbackend: cosmoss\n"
            )
            hits = self._scan_dir(tmp)
            self.assertEqual(len(hits), 1, hits)
            self.assertIn("cosmoss", hits[0])
            self.assertNotIn("cosmos\n", hits[0])  # didn't conflate


class IntegrationTest(unittest.TestCase):
    """End-to-end: real corpus passes both Check 7 and Check 7b."""

    def setUp(self):
        self.mod = _load_lint_module()

    def test_real_corpus_check_7_clean(self):
        # The 2026-04-29 burn-down moved all non-Solidity rows to a
        # `backend:` declaration. Check 7 (Solidity-only) must be 0.
        hits = self.mod.check_function_kind_unknown()
        self.assertEqual(
            hits, [],
            "Check 7 should be 0 after backend split — got: " + repr(hits[:5]),
        )

    def test_real_corpus_check_7b_clean(self):
        # No invalid backends in the real corpus.
        hits = self.mod.check_invalid_backend()
        self.assertEqual(
            hits, [],
            "Check 7b should be 0 in real corpus — got: " + repr(hits),
        )


if __name__ == "__main__":
    unittest.main()
