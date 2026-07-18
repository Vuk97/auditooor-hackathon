"""audit-text-to-specs.py — pure-helper regression suite.

Background — quoted from auto-improvement queue iter 2
(2026-04-25_23:25:22), Minimax idea 3:

    File: tools/audit-text-to-specs.py
    What: audit-text-to-specs.py converts natural-language audit notes to
    structured specs. It has no regression suite ... add smoke tests:
    feed a minimal note file ... and assert the tool emits valid YAML
    with a `specs:` key, a `finding:` field, and a `severity:` field.
    Success criterion: pytest tests/test_audit_text_to_specs.py -v passes
    with 3 assertion cases.

Kimi precheck (GAP-CONFIRMED):
    `tools/audit-text-to-specs.py` exists but `find` under `tests/` returns
    no `test_audit_text_to_specs.py`. `tests/fixtures/audit-text-to-specs/`
    is absent.

Calibration: Kimi-grep-prechecked. Kimi has 0/3 audit-style FP rate but a
higher rate on idea-prechecks. Supervisor verified by listing
`tools/tests/` for any matching name (none found) before shipping.

Note on framing: the Minimax idea proposed YAML output schema assertions
(`specs:` / `finding:` / `severity:` keys). Reading the actual emitter
shows the YAML schema is a per-detector full spec (no top-level `specs:`
key, the per-finding YAML uses different keys). To avoid baking a wrong
schema into the test (which would either silently FP or block legitimate
schema evolution), this PR covers the **pure helper functions** that the
emitter is built on:

  1. `_kebabize` — name → kebab-case detector id (with leading-letter
     guard so detectors become valid Python module names).
  2. `_pascal` — kebab → PascalCase identifier; empty input → "Finding".
  3. `_norm_sev` — severity normalization to {HIGH,MEDIUM,LOW,""}; the
     SEVERITY_MAP must collapse C/CRIT/CRITICAL → HIGH and INFO → LOW.
  4. `_classify_skeleton` — heuristic skeleton selection across the 5
     supported templates.
  5. `_is_non_evm_filename` — flag Solana / Move / Cairo files so they
     are skipped from EVM detector mining.

These helpers carry the load-bearing logic; full end-to-end YAML-schema
testing belongs in a follow-up that the schema owner can pin
deliberately.
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "audit-text-to-specs.py"


def _load_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("audit_text_to_specs", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KebabizeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_basic_lowercase(self) -> None:
        self.assertEqual(self.t._kebabize("Hello World"), "hello-world")

    def test_collapses_runs_and_strips(self) -> None:
        # Multiple separators collapse into a single hyphen and edges trim.
        self.assertEqual(self.t._kebabize("---foo___bar  baz!!!"), "foo-bar-baz")

    def test_leading_digit_gets_prefix(self) -> None:
        # Detector ids become Python module names — must start with a letter.
        out = self.t._kebabize("123finding")
        self.assertTrue(out.startswith("f-"), f"got: {out!r}")
        self.assertEqual(out, "f-123finding")

    def test_truncates_to_70(self) -> None:
        long = "a" * 200
        self.assertEqual(len(self.t._kebabize(long)), 70)


class PascalTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_capitalises_each_segment(self) -> None:
        self.assertEqual(self.t._pascal("hello-world"), "HelloWorld")

    def test_empty_falls_back(self) -> None:
        self.assertEqual(self.t._pascal(""), "Finding")
        self.assertEqual(self.t._pascal("---"), "Finding")


class NormSevTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_critical_collapses_to_high(self) -> None:
        for raw in ("C", "Crit", "CRITICAL", "critical", "  Critical  "):
            self.assertEqual(self.t._norm_sev(raw), "HIGH",
                             f"raw={raw!r} should map to HIGH")

    def test_info_collapses_to_low(self) -> None:
        for raw in ("INFO", "Informational", "QA", "Non-critical".upper()):
            self.assertEqual(self.t._norm_sev(raw), "LOW",
                             f"raw={raw!r} should map to LOW")

    def test_passes_through_unknown(self) -> None:
        # Unknown labels are uppercased but not coerced.
        self.assertEqual(self.t._norm_sev("MAGIC"), "MAGIC")

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(self.t._norm_sev(""), "")
        self.assertEqual(self.t._norm_sev(None), "")


class ClassifySkeletonTest(unittest.TestCase):
    """Each branch of `_classify_skeleton` must be reachable; we lock the
    happy path for each one. The branches are documented in the source."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_paired_function_divergence(self) -> None:
        out = self.t._classify_skeleton(
            "addLiquidity-removeLiquidity-divergence",
            "addLiquidity updates state but removeLiquidity does not",
        )
        self.assertEqual(out, "paired_function_divergence")

    def test_missing_external_call(self) -> None:
        out = self.t._classify_skeleton(
            "wrapper-missing-sibling",
            "calls foo() without invoking the matching sibling",
        )
        self.assertEqual(out, "highlevelcall_missing_sibling")

    def test_missing_require(self) -> None:
        out = self.t._classify_skeleton(
            "uncapped-mint",
            "Function lacks a check for the mint cap",
        )
        self.assertEqual(out, "name_match_missing_require")

    def test_state_write_without_paired_write(self) -> None:
        out = self.t._classify_skeleton(
            "stale-flag",
            "sets the active flag but does not update the timestamp",
        )
        self.assertEqual(out, "state_write_without_paired_write")

    def test_default_falls_through(self) -> None:
        # Unmatched description hits the default skeleton.
        out = self.t._classify_skeleton("misc", "something happens here")
        self.assertEqual(out, "name_match_missing_call")


class NonEvmFilterTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_solana_path_is_filtered(self) -> None:
        self.assertTrue(self.t._is_non_evm_filename(Path("solana_program.txt")))

    def test_cairo_and_move_paths_are_filtered(self) -> None:
        self.assertTrue(self.t._is_non_evm_filename(Path("starknet-cairo.txt")))
        self.assertTrue(self.t._is_non_evm_filename(Path("aptos-move.txt")))

    def test_evm_path_is_kept(self) -> None:
        self.assertFalse(self.t._is_non_evm_filename(Path("ethereum-evm.txt")))
        self.assertFalse(self.t._is_non_evm_filename(Path("uniswap-v4.txt")))


if __name__ == "__main__":
    unittest.main()
