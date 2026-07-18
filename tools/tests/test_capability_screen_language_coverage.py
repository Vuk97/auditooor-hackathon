#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-STEP2-SCREEN-ENFORCE registered via agent-pathspec-register.py -->
"""Regression test for the axelar-sc step-2 screen-pass enforcement-hole fix.

BACKGROUND: the 77 wired phase-2 (audit-deep) capability screens ran 75/77 on
axelar-dlt and 66/77 on nuva but only 8/77 on axelar-sc, because step-2's
done-verification only checked for a single aggregate audit-deep manifest
file, never for whether the language-applicable SCREEN PASS itself emitted
hypotheses artifacts. tools/capability-screen-language-coverage.py (wired
into tools/readme-conformance-check.py as check type
"capability_screen_language_coverage" on step-2) fixes this fail-closed and
LANGUAGE-AWARE: a workspace is only required to show screen output for the
language buckets its own detected languages trigger.

Pins:
  (a) A Solidity-only workspace with NO screen hypotheses artifacts -> the
      capability_screen_language_coverage check FAILS (step-2 unmet).
  (b) The same workspace with a language-agnostic/Solidity screen hypotheses
      artifact present -> the check PASSES (step-2 met on this axis).
  (c) The same Solidity workspace missing ONLY go-*/rust-* screen artifacts
      (Go/Rust are not in-scope languages for this workspace) -> the check
      still PASSES - it is never blocked for an inapplicable language
      bucket.

Also exercises the full readme-conformance-check.py step-2-shaped manifest
end to end (not just the coverage helper in isolation) so the wiring itself
(not merely the standalone module) is pinned.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent.parent
_COVERAGE_TOOL = _TOOLS_DIR / "capability-screen-language-coverage.py"
_CONFORMANCE_TOOL = _TOOLS_DIR / "readme-conformance-check.py"


def _load(path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = m
    spec.loader.exec_module(m)
    return m


# A trimmed fake CURATED_FULL_WIRING so the test does not depend on the real
# (large, evolving) 77-entry registry in capability-inventory-build.py - it
# only needs entries in each bucket to exercise the classification+coverage
# logic hermetically.
_FAKE_WIRING = {
    "tools/some-solidity-screen.py": {
        "outputs": ["some_solidity_screen_hypotheses.jsonl"],
    },
    "tools/go-detector-runner.py": {
        "outputs": ["consensus_write_determinism_census_hypotheses.jsonl"],
    },
    "tools/rust-detector-runner.py": {
        "outputs": ["rust_panic_reach_hypotheses.jsonl"],
    },
    "tools/non-screen-producer.py": {
        # not a screen (no hypotheses.jsonl output) - must not enter the registry
        "outputs": ["some_other_artifact.json"],
    },
}


class CapabilityScreenLanguageCoverageUnitTest(unittest.TestCase):
    """Direct tests of the standalone coverage helper."""

    def setUp(self):
        self.m = _load(_COVERAGE_TOOL, "capability_screen_language_coverage")
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True, exist_ok=True)

    def _write_artifact(self, name: str) -> None:
        (self.tmp / ".auditooor" / name).write_text(
            json.dumps({"schema": "test.v1"}) + "\n", encoding="utf-8"
        )

    def test_a_solidity_ws_no_screens_fails(self):
        """(a) Solidity-only ws, zero screen artifacts -> FAIL."""
        res = self.m.evaluate(self.tmp, {"solidity", "evm"}, wiring=_FAKE_WIRING)
        self.assertFalse(res["ok"], res)
        self.assertIn("agnostic", res["required_buckets"])
        self.assertTrue(
            any("agnostic" in f for f in res["failures"]),
            f"expected an agnostic-bucket failure, got {res['failures']}",
        )

    def test_b_solidity_ws_with_screens_passes(self):
        """(b) Solidity-only ws WITH a language-agnostic screen artifact -> PASS."""
        self._write_artifact("some_solidity_screen_hypotheses.jsonl")
        res = self.m.evaluate(self.tmp, {"solidity", "evm"}, wiring=_FAKE_WIRING)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["failures"], [])

    def test_c_solidity_ws_missing_only_go_rust_still_passes(self):
        """(c) Solidity ws has its own screens but no go-*/rust-* screens ->
        still PASS because Go/Rust are not in-scope languages here."""
        self._write_artifact("some_solidity_screen_hypotheses.jsonl")
        res = self.m.evaluate(self.tmp, {"solidity", "evm"}, wiring=_FAKE_WIRING)
        self.assertTrue(res["ok"], res)
        self.assertNotIn("go", res["required_buckets"])
        self.assertNotIn("rust", res["required_buckets"])

    def test_go_ws_requires_go_bucket_not_agnostic(self):
        """Sanity/inverse: a Go-only ws requires the go bucket, and is NOT
        blocked for the missing language-agnostic/Solidity bucket."""
        res = self.m.evaluate(self.tmp, {"go"}, wiring=_FAKE_WIRING)
        self.assertFalse(res["ok"], res)
        self.assertEqual(res["required_buckets"], ["go"])
        self._write_artifact("consensus_write_determinism_census_hypotheses.jsonl")
        res2 = self.m.evaluate(self.tmp, {"go"}, wiring=_FAKE_WIRING)
        self.assertTrue(res2["ok"], res2)

    def test_bucket_classification(self):
        self.assertEqual(self.m._bucket_for_tool_path("tools/go-slice-aliasing-screen.py"), "go")
        self.assertEqual(self.m._bucket_for_tool_path("tools/consensus-map-order-return-screen.py"), "go")
        self.assertEqual(self.m._bucket_for_tool_path("tools/rust-eager-alloc-nomax-screen.py"), "rust")
        self.assertEqual(self.m._bucket_for_tool_path("tools/transmute-type-confusion-screen.py"), "rust")
        self.assertEqual(self.m._bucket_for_tool_path("tools/raii-drop-glue-bypass-on-error-path-screen.py"), "rust")
        self.assertEqual(self.m._bucket_for_tool_path("tools/panic-during-drop-screen.py"), "rust")
        self.assertEqual(self.m._bucket_for_tool_path("tools/js-oscript-value-moving-surface.py"), "js")
        self.assertEqual(self.m._bucket_for_tool_path("tools/zk-lookup-membership-bound.py"), "zk")
        self.assertEqual(self.m._bucket_for_tool_path("tools/some-solidity-screen.py"), "agnostic")

    def test_non_screen_outputs_excluded_from_registry(self):
        registry = self.m.screen_registry(_FAKE_WIRING)
        all_names = [n for names in registry.values() for n in names]
        self.assertNotIn("some_other_artifact.json", all_names)


class ReadmeConformanceStep2WiringTest(unittest.TestCase):
    """End-to-end: the check type as wired into readme-conformance-check.py's
    step evaluator, using a step-2-shaped manifest entry (mirrors the real
    tools/readme_runbook_steps.json step-2 artifact_checks list, trimmed)."""

    def setUp(self):
        self.conf = _load(_CONFORMANCE_TOOL, "readme_conformance_check_step2_test")
        # Patch the coverage module's screen_registry to use the fake wiring
        # so this test does not depend on the real (large) capability
        # inventory - hermetic per the task's regression-test requirement.
        self.cov = _load(_COVERAGE_TOOL, "capability_screen_language_coverage_step2_test")
        self._orig_registry = self.cov.screen_registry
        self.cov.screen_registry = lambda wiring=None: self._orig_registry(_FAKE_WIRING)
        self.conf._screen_coverage_mod = self.cov

        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.tmp / "src").mkdir(parents=True, exist_ok=True)
        (self.tmp / "src" / "Foo.sol").write_text("contract Foo {}\n", encoding="utf-8")

        self.manifest = {
            "_schema_version": "test.v1",
            "waiver_file": ".auditooor/readme_step_waivers.txt",
            "steps": [
                {
                    "step_id": "step-2",
                    "label": "audit-deep",
                    "class": "conditional-mechanical",
                    "required": True,
                    "language_filter": None,
                    "how_to_verify_done": {
                        "artifact_checks": [
                            {"type": "capability_screen_language_coverage"},
                        ],
                        "attestation_required": False,
                    },
                },
            ],
        }
        self.manifest_path = self.tmp / "manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def tearDown(self):
        self.cov.screen_registry = self._orig_registry

    def _step2_status(self):
        res = self.conf.evaluate(self.tmp, self.manifest_path)
        rows = {s["step_id"]: s for s in res["steps"]}
        return rows["step-2"]

    def test_a_no_screens_step2_red(self):
        row = self._step2_status()
        self.assertEqual(row["status"], "red", row)

    def test_b_agnostic_screen_present_step2_done(self):
        (self.tmp / ".auditooor" / "some_solidity_screen_hypotheses.jsonl").write_text(
            "{}\n", encoding="utf-8"
        )
        row = self._step2_status()
        self.assertEqual(row["status"], "done", row)

    def test_c_missing_go_rust_only_step2_still_done(self):
        (self.tmp / ".auditooor" / "some_solidity_screen_hypotheses.jsonl").write_text(
            "{}\n", encoding="utf-8"
        )
        # Deliberately do NOT write go/rust screen artifacts - this workspace
        # has no .go/.rs files so those buckets must not be required.
        row = self._step2_status()
        self.assertEqual(row["status"], "done", row)


if __name__ == "__main__":
    unittest.main()
