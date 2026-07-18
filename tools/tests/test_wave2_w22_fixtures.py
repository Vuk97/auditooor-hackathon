#!/usr/bin/env python3
"""Regression tests for the Wave-2 W2.2 Phase-1 detector fixture scaffold.

Status: PREVIEW. The fixtures under
``tools/audit/detector_fixtures/wave2_w22/`` are NOT wired into
``make audit`` or ``tools/audit-deep-runner.py``. They are template
scaffolding for the 20-detector hand-curated tier-1 roster described in
``docs/WAVE2_W22_DETECTOR_AUTOGEN_SPEC_2026-05-16.md`` section 10.

What this suite enforces today (5 of 20 template detectors):

1. Each detector dir contains exactly one positive snippet, one
   negative snippet, and one ``expected.json``.
2. Positive and negative file extensions match the detector's declared
   language.
3. ``expected.json`` has the canonical shape (detector_id, language,
   attack_class, tier, severity_hint, expected_positive_hits,
   expected_negative_hits, source_records, fixture_status, phase).
4. ``detector_id`` field inside ``expected.json`` matches the directory
   name.
5. ``severity_hint`` is HIGH or CRITICAL (Phase-1 floor).
6. ``tier`` is exactly ``tier-1``.
7. ``fixture_status`` is exactly ``preview_scaffold``.
8. Deterministic ordering: the sorted directory listing matches the
   canonical roster (catches accidental rename / drift).

The suite is intentionally tolerant of source-record existence (the
records are pointed at the corpus by path, but the fixtures are
allowed to reference placeholder paths until Wave-2 synthesiser run).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "tools" / "audit" / "detector_fixtures" / "wave2_w22"

# Canonical Phase-1 template roster (5 of 20). The full 20 will be
# filled by the Wave-2 synthesiser + operator PR-review pass.
CANONICAL_ROSTER = {
    "w22_circom_under_constrained": {
        "language": "circom",
        "ext": ".circom",
        "attack_class": "unconstrained-variable",
    },
    "w22_go_cometbft_validate_basic": {
        "language": "go",
        "ext": ".go",
        "attack_class": "ghsa-public-advisory-go-cosmos-ibc-stack",
    },
    "w22_rs_l2_zksolc_compile": {
        "language": "rust",
        "ext": ".rs",
        "attack_class": "ghsa-public-advisory-rust-l2-rollup-stack",
    },
    "w22_sol_reentrancy_curve_stable": {
        "language": "solidity",
        "ext": ".sol",
        "attack_class": "reentrancy-curve-stablecoin",
    },
    "w22_vy_reentrancy_curve_ib": {
        "language": "vyper",
        "ext": ".vy",
        "attack_class": "reentrancy-curve-ib",
    },
}

REQUIRED_EXPECTED_KEYS = {
    "detector_id",
    "language",
    "attack_class",
    "tier",
    "severity_hint",
    "expected_positive_hits",
    "expected_negative_hits",
    "source_records",
    "fixture_status",
    "phase",
}

ALLOWED_SEVERITY = {"HIGH", "CRITICAL"}


class Wave2W22FixtureScaffoldTests(unittest.TestCase):
    """Structural gate for the Phase-1 W2.2 detector fixture scaffold."""

    def setUp(self) -> None:
        self.assertTrue(
            FIXTURES_ROOT.is_dir(),
            f"fixtures root not found: {FIXTURES_ROOT}",
        )

    # ----- Case 1: top-level directory presence -----
    def test_fixtures_root_exists_and_has_readme(self) -> None:
        readme = FIXTURES_ROOT / "README.md"
        self.assertTrue(
            readme.is_file(),
            f"missing README at {readme} (operator-facing doc required)",
        )

    # ----- Case 2: deterministic ordering of the roster -----
    def test_directory_listing_matches_canonical_roster(self) -> None:
        on_disk = sorted(
            p.name for p in FIXTURES_ROOT.iterdir() if p.is_dir()
        )
        expected = sorted(CANONICAL_ROSTER.keys())
        self.assertEqual(
            on_disk,
            expected,
            "directory listing drifted from canonical roster -- did a "
            "detector get renamed without updating the test?",
        )

    # ----- Case 3: positive/negative pair completeness per detector -----
    def test_positive_negative_pair_present(self) -> None:
        for detector_id, meta in CANONICAL_ROSTER.items():
            with self.subTest(detector=detector_id):
                ddir = FIXTURES_ROOT / detector_id
                pos = ddir / f"positive{meta['ext']}"
                neg = ddir / f"negative{meta['ext']}"
                self.assertTrue(
                    pos.is_file(),
                    f"missing positive snippet: {pos}",
                )
                self.assertTrue(
                    neg.is_file(),
                    f"missing negative snippet: {neg}",
                )
                self.assertGreater(
                    pos.stat().st_size,
                    0,
                    f"empty positive snippet: {pos}",
                )
                self.assertGreater(
                    neg.stat().st_size,
                    0,
                    f"empty negative snippet: {neg}",
                )

    # ----- Case 4: expected.json existence + JSON parses -----
    def test_expected_json_present_and_parses(self) -> None:
        for detector_id in CANONICAL_ROSTER:
            with self.subTest(detector=detector_id):
                expected_path = (
                    FIXTURES_ROOT / detector_id / "expected.json"
                )
                self.assertTrue(
                    expected_path.is_file(),
                    f"missing expected.json: {expected_path}",
                )
                try:
                    payload = json.loads(expected_path.read_text())
                except json.JSONDecodeError as exc:
                    self.fail(
                        f"expected.json is not valid JSON ({expected_path}): {exc}"
                    )
                self.assertIsInstance(payload, dict)

    # ----- Case 5: expected.json canonical shape -----
    def test_expected_json_canonical_shape(self) -> None:
        for detector_id in CANONICAL_ROSTER:
            with self.subTest(detector=detector_id):
                payload = json.loads(
                    (FIXTURES_ROOT / detector_id / "expected.json").read_text()
                )
                missing = REQUIRED_EXPECTED_KEYS - set(payload.keys())
                self.assertFalse(
                    missing,
                    f"{detector_id}: expected.json missing keys {sorted(missing)}",
                )
                self.assertEqual(payload["detector_id"], detector_id)
                self.assertEqual(payload["tier"], "tier-1")
                self.assertEqual(payload["fixture_status"], "preview_scaffold")
                self.assertEqual(payload["phase"], "wave2_w22_phase_1")
                self.assertIn(payload["severity_hint"], ALLOWED_SEVERITY)
                self.assertGreaterEqual(payload["expected_positive_hits"], 1)
                self.assertEqual(payload["expected_negative_hits"], 0)
                self.assertIsInstance(payload["source_records"], list)
                self.assertGreaterEqual(
                    len(payload["source_records"]),
                    1,
                    f"{detector_id}: must reference at least one source record",
                )

    # ----- Case 6: language + extension alignment per detector -----
    def test_language_and_extension_alignment(self) -> None:
        for detector_id, meta in CANONICAL_ROSTER.items():
            with self.subTest(detector=detector_id):
                payload = json.loads(
                    (FIXTURES_ROOT / detector_id / "expected.json").read_text()
                )
                self.assertEqual(
                    payload["language"],
                    meta["language"],
                    f"{detector_id}: language mismatch",
                )
                # No stray files with the wrong extension inside dir.
                stray = [
                    p.name
                    for p in (FIXTURES_ROOT / detector_id).iterdir()
                    if p.is_file()
                    and p.suffix not in {meta["ext"], ".json"}
                    and p.name != "README.md"
                ]
                self.assertEqual(
                    stray,
                    [],
                    f"{detector_id}: stray files with wrong extension: {stray}",
                )

    # ----- Case 7: attack_class field stable across roster -----
    def test_attack_class_matches_canonical(self) -> None:
        for detector_id, meta in CANONICAL_ROSTER.items():
            with self.subTest(detector=detector_id):
                payload = json.loads(
                    (FIXTURES_ROOT / detector_id / "expected.json").read_text()
                )
                self.assertEqual(
                    payload["attack_class"],
                    meta["attack_class"],
                    f"{detector_id}: attack_class drifted from canonical",
                )

    # ----- Case 8: out-of-scope guard (NOT wired into make audit) -----
    def test_scaffold_not_wired_into_make_audit(self) -> None:
        """Phase-1/2 scaffold MUST NOT be wired into the load-bearing
        ``make audit`` / ``make audit-deep`` recipes.

        Per spec section 10 acceptance: detectors are not wired into the
        production audit pipeline until the operator PR-reviews the
        synthesiser output. A test here protects against accidental early
        wiring that would break the kill-switch contract.

        Standalone opt-in smoke targets (e.g. ``wave3-w22-phase2-smoke``)
        are allowed to reference the scaffold - they are explicit
        operator-invoked targets, not part of the default audit run. The
        gate therefore inspects only the ``audit:`` / ``audit-deep:``
        recipe BODIES, not the whole Makefile.
        """
        makefile = REPO_ROOT / "Makefile"
        if not makefile.is_file():
            self.skipTest("no Makefile at repo root; nothing to verify")
        lines = makefile.read_text().splitlines()
        # Collect the recipe body lines belonging to the load-bearing
        # `audit:` and `audit-deep:` targets. A recipe body line starts
        # with a TAB; the recipe ends at the first non-tab, non-blank line.
        guarded_targets = ("audit:", "audit-deep:")
        in_recipe = False
        recipe_lines: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            if not line.startswith("\t") and stripped:
                # Target header line. Enter recipe mode iff it is one of
                # the guarded targets.
                in_recipe = any(
                    line.startswith(t) or line.startswith(t.rstrip(":") + " ")
                    for t in guarded_targets
                )
                continue
            if in_recipe and line.startswith("\t"):
                recipe_lines.append(line)
        body = "\n".join(recipe_lines)
        self.assertNotIn(
            "wave2_w22",
            body,
            "wave2_w22 fixtures are wired into the load-bearing "
            "`make audit`/`make audit-deep` recipe; that violates the "
            "Phase-1/2 'not wired' acceptance gate. Standalone opt-in "
            "smoke targets are fine - the default audit run must stay clean.",
        )


if __name__ == "__main__":
    unittest.main()
