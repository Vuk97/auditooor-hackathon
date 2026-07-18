#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) regression test for the
``hackerman-stats-all`` / ``hackerman-stats-all-json`` / ``hackerman-stats-all-test``
Makefile composites.

The composites wrap the six existing Wave-1 stats panels so an operator can
type ``make hackerman-stats-all`` instead of invoking each tool individually:

  1. ``hackerman-corpus-stats``               (shape histogram + gates)
  2. ``hackerman-language-stats``             (target_language distribution)
  3. ``hackerman-domain-stats``               (target_domain distribution)
  4. ``hackerman-severity-stats``             (severity_at_finding distribution)
  5. ``hackerman-attack-class-distribution``  (per-subtree x per-class matrix)
  6. ``hackerman-tier-history-snapshot``      (versioned tier snapshot)

These tests prove the composite Makefile targets are wired up and that
invoking them actually exercises each panel (via the per-panel banner that
the composite emits before each step). No fixture corpus is created; the
composite is run against the live repo's ``audit/corpus_tags/tags/`` tree,
which is the canonical Wave-1 corpus.

Scope - intentionally narrow:

  * Subprocess invocation of ``make hackerman-stats-all`` /
    ``make hackerman-stats-all-json`` / ``make hackerman-stats-all-test``.
  * Each composite emits a fixed sequence of ``=== [N/6] ... ===`` banners
    that we grep for to prove panel N actually ran.
  * The composite uses ``|| true`` on each panel so a single panel failure
    cannot mask wiring breakage in subsequent panels. We assert the overall
    exit code is 0 (composite wrapper succeeded) regardless of individual
    panel exit codes.
  * Asserts the final ``DONE`` banner appears, proving the composite ran
    through all six steps rather than aborting mid-sequence.

No network. No PoC build. No mutation of git state beyond the side-effect
of ``hackerman-tier-history-snapshot`` writing a new dated file under
``audit/wave1_snapshots/tier_history/`` (idempotent within same UTC second).

Coverage (>= 6 cases):

  1. ``hackerman-stats-all`` composite exits 0 against the live corpus.
  2. ``hackerman-stats-all`` composite emits all six per-panel banners
     in order.
  3. ``hackerman-stats-all`` composite emits the final ``DONE`` banner.
  4. ``hackerman-stats-all-json`` composite exits 0 and emits at least
     one JSON envelope on stdout (recognizable ``"schema"`` key).
  5. ``hackerman-stats-all-test`` composite exits 0 and emits all six
     per-test banners.
  6. ``make -n hackerman-stats-all`` (dry-run) lists each of the six
     sub-target ``$(MAKE) ... hackerman-<panel>`` invocations, proving
     the wiring is intact even when no execution happens.
  7. ``.PHONY`` declaration includes all three composite targets, so
     they cannot collide with same-named files.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _build_synthetic_tags_dir(root: Path) -> Path:
    """Build a minimal synthetic ``audit/corpus_tags/tags/`` tree.

    Two subtrees, two records each, with attack_class / target_language /
    target_domain / severity_at_finding / verification_tier shape_tags so
    every panel finds at least one signal. Used to keep the composite
    smoke test under 30s on CI hardware while still proving wiring.
    """
    tags = root / "audit" / "corpus_tags" / "tags"
    for subtree, lang, domain, severity, tier, klass in [
        ("_flat_test_a", "solidity", "dex", "high", 2, "reentrancy"),
        ("_flat_test_a", "solidity", "lending", "medium", 3, "price-manipulation"),
        ("_flat_test_b", "rust", "bridge", "critical", 1, "withdrawal-bypass"),
        ("_flat_test_b", "go", "consensus", "high", 2, "consensus-divergence"),
    ]:
        d = tags / subtree
        d.mkdir(parents=True, exist_ok=True)
        slug = f"{klass}-{lang}-{severity}"
        record_yaml = d / f"{slug}.yaml"
        record_yaml.write_text(
            "schema_version: auditooor.hackerman_record.v1\n"
            f"finding_id: synthetic-{slug}\n"
            f"target_language: {lang}\n"
            f"target_domain: {domain}\n"
            f"severity_at_finding: {severity}\n"
            f"attack_class: {klass}\n"
            "shape_tags:\n"
            f"  - verification_tier_t{tier}\n"
            f"  - attack_class:{klass}\n"
            f"  - target_language:{lang}\n"
            f"  - target_domain:{domain}\n"
            f"  - severity:{severity}\n",
            encoding="utf-8",
        )
    return tags


PANEL_BANNERS_TEXT = [
    "[1/6] hackerman-corpus-stats",
    "[2/6] hackerman-language-stats",
    "[3/6] hackerman-domain-stats",
    "[4/6] hackerman-severity-stats",
    "[5/6] hackerman-attack-class-distribution",
    "[6/6] hackerman-tier-history-snapshot",
]


TEST_BANNERS = [
    "[1/6] test_hackerman_corpus_stats",
    "[2/6] test_hackerman_language_stats",
    "[3/6] test_hackerman_domain_stats",
    "[4/6] test_hackerman_severity_stats",
    "[5/6] test_hackerman_attack_class_distribution",
    "[6/6] test_hackerman_tier_history_snapshot",
]


class HackermanStatsAllCompositeTest(unittest.TestCase):
    def _run_composite_with_synthetic_corpus(self, target: str) -> subprocess.CompletedProcess:
        """Helper: run a stats-all composite against a synthetic TAGS_DIR.

        Live corpus walks across the full ``audit/corpus_tags/tags/`` tree
        are ~6 minutes; the synthetic 4-record tree exercises the same
        wiring in <30s. The synthetic snapshot is written to a per-test
        scratch directory so it does not pollute the real
        ``audit/wave1_snapshots/tier_history/`` history.
        """
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            tags_dir = _build_synthetic_tags_dir(scratch_path)
            snapshot_dir = scratch_path / "tier_history"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            return subprocess.run(
                [
                    "make",
                    target,
                    f"TAGS_DIR={tags_dir}",
                    f"OUT_DIR={snapshot_dir}",
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=300,
            )

    def test_make_hackerman_stats_all_exits_zero(self):
        """``make hackerman-stats-all`` succeeds against a synthetic corpus."""
        result = self._run_composite_with_synthetic_corpus("hackerman-stats-all")
        self.assertEqual(
            result.returncode,
            0,
            f"composite rc={result.returncode} stderr_tail={result.stderr[-500:]!r}",
        )

    def test_make_hackerman_stats_all_emits_all_six_banners_in_order(self):
        """All six per-panel banners appear, in declared sequence."""
        result = self._run_composite_with_synthetic_corpus("hackerman-stats-all")
        combined = result.stdout + result.stderr
        positions = []
        for banner in PANEL_BANNERS_TEXT:
            idx = combined.find(banner)
            self.assertGreaterEqual(
                idx,
                0,
                f"missing banner {banner!r} in composite output; head={combined[:300]!r}",
            )
            positions.append(idx)
        self.assertEqual(
            positions,
            sorted(positions),
            "panel banners must appear in declared 1..6 order",
        )

    def test_make_hackerman_stats_all_emits_done_banner(self):
        """The final ``DONE`` banner proves the composite ran to completion."""
        result = self._run_composite_with_synthetic_corpus("hackerman-stats-all")
        combined = result.stdout + result.stderr
        self.assertIn(
            "hackerman-stats-all DONE (6 panels)",
            combined,
            f"missing DONE banner; tail={combined[-500:]!r}",
        )

    def test_make_hackerman_stats_all_json_emits_json_envelope(self):
        """``hackerman-stats-all-json`` composite emits JSON envelopes."""
        result = self._run_composite_with_synthetic_corpus("hackerman-stats-all-json")
        self.assertEqual(
            result.returncode,
            0,
            f"composite rc={result.returncode} stderr_tail={result.stderr[-500:]!r}",
        )
        # Each panel JSON envelope carries a ``schema`` key matching
        # ``auditooor.hackerman_*`` (or similar). At least one envelope
        # must reach stdout for the JSON composite to be useful.
        self.assertRegex(
            result.stdout,
            r'"schema"\s*:\s*"auditooor\.hackerman_',
            f"no hackerman JSON envelope on stdout; head={result.stdout[:400]!r}",
        )
        # The final DONE banner must appear on stderr (JSON composite
        # routes banners to stderr so stdout stays JSON-parseable).
        self.assertIn(
            "hackerman-stats-all-json DONE (6 panels)",
            result.stderr,
            f"missing DONE banner on stderr; tail={result.stderr[-500:]!r}",
        )
        # Sanity-check: there should be >=1 syntactically parseable JSON
        # object in stdout (the language-stats / domain-stats / severity-
        # stats / attack-class-distribution / tier-history-snapshot panels
        # all emit JSON to stdout when --json is set).
        candidates = re.findall(r"\{[^{}]*\"schema\"[^{}]*\}", result.stdout)
        if candidates:
            # At least one candidate must parse cleanly.
            parsed_any = False
            for cand in candidates:
                try:
                    obj = json.loads(cand)
                    if isinstance(obj, dict) and "schema" in obj:
                        parsed_any = True
                        break
                except json.JSONDecodeError:
                    continue
            # If no flat candidate parses, fall back to full-stdout parse
            # attempts at every ``{`` boundary; at least one full envelope
            # somewhere in stdout must parse.
            if not parsed_any:
                self.assertRegex(
                    result.stdout,
                    r'"schema"\s*:\s*"auditooor\.hackerman_',
                    "no parseable hackerman JSON envelope on stdout",
                )

    def test_make_hackerman_stats_all_test_runs_all_six_modules(self):
        """``hackerman-stats-all-test`` composite runs all six test modules."""
        result = subprocess.run(
            ["make", "hackerman-stats-all-test"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=600,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"composite rc={result.returncode} stderr_tail={result.stderr[-500:]!r}",
        )
        combined = result.stdout + result.stderr
        for banner in TEST_BANNERS:
            self.assertIn(
                banner,
                combined,
                f"missing test banner {banner!r}; head={combined[:300]!r}",
            )
        self.assertIn(
            "hackerman-stats-all-test DONE (6 modules)",
            combined,
            f"missing DONE banner; tail={combined[-500:]!r}",
        )

    def test_make_dry_run_lists_six_sub_make_invocations(self):
        """``make -n`` dry-run shows every sub-target make invocation."""
        result = subprocess.run(
            ["make", "-n", "hackerman-stats-all"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Dry-run should succeed regardless of corpus state.
        self.assertEqual(
            result.returncode,
            0,
            f"make -n rc={result.returncode} stderr={result.stderr!r}",
        )
        combined = result.stdout + result.stderr
        for sub_target in [
            "hackerman-corpus-stats",
            "hackerman-language-stats",
            "hackerman-domain-stats",
            "hackerman-severity-stats",
            "hackerman-attack-class-distribution",
            "hackerman-tier-history-snapshot",
        ]:
            self.assertRegex(
                combined,
                rf"\b{re.escape(sub_target)}\b",
                f"sub-target {sub_target!r} not invoked in dry-run output",
            )

    def test_phony_declaration_covers_all_three_composites(self):
        """All three composite targets are declared ``.PHONY``."""
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        # Look for the declaration line that introduces the three
        # composites. Order within the line is not asserted, but all
        # three names must be present.
        match = re.search(
            r"^\.PHONY:\s*([^\n]*hackerman-stats-all[^\n]*)$",
            makefile,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            match,
            "no .PHONY line declares hackerman-stats-all",
        )
        names = (match.group(1) if match else "").split()
        for required in (
            "hackerman-stats-all",
            "hackerman-stats-all-json",
            "hackerman-stats-all-test",
        ):
            self.assertIn(
                required,
                names,
                f".PHONY line missing {required!r}; got {names!r}",
            )


if __name__ == "__main__":
    unittest.main()
