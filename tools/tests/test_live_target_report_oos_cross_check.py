#!/usr/bin/env python3
"""End-to-end tests for LIVE_TARGET_REPORT BUG_BOUNTY.md OOS cross-check.

<!-- r36-rebuttal: lane-CAP-FIX-W12-live-target-bug-bounty-oos registered via tools/agent-pathspec-register.py in agent_pathspec.json -->

Per CAP-FIX-W12 / CAP-GAP-92: the LIVE_TARGET_REPORT generator
(``tools/live-target-intelligence-report.py``) must consult the workspace's
``BUG_BOUNTY.md`` (or sibling OOS catalog) BEFORE ranking, so candidates
whose root cause maps to a known AI-FP / acknowledged-OOS row are either
filtered or downgraded to ``NEEDS-EXTENSION-DISTINCT-ARGUMENT`` (with a
``bug_bounty_oos_match`` annotation pointing at the matched clause).

The 4 cases in this file are the canonical CAP-FIX-W12 acceptance fixtures:

  1. Workspace has NO BUG_BOUNTY.md           -> ranking unchanged.
  2. BUG_BOUNTY.md present but 0 AI-FP rows   -> ranking unchanged.
  3. BUG_BOUNTY.md with 1 AI-FP row that
     matches a candidate                       -> candidate marked
     ``bug_bounty_oos_downranked`` and
     ``hunt_priority`` becomes
     ``NEEDS-EXTENSION-DISTINCT-ARGUMENT``.
  4. BUG_BOUNTY.md with N AI-FP rows and
     M candidates (some matched, some not)     -> only matched M are
     downranked; non-matched stay at their original priority.

Stdlib only. Offline. Each test builds an isolated fake workspace.

Empirical anchor: SuperEarn wave 1 (2026-05-27) dispatched 4 drills, all
4 matched BUG_BOUNTY.md AI-FP rows exactly = 4 wasted drill budgets the
report should have pre-filtered. Implementation lives in
``tools/live-target-intelligence-report.py`` (helpers
``_build_bug_bounty_oos_index`` + ``_apply_bug_bounty_oos_cross_check``)
backed by ``tools/bug_bounty_oos_index.py``. The cross-check stage runs
during ``build_report`` after candidates are prioritized but before the
summary card / markdown render.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_cap_fix_w12", _TOOL_PATH
)
assert _spec is not None and _spec.loader is not None
ltir_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ltir_mod)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _seed_minimal_workspace(
    root: Path,
    *,
    clusters: list[dict],
    bug_bounty_text: str | None = None,
    bug_bounty_path: str = "src/superearn/BUG_BOUNTY.md",
) -> None:
    """Seed a minimal workspace with engage_report + optional BUG_BOUNTY.md.

    ``clusters`` is the engage_report ``clusters`` field shape used by the
    ranker. Each cluster has a ``detector_slug`` + ``hits`` list. The
    ranker only needs the audit-pin ledger + INTAKE_BASELINE + engage_report
    to emit entries; the OOS index is best-effort and degrades gracefully
    when BUG_BOUNTY.md is absent.
    """
    root.mkdir(parents=True, exist_ok=True)
    auditooor = root / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "commit_lifecycle_ledger.json").write_text(
        json.dumps({"audit_pin_sha": "1234567890abcdef1234567890abcdef12345678"}),
        encoding="utf-8",
    )
    (root / "INTAKE_BASELINE.json").write_text(
        json.dumps({"file_extension_counts": {".sol": 4, ".md": 1}}),
        encoding="utf-8",
    )
    src = root / "src" / "vaults"
    src.mkdir(parents=True, exist_ok=True)
    # Write minimal source files referenced by the clusters so the
    # source-context excerpt step can read something. The ranker tolerates
    # missing files, so this is best-effort.
    for cluster in clusters:
        for hit in cluster.get("hits", []):
            file_line = hit.get("file_path") or ""
            rel_path = file_line.split(":")[0]
            file_abs = root / rel_path
            file_abs.parent.mkdir(parents=True, exist_ok=True)
            if not file_abs.is_file():
                file_abs.write_text(
                    "contract Stub {\n  function fn() external {}\n}\n",
                    encoding="utf-8",
                )
    (root / "engage_report.json").write_text(
        json.dumps({"clusters": clusters}), encoding="utf-8"
    )
    (root / "SCOPE.md").write_text("# Scope\n\nIn-scope: src/\n", encoding="utf-8")
    (root / "SEVERITY.md").write_text(
        "# Severity\n\nCritical: loss of funds\nHigh: loss of funds\n",
        encoding="utf-8",
    )
    if bug_bounty_text is not None:
        bb_path = root / bug_bounty_path
        bb_path.parent.mkdir(parents=True, exist_ok=True)
        bb_path.write_text(bug_bounty_text, encoding="utf-8")


def _make_cluster(slug: str, file_path: str, severity: str = "HIGH") -> dict:
    return {
        "detector_slug": slug,
        "hit_count": 1,
        "hits": [
            {
                "file_path": file_path,
                "severity": severity,
                "snippet": f"detector hit for {slug}",
            }
        ],
    }


_FRONT_RUNNING_AI_FP_ROW = (
    "| 42 | Front-running / sandwich / MEV via public mempool against "
    "contracts using 2-step request/claim or minOut | OOS without "
    "extension-distinct evidence |"
)
_STABLECOIN_TRUST_ASSUMPTION = (
    "Stablecoin issuers are trusted. Fee-on-transfer, freeze, "
    "blacklist, depeg, or issuer-imposed transfer fee behavior requires "
    "an extension-distinct argument."
)


def _bug_bounty_header() -> list[str]:
    return [
        "# Bug Bounty",
        "",
        "## AI-Tool False-Positive Patterns",
        "",
        "| Row | Pattern | Rationale |",
        "| --- | --- | --- |",
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class LiveTargetReportOosCrossCheckTest(unittest.TestCase):
    """CAP-FIX-W12 acceptance: 4 canonical end-to-end cases."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "fake_workspace"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- Case 1: workspace has NO BUG_BOUNTY.md ---------------------------
    def test_case1_no_bug_bounty_md_behavior_unchanged(self) -> None:
        clusters = [
            _make_cluster(
                "erc4626-functions-no-slippage",
                "src/vaults/OriginVaultBase.sol:2",
            )
        ]
        _seed_minimal_workspace(self.ws, clusters=clusters, bug_bounty_text=None)
        # No BUG_BOUNTY.md anywhere: the index step is a no-op, no entry
        # gets downranked, no entry carries a bug_bounty_oos_match.
        report = ltir_mod.build_report(
            self.ws, top_n=5, triager_precheck_budget=0
        )
        self.assertTrue(report["entry_points"])
        for ep in report["entry_points"]:
            self.assertIsNone(ep.get("bug_bounty_oos_match"))
            self.assertNotEqual(
                ep["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
            )
            self.assertFalse(ep.get("bug_bounty_oos_downranked"))
        bb_stats = report["summary_card"].get("bug_bounty_oos") or {}
        self.assertEqual(bb_stats.get("entries_downranked", 0), 0)
        self.assertEqual(bb_stats.get("entries_matched", 0), 0)

    # --- Case 2: BUG_BOUNTY.md present but 0 AI-FP rows -------------------
    def test_case2_bug_bounty_with_zero_ai_fp_rows_behavior_unchanged(
        self,
    ) -> None:
        clusters = [
            _make_cluster(
                "erc4626-functions-no-slippage",
                "src/vaults/OriginVaultBase.sol:2",
            )
        ]
        # BUG_BOUNTY.md exists but contains NO AI-FP rows and NO trust
        # assumptions or OOS bullets that would semantically map to the
        # candidate cluster. The index will have 0 actionable rows for
        # the candidate's semantic class -> no downrank.
        bb_text = "\n".join(
            [
                "# Bug Bounty",
                "",
                "## Overview",
                "",
                "This document tracks the program scope.",
                "",
                "## Severity",
                "",
                "Critical / High / Medium / Low / Informational.",
                "",
            ]
        )
        _seed_minimal_workspace(
            self.ws, clusters=clusters, bug_bounty_text=bb_text
        )
        report = ltir_mod.build_report(
            self.ws, top_n=5, triager_precheck_budget=0
        )
        self.assertTrue(report["entry_points"])
        for ep in report["entry_points"]:
            # No AI-FP / trust-assumption row matches the candidate's
            # semantic class -> match must be None and downrank must be
            # False. The ranker still emits the OOS field (annotated as
            # ``None``) so downstream consumers see a stable schema.
            self.assertIsNone(ep.get("bug_bounty_oos_match"))
            self.assertNotEqual(
                ep["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
            )
            self.assertFalse(ep.get("bug_bounty_oos_downranked"))
        bb_stats = report["summary_card"].get("bug_bounty_oos") or {}
        # The index was built (BUG_BOUNTY.md exists), but no candidate
        # was downranked because the index has no AI-FP row that maps to
        # the candidate's semantic class.
        self.assertEqual(bb_stats.get("entries_downranked", 0), 0)

    # --- Case 3: 1 AI-FP row matches 1 candidate --------------------------
    def test_case3_one_ai_fp_row_matches_candidate(self) -> None:
        clusters = [
            _make_cluster(
                "erc4626-functions-no-slippage",
                "src/vaults/OriginVaultBase.sol:2",
            )
        ]
        bb_text = "\n".join(
            _bug_bounty_header()
            + [_FRONT_RUNNING_AI_FP_ROW, ""]
        )
        _seed_minimal_workspace(
            self.ws, clusters=clusters, bug_bounty_text=bb_text
        )
        report = ltir_mod.build_report(
            self.ws, top_n=5, triager_precheck_budget=0
        )
        self.assertTrue(report["entry_points"])
        by_cluster = {ep["cluster_id"]: ep for ep in report["entry_points"]}
        front = by_cluster["erc4626-functions-no-slippage"]
        # The candidate must be downranked + carry the OOS match.
        self.assertEqual(
            front["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
        )
        self.assertTrue(front.get("bug_bounty_oos_downranked"))
        match = front.get("bug_bounty_oos_match")
        self.assertIsInstance(match, dict)
        self.assertEqual(match["clause_id"], "AI-FP-row-42")
        self.assertGreaterEqual(float(match["confidence"]), 0.7)
        self.assertIn(
            "front-running-public-mempool", match["semantic_tags"]
        )
        # The candidate's priority BEFORE the cross-check must be
        # preserved so the report can show the operator what the rank
        # would have been if the OOS clause were not in play.
        self.assertEqual(
            front["hunt_priority_before_bug_bounty_oos"],
            "HIGH-PRIORITY-HUNT",
        )
        bb_stats = report["summary_card"].get("bug_bounty_oos") or {}
        self.assertEqual(bb_stats.get("entries_downranked", 0), 1)

    # --- Case 4: N AI-FP rows, M candidates: only matching M downranked ---
    def test_case4_multiple_rows_only_matching_candidates_downranked(
        self,
    ) -> None:
        clusters = [
            # Matched by AI-FP row 42 (front-running).
            _make_cluster(
                "erc4626-functions-no-slippage",
                "src/vaults/OriginVaultBase.sol:2",
            ),
            # Matched by the trust-assumption block (stablecoin trust).
            _make_cluster(
                "fee-on-transfer-not-accounted",
                "src/vaults/CooldownVault.sol:3",
            ),
            # NOT matched by any AI-FP row or trust-assumption phrase.
            # The reentrancy detector cluster does not map to the
            # workspace's front-running or stablecoin-trust rows, so it
            # must keep its original priority.
            _make_cluster(
                "reentrancy-state-update-after-external-call",
                "src/vaults/SettlementVault.sol:42",
            ),
        ]
        bb_text = "\n".join(
            _bug_bounty_header()
            + [_FRONT_RUNNING_AI_FP_ROW, ""]
            + [
                "## Trust Assumptions",
                "",
                _STABLECOIN_TRUST_ASSUMPTION,
                "",
            ]
        )
        _seed_minimal_workspace(
            self.ws, clusters=clusters, bug_bounty_text=bb_text
        )
        report = ltir_mod.build_report(
            self.ws, top_n=10, triager_precheck_budget=0
        )
        self.assertTrue(report["entry_points"])
        by_cluster = {ep["cluster_id"]: ep for ep in report["entry_points"]}
        front = by_cluster["erc4626-functions-no-slippage"]
        fot = by_cluster["fee-on-transfer-not-accounted"]
        reentrancy = by_cluster["reentrancy-state-update-after-external-call"]

        # The two matched candidates must be downranked.
        self.assertEqual(
            front["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
        )
        self.assertTrue(front.get("bug_bounty_oos_downranked"))
        self.assertEqual(
            fot["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
        )
        self.assertTrue(fot.get("bug_bounty_oos_downranked"))

        # The unmatched candidate must keep its original priority and
        # carry no OOS match.
        self.assertNotEqual(
            reentrancy["hunt_priority"], ltir_mod.BUG_BOUNTY_OOS_PRIORITY
        )
        self.assertFalse(reentrancy.get("bug_bounty_oos_downranked"))
        self.assertIsNone(reentrancy.get("bug_bounty_oos_match"))

        # The summary card must reflect exactly 2 downranks for the 2
        # matched candidates and 0 for the unmatched one.
        bb_stats = report["summary_card"].get("bug_bounty_oos") or {}
        self.assertEqual(bb_stats.get("entries_downranked", 0), 2)
        dist = report["summary_card"]["hunt_priority_distribution"]
        self.assertEqual(dist.get(ltir_mod.BUG_BOUNTY_OOS_PRIORITY, 0), 2)


if __name__ == "__main__":
    unittest.main()
