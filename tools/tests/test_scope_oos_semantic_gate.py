#!/usr/bin/env python3
"""Regression tests — program-specific OOS semantic gate (Check #77).

Anchor: a filed Graph CRITICAL submission
(`thegraph-l2gns-precurated-rounding-drain-CRITICAL`) was closed OUT OF
SCOPE because (a) the workspace had no real bounty OOS text imported and
(b) the exploit path matched a frontrunning / sandwich / natural-network-
activity OOS clause that no gate ever saw.

Three layers are exercised:

1. ``tools/scope-reasoner.py`` — the two new patterns
   (``economic_sequencing_oos`` / ``natural_network_activity_oos``) fire
   on the Graph draft.
2. ``tools/per-finding-oos-check.py`` — the economic-sequencing trap and
   the natural-network-activity trap return ``matches-oos`` for the Graph
   draft against the Graph OOS clauses, ``in-scope`` for the two
   counterfixtures, and ``--require-real-oos`` HARD-FAILS (exit 4) when no
   real OOS text exists.
3. ``tools/pre-submit-check.sh`` Check #77 — hard-fails High/Critical on
   missing-real-oos and on matches-oos; passes the counterfixtures; is
   NOT satisfiable by "OOS: in-scope" boilerplate.

Hermetic: every workspace is built in a ``tempfile.TemporaryDirectory``.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCOPE_REASONER = ROOT / "tools" / "scope-reasoner.py"
OOS_CHECK = ROOT / "tools" / "per-finding-oos-check.py"
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "scope_oos_semantic"

GRAPH_OOS = FIXTURES / "graph_program_oos_pasted.md"
CF_ROUNDING = FIXTURES / "counterfixture_rounding_no_prepositioning.md"
CF_INTERNAL = FIXTURES / "counterfixture_zero_slippage_internal_call.md"

GRAPH_DRAFT = (
    Path("/Users/wolf/audits/thegraph/submissions/paste_ready/filed")
    / "thegraph-l2gns-precurated-rounding-drain-CRITICAL.md"
)


def _run_reasoner(draft: Path, scope: Path | None = None) -> dict:
    cmd = [sys.executable, str(SCOPE_REASONER), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


def _run_oos_check(
    workspace: Path,
    finding: Path,
    *,
    oos_file: Path | None = None,
    require_real_oos: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(OOS_CHECK),
        "--workspace",
        str(workspace),
        "--finding",
        str(finding),
    ]
    if oos_file is not None:
        cmd += ["--oos-file", str(oos_file)]
    if require_real_oos:
        cmd.append("--require-real-oos")
    return subprocess.run(cmd, capture_output=True, text=True)


def _verdict(out: str) -> str:
    for line in out.splitlines():
        if "verdict=" in line:
            return line.split("verdict=", 1)[1].split()[0]
    return ""


def _run_presubmit(
    draft: Path, severity: str, env_extra: dict | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
        env=env,
    )


def _check77_lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if " 77." in ln]


class ScopeReasonerPatternTests(unittest.TestCase):
    """Layer 1 — the two new scope-reasoner patterns."""

    def test_graph_draft_fires_economic_sequencing_pattern(self) -> None:
        if not GRAPH_DRAFT.is_file():
            self.skipTest("Graph filed draft not present in workspace")
        result = _run_reasoner(GRAPH_DRAFT)
        names = {f["pattern_name"] for f in result["flags"]}
        self.assertIn(
            "economic_sequencing_oos",
            names,
            "economic-sequencing pattern must fire on the Graph pre-curated "
            "rounding-drain draft (pre-position then redeem around owner publish)",
        )

    def test_graph_draft_fires_natural_network_activity_pattern(self) -> None:
        if not GRAPH_DRAFT.is_file():
            self.skipTest("Graph filed draft not present in workspace")
        result = _run_reasoner(GRAPH_DRAFT)
        names = {f["pattern_name"] for f in result["flags"]}
        self.assertIn("natural_network_activity_oos", names)

    def test_clean_rounding_counterfixture_no_sequencing_flag(self) -> None:
        """A plain rounding bug must NOT trip the economic-sequencing pattern."""
        result = _run_reasoner(CF_ROUNDING)
        names = {f["pattern_name"] for f in result["flags"]}
        self.assertNotIn(
            "economic_sequencing_oos",
            names,
            "anti-overgeneralization: a rounding bug with no pre-position / "
            "victim-publish / redeem sequence must not be flagged",
        )

    def test_internal_call_counterfixture_no_sequencing_flag(self) -> None:
        result = _run_reasoner(CF_INTERNAL)
        names = {f["pattern_name"] for f in result["flags"]}
        self.assertNotIn("economic_sequencing_oos", names)


class PerFindingSemanticTrapTests(unittest.TestCase):
    """Layer 2 — per-finding semantic check traps."""

    def test_graph_draft_matches_oos_against_graph_clauses(self) -> None:
        if not GRAPH_DRAFT.is_file():
            self.skipTest("Graph filed draft not present in workspace")
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run_oos_check(
                Path(tmp), GRAPH_DRAFT, oos_file=GRAPH_OOS
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(
                _verdict(proc.stdout),
                "matches-oos",
                "Graph pre-curated rounding-drain draft must match an OOS "
                "clause (economic-sequencing + natural-network-activity)",
            )

    def test_rounding_counterfixture_is_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run_oos_check(
                Path(tmp), CF_ROUNDING, oos_file=GRAPH_OOS
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(
                _verdict(proc.stdout),
                "in-scope",
                "a rounding bug without pre-positioning around a victim "
                "publish must NOT be killed by the MEV/sandwich OOS clause",
            )

    def test_internal_call_counterfixture_is_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run_oos_check(
                Path(tmp), CF_INTERNAL, oos_file=GRAPH_OOS
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(
                _verdict(proc.stdout),
                "in-scope",
                "a zero-slippage internal-call bug without sandwich "
                "dependency must NOT be killed",
            )

    def test_economic_sequencing_rebuttal_marker_downgrades(self) -> None:
        """A non-empty oos-economic-sequencing-rebuttal clears that trap.

        The marker downgrades ONLY the economic-sequencing trap (clause
        C1); an independent natural-network-activity match on another
        clause is unaffected. We assert at the per-clause level via the
        JSON artifact so the two traps stay independent.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "draft.md"
            draft.write_text(
                "# Pre-curated pool drain\n\n"
                "The attacker pre-curates the future target pool, then waits "
                "for the legitimate owner to publish the new version, and "
                "after the owner publish the attacker burns the signal and "
                "redeems the full reserve.\n\n"
                "<!-- oos-economic-sequencing-rebuttal: alternate path via a "
                "direct keeper call needs no victim ordering -->\n"
            )
            proc = _run_oos_check(ws, draft, oos_file=GRAPH_OOS)
            self.assertEqual(proc.returncode, 0)
            json_path = next(
                (ws / ".auditooor").glob("oos_check_*.json"), None
            )
            self.assertIsNotNone(json_path)
            data = json.loads(json_path.read_text())
            c1 = next(c for c in data["clauses_checked"] if c["id"] == "C1")
            self.assertEqual(
                c1["verdict"],
                "NO_MATCH",
                "the economic-sequencing rebuttal marker must downgrade the "
                "C1 (frontrunning/sandwich) clause to NO_MATCH",
            )

    def test_require_real_oos_hard_fails_on_tbd_checklist(self) -> None:
        """OOS_CHECKLIST.md with only TBD bullets and no OOS_PASTED.md -> exit 4."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_CHECKLIST.md").write_text(
                "# Out-of-scope checklist\n\n"
                "TBD — operator edit.\n\n"
                "## OOS bullets\n\n"
                "- OOS-1: TBD — <operator edit>\n"
            )
            draft = ws / "draft.md"
            draft.write_text("# A High finding\n\nSome exploit.\n")
            proc = _run_oos_check(ws, draft, require_real_oos=True)
            self.assertEqual(
                proc.returncode,
                4,
                "missing real OOS text must HARD FAIL (exit 4), not no-op",
            )
            self.assertIn("missing-real-oos", proc.stdout)

    def test_require_real_oos_passes_with_real_pasted_oos(self) -> None:
        """A workspace with a real OOS_PASTED.md clears the require-real-oos gate."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_PASTED.md").write_text(GRAPH_OOS.read_text())
            draft = ws / "draft.md"
            draft.write_text("# A High finding\n\nSome internal accounting bug.\n")
            proc = _run_oos_check(ws, draft, require_real_oos=True)
            self.assertEqual(
                proc.returncode,
                0,
                "real imported OOS text must clear the require-real-oos gate",
            )


class PreSubmitCheck77Tests(unittest.TestCase):
    """Layer 3 — pre-submit-check.sh Check #77 wiring."""

    def _ws_with_oos(self, tmp: str) -> Path:
        ws = Path(tmp)
        (ws / "OOS_PASTED.md").write_text(GRAPH_OOS.read_text())
        (ws / "SCOPE.md").write_text(
            "# SCOPE\n\n## Assets in scope\n\nSmart contracts.\n"
        )
        for lane in ("paste_ready", "staging"):
            (ws / "submissions" / lane).mkdir(parents=True, exist_ok=True)
        return ws

    def test_check77_fails_missing_real_oos_for_critical(self) -> None:
        """High/Critical draft in a workspace with TBD OOS -> Check 77 FAIL."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_CHECKLIST.md").write_text(
                "# Out-of-scope checklist\n\nTBD — operator edit.\n\n"
                "## OOS bullets\n\n- OOS-1: TBD — <operator edit>\n"
            )
            (ws / "SCOPE.md").write_text("# SCOPE\n\nSmart contracts.\n")
            (ws / "submissions" / "paste_ready").mkdir(parents=True)
            draft = ws / "submissions" / "paste_ready" / "draft.md"
            draft.write_text(
                "# Theft of user funds via missing guard\n\n"
                "- Severity: Critical\n\nSome exploit drains the pool.\n"
            )
            proc = _run_presubmit(draft, "Critical")
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("❌ 77." in ln and "missing-real-oos" in ln for ln in lines),
                f"Check 77 must hard-fail missing-real-oos; got: {lines}",
            )

    def test_check77_fails_graph_draft_against_imported_oos(self) -> None:
        if not GRAPH_DRAFT.is_file():
            self.skipTest("Graph filed draft not present in workspace")
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_oos(tmp)
            draft = ws / "submissions" / "paste_ready" / "graph-draft.md"
            draft.write_text(GRAPH_DRAFT.read_text())
            proc = _run_presubmit(draft, "Critical")
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("❌ 77." in ln for ln in lines),
                f"Check 77 must hard-fail the Graph draft; got: {lines}",
            )

    def test_check77_passes_rounding_counterfixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_oos(tmp)
            draft = ws / "submissions" / "paste_ready" / "cf1.md"
            draft.write_text(CF_ROUNDING.read_text())
            proc = _run_presubmit(draft, "High")
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("✅ 77." in ln for ln in lines),
                f"Check 77 must pass the rounding counterfixture; got: {lines}",
            )

    def test_check77_passes_internal_call_counterfixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_oos(tmp)
            draft = ws / "submissions" / "paste_ready" / "cf2.md"
            draft.write_text(CF_INTERNAL.read_text())
            proc = _run_presubmit(draft, "High")
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("✅ 77." in ln for ln in lines),
                f"Check 77 must pass the internal-call counterfixture; got: {lines}",
            )

    def test_check77_not_satisfiable_by_in_scope_boilerplate(self) -> None:
        """'OOS: in-scope' boilerplate must NOT bypass Check 77.

        The Graph-shaped exploit path is reproduced with an explicit
        'Scope exclusions checked: ... in-scope' boilerplate line. The
        semantic comparison must still hard-fail because the exploit path
        itself matches the economic-sequencing OOS clause.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws_with_oos(tmp)
            draft = ws / "submissions" / "paste_ready" / "boilerplate.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Pre-curated pool drain leads to direct theft of funds

                    - Severity: Critical

                    ## Scope

                    Scope exclusions checked: this finding is in-scope; the
                    exploit does not rely on any out-of-scope class. OOS: none.

                    ## Attack Steps

                    1. The attacker pre-curates the future target pool with
                       one wei of signal.
                    2. The attacker inflates that same pool reserve.
                    3. The attacker waits for the legitimate owner to publish
                       the new version into that pool.
                    4. After the owner publish, the attacker burns the target
                       signal and redeems the entire pool reserve.
                    """
                ).strip()
                + "\n"
            )
            proc = _run_presubmit(draft, "Critical")
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("❌ 77." in ln for ln in lines),
                "Check 77 must NOT be satisfiable by 'OOS: in-scope' "
                f"boilerplate when the exploit path matches a clause; got: {lines}",
            )

    def test_check77_warn_mode_downgrades_to_advisory(self) -> None:
        """SCOPE_OOS_SEMANTIC_GATE=warn turns the hard fail into an advisory."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_CHECKLIST.md").write_text(
                "# Out-of-scope checklist\n\nTBD — operator edit.\n"
            )
            (ws / "SCOPE.md").write_text("# SCOPE\n\nSmart contracts.\n")
            (ws / "submissions" / "paste_ready").mkdir(parents=True)
            draft = ws / "submissions" / "paste_ready" / "draft.md"
            draft.write_text(
                "# Theft of funds\n\n- Severity: Critical\n\nDrains the pool.\n"
            )
            proc = _run_presubmit(
                draft, "Critical", env_extra={"SCOPE_OOS_SEMANTIC_GATE": "warn"}
            )
            lines = _check77_lines(proc.stdout)
            self.assertTrue(
                any("⚠️  77." in ln for ln in lines),
                f"warn mode must emit an advisory, not a hard fail; got: {lines}",
            )
            self.assertFalse(
                any("❌ 77." in ln for ln in lines),
                "warn mode must not hard-fail Check 77",
            )


if __name__ == "__main__":
    unittest.main()
