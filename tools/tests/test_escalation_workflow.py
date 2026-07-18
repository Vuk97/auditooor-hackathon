#!/usr/bin/env python3
"""Never-false-pass tests for the escalation-workflow enforcement (Check #128).

The load-bearing property: a finding filed BELOW its max reachable in-scope tier
CANNOT pass unless a `resolved` ledger record covers it whose every higher
candidate is terminally resolved (escalated-with-poc OR proof-of-impossibility-
with-citation) backed by >= MIN_VERIFICATION_LANES independent lanes. A single
agent's say-so, an `open` verdict, or a citation-free proof-of-impossibility must
all FAIL.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PLANNER = REPO / "tools" / "escalation-workflow-planner.py"
GATE = REPO / "tools" / "escalation-workflow-required-check.py"

SEVERITY_MD = """# Severity Rubric

## Critical
- Permanent freezing of funds of USD $5,000 or more with no on-chain remediation path (fix requires hard fork)
- Direct loss of funds of USD $5,000 or more (unauthorized transfers, token minting, or token burning)

## High
- Crash or halt of >= 1/3 of validators, resulting in loss of network liveness
- Unintended permanent chain split requiring hard fork to resolve

## Medium
- Griefing, e.g. no profit motive for an attacker, but damage to users or the protocol
- Block production delay exceeding 2.5 seconds caused by crafted transactions

## Low
- Manipulation of transaction fee calculation resulting in fees outside protocol-defined bounds
"""


def _draft(tier: str, extra: str = "") -> str:
    return f"# Some finding\n\n**Severity:** {tier}\n\n## Impact\nSomething happens.\n{extra}\n"


class EscalationWorkflowTest(unittest.TestCase):
    def _ws(self, tmp: str, draft_tier: str, draft_extra: str = "") -> tuple[Path, Path]:
        ws = Path(tmp)
        (ws / "SEVERITY.md").write_text(SEVERITY_MD)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        draft = ws / "draft.md"
        draft.write_text(_draft(draft_tier, draft_extra))
        return ws, draft

    def _gate(self, ws: Path, draft: Path, strict: bool) -> tuple[int, dict]:
        env = {"PATH": "/usr/bin:/bin", "AUDITOOOR_ESCALATION_WORKFLOW_STRICT": "1" if strict else "0"}
        r = subprocess.run(
            [sys.executable, str(GATE), "--draft", str(draft), "--workspace", str(ws), "--json"],
            capture_output=True, text=True, env=env)
        try:
            return r.returncode, json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            self.fail(f"gate non-JSON output: {r.stdout!r} {r.stderr!r}")

    def _plan(self, ws: Path, draft: Path) -> dict:
        r = subprocess.run(
            [sys.executable, str(PLANNER), "plan", "--workspace", str(ws), "--draft", str(draft),
             "--now", "2026-07-04T00:00:00Z", "--json"],
            capture_output=True, text=True)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def _finalize(self, ws: Path, payload: dict) -> tuple[int, dict]:
        r = subprocess.run(
            [sys.executable, str(PLANNER), "finalize", "--workspace", str(ws),
             "--verdicts", "-", "--now", "2026-07-04T00:00:00Z", "--json"],
            input=json.dumps(payload), capture_output=True, text=True)
        return r.returncode, json.loads(r.stdout.strip().splitlines()[-1])

    # -- out-of-scope / at-max --------------------------------------------
    def test_below_medium_out_of_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Low")
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 0)
            self.assertEqual(out["verdict"], "pass-out-of-scope")

    def test_at_max_tier_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Critical")
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 0)
            self.assertEqual(out["verdict"], "pass-at-max-tier")

    # -- the core never-false-pass cases ----------------------------------
    def test_submax_no_ledger_fails_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-no-escalation-workflow")
            # rubric has Critical + High above Medium -> both must be surfaced
            self.assertTrue(any("chain split" in r.lower() or "freezing" in r.lower()
                                for r in out["higher_targets"]))

    def test_submax_no_ledger_advisory_warns_rc0(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            rc, out = self._gate(ws, draft, strict=False)
            self.assertEqual(rc, 0)  # advisory does not block
            self.assertEqual(out["verdict"], "fail-no-escalation-workflow")

    def test_single_lane_say_so_fails(self):
        """A resolved record where a candidate has only ONE verification lane
        (single agent say-so) must FAIL - this is the whole operator ask."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            self.assertEqual(plan["verdict"], "planned")
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "reconcile.go:646",
                      "verification_lanes": [{"lane_id": "only-one", "agent": "a", "verdict": "refuted"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "current_tier": "medium",
                                "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_open_verdict_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "open", "evidence": "",
                      "verification_lanes": [{"lane_id": "l1"}, {"lane_id": "l2"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_proof_of_impossibility_without_citation_fails(self):
        """proof-of-impossibility with no file:line / bound / recovery token = FAIL."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "it just cannot happen trust me",
                      "verification_lanes": [{"lane_id": "l1", "agent": "a"}, {"lane_id": "l2", "agent": "b"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_vacuous_empty_lanes_fail(self):
        """[{}, {}] must NOT satisfy the >=2-lane requirement (rank-3 fix)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "reconcile.go:646",
                      "verification_lanes": [{}, {}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_two_lanes_same_agent_fail(self):
        """Two lanes from ONE author must not count as 2 (rank-3 fix)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "reconcile.go:646",
                      "verification_lanes": [{"lane_id": "l1", "agent": "same"},
                                             {"lane_id": "l2", "agent": "same"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_staleness_after_draft_edit_fails(self):
        """rank-5: a resolved record goes stale if the draft is edited in place."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "self-heals reconcile.go:646",
                      "verification_lanes": [{"lane_id": "prove", "agent": "a"},
                                             {"lane_id": "refute", "agent": "b"}]}
                     for r in plan["candidates"]]
            # finalize binds the CURRENT draft content hash
            r = subprocess.run(
                [sys.executable, str(PLANNER), "finalize", "--workspace", str(ws),
                 "--draft", str(draft), "--verdicts", "-", "--now", "2026-07-04T00:00:00Z", "--json"],
                input=json.dumps({"finding_id": plan["finding_id"], "candidate_targets": cands}),
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            # now mutate the draft in place -> the resolved record is stale
            draft.write_text(_draft("Medium") + "\nedited after resolution\n")
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertIn("stale", out["reason"].lower())

    def test_coverage_subset_fails(self):
        """rank-6: a record covering only SOME higher targets must fail."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            # resolve only the FIRST candidate (leave 3 uncovered)
            cands = [{"severity_row": plan["candidates"][0], "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "reconcile.go:646",
                      "verification_lanes": [{"lane_id": "prove", "agent": "a"},
                                             {"lane_id": "refute", "agent": "b"}]}]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_dispatch_crossref_enforced_when_log_present(self):
        """rank-4: when a spawn_worker_log exists, lanes must map to real
        dispatches with distinct prompt_sha256; self-declared lanes fail."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            # a real dispatch log exists but the ledger lanes do NOT match it
            (ws / ".auditooor" / "spawn_worker_log.jsonl").write_text(
                json.dumps({"lane_id": "unrelated", "ts": "2026-07-04T01:00:00Z", "prompt_sha256": "aaa"}) + "\n")
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "reconcile.go:646",
                      "verification_lanes": [{"lane_id": "prove", "agent": "a"},
                                             {"lane_id": "refute", "agent": "b"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")

    def test_proper_multilane_resolved_passes(self):
        """Every higher candidate terminal (poi w/ file:line OR escalated w/ poc)
        + >=2 distinct lanes backed by real dispatch log -> PASS (strict).

        rank-7: strict mode now requires a genuine spawn_worker_log, so the two
        lanes ('prove'/'refute') are backed by two real dispatch records with
        distinct prompt_sha256 - the honest shape of a resolved multi-lane run.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            # rank-7: back the self-attested lanes with genuine dispatch records.
            (ws / ".auditooor" / "spawn_worker_log.jsonl").write_text(
                json.dumps({"lane_id": "prove", "ts": "2026-07-04T02:00:00Z", "prompt_sha256": "prv"}) + "\n"
                + json.dumps({"lane_id": "refute", "ts": "2026-07-04T02:00:00Z", "prompt_sha256": "ref"}) + "\n")
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "self-heals: reconcile.go:646-648",
                      "verification_lanes": [
                          {"lane_id": "prove", "agent": "a", "verdict": "could-not-prove"},
                          {"lane_id": "refute", "agent": "b", "verdict": "refuted-with-code"}]}
                     for r in plan["candidates"]]
            rcf, outf = self._finalize(ws, {"finding_id": plan["finding_id"],
                                            "current_tier": "medium", "final_tier": "medium",
                                            "candidate_targets": cands})
            self.assertEqual(rcf, 0, outf)
            self.assertTrue(outf["resolved_terminal"], outf)
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 0, out)
            self.assertEqual(out["verdict"], "pass-escalation-workflow-resolved")

    def test_selfattested_lanes_without_dispatch_log_fail_strict(self):
        """rank-7 (self-attest-when-log-absent loophole): under STRICT, a finding
        whose candidates carry only self-attested distinct-agent lanes with NO
        spawn_worker_log.jsonl to back them must FAIL CLOSED - a single agent must
        not be able to green every candidate with two fabricated `agent` strings
        it never dispatched. Advisory mode is unchanged (still warns rc0)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            # NO spawn_worker_log.jsonl written -> lanes are unverifiable.
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "proof-of-impossibility", "evidence": "capped: reconcile.go:646-648",
                      "verification_lanes": [{"lane_id": "made-up-1", "agent": "fabricated-a"},
                                             {"lane_id": "made-up-2", "agent": "fabricated-b"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"],
                                "current_tier": "medium", "final_tier": "medium",
                                "candidate_targets": cands})
            # STRICT: fail closed (loophole closed).
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-escalation-workflow-incomplete")
            self.assertTrue(any("STRICT" in f for f in out.get("candidate_failures", [])), out)
            # ADVISORY: unchanged, warns rc0 (does not fail closed).
            rc_adv, _ = self._gate(ws, draft, strict=False)
            self.assertEqual(rc_adv, 0)

    def test_escalated_verdict_needs_poc(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            # escalated but empty evidence -> fail (2 real agents isolate the poc check)
            cands = [{"severity_row": r, "impact_class": "x", "tier": "critical",
                      "verdict": "escalated", "evidence": "",
                      "verification_lanes": [{"lane_id": "l1", "agent": "a"}, {"lane_id": "l2", "agent": "b"}]}
                     for r in plan["candidates"]]
            self._finalize(ws, {"finding_id": plan["finding_id"], "candidate_targets": cands})
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1)

    def test_rebuttal_marker_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(
                tmp, "Medium",
                draft_extra="<!-- escalation-workflow-rebuttal: higher framing is platform-OOS per SCOPE -->")
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 0)
            self.assertEqual(out["verdict"], "ok-rebuttal")

    def test_empty_severity_md_does_not_false_pass(self):
        """False-pass guard: a Medium finding in a ws with an empty/unparseable
        SEVERITY.md must NOT pass-at-max-tier (the gate can't read the ceiling)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text("# no parseable rubric rows here\n\njust prose\n")
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            draft = ws / "draft.md"
            draft.write_text(_draft("Medium"))
            rc, out = self._gate(ws, draft, strict=True)
            self.assertEqual(rc, 1, out)
            self.assertEqual(out["verdict"], "fail-no-rubric")

    def test_planner_enumerates_from_rubric(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws, draft = self._ws(tmp, "Medium")
            plan = self._plan(ws, draft)
            self.assertEqual(plan["verdict"], "planned")
            # Medium finding: Critical (2 rows) + High (2 rows) = 4 higher targets
            self.assertEqual(plan["candidate_count"], 4, plan)
            self.assertEqual(plan["max_reachable_tier"], "critical")


class InferTierTest(unittest.TestCase):
    """rank-1: shared infer_tier() must catch the common template shapes an honest
    agent hits by accident, and must NOT mistake compound words for tiers."""

    def setUp(self):
        sys.path.insert(0, str(REPO / "tools"))
        from lib.escalation_ledger import infer_tier  # noqa: E402
        self.infer = infer_tier

    def test_positive_shapes(self):
        cases = {
            "**Severity:** Medium": "medium",
            "Severity Level: High": "high",
            "Risk: Critical": "critical",
            "Rating = Low": "low",
            "Tier is High": "high",
            "Severity (High)": "high",
            "# High: unbounded loop": "high",
            "## [Critical] chain halt": "critical",
            "| finding | Medium | desc |": "medium",
            "Severity: Crit": "critical",
            "Severity: Med": "medium",
        }
        for text, want in cases.items():
            self.assertEqual(self.infer(text), want, msg=f"{text!r} -> {want}")

    def test_negative_shapes(self):
        # a hyphen-compound heading is NOT a severity claim
        self.assertIsNone(self.infer("# Medium-effort refactor note"))
        self.assertIsNone(self.infer("This is a low-level detail about the code"))
        self.assertIsNone(self.infer("no severity here at all"))


class ParseSeverityTest(unittest.TestCase):
    """rank-2: table rows, setext headings, and the mis-tier compound guard."""

    def setUp(self):
        sys.path.insert(0, str(REPO / "tools"))
        from lib.escalation_ledger import parse_severity_rows  # noqa: E402
        self.parse = parse_severity_rows

    def _rows(self, md: str):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "SEVERITY.md"
            p.write_text(md)
            return self.parse(p)

    def test_table_rows(self):
        rows = self._rows(
            "| Severity | Reward | Title |\n|---|---|---|\n"
            "| Critical | USD 500,000 | Permanent freezing of funds |\n"
            "| High | USD 25,000 | Crash or halt of 1/3 of validators |\n")
        tiers = {r["tier"] for r in rows}
        self.assertIn("critical", tiers)
        self.assertIn("high", tiers)
        self.assertTrue(any("freezing" in r["text"].lower() for r in rows))
        # reward cell must NOT be picked as the impact text
        self.assertFalse(any("500,000" in r["text"] for r in rows))

    def test_setext_headings(self):
        rows = self._rows("Critical\n========\n- Direct loss of funds\n\nHigh\n----\n- Chain halt\n")
        self.assertTrue(any(r["tier"] == "critical" and "loss" in r["text"].lower() for r in rows))
        self.assertTrue(any(r["tier"] == "high" for r in rows))

    def test_mistier_compound_inherits_section(self):
        # "Low-level ... permanent freezing" under ## Critical must stay Critical,
        # not be mis-demoted to Low by its leading word.
        rows = self._rows("## Critical\n- Low-level bug causing permanent freezing of funds\n")
        match = [r for r in rows if "permanent freezing" in r["text"].lower()]
        self.assertTrue(match)
        self.assertEqual(match[0]["tier"], "critical")


if __name__ == "__main__":
    unittest.main()
