#!/usr/bin/env python3
# r36-rebuttal: lane escalate-first-gate-diag registered in .auditooor/agent_pathspec.json
"""Tests for tools/escalate-first-required-check.py (R-escalate-first gate).

Covers the bsc-epoch loophole anchor plus every verdict branch.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "escalate-first-required-check.py"
_spec = importlib.util.spec_from_file_location("escalate_first_required_check", str(_TOOL))
assert _spec and _spec.loader
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "escalate_first_measured"


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.write_text(body, encoding="utf-8")
    return p


class TestEscalateFirstRequired(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _check(self, body: str, severity: str = "auto"):
        p = _write(self.tmp, "draft.md", body)
        return mod.check(p, workspace=None, severity_override=severity, enrich_asymmetry=False)

    # --- severity discipline -------------------------------------------------
    def test_low_severity_out_of_scope(self):
        r = self._check("- Severity: Low\nclaim narrowed to the source-level gap; theft of bridged funds")
        self.assertEqual(r["verdict"], "pass-out-of-scope")
        self.assertEqual(r["exit"], 0)

    def test_unknown_severity_out_of_scope(self):
        r = self._check("no severity line here; narrowed to the source; theft of bridged funds")
        self.assertEqual(r["verdict"], "pass-out-of-scope")

    # --- no narrowing --------------------------------------------------------
    def test_high_no_narrowing_passes(self):
        r = self._check("- Severity: High\nthe verifier accepts a forged header; direct theft of funds proven end-to-end")
        self.assertEqual(r["verdict"], "pass-no-narrowing")
        self.assertEqual(r["exit"], 0)

    # --- narrowed but no higher tier walked ----------------------------------
    def test_narrowed_no_higher_tier(self):
        r = self._check(
            "- Severity: Medium\n"
            "the claim is narrowed to the source-level gap; only a minor logic deviation, no fund movement involved"
        )
        self.assertEqual(r["verdict"], "pass-narrowed-no-higher-tier-walked")
        self.assertEqual(r["exit"], 0)

    # --- THE BSC-EPOCH ANCHOR: narrowed away a higher tier, no escalate-first -
    def test_bsc_epoch_shape_fails_closed(self):
        # Mirrors the real draft: HIGH, narrows away the CRITICAL theft tail.
        body = (
            "- Severity: High\n"
            "the downstream forged-state-root -> unauthorized cross-chain asset movement "
            "is source-traced, not separately executed\n"
            "The Critical end-to-end fund-theft framing is deliberately NOT claimed: the "
            "downstream rotation -> message-forgery -> fund-drain tail is source-traced, not executed, "
            "so the evidence-class supports High.\n"
            "the loss statement is the at-risk bridged-asset reserve; theft of bridged funds is the tail."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")
        self.assertEqual(r["exit"], 1)
        # Both signals must have fired.
        self.assertTrue(r["evidence"]["narrowing_hits"])
        self.assertTrue(r["evidence"]["higher_tier_walked_hits"])
        self.assertIn("remediation", r)

    # --- path (a): escalate-first attempt + blocker --------------------------
    def test_escalate_first_attempted_passes(self):
        body = (
            "- Severity: High\n"
            "downstream fund-drain is source-traced, not separately executed.\n"
            "## Escalate-First Attempt\n"
            "We attempted the critical end-to-end execution of the downstream theft against the real "
            "verifier and a downstream consumer. Blocker: no reachable in-scope downstream consumer "
            "is deployed at the audit pin to sink the forged state root, so the end-to-end drain "
            "could not be executed; the narrowing to High is a forced fallback."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "pass-escalate-first-attempted")
        self.assertEqual(r["exit"], 0)

    def test_attempt_without_blocker_still_fails(self):
        # Attempt phrasing but NO blocker -> not a complete escalate-first record.
        body = (
            "- Severity: High\n"
            "downstream theft of bridged funds is source-traced, not executed.\n"
            "We attempted the critical end-to-end execution."  # no blocker
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")

    # --- path (b): Rule-14 asymmetry cited + reason higher not filed ---------
    def test_asymmetry_cited_passes(self):
        body = (
            "- Severity: High\n"
            "the critical end-to-end fund-theft framing is not claimed; downstream is source-traced, not executed.\n"
            "Per Rule 14 upside-asymmetric calculus we considered filing at the higher tier, but the "
            "higher framing matches a platform-OOS clause (theoretical vulnerability without demonstration), "
            "so the evidence-class ceiling caps this at High."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "pass-escalate-first-asymmetry-cited")
        self.assertEqual(r["exit"], 0)

    def test_asymmetry_cited_without_reason_fails(self):
        body = (
            "- Severity: High\n"
            "downstream drain the reserve is source-traced, not executed.\n"
            "Per Rule 14 upside-asymmetric calculus we file high."  # no higher-not-filed reason
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")

    # --- path (c): rebuttal --------------------------------------------------
    def test_html_rebuttal_accepted(self):
        body = (
            "- Severity: High\n"
            "downstream fund-drain source-traced, not executed.\n"
            "<!-- r-escalate-first-rebuttal: operator confirmed CRITICAL attempt logged in sibling PoC dir -->"
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["exit"], 0)

    def test_line_rebuttal_accepted(self):
        body = (
            "- Severity: Critical\n"
            "downstream theft of bridged is source-traced, not separately executed.\n"
            "r-escalate-first-rebuttal: higher tier IS the filed tier here; narrowing is on a sub-variant"
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored(self):
        body = (
            "- Severity: High\n"
            "downstream fund-drain source-traced, not executed.\n"
            "r-escalate-first-rebuttal: " + ("x" * 250)
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")

    def test_empty_rebuttal_ignored(self):
        body = (
            "- Severity: High\n"
            "downstream fund-drain source-traced, not executed.\n"
            "<!-- r-escalate-first-rebuttal:  -->"
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")

    # --- severity override ---------------------------------------------------
    def test_severity_override_forces_fire(self):
        body = "no severity line\ndownstream fund-drain source-traced, not executed"
        r = self._check(body, severity="HIGH")
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")

    # --- error cases ---------------------------------------------------------
    def test_missing_draft_errors(self):
        r = mod.check(self.tmp / "nope.md", workspace=None)
        self.assertEqual(r["verdict"], "error")
        self.assertEqual(r["exit"], 2)

    def test_empty_draft_errors(self):
        p = _write(self.tmp, "empty.md", "   \n  ")
        r = mod.check(p, workspace=None)
        self.assertEqual(r["verdict"], "error")

    # --- schema/payload sanity ----------------------------------------------
    def test_payload_carries_schema_on_emit(self):
        body = "- Severity: High\ndirect theft of funds, fully executed end-to-end"
        p = _write(self.tmp, "d.md", body)
        rc = mod.main([str(p), "--json", "--no-asymmetry"])
        self.assertEqual(rc, 0)

    # ========================================================================
    # Reasoned-walkback-must-be-measured (zebra getaddresstxids anchor).
    # ========================================================================

    # --- THE ZEBRA ANCHOR PAIR + plain-escalation control (fixtures) ---------
    def test_zebra_reasoned_walkback_fixture_fails(self):
        """Reasoned 512-thread pool walk-back, no numbers -> fail-closed."""
        p = _FIXTURES / "zebra_reasoned_walkback_FAIL.md"
        r = mod.check(p, workspace=None, enrich_asymmetry=False)
        self.assertEqual(r["verdict"], "fail-reasoned-walkback-not-measured")
        self.assertEqual(r["exit"], 1)
        self.assertTrue(r["evidence"]["reasoning_only_walkback_hits"])
        self.assertFalse(r["evidence"]["measured_evidence_hits"])
        self.assertIn("remediation", r)

    def test_zebra_measured_walkback_fixture_passes(self):
        """Same walk-back but with control-query 0.156ms->225s + RSS -> PASS."""
        p = _FIXTURES / "zebra_measured_walkback_PASS.md"
        r = mod.check(p, workspace=None, enrich_asymmetry=False)
        self.assertEqual(r["verdict"], "pass-walkback-measured")
        self.assertEqual(r["exit"], 0)
        self.assertTrue(r["evidence"]["measured_evidence_hits"])

    def test_plain_escalation_fixture_out_of_scope(self):
        """Plain HIGH, no walk-back -> escalate-measure gate is moot."""
        p = _FIXTURES / "plain_escalation_OOS.md"
        r = mod.check(p, workspace=None, enrich_asymmetry=False)
        self.assertEqual(r["verdict"], "pass-no-narrowing")
        self.assertEqual(r["exit"], 0)

    # --- inline reasoned-walkback (DoS HIGH->MEDIUM, no numbers) -------------
    def test_inline_reasoned_dos_walkback_fails(self):
        body = (
            "- Severity: Medium\n"
            "We walked this back from HIGH to MEDIUM. The handler runs on the "
            "spawn_blocking pool (512 threads), so a single request cannot deny "
            "the node. The de-escalation rests on the pool capacity argument."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-reasoned-walkback-not-measured")
        self.assertEqual(r["exit"], 1)

    # --- inline measured walk-back passes ------------------------------------
    def test_inline_measured_dos_walkback_passes(self):
        body = (
            "- Severity: High\n"
            "We considered the spawn_blocking pool capacity argument and walked "
            "back from HIGH, but MEASURED it: control query 0.156ms -> 225s under "
            "load, +2.3GiB RSS. The de-escalation does not hold; severity stays High."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "pass-walkback-measured")
        self.assertEqual(r["exit"], 0)

    # --- measure-rebuttal override -------------------------------------------
    def test_measure_rebuttal_html_accepted(self):
        body = (
            "- Severity: Medium\n"
            "Walked back from HIGH; the architecture means one request cannot "
            "exhaust the node, so the de-escalation rests on the pool capacity.\n"
            "<!-- r-escalate-measure-rebuttal: measurement infeasible without "
            "mainnet load; reviewed by operator -->"
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["exit"], 0)

    def test_measure_rebuttal_line_accepted(self):
        body = (
            "- Severity: Medium\n"
            "Walked back from HIGH; the concurrency model means a single request "
            "cannot deny the node. De-escalation rests on pool capacity.\n"
            "r-escalate-measure-rebuttal: pool-size argument is structurally sound"
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_measure_rebuttal_oversized_ignored(self):
        body = (
            "- Severity: Medium\n"
            "Walked back from HIGH; the architecture means one request cannot "
            "exhaust the node; de-escalation rests on pool capacity.\n"
            "r-escalate-measure-rebuttal: " + ("x" * 250)
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-reasoned-walkback-not-measured")

    # --- funds-class bsc-epoch path is unchanged by the new branch -----------
    def test_funds_walkback_no_reasoning_still_uses_escalate_first_branch(self):
        """A funds walk-back with NO reasoning-only prose still routes to the
        original escalate-first fail, not the new measured branch."""
        body = (
            "- Severity: High\n"
            "the downstream forged-state-root -> unauthorized cross-chain asset "
            "movement is source-traced, not separately executed; theft of bridged "
            "funds is the tail. The Critical end-to-end fund-theft framing is "
            "deliberately NOT claimed."
        )
        r = self._check(body)
        self.assertEqual(r["verdict"], "fail-narrowed-without-escalate-first-attempt")
        self.assertEqual(r["exit"], 1)
        self.assertFalse(r["evidence"]["reasoning_only_walkback_hits"])


class TestProveImpossibleOrEscalateStrict(unittest.TestCase):
    """PROVE-IMPOSSIBLE-OR-ESCALATE (operator directive 2026-07-02, NUVA anchor).

    A finding may NEVER fall to a lower tier via a PUNT ("attempted but could
    not build the evidence" / "single-process cannot model a consensus engine" /
    "would require a testnet"). The ONLY valid fallback is a cited
    PROOF-OF-IMPOSSIBILITY for the higher tier. Advisory-first behind
    AUDITOOOR_ESCALATE_FIRST_STRICT / strict=True; NON-strict is byte-identical
    to the legacy gate.
    """

    def setUp(self) -> None:
        import tempfile

        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _check(self, body: str, severity: str = "auto", strict: bool = False):
        p = _write(self.tmp, "draft.md", body)
        return mod.check(
            p,
            workspace=None,
            severity_override=severity,
            enrich_asymmetry=False,
            strict=strict,
        )

    # The NUVA begin-blocker escalation-consideration shape, distilled: walks
    # away from the higher freeze tier on a "single-process cannot model a
    # consensus engine" PUNT, WITH a bare r-escalate-first-rebuttal.
    _NUVA_SHAPE = (
        "- Severity: Medium\n"
        "r-escalate-first-rebuttal: a self-standing Medium row is fully proven; "
        "the higher tier is unproven and explicitly not claimed.\n"
        "The claim is narrowed and walked back from HIGH to MEDIUM; the higher "
        "Temporary freezing of funds tier was considered and deliberately not "
        "claimed.\n"
        "Escalation would require a validator-set-level measurement; a single-"
        "process in-tree measurement cannot model a consensus engine or its "
        "timeout, so neither leg is established. This is walked back to the "
        "Medium floor pending consensus-level instrumentation.\n"
        "not_proven_impacts: Temporary freezing of funds (High) - consensus-halt "
        "leg not driven by a single-process test."
    )

    # (a) STRICT: punt blocker + NO cited impossibility -> FAIL.
    def test_strict_punt_without_impossibility_fails(self):
        r = self._check(self._NUVA_SHAPE, strict=True)
        self.assertEqual(r["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r["exit"], 1)
        self.assertTrue(r["evidence"]["punt_blocker_hits"])
        self.assertFalse(r["evidence"]["impossibility_cited_hits"])
        self.assertIn("remediation", r)

    # (c) STRICT: a bare escalate-first-rebuttal does NOT green a punt.
    def test_strict_bare_rebuttal_does_not_green_punt(self):
        # The NUVA shape ALREADY carries a bare r-escalate-first-rebuttal.
        r = self._check(self._NUVA_SHAPE, strict=True)
        self.assertEqual(r["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r["exit"], 1)

    # (d) NON-strict on the SAME body is byte-identical to the legacy gate:
    #     the punt reads as an escalate-first attempt / rebuttal and PASSES.
    def test_nonstrict_same_body_passes_backward_compat(self):
        r = self._check(self._NUVA_SHAPE, strict=False)
        self.assertEqual(r["exit"], 0)
        self.assertNotEqual(r["verdict"], "fail-punt-without-cited-impossibility")

    # (b) STRICT: a fallback that CITES a real code-guard impossibility PASSES.
    def test_strict_cited_codeguard_impossibility_passes(self):
        body = (
            "- Severity: Medium\n"
            "The claim is narrowed to Medium; the higher Temporary freezing of "
            "funds tier was attempted but not reached.\n"
            "Escalation blocker: a single-process test cannot model the consensus "
            "engine.\n"
            "Proof-of-impossibility for the higher freeze tier: the settlement "
            "path caps freeze at MaxSwapOutBatchSize per block "
            "(src/vault/keeper/abci.go:14), which structurally bounds the halt "
            "impact - the consensus-halt tier is unreachable because that guard "
            "prevents unbounded per-block work on the settlement leg."
        )
        r = self._check(body, strict=True)
        self.assertTrue(r["evidence"]["impossibility_cited_hits"])
        self.assertNotEqual(r["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r["exit"], 0)

    # (b') STRICT: a numeric economic-bound impossibility PASSES.
    def test_strict_cited_economic_bound_impossibility_passes(self):
        body = (
            "- Severity: Medium\n"
            "The claim is narrowed to Medium; the higher drain tier was "
            "considered and not claimed.\n"
            "Blocker: a single-process test cannot model the multi-node drain.\n"
            "Proof-of-impossibility: the higher drain tier is economically "
            "infeasible - reaching it costs the attacker 5000000 USD in fees to "
            "sustain, so the higher impact is unreachable."
        )
        r = self._check(body, strict=True)
        self.assertTrue(r["evidence"]["impossibility_cited_hits"])
        self.assertNotEqual(r["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r["exit"], 0)

    # (b'') STRICT: a named in-protocol recovery mechanism PASSES.
    def test_strict_named_recovery_mechanism_passes(self):
        body = (
            "- Severity: Medium\n"
            "The claim is narrowed to Medium; the higher freezing-of-funds tier "
            "was attempted but the end-to-end drain could not be executed.\n"
            "Blocker: would require a testnet to model the consensus halt.\n"
            "Proof-of-impossibility for the higher freeze tier: frozen funds are "
            "recoverable via the module's in-protocol refund window, which caps "
            "the loss and reverses any temporary freeze."
        )
        r = self._check(body, strict=True)
        self.assertTrue(r["evidence"]["impossibility_cited_hits"])
        self.assertNotEqual(r["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r["exit"], 0)

    # STRICT off by default: a punt-only body with strict=False PASSES (the
    # advisory-first contract - the new fail fires ONLY under STRICT).
    def test_default_is_advisory_off(self):
        r = self._check(self._NUVA_SHAPE)  # strict defaults False
        self.assertEqual(r["exit"], 0)

    # No-punt STRICT body is unaffected by the new gate (a genuine attempt with
    # a non-punt blocker still passes under strict).
    def test_strict_nonpunt_attempt_still_passes(self):
        body = (
            "- Severity: High\n"
            "downstream fund-drain is source-traced, not separately executed.\n"
            "## Escalate-First Attempt\n"
            "We attempted the critical end-to-end execution. Blocker: no reachable "
            "in-scope downstream consumer is deployed at the audit pin, so the "
            "end-to-end drain could not be executed; the narrowing is a forced "
            "fallback."
        )
        r = self._check(body, strict=True)
        # non-punt blocker -> the STRICT gate does not fire; legacy attempt pass.
        self.assertEqual(r["verdict"], "pass-escalate-first-attempted")
        self.assertEqual(r["exit"], 0)

    # The real NUVA draft on disk: NON-strict PASS, STRICT FAIL (integration).
    def test_real_nuva_draft_strict_fail_nonstrict_pass(self):
        nuva = Path(
            "/Users/wolf/audits/nuva/submissions/paste_ready/"
            "nuva-begin-blocker-unbounded-timeout-queue-walk-block-time/"
            "nuva-begin-blocker-unbounded-timeout-queue-walk-block-time.md"
        )
        if not nuva.exists():
            self.skipTest("NUVA draft not present in this checkout")
        r_ns = mod.check(nuva, workspace=None, severity_override="MEDIUM",
                         enrich_asymmetry=False, strict=False)
        self.assertEqual(r_ns["exit"], 0)
        r_s = mod.check(nuva, workspace=None, severity_override="MEDIUM",
                        enrich_asymmetry=False, strict=True)
        self.assertEqual(r_s["verdict"], "fail-punt-without-cited-impossibility")
        self.assertEqual(r_s["exit"], 1)

    # env-driven STRICT via main(): AUDITOOOR_ESCALATE_FIRST_STRICT=1 fails.
    def test_env_strict_via_main_fails(self):
        import os

        p = _write(self.tmp, "nuva.md", self._NUVA_SHAPE)
        old = os.environ.get("AUDITOOOR_ESCALATE_FIRST_STRICT")
        try:
            os.environ["AUDITOOOR_ESCALATE_FIRST_STRICT"] = "1"
            rc = mod.main([str(p), "--severity", "MEDIUM", "--no-asymmetry", "--json"])
            self.assertEqual(rc, 1)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_ESCALATE_FIRST_STRICT", None)
            else:
                os.environ["AUDITOOOR_ESCALATE_FIRST_STRICT"] = old

    def test_env_absent_via_main_passes(self):
        import os

        p = _write(self.tmp, "nuva.md", self._NUVA_SHAPE)
        old = os.environ.get("AUDITOOOR_ESCALATE_FIRST_STRICT")
        try:
            os.environ.pop("AUDITOOOR_ESCALATE_FIRST_STRICT", None)
            rc = mod.main([str(p), "--severity", "MEDIUM", "--no-asymmetry", "--json"])
            self.assertEqual(rc, 0)
        finally:
            if old is not None:
                os.environ["AUDITOOOR_ESCALATE_FIRST_STRICT"] = old


class TestDispatchBriefNeverGiveUpDirective(unittest.TestCase):
    """(e) The dispatch-brief skeleton now carries the never-give-up directive."""

    def test_skeleton_contains_never_give_up_directive(self):
        tool = Path(__file__).resolve().parents[1] / "dispatch-agent-with-prebriefing.py"
        spec = importlib.util.spec_from_file_location("dispatch_agent_with_prebriefing", str(tool))
        assert spec and spec.loader
        dmod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dmod)  # type: ignore[union-attr]
        lines = dmod._format_escalate_first_standing_directive()
        blob = "\n".join(lines)
        self.assertIn("NEVER give up on escalation", blob)
        self.assertIn("PROOF-OF-IMPOSSIBILITY", blob)
        self.assertIn("prove not-possible", blob)

    def test_skeleton_directive_prepended_on_both_paths(self):
        tool = Path(__file__).resolve().parents[1] / "dispatch-agent-with-prebriefing.py"
        spec = importlib.util.spec_from_file_location("dispatch_agent_with_prebriefing2", str(tool))
        assert spec and spec.loader
        dmod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dmod)  # type: ignore[union-attr]
        # skeleton-unavailable path (payload=None)
        out_none = dmod.format_skeleton_as_markdown(
            None, lane_type="escalation", severity="HIGH", workspace_path=None
        )
        self.assertIn("NEVER give up on escalation", out_none)
        # skeleton-available path (minimal payload)
        out_payload = dmod.format_skeleton_as_markdown(
            {"lane_specific_rules": [], "skeleton_sections": []},
            lane_type="escalation",
            severity="HIGH",
            workspace_path=None,
        )
        self.assertIn("NEVER give up on escalation", out_payload)


if __name__ == "__main__":
    unittest.main()
