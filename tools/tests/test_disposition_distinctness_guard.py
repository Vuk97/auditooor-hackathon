"""test_disposition_distinctness_guard.py

Tests for the anti-false-negative gate on NEGATIVE dispositions. The load-bearing
property: a finding-KILL (dup/OOS/known-issue/R47/R53/upstream) is permitted ONLY
with a four-axis all-`match` record carrying cited evidence; anything less FAILS
OPEN (finding stays live). Inverts the reflexive-dedup false-negative asymmetry.

Includes a regression test that reproduces the exact NUVA near-miss: reflexively
killing the uncapped-BeginBlocker finding as a Halborn-7.2 dup, where the IMPACT
axis differs (block-stuffing vs premature-dequeue) -> the guard KEEPS IT OPEN.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "disposition-distinctness-guard.py"


def _load():
    spec = importlib.util.spec_from_file_location("distinctness_guard", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["distinctness_guard"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


G = _load()

_EV = "src/vault/keeper/reconcile.go:474 - cited real source line proving the axis"


def _axis(v):
    return {"verdict": v, "evidence": _EV}


class TestDistinctnessGuard(unittest.TestCase):
    def test_no_four_axis_record_fails_open(self):
        """The classic shallow kill: keyword/mention-only, no distinctness block."""
        res = G.evaluate_distinctness({"disposition_type": "dupe",
                                       "prior_art_ref": "Halborn 7.2"})
        self.assertEqual(res["verdict"], "keep-open-insufficient-evidence")
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))

    def test_all_axes_match_permits_kill(self):
        res = G.evaluate_distinctness({
            "disposition_type": "dupe",
            "distinctness": {a: _axis("match") for a in G.AXES},
        })
        self.assertEqual(res["verdict"], "kill-permitted")
        self.assertTrue(G._verdict_permits_kill(res["verdict"]))

    def test_one_axis_differ_keeps_open_extension_distinct(self):
        d = {a: _axis("match") for a in G.AXES}
        d["impact"] = _axis("differ")
        res = G.evaluate_distinctness({"disposition_type": "dupe", "distinctness": d})
        self.assertEqual(res["verdict"], "keep-open-extension-distinct")
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))

    def test_match_without_evidence_is_not_a_match(self):
        d = {a: _axis("match") for a in G.AXES}
        d["privilege"] = {"verdict": "match", "evidence": "ok"}  # too short
        res = G.evaluate_distinctness({"disposition_type": "oos", "distinctness": d})
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))
        self.assertEqual(res["axes"]["privilege"]["verdict"], "match-uncited")

    def test_unknown_axis_fails_open(self):
        d = {a: _axis("match") for a in G.AXES}
        d["attack_path"] = _axis("unknown")
        res = G.evaluate_distinctness({"disposition_type": "r53", "distinctness": d})
        self.assertTrue(res["verdict"].startswith("keep-open"))

    def test_non_kill_disposition_is_na(self):
        res = G.evaluate_distinctness({"disposition_type": "in-scope-confirmed"})
        self.assertEqual(res["verdict"], "not-a-kill")
        self.assertTrue(G._verdict_permits_kill(res["verdict"]))

    def test_rebuttal_marker_rules_in_a_blocked_kill(self):
        res = G.evaluate_distinctness({
            "disposition_type": "oos",
            "_text": "distinctness-guard-rebuttal: operator confirms OOS per clause 3",
        })
        self.assertEqual(res["verdict"], "kill-permitted-via-rebuttal")

    def test_NUVA_halborn_7_2_reflexive_kill_is_blocked(self):
        """Regression: the exact near-miss. Killing the uncapped-BeginBlocker
        timeout-queue finding as a Halborn-7.2 dup. Root-cause/attack-path/privilege
        look similar (queue walk in a block hook), but IMPACT differs: Halborn 7.2 =
        premature-dequeue/automation-loss on the CAPPED swap-out queue; this finding
        = block-stuffing/unbounded-gas via the UNCAPPED timeout queues. The guard
        must KEEP IT OPEN, not kill."""
        res = G.evaluate_distinctness({
            "disposition_type": "known-issue",
            "prior_art_ref": "Halborn 7.2 (Risk Accepted)",
            "finding_ref": "nuva-begin-blocker-unbounded-timeout-queue",
            "distinctness": {
                "root_cause": {"verdict": "differ",
                               "evidence": "7.2 = paused-skip counter bug on the CAPPED "
                                           "swap-out queue; this = NO batch cap on the "
                                           "timeout queues (reconcile.go:474)"},
                "attack_path": {"verdict": "differ",
                                "evidence": "7.2 relies on organically paused vaults; this "
                                            "is permissionless CreateVault x N (vault.go)"},
                "privilege": _axis("match"),
                "impact": {"verdict": "differ",
                           "evidence": "7.2 impact = automation-loss/Low; this = Block "
                                       "stuffing / Unbounded gas (SEVERITY.md:43,46)"},
            },
        })
        self.assertEqual(res["verdict"], "keep-open-extension-distinct")
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))

    def test_refutation_kill_with_cited_reason_is_permitted(self):
        """A reachability/design-intent refutation (not-reachable, false-positive, OOS-
        by-code) with a SOURCE-CITED reason is a legitimate kill - it does NOT need a
        four-axis dedup proof. This is the strata adversarial-verify case."""
        res = G.evaluate_distinctness({
            "disposition_type": "known-dead-end",
            "id": "init-reinit",
            "reason": "Not reachable. The Tranche implementation is protected via the "
                      "inherited constructor _disableInitializers() at AccessControlled.sol:49-52.",
        })
        self.assertEqual(res["verdict"], "kill-permitted-refutation-cited")
        self.assertTrue(G._verdict_permits_kill(res["verdict"]))

    def test_dedup_kill_with_cited_reason_STILL_needs_four_axis(self):
        """A DEDUP-class kill is NOT rescued by a cited reason - citing the prior art
        does not prove four-axis distinctness. This is exactly the reflexive-dedup trap
        (my NUVA Halborn-7.2 near-miss) and must stay BLOCKED."""
        res = G.evaluate_distinctness({
            "disposition_type": "dupe",
            "prior_art_ref": "Halborn 7.2",
            "reason": "Duplicate of Halborn 7.2 queue-walk DoS at payout.go:840.",
        })
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))
        self.assertTrue(res["verdict"].startswith("keep-open"))

    def test_bare_killed_reason_is_still_shallow(self):
        res = G.evaluate_distinctness({"disposition_type": "known-dead-end",
                                       "reason": "KILLED"})
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))

    def test_cited_reason_embedded_in_verdict_field_is_permitted(self):
        """mechanism_dispositions.jsonl embeds the cited reason inline in the
        `verdict` field (verdict='refuted: ...file.sol:NN...'). The guard must
        recognize that as a legitimate refutation, not flag it shallow."""
        res = G.evaluate_distinctness({
            "disposition_type": "refuted",
            "verdict": "refuted: reentrancy is not unprivileged-exploitable; the "
                       "value-moving sinks StrataCDO.deposit (StrataCDO.sol:228) and "
                       "withdraw (StrataCDO.sol:259) are nonReentrant.",
        })
        self.assertEqual(res["verdict"], "kill-permitted-refutation-cited")

    def test_short_oos_verdict_still_shallow(self):
        """A short keyword verdict with no citation stays shallow even via `verdict`."""
        res = G.evaluate_distinctness({"disposition_type": "oos", "verdict": "matches-oos"})
        self.assertFalse(G._verdict_permits_kill(res["verdict"]))

    def test_sweep_strata_refutations_are_guarded(self):
        """The 8 strata known_dead_ends are cited reachability refutations -> guarded."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "known_dead_ends.jsonl").write_text(
                json.dumps({"id": "quoteDeposit-underflow", "verdict": "KILLED",
                            "reason": "The dangerous threshold feeBps >= 10000 is NOT reachable; "
                                      "capped by setExitFees require(fee <= 0.01e18) at StrataCDO.sol:424-426.",
                            "source": "adversarial-verify"}) + "\n",
                encoding="utf-8",
            )
            res = G.sweep_workspace(ws)
            self.assertEqual(res["kills_total"], 1)
            self.assertEqual(res["shallow_count"], 0)

    def test_sweep_flags_shallow_oos_kill(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            # a shallow OOS kill sidecar with no four-axis record
            (ws / ".auditooor" / "oos_check_abc123.json").write_text(
                json.dumps({"schema": "auditooor.oos_check.v1", "verdict": "matches-oos",
                            "finding_ref": "some-finding"}),
                encoding="utf-8",
            )
            res = G.sweep_workspace(ws)
            self.assertEqual(res["kills_total"], 1)
            self.assertEqual(res["shallow_count"], 1)

    def test_sweep_passes_guarded_kill(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "mechanism_dispositions.jsonl").write_text(
                json.dumps({"verdict": "refuted-known-issue", "disposition_type": "known-issue",
                            "distinctness": {a: {"verdict": "match", "evidence": _EV}
                                             for a in G.AXES}}) + "\n",
                encoding="utf-8",
            )
            res = G.sweep_workspace(ws)
            self.assertEqual(res["shallow_count"], 0)
            self.assertEqual(len(res["guarded"]), 1)


if __name__ == "__main__":
    unittest.main()
