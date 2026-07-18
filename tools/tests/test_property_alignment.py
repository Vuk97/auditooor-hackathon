#!/usr/bin/env python3
"""test_property_alignment.py - disposition PROPERTY-ALIGNMENT advisory axis (E7).

Extends tools/disposition-rationale-check.py with an advisory-first, NO-AUTO-
CREDIT (verdict="needs-review") sub-check: for a NEGATIVE FALSIFICATION/mechanism
kill on a severity-eligible finding, the property the kill REFUTES must be the
SAME property the finding CLAIMS. A kill that soundly disproves property X while
the finding claims a distinct property Y does NOT refute the finding.

Anchor (nuva swapout mis-kill): a prior falsification refuted "processPendingSwap-
Outs is capped at MaxSwapOutBatchSize=100 (bounded)" while the real Critical is
"paused entries BYPASS the cap => unbounded permanent chain-halt" - a distinct
property; the wrong-property refutation silently buried a FILED Critical until it
was re-opened by manual re-adjudication.

Non-vacuity: a kill refuting property X while the finding claims Y FIRES; a kill
refuting the SAME property the finding claims stays SILENT (test_mismatch_fires /
test_aligned_stays_green). The bypass-marker and premise-concept predicates are
load-bearing (test_bypass_predicate_is_load_bearing / _premise_concept_...).
DEDUP boundary: E7 only examines entries #146 deems 'ok' (test_distinct_from_146);
dedup/prior-art and scope/OOS-concession kills are out of E7 scope.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "disposition-rationale-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("disp_e7", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["disp_e7"] = m
    spec.loader.exec_module(m)
    return m


# --- finding bodies ---------------------------------------------------------
# MISMATCH: claims a FREEZE/DoS via a cap-BYPASS; the kill refutes a bounded cap
# + a theft (over-pay/drain) family -> distinct property (S1 premise-bypass +
# S2 impact-class-disjoint).
_MD_MISMATCH = """# Cap-bypass unbounded EndBlocker iteration in processPendingSwapOuts leads to permanent chain-halt

attack_class: griefing-dos

Severity: Critical
Impact(s): Permanent freezing of funds

## Summary
processPendingSwapOuts walks the global queue; paused entries bypass the cap so the
cap check is never reached, giving an unbounded non-draining O(N) per-block walk.
"""

# BOLD/LIST severity forms: same cap-bypass MISMATCH content but the severity is
# `**Severity:**` (bold) and the impact is `- Impact(s):` (list) - the real finding
# forms the old `^\s*severity\s*:` regex silently skipped (DEFECT 2 severity FN).
_MD_BOLD_SEV = """# Cap-bypass unbounded EndBlocker iteration in processPendingSwapOuts leads to permanent chain-halt

attack_class: griefing-dos

**Severity:** Critical

- Impact(s): Permanent freezing of funds

## Summary
processPendingSwapOuts walks the global queue; paused entries bypass the cap so the
cap check is never reached, giving an unbounded non-draining O(N) per-block walk.
"""

# ALIGNED: the kill refutes the SAME phantom-NAV-via-splitValuatedNavOut property
# the finding claims (no bypass marker, same subject, same THEFT class) -> GREEN.
_MD_ALIGNED = """# Phantom NAV via splitValuatedNavOut inflates tranche accounting

attack_class: accounting

Severity: High
Impact(s): Theft of funds

## Summary
splitValuatedNavOut produces a phantom NAV that inflates senior-tranche value and
leads to over-withdrawal by the exiting holder.
"""

_KILL_MISMATCH = {
    "verdict": "INVALID (false positive - bounded)",
    "rule": "Mechanism refuted: the MaxSwapOutBatchSize=100 batch cap bounds the walk",
    "proof": ("processPendingSwapOuts is capped at batchSize=100 per block "
              "(abci.go:13); no over-pay/drain; per-vault error isolation."),
}
_KILL_ALIGNED = {
    "verdict": "INVALID (false positive)",
    "rule": "Mechanism refuted: AccountingLib helper removed",
    "proof": ("splitValuatedNavOut does not exist in the shipped tranche code "
              "(Tranche.sol:120); phantom-NAV is not reachable; AccountingLib removed."),
}
_KILL_DEDUP = {
    "verdict": "INVALID (duplicate)",
    "rule": "Duplicate: disclosed in the prior audit (known issue).",
    "proof": "Already reported as prior-audit id QS-2026-03; no new code cite needed.",
}
_KILL_SCOPE = {
    "verdict": "OUT-OF-SCOPE",
    "rule": "Mechanism REAL but out of scope (not an in-scope asset).",
    "proof": ("Mechanism REAL but OUT-OF-SCOPE: the cap bypass is genuine yet the "
              "target contract is not an in-scope asset per SCOPE.md."),
}
# SUPER-PROPERTY kill: introduces a strictly-OUTER bound (queue length enforced at
# INSERTION via requireQueueSpace, applying to paused AND active) the finding never
# names. Its load-bearing premise noun (insertion-time queue length) is DISTINCT
# from the per-batch CAP the finding's bypass clause targets -> a legit kill that
# S1 must NOT flag. The old bucket-collapse S1 flagged it identically to a mis-kill.
_KILL_SUPER = {
    "verdict": "INVALID (false positive - outer bound)",
    "rule": ("Mechanism refuted: the pending-swap queue is length-bounded at "
             "insertion, applying to paused AND active entries alike"),
    "proof": ("the queue is length-bounded at insertion via requireQueueSpace "
              "(payout.go:31); this outer bound applies to paused and active "
              "entries, so paused entries cannot accumulate and the per-block "
              "iteration stays bounded regardless of the downstream limit."),
}


class TestPropertyAlignment(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        for v in ("AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT",
                  "AUDITOOOR_KILL_ANCHOR_SOUNDNESS", "AUDITOOOR_L37_STRICT"):
            os.environ.pop(v, None)

    def _ws(self, md, kill, dispo="_killed", entry="f1", md_extra=""):
        d = Path(tempfile.mkdtemp())
        e = d / "submissions" / dispo / entry
        e.mkdir(parents=True)
        (e / f"{entry}.md").write_text(md + md_extra, encoding="utf-8")
        name = "_KILL_RATIONALE.json" if dispo == "_killed" else "_OOS_REJECTION.json"
        (e / name).write_text(json.dumps(kill), encoding="utf-8")
        return d

    # ---- (i) MISMATCH fires ------------------------------------------------
    def test_mismatch_fires(self):
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
        self.assertEqual(r["misaligned_count"], 1)
        row = r["rows"][0]
        self.assertIn("S1", row["signal"])
        self.assertIn("S2", row["signal"])
        self.assertEqual(row["verdict"], "needs-review")   # NO-AUTO-CREDIT
        self.assertEqual(r["verdict"], "warn-disposition-property-misaligned")

    # ---- (ii) ALIGNED stays GREEN (same-property refutation) ---------------
    def test_aligned_stays_green(self):
        r = self.m.property_alignment_check(self._ws(_MD_ALIGNED, _KILL_ALIGNED))
        self.assertEqual(r["misaligned_count"], 0)
        self.assertEqual(r["verdict"], "pass-disposition-property-align")

    # ---- (iii) DEDUP kill skipped (distinctness-guard's job) --------------
    def test_dedup_kill_skipped(self):
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_DEDUP))
        self.assertEqual(r["misaligned_count"], 0)

    # ---- (iv) OOS/scope-concession kill skipped (concedes mechanism) ------
    def test_scope_concession_skipped(self):
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_SCOPE))
        self.assertEqual(r["misaligned_count"], 0)

    # ---- (v) rebuttal clears the row --------------------------------------
    def test_rebuttal_clears(self):
        ws = self._ws(_MD_MISMATCH, _KILL_MISMATCH,
                      md_extra="\n<!-- disposition-property-alignment-rebuttal: the "
                               "bounded-cap refutation DOES dispose the bypass because "
                               "operator confirmed no paused path -->\n")
        self.assertEqual(self.m.property_alignment_check(ws)["misaligned_count"], 0)

    # ---- (vi) #146-not-ok entry is out of E7 scope (no double-report) -----
    def test_skips_146_flagged(self):
        # empty proof -> #146 flags it; E7 must NOT also report it.
        bad_kill = {"verdict": _KILL_MISMATCH["verdict"],
                    "rule": _KILL_MISMATCH["rule"], "proof": ""}
        ws = self._ws(_MD_MISMATCH, bad_kill)
        self.assertEqual(self.m.check(ws)["verdict"],
                         "warn-disposition-missing-rationale")
        self.assertEqual(self.m.property_alignment_check(ws)["misaligned_count"], 0)

    # ---- distinct from #146 (net-new coverage) ----------------------------
    def test_distinct_from_146(self):
        ws = self._ws(_MD_MISMATCH, _KILL_MISMATCH)
        r7 = self.m.property_alignment_check(ws)
        self.assertEqual(r7["misaligned_count"], 1)
        self.assertFalse(r7["rows"][0]["covered_by_146"])
        # #146 (field-non-empty) PASSES the same entry -> E7 is not a re-derivation.
        self.assertEqual(self.m.check(ws)["verdict"], "pass-disposition-rationale")

    # ---- non-vacuity: bypass marker is load-bearing (S1) ------------------
    def test_bypass_predicate_is_load_bearing(self):
        ws = self._ws(_MD_MISMATCH, _KILL_MISMATCH)
        saved = self.m._BYPASS_TOKENS
        try:
            self.m._BYPASS_TOKENS = ()  # no bypass marker -> S1 cannot fire
            r = self.m.property_alignment_check(ws)
            self.assertEqual(r["misaligned_count"], 0,
                             "with no bypass marker the S1 premise-bypass must go silent")
        finally:
            self.m._BYPASS_TOKENS = saved
        self.assertEqual(self.m.property_alignment_check(ws)["misaligned_count"], 1)

    # ---- non-vacuity: shared premise concept is load-bearing (S1) ---------
    def test_premise_concept_is_load_bearing(self):
        ws = self._ws(_MD_MISMATCH, _KILL_MISMATCH)
        saved = self.m._PREMISE_CONCEPT_IDS
        try:
            self.m._PREMISE_CONCEPT_IDS = set()  # no shared premise -> S1 silent
            self.assertEqual(self.m.property_alignment_check(ws)["misaligned_count"], 0)
        finally:
            self.m._PREMISE_CONCEPT_IDS = saved

    # ---- (1) SUPER-PROPERTY kill does NOT flag (S1 over-flag fix) ----------
    def test_super_property_kill_does_not_flag(self):
        # A legit kill that introduces a strictly-OUTER bound (queue length at
        # INSERTION, applying to paused AND active) the finding never names. Its
        # premise noun differs from the per-batch CAP the finding's bypass clause
        # targets, so S1's co-location model must stay silent; the old bucket-
        # collapse S1 flagged this identically to the genuine mis-kill.
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_SUPER))
        self.assertEqual(r["misaligned_count"], 0,
                         "super-property kill on an outer bound must not flag")
        # non-vacuity: under the OLD bucket-collapse S1 (shared subject concept +
        # any bypass token) this WOULD have fired - prove the co-location model is
        # what suppresses it, not an unrelated skip.
        _emit, fired, fp, kp = self.m._evaluate_alignment(
            _MD_MISMATCH, "\n".join(_KILL_SUPER.values()))
        self.assertNotIn("S1", fired)
        old_shared = kp["premise_concepts"] & fp["concepts"]
        self.assertTrue(old_shared, "old bucket-collapse S1 WOULD have shared a "
                        "premise concept (proves the fix, not a vacuous pass)")

    # ---- (2) genuine nuva-class mis-kill STILL flags via S1 ----------------
    def test_bypassed_premise_still_flags(self):
        # the finding NAMES the cap its bypass clause defeats and the kill leans
        # on THAT SAME cap -> co-located premise-bypass -> S1 must still fire.
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
        self.assertEqual(r["misaligned_count"], 1)
        self.assertIn("S1", r["rows"][0]["signal"])

    # ---- (3) bold `**Severity:**` / list `- Impact(s):` are eligible ------
    def test_bold_and_list_severity_eligible(self):
        # DEFECT 2: the old `^\s*severity\s*:` missed the real markdown forms.
        self.assertTrue(self.m._severity_eligible(_MD_BOLD_SEV))
        self.assertTrue(self.m._severity_eligible(
            "# t\n\n- Impact(s): Theft of funds\n\n## Summary\nx.\n"))
        self.assertTrue(self.m._severity_eligible("# t\n\nSeverity: High\n\nx\n"))
        # a non-eligible severity still returns False (no false-widening)
        self.assertFalse(self.m._severity_eligible("# t\n\n**Severity:** Info\n\nx\n"))
        # end-to-end: a bold-severity mismatch finding now flows through and flags
        r = self.m.property_alignment_check(self._ws(_MD_BOLD_SEV, _KILL_MISMATCH))
        self.assertEqual(r["misaligned_count"], 1)
        self.assertIn("S1", r["rows"][0]["signal"])

    # ---- advisory-first gating + STRICT -----------------------------------
    def test_advisory_off_by_default(self):
        r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
        self.assertEqual(r["verdict"], "warn-disposition-property-misaligned")
        self.assertFalse(r["strict"])

    def test_strict_hard_fails_own_env(self):
        os.environ["AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT"] = "1"
        try:
            r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
            self.assertEqual(r["verdict"], "fail-disposition-property-misaligned")
            self.assertTrue(r["strict"])
        finally:
            os.environ.pop("AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT", None)

    def test_l37_hard_fails_after_graduation(self):
        # R5 E7 GRADUATED to the L37 umbrella (fleet-validated, real-fleet-FP-0): the
        # global AUDITOOOR_L37_STRICT now enforces alongside the two dedicated envs, so a
        # mismatched-hypothesis mis-kill hard-fails under the strict-by-default pipeline.
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
            self.assertEqual(r["verdict"], "fail-disposition-property-misaligned")
            self.assertTrue(r["strict"])
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_kill_anchor_soundness_env_also_enforces(self):
        os.environ["AUDITOOOR_KILL_ANCHOR_SOUNDNESS"] = "1"
        try:
            r = self.m.property_alignment_check(self._ws(_MD_MISMATCH, _KILL_MISMATCH))
            self.assertEqual(r["verdict"], "fail-disposition-property-misaligned")
        finally:
            os.environ.pop("AUDITOOOR_KILL_ANCHOR_SOUNDNESS", None)

    # ---- CLI --emit writes JSONL ------------------------------------------
    def test_cli_emit_writes_jsonl(self):
        ws = self._ws(_MD_MISMATCH, _KILL_MISMATCH)
        out = Path(tempfile.mkdtemp()) / "disposition_property_alignment.jsonl"
        subprocess.run([sys.executable, str(_TOOL), "--workspace", str(ws),
                        "--property-align", "--emit", str(out)], check=True,
                       capture_output=True, text=True)
        lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["verdict"], "needs-review")

    # ---- sidecar cross-join extension (anchor reproduction) ---------------
    def _sidecar_ws(self):
        d = Path(tempfile.mkdtemp())
        # negative hunt sidecar that refuted the BOUNDED-CAP premise.
        sc = d / ".auditooor" / "hunt_findings_sidecars"
        sc.mkdir(parents=True)
        result = json.dumps({
            "applies_to_target": "no",
            "candidate_finding": "processPendingSwapOuts unbounded queue stall?",
            "falsification_attempt": ("processPendingSwapOuts is capped at "
                                      "batchSize=100 per block (payout.go:31), "
                                      "so the walk is bounded; no over-pay."),
        })
        (sc / "hunt__payout.go__processPendingSwapOuts__deadbeef.json").write_text(
            json.dumps({
                "function_anchor": {"file": "/x/src/vault/keeper/payout.go",
                                    "fn": "processPendingSwapOuts"},
                "result": result,
            }), encoding="utf-8")
        # a FILED finding at the SAME anchor claiming the cap-BYPASS property.
        fdir = d / "submissions" / "paste_ready" / "filed" / "endblocker-cap-bypass"
        fdir.mkdir(parents=True)
        (fdir / "endblocker-cap-bypass.md").write_text(_MD_MISMATCH.replace(
            "walks the global queue",
            "walks the global queue in payout.go"), encoding="utf-8")
        return d

    def test_sidecar_cross_join_fires(self):
        ws = self._sidecar_ws()
        # default (disposed-dir only): no _killed entries -> clean.
        self.assertEqual(self.m.property_alignment_check(ws)["misaligned_count"], 0)
        # with the extension on: the negative sidecar vs the filed finding fires.
        r = self.m.property_alignment_check(ws, include_sidecars=True)
        self.assertGreaterEqual(r["misaligned_count"], 1)
        self.assertEqual(r["rows"][0]["dispo"], "sidecar")
        self.assertIn("S1", r["rows"][0]["signal"])


if __name__ == "__main__":
    unittest.main()
