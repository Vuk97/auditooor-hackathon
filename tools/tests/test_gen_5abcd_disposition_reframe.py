#!/usr/bin/env python3
"""GEN-5A/5B/5C/5D regression: an impact-REFRAME kill/OOS must carry the reframe's
required SOUNDNESS PROOF or the disposition is reopened (needs-fuzz).

Covers, for each of the four sub-checks:
  * a missing-proof fixture FIRES a reopen with the correct reframe_kind + missing
    element(s);
  * a with-proof fixture stays SILENT.
Plus: FP-control (dedup / stale-pin / oos-by-path silent), the rebuttal marker,
the advisory-exit matrix (WARN rc0 default, strict rc1 on a reopen), sidecar
emission + schema, and a REAL-fleet-shaped 5A artifact (mirrors obyte
importassistant-buyshares-donation-dos: carries all 3 => silent; strip => reopen).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_TOOL = _H.parent / "disposition-reframe-soundness-check.py"
_s = importlib.util.spec_from_file_location("drsc", _TOOL)
_m = importlib.util.module_from_spec(_s)
sys.modules["drsc"] = _m
_s.loader.exec_module(_m)


def _mkws(dispo, entry, rationale, md="# finding\nstatus: disposed\n",
          rationale_name=None):
    ws = Path(tempfile.mkdtemp())
    d = ws / "submissions" / dispo / entry
    d.mkdir(parents=True)
    (d / f"{entry}.md").write_text(md)
    if rationale is not None:
        name = rationale_name or ("_KILL_RATIONALE.json" if dispo == "_killed"
                                  else "_OOS_REJECTION.json")
        (d / name).write_text(json.dumps(rationale))
    return ws, d


def _kinds(res):
    return {r["reframe_kind"] for r in res["rows"]}


class Gen5(unittest.TestCase):
    # -- 5A griefing / DoS-only ------------------------------------------------
    def test_5A_fires_when_proof_absent(self):
        ws, _ = _mkws("_oos_rejected", "f", {
            "verdict": "OUT-OF-SCOPE (griefing only)",
            "rule": "denial-of-service, no double-spend",
            "proof": "attacker can just revert the first call."})
        r = _m.check(ws)
        self.assertEqual(r["verdict"], "warn-disposition-reframe-unsound")
        self.assertIn("5A", _kinds(r))
        row = [x for x in r["rows"] if x["reframe_kind"] == "5A"][0]
        # all three 5A elements are absent
        self.assertEqual(set(row["missing_proof"]),
                         {"not-permanent", "rubric-threshold", "composition"})

    def test_5A_silent_when_all_three_present(self):
        ws, _ = _mkws("_oos_rejected", "f", {
            "verdict": "OUT-OF-SCOPE (griefing, below floor)",
            "rule": "SCOPE.md:60 fund-loss floor USD 1000; griefing OOS",
            "proof": ("A fresh instance holds no user funds; the deployer "
                      "redeploys via Factory.sol so it is not a permanent freeze "
                      "(temporary). Below the SEVERITY.md Medium floor: $0 "
                      "non-attacker loss, only the attacker's dust is stuck - it "
                      "does not compose into any theft downstream.")})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_5A_partial_proof_still_reopens(self):
        # has not-permanent + composition but NO rubric-threshold cite
        ws, _ = _mkws("_killed", "f", {
            "verdict": "griefing DoS-only",
            "rule": "griefing",
            "proof": ("recoverable via redeploy (not permanent); only the "
                      "attacker's own funds affected, no downstream theft.")})
        r = _m.check(ws)
        row = [x for x in r["rows"] if x["reframe_kind"] == "5A"][0]
        self.assertEqual(row["missing_proof"], ["rubric-threshold"])

    # -- 5B unreachable-by-deployment-constant ---------------------------------
    def test_5B_fires_when_proof_absent(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (unreachable)",
            "rule": "gated by a deploy constant",
            "proof": "the FEE_ON flag is a hardcoded constant so it cannot reach."})
        r = _m.check(ws)
        self.assertIn("5B", _kinds(r))
        row = [x for x in r["rows"] if x["reframe_kind"] == "5B"][0]
        self.assertIn("all-deployments", row["missing_proof"])

    def test_5B_silent_when_immutable_and_all_deployments(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (unreachable by a deployment constant)",
            "rule": "immutable config",
            "proof": ("FEE_ON is an immutable compile-time constant (no setter, "
                      "cannot be changed) and this holds across all deployments / "
                      "every instance on all chains.")})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    # -- 5C mathematically-impossible-single-step ------------------------------
    def test_5C_fires_when_proof_absent(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (mathematically impossible)",
            "rule": "impossible in a single tx",
            "proof": "the two writes cannot happen in one transaction, atomic."})
        r = _m.check(ws)
        self.assertIn("5C", _kinds(r))
        row = [x for x in r["rows"] if x["reframe_kind"] == "5C"][0]
        self.assertEqual(row["missing_proof"], ["multi-step-considered"])

    def test_5C_silent_when_multistep_considered(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (mathematically impossible in a single tx)",
            "rule": "impossible single-step",
            "proof": ("even across multiple blocks / a sequenced multi-step "
                      "composition of cross-fn calls, no path reaches it.")})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_5C_does_not_fire_on_bare_atomic_revert(self):
        # 'reverts atomically' is a single-step word with NO impossibility claim -
        # it is a 5A griefing argument, not a 5C impossibility reframe.
        ws, _ = _mkws("_oos_rejected", "f", {
            "verdict": "OUT-OF-SCOPE (griefing, below floor)",
            "rule": "SCOPE.md:60 floor; griefing",
            "proof": ("the first call reverts atomically and unwinds; recoverable "
                      "via redeploy (not permanent); below the SEVERITY.md floor, "
                      "$0 non-attacker loss, no downstream theft.")})
        r = _m.check(ws)
        self.assertNotIn("5C", _kinds(r))
        self.assertEqual(r["verdict"], "pass-disposition-reframe-sound")

    # -- 5D trusted-actor-only escape-hatch ------------------------------------
    def test_5D_fires_when_proof_absent(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (onlyOwner only)",
            "rule": "access-control, privileged only",
            "proof": "only the owner can call setFee()."})
        r = _m.check(ws)
        self.assertIn("5D", _kinds(r))
        row = [x for x in r["rows"] if x["reframe_kind"] == "5D"][0]
        self.assertEqual(set(row["missing_proof"]),
                         {"actor-trusted-per-scope", "no-escape-hatch"})

    def test_5D_silent_when_trust_and_no_escape_hatch(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "NEGATIVE (only the owner)",
            "rule": "onlyOwner access-control",
            "proof": ("the owner is a trusted actor per SCOPE.md's trust model; "
                      "there is no escape-hatch, no self-grant and no delegatecall "
                      "path, so no lower-priv actor can obtain the role.")})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    # -- FP-control ------------------------------------------------------------
    def test_dedup_kill_is_silent(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "DROPPED (duplicate of a disclosed prior-audit finding)",
            "rule": "DISCLOSED-INELIGIBLE dedup",
            "proof": "the griefing vector is prior-audit H-1, cap present."})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_stale_pin_kill_is_silent(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "INVALID (stale target)",
            "rule": "cites removed code, no longer exists at the pin",
            "proof": "griefing on onlyOwner path but the function was removed."})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_oos_by_path_kill_is_silent(self):
        ws, _ = _mkws("_oos_rejected", "f", {
            "verdict": "OUT-OF-SCOPE by path (not in the scope tree)",
            "rule": "path exclusion",
            "proof": "the file is out of scope; griefing on an onlyOwner setter."})
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_rebuttal_marker_clears_entry(self):
        ws, d = _mkws("_killed", "f", {
            "verdict": "griefing DoS-only", "rule": "griefing",
            "proof": "just reverts."})
        (d / "f.md").write_text(
            "# finding\n<!-- disposition-reframe-rebuttal: operator-acked, "
            "non-permanent recovery documented offline -->\n")
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_finding_body_word_does_not_invoke_reframe(self):
        # a griefing word in the FINDING md (the finding's OWN claim) must not by
        # itself invoke a reframe - the trigger keys on the disposition WHY only.
        ws, d = _mkws("_killed", "f", {
            "verdict": "DROPPED", "rule": "R47 dedup",
            "proof": "matches disclosed H-1 at Foo.sol:36"},
            md="# finding\nThis is a griefing / denial-of-service DoS bug.\n")
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    # -- advisory-exit matrix + sidecar ----------------------------------------
    def _run_cli(self, ws, env_extra=None, no_emit=True):
        env = dict(os.environ)
        env.pop("AUDITOOOR_L37_STRICT", None)
        env.pop("AUDITOOOR_DISPOSITION_REFRAME_STRICT", None)
        if env_extra:
            env.update(env_extra)
        args = [sys.executable, str(_TOOL), "--workspace", str(ws)]
        if no_emit:
            args.append("--no-emit")
        return subprocess.run(args, capture_output=True, text=True, env=env)

    def test_advisory_exit_matrix(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "griefing DoS-only", "rule": "griefing",
            "proof": "just reverts."})
        # default WARN -> rc0
        p = self._run_cli(ws)
        self.assertEqual(p.returncode, 0)
        self.assertIn("warn-disposition-reframe-unsound", p.stdout)
        # dedicated STRICT -> rc1
        p = self._run_cli(ws, {"AUDITOOOR_DISPOSITION_REFRAME_STRICT": "1"})
        self.assertEqual(p.returncode, 1)
        self.assertIn("fail-disposition-reframe-unsound", p.stdout)
        # L37 umbrella STRICT -> rc1
        p = self._run_cli(ws, {"AUDITOOOR_L37_STRICT": "1"})
        self.assertEqual(p.returncode, 1)
        self.assertIn("fail-disposition-reframe-unsound", p.stdout)

    def test_clean_ws_passes_rc0(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "DROPPED (dupe)", "rule": "R47 dedup",
            "proof": "matches disclosed H-1 at Foo.sol:36"})
        p = self._run_cli(ws, {"AUDITOOOR_L37_STRICT": "1"})
        self.assertEqual(p.returncode, 0)
        self.assertIn("pass-disposition-reframe-sound", p.stdout)

    def test_sidecar_emitted_with_schema(self):
        ws, _ = _mkws("_killed", "f", {
            "verdict": "griefing DoS-only", "rule": "griefing",
            "proof": "just reverts."})
        args = [sys.executable, str(_TOOL), "--workspace", str(ws)]
        subprocess.run(args, capture_output=True, text=True,
                       env={k: v for k, v in os.environ.items()
                            if k not in ("AUDITOOOR_L37_STRICT",)})
        sc = ws / ".auditooor" / "disposition_reframe_soundness_hypotheses.jsonl"
        self.assertTrue(sc.is_file())
        rows = [json.loads(l) for l in sc.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema"],
                         "auditooor.disposition_reframe_soundness_hypotheses.v1")
        for f in ("id", "finding_dir", "disposition", "reframe_kind",
                  "missing_proof", "verdict", "excerpt", "why", "reopen"):
            self.assertIn(f, rows[0])
        self.assertTrue(rows[0]["reopen"])

    # -- real-fleet-shaped 5A artifact (obyte importassistant mirror) ----------
    _FLEET_5A = {
        "verdict": "OUT-OF-SCOPE (frontrunning/griefing + below $1000 floor + "
                   "redeployable non-permanent)",
        "rule": "SCOPE.md frontrunning/griefing OOS; SCOPE.md:60 fund-loss floor "
                "USD 1000; redeployable temporary-availability (not permanent "
                "freeze of user funds)",
        "proof": ("ImportAssistant.sol:330 require(...) reverts atomically. It is "
                  "a DoS not theft: $0 non-attacker loss; only the attacker's "
                  "self-donated dust is stuck. A fresh ImportAssistant holds no "
                  "user funds and the deployer redeploys via AssistantFactory.sol "
                  "-> not a permanent freeze of user capital.")}

    def test_fleet_shaped_5A_with_proof_is_silent(self):
        ws, _ = _mkws("_oos_rejected", "importassistant", dict(self._FLEET_5A))
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-reframe-sound")

    def test_fleet_shaped_5A_stripped_reopens(self):
        stripped = dict(self._FLEET_5A)
        stripped["proof"] = ""
        stripped["rule"] = "griefing OOS"
        stripped["verdict"] = "OUT-OF-SCOPE (griefing only)"
        ws, _ = _mkws("_oos_rejected", "importassistant", stripped)
        r = _m.check(ws)
        self.assertEqual(r["verdict"], "warn-disposition-reframe-unsound")
        self.assertIn("5A", _kinds(r))


if __name__ == "__main__":
    unittest.main()
