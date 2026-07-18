#!/usr/bin/env python3
"""Regression tests for the DISPOSITION-QUALITY gate (operator directive 2026-07-02).

THE BUG THIS CLOSES
-------------------
The 100%-adjudication enforcement was greenable by a SHALLOW disposition: an
N-A / cleared / dispositioned verdict passed on "reason >= 8 chars" (rubric /
swept axes) or a bare `mechanism` field (mechanism axis). A keyword grep
("grep Governor|castVote = 0 hits -> governance N-A") satisfied it. That is NOT a
genuine attempt to prove the impact unreachable - it is the 'killing easier than
keeping' false-negative anti-pattern. An N-A/cleared verdict must PROVE the impact
UNREACHABLE, not note keyword absence.

WHAT THE GATE REQUIRES (advisory-first behind AUDITOOOR_DISPOSITION_PROOF_STRICT)
--------------------------------------------------------------------------------
An N-A / cleared reason is TERMINAL only when it carries a PROVEN-UNREACHABLE
structure (mirrors escalate-first-required-check.py's admissible forms), ANCHORED
to source (structural claim + file:line on the SAME clause):
  (a) a code-guard / structural fact at file:line;
  (b) a MECHANISM-level absence argument (name the mechanism + why the deployed
      asset structurally cannot reach it);
  (c) a named in-protocol invariant / cap / recovery.
REJECTED: a reason whose only evidence is a bare keyword-grep / "no X found" /
"0 hits" / "not present".

Covered here:
  * tools/lib/disposition_proof_quality.py  - the classifier + never-false-pass.
  * tools/audit-completeness-check.py::_load_terminal_dispositions  - rubric /
    swept-surface axes reject a grep-only N-A under strict, keep it non-strict.
  * tools/completeness-matrix-build.py::_load_mechanism_dispositions - mechanism
    axis rejects a grep-only refuted verdict under strict, keeps it non-strict.

ZERO workspace hardcoding.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_LIB = _TOOLS / "lib" / "disposition_proof_quality.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


dpq = _load("disposition_proof_quality", _LIB)


# --- the two operator-cited NUVA grep-only reasons (verbatim shape) -----------
GREP_ONLY_GOVERNANCE = (
    "N/A on deployed pin: no on-chain voting/proposal/tally mechanism exists in "
    "scope. grep for Proposal|castVote|VoteOption|ERC20Votes|Governor|Tally over "
    "src/vault returns 0 hits. The only 'gov' reference is the stock cosmos-sdk "
    "x/gov import wired into the OUT-OF-SCOPE test harness simapp/app.go:36-37. "
    "No mechanism-axis path to manipulate a vote-result on the deployed source."
)
GREP_ONLY_THEFT_OF_GAS = (
    "N/A on deployed pin: no gas-refund, gas-metering-manipulation, or "
    "gasprice-controllable path exists in scope. grep for gasRefund|refundGas|"
    "gasleft|GasMeter over src/vault and src/nuva-evm-contracts returns 0 "
    "in-scope hits. No mechanism-axis path to theft of gas on the deployed source."
)

# --- the brief's PASS rewrite: a mechanism-level unreachability argument -------
MECHANISM_GROUNDED = (
    "N/A: no on-chain voting module is wired into any in-scope state-transition "
    "(vault/keeper/msg_server.go:28-140), so there is no tally to manipulate; "
    "in-scope governance is admin-Msg only, authority-gated."
)
CODE_GUARD_GROUNDED = (
    "N/A: the interest-transfer leg reverts with 'insufficient reserves' at "
    "reconcile.go:184-186, so no over-release of the escrow is reachable."
)
BARE_ASSERTION = (
    "N/A: this impact class does not apply to the deployed protocol on the "
    "current pin; considered and not claimed."
)
CANDIDATE_KEEP = (
    "CANDIDATE: maps to the existing begin-blocker draft; the source-grounded "
    "path reaches this rubric row as a secondary Critical mapping."
)


class TestClassifier(unittest.TestCase):
    def test_grep_only_governance_rejected(self):
        c = dpq.classify_reason(GREP_ONLY_GOVERNANCE)
        self.assertFalse(c["admissible"])
        self.assertEqual(c["verdict"], "fail-grep-only-absence")
        self.assertTrue(c["grep_only"])

    def test_grep_only_theft_of_gas_rejected(self):
        c = dpq.classify_reason(GREP_ONLY_THEFT_OF_GAS)
        self.assertFalse(c["admissible"])
        self.assertEqual(c["verdict"], "fail-grep-only-absence")

    def test_mechanism_grounded_passes(self):
        c = dpq.classify_reason(MECHANISM_GROUNDED)
        self.assertTrue(c["admissible"])
        self.assertEqual(c["verdict"], "pass-mechanism-argument")
        self.assertTrue(c["has_mechanism_arg"])

    def test_code_guard_grounded_passes(self):
        c = dpq.classify_reason(CODE_GUARD_GROUNDED)
        self.assertTrue(c["admissible"])
        self.assertEqual(c["verdict"], "pass-code-guard-cited")

    def test_bare_assertion_rejected(self):
        c = dpq.classify_reason(BARE_ASSERTION)
        self.assertFalse(c["admissible"])
        self.assertEqual(c["verdict"], "fail-no-unreachability-proof")

    def test_candidate_keep_exempt(self):
        # A disposition that POINTS AT a real finding is a KEEP not a KILL; the
        # unreachability-proof bar does not apply to it.
        c = dpq.classify_reason(CANDIDATE_KEEP)
        self.assertTrue(c["admissible"])
        self.assertEqual(c["verdict"], "exempt-not-na-claim")

    def test_stray_file_line_does_not_rescue_grep_only(self):
        # The governance reason DOES contain a file:line (the OUT-OF-SCOPE simapp
        # import). That stray citation must NOT rescue the grep-only verdict - the
        # structural unreachability claim itself must be anchored (co-occurrence).
        self.assertIn("app.go:36-37", GREP_ONLY_GOVERNANCE)
        self.assertFalse(dpq.reason_is_terminal_quality(GREP_ONLY_GOVERNANCE))

    def test_proof_strict_env_reader(self):
        old = os.environ.get("AUDITOOOR_DISPOSITION_PROOF_STRICT")
        try:
            for off in ("", "0", "false", "no", "off"):
                os.environ["AUDITOOOR_DISPOSITION_PROOF_STRICT"] = off
                self.assertFalse(dpq.proof_strict_enabled(), off)
            for on in ("1", "true", "yes", "on"):
                os.environ["AUDITOOOR_DISPOSITION_PROOF_STRICT"] = on
                self.assertTrue(dpq.proof_strict_enabled(), on)
        finally:
            os.environ.pop("AUDITOOOR_DISPOSITION_PROOF_STRICT", None)
            if old is not None:
                os.environ["AUDITOOOR_DISPOSITION_PROOF_STRICT"] = old


class _WS:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / ".auditooor").mkdir()

    def jsonl(self, name, rows):
        p = self.dir / ".auditooor" / name
        p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return p


def _with_strict(value):
    """Context-managed env toggle for AUDITOOOR_DISPOSITION_PROOF_STRICT."""
    class _Ctx:
        def __enter__(self):
            self.old = os.environ.get("AUDITOOOR_DISPOSITION_PROOF_STRICT")
            if value is None:
                os.environ.pop("AUDITOOOR_DISPOSITION_PROOF_STRICT", None)
            else:
                os.environ["AUDITOOOR_DISPOSITION_PROOF_STRICT"] = value

        def __exit__(self, *a):
            os.environ.pop("AUDITOOOR_DISPOSITION_PROOF_STRICT", None)
            if self.old is not None:
                os.environ["AUDITOOOR_DISPOSITION_PROOF_STRICT"] = self.old
    return _Ctx()


class TestRubricLoaderIntegration(unittest.TestCase):
    """tools/audit-completeness-check.py::_load_terminal_dispositions."""

    def setUp(self):
        self.acc = _load("acc_disp", _TOOLS / "audit-completeness-check.py")

    def _ws_rubric(self):
        ws = _WS()
        ws.jsonl("rubric_attempt_dispositions.jsonl", [
            {"sentence": "governance vote manip", "reason": GREP_ONLY_GOVERNANCE},
            {"sentence": "theft of gas", "reason": GREP_ONLY_THEFT_OF_GAS},
            {"sentence": "insolvency", "reason": MECHANISM_GROUNDED},
            {"sentence": "over release", "reason": CODE_GUARD_GROUNDED},
        ])
        return ws

    def test_a_grep_only_rejected_strict(self):
        ws = self._ws_rubric()
        with _with_strict("1"):
            d = self.acc._load_terminal_dispositions(
                ws.dir, "rubric_attempt_dispositions.jsonl")
        self.assertNotIn("governance vote manip", d,
                         "grep-only 'no Governor keyword' N-A must be REJECTED strict")
        self.assertNotIn("theft of gas", d,
                         "grep-only theft-of-gas N-A must be REJECTED strict")

    def test_b_mechanism_and_code_guard_pass_strict(self):
        ws = self._ws_rubric()
        with _with_strict("1"):
            d = self.acc._load_terminal_dispositions(
                ws.dir, "rubric_attempt_dispositions.jsonl")
        self.assertIn("insolvency", d,
                      "mechanism-grounded unreachability argument must PASS")
        self.assertIn("over release", d,
                      "code-guard file:line disposition must PASS")

    def test_c_non_strict_byte_identical(self):
        ws = self._ws_rubric()
        with _with_strict(None):
            d = self.acc._load_terminal_dispositions(
                ws.dir, "rubric_attempt_dispositions.jsonl")
        # legacy: all four credited (reason >= 8 chars).
        self.assertEqual(set(d), {"governance vote manip", "theft of gas",
                                  "insolvency", "over release"})


class TestMechanismLoaderIntegration(unittest.TestCase):
    """tools/completeness-matrix-build.py::_load_mechanism_dispositions."""

    def setUp(self):
        self.cmb = _load("cmb_disp", _TOOLS / "completeness-matrix-build.py")

    def _ws_mech(self):
        ws = _WS()
        ws.jsonl("mechanism_dispositions.jsonl", [
            {"mechanism": "governance-vote-manip", "file": "x.go", "line": 10,
             "verdict": "cleared", "reasoning": GREP_ONLY_GOVERNANCE},
            {"mechanism": "reserve-over-release", "file": "reconcile.go", "line": 184,
             "verdict": "refuted", "reasoning": CODE_GUARD_GROUNDED},
        ])
        return ws

    def test_a_grep_only_mechanism_rejected_strict(self):
        ws = self._ws_mech()
        with _with_strict("1"):
            keys = self.cmb._load_mechanism_dispositions(ws.dir)
        self.assertFalse(any(k.startswith("governance-vote-manip::") for k in keys),
                         "grep-only mechanism disposition must be REJECTED strict")

    def test_b_code_guard_mechanism_passes_strict(self):
        ws = self._ws_mech()
        with _with_strict("1"):
            keys = self.cmb._load_mechanism_dispositions(ws.dir)
        self.assertTrue(any(k.startswith("reserve-over-release::") for k in keys),
                        "code-guard mechanism disposition must PASS strict")

    def test_c_non_strict_byte_identical(self):
        ws = self._ws_mech()
        with _with_strict(None):
            keys = self.cmb._load_mechanism_dispositions(ws.dir)
        # legacy: both credited (any row with a mechanism field).
        self.assertEqual(len(keys), 2)
        self.assertTrue(any(k.startswith("governance-vote-manip::") for k in keys))
        self.assertTrue(any(k.startswith("reserve-over-release::") for k in keys))


if __name__ == "__main__":
    unittest.main()
