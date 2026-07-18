#!/usr/bin/env python3
"""Regression (predmkt lesson 2026-07-09): a driving agent over-claimed a prediction-markets
redeem slippage sandwich as "clears $1000 comfortably", citing a Node.js "sweep" artifact
that does NOT exist in the workspace. Ground truth: loss asset = GBYTE (factory.oscript:58),
victim loss 26,341,593 bytes, 1 GBYTE = 1e9 bytes @ ~$5 => ~$0.13 - ~4 orders of magnitude
UNDER the program's USD-1000 fund-loss floor. This gate makes a HIGH/CRITICAL fund-loss
finding on a floor-declaring program carry a 4-part source-anchored USD derivation and flags
a cited evidence artifact absent from the workspace tree.

Positive case = the reconstructed over-claim MUST be flagged (warn default / fail strict).
Negative case = a properly-derived finding (asset file:line + unit->USD + market-size +
absolute $ vs floor) MUST pass. Plus N/A (no floor), rebuttal, tier-gate, and floor-parse."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "ausd", _HERE.parent / "absolute-usd-derivation-check.py")
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

# Obyte-like program_rules.json: the fund-loss floor lives ONLY as free text inside
# invalid_impact_conditions (no dedicated key), exactly as obyte ships it.
_OBYTE_LIKE_RULES = {
    "program": "Obyte-like",
    "invalid_impact_conditions": [
        "Direct financial damage where total <= 200% of the attacker's total expense",
        "Any lost/frozen-funds impact below USD 1000 (fund-loss floor)",
        "Basic economic / governance attacks (51%, frontrunning, sandwich), Sybil",
    ],
}
_NO_FLOOR_RULES = {"program": "NoFloor", "invalid_impact_conditions": [
    "Best-practice recommendations, feature requests"]}

_PREDMKT_FIXTURE = _HERE / "fixtures" / "predmkt_overclaim.md"

# A properly-derived High fund-loss finding: all four parts, source-anchored, consistent.
_COMPLETE_DRAFT = """# Reserve drain in prediction-markets AA leads to theft of user funds

Severity: High

## Summary
An attacker drains the reserve pool of the prediction-markets AA on a manipulated price.

## Impact
The loss is denominated in the reserve asset GBYTE (factory.oscript:58 default reserve_asset 'base').
1 GBYTE = 1e9 bytes; GBYTE ~ $5 (coingecko spot price, as of 2026-07-09).
At the pool's current TVL of 2000 GBYTE, a full drain moves 2,000,000,000,000 bytes to the attacker.
The derived loss = 2000 GBYTE = $10,000, which is above the $1000 fund-loss floor.

## What the PoC proves
The PoC drives the drain end-to-end and asserts the attacker balance rises by 2000 GBYTE.
"""

# Task 1 (hard-wrap): a properly-derived High fund-loss finding written as markdown BULLETS
# where the asset-identity bullet HARD-WRAPS across two physical lines - the asset keyword
# ("reserve asset") lands on line 1 and the file:line citation ("factory.oscript:58") on the
# continuation line, with NEITHER physical line carrying both. Under the old per-physical-line
# scan this false-FAILED; with logical-bullet joining it must PASS (even under strict).
_HARDWRAP_BULLET_DRAFT = """# Reserve drain in prediction-markets AA leads to theft of user funds

Severity: High

## Impact

- (a) ASSET-IDENTITY: the loss is denominated in the reserve asset GBYTE, fixed at
  factory.oscript:58 in the default configuration.
- (b) UNIT->USD: 1 GBYTE = 1e9 bytes; GBYTE ~ $5 (coingecko spot price as of 2026-07-09).
- (c) MARKET-SIZE: at the pool's current TVL of 2000 GBYTE, a full drain moves
  2,000,000,000,000 bytes to the attacker.
- (d) ABSOLUTE $ vs FLOOR: derived loss = 2000 GBYTE = $10,000, which is above the $1000 fund-loss floor.

## What the PoC proves

The PoC drives the drain end-to-end and asserts the attacker balance rises by 2000 GBYTE.
"""

# A Solidity High theft finding with NO program floor -> gate is N/A.
_SOLIDITY_NO_FLOOR_DRAFT = """# Reentrancy in Vault leads to theft of user funds

Severity: High

## Summary
A reentrancy in Vault.withdraw (Vault.sol:142) lets an attacker drain user funds.

## Impact
Theft of user funds; the attacker withdraws more than their balance.
"""


class TestAbsoluteUsdDerivationCheck(unittest.TestCase):
    def _ws(self, rules: dict | None, extra_files: dict[str, str] | None = None) -> Path:
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        if rules is not None:
            (ws / ".auditooor" / "program_rules.json").write_text(json.dumps(rules))
        for rel, body in (extra_files or {}).items():
            p = ws / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return ws

    def _draft(self, ws: Path, body: str, name: str = "f.md") -> Path:
        fd = ws / "submissions" / "paste_ready" / "f"
        fd.mkdir(parents=True, exist_ok=True)
        p = fd / name
        p.write_text(body)
        return p

    # --- floor discovery -----------------------------------------------------
    def test_parse_floor_from_invalid_impact_conditions(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        floor, src = _m.parse_floor(_OBYTE_LIKE_RULES, ws)
        self.assertEqual(floor, 1000)
        self.assertIn("invalid_impact_conditions", src)

    def test_parse_floor_none_when_absent(self):
        ws = self._ws(_NO_FLOOR_RULES)
        floor, _src = _m.parse_floor(_NO_FLOOR_RULES, ws)
        self.assertIsNone(floor)

    def test_reward_tier_maxima_not_mistaken_for_floor(self):
        # SEVERITY.md "up to $X" reward maxima carry no floor keyword -> not a floor.
        ws = self._ws(None, {"SEVERITY.md":
            "| Critical | up to $100,000 |\n| Low | up to $1,000 |\n"})
        floor, _src = _m.parse_floor(None, ws)
        self.assertIsNone(floor)

    # --- POSITIVE: the predmkt over-claim MUST be flagged --------------------
    def test_predmkt_overclaim_warns_by_default(self):
        ws = self._ws(_OBYTE_LIKE_RULES)  # no redeem-slippage-sweep.js in ws
        out = _m.check(ws, _PREDMKT_FIXTURE, "auto", strict=False)
        self.assertEqual(out["verdict"], "warn-derivation-incomplete")
        self.assertTrue(out["trigger"]["tier_high_plus"])
        self.assertTrue(out["trigger"]["floor_declared"])
        self.assertTrue(out["trigger"]["fund_loss"])
        # asset-identity, unit->USD and market-size are all missing.
        self.assertFalse(out["derivation_parts"]["asset_identity"])
        self.assertFalse(out["derivation_parts"]["unit_to_usd"])
        self.assertFalse(out["derivation_parts"]["market_size"])
        # the cited Node.js sweep artifact is absent from the workspace -> flagged.
        self.assertIn("redeem-slippage-sweep.js", out["missing_artifacts"])

    def test_predmkt_overclaim_fails_under_strict(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        out = _m.check(ws, _PREDMKT_FIXTURE, "auto", strict=True)
        self.assertEqual(out["verdict"], "fail-derivation-incomplete")

    def test_predmkt_cli_advisory_first_rc(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        # default: advisory (rc 0)
        rc = _m.main(["--workspace", str(ws), "--draft", str(_PREDMKT_FIXTURE), "--json"])
        self.assertEqual(rc, 0)
        # --strict: hard block (rc 1)
        rc_strict = _m.main(["--workspace", str(ws), "--draft", str(_PREDMKT_FIXTURE),
                             "--strict", "--json"])
        self.assertEqual(rc_strict, 1)

    def test_cli_accepts_titlecase_severity(self):
        # Regression: pre-submit-check.sh passes SEVERITY_ARG="High" (title-case). The CLI
        # must accept it (not argparse-reject), else Check #148 silently no-ops (rc=2).
        ws = self._ws(_OBYTE_LIKE_RULES)
        rc = _m.main(["--workspace", str(ws), "--draft", str(_PREDMKT_FIXTURE),
                      "--severity", "High", "--json"])
        self.assertEqual(rc, 0)  # advisory default
        # and the derivation IS evaluated (High tier triggers), not skipped as N/A.
        out = _m.check(ws, _PREDMKT_FIXTURE, "High", strict=False)
        self.assertEqual(out["verdict"], "warn-derivation-incomplete")

    def test_env_strict_flips_rc(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        os.environ["AUDITOOOR_ABSOLUTE_USD_STRICT"] = "1"
        try:
            rc = _m.main(["--workspace", str(ws), "--draft", str(_PREDMKT_FIXTURE),
                          "--json"])
        finally:
            del os.environ["AUDITOOOR_ABSOLUTE_USD_STRICT"]
        self.assertEqual(rc, 1)

    # --- NEGATIVE: a properly-derived finding MUST pass ----------------------
    def test_complete_derivation_passes(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._draft(ws, _COMPLETE_DRAFT)
        out = _m.check(ws, md, "auto", strict=True)  # even under strict
        self.assertEqual(out["verdict"], "pass-derivation-complete", out)
        self.assertEqual(out["missing_parts"], [])
        self.assertIsNone(out["magnitude_flag"])
        self.assertEqual(out["missing_artifacts"], [])

    # --- N/A: no floor declared ---------------------------------------------
    def test_no_floor_is_not_applicable(self):
        ws = self._ws(_NO_FLOOR_RULES)
        md = self._draft(ws, _SOLIDITY_NO_FLOOR_DRAFT)
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "pass-not-applicable")

    def test_no_rules_file_is_not_applicable(self):
        ws = Path(tempfile.mkdtemp())
        md = ws / "f.md"
        md.write_text(_SOLIDITY_NO_FLOOR_DRAFT)
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "pass-not-applicable")

    # --- tier gate: Medium fund-loss on a floor ws is N/A --------------------
    def test_medium_tier_is_not_applicable(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._draft(ws, _PREDMKT_FIXTURE.read_text().replace(
            "Severity: High", "Severity: Medium"))
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "pass-not-applicable")

    # --- Task 1: a hard-wrapped bullet derivation PASSES; predmkt STILL fails ----
    def test_hardwrapped_bullet_derivation_passes_under_strict(self):
        # asset keyword on line 1, file:line on the continuation line -> only the LOGICAL
        # bullet carries both. Old per-physical-line scan false-FAILED; must PASS now.
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._draft(ws, _HARDWRAP_BULLET_DRAFT)
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "pass-derivation-complete", out)
        self.assertTrue(out["derivation_parts"]["asset_identity"])
        self.assertEqual(out["missing_parts"], [])
        self.assertIsNone(out["magnitude_flag"])
        self.assertEqual(out["missing_artifacts"], [])

    def test_hardwrap_asset_identity_needs_the_logical_join(self):
        # Prove the bullet join is load-bearing: neither physical line of the (a) bullet
        # carries BOTH the asset keyword and a file:line, so per-line scanning would fail.
        line1 = ("- (a) ASSET-IDENTITY: the loss is denominated in the reserve asset "
                 "GBYTE, fixed at")
        line2 = "  factory.oscript:58 in the default configuration."
        self.assertTrue(_m.ASSET_KW_RE.search(line1))
        self.assertFalse(_m.SOURCE_CITED_RE.search(line1))       # no file:line on line 1
        self.assertTrue(_m.SOURCE_CITED_RE.search(line2))
        self.assertFalse(_m.ASSET_KW_RE.search(line2))           # no asset kw on line 2
        # ... but the joined logical unit carries both.
        units = _m._logical_units(line1 + "\n" + line2)
        self.assertTrue(any(_m.ASSET_KW_RE.search(u) and _m.SOURCE_CITED_RE.search(u)
                            for u in units))

    def test_predmkt_prose_still_fails_after_hardwrap_fix(self):
        # The logical-unit join must NOT collapse the predmkt prose paragraphs into a
        # single scannable block (that would false-PASS market_size on the "$1000"+"victim"
        # paragraph). The bare assertion still fails.
        ws = self._ws(_OBYTE_LIKE_RULES)
        out = _m.check(ws, _PREDMKT_FIXTURE, "auto", strict=True)
        self.assertEqual(out["verdict"], "fail-derivation-incomplete")
        self.assertFalse(out["derivation_parts"]["asset_identity"])
        self.assertFalse(out["derivation_parts"]["market_size"])

    # --- Task 3: rebuttal must reference a valid verification receipt ------------
    def _bare_rebuttal_draft(self, ws):
        body = _PREDMKT_FIXTURE.read_text() + \
            "\n<!-- absolute-usd-rebuttal: operator confirmed impact is below-floor / OOS -->\n"
        return self._draft(ws, body)

    def test_bare_rebuttal_warns_by_default(self):
        # byte-compatible-ish: a bare prose rebuttal no longer greens; it WARNs (advisory).
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._bare_rebuttal_draft(ws)
        out = _m.check(ws, md, "auto", strict=False)
        self.assertEqual(out["verdict"], "warn-rebuttal-unverified")
        self.assertFalse(out["receipt_validated"])

    def test_bare_rebuttal_fails_under_strict(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._bare_rebuttal_draft(ws)
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "fail-rebuttal-unverified")

    def test_bare_rebuttal_fails_under_receipt_strict_env(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        md = self._bare_rebuttal_draft(ws)
        os.environ["AUDITOOOR_VERIFICATION_RECEIPT_STRICT"] = "1"
        try:
            rc = _m.main(["--workspace", str(ws), "--draft", str(md), "--json"])
        finally:
            del os.environ["AUDITOOOR_VERIFICATION_RECEIPT_STRICT"]
        self.assertEqual(rc, 1)

    def _make_absolute_usd_receipt(self, ws, rid, *, author="lane-author-01",
                                   verifier="lane-verify-99", verdict="CONFIRMED"):
        """Mint a valid gate=absolute-usd receipt + a binding dispatch-log entry, reusing
        verification-receipt-check.py's own hashing (single source of truth)."""
        vrc = _m._load_module("verification-receipt-check.py", "_test_vrc")
        self.assertIsNotNone(vrc)
        claim = "Absolute redeem-drain loss = $10,000 vs the $1000 fund-loss floor"
        ch = vrc.claim_hash(claim)
        th = vrc.task_hash("absolute-usd", ch)
        obj = {
            "schema": "auditooor.verification_receipt.v1",
            "receipt_id": rid, "gate_id": "absolute-usd", "claim": claim,
            "claim_hash": ch, "task_hash": th,
            "author_lane": author, "verifier_lane": verifier, "verdict": verdict,
            "evidence": ["asset=GBYTE (factory.oscript:58)", "1 GBYTE=1e9 bytes @ $5",
                         "TVL 2000 GBYTE -> $10,000 (recomputed)"],
        }
        rdir = ws / ".auditooor" / "verification_receipts"
        rdir.mkdir(parents=True, exist_ok=True)
        (rdir / (rid + ".json")).write_text(json.dumps(obj))
        dlog = ws / ".auditooor" / "verification_dispatch_log.jsonl"
        dlog.write_text(json.dumps({"lane_id": verifier, "task_hash": th,
                                    "lane_type": "verify", "workspace": str(ws.resolve())})
                        + "\n")
        return obj

    def test_receipt_backed_rebuttal_greens(self):
        ws = self._ws(_OBYTE_LIKE_RULES)
        self._make_absolute_usd_receipt(ws, "rcpt_ausd_ok")
        body = _PREDMKT_FIXTURE.read_text() + \
            "\n<!-- absolute-usd-rebuttal: receipt:rcpt_ausd_ok operator confirmed via independent verify -->\n"
        md = self._draft(ws, body)
        out = _m.check(ws, md, "auto", strict=True)  # greens even under strict
        self.assertEqual(out["verdict"], "ok-rebuttal", out)
        self.assertTrue(out["receipt_validated"])
        self.assertEqual(out["receipt_id"], "rcpt_ausd_ok")

    def test_self_authored_receipt_rebuttal_does_not_green(self):
        # a hand-forged self-authored receipt (author==verifier) must NOT validate.
        ws = self._ws(_OBYTE_LIKE_RULES)
        self._make_absolute_usd_receipt(ws, "rcpt_ausd_self",
                                        author="lane-solo", verifier="lane-solo")
        body = _PREDMKT_FIXTURE.read_text() + \
            "\n<!-- absolute-usd-rebuttal: receipt:rcpt_ausd_self self-verified -->\n"
        md = self._draft(ws, body)
        out = _m.check(ws, md, "auto", strict=True)
        self.assertEqual(out["verdict"], "fail-rebuttal-unverified")
        self.assertFalse(out["receipt_validated"])


class TestBriefGateLabelBinding(unittest.TestCase):
    """Task 2: the gate's required-derivation labels come from the shared lib constant."""

    def test_gate_labels_come_from_shared_lib(self):
        from lib import dollar_impact_labels as dil
        self.assertEqual(tuple(_m.REQUIRED_DERIVATION_LABELS),
                         tuple(dil.DOLLAR_IMPACT_DERIVATION_LABELS))


if __name__ == "__main__":
    unittest.main()
