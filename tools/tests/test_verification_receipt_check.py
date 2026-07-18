#!/usr/bin/env python3
"""Regression for verification-receipt-check.py - the VERIFICATION RECEIPT
VALIDATOR that closes the prose-greening gap on converted load-bearing gates.

Thesis (operator, predmkt driver): a load-bearing gate (impact/scope/severity/
dedup/reachability/permanence) must not be greened by the author's own prose or a
self-applied "<gate>-rebuttal" marker. It greens ONLY on an independent-verification
receipt whose:
  - verifier_lane != author_lane (independence),
  - task_hash is the canonical hash of (gate, claim) AND appears in the dispatch
    log for that verifier lane (anti-forgery: the author does not write the
    dispatch log),
  - claim_hash == the claim the draft asserts NOW (no stale reuse),
  - verdict == CONFIRMED.

Cases: valid-independent-receipt PASS, prose-only-rebuttal FAIL,
self-authored-receipt(author==verifier) FAIL, task-hash-mismatch FAIL,
stale-receipt-for-other-claim FAIL, plus advisory-first WARN default,
anti-forgery forged-no-dispatch FAIL, and rebuttal walk-back."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("vrc", _H.parent / "verification-receipt-check.py")
_m = importlib.util.module_from_spec(_s)
sys.modules["vrc"] = _m
_s.loader.exec_module(_m)

_CLAIM = "Net profit clears $1000 on a 2000-share fill at $0.65 on market YES-BTC-UP"
_OTHER_CLAIM = "Net profit clears $5 on a 10-share fill (a different, earlier claim)"
_STRICT_ENV = "AUDITOOOR_VERIFICATION_DISPATCH_STRICT"


class T(unittest.TestCase):
    def setUp(self):
        # hermetic: neither strict env set unless a test opts in
        for k in (_STRICT_ENV, "AUDITOOOR_L37_STRICT"):
            os.environ.pop(k, None)

    # -- fixtures ----------------------------------------------------------
    def _ws(self):
        return Path(tempfile.mkdtemp())

    def _receipt(self, ws, rid, *, gate="impact", claim=_CLAIM,
                 author="lane-author-01", verifier="lane-verify-99",
                 verdict="CONFIRMED", task_hash=None):
        ch = _m.claim_hash(claim)
        th = task_hash if task_hash is not None else _m.task_hash(gate, ch)
        obj = {
            "schema": "auditooor.verification_receipt.v1",
            "receipt_id": rid,
            "gate_id": gate,
            "claim": claim,
            "claim_hash": ch,
            "task_hash": th,
            "author_lane": author,
            "verifier_lane": verifier,
            "verdict": verdict,
            "evidence": ["asset=YES-BTC-UP resolved via clob:markets", "mid=0.65 (clob book)",
                         "size cap 2000 shares -> net $1040 (computed)"],
            "ts": "2026-07-09T00:00:00Z",
        }
        d = ws / ".auditooor" / "verification_receipts"
        d.mkdir(parents=True, exist_ok=True)
        (d / (rid + ".json")).write_text(json.dumps(obj), encoding="utf-8")
        return obj

    def _dispatch(self, ws, entries):
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "verification_dispatch_log.jsonl"
        with p.open("w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")
        return p

    def _draft(self, ws, body):
        p = ws / "finding.md"
        p.write_text(body, encoding="utf-8")
        return p

    def _bind_entry(self, ws, obj):
        return {"lane_id": obj["verifier_lane"], "task_hash": obj["task_hash"],
                "lane_type": "verify", "workspace": str(ws.resolve())}

    def _check(self, ws, draft, gate="impact", dlog=None):
        return _m.check(ws, draft=draft, gate=gate,
                        dispatch_logs=[dlog] if dlog else None,
                        include_default_dispatch=False)

    def _status(self, r, gate="impact"):
        return [i for i in r["items"] if i["gate"] == gate][0]["status"]

    # -- 1. valid independent receipt PASS ---------------------------------
    def test_valid_independent_receipt_passes(self):
        ws = self._ws()
        obj = self._receipt(ws, "rcpt_ok")
        dlog = self._dispatch(ws, [self._bind_entry(ws, obj)])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_ok -->\n" % _CLAIM))
        r = self._check(ws, draft, dlog=dlog)
        self.assertEqual(r["verdict"], "pass-verification-receipt")
        self.assertEqual(self._status(r), "ok")

    def test_valid_receipt_auto_scan_no_explicit_gate(self):
        ws = self._ws()
        obj = self._receipt(ws, "rcpt_ok")
        dlog = self._dispatch(ws, [self._bind_entry(ws, obj)])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_ok -->\n" % _CLAIM))
        r = _m.check(ws, draft=draft, gate=None, dispatch_logs=[dlog],
                     include_default_dispatch=False)
        self.assertEqual(r["verdict"], "pass-verification-receipt")
        self.assertIn("impact", r["gates_evaluated"])

    # -- 2. prose-only / marker rebuttal FAIL ------------------------------
    def test_prose_only_rebuttal_fails_under_strict(self):
        ws = self._ws()
        draft = self._draft(ws, (
            "# finding\n"
            "## Impact\nThis clears $1000 comfortably.\n"
            "<!-- impact-rebuttal: clears $1000 comfortably per sweep -->\n"))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "fail-verification-missing-receipt")
        self.assertEqual(self._status(r), "receipt-missing")

    def test_prose_only_rebuttal_warns_by_default(self):
        # advisory-first: without strict env it must WARN, not FAIL (byte-compatible)
        ws = self._ws()
        draft = self._draft(ws, (
            "# finding\n<!-- impact-rebuttal: clears $1000 comfortably -->\n"))
        r = self._check(ws, draft)
        self.assertEqual(r["verdict"], "warn-verification-missing-receipt")
        self.assertEqual(self._status(r), "receipt-missing")

    # -- 3. self-authored receipt (author == verifier) FAIL ----------------
    def test_self_authored_receipt_fails(self):
        ws = self._ws()
        obj = self._receipt(ws, "rcpt_self", author="lane-solo", verifier="lane-solo")
        dlog = self._dispatch(ws, [self._bind_entry(ws, obj)])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_self -->\n" % _CLAIM))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft, dlog=dlog)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "fail-verification-missing-receipt")
        self.assertEqual(self._status(r), "self-authored-receipt")

    # -- 4. task-hash mismatch FAIL ----------------------------------------
    def test_task_hash_mismatch_fails(self):
        ws = self._ws()
        # correct claim (stale check passes) but a fudged/forged task_hash token
        obj = self._receipt(ws, "rcpt_badhash", task_hash="0" * 64)
        dlog = self._dispatch(ws, [{"lane_id": obj["verifier_lane"],
                                    "task_hash": "0" * 64, "workspace": str(ws.resolve())}])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_badhash -->\n" % _CLAIM))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft, dlog=dlog)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "fail-verification-missing-receipt")
        self.assertEqual(self._status(r), "task-hash-mismatch")

    # -- 5. stale receipt for another claim FAIL ---------------------------
    def test_stale_receipt_for_other_claim_fails(self):
        ws = self._ws()
        # receipt is internally consistent but about _OTHER_CLAIM
        obj = self._receipt(ws, "rcpt_stale", claim=_OTHER_CLAIM)
        dlog = self._dispatch(ws, [self._bind_entry(ws, obj)])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"     # draft now asserts _CLAIM
            "<!-- verification-receipt: impact=rcpt_stale -->\n" % _CLAIM))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft, dlog=dlog)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "fail-verification-missing-receipt")
        self.assertEqual(self._status(r), "stale-receipt-for-other-claim")

    # -- anti-forgery: correct hash but no real dispatch -------------------
    def test_forged_receipt_no_dispatch_fails(self):
        ws = self._ws()
        obj = self._receipt(ws, "rcpt_forged")            # canonical task_hash...
        dlog = self._dispatch(ws, [])                     # ...but NO dispatch entry
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_forged -->\n" % _CLAIM))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft, dlog=dlog)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "fail-verification-missing-receipt")
        self.assertEqual(self._status(r), "forged-no-dispatch")

    # -- verdict REFUTED does not green ------------------------------------
    def test_refuted_verdict_fails(self):
        ws = self._ws()
        obj = self._receipt(ws, "rcpt_refuted", verdict="REFUTED")
        dlog = self._dispatch(ws, [self._bind_entry(ws, obj)])
        draft = self._draft(ws, (
            "# finding\n"
            "<!-- verification-claim: impact=%s -->\n"
            "<!-- verification-receipt: impact=rcpt_refuted -->\n" % _CLAIM))
        r = self._check(ws, draft, dlog=dlog)
        self.assertEqual(self._status(r), "verdict-not-confirmed")

    # -- receipt file referenced but absent --------------------------------
    def test_missing_receipt_file_flagged(self):
        ws = self._ws()
        dlog = self._dispatch(ws, [])
        draft = self._draft(ws, (
            "# finding\n<!-- verification-receipt: impact=rcpt_nope -->\n"))
        r = self._check(ws, draft, dlog=dlog)
        self.assertEqual(self._status(r), "receipt-file-missing")

    # -- rebuttal walk-back clears the gate --------------------------------
    def test_receipt_rebuttal_marker_clears(self):
        ws = self._ws()
        draft = self._draft(ws, (
            "# finding\n<!-- impact-rebuttal: prose only -->\n"
            "<!-- verification-receipt-rebuttal: legacy finding, operator-acked -->\n"))
        os.environ[_STRICT_ENV] = "1"
        try:
            r = self._check(ws, draft)
        finally:
            os.environ.pop(_STRICT_ENV, None)
        self.assertEqual(r["verdict"], "pass-verification-receipt")
        self.assertEqual(self._status(r), "rebutted")

    # -- no converted gate in play -> pass (advisory scope) ----------------
    def test_no_gate_in_play_passes(self):
        ws = self._ws()
        draft = self._draft(ws, "# finding\nsome narrative, no load-bearing markers\n")
        r = _m.check(ws, draft=draft, gate=None, include_default_dispatch=False)
        self.assertEqual(r["verdict"], "pass-verification-receipt")
        self.assertEqual(r["gates_evaluated"], [])

    # -- determinism of the binding primitives -----------------------------
    def test_task_hash_is_deterministic_and_claim_bound(self):
        ch = _m.claim_hash(_CLAIM)
        self.assertEqual(_m.task_hash("impact", ch), _m.task_hash("impact", ch))
        self.assertNotEqual(_m.task_hash("impact", ch),
                            _m.task_hash("impact", _m.claim_hash(_OTHER_CLAIM)))
        self.assertNotEqual(_m.task_hash("impact", ch), _m.task_hash("scope", ch))

    # -- whitespace-normalized claim still matches -------------------------
    def test_claim_hash_whitespace_insensitive(self):
        self.assertEqual(_m.claim_hash("a  b\n c"), _m.claim_hash("a b c"))


if __name__ == "__main__":
    unittest.main()
