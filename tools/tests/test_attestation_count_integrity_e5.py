#!/usr/bin/env python3
"""test_attestation_count_integrity_e5.py

E5 (enforcement id22, 2026-07-03): attestation-count integrity + KILL
disposition-distinctness signal.

Two credit-leaks the verbatim attestation gate never caught (operator-caught on
NUVA):
  (1) a step attestation payload's free-text `summary` claims "N obligations, all
      resolved" whose N does NOT match the recomputed hacker_question_obligations
      total (NUVA step-0f claimed 647, artifact holds 1147);
  (2) a KILL-only verdict cluster (hacker_question_verdicts/*.json) that is
      ~100% KILL with a large fraction of EMPTY `reason` fields is not a terminal
      adjudication (NUVA: 264/575 reasonless KILLs).

The signal is ADVISORY-FIRST: WARN-pass unless the DEDICATED env
AUDITOOOR_ATTESTATION_COUNT_STRICT is set. It is deliberately NOT subsumed by the
global AUDITOOOR_L37_STRICT umbrella, so `make audit-complete [STRICT=1]` stays
byte-identical and never retro-reds a parked audit.

This test builds a synthetic workspace (both a mismatch + a reasonless KILL
cluster, and a clean control) and pins: advisory WARN-pass with env unset,
hard-FAIL under the dedicated env, byte-parity (env-unset always ok=True), and
that a clean workspace passes even under strict. Also pins the source wiring in
both audit-completeness-check.py and audit-done-guard.py.
"""
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_ACC_SRC = (_TOOLS / "audit-completeness-check.py").read_text(
    encoding="utf-8", errors="replace")
_DONE_SRC = (_TOOLS / "audit-done-guard.py").read_text(
    encoding="utf-8", errors="replace")

_ENV = "AUDITOOOR_ATTESTATION_COUNT_STRICT"
_L37 = "AUDITOOOR_L37_STRICT"


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_e5", str(_TOOLS / "audit-completeness-check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_e5"] = m  # dataclass needs the module registered
    spec.loader.exec_module(m)
    return m


def _mk_ws(tmp: Path, *, claimed_obligations, actual_rows,
           kill_total, kill_empty_reason) -> Path:
    ad = tmp / ".auditooor"
    (ad / "attestations").mkdir(parents=True, exist_ok=True)
    (ad / "hacker_question_verdicts").mkdir(parents=True, exist_ok=True)
    # obligations artifact
    with (ad / "hacker_question_obligations.jsonl").open("w") as fh:
        for i in range(actual_rows):
            fh.write(json.dumps({"obligation_id": f"o{i}", "state": "killed"}) + "\n")
    # step attestation payload with a free-text obligation-count claim
    if claimed_obligations is not None:
        (ad / "attestations" / "step-0f.json").write_text(json.dumps({
            "schema": "auditooor.attestation.step-0f.v1", "step": "0f",
            "summary": (f"Per-fn ranked hacker-question hunt ran "
                        f"({claimed_obligations} obligations, all resolved)."),
        }))
    # KILL verdict cluster: `kill_empty_reason` of them have an empty reason
    for i in range(kill_total):
        reason = "" if i < kill_empty_reason else (
            f"attack-class N/A at src/x.go:{i}: pure helper, no Msg handler surface")
        (ad / "hacker_question_verdicts" / f"hq_{i:04d}.json").write_text(json.dumps({
            "question_id": f"q{i}", "verdict": "KILL", "reason": reason}))
    return tmp


class TestE5AttestationCountIntegrity(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop(_ENV, None)
        self._saved_l37 = os.environ.pop(_L37, None)
        self.acc = _load_acc()

    def tearDown(self):
        for k, v in ((_ENV, self._saved), (_L37, self._saved_l37)):
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # -- functional: the NUVA-shaped defective workspace -------------------
    def _defective(self, tmp):
        return _mk_ws(Path(tmp), claimed_obligations=647, actual_rows=1147,
                      kill_total=575, kill_empty_reason=264)

    # -- 4-case default-ON-under-L37 matrix --------------------------------
    def test_case_non_strict_advisory_env_unset_no_l37(self):
        # env unset AND no L37 -> advisory WARN-pass (bare / library caller).
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            os.environ.pop(_ENV, None)
            os.environ.pop(_L37, None)
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertTrue(r.ok, "env-unset + no L37 MUST WARN-pass (advisory-first)")
            self.assertTrue(r.reason.startswith("WARN:"), "advisory reason must be a WARN")
            # both defects surfaced in the advisory even though ok=True
            self.assertTrue(r.detail["attestation_count_mismatches"])
            self.assertTrue(r.detail["kill_cluster"]["flagged"])
            self.assertFalse(r.detail["strict"])

    def test_case_default_under_l37_enforced(self):
        # env UNSET but AUDITOOOR_L37_STRICT=1 -> NEW default: ENFORCED, hard-FAIL.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            os.environ.pop(_ENV, None)
            os.environ[_L37] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertFalse(r.ok, "env-unset under L37 must ENFORCE (default-ON)")
            self.assertTrue(r.detail["strict"])
            self.assertIn("attestation-count-mismatch", r.reason)
            self.assertIn("KILL-only-no-reason", r.reason)

    def test_case_opt_out_env_zero_even_under_l37(self):
        # explicit AUDITOOOR_ATTESTATION_COUNT_STRICT=0 -> DISABLED escape hatch even
        # under L37: advisory WARN-pass.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            os.environ[_ENV] = "0"
            os.environ[_L37] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertTrue(r.ok, "env=0 is an explicit opt-out even under L37")
            self.assertTrue(r.reason.startswith("WARN:"))
            self.assertFalse(r.detail["strict"])

    def test_case_explicit_on_env_one(self):
        # explicit opt-in -> ENFORCED (no L37 needed), hard-FAIL on the defect.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            os.environ[_ENV] = "1"
            os.environ.pop(_L37, None)
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertFalse(r.ok, "strict MUST FAIL on a count mismatch + reasonless KILL bucket")
            self.assertTrue(r.detail["strict"])
            self.assertIn("attestation-count-mismatch", r.reason)
            self.assertIn("KILL-only-no-reason", r.reason)

    def test_count_recomputed_from_artifact(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertEqual(r.detail["recomputed_obligation_rows"], 1147)
            mm = r.detail["attestation_count_mismatches"]
            self.assertEqual(mm[0]["claimed"], 647)

    def test_clean_ws_passes_even_strict(self):
        # matching count + KILL cluster with per-row reasons -> genuine pass
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_ws(Path(tmp), claimed_obligations=1147, actual_rows=1147,
                        kill_total=575, kill_empty_reason=0)
            os.environ[_ENV] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertTrue(r.ok, "matching count + reasoned KILLs must pass under strict")
            self.assertFalse(r.detail["attestation_count_mismatches"])
            self.assertFalse(r.detail["kill_cluster"]["flagged"])

    def test_no_debt_ws_passes(self):
        # no attestation claim + no verdict cluster -> nothing to gate
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_ws(Path(tmp), claimed_obligations=None, actual_rows=0,
                        kill_total=0, kill_empty_reason=0)
            os.environ[_ENV] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertTrue(r.ok, "empty workspace must pass (no debt to gate)")

    def test_small_kill_cluster_not_flagged(self):
        # a below-threshold KILL cluster with empty reasons is noise, not a bucket
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_ws(Path(tmp), claimed_obligations=5, actual_rows=5,
                        kill_total=5, kill_empty_reason=5)
            os.environ[_ENV] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertFalse(r.detail["kill_cluster"]["flagged"],
                             "a <10-KILL cluster is below the systemic-bucket floor")

    # -- registration + byte-parity ---------------------------------------
    def test_signal_registered_after_hacker_questions_resolved(self):
        names = [s for s, _ in self.acc._SIGNAL_ORDER]
        self.assertIn("attestation-count-integrity", names)
        self.assertEqual(
            names.index("attestation-count-integrity"),
            names.index("hacker-questions-resolved") + 1,
            "E5 signal must sit right after hacker-questions-resolved")

    def test_non_strict_never_adds_a_failure(self):
        # Advisory contract for a bare/library caller: env unset AND no L37 -> the
        # signal is always ok=True, so it can never change the top-level verdict.
        import tempfile
        os.environ.pop(_ENV, None)
        os.environ.pop(_L37, None)
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._defective(tmp)
            self.assertTrue(self.acc.check_attestation_count_integrity(ws).ok)

    # -- source wiring pins ------------------------------------------------
    def test_default_on_predicate_wiring(self):
        # DEFAULT-ON graduation: the strict decision delegates to the shared
        # _gate_default_on_strict() over the dedicated env - default-ON under the
        # L37 umbrella with a per-gate opt-out. It must NOT use _l37_gate_strict /
        # _all_axes_strict directly (those would also enable on unrelated L37_<X>).
        i = _ACC_SRC.find("def check_attestation_count_integrity")
        seg = _ACC_SRC[i:i + 1700]
        self.assertIn(_ENV, seg)
        self.assertIn("_gate_default_on_strict", seg)
        self.assertNotIn("_l37_gate_strict", seg)
        self.assertNotIn("_all_axes_strict", seg)
        # the shared helper reads L37 as the default umbrella + honors the opt-out
        h = _ACC_SRC.find("def _gate_default_on_strict")
        self.assertGreater(h, 0)
        hseg = _ACC_SRC[h:h + 1400]
        self.assertIn("AUDITOOOR_L37_STRICT", hseg)
        self.assertIn('("0", "false", "no")', hseg)

    def test_done_guard_default_on_wired(self):
        self.assertIn("attestation_count_integrity_advisory", _DONE_SRC,
                      "done-guard must attach a read-only E5 advisory")
        self.assertIn(_ENV, _DONE_SRC,
                      "done-guard hard-block must reference the dedicated env")
        self.assertIn("attestation-count-integrity FAIL (STRICT)", _DONE_SRC)
        # reuses the completeness-check helper (no logic fork) for BOTH the check
        # and the default-ON predicate
        self.assertIn("check_attestation_count_integrity", _DONE_SRC)
        self.assertIn('_mca._gate_default_on_strict(', _DONE_SRC)

    def test_syntax_ok(self):
        import ast
        ast.parse(_ACC_SRC)
        ast.parse(_DONE_SRC)


if __name__ == "__main__":
    unittest.main()


class TestE5CorpusFuelExclusion(unittest.TestCase):
    """2026-07-03: the mined-findings-hunter-bridge appended 500 mined-corpus leads
    (question_source=mined-finding, fake fn, artifact file) into the per-fn obligations
    file, fabricating a 647-vs-1147 attestation mismatch. The per-fn attestation
    denominator must EXCLUDE corpus-fuel (it stays accountable under conversion-throughput)."""

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in (_ENV, _L37)}
        self.acc = _load_acc()

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def _mk_mixed(self, tmp, *, genuine, corpus_fuel, claimed):
        ad = Path(tmp) / ".auditooor"
        (ad / "attestations").mkdir(parents=True, exist_ok=True)
        (ad / "hacker_question_verdicts").mkdir(parents=True, exist_ok=True)
        with (ad / "hacker_question_obligations.jsonl").open("w") as fh:
            for i in range(genuine):
                fh.write(json.dumps({"obligation_id": f"g{i}", "state": "killed",
                                     "question_source": "per-fn",
                                     "file": "/ws/src/vault/keeper/x.go",
                                     "function_name": "DoThing"}) + "\n")
            for i in range(corpus_fuel):
                fh.write(json.dumps({"obligation_id": f"m{i}", "state": "open",
                                     "question_source": "mined-finding",
                                     "file": "<workspace>/.auditooor/mined_findings_hunter_bridge.json",
                                     "function_name": "mined_findings_hunter_bridge"}) + "\n")
        (ad / "attestations" / "step-0f.json").write_text(json.dumps({
            "schema": "auditooor.attestation.step-0f.v1", "step": "0f",
            "summary": f"Per-fn ranked hacker-question hunt ran ({claimed} obligations, all resolved)."}))
        return Path(tmp)

    def test_corpus_fuel_excluded_from_per_fn_recompute(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            # 647 genuine per-fn + 500 corpus-fuel = 1147 rows; attestation claims 647.
            ws = self._mk_mixed(tmp, genuine=647, corpus_fuel=500, claimed=647)
            # classifier: 500 corpus-fuel identified, 647 genuine per-fn remain.
            self.assertEqual(len(self.acc._read_obligations_jsonl(ws)), 1147)
            self.assertEqual(len(self.acc._read_per_fn_obligations_jsonl(ws)), 647)
            os.environ[_ENV] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertEqual(r.detail["recomputed_obligation_rows"], 647,
                             "per-fn recompute must exclude the 500 corpus-fuel leads")
            self.assertEqual(len(r.detail["attestation_count_mismatches"]), 0,
                             "647 claim == 647 genuine per-fn -> NO mismatch")

    def test_genuine_mismatch_still_caught(self):
        # a REAL under-attestation (claim 100, but 647 genuine per-fn) is still flagged.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._mk_mixed(tmp, genuine=647, corpus_fuel=500, claimed=100)
            os.environ[_ENV] = "1"
            r = self.acc.check_attestation_count_integrity(ws)
            self.assertEqual(r.detail["recomputed_obligation_rows"], 647)
            self.assertTrue(r.detail["attestation_count_mismatches"],
                            "100 != 647 genuine per-fn -> mismatch still caught (fail-closed)")


if __name__ == "__main__":
    unittest.main()


class TestVendoredOOSExclusion(unittest.TestCase):
    """2026-07-04: vendored-dependency obligations (/go/pkg/mod/.../baseapp.go) are OOS -
    excluded from the HACKER-Q-RESOLUTION denominator but KEPT in the ATTESTATION-COUNT
    denominator (the step-0f claim counted them). Two distinct denominators."""

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in (_ENV, _L37)}
        self.acc = _load_acc()

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def test_vendored_split_denominators(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            ad = Path(tmp) / ".auditooor"
            ad.mkdir(parents=True)
            with (ad / "hacker_question_obligations.jsonl").open("w") as fh:
                for i in range(575):
                    fh.write(json.dumps({"obligation_id": f"g{i}", "question_source": "per-fn",
                                         "file": "/ws/src/vault/keeper/x.go", "function_name": "F"}) + "\n")
                for i in range(72):  # vendored cosmos-sdk baseapp - OOS
                    fh.write(json.dumps({"obligation_id": f"v{i}", "question_source": "per-fn",
                                         "file": "/Users/x/go/pkg/mod/github.com/cosmos/cosmos-sdk@v0.50/baseapp/baseapp.go",
                                         "function_name": "AnteHandler"}) + "\n")
                for i in range(500):  # mined corpus-fuel
                    fh.write(json.dumps({"obligation_id": f"m{i}", "question_source": "mined-finding",
                                         "file": "<workspace>/.auditooor/mined_findings_hunter_bridge.json",
                                         "function_name": "mined_findings_hunter_bridge"}) + "\n")
            ws = Path(tmp)
            # attestation denom keeps vendored: 575 + 72 = 647 (corpus-fuel excluded).
            self.assertEqual(len(self.acc._read_per_fn_obligations_jsonl(ws)), 647)
            # hacker-Q denom also drops vendored: 575.
            self.assertEqual(len(self.acc._read_inscope_per_fn_obligations_jsonl(ws)), 575)
            # a genuine in-scope src/ file is never dropped by the vendored check.
            self.assertFalse(self.acc._is_oos_vendored_obligation({"file": "/ws/src/vault/keeper/x.go"}))
            self.assertTrue(self.acc._is_oos_vendored_obligation({"file": "/x/go/pkg/mod/foo/baseapp.go"}))


if __name__ == "__main__":
    unittest.main()
