#!/usr/bin/env python3
"""test_conversion_throughput_d1.py

D1 (enforcement id15/20, 2026-07-03): conversion-throughput delivery-leak signal.

check_exploit_queue_resolution only inspects the TOP-5 leads, so an audit passes
while ~0% of the WHOLE non-vacuous corpus/hacker-Q lead corpus reaches a terminal
work-backed verdict (NUVA: 133/7814). This signal measures the whole-corpus
conversion throughput and emits the undriven count loudly.

SCOPE-HONESTY: this is a THROUGHPUT gap, NOT a false-green (operator flagged the
severity as overstated). It is ADVISORY-FIRST (WARN by default), hard-fails ONLY
under the dedicated AUDITOOOR_CONVERSION_THROUGHPUT_STRICT, and is DELIBERATELY
not wired into audit-done-guard done=True.

This test builds a synthetic exploit_queue and pins: a low-throughput corpus
WARN-passes with env unset (byte-parity) and FAILs under the env; a high-throughput
corpus passes; a below-min corpus is N/A; the done-guard advisory is attach-only.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_ACC_SRC = (_TOOLS / "audit-completeness-check.py").read_text(
    encoding="utf-8", errors="replace")
_DONE_SRC = (_TOOLS / "audit-done-guard.py").read_text(
    encoding="utf-8", errors="replace")
_ENV = "AUDITOOOR_CONVERSION_THROUGHPUT_STRICT"
_L37 = "AUDITOOOR_L37_STRICT"


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_d1", str(_TOOLS / "audit-completeness-check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_d1"] = m
    spec.loader.exec_module(m)
    return m


def _mk_queue(tmp: Path, *, undriven, terminal):
    ad = tmp / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    rows = []
    for i in range(undriven):
        rows.append({"lead_id": f"u{i}", "proof_status": "unproved",
                     "quality_gate_status": "open"})
    for i in range(terminal):
        # a genuine refuted-with-substantive-negative-control terminal row
        rows.append({"lead_id": f"t{i}", "proof_status": "killed",
                     "negative_control": "src/Vault.sol:120 require() reverts; test_guard PASS"})
    (ad / "exploit_queue.json").write_text(json.dumps({"queue": rows}))
    return tmp


class TestD1ConversionThroughput(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop(_ENV, None)
        self._saved_l37 = os.environ.pop(_L37, None)
        self.acc = _load_acc()

    def tearDown(self):
        for k, v in ((_ENV, self._saved), (_L37, self._saved_l37)):
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # ---- 4-case default-ON-under-L37 matrix ------------------------------
    def test_case_non_strict_advisory_env_unset_no_l37(self):
        # env unset AND no L37 -> advisory WARN-pass (bare / library caller).
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=200, terminal=2)  # ~1%
            os.environ.pop(_ENV, None)
            os.environ.pop(_L37, None)
            r = self.acc.check_conversion_throughput(ws)
            self.assertTrue(r.ok, "env-unset + no L37 must WARN-pass (advisory-first)")
            self.assertTrue(r.reason.startswith("WARN:"))
            self.assertFalse(r.detail["strict"])
            self.assertEqual(r.detail["undriven"], 200)
            self.assertEqual(r.detail["terminal_work_backed"], 2)

    def test_case_default_under_l37_enforced(self):
        # env UNSET but AUDITOOOR_L37_STRICT=1 -> NEW default: ENFORCED, hard-FAIL.
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=200, terminal=2)
            os.environ.pop(_ENV, None)
            os.environ[_L37] = "1"
            r = self.acc.check_conversion_throughput(ws)
            self.assertFalse(r.ok, "env-unset under L37 must ENFORCE (default-ON)")
            self.assertTrue(r.detail["strict"])
            self.assertIn("conversion-throughput LEAK", r.reason)
            self.assertIn("UNDRIVEN", r.reason)

    def test_case_opt_out_env_zero_even_under_l37(self):
        # explicit AUDITOOOR_CONVERSION_THROUGHPUT_STRICT=0 -> DISABLED escape hatch
        # even under L37: advisory WARN-pass.
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=200, terminal=2)
            os.environ[_ENV] = "0"
            os.environ[_L37] = "1"
            r = self.acc.check_conversion_throughput(ws)
            self.assertTrue(r.ok, "env=0 is an explicit opt-out even under L37")
            self.assertTrue(r.reason.startswith("WARN:"))
            self.assertFalse(r.detail["strict"])

    def test_case_explicit_on_env_one(self):
        # explicit opt-in -> ENFORCED (no L37 needed), hard-FAIL below the floor.
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=200, terminal=2)
            os.environ[_ENV] = "1"
            os.environ.pop(_L37, None)
            r = self.acc.check_conversion_throughput(ws)
            self.assertFalse(r.ok, "env-set + below-floor throughput must FAIL")
            self.assertTrue(r.detail["strict"])
            self.assertIn("conversion-throughput LEAK", r.reason)
            self.assertIn("UNDRIVEN", r.reason)

    def test_high_throughput_passes_even_under_env(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=10, terminal=90)  # 90%
            os.environ[_ENV] = "1"
            r = self.acc.check_conversion_throughput(ws)
            self.assertTrue(r.ok, "a high-throughput corpus must pass under strict")
            self.assertGreaterEqual(r.detail["terminal_fraction"], 0.05)

    def test_small_corpus_is_na(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=10, terminal=0)  # < min rows
            os.environ[_ENV] = "1"
            r = self.acc.check_conversion_throughput(ws)
            self.assertTrue(r.ok, "a <50-lead corpus is not measurable -> pass")
            self.assertIn("N/A", r.reason)

    def test_no_queue_passes(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / ".auditooor").mkdir()
            os.environ[_ENV] = "1"
            r = self.acc.check_conversion_throughput(Path(t))
            self.assertTrue(r.ok, "no exploit_queue.json -> N/A pass")

    def test_bare_killed_is_not_terminal(self):
        # a killed row WITHOUT a substantive negative_control is UNDRIVEN
        row = {"lead_id": "x", "proof_status": "killed",
               "negative_control": "PoC must include a baseline run"}  # boilerplate
        self.assertFalse(self.acc._lead_is_terminal_work_backed(row))
        # a proved row IS terminal
        self.assertTrue(self.acc._lead_is_terminal_work_backed(
            {"lead_id": "y", "proof_status": "proved"}))

    def test_advisory_only_leads_excluded_as_vacuous(self):
        with tempfile.TemporaryDirectory() as t:
            ad = Path(t) / ".auditooor"
            ad.mkdir(parents=True)
            rows = [{"lead_id": f"a{i}", "advisory_only": True,
                     "proof_status": "unproved"} for i in range(100)]
            rows += [{"lead_id": "t", "proof_status": "proved"}]
            (ad / "exploit_queue.json").write_text(json.dumps({"queue": rows}))
            os.environ[_ENV] = "1"
            r = self.acc.check_conversion_throughput(Path(t))
            # only the 1 non-vacuous row counts -> below min-rows -> N/A pass
            self.assertEqual(r.detail["nonvacuous_leads"], 1)
            self.assertTrue(r.ok)

    # ---- closed_negative terminal-refuted vocab reconciliation (gap55) -----
    def test_closed_negative_with_substantive_nc_is_terminal(self):
        # (1) a closed_negative lead WITH a substantive negative-control IS
        # credited terminal-refuted (the miner's terminal token is now read).
        row = {"lead_id": "cn", "proof_status": "closed_negative",
               "negative_control": "src/Vault.sol:120 require() reverts; test_guard PASS"}
        self.assertTrue(self.acc._lead_is_terminal_work_backed(row))

    def test_closed_negative_without_nc_is_not_terminal(self):
        # (2) a closed_negative lead with NO substantive negative-control is NOT
        # credited (boilerplate template) - it stays an undriven LEAK, no false-green.
        # This is exactly the axelar-dlt shape (5545 rows, boilerplate nc).
        boiler = {"lead_id": "cn2", "proof_status": "closed_negative",
                  "negative_control":
                  "run identical scenario without the bug path and confirm clean state"}
        self.assertFalse(self.acc._lead_is_terminal_work_backed(boiler))
        # and one with no nc field at all
        self.assertFalse(self.acc._lead_is_terminal_work_backed(
            {"lead_id": "cn3", "proof_status": "closed_negative"}))

    def test_open_lead_is_never_terminal(self):
        # (3) an open lead is never credited, with or without an nc field.
        self.assertFalse(self.acc._lead_is_terminal_work_backed(
            {"lead_id": "o1", "proof_status": "open"}))
        self.assertFalse(self.acc._lead_is_terminal_work_backed(
            {"lead_id": "o2", "proof_status": "open",
             "negative_control": "src/Vault.sol:120 require() reverts; test_guard PASS"}))

    def test_serving_join_gate_reads_every_miner_terminal_token(self):
        # SERVING-JOIN pin: every terminal-refuted proof_status the miner
        # (exploit-queue.py _SOURCE_MINED_TERMINAL_PROOF_STATUSES) WRITES must be
        # in the set the gate READS, else honestly-refuted leads score 0 -> false LEAK.
        eq_src = (_TOOLS / "exploit-queue.py").read_text(
            encoding="utf-8", errors="replace")
        import re as _re
        m = _re.search(r"_SOURCE_MINED_TERMINAL_PROOF_STATUSES\s*=\s*\{([^}]*)\}",
                       eq_src)
        self.assertIsNotNone(m, "miner terminal-refuted vocab not found")
        writer = {t.strip().strip("'\"").lower()
                  for t in m.group(1).split(",") if t.strip().strip("'\"")}
        reader = set(self.acc._CONVERSION_TERMINAL_REFUTED_PROOF_STATES)
        missing = writer - reader
        self.assertEqual(missing, set(),
                         f"gate reader missing miner terminal tokens: {missing}")

    # ---- registration + wiring pins --------------------------------------
    def test_signal_registered_after_exploit_queue_resolution(self):
        names = [s for s, _ in self.acc._SIGNAL_ORDER]
        self.assertIn("conversion-throughput", names)
        self.assertEqual(
            names.index("conversion-throughput"),
            names.index("exploit-queue-resolution") + 1)

    def test_non_strict_never_adds_a_failure(self):
        # Advisory for a bare/library caller: env unset AND no L37 -> always ok=True.
        os.environ.pop(_ENV, None)
        os.environ.pop(_L37, None)
        with tempfile.TemporaryDirectory() as t:
            ws = _mk_queue(Path(t), undriven=200, terminal=1)
            self.assertTrue(self.acc.check_conversion_throughput(ws).ok)

    def test_default_on_predicate_wiring(self):
        # DEFAULT-ON graduation: the strict decision delegates to the shared
        # _gate_default_on_strict() over the dedicated env - default-ON under L37
        # with a per-gate opt-out. It must NOT call _l37_gate_strict directly.
        i = _ACC_SRC.find("def check_conversion_throughput")
        seg = _ACC_SRC[i:i + 1100]
        self.assertIn(_ENV, seg)
        self.assertIn("_gate_default_on_strict", seg)
        self.assertNotIn("_l37_gate_strict", seg)
        # the shared helper reads L37 as the default umbrella + honors the opt-out
        h = _ACC_SRC.find("def _gate_default_on_strict")
        self.assertGreater(h, 0)
        hseg = _ACC_SRC[h:h + 1400]
        self.assertIn("AUDITOOOR_L37_STRICT", hseg)
        self.assertIn('("0", "false", "no")', hseg)

    def test_done_guard_advisory_attach_only_not_wired_into_done(self):
        # the done-guard leg must ATTACH the advisory but NEVER return/brick done
        self.assertIn("conversion_throughput_advisory", _DONE_SRC)
        self.assertIn("not wired into done=True", _DONE_SRC)
        # find the D1 block and confirm there is no `return res` inside it
        i = _DONE_SRC.find("conversion_throughput_advisory")
        # block spans from the D1 comment to the next `# R8` marker after it
        start = _DONE_SRC.rfind("# D1 (enforcement", 0, i)
        end = _DONE_SRC.find("# R8 (enforcement-gap 2026-07-03): prior-audit", i)
        block = _DONE_SRC[start:end]
        self.assertNotIn("res[\"fail_gates\"]", block,
                         "D1 must NOT set a fail gate (throughput gap, not false-green)")
        self.assertNotIn("return res", block,
                         "D1 must NOT brick done in this wave")

    def test_syntax_ok(self):
        import ast
        ast.parse(_ACC_SRC)
        ast.parse(_DONE_SRC)


if __name__ == "__main__":
    unittest.main()
