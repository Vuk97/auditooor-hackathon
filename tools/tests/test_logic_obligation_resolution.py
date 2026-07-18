#!/usr/bin/env python3
"""Guard tests for the LOGIC-REASONER ENFORCEMENT wiring (LOGIC_ARSENAL_ROADMAP
"ENFORCE, NOT ADVISORY", 2026-07-13):

  1. tools/logic-obligation-resolution-check.py - the terminal-verdict RESOLUTION
     gate over every pre-hunt reasoner obligation ledger (step-2d-*). Advisory-WARN
     by default; fail-closed (fail-logic-obligation-unresolved) under strict when an
     emitted obligation is still OPEN.
  2. tools/readme_runbook_steps.json - the 8 core reasoners are REQUIRED steps that
     run BEFORE the step-3 hunt (ORDER), each verified by its obligation ledger.
  3. tools/audit-completeness-check.py - the three umbrella JOINs
     (logic-obligation-resolution, executed-refutation-honesty,
     capability-firing-fraction) are registered in BOTH _SIGNAL_ORDER and by_signal.

Cases:
  A  reasoner ledger with OPEN obligations, DEFAULT -> advisory WARN-pass (ok=True).
  B  same ledger, STRICT -> FAIL (ok=False, fail-logic-obligation-unresolved).
  C  ledger whose rows are all TERMINAL (proof_status=killed) -> PASS even under strict.
  D  external resolution sidecar flips an OPEN row terminal -> PASS.
  E  no ledger + no dataflow substrate -> WARN-pass (nothing reasoned).
  F  no ledger + dataflow substrate + STRICT -> FAIL (reasoners skipped).
  G  runbook: 8 core reasoner steps are required, before step-3, ledger-verified.
  H  runbook: all step-2d-* steps precede step-3 (ORDER / DAG).
  I  completeness registry: the 3 new signals are in BOTH _SIGNAL_ORDER and by_signal.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "logic-obligation-resolution-check.py"
_ACC_TOOL = _REPO / "tools" / "audit-completeness-check.py"
_MANIFEST = _REPO / "tools" / "readme_runbook_steps.json"

_CORE_REASONER_STEPS = {
    "step-2d-callgraph-setdiff": "unguarded_mutation_obligations.jsonl",
    "step-2d-atomic-sequence": "atomic_sequence_obligations.jsonl",
    "step-2d-conservation-haircut": "conservation_haircut_obligations.jsonl",
    "step-2d-degenerate-input": "degenerate_input_verdict_obligations.jsonl",
    "step-2d-privilege-trust": "payload_derived_trusted_dispatch_obligations.jsonl",
    "step-2d-numeric-boundary": "numeric_boundary_obligations.jsonl",
    "step-2d-oracle-spot": "oracle_spot_price_obligations.jsonl",
    "step-2d-crosschain-forgery": "crosschain_forgery_obligations.jsonl",
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_LOR = _load("_lor_test_mod", _TOOL)
_ACC = _load("_acc_lor_test_mod", _ACC_TOOL)


class _EnvGuard:
    def __init__(self, **kv):
        self.kv = kv
        self.old = {}

    def __enter__(self):
        for k, v in self.kv.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


_CLEAR = {"AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT": None,
          "AUDITOOOR_L37_LOGIC_OBLIGATION_RESOLUTION_STRICT": None,
          "AUDITOOOR_L37_STRICT": None}


def _mk_ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="l37_lor_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    return ws


def _write_substrate(ws: Path) -> None:
    (ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
        json.dumps({"fn": "burn", "kind": "balance_decrease"}) + "\n", encoding="utf-8")


def _write_ledger(ws: Path, fname: str, rows: list[dict]) -> None:
    (ws / ".auditooor" / fname).write_text(
        "\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""), encoding="utf-8")


def _open_row(contract="C", fn="f", ac="unguarded-downward-mutation-no-solvency-check"):
    return {"contract": contract, "function": fn, "attack_class": ac,
            "proof_status": "needs_source", "quality_gate_status": "needs_source"}


class LogicObligationResolution(unittest.TestCase):
    def test_a_open_default_warn_pass(self):
        ws = _mk_ws()
        _write_substrate(ws)
        _write_ledger(ws, "numeric_boundary_obligations.jsonl", [_open_row(fn="a"), _open_row(fn="b")])
        with _EnvGuard(**_CLEAR):
            res = _LOR.check(ws)
        self.assertTrue(res["ok"])
        self.assertEqual(res["open"], 2)
        self.assertEqual(res["verdict"], "pass-advisory-open")

    def test_b_open_strict_fail(self):
        ws = _mk_ws()
        _write_substrate(ws)
        _write_ledger(ws, "numeric_boundary_obligations.jsonl", [_open_row()])
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT": "1"}):
            res = _LOR.check(ws)
        self.assertFalse(res["ok"])
        self.assertEqual(res["verdict"], "fail-logic-obligation-unresolved")

    def test_c_all_terminal_pass_under_strict(self):
        ws = _mk_ws()
        _write_substrate(ws)
        rows = [dict(_open_row(fn=f"f{i}"), proof_status="killed") for i in range(3)]
        _write_ledger(ws, "numeric_boundary_obligations.jsonl", rows)
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            res = _LOR.check(ws)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertEqual(res["open"], 0)
        self.assertEqual(res["resolved"], 3)

    def test_d_resolution_sidecar_flips_terminal(self):
        ws = _mk_ws()
        _write_substrate(ws)
        _write_ledger(ws, "numeric_boundary_obligations.jsonl",
                      [_open_row(contract="Vault", fn="withdraw", ac="oracle-spot")])
        # external resolution ledger marks the same key terminal (dispositioned)
        (ws / ".auditooor" / "logic_obligation_resolutions.jsonl").write_text(
            json.dumps({"contract": "Vault", "function": "withdraw",
                        "attack_class": "oracle-spot", "state": "dispositioned"}) + "\n",
            encoding="utf-8")
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            res = _LOR.check(ws)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertEqual(res["open"], 0)

    def test_e_no_ledger_no_substrate_warn_pass(self):
        ws = _mk_ws()
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            res = _LOR.check(ws)
        self.assertTrue(res["ok"])
        self.assertEqual(res["ledgers_ran"], 0)

    def test_f_no_ledger_with_substrate_strict_fail(self):
        ws = _mk_ws()
        _write_substrate(ws)
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            res = _LOR.check(ws)
        self.assertFalse(res["ok"])
        self.assertEqual(res["verdict"], "fail-logic-obligation-unresolved")


class RunbookReasonerSteps(unittest.TestCase):
    def setUp(self):
        self.man = json.loads(_MANIFEST.read_text(encoding="utf-8"))
        self.steps = self.man["steps"]
        self.by_id = {s["step_id"]: s for s in self.steps}
        self.order = [s["step_id"] for s in self.steps]

    def test_g_core_reasoners_required_and_ledger_verified(self):
        for sid, ledger in _CORE_REASONER_STEPS.items():
            self.assertIn(sid, self.by_id, f"{sid} missing from runbook")
            step = self.by_id[sid]
            self.assertTrue(step.get("required"), f"{sid} must be REQUIRED")
            checks = step["how_to_verify_done"]["artifact_checks"]
            paths = [c.get("path") for c in checks]
            self.assertIn(f".auditooor/{ledger}", paths,
                          f"{sid} must verify its obligation ledger {ledger}")

    def test_h_all_reasoner_steps_precede_hunt(self):
        i3 = self.order.index("step-3")
        reasoners = [i for i in self.order if i.startswith("step-2d-")]
        self.assertGreaterEqual(len(reasoners), 8)
        for r in reasoners:
            self.assertLess(self.order.index(r), i3,
                            f"reasoner {r} must run BEFORE the step-3 hunt (ORDER)")

    def test_h2_reasoner_steps_depend_on_dataflow_slice(self):
        for sid in _CORE_REASONER_STEPS:
            self.assertEqual(self.by_id[sid].get("depends_on"), "step-1c")


class AsyncLifecycleResolutionParity(unittest.TestCase):
    def test_typed_async_lifecycle_substrate_is_registered_as_rust_reasoner(self):
        rows = [row for row in _LOR._REASONER_LEDGERS
                if row[1] == "async-cancel-coupled-state-screen.py"]
        self.assertEqual(rows, [(
            "async_cancel_coupled_state_hypotheses.jsonl",
            "async-cancel-coupled-state-screen.py",
            "rust",
        )])


class UmbrellaRegistry(unittest.TestCase):
    def test_i_new_signals_registered_both_places(self):
        order_names = {s for s, _ in _ACC._SIGNAL_ORDER}
        for sig in ("logic-obligation-resolution", "executed-refutation-honesty",
                    "capability-firing-fraction"):
            self.assertIn(sig, order_names, f"{sig} missing from _SIGNAL_ORDER")
            # a check_* function must exist for the by_signal map
            fn_name = "check_" + sig.replace("-", "_")
            self.assertTrue(hasattr(_ACC, fn_name), f"{fn_name} missing")


if __name__ == "__main__":
    unittest.main()
