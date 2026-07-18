"""Wrapper-level regression for the reasoner-firing-nonvacuity L37 GATE (step 4b).

The sibling test_reasoner_firing_nonvacuity_check.py exercises the standalone tool's
``check()``. This test pins the AUDIT-COMPLETENESS GATE wiring in
``tools/audit-completeness-check.py`` - i.e. that ``check_reasoner_firing_nonvacuity``
is default-ON-under-STRICT (blocking), hard-required (registered in ``_SIGNAL_ORDER``
so the aggregator can actually fail on it), and advisory by default with a per-gate
opt-out. This is the "flip from advisory to blocking" contract that step 4b enforces.

Cases:
  A  registration bijection: ("reasoner-firing-nonvacuity", "fail-reasoner-vacuous")
     is in _SIGNAL_ORDER (else the aggregator silently drops it - false-green vector).
  B  a synthetic silently-vacuous non-exempt reasoner ws => wrapper ok=False under STRICT.
  C  an all-fired-or-exempt ws => wrapper ok=True under STRICT.
  D  default policy (no L37) => advisory ok=True (no retro-red on a bare caller).
  E  explicit per-gate opt-out under global STRICT downgrades to advisory ok=True.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_ACC_TOOL = _REPO / "tools" / "audit-completeness-check.py"
_RFNV_TOOL = _REPO / "tools" / "reasoner-firing-nonvacuity-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_ACC = _load("_acc_reasoner_gate_test_mod", _ACC_TOOL)
_RFNV = _load("_rfnv_gate_test_mod", _RFNV_TOOL)


def _mk_ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="l37_reasoner_gate_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    return ws


def _populate_all_fired(ws: Path) -> None:
    """Write an anchored obligation for EVERY wired reasoner ledger -> 0 vacuous."""
    aud = ws / ".auditooor"
    for fname, _tool, _lang in _RFNV._load_reasoner_ledgers():
        p = aud / fname
        p.parent.mkdir(parents=True, exist_ok=True)  # some ledgers nest (e.g. dirm/)
        p.write_text(
            json.dumps({"contract": "C", "function": "f", "attack_class": "x"}) + "\n",
            encoding="utf-8")


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


# neutralize any ambient L37 env; each case sets exactly what it exercises
_CLEAR = {"AUDITOOOR_L37_STRICT": None,
          "AUDITOOOR_L37_REASONER_FIRING_STRICT": None}


class ReasonerFiringGateBlocking(unittest.TestCase):
    def test_a_registered_hard_required_in_signal_order(self):
        order = dict(_ACC._SIGNAL_ORDER)
        self.assertIn("reasoner-firing-nonvacuity", order,
                      "signal MUST be in _SIGNAL_ORDER or the aggregator silently "
                      "drops it (false-green): it could never fail audit-complete")
        self.assertEqual(order["reasoner-firing-nonvacuity"], "fail-reasoner-vacuous")

    def test_b_synthetic_vacuous_fails_under_strict(self):
        # a bare .auditooor (every wired ledger missing, no exemptions) is silently
        # vacuous; under the global STRICT umbrella the GATE must block (ok=False).
        ws = _mk_ws()
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            r = _ACC.check_reasoner_firing_nonvacuity(ws)
        self.assertFalse(r.ok, "vacuous reasoner(s) must FAIL the gate under STRICT")
        self.assertIn("SILENTLY VACUOUS", r.reason)

    def test_c_all_fired_passes_under_strict(self):
        ws = _mk_ws()
        _populate_all_fired(ws)
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1"}):
            r = _ACC.check_reasoner_firing_nonvacuity(ws)
        self.assertTrue(r.ok, "an all-fired ws must PASS the gate under STRICT")
        self.assertIn("0 silently-vacuous", r.reason)

    def test_d_advisory_pass_by_default_no_l37(self):
        # no L37 env at all -> advisory WARN-pass (a bare / library caller keeps
        # advisory behaviour, no retro-red).
        ws = _mk_ws()
        with _EnvGuard(**_CLEAR):
            r = _ACC.check_reasoner_firing_nonvacuity(ws)
        self.assertTrue(r.ok, "default (no L37) policy is advisory WARN-pass")

    def test_e_per_gate_optout_downgrades_under_global_strict(self):
        ws = _mk_ws()
        with _EnvGuard(**{**_CLEAR, "AUDITOOOR_L37_STRICT": "1",
                          "AUDITOOOR_L37_REASONER_FIRING_STRICT": "0"}):
            r = _ACC.check_reasoner_firing_nonvacuity(ws)
        self.assertTrue(r.ok, "explicit per-gate opt-out downgrades to advisory")


if __name__ == "__main__":
    unittest.main()
