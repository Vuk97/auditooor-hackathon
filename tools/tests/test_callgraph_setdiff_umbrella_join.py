#!/usr/bin/env python3
"""Guard test for the LOGIC #3 callgraph SET-DIFFERENCE reasoner JOIN into the
L37 umbrella (``tools/audit-completeness-check.py``).

Hole (produced-but-unread): the pre-hunt producer
``tools/callgraph-set-difference-hunter.py`` (the Euler $197M reasoning query)
emits ``<ws>/.auditooor/unguarded_mutation_obligations.jsonl`` and exploit-queue
ingests it - but the L37 audit-complete umbrella never READ the reasoner's
artifact, so "did we even run the unguarded-downward-mutation trust-layer probe?"
could never fail / even appear in the audit-complete result JSON.

Fix: ``check_callgraph_set_difference`` reads the artifact; the signal is
registered in both ``_SIGNAL_ORDER`` and ``by_signal`` so the aggregator SEES it.
Advisory-first (report-only by default), fail-closed only under the DEDICATED
``AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT`` (or the global ``AUDITOOOR_L37_STRICT``)
when the reasoner never ran while a dataflow substrate exists.

Cases:
  A  reasoner ran (obligations present) -> PASS, survivor count reported.
  B  no dataflow substrate + never ran -> WARN-pass (nothing to reason over).
  C  substrate present + never ran, DEFAULT mode -> advisory PASS (not a gate).
  D  substrate present + never ran, STRICT -> FAIL (unprobed trust layer).
  E  registry bijection: the signal is in BOTH _SIGNAL_ORDER and the check map.
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
_TOOL = _REPO / "tools" / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("_acc_setdiff_test_mod", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acc_setdiff_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


_ACC = _load()


def _mk_ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="l37_setdiff_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    return ws


def _write_substrate(ws: Path) -> None:
    (ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
        json.dumps({"fn": "burn", "kind": "balance_decrease"}) + "\n",
        encoding="utf-8",
    )


def _write_obligations(ws: Path, n: int) -> None:
    lines = [json.dumps({"fn": f"f{i}", "kind": "unguarded-mutation-entrypoint"})
             for i in range(n)]
    (ws / ".auditooor" / "unguarded_mutation_obligations.jsonl").write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )


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


_CLEAR = {"AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT": None,
          "AUDITOOOR_L37_STRICT": None}


class CallgraphSetdiffUmbrellaJoin(unittest.TestCase):
    def test_a_ran_pass(self):
        ws = _mk_ws()
        _write_substrate(ws)
        _write_obligations(ws, 3)
        with _EnvGuard(**_CLEAR):
            r = _ACC.check_callgraph_set_difference(ws)
        self.assertTrue(r.ok)
        self.assertEqual(r.signal, "callgraph-set-difference")
        self.assertEqual(r.detail.get("survivors"), 3)
        self.assertTrue(r.detail.get("ran"))
        self.assertTrue(r.artifacts)

    def test_b_no_substrate_warn_pass(self):
        ws = _mk_ws()  # no substrate, no obligations
        with _EnvGuard(**_CLEAR):
            r = _ACC.check_callgraph_set_difference(ws)
        self.assertTrue(r.ok)
        self.assertFalse(r.detail.get("ran"))
        self.assertFalse(r.detail.get("has_substrate"))

    def test_c_substrate_not_ran_default_advisory_pass(self):
        ws = _mk_ws()
        _write_substrate(ws)  # substrate but reasoner never ran
        with _EnvGuard(**_CLEAR):
            r = _ACC.check_callgraph_set_difference(ws)
        self.assertTrue(r.ok, "default mode must be advisory (never a gate)")
        self.assertTrue(r.detail.get("has_substrate"))
        self.assertFalse(r.detail.get("ran"))

    def test_d_substrate_not_ran_strict_fail(self):
        ws = _mk_ws()
        _write_substrate(ws)
        with _EnvGuard(AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT="1",
                       AUDITOOOR_L37_STRICT=None):
            r = _ACC.check_callgraph_set_difference(ws)
        self.assertFalse(r.ok, "STRICT must fail an unprobed trust layer")
        # global strict flips it too
        with _EnvGuard(AUDITOOOR_L37_CALLGRAPH_SETDIFF_STRICT=None,
                       AUDITOOOR_L37_STRICT="1"):
            r2 = _ACC.check_callgraph_set_difference(ws)
        self.assertFalse(r2.ok)

    def test_e_registered_in_signal_order_and_bijection(self):
        ordered = {s for s, _ in _ACC._SIGNAL_ORDER}
        self.assertIn("callgraph-set-difference", ordered,
                      "signal must be in _SIGNAL_ORDER or it is silently dropped")


if __name__ == "__main__":
    unittest.main()
