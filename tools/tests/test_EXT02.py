#!/usr/bin/env python3
"""EXT02 ABCI++ cross-phase acceptance-symmetry screen - non-vacuous regression.

Pins tools/abci-phase-predicate-symmetry-screen.py: for a producer->consumer ABCI++
phase pair (PrepareProposal->ProcessProposal, ExtendVote->VerifyVoteExtension), it
extracts the CONSUMER's acceptance-predicate items (per-item validators + gas/size/
sequence/signature/height dimensions + domain operands) and flags every item the
PRODUCER does not re-establish (coverage subset check) - the producer-ACCEPT must be
a subset of consumer-ACCEPT invariant (ASA-2024-002 class). Every row is advisory
verdict="needs-fuzz".

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a ProcessProposal that REJECTS on total block gas,
      paired with a PrepareProposal that never references gas -> a gas phase-
      asymmetry lead fires.
  (2) COVERED NEGATIVE silent  - the SAME pair, but the producer re-establishes the
      block-gas bound; the coverage check cancels it -> silent.
  (3) NEUTRALIZE the core predicate - monkeypatch `_item_covered` to a constant True
      ("producer covers everything"); the planted positive must then STOP firing.
      Proves the coverage predicate is load-bearing, not decoration.
Plus: a producer-missing lead (custom consumer, no producer for the receiver) fires
via scan_tree; a tree with no phase handlers is silent; the advisory contract holds
on every row; machinery tokens (the handler's own dispatch / proto getters) never
fire.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_TOOL = ROOT / "tools" / "abci-phase-predicate-symmetry-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext02_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


EXT = _load()


def _scan_src(src: str, name: str = "abci_x.go"):
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / name
        p.write_text(src)
        return EXT.scan_file(p, name)


def _scan_tree(files: dict):
    with tempfile.TemporaryDirectory() as td:
        for rel, src in files.items():
            fp = pathlib.Path(td) / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(src)
        return EXT.scan_tree(pathlib.Path(td))


def _fired(rows):
    return [r for r in rows if r["fires"]]


# ---- fixtures --------------------------------------------------------------
# PLANTED POSITIVE: ProcessProposal rejects on total block gas; PrepareProposal
# selects txs but NEVER re-establishes the block-gas bound -> gas phase-asymmetry.
POSITIVE = """
package app

func (h *MyHandler) PrepareProposalHandler() PrepareFn {
\treturn func(ctx Context, req *RequestPrepareProposal) (*ResponsePrepareProposal, error) {
\t\tvar selected [][]byte
\t\tfor _, txBz := range req.Txs {
\t\t\t_, err := h.verifier.PrepareProposalVerifyTx(txBz)
\t\t\tif err != nil {
\t\t\t\tcontinue
\t\t\t}
\t\t\tselected = append(selected, txBz)
\t\t}
\t\treturn &ResponsePrepareProposal{Txs: selected}, nil
\t}
}

func (h *MyHandler) ProcessProposalHandler() ProcessFn {
\treturn func(ctx Context, req *RequestProcessProposal) (*ResponseProcessProposal, error) {
\t\tvar totalTxGas uint64
\t\tmaxBlockGas := ctx.MaxGas()
\t\tfor _, txBytes := range req.Txs {
\t\t\ttx, err := h.verifier.ProcessProposalVerifyTx(txBytes)
\t\t\tif err != nil {
\t\t\t\treturn &ResponseProcessProposal{Status: REJECT}, nil
\t\t\t}
\t\t\ttotalTxGas += tx.GetGas()
\t\t\tif totalTxGas > maxBlockGas {
\t\t\t\treturn &ResponseProcessProposal{Status: REJECT}, nil
\t\t\t}
\t\t}
\t\treturn &ResponseProcessProposal{Status: ACCEPT}, nil
\t}
}
"""

# COVERED NEGATIVE: identical, but PrepareProposal re-establishes the block-gas
# bound (references maxBlockGas / GetGas) -> the gas dimension is covered -> silent.
NEGATIVE = """
package app

func (h *MyHandler) PrepareProposalHandler() PrepareFn {
\treturn func(ctx Context, req *RequestPrepareProposal) (*ResponsePrepareProposal, error) {
\t\tvar selected [][]byte
\t\tvar runningGas uint64
\t\tmaxBlockGas := ctx.MaxGas()
\t\tfor _, txBz := range req.Txs {
\t\t\ttx, err := h.verifier.PrepareProposalVerifyTx(txBz)
\t\t\tif err != nil {
\t\t\t\tcontinue
\t\t\t}
\t\t\trunningGas += tx.GetGas()
\t\t\tif runningGas > maxBlockGas {
\t\t\t\tbreak
\t\t\t}
\t\t\tselected = append(selected, txBz)
\t\t}
\t\treturn &ResponsePrepareProposal{Txs: selected}, nil
\t}
}

func (h *MyHandler) ProcessProposalHandler() ProcessFn {
\treturn func(ctx Context, req *RequestProcessProposal) (*ResponseProcessProposal, error) {
\t\tvar totalTxGas uint64
\t\tmaxBlockGas := ctx.MaxGas()
\t\tfor _, txBytes := range req.Txs {
\t\t\ttx, err := h.verifier.ProcessProposalVerifyTx(txBytes)
\t\t\tif err != nil {
\t\t\t\treturn &ResponseProcessProposal{Status: REJECT}, nil
\t\t\t}
\t\t\ttotalTxGas += tx.GetGas()
\t\t\tif totalTxGas > maxBlockGas {
\t\t\t\treturn &ResponseProcessProposal{Status: REJECT}, nil
\t\t\t}
\t\t}
\t\treturn &ResponseProcessProposal{Status: ACCEPT}, nil
\t}
}
"""

# producer-missing: a CUSTOM consumer with a gas content check and no producer for
# its receiver anywhere in the tree (the ASA default-producer + custom-consumer
# shape).
PRODUCER_MISSING = """
package app

func (app *App) ProcessProposalHandler() ProcessFn {
\treturn func(ctx Context, req *RequestProcessProposal) (*ResponseProcessProposal, error) {
\t\tif !app.checkTotalBlockGas(ctx, req.Txs) {
\t\t\treturn &ResponseProcessProposal{Status: REJECT}, nil
\t\t}
\t\treturn &ResponseProcessProposal{Status: ACCEPT}, nil
\t}
}
"""

# no phase handlers at all -> silent.
NO_PHASE = """
package app

func (k Keeper) Transfer(ctx Context, amount uint64) error {
\tif amount > k.balance {
\t\treturn ErrInsufficient
\t}
\tk.balance -= amount
\treturn nil
}
"""


class TestExt02(unittest.TestCase):
    # ---- leg 1: planted positive fires -----------------------------------
    def test_positive_fires_gas_asymmetry(self):
        rows = _scan_src(POSITIVE)
        fired = _fired(rows)
        self.assertTrue(fired, "planted gas phase-asymmetry must fire")
        gas = [r for r in fired if r["kind"] == "phase-asymmetry"
               and r["asymmetric_item"] == "gas"]
        self.assertTrue(gas, f"expected a gas phase-asymmetry row, got {fired}")
        r = gas[0]
        self.assertEqual(r["pair"], "PrepareProposal->ProcessProposal")
        self.assertEqual(r["producer_phase"], "PrepareProposal")
        self.assertEqual(r["consumer_phase"], "ProcessProposal")
        self.assertEqual(r["receiver_type"], "MyHandler")
        self.assertTrue(r["severity_eligible"])

    def test_positive_shared_validator_not_flagged(self):
        # ProcessProposalVerifyTx / PrepareProposalVerifyTx normalize to the SAME
        # validator (verifytx) -> symmetric -> must NOT be a fired item.
        rows = _scan_src(POSITIVE)
        vals = [r for r in _fired(rows)
                if r["kind"] == "phase-asymmetry"
                and str(r["asymmetric_item"]).startswith("verify")]
        self.assertEqual(vals, [], f"shared validator wrongly flagged: {vals}")

    # ---- leg 2: covered negative is silent -------------------------------
    def test_negative_silent(self):
        rows = _scan_src(NEGATIVE)
        self.assertEqual(_fired(rows), [],
                         f"producer re-establishes gas -> must be silent: "
                         f"{_fired(rows)}")

    # ---- leg 3: neutralize the core predicate ----------------------------
    def test_neutralized_predicate_stops_positive(self):
        orig = EXT._item_covered
        try:
            EXT._item_covered = lambda *a, **k: True  # producer "covers" everything
            rows = _scan_src(POSITIVE)
            self.assertEqual(
                _fired(rows), [],
                "with _item_covered forced True the positive must NOT fire "
                "(coverage predicate is load-bearing)")
        finally:
            EXT._item_covered = orig
        # sanity: restoring the predicate re-fires the positive
        self.assertTrue(_fired(_scan_src(POSITIVE)))

    # ---- producer-missing arm (scan_tree) --------------------------------
    def test_producer_missing_fires(self):
        rows = _scan_tree({"app/app.go": PRODUCER_MISSING})
        pm = [r for r in _fired(rows) if r["kind"] == "producer-missing"]
        self.assertTrue(pm, f"producer-missing must fire, got {rows}")
        self.assertFalse(pm[0]["severity_eligible"],
                         "producer-missing must NOT be strict-eligible")

    # ---- silence on a tree with no phase handlers ------------------------
    def test_no_phase_silent(self):
        rows = _scan_tree({"keeper/transfer.go": NO_PHASE})
        self.assertEqual(rows, [])

    # ---- machinery is never an item --------------------------------------
    def test_machinery_dispatch_not_flagged(self):
        # a BaseApp-style dispatch wrapper: consumer just forwards to the wired
        # handler (app.processProposal) and compares Status enums - pure machinery.
        src = """
package baseapp

func (app *BaseApp) PrepareProposal(req *RequestPrepareProposal) (*ResponsePrepareProposal, error) {
\tif req.Height < 1 {
\t\treturn nil, ErrHeight
\t}
\treturn app.prepareProposal(req)
}

func (app *BaseApp) ProcessProposal(req *RequestProcessProposal) (*ResponseProcessProposal, error) {
\tif req.Height < 1 {
\t\treturn nil, ErrHeight
\t}
\tresp, _ := app.processProposal(req)
\tif resp.Status == ResponseProcessProposal_ACCEPT {
\t\treturn resp, nil
\t}
\treturn resp, nil
}
"""
        rows = _scan_src(src, name="abci.go")
        self.assertEqual(_fired(rows), [],
                         f"dispatch machinery must not fire: {_fired(rows)}")

    # ---- advisory contract holds on every row ----------------------------
    def test_advisory_contract(self):
        rows = _scan_src(POSITIVE) + _scan_tree({"app/app.go": PRODUCER_MISSING})
        self.assertTrue(rows)
        for r in rows:
            self.assertIs(r["advisory"], True)
            self.assertIs(r["auto_credit"], False)
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertEqual(r["capability"], "EXT02")
            self.assertIn("question", r)
            # every row is JSON-serializable (sidecar contract)
            json.dumps(r)

    # ---- workspace mode emits the sidecar --------------------------------
    def test_workspace_emits_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src" / "app").mkdir(parents=True)
            (ws / "src" / "app" / "app.go").write_text(PRODUCER_MISSING)
            rc = EXT.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)  # advisory default exit 0
            side = ws / ".auditooor" / EXT._SIDE_NAME
            self.assertTrue(side.exists(), "sidecar must be written")
            lines = [json.loads(l) for l in side.read_text().splitlines()
                     if l.strip()]
            self.assertTrue(any(r["kind"] == "producer-missing" for r in lines))

    def test_strict_exit_on_severity_eligible(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "abci_x.go").write_text(POSITIVE)
            rc = EXT.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc, 1,
                             "a fired phase-asymmetry must trip --strict exit 1")


if __name__ == "__main__":
    unittest.main()
