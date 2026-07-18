#!/usr/bin/env python3
"""A12 FRESHNESS-COUPLED-TO-SHARED-CURSOR (13th SCG kind) regression.

A freshness SIBLING kind: cell A is a SNAPSHOT of an ON-CHAIN cursor the protocol ADVANCES,
read CROSS-MODULE via `X.epoch()` / `X.checkpoint()` (root in _ORDERING_ROOTS), where that
cursor has a PROVEN NON-MONOTONIC writer (a set/reset fn assigning it from an arbitrary value,
or a `delete` - so it can roll BACK / reorg) AND a SIBLING reader trusts the stored A without
re-establishing it. Trigger = rollover/reset/reorg, NOT age. Advisory + verdict=needs-fuzz.

DEDUP BOUNDARY (A1): DISTINCT from the external-CLOCK freshness kind (block.timestamp / oracle
-round TOKENS the contract never writes, trigger=age) - A12 fires only on a cross-module method
read + a PROVEN non-monotonic writer, keys cell_b='shared-cursor:<root>', and skips any
(file, cell) the external-clock lane already emitted. Distinct from interruption (atomicity).

Covers:
  1. SYNTHETIC clean/vulnerable pair: the cross-module cursor snapshot + non-monotonic setter +
     sibling reader FIRES; removing the non-monotonic writer (monotonic-only cursor) does NOT.
  2. FP-guards: intra-fn SLOAD-to-local gas caching (bare state-var read) is NOT a source;
     a block.timestamp receiver routes to the external-clock lane (no shared-cursor edge).
  3. DEDUP: a (file, cell) already covered by an external-clock edge is skipped.
  4. NATURAL instance on the real polygon WS (read-only): fires on ValidatorShare.sol with
     cell=withdrawEpoch, cursor root=epoch, non-monotonic writer setCurrentEpoch.
  5. MUTATION-VERIFY on a mkdtemp COPY of the real polygon target (shared WS never git-mutated):
     the MUTANT copy (real line 207 `withdrawEpoch = stakeManager.epoch()`) lists __sellVoucher
     as a source-writer; the CLEAN copy (line 207 neutralized to a non-cursor read) does NOT.
"""
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


scg = _load("state_coupling_graph", "state-coupling-graph.py")
scs = _load("state_coupling_schema", "state_coupling_schema.py")

_REAL_POLY = Path("/Users/wolf/audits/polygon")
_POLY_VS = _REAL_POLY / "src/pos-contracts/contracts/staking/validatorShare/ValidatorShare.sol"
_POLY_SM = _REAL_POLY / "src/pos-contracts/contracts/staking/stakeManager/StakeManager.sol"
_POLY_SMS = _REAL_POLY / "src/pos-contracts/contracts/staking/stakeManager/StakeManagerStorage.sol"


def _mk_ws(files: dict) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True)
    lines = []
    for rel, src in files.items():
        fp = ws / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(src, encoding="utf-8")
        lines.append(json.dumps({"file": rel, "unit": f"{rel}::fn"}))
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("\n".join(lines) + "\n")
    return ws


# ---- SYNTHETIC clean/vulnerable pair (faithful cross-module cursor-snapshot idiom) --------
_CURSOR_OWNER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EpochCursor {
    uint256 public epochNo;
    // NON-MONOTONIC writer: a governance setter can roll the cursor BACK to any value.
    function setEpoch(uint256 e) external { epochNo = e; }
    function epoch() external view returns (uint256) { return epochNo; }
}
"""

_SNAP = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEpochCursor { function epoch() external view returns (uint256); }

contract Snapshotter {
    IEpochCursor public cursor;
    struct Rec { uint256 withdrawEpoch; uint256 shares; }
    mapping(address => Rec) public recs;

    function open(uint256 s) external {
        Rec memory r = recs[msg.sender];
        r.shares = s;
        r.withdrawEpoch = cursor.epoch();        // cross-module cursor SNAPSHOT
        recs[msg.sender] = r;
    }

    function settle() external {
        Rec memory r = recs[msg.sender];
        // SIBLING reader: trusts the STORED withdrawEpoch against the live cursor.
        require(r.withdrawEpoch + 10 <= cursor.epoch(), "wait");
        r.shares = 0;
        recs[msg.sender] = r;
    }
}
"""

# monotonic-only cursor: an `advance()` that only ever increments -> no reset/reorg surface.
_CURSOR_MONOTONIC = _CURSOR_OWNER.replace(
    "    function setEpoch(uint256 e) external { epochNo = e; }\n",
    "    function advance() external { epochNo = epochNo + 1; }\n")


def _sc_edges(ws):
    return [e for e in scg._freshness_shared_cursor_edges(ws)
            if e.get("kind") == "freshness-coupled-to-shared-cursor"]


class A12SharedCursorFreshness(unittest.TestCase):

    def test_vulnerable_pair_fires(self):
        ws = _mk_ws({"src/EpochCursor.sol": _CURSOR_OWNER, "src/Snapshotter.sol": _SNAP})
        edges = _sc_edges(ws)
        self.assertEqual(len(edges), 1, "cross-module cursor snapshot + non-monotonic writer "
                                        "+ sibling reader must fire exactly once")
        e = edges[0]
        self.assertEqual(e["cell_a"], "withdrawEpoch")
        self.assertEqual(e["cell_b"], "shared-cursor:epoch")
        self.assertEqual(e["evidence"]["cursor_root"], "epoch")
        self.assertEqual(e["evidence"]["cursor_recv"], "cursor")
        self.assertIn("open", e["evidence"]["source_writers"])
        self.assertIn("settle", e["evidence"]["sibling_readers"])
        nm = e["evidence"]["nonmonotonic_writer"]
        self.assertEqual(nm["fn"], "setEpoch")
        self.assertEqual(nm["how"], "setter")
        self.assertEqual(nm["cursor_cell"], "epochNo")
        # advisory / needs-fuzz / NO auto-credit contract.
        self.assertEqual(e["evidence"]["verdict"], "needs-fuzz")
        self.assertFalse(e["evidence"]["auto_credit"])
        self.assertFalse(e["evidence"]["promotable"])
        ok, errs = scs.validate(e)
        self.assertTrue(ok, errs)
        shutil.rmtree(ws, ignore_errors=True)

    def test_monotonic_only_cursor_does_not_fire(self):
        # PROVEN-writer gate: a cursor that only ever increases has no reset/reorg surface.
        ws = _mk_ws({"src/EpochCursor.sol": _CURSOR_MONOTONIC, "src/Snapshotter.sol": _SNAP})
        self.assertEqual(scg._cursor_nonmonotonic_writers(ws), {},
                         "monotonic-only advance() is not a non-monotonic writer")
        self.assertEqual(_sc_edges(ws), [], "no proven non-monotonic writer -> no edge")
        shutil.rmtree(ws, ignore_errors=True)

    def test_intra_fn_sload_gas_cache_is_not_a_source(self):
        # FP-guard: a bare state-var read into a local (`uint256 _e = epochNo;`) is intra-module
        # SLOAD gas caching, NOT a cross-module cursor read - must never match the source RE.
        self.assertIsNone(scg._CURSOR_READ_RE.search("uint256 _e = epochNo;"))
        self.assertIsNotNone(scg._CURSOR_READ_RE.search("x = cursor.epoch();"))

    def test_block_timestamp_receiver_excluded(self):
        # a block.timestamp source is the external-CLOCK lane's job, NOT shared-cursor.
        snap = _SNAP.replace("r.withdrawEpoch = cursor.epoch();",
                             "r.withdrawEpoch = block.timestamp;")
        ws = _mk_ws({"src/EpochCursor.sol": _CURSOR_OWNER, "src/Snapshotter.sol": snap})
        self.assertEqual(_sc_edges(ws), [],
                         "block.timestamp receiver must route to the external-clock lane")
        shutil.rmtree(ws, ignore_errors=True)

    def test_dedup_skips_external_clock_covered_cell(self):
        # A1 boundary: a (file, cell) already emitted by the external-clock lane is skipped.
        ws = _mk_ws({"src/EpochCursor.sol": _CURSOR_OWNER, "src/Snapshotter.sol": _SNAP})
        fake_clock = [{
            "kind": "freshness-coupled-to-external-clock", "cell_a": "withdrawEpoch",
            "violators": [{"file": "src/Snapshotter.sol"}]}]
        edges = [e for e in scg._freshness_shared_cursor_edges(ws, fresh_edges=fake_clock)
                 if e.get("kind") == "freshness-coupled-to-shared-cursor"]
        self.assertEqual(edges, [], "cell covered by external-clock lane must be deduped")
        shutil.rmtree(ws, ignore_errors=True)

    @unittest.skipUnless(_POLY_VS.is_file(), "real polygon ws not present")
    def test_natural_instance_polygon(self):
        """Read-only confirmation on the real ws (never mutated)."""
        edges = _sc_edges(_REAL_POLY)
        vs = [e for e in edges
              if e["cell_a"] == "withdrawEpoch"
              and any("ValidatorShare.sol" in v["file"] for v in e["violators"])]
        self.assertTrue(vs, "A12 must fire on the real polygon ValidatorShare withdrawEpoch")
        e = vs[0]
        self.assertEqual(e["cell_b"], "shared-cursor:epoch")
        self.assertEqual(e["evidence"]["cursor_recv"], "stakeManager")
        self.assertIn("__sellVoucher", e["evidence"]["source_writers"])
        self.assertIn("_unstakeClaimTokens", e["evidence"]["sibling_readers"])
        nm = e["evidence"]["nonmonotonic_writer"]
        self.assertEqual(nm["fn"], "setCurrentEpoch")
        self.assertEqual(nm["cursor_cell"], "currentEpoch")
        self.assertIn("StakeManager.sol", nm["file"])

    @unittest.skipUnless(_POLY_VS.is_file() and _POLY_SM.is_file() and _POLY_SMS.is_file(),
                         "real polygon ws not present")
    def test_mutation_verify_on_mkdtemp_copy(self):
        """cp the shared-ws target files to a mkdtemp, inject a behaviour-changing mutation at
        the TARGET line (ValidatorShare.sol:207) and confirm the MUTANT fires (line 207's
        cross-module cursor read makes __sellVoucher a source-writer) while the CLEAN copy (line
        207 neutralized to a non-cursor read) does NOT list __sellVoucher. The shared polygon ws
        is NEVER git-mutated - only the mkdtemp copy."""
        vs_src = _POLY_VS.read_text()
        line207 = "        unbond.withdrawEpoch = stakeManager.epoch();\n"
        self.assertIn(line207, vs_src, "target line 207 present in the real file")
        # CLEAN mutation: strip the cross-module cursor read from line 207 (a non-cursor SSTORE).
        clean_vs = vs_src.replace(line207, "        unbond.withdrawEpoch = unbond.shares;\n", 1)
        self.assertNotEqual(vs_src, clean_vs, "mutation must change the source")

        vsrel = "ValidatorShare.sol"
        smrel = "StakeManager.sol"
        smsrel = "StakeManagerStorage.sol"
        sm_src, sms_src = _POLY_SM.read_text(), _POLY_SMS.read_text()

        def _sellvoucher_is_source(vs_text):
            ws = _mk_ws({vsrel: vs_text, smrel: sm_src, smsrel: sms_src})
            edges = _sc_edges(ws)
            hit = [e for e in edges if e["cell_a"] == "withdrawEpoch"]
            shutil.rmtree(ws, ignore_errors=True)
            return bool(hit) and "__sellVoucher" in hit[0]["evidence"]["source_writers"]

        mutant_fires = _sellvoucher_is_source(vs_src)      # real line 207 = cursor read
        clean_fires = _sellvoucher_is_source(clean_vs)     # neutralized line 207
        self.assertTrue(mutant_fires,
                        "MUTANT: line-207 cursor read makes __sellVoucher a source-writer")
        self.assertFalse(clean_fires,
                         "CLEAN: neutralized line 207 must NOT make __sellVoucher a source-writer")


if __name__ == "__main__":
    unittest.main()
