#!/usr/bin/env python3
"""R1 HANDLE-FRESHNESS ARM (14th SCG kind "stale-handle-after-recycle") regression.

The READ/HOLD side of a reusable identity handle: a handle correctly unique when ISSUED has its
handle-space slot FREED (pop / swap-pop C[i]=C[len-1] / delete C[k] / _burn / EnumerableSet.remove
/ Table::remove / move_from) and RE-ISSUED to a NEW occupant, and a STALE HOLDER persisted across a
tx/step/epoch resolves the recycled slot BLINDLY (no binding-freshness re-check) into a severity-
eligible sink. The namesake Hexens 'Arbitrary Struct Hijack in Aptos Move VM' 0-day.

DEDUP BOUNDARIES (load-bearing, enforced by construction + emitted-hit dedup):
  vs A4 (write-collision on ISSUANCE): no recycle, no persisted holder -> this arm never fires.
  vs A12 (numeric-cursor MONOTONICITY): a numeric cursor rolling back, not a freed+reissued slot's
    referent IDENTITY -> numeric-cursor holders/containers are skipped (A12's turf) + emitted-hit
    dedup by (file, cell_a) vs the A12 shared-cursor edges passed via prior_edges.
  GENERALIZES backlog M3 (Move-only type-handle) into the cross-language plane.

Non-vacuity (mutating any ONE predicate breaks a case):
  1. VULNERABLE swap-pop container + stored holder id + blind resolve into a transfer sink -> ONE
     stale-handle-after-recycle edge (promotable, value-move sink, violator = the resolving fn).
  2. GREEN: a generation-counter re-validation witness OR a monotonic-never-recycled (append-only)
     container -> SILENT (no edge).
  3. Move type_of/StructNameIndex + move_from -> fires (the namesake specialization).
  4. A4 issuance-collision + A12 numeric-cursor fixtures -> do NOT emit this kind (dedup).
  5. A12 shared-cursor edge sharing (file, cell_a) passed via prior_edges dedups an emitted hit.
  6. UN-ANALYZED: a recyclable-handle holder in an unsupported language (Rust) sets
     unanalyzed_inscope and blocks check_state_coupling ONLY under the dedicated enforce env.
  7. Advisory-first gating: the promotable edge is DEMOTED (advisory) by default, and un-demotes to
     an OPEN edge that fails-closed under AUDITOOOR_HANDLE_FRESHNESS_ENFORCE + AUDITOOOR_L37_STRICT.
"""
import contextlib
import importlib.util
import io
import json
import os
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
scc = _load("state_coupling_completeness_check", "state-coupling-completeness-check.py")


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


# ---- fixtures (well-formed Solidity: one state-var declaration per line) --------------------
_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SlotRegistry {
    struct Item { address owner; uint256 amount; uint256 gen; }
    Item[] public items;                        // handle-space container (array-index handle)
    mapping(address => uint256) public slotOf;  // HOLDER: stored index into items (persisted)
    mapping(address => uint256) public genOf;

    function claim(uint256 amount) external {
        items.push(Item(msg.sender, amount, 0));
        slotOf[msg.sender] = items.length - 1;  // issue + store the holder
    }

    // RECYCLE EVENT: swap-pop frees slot i and MOVES the last item's identity onto it.
    function remove(uint256 i) external {
        items[i] = items[items.length - 1];
        items.pop();
    }

    function withdraw() external {
        uint256 idx = slotOf[msg.sender];       // read the STALE holder
        Item storage it = items[idx];           // BLIND resolve of the recycled slot
        payable(msg.sender).transfer(it.amount); // severity-eligible sink (value-move)
    }
}
"""

# GREEN: a generation-counter re-validation witness before the referent is trusted.
_GREEN_GEN = _VULN.replace(
    "        Item storage it = items[idx];           // BLIND resolve of the recycled slot\n",
    "        Item storage it = items[idx];\n"
    "        require(it.gen == genOf[msg.sender], \"stale\"); // binding-freshness witness\n")

# GREEN: no recycle event anywhere (append-only container) -> monotonic-never-recycled.
_GREEN_APPEND = _VULN.replace(
    "    // RECYCLE EVENT: swap-pop frees slot i and MOVES the last item's identity onto it.\n"
    "    function remove(uint256 i) external {\n"
    "        items[i] = items[items.length - 1];\n"
    "        items.pop();\n"
    "    }\n\n", "")

# Move specialization: cached type_of<T>() tag + move_from<T> recycle + blind type-dispatch.
_MOVE = """module 0x42::vault {
    struct TypeTag has store, drop { id: u64 }
    struct Cache has key { tag: TypeTag }

    public fun cache<T>(a: address) acquires Cache {
        let c = borrow_global_mut<Cache>(a);
        c.tag = TypeTag { id: type_of<T>() };   // cached type-tag / StructNameIndex handle
    }

    public fun recycle<T>(a: address) {
        let _x = move_from<T>(a);               // RECYCLE: frees the referent
    }

    public fun resolve(a: address) acquires Cache {
        let c = borrow_global<Cache>(a);
        dispatch(c.tag);                         // BLIND type-dispatch on the stale tag
    }
}
"""

# A4 issuance-collision (write collision on the SAME fresh handle at mint; NO recycle).
_A4 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract A4 {
    mapping(uint256 => address) public reg;
    uint256 public nextId;

    function mint() external {
        uint256 id = nextId++;
        reg[id] = msg.sender;
    }

    function dup(uint256 id) external {
        reg[id] = msg.sender;   // collision on issuance - A4's turf, not this arm
    }
}
"""

# A12 numeric-cursor snapshot (cross-module epoch); no recyclable container.
_A12 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IE { function epoch() external view returns (uint256); }

contract Snap {
    IE public cursor;
    struct Rec { uint256 withdrawEpoch; uint256 shares; }
    mapping(address => Rec) public recs;

    function open(uint256 s) external {
        Rec memory r = recs[msg.sender];
        r.shares = s;
        r.withdrawEpoch = cursor.epoch();
        recs[msg.sender] = r;
    }

    function settle() external {
        Rec memory r = recs[msg.sender];
        require(r.withdrawEpoch + 10 <= cursor.epoch(), "w");
        r.shares = 0;
        recs[msg.sender] = r;
    }
}
"""

# UNSUPPORTED language (Rust): a recycle op (swap_remove) + a persisted-handle field (slot_idx).
_RUST = """struct Registry { slots: Vec<Item> }
struct Holder { slot_idx: usize }
impl Registry {
    fn remove(&mut self, i: usize) { self.slots.swap_remove(i); }
    fn resolve(&self, h: &Holder) -> &Item { &self.slots[h.slot_idx] }
}
fn store(h: &mut Holder, i: usize) { h.slot_idx = i; }
"""


def _hf(ws, **kw):
    scg._SOL_SVAR_CACHE.clear()
    return [e for e in scg._handle_freshness_edges(ws, **kw)
            if e.get("kind") == "stale-handle-after-recycle"]


class HandleFreshnessArm(unittest.TestCase):

    def test_vulnerable_fires_once(self):
        ws = _mk_ws({"src/SlotRegistry.sol": _VULN})
        edges = _hf(ws)
        self.assertEqual(len(edges), 1, "stale holder resolving a recycled swap-pop slot into a "
                                        "transfer sink must fire exactly once")
        e = edges[0]
        self.assertEqual(e["cell_a"], "holder:slotOf")
        self.assertEqual(e["cell_b"], "handle-space:items")
        self.assertEqual(e["impact_class"], "stale-handle-referent-desync")
        self.assertEqual(e["language"], "solidity")
        self.assertIn("withdraw", [v["fn"] for v in e["violators"]])
        self.assertIn("remove", e["writers_b"])            # the recycle-event writer
        self.assertIn("claim", e["writers_a"])             # the issuance/store site
        ev = e["evidence"]
        self.assertEqual(ev["tier"], "handle-freshness")
        self.assertEqual(ev["verdict"], "needs-fuzz")
        self.assertTrue(ev["advisory"])
        self.assertFalse(ev["auto_credit"])
        self.assertTrue(ev["promotable"], "state-var holder + container + value-move sink = 3-leg")
        self.assertEqual(ev["sink_class"], "value-move")
        self.assertTrue(ev["revalidation_absent"])
        ok, errs = scs.validate(e)
        self.assertTrue(ok, errs)
        shutil.rmtree(ws, ignore_errors=True)

    def test_generation_witness_is_green(self):
        ws = _mk_ws({"src/SlotRegistry.sol": _GREEN_GEN})
        self.assertEqual(_hf(ws), [], "a generation-counter re-validation witness must stay GREEN")
        shutil.rmtree(ws, ignore_errors=True)

    def test_append_only_container_is_green(self):
        ws = _mk_ws({"src/SlotRegistry.sol": _GREEN_APPEND})
        self.assertEqual(_hf(ws), [], "a monotonic-never-recycled (append-only) container is GREEN")
        shutil.rmtree(ws, ignore_errors=True)

    def test_move_type_handle_fires(self):
        ws = _mk_ws({"sources/vault.move": _MOVE})
        edges = _hf(ws)
        self.assertEqual(len(edges), 1, "cached type_of + move_from + type-dispatch = the namesake "
                                        "Move struct-hijack must fire")
        e = edges[0]
        self.assertEqual(e["language"], "move")
        self.assertEqual(e["cell_a"], "holder:type-tag")
        self.assertEqual(e["cell_b"], "handle-space:type-table")
        self.assertIn("move_from", e["evidence"]["recycle_op"])
        ok, errs = scs.validate(e)
        self.assertTrue(ok, errs)
        shutil.rmtree(ws, ignore_errors=True)

    def test_a4_issuance_collision_does_not_emit(self):
        # DEDUP vs A4: a pure write-collision on ISSUANCE (no recycle, no persisted holder resolve)
        # is A4's turf; this READ/HOLD-side arm must never fire on it.
        ws = _mk_ws({"src/A4.sol": _A4})
        self.assertEqual(_hf(ws), [], "A4 issuance-collision must not emit a stale-handle edge")
        shutil.rmtree(ws, ignore_errors=True)

    def test_a12_numeric_cursor_does_not_emit(self):
        # DEDUP vs A12: a numeric-cursor snapshot (no recyclable container) is A12's turf.
        ws = _mk_ws({"src/Snap.sol": _A12})
        self.assertEqual(_hf(ws), [], "A12 numeric-cursor fixture must not emit a stale-handle edge")
        shutil.rmtree(ws, ignore_errors=True)

    def test_a12_prior_edge_dedups_emitted_hit(self):
        # A1 boundary: an A12 shared-cursor edge sharing (file, cell_a) suppresses the emitted hit.
        ws = _mk_ws({"src/SlotRegistry.sol": _VULN})
        fake_a12 = [{"kind": "freshness-coupled-to-shared-cursor", "cell_a": "holder:slotOf",
                     "violators": [{"file": "src/SlotRegistry.sol"}]}]
        self.assertEqual(_hf(ws, prior_edges=fake_a12), [],
                         "an A12 edge covering (file, cell_a) must dedup the emitted hit")
        # sanity: without the prior edge it DOES fire (the dedup is doing real work).
        self.assertEqual(len(_hf(ws)), 1)
        shutil.rmtree(ws, ignore_errors=True)

    def test_unanalyzed_unsupported_language_sets_flag(self):
        ws = _mk_ws({"src/registry.rs": _RUST})
        edges = _hf(ws)
        self.assertEqual(edges, [], "the arm has no Rust parser -> emits no edge")
        acct = json.loads((ws / ".auditooor" / "state_coupling_handle_freshness.json").read_text())
        self.assertTrue(acct["unanalyzed_inscope"],
                        "a recyclable-handle holder in an unsupported language must be flagged")
        self.assertTrue(any("registry.rs" in ex.get("file", "") for ex in acct["unanalyzed_examples"]))
        shutil.rmtree(ws, ignore_errors=True)

    def test_schema_registers_kind_and_impact(self):
        self.assertIn("stale-handle-after-recycle", scs.COUPLING_KINDS)
        self.assertEqual(scs.KIND_IMPACT["stale-handle-after-recycle"],
                         "stale-handle-referent-desync")


class _EnvGuard:
    """Save/restore the SCG + L37 env so a strict/enforce test never leaks into a sibling test."""
    _KEYS = ("SCG_HANDLE_FRESHNESS", "AUDITOOOR_HANDLE_FRESHNESS_ENFORCE",
             "AUDITOOOR_L37_STRICT", "AUDITOOOR_SCG_SUBTYPES_STRICT",
             "SCG_SHARED_CURSOR", "SCG_INTERRUPTION", "SCG_XCONTRACT")

    def __init__(self, env):
        self.env = env
        self.saved = {}

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self._KEYS}
        for k in self._KEYS:
            os.environ.pop(k, None)
        os.environ.update(self.env)
        return self

    def __exit__(self, *a):
        for k in self._KEYS:
            os.environ.pop(k, None)
        for k, v in self.saved.items():
            if v is not None:
                os.environ[k] = v


class HandleFreshnessGating(unittest.TestCase):
    """The advisory-first-but-ENFORCED contract through state-coupling-completeness-check."""

    def _run(self, env, files):
        with _EnvGuard(env):
            ws = _mk_ws(files)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = scc.main(["--workspace", str(ws), "--json"])
            res = json.loads((ws / ".auditooor" / "state_coupling_completeness.json").read_text())
            shutil.rmtree(ws, ignore_errors=True)
            return rc, res

    def test_advisory_by_default(self):
        # arm ON (emits + feeds the hunt), but the promotable edge is DEMOTED - it never gates.
        rc, res = self._run({"SCG_HANDLE_FRESHNESS": "1"}, {"s.sol": _VULN})
        self.assertEqual(rc, 0)
        self.assertEqual(res["verdict"], "pass-state-coupling-completeness")
        self.assertEqual(res["open_edges"], 0)
        self.assertGreaterEqual(res["advisory_edges"], 1, "the stale-handle edge is emitted advisory")

    def test_enforced_under_dedicated_env(self):
        # AUDITOOOR_HANDLE_FRESHNESS_ENFORCE un-demotes the 3-leg edge to an OPEN promotable edge;
        # the strict L37 umbrella turns it into a fail-closed rc=1.
        rc, res = self._run(
            {"SCG_HANDLE_FRESHNESS": "1", "AUDITOOOR_HANDLE_FRESHNESS_ENFORCE": "1",
             "AUDITOOOR_L37_STRICT": "1"}, {"s.sol": _VULN})
        self.assertEqual(rc, 1, "a strong-witness stale-handle edge must fail-closed under the "
                                "dedicated enforce env + strict L37")
        self.assertEqual(res["verdict"], "fail-state-coupling-open")
        self.assertEqual(res["open_edges"], 1)


class HandleFreshnessUnanalyzedGate(unittest.TestCase):
    """The un-analyzed anti-silent-suppression block through check_state_coupling (audit-complete)."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("_acc_hf", _T / "audit-completeness-check.py")
        cls.acc = importlib.util.module_from_spec(spec)
        sys.modules["_acc_hf"] = cls.acc
        spec.loader.exec_module(cls.acc)

    def _ok(self, env):
        with _EnvGuard(env):
            ws = _mk_ws({"src/registry.rs": _RUST})
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                r = self.acc.check_state_coupling(ws)
            shutil.rmtree(ws, ignore_errors=True)
            return r.ok, bool(r.detail.get("handle_freshness_unanalyzed_inscope"))

    def test_advisory_default_does_not_block(self):
        ok, flagged = self._ok({})
        self.assertTrue(ok, "un-analyzed is advisory by default (no fleet false-RED)")
        self.assertTrue(flagged, "the un-analyzed recyclable-handle holder is still recorded")

    def test_plain_strict_without_dedicated_env_does_not_block(self):
        # advisory-first: plain L37 STRICT must NOT block until the arm is fleet-validated.
        ok, flagged = self._ok({"AUDITOOOR_L37_STRICT": "1"})
        self.assertTrue(ok)
        self.assertTrue(flagged)

    def test_strict_plus_dedicated_env_blocks(self):
        ok, flagged = self._ok({"AUDITOOOR_L37_STRICT": "1", "AUDITOOOR_HANDLE_FRESHNESS_ENFORCE": "1"})
        self.assertFalse(ok, "a STARVED handle-freshness arm must not masquerade as a clean 0")
        self.assertTrue(flagged)


if __name__ == "__main__":
    unittest.main()
