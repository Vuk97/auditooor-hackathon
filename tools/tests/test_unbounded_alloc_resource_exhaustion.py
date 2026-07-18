#!/usr/bin/env python3
"""unbounded-alloc-resource-exhaustion reasoner - regression + non-vacuity tests.

Pins tools/unbounded-alloc-resource-exhaustion.py: the untrusted-size-taint +
bound-dominance set-difference over alloc / loop / recursion nodes.
  SURVIVORS = { N in alloc/loop/recursion nodes of an entry-fn closure :
                  untrusted_size_taint(size_operand(N))
                  AND NOT bound_dominated(N) }

Matrix (self-contained Solidity/Go string fixtures, no external toolchain):
  - Go make([]T, msg-count)          -> 1 survivor (attacker-sized alloc, no cap).
  - Go make([]T, MAX const)          -> 0 survivors (constant size not untrusted).
  - Go make with a dominating cap     -> 0 survivors (bound-dominated).
  - Sol new bytes[](caller param)     -> 1 survivor (param-sized dynamic-array alloc).
  - Go decoded-length make            -> 1 survivor (binary.BigEndian decoded size).
  - no alloc/loop node                -> substrate_vacuous.

Non-vacuity mutation pair (the REQUIRED test):
  (1) add a size-cap that DOMINATES the alloc (`if n > MAX { return }`) -> survivor
      DISAPPEARS (bound-dominance filter is load-bearing).
  (2) make the size a CONSTANT literal -> survivor DISAPPEARS (untrusted-size-taint
      filter is load-bearing).
"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "unbounded_alloc_resource_exhaustion",
        TOOLS / "unbounded-alloc-resource-exhaustion.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


UAR = _load_tool()


def _run_on(files: dict):
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        src = ws / "src"
        src.mkdir(parents=True)
        for rel, content in files.items():
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return UAR.run(["--workspace", str(ws), "--json"])


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
GO_MSG_MAKE = """package keeper

type MsgSubmit struct{ Count int }
type Keeper struct{}

func (k Keeper) Submit(msg MsgSubmit) error {
    buf := make([]byte, msg.Count)   // attacker-sized alloc, no cap
    _ = buf
    return nil
}
"""

GO_CONST_MAKE = """package keeper

type Keeper struct{}

const MAXBUF = 1024

func (k Keeper) Init() error {
    buf := make([]byte, MAXBUF)   // constant size, not untrusted
    _ = buf
    return nil
}
"""

GO_CAPPED_MAKE = """package keeper

type MsgSubmit struct{ Count int }
type Keeper struct{}

func (k Keeper) Submit(msg MsgSubmit) error {
    if msg.Count > 1000 {          // dominating cap on the size operand
        return errInvalid
    }
    buf := make([]byte, msg.Count)
    _ = buf
    return nil
}
"""

SOL_PARAM_NEWARR = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Alloc {
    function build(uint256 count) external returns (bytes32[] memory) {
        bytes32[] memory out = new bytes32[](count);   // caller-sized alloc, no cap
        return out;
    }
}
"""

GO_DECODED_MAKE = """package keeper

type Keeper struct{}

func (k Keeper) Handle(data []byte) error {
    n := binary.BigEndian.Uint32(data[0:4])   // decoded wire length
    buf := make([]byte, n)                     // decoded-len alloc, no cap
    _ = buf
    return nil
}
"""

# ---- NEGATIVE fixtures (must NOT survive; guard the shape->logic tightening) ----

# A governance member-count sizing a `new T[](count)` + loop. `count` here is a trusted
# governance cardinality (getRoleMemberCount), NOT attacker wire data. The old
# UNANCHORED substring match flagged it because "count" is a substring of
# "getRoleMemberCount"; word-boundary anchoring + the drop-generic-noun rule must send
# it to KEPT(taint-unproven).
SOL_GOV_COUNT_NOT_SURVIVOR = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    function getWhitelist() public view returns (address[] memory) {
        uint256 count = getRoleMemberCount(WHITELISTED_ROLE);
        address[] memory members = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            members[i] = getRoleMember(WHITELISTED_ROLE, i);
        }
        return members;
    }
}
"""

# Iterating a REGISTERED module list (`app.mm.Modules`) inside an internal, non-ingress
# accessor. `app` is the RECEIVER (not a caller param) and the fn is not an external
# message handler; both the receiver-as-param bug and the no-ingress-gate must keep it
# out of the survivor set.
GO_MODULE_LIST_NOT_SURVIVOR = """package app

type AxelarApp struct{ mm ModuleManager }

func (app *AxelarApp) AutoCliOpts() AppOptions {
    modules := make(map[string]AppModule, 0)
    for _, m := range app.mm.Modules {
        _ = m
    }
    _ = modules
    return AppOptions{}
}
"""

# An INTERNAL helper (lowercase name, plain receiver, no msg/ctx signature) whose slice
# is sized by a caller-supplied param. A trusted caller sets `n`; the fn is not an
# external attacker ingress, so the param taint must NOT count it a certain survivor.
GO_INTERNAL_HELPER_PARAM_NOT_SURVIVOR = """package keeper

type Keeper struct{}

func (k Keeper) Warmup() []byte {
    return k.buildBuffer(64)
}

func (k Keeper) buildBuffer(n int) []byte {
    buf := make([]byte, n)   // internal helper, caller-controlled but not attacker
    _ = buf
    return buf
}
"""

# A genuine cosmos msg-server (gRPC ingress) handler whose loop iterates an
# attacker-supplied request collection. This MUST remain a survivor.
GO_MSGSERVER_REQ_SURVIVOR = """package keeper

type msgServer struct{}

func (s msgServer) Register(c context.Context, req *types.MsgRegisterRequest) (*types.MsgRegisterResponse, error) {
    for _, chain := range req.Chains {
        _ = chain
    }
    return nil, nil
}
"""


class TestUnboundedAllocResourceExhaustion(unittest.TestCase):

    def test_go_msg_make_survivor(self):
        s = _run_on({"keeper.go": GO_MSG_MAKE})
        self.assertGreaterEqual(s["n_entry_fns"], 1)
        self.assertEqual(s["n_survivors"], 1, s["survivors"])
        surv = s["survivors"][0]
        self.assertEqual(surv["alloc_kind"], "make-alloc")
        self.assertIn(surv["taint"], ("untrusted-msg", "param", "unbounded-queue"))
        self.assertTrue(surv["entry_fn"].endswith(".Submit"))
        self.assertFalse(s["substrate_vacuous"])

    def test_go_const_make_no_survivor(self):
        s = _run_on({"keeper.go": GO_CONST_MAKE})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertTrue(s["cited_empty"])
        self.assertGreaterEqual(s["n_kept_taint_unproven"], 1)

    def test_go_capped_make_bound_dominated(self):
        s = _run_on({"keeper.go": GO_CAPPED_MAKE})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertGreaterEqual(s["n_kept_bound_dominated"], 1)
        self.assertTrue(s["cited_empty"])

    def test_sol_param_newarray_survivor(self):
        s = _run_on({"Alloc.sol": SOL_PARAM_NEWARR})
        self.assertGreaterEqual(s["n_entry_fns"], 1)
        self.assertEqual(s["n_survivors"], 1, s["survivors"])
        surv = s["survivors"][0]
        self.assertEqual(surv["alloc_kind"], "new-array")
        self.assertEqual(surv["lang"], "sol")

    def test_go_decoded_len_survivor(self):
        s = _run_on({"keeper.go": GO_DECODED_MAKE})
        self.assertEqual(s["n_survivors"], 1, s["survivors"])
        self.assertEqual(s["survivors"][0]["taint"], "decoded-len")

    def test_substrate_vacuous_when_no_alloc_node(self):
        no_alloc = """package keeper
type Keeper struct{}
func (k Keeper) Ping() int { return 1 }
"""
        s = _run_on({"keeper.go": no_alloc})
        self.assertEqual(s["n_alloc_loop_nodes"], 0)
        self.assertTrue(s["substrate_vacuous"])
        self.assertFalse(s["cited_empty"])

    # -------- NEGATIVE tests: shape->logic tightening (FP kills) --------
    def test_gov_member_count_not_survivor(self):
        """A governance member-count sizing an alloc (getRoleMemberCount) is trusted
        cardinality, NOT attacker wire data; unanchored 'count' substring must no longer
        flag it - it falls to KEPT(taint-unproven)."""
        s = _run_on({"Vault.sol": SOL_GOV_COUNT_NOT_SURVIVOR})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertTrue(s["cited_empty"])
        self.assertGreaterEqual(s["n_kept_taint_unproven"], 1)

    def test_registered_module_list_not_survivor(self):
        """Iterating app.mm.Modules in an internal, non-ingress accessor: the receiver is
        not a caller param and the fn is not a message handler -> not a survivor."""
        s = _run_on({"app.go": GO_MODULE_LIST_NOT_SURVIVOR})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertGreaterEqual(s["n_kept_taint_unproven"], 1)

    def test_internal_helper_param_not_survivor(self):
        """A param-sized alloc in an internal (non-ingress) helper is caller-controlled
        but NOT attacker-supplied - the ingress gate must keep it out of survivors."""
        s = _run_on({"keeper.go": GO_INTERNAL_HELPER_PARAM_NOT_SURVIVOR})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertGreaterEqual(s["n_kept_taint_unproven"], 1)

    def test_msgserver_req_collection_survivor(self):
        """A genuine gRPC msg-server handler iterating an attacker-supplied request
        collection MUST remain a survivor (ingress gate does not over-suppress)."""
        s = _run_on({"msg_server.go": GO_MSGSERVER_REQ_SURVIVOR})
        self.assertGreaterEqual(s["n_survivors"], 1, s["survivors"])
        surv = s["survivors"][0]
        self.assertEqual(surv["taint"], "untrusted-msg")
        self.assertTrue(surv["entry_fn"].endswith(".Register"))

    # -------- non-vacuity mutation pair (REQUIRED) --------
    def test_mutate_add_cap_kills_survivor(self):
        """Add a dominating size-cap before the alloc -> the survivor must disappear
        (bound-dominance filter is load-bearing)."""
        base = _run_on({"keeper.go": GO_MSG_MAKE})
        self.assertEqual(base["n_survivors"], 1)

        mutated = GO_MSG_MAKE.replace(
            "    buf := make([]byte, msg.Count)   // attacker-sized alloc, no cap",
            "    if msg.Count > 1000 {\n"
            "        return errInvalid\n"
            "    }\n"
            "    buf := make([]byte, msg.Count)")
        mut = _run_on({"keeper.go": mutated})
        self.assertEqual(mut["n_survivors"], 0,
                         "a dominating size-cap should remove the survivor")
        self.assertGreaterEqual(mut["n_kept_bound_dominated"], 1)

    def test_mutate_constant_size_kills_survivor(self):
        """Replace the attacker-sized operand with a CONSTANT literal -> the survivor
        must disappear (untrusted-size-taint filter is load-bearing)."""
        base = _run_on({"keeper.go": GO_MSG_MAKE})
        self.assertEqual(base["n_survivors"], 1)

        mutated = GO_MSG_MAKE.replace(
            "    buf := make([]byte, msg.Count)   // attacker-sized alloc, no cap",
            "    buf := make([]byte, 256)   // constant size")
        mut = _run_on({"keeper.go": mutated})
        self.assertEqual(mut["n_survivors"], 0,
                         "a constant size is not untrusted -> no survivor")
        self.assertGreaterEqual(mut["n_kept_taint_unproven"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
