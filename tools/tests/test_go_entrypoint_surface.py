#!/usr/bin/env python3
"""Regression: Go/Cosmos external entry-surface narrowing of the function-coverage gate.

Two layers:
  (A) unit tests of tools/go_entrypoint_surface.py - the classifier that decides
      whether a Go function is a TRUE external entry point (msg-server / ABCI /
      precompile / ante / IBC / genesis / hooks / ValidateBasic) vs an internal
      helper (the Go analog of a Solidity ``internal`` fn).
  (B) an END-TO-END integration test that builds a tiny synthetic Cosmos-Go
      workspace on disk and runs ``function-coverage-completeness.evaluate`` over
      it, asserting the denominator is narrowed to entry points, helpers are
      excluded (and COUNTED, not silently dropped), and - the never-false-pass
      guarantees - a non-Cosmos Go ws and a Solidity ws are BYTE-IDENTICAL to the
      pre-change every-exported behavior.

These assertions FAIL if the narrowing (a) drops a real entry point, (b) silently
empties the denominator, (c) leaks into a non-Cosmos / Solidity workspace, or (d)
promotes proto/Msg boilerplate (Type/Route/GetSigners) to attack surface.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

import go_entrypoint_surface as G  # noqa: E402


def _load_fcc():
    spec = importlib.util.spec_from_file_location(
        "fcc_mod", str(_TOOLS / "function-coverage-completeness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fcc_mod"] = mod  # register so @dataclass can resolve module
    spec.loader.exec_module(mod)
    return mod


class ClassifierEntryFamiliesTest(unittest.TestCase):
    """Every real external entry-point family classifies as entry (True)."""

    _ENTRY = [
        # (name, receiver, rel_path, sig)
        ("EVMTransaction", "msgServer", "x/evm/keeper/msg_server.go",
         "func (server msgServer) EVMTransaction(goCtx context.Context, msg *types.MsgEVMTransaction) (*types.MsgEVMTransactionResponse, error)"),
        # handler on a non-msgServer receiver caught by the Response return:
        ("Vote", "k", "x/oracle/keeper/msg_server.go",
         "func (k keeperImpl) Vote(c context.Context, m *types.MsgVote) (*types.MsgVoteResponse, error)"),
        ("BeginBlock", "App", "app/abci.go", "func (app *App) BeginBlock("),
        ("EndBlock", "App", "app/abci.go", "func (app *App) EndBlock("),
        ("CheckTx", "App", "app/abci.go", "func (app *App) CheckTx("),
        ("PrepareProposal", "App", "app/abci.go", "func (app *App) PrepareProposal("),
        ("AnteHandle", "PriorityDecorator", "app/antedecorators/priority.go",
         "func (pd PriorityDecorator) AnteHandle("),
        ("OnRecvPacket", "IBCModule", "sei-ibc-go/modules/apps/transfer/ibc_module.go",
         "func (im IBCModule) OnRecvPacket("),
        ("InitGenesis", "", "x/oracle/genesis.go", "func InitGenesis("),
        ("BeginBlocker", "", "x/mint/abci.go", "func BeginBlocker("),
        ("ValidateBasic", "MsgSend", "x/bank/types/msgs.go",
         "func (msg *MsgSend) ValidateBasic() error"),
        ("Execute", "PrecompileExecutor", "precompiles/bank/bank.go",
         "func (p PrecompileExecutor) Execute("),
        ("RequiredGas", "PrecompileExecutor", "precompiles/bank/bank.go",
         "func (p PrecompileExecutor) RequiredGas("),
        # anything under precompiles/ (boundary package, over-inclusive = safe):
        ("EVMKeeper", "PrecompileExecutor", "precompiles/bank/bank.go",
         "func (p PrecompileExecutor) EVMKeeper() putils.EVMKeeper"),
    ]

    def test_entry_families_all_classify_entry(self):
        for name, rv, rel, sig in self._ENTRY:
            self.assertTrue(
                G.is_go_entry_point(name, rv, rel, sig),
                f"{name} ({rv} @ {rel}) must be an entry point")


class ClassifierInternalHelperTest(unittest.TestCase):
    """Internal helpers + proto/Msg boilerplate classify as NOT-entry (False)."""

    _INTERNAL = [
        # exported *Keeper helpers in a boundary file are internal (Solidity-internal
        # analog) - the real handlers there are on the msgServer receiver.
        ("GetGasPool", "Keeper", "x/evm/keeper/msg_server.go",
         "func (k *Keeper) GetGasPool() core.GasPool"),
        ("PrepareCtxForEVMTransaction", "Keeper", "x/evm/keeper/msg_server.go",
         "func (k *Keeper) PrepareCtxForEVMTransaction("),
        ("CalculateReward", "Keeper", "x/mint/keeper/reward.go",
         "func (k Keeper) CalculateReward(ctx sdk.Context) sdk.Int"),
        ("NewKeeper", "", "x/evm/keeper/keeper.go", "func NewKeeper(...) *Keeper"),
        # proto/Msg boilerplate: mentions MsgSend but is NOT a handler (no Response).
        ("Type", "MsgSend", "x/bank/types/msgs.go", "func (msg MsgSend) Type() string"),
        ("Route", "MsgSend", "x/bank/types/msgs.go", "func (msg MsgSend) Route() string"),
        ("GetSigners", "MsgSend", "x/bank/types/msgs.go",
         "func (msg *MsgSend) GetSigners() []sdk.AccAddress"),
        # go-ethereum EVM tracer hooks / service lifecycle - internal callbacks.
        ("OnStart", "BaseService", "sei-tendermint/libs/service/service.go",
         "func (bs *BaseService) OnStart() error"),
        ("OnBalanceChange", "hooked", "core/vm/logger.go",
         "func (h *hooked) OnBalanceChange(a common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason)"),
    ]

    def test_internal_helpers_not_entry(self):
        for name, rv, rel, sig in self._INTERNAL:
            self.assertFalse(
                G.is_go_entry_point(name, rv, rel, sig),
                f"{name} ({rv} @ {rel}) must be an internal helper (not entry)")

    def test_receiver_extractor(self):
        self.assertEqual(G.extract_go_receiver("func (server msgServer) EVMTransaction("), "msgServer")
        self.assertEqual(G.extract_go_receiver("func (app *App) BeginBlock("), "App")
        self.assertEqual(G.extract_go_receiver("func NewKeeper(k Keeper) *Keeper {"), "")


class WorkspaceDetectAndFailOpenTest(unittest.TestCase):
    def _write(self, root: Path, rel: str, body: str):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_cosmos_gomod_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "src/chain/go.mod",
                        "module x\n\nrequire github.com/cosmos/cosmos-sdk v0.47.0\n")
            self.assertTrue(G.is_cosmos_go_workspace(root))

    def test_plain_go_not_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "svc/go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
            self._write(root, "svc/main.go", "package main\nfunc Handler(){}\n")
            self.assertFalse(G.is_cosmos_go_workspace(root))

    def test_env_kill_switch(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "src/chain/go.mod",
                        "module x\n\nrequire github.com/cosmos/cosmos-sdk v0.47.0\n")
            old = os.environ.get(G._ENV_DISABLE)
            try:
                os.environ[G._ENV_DISABLE] = "0"
                G._WS_COSMOS_CACHE.clear()
                self.assertFalse(G.is_cosmos_go_workspace(root),
                                 "kill-switch must disable narrowing (fail-open)")
            finally:
                if old is None:
                    os.environ.pop(G._ENV_DISABLE, None)
                else:
                    os.environ[G._ENV_DISABLE] = old
                G._WS_COSMOS_CACHE.clear()


class GateIntegrationTest(unittest.TestCase):
    """End-to-end: evaluate() over synthetic workspaces."""

    def _write(self, root: Path, rel: str, body: str):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def _cosmos_ws(self, d: str) -> Path:
        root = Path(d)
        self._write(root, "src/chain/go.mod",
                    "module chain\n\nrequire github.com/cosmos/cosmos-sdk v0.47.0\n")
        # one real msg-server handler + several internal helpers
        # 1 real handler (entry) + 2 exported non-getter Keeper helpers (internal;
        # they mutate state so the read-only drop does NOT swallow them - they are
        # excluded specifically by the entry-surface narrowing).
        self._write(root, "src/chain/x/mymod/keeper/msg_server.go", (
            "package keeper\n"
            "func (server msgServer) DoThing(goCtx context.Context, msg *types.MsgDoThing) "
            "(*types.MsgDoThingResponse, error) { return nil, nil }\n"
            "func (k *Keeper) ComputeAndStore(ctx sdk.Context) int { k.store.Set(k, v); return 1 }\n"
            "func (k *Keeper) ProcessInternal(ctx sdk.Context) int { k.store.Set(a, b); return 3 }\n"
        ))
        self._write(root, "src/chain/app/abci.go", (
            "package app\n"
            "func (app *App) BeginBlock(ctx sdk.Context) {}\n"
        ))
        return root

    def test_cosmos_ws_narrows_and_counts(self):
        fcc = _load_fcc()
        G._WS_COSMOS_CACHE.clear()
        with tempfile.TemporaryDirectory() as d:
            root = self._cosmos_ws(d)
            res = fcc.evaluate(root)
            c = res.get("counts", {})
            # entry points = DoThing (msg handler) + BeginBlock (ABCI) = 2.
            # helpers = helperCompute (lowercase, not even exported) is dropped
            # earlier; GetSomething + AnotherInternal are exported Keeper helpers
            # -> excluded as internal (>=2 excluded).
            self.assertTrue(res.get("go_entry_surface", {}).get("applied"),
                            "narrowing must apply on a cosmos-go ws")
            names = {f["name"] for f in res.get("functions", [])}
            self.assertEqual(names, {"DoThing", "BeginBlock"},
                             f"denominator must be the entry points only, got {names}")
            self.assertEqual(c.get("total"), 2)
            self.assertGreaterEqual(c.get("go_internal_helpers_excluded", 0), 2,
                                    "the 2 exported Keeper helpers must be COUNTED as excluded")

    def test_non_cosmos_go_ws_unchanged(self):
        """A plain Go ws keeps every-exported (fail-open) - narrowing must NOT apply."""
        fcc = _load_fcc()
        G._WS_COSMOS_CACHE.clear()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "svc/go.mod", "module svc\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
            self._write(root, "svc/handlers.go", (
                "package svc\n"
                "func ExportedA() {}\n"
                "func ExportedB() {}\n"
                "func (s *Server) DoWork() int { return 1 }\n"
            ))
            res = fcc.evaluate(root)
            self.assertFalse(res.get("go_entry_surface", {}).get("applied"),
                             "narrowing must NOT apply on a non-cosmos Go ws")
            # every-exported behavior is preserved: all 3 exported fns stay counted
            # (none is narrowed out as an internal helper). This is the fail-open
            # guarantee - a non-Cosmos Go ws is byte-identical to the old behavior.
            names = {f["name"] for f in res.get("functions", [])}
            self.assertEqual(names, {"ExportedA", "ExportedB", "DoWork"})

    def test_solidity_ws_byte_identical(self):
        """A Solidity ws is untouched: narrowing never applies, entry_point stays True."""
        fcc = _load_fcc()
        G._WS_COSMOS_CACHE.clear()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "src/Vault.sol", (
                "pragma solidity ^0.8.0;\n"
                "contract Vault {\n"
                "  function deposit(uint256 a) external {}\n"
                "  function withdraw(uint256 a) public {}\n"
                "  function _internal() internal {}\n"
                "}\n"
            ))
            res = fcc.evaluate(root)
            self.assertFalse(res.get("go_entry_surface", {}).get("applied"))
            # external+public only (Solidity's own entry filter), internal excluded
            names = {f["name"] for f in res.get("functions", [])}
            self.assertEqual(names, {"deposit", "withdraw"})


class _FakeFn:
    """Minimal duck-typed stand-in for the fcc Fn dataclass (name/file/line/
    classification/end_line) for the collection-level lever tests."""
    def __init__(self, name, file, line=1, classification="untouched", end_line=0):
        self.name = name
        self.file = file
        self.line = line
        self.classification = classification
        self.end_line = end_line


class PrecompileDedupTest(unittest.TestCase):
    """LEVER 1 - precompile version-dedup + non-dispatch accessor drop."""

    def test_dedup_collapses_versions_and_drops_accessors(self):
        fns = [
            # live bank dispatch surface (kept once each)
            _FakeFn("Execute", "precompiles/bank/bank.go", 10),
            _FakeFn("RequiredGas", "precompiles/bank/bank.go", 20),
            # per-version legacy DUPLICATES of the same dispatch (dropped)
            _FakeFn("Execute", "precompiles/bank/legacy/v605/bank.go", 10),
            _FakeFn("RequiredGas", "precompiles/bank/legacy/v605/bank.go", 20),
            _FakeFn("Execute", "precompiles/bank/legacy/v580/bank.go", 10),
            # non-dispatch accessors under a precompile WITH dispatch (dropped)
            _FakeFn("EVMKeeper", "precompiles/bank/bank.go", 30),
            _FakeFn("Address", "precompiles/bank/bank.go", 40),
            _FakeFn("GetABI", "precompiles/bank/bank.go", 50),
            # a NON-precompile fn must pass through untouched
            _FakeFn("BeginBlock", "app/abci.go", 5),
        ]
        kept, detail = G.dedup_precompile_entry_points(fns)
        names_files = {(f.name, f.file) for f in kept}
        self.assertIn(("Execute", "precompiles/bank/bank.go"), names_files)
        self.assertIn(("RequiredGas", "precompiles/bank/bank.go"), names_files)
        self.assertIn(("BeginBlock", "app/abci.go"), names_files)
        # accessors + legacy dups dropped:
        self.assertNotIn(("EVMKeeper", "precompiles/bank/bank.go"), names_files)
        self.assertNotIn(("Address", "precompiles/bank/bank.go"), names_files)
        self.assertNotIn(("Execute", "precompiles/bank/legacy/v605/bank.go"), names_files)
        self.assertEqual(detail["dropped_version_legacy_duplicates"], 3)
        self.assertEqual(detail["dropped_non_dispatch_accessors"], 3)
        # bank Execute+RequiredGas + BeginBlock kept = 3 total
        self.assertEqual(len(kept), 3)

    def test_net_new_dispatch_in_version_dir_kept(self):
        """A dispatch method that exists ONLY in a version dir (no live copy) is
        still kept once (bias-to-include on the dispatch surface)."""
        fns = [
            _FakeFn("Execute", "precompiles/gov/gov.go", 10),
            # a net-new dispatch only in a legacy dir - kept once
            _FakeFn("Run", "precompiles/gov/legacy/v65/gov.go", 99),
        ]
        kept, _ = G.dedup_precompile_entry_points(fns)
        kept_names = {f.name for f in kept}
        self.assertIn("Execute", kept_names)
        self.assertIn("Run", kept_names, "net-new dispatch in a version dir is kept")

    def test_no_dispatch_precompile_keeps_one_fallback(self):
        """A precompile with NO recognised dispatch method keeps ONE accessor
        (never dropped to zero surface = never-false-pass fallback)."""
        fns = [
            _FakeFn("BankK", "precompiles/utils/utils.go", 10),
            _FakeFn("EVMK", "precompiles/utils/utils.go", 20),
        ]
        kept, detail = G.dedup_precompile_entry_points(fns)
        self.assertEqual(len(kept), 1, "one fallback unit kept for a no-dispatch precompile")
        self.assertEqual(detail["no_dispatch_fallback_groups"], 1)

    def test_no_precompiles_is_noop(self):
        fns = [_FakeFn("BeginBlock", "app/abci.go", 5),
               _FakeFn("EndBlock", "app/abci.go", 9)]
        kept, detail = G.dedup_precompile_entry_points(fns)
        self.assertEqual(len(kept), 2)
        self.assertFalse(detail["applied"])


class ForkDeltaPruneTest(unittest.TestCase):
    """LEVER 2 - drop PROVEN-unmodified-upstream fork entry fns; FAIL OPEN otherwise."""

    def test_drops_unmodified_keeps_modified(self):
        fns = [
            _FakeFn("Commit", "src/go-ethereum/core/genesis.go", 10),   # unmodified
            _FakeFn("Run", "src/go-ethereum/core/vm/evm.go", 20),       # modified
            _FakeFn("DoThing", "x/mymod/keeper/msg_server.go", 5),      # non-fork
        ]

        def fake_fork_scope(ws, rows):
            # simulate _apply_fork_scope: keep only the modified file + non-fork rows
            modified = {"src/go-ethereum/core/vm/evm.go"}
            kept = [r for r in rows
                    if (not r["file"].startswith("src/go-ethereum/"))
                    or r["file"] in modified]
            return kept, {"applied": True, "forks": [{"local_name": "go-ethereum"}]}

        kept, detail = G.prune_unmodified_fork_entry_points(None, fns, fake_fork_scope)
        kept_files = {f.file for f in kept}
        self.assertIn("src/go-ethereum/core/vm/evm.go", kept_files)   # modified kept
        self.assertIn("x/mymod/keeper/msg_server.go", kept_files)     # non-fork kept
        self.assertNotIn("src/go-ethereum/core/genesis.go", kept_files)  # unmodified dropped
        self.assertEqual(detail["removed"], 1)

    def test_fail_open_when_not_applied(self):
        """No fork_bases / degraded resolution -> KEEP ALL (larger denominator)."""
        fns = [_FakeFn("Commit", "src/go-ethereum/core/genesis.go", 10)]

        def fake_no_forkbases(ws, rows):
            return rows, {"applied": False, "reason": "no-fork_bases.json"}

        kept, detail = G.prune_unmodified_fork_entry_points(None, fns, fake_no_forkbases)
        self.assertEqual(len(kept), 1, "fail-open keeps all fork fns")
        self.assertEqual(detail["removed"], 0)
        self.assertFalse(detail["applied"])

    def test_fail_open_when_no_helper(self):
        fns = [_FakeFn("Commit", "src/go-ethereum/core/genesis.go", 10)]
        kept, detail = G.prune_unmodified_fork_entry_points(None, fns, None)
        self.assertEqual(len(kept), 1)
        self.assertFalse(detail["applied"])

    def test_fork_scope_exception_fails_open(self):
        fns = [_FakeFn("Commit", "src/go-ethereum/core/genesis.go", 10)]

        def boom(ws, rows):
            raise RuntimeError("clone blew up")

        kept, detail = G.prune_unmodified_fork_entry_points(None, fns, boom)
        self.assertEqual(len(kept), 1, "an exception must fail open (keep all)")
        self.assertFalse(detail["applied"])


class ClosureCreditTest(unittest.TestCase):
    """LEVER 3 - credit an entry fn covered when reachable from a covered entry fn
    over the REAL (proven) Go call graph; no false collision; no graph => no-op."""

    def _path(self, chain):
        """chain = list of (fn_qual, file); build a DefUsePath-shaped record."""
        src = {"fn": chain[0][0], "file": chain[0][1], "line": 1}
        sink = {"fn": chain[-1][0], "file": chain[-1][1], "line": 1}
        hops = [{"fn": f, "file": fl, "via": "internal_call"} for (f, fl) in chain[1:-1]]
        return {"language": "go", "degraded": False,
                "source": src, "sink": sink, "hops": hops}

    def test_reachable_helper_credited(self):
        fns = [
            _FakeFn("EVMTransaction", "x/evm/keeper/msg_server.go", 10,
                    classification="real-attack"),
            _FakeFn("ApplyEVMMessage", "x/evm/keeper/msg_server.go", 60,
                    classification="untouched"),
        ]
        # real path: EVMTransaction -> ApplyEVMMessage (proven edge)
        paths = [self._path([
            ("github.com/sei/x/evm/keeper.(*msgServer).EVMTransaction",
             "/abs/x/evm/keeper/msg_server.go"),
            ("github.com/sei/x/evm/keeper.(*Keeper).ApplyEVMMessage",
             "/abs/x/evm/keeper/msg_server.go"),
        ])]
        credited, detail = G.credit_closure_reachable(
            fns, paths, lambda f: f.classification == "real-attack")
        credited_names = {f.name for f in credited}
        self.assertIn("ApplyEVMMessage", credited_names)
        self.assertEqual(detail["credited"], 1)

    def test_unreachable_not_credited(self):
        fns = [
            _FakeFn("EVMTransaction", "x/evm/keeper/msg_server.go", 10,
                    classification="real-attack"),
            _FakeFn("UnrelatedFn", "x/other/keeper/foo.go", 5,
                    classification="untouched"),
        ]
        # a path that does NOT connect the covered fn to UnrelatedFn
        paths = [self._path([
            ("pkg.SomethingElse", "/abs/x/misc/a.go"),
            ("pkg.AlsoElse", "/abs/x/misc/b.go"),
        ])]
        credited, _ = G.credit_closure_reachable(
            fns, paths, lambda f: f.classification == "real-attack")
        self.assertEqual(len(credited), 0, "no path from covered fn => no credit")

    def test_no_false_collision_on_same_basename_diff_file(self):
        """Two fns share a basename (Run) but live in different files; a covered
        Run in file A must NOT credit an untouched Run in unrelated file B."""
        fns = [
            _FakeFn("Run", "precompiles/bank/bank.go", 10, classification="real-attack"),
            _FakeFn("Run", "src/go-ethereum/common/mclock/simclock.go", 20,
                    classification="untouched"),
        ]
        # the only path is internal to bank - does NOT reach the go-ethereum Run.
        paths = [self._path([
            ("github.com/sei/precompiles/bank.(*PrecompileExecutor).Run",
             "/abs/precompiles/bank/bank.go"),
            ("github.com/sei/precompiles/bank.(*PrecompileExecutor).handle",
             "/abs/precompiles/bank/bank.go"),
        ])]
        credited, _ = G.credit_closure_reachable(
            fns, paths, lambda f: f.classification == "real-attack")
        credited_files = {f.file for f in credited}
        self.assertNotIn("src/go-ethereum/common/mclock/simclock.go", credited_files,
                         "same-basename fn in an unrelated file must not be credited")

    def test_no_graph_is_noop(self):
        fns = [_FakeFn("EVMTransaction", "x/evm/keeper/msg_server.go", 10,
                       classification="real-attack")]
        credited, detail = G.credit_closure_reachable(
            fns, [], lambda f: f.classification == "real-attack")
        self.assertEqual(len(credited), 0)
        self.assertFalse(detail["applied"])

    def test_degraded_records_ignored(self):
        fns = [
            _FakeFn("A", "x/m/a.go", 1, classification="real-attack"),
            _FakeFn("B", "x/m/b.go", 1, classification="untouched"),
        ]
        paths = [{"language": "go", "degraded": True,
                  "source": {"fn": "pkg.A", "file": "/abs/x/m/a.go"},
                  "sink": {"fn": "pkg.B", "file": "/abs/x/m/b.go"}, "hops": []}]
        credited, detail = G.credit_closure_reachable(
            fns, paths, lambda f: f.classification == "real-attack")
        self.assertEqual(len(credited), 0, "degraded records must not build edges")

    def test_non_go_records_ignored(self):
        fns = [
            _FakeFn("A", "x/m/a.go", 1, classification="real-attack"),
            _FakeFn("B", "x/m/b.go", 1, classification="untouched"),
        ]
        paths = [{"language": "solidity", "degraded": False,
                  "source": {"fn": "A", "file": "/abs/x/m/a.go"},
                  "sink": {"fn": "B", "file": "/abs/x/m/b.go"}, "hops": []}]
        credited, _ = G.credit_closure_reachable(
            fns, paths, lambda f: f.classification == "real-attack")
        self.assertEqual(len(credited), 0, "non-go records must not build edges")


if __name__ == "__main__":
    unittest.main()
