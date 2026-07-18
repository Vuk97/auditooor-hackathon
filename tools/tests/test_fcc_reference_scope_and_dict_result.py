#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered via agent-pathspec-register.py -->
"""Guards for the function-coverage-completeness false-red fixes (R91 follow-on).

Three regressions are guarded:

1. reference/ + vendored @openzeppelin are EXCLUDED from the in-scope function
   inventory. A top-level reference/ dir conventionally ships deployed-bytecode
   dumps / decompiled snapshots / vendored OZ copies; coverage-map's scope-file
   mode already excludes them, so the strict gate must too, else it counts
   reference/*.sol as in-scope-untouched and emits a permanent false-red.

2. _parse_nested_sidecar_result accepts ``result`` as EITHER a JSON string (the
   MIMO/haiku scoped-hunt schema) OR an already-parsed dict (the spawn-worker
   Sonnet residual schema). A dict-form result previously returned (None, None),
   suppressing the function_anchor credit.

3. A per-function sidecar whose function_anchor uses the canonical
   {file, function, line} keys (NOT {fn, start_line}) and whose prose cites a
   DEFENDING line in a DIFFERENT in-scope file still credits its OWN anchored
   function (hollow, not untouched).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("fcc_under_test", str(_TOOLS / "function-coverage-completeness.py"))
fcc = importlib.util.module_from_spec(spec)
sys.modules["fcc_under_test"] = fcc  # dataclass string-annotations need the module registered
spec.loader.exec_module(fcc)


class TestReferenceScope(unittest.TestCase):
    def test_reference_and_oz_in_skip_dirs(self):
        self.assertIn("reference", fcc._SKIP_DIRS)
        self.assertIn("@openzeppelin", fcc._SKIP_DIRS)
        self.assertIn("/reference/", fcc._TEST_HINTS)


class TestCosmosSimScope(unittest.TestCase):
    """Cosmos-SDK OOS sim/test infra (x/<module>/simulation/, simapp/, testutil/)
    must be excluded from the in-scope function inventory. NUVA 2026-06-30:
    simulation/operations.go (20) + simapp/app.go (6) + simapp/provenance.go (9)
    were over-counted as in-scope-untouched, a permanent false-red, because this
    gate's own classifier copy lacked the sim markers that scope_exclusion.py has."""

    def test_sim_markers_in_skip_dirs_and_hints(self):
        for d in ("simulation", "simapp", "testutil", "testutils"):
            self.assertIn(d, fcc._SKIP_DIRS, f"{d} must be in _SKIP_DIRS")
        for h in ("/simulation/", "/simapp/", "/testutil/", "/testutils/"):
            self.assertIn(h, fcc._TEST_HINTS, f"{h} must be in _TEST_HINTS")

    def test_sim_go_excluded_keeper_kept(self):
        ws = Path(tempfile.mkdtemp())
        sim = ws / "src" / "vault" / "simulation"
        simapp = ws / "src" / "vault" / "simapp"
        keeper = ws / "src" / "vault" / "keeper"
        for d in (sim, simapp, keeper):
            d.mkdir(parents=True)
        (sim / "operations.go").write_text(
            "package simulation\nfunc SimulateMsgDeposit(ctx sdk.Context) {}\n", encoding="utf-8")
        (simapp / "app.go").write_text(
            "package simapp\nfunc (a *App) RegisterAPIRoutes(ctx sdk.Context) {}\n", encoding="utf-8")
        (keeper / "vault.go").write_text(
            "package keeper\nfunc (k Keeper) ProcessPayout(ctx sdk.Context, amt uint64) {}\n", encoding="utf-8")
        files = {str(p) for p, _ in fcc._iter_source_files(ws)}
        self.assertFalse([f for f in files if "/simulation/" in f],
                         f"simulation/ must be excluded; got {files}")
        self.assertFalse([f for f in files if "/simapp/" in f],
                         f"simapp/ must be excluded; got {files}")
        self.assertTrue([f for f in files if "keeper/vault.go" in f],
                        f"production keeper/ must be kept; got {files}")


class TestGoReadOnlyComputeAndConstructor(unittest.TestCase):
    """NUVA 2026-06-30: Go compute/iterator/constructor fns (Estimate*, Walk*,
    New*) that are PROVABLY zero-write must be dropped as read-only, while a real
    collections-API mutator (Enqueue via p.IndexedMap.Set / p.Sequence.Next) must
    be KEPT in scope. The double-gate is: read-ish NAME AND zero write tokens."""

    def test_estimate_walk_new_are_readonly(self):
        # zero-write bodies, non-getter names -> now read-only
        self.assertTrue(fcc._is_read_only(
            "EstimateSwapIn", "func (k queryServer) EstimateSwapIn(c context.Context) error",
            "go", "vault, err := k.GetVault(ctx); return vault.Quote()"))
        self.assertTrue(fcc._is_read_only(
            "WalkByVault", "func (p *Q) WalkByVault(c context.Context) error",
            "go", "for ; iter.Valid(); iter.Next() { req, _ := p.IndexedMap.Get(ctx, pk) }"))
        self.assertTrue(fcc._is_read_only(
            "NewQueryServer", "func NewQueryServer(k *Keeper) types.QueryServer",
            "go", "return &queryServer{Keeper: k}"))

    def test_collections_mutator_is_kept(self):
        # Enqueue writes via .Set( -> must NOT be read-only even though we widened names
        self.assertFalse(fcc._is_read_only(
            "Enqueue", "func (p *Q) Enqueue(c context.Context) (uint64, error)",
            "go", "id, _ := p.Sequence.Next(ctx); return id, p.IndexedMap.Set(ctx, k, *req)"))
        # a Set-named setter stays kept
        self.assertFalse(fcc._is_read_only(
            "SetMaxInterestRate", "func (v *V) SetMaxInterestRate(r Dec)",
            "go", "v.maxRate = r"))

    def test_validate_stays_in_scope(self):
        # validators are security gates - NOT in the read-only verb set, kept for hunt
        self.assertFalse(fcc._is_read_only(
            "ValidateAcceptedDenom", "func (v *V) ValidateAcceptedDenom(d string) error",
            "go", "if v.IsAcceptedDenom(d) { return nil }; return err"))

    def test_grpc_query_handler_signature_is_readonly(self):
        # entity-named gRPC Query handler (returns *types.QueryXResponse) is read-only
        self.assertTrue(fcc._is_read_only(
            "Vaults",
            "func (k queryServer) Vaults(goCtx context.Context, req *types.QueryVaultsRequest) (*types.QueryVaultsResponse, error)",
            "go", "vaults := k.GetAllVaults(ctx); return &types.QueryVaultsResponse{Vaults: vaults}, nil"))
        # a query handler that WRITES is still kept (zero-write AND-gate)
        self.assertFalse(fcc._is_read_only(
            "Vaults",
            "func (k queryServer) Vaults(c context.Context, r *types.QueryVaultsRequest) (*types.QueryVaultsResponse, error)",
            "go", "k.store.Set(ctx, key, val); return resp, nil"))

    def test_error_iface_and_module_wiring_boilerplate(self):
        for n in ("Error", "Unwrap", "ProvideModule", "AutoCLIOptions"):
            self.assertTrue(fcc._is_nonattack_boilerplate(n, "", "go", ""),
                            f"{n} must be non-attack boilerplate")


class TestDictFormResultParse(unittest.TestCase):
    def test_dict_result_parsed(self):
        obj = {"status": "ok", "result": {"applies_to_target": "no", "candidate_finding": "x"}}
        applies, inner = fcc._parse_nested_sidecar_result(obj)
        self.assertEqual(applies, "no")
        self.assertIsNotNone(inner)

    def test_json_string_result_still_parsed(self):
        obj = {"status": "ok", "result": json.dumps({"applies_to_target": "yes"})}
        applies, inner = fcc._parse_nested_sidecar_result(obj)
        self.assertEqual(applies, "yes")
        self.assertIsNotNone(inner)

    def test_failed_outer_status_rejected(self):
        obj = {"status": "error", "result": {"applies_to_target": "no"}}
        applies, inner = fcc._parse_nested_sidecar_result(obj)
        self.assertIsNone(applies)


class TestAnchorCreditsOwnFunction(unittest.TestCase):
    """End-to-end: a dict-result sidecar with a canonical function_anchor whose
    prose cites a DEFENDING line in a different file credits its OWN function as
    hollow, not untouched."""

    def _ws(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        src = ws / "src" / "ecosystem"
        src.mkdir(parents=True)
        target = src / "ShipmentPlanner.sol"
        # a real STATE-MUTATING external function so the inventory picks it up.
        # NOTE: must NOT be `view`/`pure` - those are now correctly dropped as
        # EVM-guaranteed read-only (no per-function attack surface). The test
        # verifies the anchor-credit mechanism, so it needs a fn that survives
        # the read-only exclusion (a mutator).
        target.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
            "contract ShipmentPlanner {\n"
            "    uint256 public plan;\n"
            "    function getBarnPlan(bytes memory) external returns (uint256) {\n"
            "        plan += 1;\n"
            "        return plan;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        # also a defending lib file referenced by the sidecar prose
        lib = ws / "src" / "libraries"
        lib.mkdir(parents=True)
        (lib / "LibReceiving.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
            "library LibReceiving {\n"
            "    function barnReceive(uint256 a) internal pure returns (uint256) {\n"
            "        return a;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        sd = ws / ".auditooor" / "hunt_findings_sidecars"
        sd.mkdir(parents=True)
        sidecar = {
            "task_id": "residual_fc_b6_0",
            "workspace": "t", "workspace_path": str(ws),
            "function_anchor": {"file": str(target), "function": "getBarnPlan", "line": 5},
            "status": "ok",
            "verification_tier": "tier-2-source-verified",
            "result": {
                "applies_to_target": "no",
                "confidence": "medium",
                "candidate_finding": "subtraction cannot underflow",
                # prose cites a DEFENDING line in a DIFFERENT in-scope file
                "defending_lines": "LibReceiving.sol:4 barnReceive maintains the invariant",
                "attacker_path": "",
            },
        }
        (sd / "residual_fc_sonnet__ShipmentPlanner-getBarnPlan.json").write_text(
            json.dumps(sidecar), encoding="utf-8")
        return ws, target

    def test_anchored_fn_is_hollow_not_untouched(self):
        ws, target = self._ws()
        rep = fcc.evaluate(ws)
        rows = {f["name"]: f["classification"] for f in rep.get("functions", [])}
        self.assertIn("getBarnPlan", rows, f"function not in inventory: {rows}")
        self.assertEqual(rows["getBarnPlan"], "hollow",
                         f"anchored fn must be credited hollow (examined+ruled-out), not {rows['getBarnPlan']}")


class TestBodilessInterfaceDeclExcluded(unittest.TestCase):
    """A bodiless interface/abstract declaration (`function f(...) external;`,
    incl. a multi-line signature) is NOT an implementation - it must be excluded
    from the in-scope function inventory; only the real body is enumerated. Else
    the bare decl is a permanently-hollow phantom (no body to hunt)."""

    def test_bodiless_interface_decls_excluded_impl_kept(self):
        ws = Path(tempfile.mkdtemp())
        f = ws / "src" / "Facet.sol"
        f.parent.mkdir(parents=True)
        f.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
            "interface IInbox {\n"
            "    function createRetryableTicket(\n"
            "        address to,\n"
            "        uint256 callValue,\n"
            "        bytes calldata data\n"
            "    ) external payable returns (uint256);\n"
            "    function cancelPodListing(uint256 i) external;\n"
            "}\n"
            "contract Facet {\n"
            "    function realImpl(uint256 x) external returns (uint256) {\n"
            "        return x + 1;\n"
            "    }\n"
            "    function oneLiner() external { revert(); }\n"
            "}\n",
            encoding="utf-8",
        )
        names = {fn.name for fn in fcc._extract_entry_fns(f, "sol", "src/Facet.sol")}
        self.assertIn("realImpl", names)
        self.assertIn("oneLiner", names)
        self.assertNotIn("createRetryableTicket", names)
        self.assertNotIn("cancelPodListing", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
