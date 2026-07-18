from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEMANTIC = ROOT / "tools" / "semantic-graph.py"
DOSSIER_CLI = ROOT / "tools" / "production-path-dossier.py"
LIB = ROOT / "tools" / "lib" / "production_path_dossier.py"


def _load_lib():
    spec = importlib.util.spec_from_file_location("production_path_dossier", LIB)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["production_path_dossier"] = mod
    spec.loader.exec_module(mod)
    return mod


def _workspace(ws: Path) -> None:
    (ws / "src").mkdir()
    (ws / "src" / "Game.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;
            contract Game {
                mapping(address => uint256) public bond;
                function claimCredit() external {
                    bond[msg.sender] = 0;
                    payable(msg.sender).transfer(1 ether);
                }
                function blacklistDisputeGame(address game) external onlyGuardian {}
                modifier onlyGuardian() { _; }
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


def _factory_workspace(ws: Path) -> None:
    (ws / "src").mkdir()
    (ws / "src" / "Factory.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            library Clones {
                function clone(address implementation) internal returns (address) {}
            }

            contract ERC1967Proxy {
                constructor(address implementation, bytes memory data) {}
            }

            contract ProofVerifier {
                function verifyProof(bytes calldata proof) external returns (bool) {}
            }

            contract VaultFactory {
                address public implementation;
                Registry public registry;
                ProofVerifier public verifier;

                function deploy(bytes calldata proof, bytes calldata data) external onlyOwner {
                    require(verifier.verifyProof(proof), "proof");
                    address clone = Clones.clone(implementation);
                    registry.registerVault(clone);
                    new ERC1967Proxy(implementation, data);
                }

                modifier onlyOwner() { _; }
            }

            contract Registry {
                function registerVault(address vault) external {}
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


def _parent_loss_factory_workspace(ws: Path) -> None:
    (ws / "src").mkdir()
    (ws / "src" / "ParentLossFactory.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract ERC1967Proxy {
                constructor(address implementation, bytes memory data) {}
            }

            contract DisputeGameFactory {
                address public childImplementation;
                GameRegistry public registry;

                function createGame(bytes calldata data) external returns (address game) {
                    game = address(new ERC1967Proxy(childImplementation, data));
                    registry.registerGame(game);
                }
            }

            contract GameRegistry {
                function registerGame(address game) external {}
            }

            contract GuardianPortal {
                function blacklistDisputeGame(address game) external onlyGuardian {}
                modifier onlyGuardian() { _; }
            }

            contract ChildGame {
                uint256 public bond;
                function resolveParentLoss(address recipient) external {
                    bond = 0;
                    payable(recipient).transfer(1 ether);
                }
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(SEMANTIC), "--workspace", str(ws)], check=True)


def _candidate(**overrides):
    doc = {
        "schema_version": "deep_candidate.v1",
        "lane": "source_mine",
        "candidate_id": "cand-1",
        "files": ["src/Game.sol:4-7"],
        "claim": "claimCredit sends the bond to the wrong actor.",
        "trigger": "Anyone calls claimCredit after the accounting state is prepared.",
        "impact": "The attacker can steal bond funds.",
        "reproduction": "forge test --match-test test_claimCredit",
        "confidence": "high",
        "blocking_questions": [],
        "promotion_status": "poc_ready",
    }
    doc.update(overrides)
    return doc


def _go_sig_row(**overrides):
    row = {
        "calls_made": [],
        "file_path": "protocol/app/app.go",
        "function_name": "BeginBlocker",
        "function_signature": "func (app *App) BeginBlocker(ctx sdk.Context) (sdk.BeginBlock, error)",
        "guards_detected": [],
        "language": "go",
        "line_end": 20,
        "line_start": 10,
        "modifiers": ["pointer-receiver"],
        "params": [],
        "receiver_type": "App",
        "return_types": [],
        "visibility": "exported",
    }
    row.update(overrides)
    return row


def _write_go_sig_extracts(ws: Path, rows: list[dict]) -> None:
    audit = ws / ".auditooor"
    audit.mkdir()
    (audit / "go_sig_extracts.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class ProductionPathDossierTest(unittest.TestCase):
    def test_permissionless_funds_path_is_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(_candidate(), workspace=ws, graph=graph)
            self.assertEqual(dossier["external_actor_path"], "proven")
            self.assertEqual(dossier["victim_impact"], "funds")
            self.assertEqual(dossier["proof_plan"], "forge PoC")
            self.assertEqual(dossier["submit_verdict"], "poc_ready")

    def test_base_fn1_style_privileged_parent_loss_path_is_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    trigger=(
                        "Child resolves through CHALLENGER_WINS parent after "
                        "guardian blacklistDisputeGame or invalid TEE proof."
                    ),
                    impact="Challenge-system bond reward is misrouted.",
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(dossier["external_actor_path"], "privileged-only")
            self.assertEqual(dossier["submit_verdict"], "unsafe_to_submit")
            self.assertIn("precondition_privileged", dossier["blockers"])

    def test_single_file_without_entrypoint_name_does_not_prove_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    claim="Some state in this source file can drift.",
                    trigger="A condition eventually happens.",
                    impact="The attacker can steal bond funds.",
                    reproduction="forge test --match-test test_stateDrift",
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(dossier["external_actor_path"], "missing")
            self.assertEqual(dossier["submit_verdict"], "needs_poc")
            self.assertIn("external_actor_path_missing", dossier["blockers"])

    def test_structured_predeployment_source_only_rationale_can_be_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    trigger="Pre-deployment source-only issue; no live deployment exists.",
                    lane_payload={"production_path_verdict": "PRE_DEPLOYMENT_SOURCE_ONLY"},
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(dossier["external_actor_path"], "source-only")
            self.assertEqual(dossier["submit_verdict"], "poc_ready")

    def test_factory_relation_edges_explain_privileged_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=["src/Factory.sol:18-23"],
                    claim="VaultFactory deploy wires clones, proxies, registry entries, and proof verifier adapters incorrectly.",
                    trigger="VaultFactory.deploy is invoked by the owner during setup.",
                    impact="The attacker can steal vault funds after the wrong clone is registered.",
                    reproduction="forge test --match-test test_factoryWiring",
                    lane_payload={"contract": "VaultFactory", "function": "deploy"},
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(dossier["external_actor_path"], "privileged-only")
            self.assertEqual(dossier["submit_verdict"], "unsafe_to_submit")
            edges = dossier["state_transition"]["matched_relation_edges"]
            edge_kinds = {edge["kind"] for edge in edges}
            self.assertIn("clone-deploy", edge_kinds)
            self.assertIn("proxy-deploy", edge_kinds)
            self.assertIn("registry-write", edge_kinds)
            self.assertIn("verifier-adapter-call", edge_kinds)
            self.assertIn("cross-contract edges", dossier["blocker_explanation"])

    def test_base_fn1_parent_loss_stays_blocked_despite_factory_proxy_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _parent_loss_factory_workspace(ws)
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=["src/ParentLossFactory.sol:9-13"],
                    claim=(
                        "DisputeGameFactory createGame deploys a child through a proxy and "
                        "registers it; ChildGame.resolveParentLoss can later pay the wrong actor."
                    ),
                    trigger=(
                        "Anyone can call createGame, but the parent-loss branch only becomes "
                        "reachable after CHALLENGER_WINS caused by guardian blacklistDisputeGame."
                    ),
                    impact="The attacker can steal challenge bond rewards from the child game.",
                    reproduction="forge test --match-test test_parentLossFactoryReachability",
                    lane_payload={
                        "contract": "DisputeGameFactory",
                        "function": "createGame",
                        "target_contract": "ChildGame",
                    },
                ),
                workspace=ws,
                graph=graph,
            )
            self.assertEqual(dossier["external_actor_path"], "privileged-only")
            self.assertEqual(dossier["submit_verdict"], "unsafe_to_submit")
            self.assertIn("precondition_privileged", dossier["blockers"])
            self.assertIn("external_actor_path_privileged_only", dossier["blockers"])
            entries = dossier["state_transition"]["matched_entrypoints"]
            self.assertTrue(
                any(entry["function"] == "createGame" and entry["role"] == "permissionless" for entry in entries)
            )
            edges = dossier["state_transition"]["matched_relation_edges"]
            edge_kinds = {edge["kind"] for edge in edges}
            self.assertIn("proxy-deploy", edge_kinds)
            self.assertIn("registry-write", edge_kinds)
            self.assertIn("privileged or unsafe preconditions", dossier["blocker_explanation"])

    def test_prefers_rich_named_rust_source_graph_and_merges_rpc_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit = ws / ".auditooor"
            audit.mkdir()
            (audit / "semantic_graph.json").write_text("{}\n", encoding="utf-8")
            (audit / "rust_source_graph.json").write_text(
                json.dumps({
                    "_meta": {"schema_version": "auditooor.rust_source_graph.v1", "crate_count": 1},
                    "stale": {
                        "crate_root": "stale",
                        "files_scanned": 1,
                        "entrypoints": [{"file": "stale/src/lib.rs", "line": 1, "fn": "old", "kind": "lib_rs_pub", "attrs": []}],
                        "trait_impls": [],
                        "trait_impl_methods": [],
                        "enum_dispatches": [],
                        "external_calls": [],
                        "runtime_calls": [],
                        "rpc_routes": [],
                        "unsafe_blocks": [],
                        "value_movement_calls": [],
                    },
                }) + "\n",
                encoding="utf-8",
            )
            (audit / "rust_source_graph.rc28-clean.json").write_text(
                json.dumps({
                    "_meta": {"schema_version": "auditooor.rust_source_graph.v1", "crate_count": 1},
                    "base-consensus-rpc": {
                        "crate_root": "crates/consensus/rpc",
                        "files_scanned": 1,
                        "entrypoints": [
                            {
                                "file": "crates/consensus/rpc/src/lib.rs",
                                "line": 10,
                                "fn": "new_payload_v4",
                                "kind": "jsonrpsee_method",
                                "attrs": [],
                                "rpc_method": "newPayloadV4",
                                "cfg_attrs": ['#[cfg(feature = "v4")]'],
                            },
                            {
                                "file": "crates/consensus/rpc/src/lib.rs",
                                "line": 14,
                                "fn": "rollup_config",
                                "kind": "jsonrpsee_method",
                                "attrs": [],
                                "rpc_method": "rollupConfig",
                                "cfg_attrs": [],
                            }
                        ],
                        "trait_impls": [],
                        "trait_impl_methods": [
                            {
                                "file": "crates/consensus/engine/src/task_queue/tasks/insert/task.rs",
                                "line": 54,
                                "trait": "EngineTaskExt",
                                "struct": "InsertTask",
                                "fn": "execute",
                                "trait_decl_file": "crates/consensus/engine/src/task_queue/tasks/task.rs",
                                "trait_decl_line": 59,
                                "runtime_calls": [
                                    {
                                        "file": "crates/consensus/engine/src/task_queue/tasks/insert/task.rs",
                                        "line": 73,
                                        "call": "engine_new_payload",
                                        "snippet": "self.client.new_payload_v4(payload).await?",
                                    }
                                ],
                            }
                        ],
                        "enum_dispatches": [
                            {
                                "file": "crates/consensus/engine/src/task_queue/tasks/task.rs",
                                "line": 137,
                                "enum": "EngineTask",
                                "variant": "Insert",
                                "dispatch_kind": "variant_method_call",
                                "target": "task.execute",
                                "snippet": "Self::Insert(task) => task.execute(state).await?",
                            }
                        ],
                        "external_calls": [],
                        "runtime_calls": [
                            {
                                "file": "crates/consensus/rpc/src/lib.rs",
                                "line": 20,
                                "call": "engine_new_payload",
                                "snippet": "self.inner.new_payload_v4_metered(payload).await?",
                            }
                        ],
                        "rpc_routes": [
                            {
                                "file": "crates/consensus/rpc/src/lib.rs",
                                "line": 10,
                                "fn": "new_payload_v4",
                                "rpc_method": "newPayloadV4",
                                "impl_file": "crates/consensus/rpc/src/lib.rs",
                                "impl_line": 18,
                                "runtime_calls": [
                                    {
                                        "file": "crates/consensus/rpc/src/lib.rs",
                                        "line": 20,
                                        "call": "engine_new_payload",
                                        "snippet": "self.inner.new_payload_v4_metered(payload).await?",
                                    }
                                ],
                                "cfg_attrs": ['#[cfg(feature = "v4")]'],
                                "impl_method_cfg_attrs": ['#[cfg(feature = "v4")]'],
                            },
                            {
                                "file": "crates/consensus/rpc/src/lib.rs",
                                "line": 14,
                                "fn": "rollup_config",
                                "rpc_method": "rollupConfig",
                                "impl_file": "crates/consensus/rpc/src/lib.rs",
                                "impl_line": 24,
                                "runtime_calls": [],
                            }
                        ],
                        "unsafe_blocks": [],
                        "value_movement_calls": [],
                    },
                }) + "\n",
                encoding="utf-8",
            )

            lib = _load_lib()
            graph = lib.load_graph(ws)

            self.assertTrue(graph["_rust_source_graph_path"].endswith("rust_source_graph.rc28-clean.json"))
            entries = graph["entrypoints"]
            self.assertTrue(any(e["contract"] == "base-consensus-rpc" and e["function"] == "new_payload_v4" for e in entries))
            self.assertFalse(any(e["contract"] == "stale" for e in entries))
            edges = graph["relation_edges"]
            edge_kinds = {edge["kind"] for edge in edges}
            self.assertIn("rust_runtime_call", edge_kinds)
            self.assertIn("rust_rpc_route", edge_kinds)
            self.assertIn("rust_rpc_runtime_call", edge_kinds)
            self.assertIn("rust_trait_impl_method", edge_kinds)
            self.assertIn("rust_trait_impl_runtime_call", edge_kinds)
            self.assertIn("rust_enum_dispatch", edge_kinds)

            dossier = lib.build_dossier(
                _candidate(
                    files=["crates/consensus/rpc/src/lib.rs"],
                    claim="new_payload_v4 reaches the newPayloadV4 RPC route.",
                    impact="can halt the chain",
                    reproduction="source-only",
                    lane_payload={
                        "contract": "base-consensus-rpc",
                        "function": "new_payload_v4",
                        "target_function": "newPayloadV4",
                    },
                ),
                workspace=ws,
                graph=graph,
            )
            matched_fns = {
                entry["function"]
                for entry in dossier["state_transition"]["matched_entrypoints"]
            }
            self.assertIn("new_payload_v4", matched_fns)
            self.assertNotIn("rollup_config", matched_fns)
            matched_route_targets = {
                edge["target"]
                for edge in dossier["state_transition"]["matched_relation_edges"]
                if edge["kind"] == "rust_rpc_route"
            }
            self.assertIn("newPayloadV4", matched_route_targets)
            self.assertNotIn("rollupConfig", matched_route_targets)

    def test_go_cosmos_external_sig_extract_rows_clear_actor_path_with_call_edges(self) -> None:
        cases = [
            (
                "abci",
                _go_sig_row(
                    calls_made=["app.ModuleManager.BeginBlock"],
                    file_path="protocol/app/app.go",
                    function_name="BeginBlocker",
                    function_signature="func (app *App) BeginBlocker(ctx sdk.Context) (sdk.BeginBlock, error)",
                    line_start=1823,
                    receiver_type="App",
                ),
                "protocol/app/app.go:1823-1831",
                "App",
                "BeginBlocker",
                "cosmos_abci_entrypoint",
                "app.ModuleManager.BeginBlock",
            ),
            (
                "ante",
                _go_sig_row(
                    calls_made=["h.clobAnteHandle"],
                    file_path="protocol/app/ante.go",
                    function_name="AnteHandle",
                    function_signature="func (h *lockingAnteHandler) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error)",
                    line_start=195,
                    receiver_type="lockingAnteHandler",
                ),
                "protocol/app/ante.go:195-209",
                "lockingAnteHandler",
                "AnteHandle",
                "cosmos_ante_handler",
                "h.clobAnteHandle",
            ),
            (
                "msg_server",
                _go_sig_row(
                    calls_made=["k.bankKeeper.SendCoins"],
                    file_path="protocol/x/vault/keeper/msg_server.go",
                    function_name="DepositToMegavault",
                    function_signature="func (k msgServer) DepositToMegavault(goCtx context.Context, msg *types.MsgDepositToMegavault) (*types.MsgDepositToMegavaultResponse, error)",
                    line_start=41,
                    receiver_type="msgServer",
                ),
                "protocol/x/vault/keeper/msg_server.go:41-90",
                "msgServer",
                "DepositToMegavault",
                "cosmos_msg_server",
                "k.bankKeeper.SendCoins",
            ),
        ]
        for name, row, file_ref, contract, function, kind, call in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    ws = Path(tmp)
                    _write_go_sig_extracts(ws, [row])
                    lib = _load_lib()
                    graph = lib.load_graph(ws)
                    dossier = lib.build_dossier(
                        _candidate(
                            files=[file_ref],
                            claim=f"{contract}.{function} can move funds through {call}.",
                            trigger=f"Anyone can reach {function} through the Cosmos production path.",
                            impact="The attacker can steal funds.",
                            reproduction="go test ./protocol/...",
                            lane_payload={"contract": contract, "function": function},
                        ),
                        workspace=ws,
                        graph=graph,
                    )

                    self.assertEqual(dossier["external_actor_path"], "proven")
                    self.assertEqual(dossier["submit_verdict"], "poc_ready")
                    entries = dossier["state_transition"]["matched_entrypoints"]
                    self.assertTrue(
                        any(
                            entry["function"] == function
                            and entry["role"] == "permissionless"
                            and entry["lang"] == "go"
                            and entry["kind"] == kind
                            and entry["evidence"] == "go-sig-extract"
                            for entry in entries
                        ),
                        entries,
                    )
                    edges = dossier["state_transition"]["matched_relation_edges"]
                    self.assertTrue(
                        any(
                            edge["kind"] == "go_call"
                            and edge["source_function"] == function
                            and edge["target"] == call
                            and edge["evidence"] == "go-sig-extract-calls_made"
                            for edge in edges
                        ),
                        edges,
                    )

    def test_go_cosmos_source_scan_emits_msgserver_call_edges_without_sig_extracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            msg_server = ws / "protocol" / "x" / "accountplus" / "keeper" / "msg_server.go"
            msg_server.parent.mkdir(parents=True)
            msg_server.write_text(
                textwrap.dedent(
                    """
                    package keeper

                    import "context"

                    func (m msgServer) AddAuthenticator(
                        goCtx context.Context,
                        msg *types.MsgAddAuthenticator,
                    ) (*types.MsgAddAuthenticatorResponse, error) {
                        ctx := sdk.UnwrapSDKContext(goCtx)
                        id, err := m.Keeper.AddAuthenticator(ctx, msg.Sender, msg.AuthenticatorType, msg.Data)
                        if err != nil {
                            return nil, err
                        }
                        return &types.MsgAddAuthenticatorResponse{AuthenticatorId: id}, nil
                    }
                    """
                ),
                encoding="utf-8",
            )

            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=["protocol/x/accountplus/keeper/msg_server.go:6-15"],
                    claim="msgServer.AddAuthenticator reaches Keeper.AddAuthenticator and changes authenticator state.",
                    trigger="External user submits MsgAddAuthenticator through the Cosmos SDK tx path.",
                    impact="The attacker can steal funds through account authorization state.",
                    reproduction="go test ./protocol/x/accountplus/keeper -run TestMsgServer_AddAuthenticator",
                    lane_payload={
                        "contract": "msgServer",
                        "function": "AddAuthenticator",
                        "target_function": "AddAuthenticator",
                    },
                ),
                workspace=ws,
                graph=graph,
            )

            self.assertEqual(dossier["external_actor_path"], "proven")
            self.assertEqual(dossier["submit_verdict"], "poc_ready")
            self.assertTrue(
                any(
                    entry["function"] == "AddAuthenticator"
                    and entry["role"] == "permissionless"
                    and entry["kind"] == "cosmos_msg_server"
                    and entry["evidence"] == "go-cosmos-source-shape"
                    for entry in dossier["state_transition"]["matched_entrypoints"]
                )
            )
            self.assertTrue(
                any(
                    edge["kind"] == "go_call"
                    and edge["source_function"] == "AddAuthenticator"
                    and edge["target"] == "m.Keeper.AddAuthenticator"
                    and edge["evidence"] == "go-cosmos-source-call"
                    for edge in dossier["state_transition"]["matched_relation_edges"]
                )
            )

    def test_go_cosmos_msgserver_helpers_do_not_clear_actor_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go_sig_extracts(
                ws,
                [
                    _go_sig_row(
                        calls_made=["m.Keeper.AddAuthenticator"],
                        file_path="protocol/x/accountplus/keeper/msg_server.go",
                        function_name="validateAuthenticatorConfig",
                        function_signature="func (m msgServer) validateAuthenticatorConfig(config []byte) error",
                        line_start=91,
                        receiver_type="msgServer",
                        params=[{"name": "config", "type": "[]byte"}],
                        return_types=["error"],
                    ),
                ],
            )
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=["protocol/x/accountplus/keeper/msg_server.go:91-99"],
                    claim="msgServer.validateAuthenticatorConfig reaches Keeper.AddAuthenticator.",
                    trigger="The helper is called from an internal module path.",
                    impact="The attacker can steal funds through account authorization state.",
                    reproduction="go test ./protocol/x/accountplus/keeper",
                    lane_payload={"contract": "msgServer", "function": "validateAuthenticatorConfig"},
                ),
                workspace=ws,
                graph=graph,
            )

            self.assertEqual(dossier["external_actor_path"], "missing")
            self.assertEqual(dossier["submit_verdict"], "needs_poc")
            self.assertIn("external_actor_path_missing", dossier["blockers"])
            self.assertTrue(
                any(
                    entry["function"] == "validateAuthenticatorConfig"
                    and entry["role"] == "cosmos-internal"
                    and entry["kind"] == "cosmos_keeper_method"
                    for entry in dossier["state_transition"]["matched_entrypoints"]
                ),
                dossier["state_transition"]["matched_entrypoints"],
            )

    def test_go_cosmos_internal_sig_extract_rows_match_without_clearing_actor_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go_sig_extracts(
                ws,
                [
                    _go_sig_row(
                        calls_made=["k.bankKeeper.SendCoins"],
                        file_path="protocol/x/vault/keeper/keeper.go",
                        function_name="SetVaultParams",
                        function_signature="func (k Keeper) SetVaultParams(ctx sdk.Context, params types.Params) error",
                        line_start=77,
                        receiver_type="Keeper",
                    ),
                    _go_sig_row(
                        calls_made=["tree.Set"],
                        file_path="protocol/store/iavl/tree.go",
                        function_name="Set",
                        function_signature="func (tree *MutableTree) Set(key []byte, value []byte) (bool, error)",
                        line_start=120,
                        receiver_type="MutableTree",
                    ),
                ],
            )
            lib = _load_lib()
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(
                _candidate(
                    files=[
                        "protocol/x/vault/keeper/keeper.go:77-90",
                        "protocol/store/iavl/tree.go:120-140",
                    ],
                    claim="Keeper.SetVaultParams and MutableTree.Set can move accounting state.",
                    trigger="An internal module path reaches SetVaultParams before MutableTree.Set.",
                    impact="The attacker can steal funds.",
                    reproduction="go test ./protocol/...",
                ),
                workspace=ws,
                graph=graph,
            )

            self.assertEqual(dossier["external_actor_path"], "missing")
            self.assertEqual(dossier["submit_verdict"], "needs_poc")
            self.assertIn("external_actor_path_missing", dossier["blockers"])
            entries = dossier["state_transition"]["matched_entrypoints"]
            self.assertTrue(
                any(
                    entry["function"] == "SetVaultParams"
                    and entry["role"] == "cosmos-internal"
                    and entry["kind"] == "cosmos_keeper_method"
                    for entry in entries
                ),
                entries,
            )
            self.assertTrue(
                any(
                    entry["function"] == "Set"
                    and entry["role"] == "cosmos-internal"
                    and entry["kind"] == "iavl_storage_method"
                    for entry in entries
                ),
                entries,
            )

    def test_dydx_workspace_surfaces_fallback_go_sig_extracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "dydx"
            (ws / ".auditooor").mkdir(parents=True)
            lib = _load_lib()
            graph = lib.load_graph(ws)

            meta = graph.get("_go_cosmos_source_graph", {})
            fallback = str(ROOT / "audit" / "sig_extracts" / "dydx-v4-chain.jsonl")
            self.assertIn(fallback, meta.get("sig_extract_sources", []))
            self.assertGreater(meta.get("sig_extract_entrypoint_count", 0), 0)
            self.assertTrue(
                any(
                    entry.get("file") == "protocol/app/ante.go"
                    and entry.get("function") == "AnteHandle"
                    and entry.get("role") == "permissionless"
                    and entry.get("evidence") == "go-sig-extract"
                    for entry in graph.get("entrypoints", [])
                )
            )
            self.assertFalse(
                any(
                    str(entry.get("file", "")).startswith("protocol/mocks/")
                    or str(entry.get("file", "")).endswith(".pb.go")
                    for entry in graph.get("entrypoints", [])
                )
            )

    def test_cli_writes_dossier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _workspace(ws)
            cand = ws / "cand.json"
            cand.write_text(json.dumps(_candidate()) + "\n", encoding="utf-8")
            out_dir = ws / "dossiers"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(DOSSIER_CLI),
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(out_dir),
                    str(cand),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(list(out_dir.glob("*.production_path_dossier.json")))


class TestProductionPathResolution(unittest.TestCase):
    """P0-2 Wave C-2B: production_path_resolution and cited_constants in dossier."""

    def _lib(self):
        return _load_lib()

    def test_production_path_resolution_present_in_dossier(self):
        """build_dossier always emits production_path_resolution."""
        lib = self._lib()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            # Minimal empty graph — no rust source graph present.
            candidate = {
                "candidate_id": "test-c1",
                "claim": "some rust bug",
                "trigger": "user calls process()",
                "impact": "funds drained via withdraw",
                "files": [],
            }
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(candidate, workspace=ws, graph=graph)
            self.assertIn("production_path_resolution", dossier)
            ppr = dossier["production_path_resolution"]
            self.assertIn("verdict", ppr)
            self.assertIn("hops", ppr)
            self.assertIn("reason", ppr)
            # With no rust edges the verdict should be NOT_RUST.
            self.assertEqual(ppr["verdict"], "NOT_RUST")

    def test_cited_constants_present_in_dossier(self):
        """cited_constants is emitted even when empty."""
        lib = self._lib()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir()
            candidate = {
                "candidate_id": "test-c2",
                "claim": "references MAX_RETRIES constant",
                "trigger": "loop up to MAX_RETRIES",
                "impact": "freeze",
                "files": [],
            }
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(candidate, workspace=ws, graph=graph)
            self.assertIn("cited_constants", dossier)
            self.assertIsInstance(dossier["cited_constants"], list)

    def test_cited_constants_resolved_from_registry(self):
        """When the constant registry is present and a constant name appears
        in the candidate text, it is surfaced in cited_constants."""
        lib = self._lib()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            auditooor_dir = ws / ".auditooor"
            auditooor_dir.mkdir()
            # Write a minimal constant registry.
            registry = {
                "_meta": {
                    "schema_version": "auditooor.rust_constant_registry.v1",
                    "workspace": str(ws),
                    "crate_count": 1,
                    "total_constants": 1,
                    "literal_count": 1,
                    "expression_count": 0,
                    "opaque_count": 0,
                },
                "constants": [{
                    "crate": "my_crate",
                    "file": "src/lib.rs",
                    "line": 3,
                    "kind": "const",
                    "name": "VSOCK_PORT",
                    "type": "u32",
                    "literal_value_or_expr": "8000",
                    "resolution_confidence": "literal",
                }],
            }
            (auditooor_dir / "rust_constant_registry.json").write_text(
                json.dumps(registry), encoding="utf-8"
            )
            candidate = {
                "candidate_id": "test-c3",
                "claim": "attacker abuses VSOCK_PORT",
                "trigger": "connects to VSOCK_PORT",
                "impact": "funds stolen",
                "files": [],
            }
            graph = lib.load_graph(ws)
            dossier = lib.build_dossier(candidate, workspace=ws, graph=graph)
            cited = dossier.get("cited_constants", [])
            names = [c["name"] for c in cited]
            self.assertIn("VSOCK_PORT", names)
            vsock = next(c for c in cited if c["name"] == "VSOCK_PORT")
            self.assertEqual(vsock["literal_value_or_expr"], "8000")
            self.assertEqual(vsock["resolution_confidence"], "literal")


if __name__ == "__main__":
    unittest.main()
