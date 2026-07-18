#!/usr/bin/env python3
"""Tests for tools/rust-source-graph.py (P1-2 burn-down).

Stdlib-only. Synthetic Soroban-shaped fixtures in tempdirs — no
dependency on `~/audits/` or any external source root.

Coverage:
  1. One entrypoint detected (`#[contractimpl]` + `pub fn`).
  2. One trait impl edge detected.
  3. One external_call site detected (`env.invoke_contract`).
  4. One unsafe block location captured.
  5. One value_movement call captured (`token::transfer`).
  6. Base runtime calls are captured for production-path dossiers.
  7. jsonrpsee `#[method]` RPC trait methods become entrypoints.
  8. jsonrpsee RPC declarations route to same-named impl methods.
  9. cfg/cfg_attr annotations are preserved on RPC routes and impl methods.
  10. Empty crate (no .rs files) -> empty graph, schema valid.
  11. --validate mode round-trip succeeds; mutated JSON fails.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-source-graph.py"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _make(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


SOROBAN_LIB_RS = """\
use soroban_sdk::{contract, contractimpl, Env, Address};

pub struct Foo;

pub trait Greet {
    fn hello(&self) -> u32;
}

impl Greet for Foo {
    fn hello(&self) -> u32 { 1 }
    fn runtime_dispatch(&self) -> u32 { self.hello() }
}

#[cfg(feature = "reth")]
pub fn cfg_only_runtime() {}

#[contractimpl]
impl Foo {
    pub fn external_entry(env: Env, to: Address, amount: i128) -> i128 {
        let result = env.invoke_contract(&to, &symbol_short!("a"), ().into());
        unsafe {
            let _x = 1u32;
        }
        token::transfer(&env, &to, &amount);
        self.client.new_payload_v4(payload, root).await?;
        amount
    }
}
"""


class TestRustSourceGraph(unittest.TestCase):

    def _build(self, ws: Path) -> dict:
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = ws / ".auditooor" / "rust_source_graph.json"
        self.assertTrue(out.is_file(), f"expected {out}")
        return json.loads(out.read_text(encoding="utf-8"))

    def test_full_inventory_on_soroban_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/foo/Cargo.toml", "[package]\nname = \"foo\"\n")
            _make(ws, "contracts/foo/src/lib.rs", SOROBAN_LIB_RS)
            graph = self._build(ws)

            self.assertIn("foo", graph)
            crate = graph["foo"]
            self.assertEqual(crate["files_scanned"], 1)

            # (1) entrypoint
            entries = crate["entrypoints"]
            self.assertTrue(any(e["fn"] == "external_entry" and e["kind"] == "contractimpl" for e in entries),
                            f"missing contract entrypoint: {entries}")

            # (2) trait impl
            traits = crate["trait_impls"]
            self.assertTrue(traits, traits)
            self.assertTrue(any(t["trait"] == "Greet" and t["struct"] == "Foo" for t in traits),
                            f"missing Greet for Foo edge: {traits}")
            self.assertTrue(any("runtime_dispatch" in t.get("methods", []) for t in traits),
                            f"missing trait method inventory: {traits}")
            trait_methods = crate["trait_method_impls"]
            self.assertTrue(any(t["trait"] == "Greet" and t["method"] == "hello" for t in trait_methods),
                            f"missing Greet.hello method edge: {trait_methods}")
            self.assertTrue(any(t["trait"] == "Greet" and t["method"] == "runtime_dispatch" for t in trait_methods),
                            f"missing Greet.runtime_dispatch method edge: {trait_methods}")

            cfg_attrs = crate["cfg_attrs"]
            self.assertTrue(any(c["kind"] == "cfg" and c["feature"] == "reth" for c in cfg_attrs),
                            f"missing reth cfg attr: {cfg_attrs}")

            macros = crate["macro_invocations"]
            self.assertTrue(any(m["macro"] == "symbol_short" for m in macros),
                            f"missing symbol_short macro invocation: {macros}")

            # (3) external call
            ext = crate["external_calls"]
            self.assertTrue(ext, ext)
            self.assertTrue(any(c["call"] == "invoke_contract" for c in ext),
                            f"missing invoke_contract: {ext}")

            # (4) unsafe block
            unsafe = crate["unsafe_blocks"]
            self.assertEqual(len(unsafe), 1, unsafe)
            self.assertGreater(unsafe[0]["line"], 0)

            # (5) value movement
            value = crate["value_movement_calls"]
            self.assertTrue(value, value)
            self.assertTrue(any(v["call"] in {"token::transfer", "transfer"} for v in value),
                            f"missing transfer: {value}")

            # (6) runtime production-path call
            runtime = crate["runtime_calls"]
            self.assertTrue(any(r["call"] == "engine_new_payload" for r in runtime),
                            f"missing engine_new_payload: {runtime}")

    def test_cosmwasm_entry_point_free_fns_are_entrypoints(self):
        # GUARD (rust-entrypoint funnel bug): a CosmWasm swap-contract uses
        # `#[entry_point]` / `#[cfg_attr(not(feature="library"), entry_point)]`
        # on FREE pub fns (execute/query/instantiate/migrate/reply), NOT inside
        # an impl, and moves funds via `BankMsg::Send` + dispatches the chain
        # module via `create_*_msg(...)` wrapped in `SubMsg`. Before the fix the
        # extractor reported entrypoints=0 external_calls=0 value_movement=0,
        # making the Rust analysis blind to the whole contract.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/swap/Cargo.toml", "[package]\nname = \"swap-contract\"\n")
            _make(ws, "contracts/swap/src/contract.rs", """\
use cosmwasm_std::{entry_point, BankMsg, DepsMut, Env, MessageInfo, Reply, Response, SubMsg};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, ContractError> {
    let order_message = SubMsg::reply_on_success(create_spot_market_order_msg(contract, order), 1u64);
    let send_message = BankMsg::Send { to_address: info.sender.to_string(), amount: coins };
    Ok(Response::new().add_submessage(order_message).add_message(send_message))
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, StdError> {
    Ok(Binary::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::new())
}

// A plain `use` import of entry_point must NOT be treated as an entrypoint,
// and a private helper fn must not be surfaced.
fn helper_not_an_entrypoint() {}
""")
            graph = self._build(ws)
            crate = graph["swap-contract"]
            entries = crate["entrypoints"]

            # (1) primary assertion: entrypoints > 0 (the funnel-blindness bug).
            self.assertGreater(len(entries), 0,
                               f"CosmWasm entrypoints not detected: {entries}")

            entry_fns = {e["fn"] for e in entries}
            for expected in {"instantiate", "execute", "query", "reply", "migrate"}:
                self.assertIn(expected, entry_fns,
                              f"missing CosmWasm entrypoint {expected!r}: {entries}")
            self.assertTrue(all(e["kind"] == "entry_point"
                                for e in entries if e["fn"] in entry_fns),
                            f"wrong kind on CosmWasm entrypoints: {entries}")

            # The bare `use cosmwasm_std::{entry_point, ...}` import and the
            # private helper must not leak in as entrypoints.
            self.assertNotIn("helper_not_an_entrypoint", entry_fns, entries)

            # (2) value movement: BankMsg::Send is captured.
            value = {v["call"] for v in crate["value_movement_calls"]}
            self.assertIn("BankMsg::Send", value,
                          f"missing BankMsg::Send value movement: {value}")

            # (3) external/cross-module dispatch: SubMsg builder + add_submessage.
            ext = {c["call"] for c in crate["external_calls"]}
            self.assertIn("cosmwasm_msg_builder", ext,
                          f"missing create_*_msg builder: {ext}")
            self.assertIn("add_submessage", ext,
                          f"missing add_submessage dispatch: {ext}")

    def test_jsonrpsee_rpc_trait_methods_are_entrypoints(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "rpc/Cargo.toml", "[package]\nname = \"rpc\"\n")
            _make(ws, "rpc/src/lib.rs", """\
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[cfg_attr(not(feature = "client"), rpc(server, namespace = "optimism"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "optimism"))]
pub trait RollupNodeApi {
    #[method(name = "outputAtBlock")]
    async fn output_at_block(&self) -> RpcResult<()>;

    #[subscription(name = "subscribe_safe_head", item = u64)]
    async fn ws_safe_head_updates(&self) -> RpcResult<()>;
}
""")
            graph = self._build(ws)
            entries = graph["rpc"]["entrypoints"]

            output = [e for e in entries if e["fn"] == "output_at_block"]
            self.assertEqual(len(output), 1, entries)
            self.assertEqual(output[0]["kind"], "jsonrpsee_method")
            self.assertEqual(output[0]["rpc_method"], "outputAtBlock")

            sub = [e for e in entries if e["fn"] == "ws_safe_head_updates"]
            self.assertEqual(len(sub), 1, entries)
            self.assertEqual(sub[0]["kind"], "jsonrpsee_subscription")
            self.assertEqual(sub[0]["rpc_method"], "subscribe_safe_head")

    def test_jsonrpsee_routes_to_impl_methods_and_runtime_calls(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "rpc/Cargo.toml", "[package]\nname = \"rpc\"\n")
            _make(ws, "rpc/src/lib.rs", """\
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "engine")]
pub trait BaseEngineApi {
    #[method(name = "newPayloadV4")]
    async fn new_payload_v4(&self, payload: Payload) -> RpcResult<Status>;

    #[method(name = "forkchoiceUpdatedV3")]
    async fn fork_choice_updated_v3(&self, state: State) -> RpcResult<Status>;
}

#[rpc(server, namespace = "admin")]
pub trait AdminApi {
    #[method(name = "postUnsafePayload")]
    async fn admin_post_unsafe_payload(&self, payload: Payload) -> RpcResult<()>;
}

#[async_trait]
impl BaseEngineApiServer for EngineRpc {
    async fn new_payload_v4(&self, payload: Payload) -> RpcResult<Status> {
        Ok(self.inner.new_payload_v4_metered(payload).await?)
    }

    async fn fork_choice_updated_v3(&self, state: State) -> RpcResult<Status> {
        Ok(self.inner.fork_choice_updated_v3_metered(state).await?)
    }
}

#[async_trait]
impl AdminApiServer for AdminRpc {
    async fn admin_post_unsafe_payload(&self, payload: Payload) -> RpcResult<()> {
        self.sender.send(AdminQuery::PostUnsafePayload { payload }).await?;
        Ok(())
    }
}
""")
            graph = self._build(ws)
            routes = graph["rpc"]["rpc_routes"]

            new_payload = [r for r in routes if r["fn"] == "new_payload_v4"]
            self.assertEqual(len(new_payload), 1, routes)
            self.assertEqual(new_payload[0]["rpc_method"], "newPayloadV4")
            self.assertEqual(new_payload[0]["rpc_trait"], "BaseEngineApi")
            self.assertTrue(any(c["call"] == "engine_new_payload"
                                for c in new_payload[0]["runtime_calls"]),
                            f"missing new-payload call: {new_payload}")

            fcu = [r for r in routes if r["fn"] == "fork_choice_updated_v3"]
            self.assertEqual(len(fcu), 1, routes)
            self.assertTrue(any(c["call"] == "engine_forkchoice"
                                for c in fcu[0]["runtime_calls"]),
                            f"missing forkchoice call: {fcu}")

            admin = [r for r in routes if r["fn"] == "admin_post_unsafe_payload"]
            self.assertEqual(len(admin), 1, routes)
            self.assertTrue(any(c["call"] == "actor_send" for c in admin[0]["runtime_calls"]),
                            f"missing admin send route: {admin}")

    def test_engine_task_insert_and_execute_paths_are_runtime_calls(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "engine/Cargo.toml", "[package]\nname = \"engine\"\n")
            _make(ws, "engine/src/lib.rs", """\
pub fn enqueue_insert(engine: &Engine) {
    let task = EngineTask::Insert(Box::new(InsertTask::new(payload)));
    engine.enqueue(task);
}

impl EngineTask {
    pub async fn execute(&self, state: &mut EngineState) -> Result<(), Error> {
        match self {
            Self::Insert(task) => task.execute(state).await?,
            _ => {}
        }
        Ok(())
    }
}
""")
            graph = self._build(ws)
            runtime = graph["engine"]["runtime_calls"]
            self.assertTrue(any(r["call"] == "engine_task_insert" for r in runtime), runtime)
            self.assertTrue(any(r["call"] == "engine_enqueue" for r in runtime), runtime)
            self.assertTrue(any(r["call"] == "engine_task_insert_execute" for r in runtime),
                            runtime)

    def test_trait_impl_methods_bind_to_trait_declarations(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "engine/Cargo.toml", "[package]\nname = \"engine\"\n")
            _make(ws, "engine/src/lib.rs", """\
pub trait EngineTaskExt {
    async fn execute(&self, state: &mut EngineState) -> Result<(), Error>;
}

pub struct InsertTask;

#[async_trait]
impl EngineTaskExt for InsertTask {
    async fn execute(&self, state: &mut EngineState) -> Result<(), Error> {
        self.client.new_payload_v4(payload).await?;
        Ok(())
    }
}
""")
            graph = self._build(ws)
            methods = graph["engine"]["trait_impl_methods"]
            bound = [m for m in methods
                     if m["trait"] == "EngineTaskExt"
                     and m["struct"] == "InsertTask"
                     and m["fn"] == "execute"]
            self.assertEqual(len(bound), 1, methods)
            self.assertGreater(bound[0]["trait_decl_line"], 0)
            self.assertTrue(any(c["call"] == "engine_new_payload"
                                for c in bound[0]["runtime_calls"]),
                            bound)

    def test_enum_dispatch_edges_capture_construction_and_match_arm_execution(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "engine/Cargo.toml", "[package]\nname = \"engine\"\n")
            _make(ws, "engine/src/lib.rs", """\
pub enum EngineTask {
    Insert(Box<InsertTask>),
    Finalize(Box<FinalizeTask>),
}

pub fn enqueue_insert(engine: &mut Engine) {
    let task = EngineTask::Insert(Box::new(InsertTask::new(payload)));
    engine.enqueue(task);
}

impl EngineTask {
    async fn execute_inner(&self, state: &mut EngineState) -> Result<(), Error> {
        match self {
            Self::Insert(task) => task.execute(state).await?,
            Self::Finalize(task) => {
                task.execute(state).await?;
            }
        }
        Ok(())
    }
}
""")
            graph = self._build(ws)
            dispatches = graph["engine"]["enum_dispatches"]
            self.assertTrue(any(d["enum"] == "EngineTask"
                                and d["variant"] == "Insert"
                                and d["dispatch_kind"] == "variant_construct"
                                for d in dispatches),
                            dispatches)
            self.assertTrue(any(d["enum"] == "EngineTask"
                                and d["variant"] == "Insert"
                                and d["dispatch_kind"] == "variant_method_call"
                                and d["target"] == "task.execute"
                                for d in dispatches),
                            dispatches)

    def test_struct_like_enum_variant_construction_is_captured(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "rpc/Cargo.toml", "[package]\nname = \"rpc\"\n")
            _make(ws, "rpc/src/lib.rs", """\
pub enum NetworkAdminQuery {
    PostUnsafePayload { payload: Payload },
    Ping,
}

pub async fn post_unsafe_payload(sender: Sender, payload: Payload) -> Result<(), Error> {
    sender.send(NetworkAdminQuery::PostUnsafePayload { payload }).await?;
    Ok(())
}
""")
            graph = self._build(ws)
            dispatches = graph["rpc"]["enum_dispatches"]
            self.assertTrue(any(d["enum"] == "NetworkAdminQuery"
                                and d["variant"] == "PostUnsafePayload"
                                and d["dispatch_kind"] == "variant_construct"
                                and d["target"] == "NetworkAdminQuery::PostUnsafePayload"
                                for d in dispatches),
                            dispatches)

    def test_cfg_annotations_are_preserved_on_rpc_routes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "rpc/Cargo.toml", "[package]\nname = \"rpc\"\n")
            _make(ws, "rpc/src/lib.rs", """\
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[cfg_attr(feature = "server", rpc(server, namespace = "engine"))]
pub trait EngineApi {
    #[cfg(feature = "v4")]
    #[method(name = "newPayloadV4")]
    async fn new_payload_v4(&self, payload: Payload) -> RpcResult<Status>;
}

#[cfg(feature = "server")]
impl EngineApiServer for EngineRpc {
    #[cfg(feature = "v4")]
    async fn new_payload_v4(&self, payload: Payload) -> RpcResult<Status> {
        Ok(self.inner.new_payload_v4_metered(payload).await?)
    }
}
""")
            graph = self._build(ws)
            entries = graph["rpc"]["entrypoints"]
            entry = [e for e in entries if e["fn"] == "new_payload_v4"][0]
            self.assertEqual(entry["cfg_attrs"], ['#[cfg(feature = "v4")]'])
            self.assertEqual(
                entry["rpc_trait_cfg_attrs"],
                ['#[cfg_attr(feature = "server", rpc(server, namespace = "engine"))]'],
            )

            routes = graph["rpc"]["rpc_routes"]
            route = [r for r in routes if r["fn"] == "new_payload_v4"][0]
            self.assertEqual(route["cfg_attrs"], ['#[cfg(feature = "v4")]'])
            self.assertEqual(route["impl_cfg_attrs"], ['#[cfg(feature = "server")]'])
            self.assertEqual(route["impl_method_cfg_attrs"], ['#[cfg(feature = "v4")]'])
            self.assertTrue(any(c["call"] == "engine_new_payload"
                                for c in route["runtime_calls"]),
                            route)

            traits = graph["rpc"]["trait_impls"]
            impl_edge = [t for t in traits if t["trait"] == "EngineApiServer"][0]
            self.assertEqual(impl_edge["cfg_attrs"], ['#[cfg(feature = "server")]'])

    def test_empty_crate_is_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Crate dir present but no .rs files.
            _make(ws, "contracts/empty/Cargo.toml", "[package]\nname=\"empty\"\n")
            (ws / "contracts" / "empty" / "src").mkdir(parents=True)
            graph = self._build(ws)

            self.assertIn("empty", graph)
            crate = graph["empty"]
            self.assertEqual(crate["files_scanned"], 0)
            self.assertEqual(crate["entrypoints"], [])
            self.assertEqual(crate["trait_impls"], [])
            self.assertEqual(crate["trait_impl_methods"], [])
            self.assertEqual(crate["enum_dispatches"], [])
            self.assertEqual(crate["external_calls"], [])
            self.assertEqual(crate["runtime_calls"], [])
            self.assertEqual(crate["rpc_routes"], [])
            self.assertEqual(crate["unsafe_blocks"], [])
            self.assertEqual(crate["value_movement_calls"], [])

    def test_workspace_with_no_crates_emits_empty_meta(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "README.md").write_text("# nothing here\n", encoding="utf-8")
            graph = self._build(ws)
            self.assertEqual(graph["_meta"]["crate_count"], 0)
            # Only _meta key.
            self.assertEqual(set(graph.keys()), {"_meta"})

    def test_validate_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/foo/Cargo.toml", "[package]\nname=\"foo\"\n")
            _make(ws, "contracts/foo/src/lib.rs", SOROBAN_LIB_RS)
            self._build(ws)
            out = ws / ".auditooor" / "rust_source_graph.json"
            proc = _run(["--validate", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stderr)

            # Corrupt: drop schema version.
            data = json.loads(out.read_text(encoding="utf-8"))
            data["_meta"]["schema_version"] = "wrong"
            out.write_text(json.dumps(data) + "\n", encoding="utf-8")
            proc = _run(["--validate", str(out)])
            self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_fallback_workspace_as_single_crate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "src/lib.rs",
                  "pub fn top_level_export() -> u32 { 0 }\n")
            graph = self._build(ws)
            # Crate name is workspace dir basename.
            crates = [k for k in graph if k != "_meta"]
            self.assertEqual(len(crates), 1, graph)
            crate = graph[crates[0]]
            entries = crate["entrypoints"]
            self.assertTrue(any(e["fn"] == "top_level_export" and e["kind"] == "lib_rs_pub"
                                for e in entries),
                            f"missing top_level_export entry: {entries}")

    def test_nested_crates_and_bin_layouts_are_discovered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "Cargo.toml", "[workspace]\nmembers = [\"crates/*/*\", \"bin/*\"]\n")
            _make(ws, "crates/execution/payload/Cargo.toml",
                  "[package]\nname=\"base-execution-payload\"\n")
            _make(ws, "crates/execution/payload/src/lib.rs",
                  "pub fn payload_entry() {}\n")
            _make(ws, "crates/consensus/derive/Cargo.toml",
                  "[package]\nname=\"base-consensus-derive\"\n")
            _make(ws, "crates/consensus/derive/src/lib.rs",
                  "pub fn derive_entry() {}\n")
            _make(ws, "bin/node/Cargo.toml",
                  "[package]\nname=\"base-node\"\n")
            _make(ws, "bin/node/src/main.rs",
                  "pub fn node_entry() {}\n")

            graph = self._build(ws)

            crates = {k for k in graph if k != "_meta"}
            self.assertEqual(
                crates,
                {
                    "base-execution-payload",
                    "base-consensus-derive",
                    "base-node",
                },
            )
            self.assertEqual(graph["_meta"]["crate_count"], 3)

    def test_nested_external_checkout_is_discovered_from_engagement_root(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "external/base/Cargo.toml",
                  "[workspace]\nmembers = [\"crates/*/*\", \"bin/*\"]\n")
            _make(ws, "external/base/crates/execution/payload/Cargo.toml",
                  "[package]\nname=\"base-execution-payload\"\n")
            _make(ws, "external/base/crates/execution/payload/src/lib.rs",
                  "pub fn payload_entry() {}\n")
            _make(ws, "external/base/bin/node/Cargo.toml",
                  "[package]\nname=\"base-node\"\n")
            _make(ws, "external/base/bin/node/src/main.rs",
                  "pub fn node_entry() {}\n")

            graph = self._build(ws)

            crates = {k for k in graph if k != "_meta"}
            self.assertEqual(crates, {"base-execution-payload", "base-node"})
            self.assertEqual(graph["_meta"]["crate_count"], 2)

    def test_scanner_scratch_is_not_treated_as_audited_rust_source(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "external/base/crates/execution/evm/Cargo.toml",
                  "[package]\nname=\"base-execution-evm\"\n")
            _make(ws, "external/base/crates/execution/evm/src/lib.rs",
                  "pub fn execute() {}\n")
            _make(ws, "scanners/_slither-tmp/lib/risc0-ethereum/Cargo.toml",
                  "[package]\nname=\"risc0-ethereum-trie\"\n")
            _make(ws, "scanners/_slither-tmp/lib/risc0-ethereum/src/lib.rs",
                  "pub fn scanner_only() {}\n")

            graph = self._build(ws)

            crates = {k for k in graph if k != "_meta"}
            self.assertEqual(crates, {"base-execution-evm"})
            self.assertEqual(graph["_meta"]["crate_count"], 1)


if __name__ == "__main__":
    unittest.main()
