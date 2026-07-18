#!/usr/bin/env python3
"""Tests for tools/rust-runtime-semantic-blockers.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-runtime-semantic-blockers.py"


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


def _write_scan_summary(ws: Path) -> None:
    summary = {
        "semantic_inventory": {
            "status": "OK",
            "source_graph": {"status": "OK", "path": str(ws / ".auditooor" / "rust_source_graph.json")},
            "cross_crate_graph": {"status": "OK", "path": str(ws / ".auditooor" / "rust_cross_crate_graph.json")},
        },
        "semantic_depth_accounting": {
            "schema": "auditooor.rust_semantic_depth_accounting.v1",
            "items": [
                {"id": "RD-16", "area": "runtime_resolution", "status": "blocked", "detail": "imports are not runtime calls"},
                {"id": "RD-17", "area": "macro_expansion", "status": "blocked", "detail": "macros are not expanded"},
                {"id": "RD-45", "area": "dependency_audit", "status": "implemented", "detail": "cargo audit available"},
            ],
        },
    }
    out = ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


class TestRustRuntimeSemanticBlockers(unittest.TestCase):
    def test_generates_queue_from_source_cross_crate_and_scan_summary(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/a/Cargo.toml", "[package]\nname=\"a\"\n[dependencies]\nb={path=\"../b\"}\n")
            _make(ws, "contracts/a/src/lib.rs", """\
use b::helper;
pub struct A;
pub trait RuntimeHook {
    fn apply(&self, env: Env);
}
impl RuntimeHook for A {
    fn apply(&self, env: Env) {
        runtime_macro!(env);
    }
}
#[cfg(feature = "reth")]
pub fn feature_gated_runtime(env: Env) {
    helper();
}
#[contractimpl]
impl A {
    pub fn execute(env: Env, to: Address, amount: i128) {
        env.invoke_contract(&to, &symbol_short!("x"), ().into());
        token::transfer(&env, &to, &amount);
    }
}
""")
            _make(ws, "contracts/b/Cargo.toml", "[package]\nname=\"b\"\n")
            _make(ws, "contracts/b/src/lib.rs", "pub fn helper() {}\n")
            _write_scan_summary(ws)

            proc = _run(["--workspace", str(ws), "--generate-graphs", "--limit", "50"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = ws / ".auditooor" / "rust_runtime_semantic_blockers.json"
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))

            self.assertEqual(payload["schema"], "auditooor.rust_runtime_semantic_blockers.v1")
            self.assertFalse(payload["promotion_allowed"])
            self.assertFalse(payload["semantic_completeness_claim"])
            self.assertLessEqual(payload["item_count"], 50)
            self.assertGreater(payload["item_count"], 0)
            self.assertIn("runtime_model_matrix", payload)
            self.assertIn("runtime_component_family_counts", payload)
            self.assertIn("runtime_readiness_gates", payload)
            self.assertIn("runtime_readiness_summary", payload)
            self.assertIn("semantic_resolution_hint_summary", payload)
            self.assertGreaterEqual(payload["summary"]["trait_method_impl_count"], 1)
            self.assertGreaterEqual(payload["summary"]["cfg_attr_count"], 1)
            self.assertGreaterEqual(payload["summary"]["macro_invocation_count"], 1)
            self.assertGreaterEqual(payload["semantic_resolution_hint_summary"]["trait_method_impls_indexed"], 1)
            self.assertGreaterEqual(payload["semantic_resolution_hint_summary"]["cfg_attrs_indexed"], 1)
            self.assertGreaterEqual(payload["semantic_resolution_hint_summary"]["macro_invocations_indexed"], 1)
            self.assertTrue(
                any(row["runtime_component_family"] == "execution_client" for row in payload["items"]),
                payload["items"],
            )
            blocker_ids = {bid for row in payload["items"] for bid in row["blocker_ids"]}
            self.assertIn("rust-trait-method-dispatch", blocker_ids)
            self.assertIn("rust-cfg-feature-resolution", blocker_ids)
            self.assertIn("rust-macro-expansion-required", blocker_ids)

            lanes = {row["action_lane"] for row in payload["items"]}
            self.assertIn("safe_detectorization_handoff", lanes)
            self.assertIn("runtime_semantic_blocker_queue", lanes)
            self.assertTrue(
                any(row["source_kind"] == "rust_cross_crate_graph.edge" for row in payload["items"]),
                payload["items"],
            )
            self.assertTrue(
                any(row["source_id"] == "RD-16" for row in payload["items"]),
                payload["items"],
            )
            for row in payload["items"]:
                self.assertEqual(row["severity"], "none")
                self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
                self.assertFalse(row["promotion_allowed"])
                self.assertEqual(row["runtime_model_requirement"]["model_status"], "required_not_collected")
                self.assertEqual(row["harness_binding_requirement"]["status"], "blocked_missing_runtime_binding")
                self.assertEqual(row["workspace_neutrality_requirement"]["status"], "required_not_demonstrated")
                self.assertTrue(row["executable_next_commands"])

            matrix = {row["runtime_component_family"]: row for row in payload["runtime_model_matrix"]}
            self.assertIn("execution_client", matrix)
            self.assertGreater(matrix["execution_client"]["matching_queue_rows"], 0)
            self.assertIn("state-root", " ".join(matrix["execution_client"]["required_proof_artifacts"]))
            gates = {row["runtime_component_family"]: row for row in payload["runtime_readiness_gates"]}
            self.assertEqual(gates["execution_client"]["status"], "observed_but_unproved")
            self.assertEqual(gates["tee_runtime"]["status"], "missing_workspace_evidence")
            self.assertIn("non-Base/hermetic", " ".join(gates["execution_client"]["required_before_closure"]))

    def test_limit_truncates_without_completeness_claim(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, ".auditooor/rust_source_graph.json", json.dumps({
                "_meta": {"schema_version": "auditooor.rust_source_graph.v1", "workspace": str(ws), "crate_count": 1},
                "a": {
                    "crate_root": "contracts/a",
                    "files_scanned": 1,
                    "entrypoints": [
                        {"file": "contracts/a/src/lib.rs", "line": i, "fn": f"entry_{i}", "kind": "lib_rs_pub", "attrs": []}
                        for i in range(1, 80)
                    ],
                    "trait_impls": [],
                    "external_calls": [],
                    "unsafe_blocks": [],
                    "value_movement_calls": [],
                },
            }) + "\n")
            _make(ws, ".auditooor/rust_cross_crate_graph.json", json.dumps({
                "_meta": {"schema_version": "auditooor.rust_cross_crate_graph.v1", "workspace": str(ws), "crate_count": 1, "edge_count": 0},
                "crates": {},
                "edges": [],
            }) + "\n")

            proc = _run(["--workspace", str(ws), "--limit", "50"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((ws / ".auditooor" / "rust_runtime_semantic_blockers.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["item_count"], 50)
            self.assertTrue(payload["truncated"])
            self.assertFalse(payload["semantic_completeness_claim"])


if __name__ == "__main__":
    unittest.main()
