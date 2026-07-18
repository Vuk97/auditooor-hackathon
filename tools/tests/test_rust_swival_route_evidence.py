from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-swival-route-evidence.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_swival_route_evidence", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_swival_route_evidence"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write_fixture_index(path: Path) -> None:
    records = [
        {
            "item_id": "SWIVAL-H-001",
            "title": "Unsafe from_raw_parts length overflow in decoder",
            "corpus_severity": "High",
            "component": "io",
            "route": "detector",
            "family": "rust_unsafe_memory_boundary",
            "source_pointers": ["library/std/src/io/mod.rs"],
            "patch_pointers": ["patches/H-001.patch"],
            "fixture_pointers": ["tests/H-001-repro.rs"],
        },
        {
            "item_id": "SWIVAL-M-002",
            "title": "Relaxed atomic ordering allows stale state transition",
            "corpus_severity": "Medium",
            "component": "sync",
            "description": "race under relaxed atomic ordering",
            "source_pointers": ["library/std/src/sync/state.rs"],
        },
        {
            "item_id": "SWIVAL-M-003",
            "title": "Consensus node decode divergence causes liveness failure",
            "corpus_severity": "Medium",
            "component": "runtime",
            "description": "reth engine api state root decode mismatch affects DLT finality",
            "source_pointers": ["library/std/src/runtime/decode.rs"],
            "replay_commands": ["cargo test consensus_decode_replay"],
        },
        {
            "item_id": "SWIVAL-M-004",
            "title": "cfg feature trait impl divergence",
            "corpus_severity": "Medium",
            "component": "alloc",
            "description": "cross-crate trait impl differs under cfg(feature)",
            "source_pointers": ["library/alloc/src/lib.rs"],
            "fixture_pointers": ["tests/cfg_trait.rs"],
        },
        {
            "item_id": "SWIVAL-L-005",
            "title": "Windows-only terminal unicode rendering issue",
            "corpus_severity": "Low",
            "component": "terminal",
            "description": "host-only terminal unicode handling",
            "source_pointers": ["library/std/src/sys/windows/stdio.rs"],
        },
    ]
    payload = {
        "schema": "auditooor.rust_corpus_ingest.v1",
        "summary": {"item_count": len(records)},
        "records": records,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class RustSwivalRouteEvidenceTests(unittest.TestCase):
    def test_missing_input_emits_exact_local_checkout_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            payload = MOD.build_payload(ws, [])
            self.assertEqual(payload["summary"]["row_count"], 0)
            self.assertEqual(payload["blockers"][0]["blocker_id"], "swival-rust-stdlib-local-checkout-or-ingest-missing")
            self.assertIn("Swival/security-audits", payload["blockers"][0]["required_input"])
            self.assertIn("make rust-corpus-ingest", " ".join(payload["blockers"][0]["next_commands"]))

    def test_routes_detector_invariant_runtime_cross_crate_and_oos(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "rust_corpus_index.json"
            _write_fixture_index(index)
            payload = MOD.build_payload(ws, [index], expected_total=5)
            by_id = {row["item_id"]: row for row in payload["rows"]}
            self.assertEqual(by_id["SWIVAL-H-001"]["primary_route"], "detector_candidate")
            self.assertEqual(by_id["SWIVAL-H-001"]["detector_lane"], "rust_unsafe_memory_boundary_detector")
            self.assertTrue(by_id["SWIVAL-H-001"]["fixture_backed"])
            self.assertEqual(by_id["SWIVAL-M-002"]["primary_route"], "invariant_family")
            self.assertEqual(by_id["SWIVAL-M-003"]["primary_route"], "runtime_dlt_relevance")
            self.assertEqual(by_id["SWIVAL-M-003"]["runtime_dlt_relevance"], "yes")
            self.assertEqual(by_id["SWIVAL-M-004"]["primary_route"], "cross_crate_semantic_blocker")
            self.assertEqual(by_id["SWIVAL-M-004"]["cross_crate_blocker"], "requires_cross_crate_trait_macro_cfg_resolution")
            self.assertEqual(by_id["SWIVAL-L-005"]["primary_route"], "oos_not_applicable")
            self.assertEqual(payload["summary"]["coverage_complete_for_expected_swival_total"], True)
            self.assertFalse(payload["blockers"])

    def test_incomplete_expected_total_is_explicit_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "rust_corpus_index.json"
            _write_fixture_index(index)
            payload = MOD.build_payload(ws, [index])
            self.assertFalse(payload["summary"]["coverage_complete_for_expected_swival_total"])
            self.assertEqual(payload["blockers"][0]["blocker_id"], "swival-rust-stdlib-route-coverage-incomplete")
            self.assertEqual(payload["blockers"][0]["observed_total"], 5)
            self.assertEqual(payload["blockers"][0]["expected_total"], 151)

    def test_cli_writes_json_and_markdown_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "rust_corpus_index.json"
            out = Path(tmp) / "out"
            _write_fixture_index(index)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--input",
                    str(index),
                    "--expected-total",
                    "5",
                    "--out-dir",
                    str(out),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)["summary"]
            self.assertEqual(summary["row_count"], 5)
            self.assertTrue((out / "rust_swival_route_evidence.json").is_file())
            self.assertTrue((out / "rust_swival_route_evidence.md").is_file())
            self.assertTrue((ws / ".auditooor" / "rust_swival_route_evidence.json").is_file())


if __name__ == "__main__":
    unittest.main()
