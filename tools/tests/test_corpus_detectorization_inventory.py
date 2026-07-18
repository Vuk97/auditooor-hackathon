#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "corpus-detectorization-inventory.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("corpus_detectorization_inventory", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["corpus_detectorization_inventory"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class CorpusDetectorizationInventoryTests(unittest.TestCase):
    def test_swival_rows_route_to_detectorized_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            swival = base / "swival_findings_normalized.json"
            swival.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "id": "SWIVAL-INT-001",
                                "title": "integer length truncation before allocation",
                                "source_path": "library/std/src/io/read.rs",
                                "family": "integer overflow / usize truncation",
                            },
                            {
                                "id": "SWIVAL-DECODE-002",
                                "title": "snappy decompress_vec decode bomb",
                                "source_path": "library/std/src/codec/snappy.rs",
                                "family": "unbounded decompress",
                            },
                            {
                                "id": "SWIVAL-ATOMIC-003",
                                "title": "Relaxed atomic lifecycle state transition",
                                "source_path": "library/std/src/sync/state.rs",
                                "family": "atomic ordering hazard",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = MOD.build_inventory(
                workspace=None,
                swival_json=[swival],
                rust_corpus_index=[],
                zkbugs_index=[],
                recon_json=[],
                source_mining_json=[],
            )
            rows = payload["rows"]
            self.assertEqual(len(rows), 3)
            self.assertEqual(
                {row["terminal_state"] for row in rows},
                {"detectorized"},
            )
            lanes = {row["source_id"]: row["detector_or_lane"] for row in rows}
            self.assertEqual(lanes["SWIVAL-INT-001"], "base-rust-swival-shape-scan")
            self.assertEqual(lanes["SWIVAL-DECODE-002"], "rust-decode-bomb-scan")
            self.assertEqual(lanes["SWIVAL-ATOMIC-003"], "base-rust-swival-shape-scan")
            for row in rows:
                self.assertEqual(row["selected_impact"], "")
                self.assertEqual(row["severity"], "none")
                self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
                self.assertEqual(row["submit_status"], "NOT_SUBMIT_READY")
                self.assertTrue(row["impact_contract_required"])
                self.assertEqual(row["impact_contract_id"], "")

    def test_terminal_states_cover_killed_blocked_and_harness_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            swival = base / "swival.json"
            swival.write_text(
                json.dumps(
                    [
                        {
                            "id": "SWIVAL-WIN",
                            "title": "Windows-only terminal unicode issue",
                            "source_path": "library/std/src/os/windows.rs",
                        },
                        {
                            "id": "SWIVAL-MISSING",
                            "title": "integer truncation but source missing",
                        },
                        {
                            "id": "SWIVAL-MANUAL",
                            "title": "cross component cache invalidation concern",
                            "source_path": "library/std/src/cache.rs",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            payload = MOD.build_inventory(
                workspace=None,
                swival_json=[swival],
                rust_corpus_index=[],
                zkbugs_index=[],
                recon_json=[],
                source_mining_json=[],
            )
            by_id = {row["source_id"]: row for row in payload["rows"]}
            self.assertEqual(by_id["SWIVAL-WIN"]["terminal_state"], "killed")
            self.assertEqual(by_id["SWIVAL-MISSING"]["terminal_state"], "blocked_missing_source")
            self.assertEqual(by_id["SWIVAL-MANUAL"]["terminal_state"], "harness_task")

    def test_zkbugs_recon_and_source_mining_are_impact_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            zk = base / "zkbugs_index.json"
            zk.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "bug_id": "ZK-001",
                                "title": "bellperson unconstrained zero default",
                                "dsl": "Rust",
                                "vulnerability": "bellperson zero witness accepted",
                                "config_path": "dataset/bellperson/zkbugs_config.json",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            recon = base / "recon_results.json"
            recon.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "id": "RECON-001",
                                "title": "counterexample found",
                                "status": "counterexample",
                                "replay_command": "forge test --match-test test_replay",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            sm = base / "survivors.json"
            sm.write_text(
                json.dumps(
                    [
                        {
                            "candidate_id": "SM-001",
                            "bug_shape": "source-mined verifier concern",
                            "source_files": ["src/lib.rs:10-20"],
                            "severity": "Critical",
                            "selected_impact": "Network not being able to confirm new transactions",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            payload = MOD.build_inventory(
                workspace=None,
                swival_json=[],
                rust_corpus_index=[],
                zkbugs_index=[zk],
                recon_json=[recon],
                source_mining_json=[sm],
            )
            by_corpus = {row["corpus"]: row for row in payload["rows"]}
            self.assertEqual(by_corpus["zkbugs"]["terminal_state"], "detectorized")
            self.assertEqual(by_corpus["recon"]["terminal_state"], "harness_task")
            self.assertEqual(by_corpus["source_mining"]["terminal_state"], "harness_task")
            for row in payload["rows"]:
                self.assertEqual(row["selected_impact"], "")
                self.assertEqual(row["severity"], "none")
                self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
                self.assertEqual(row["submit_status"], "NOT_SUBMIT_READY")
                self.assertTrue(row["impact_contract_required"])

    def test_rust_corpus_index_routes_detector_invariant_and_replay_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            rust_index = base / "rust_corpus_index.json"
            rust_index.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "item_id": "RB-DETECT",
                                "title": "unsafe decode fixture",
                                "route": "detector",
                                "family": "rust_unsafe_memory_boundary",
                                "fixture_backed": True,
                            },
                            {
                                "item_id": "RB-TRAIT",
                                "title": "cfg trait dispatch divergence",
                                "route": "invariant",
                                "family": "rust_trait_macro_cfg_resolution",
                                "blockers": ["requires_cross_crate_trait_macro_cfg_resolution"],
                            },
                            {
                                "item_id": "RB-REPLAY",
                                "title": "reth state root replay",
                                "route": "replay",
                                "family": "rust_dlt_runtime_execution",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = MOD.build_inventory(
                workspace=None,
                swival_json=[],
                rust_corpus_index=[rust_index],
                zkbugs_index=[],
                recon_json=[],
                source_mining_json=[],
            )
            by_id = {row["source_id"]: row for row in payload["rows"]}
            self.assertEqual(by_id["RB-DETECT"]["terminal_state"], "detectorized")
            self.assertEqual(by_id["RB-TRAIT"]["terminal_state"], "blocked_missing_source")
            self.assertEqual(by_id["RB-REPLAY"]["terminal_state"], "harness_task")
            for row in payload["rows"]:
                self.assertEqual(row["selected_impact"], "")
                self.assertEqual(row["severity"], "none")
                self.assertTrue(row["impact_contract_required"])

    def test_jsonl_swival_corpus_is_parsed(self) -> None:
        # Real swival corpus ships as JSON Lines (reference/findings_go_swival.jsonl),
        # which a single json.loads() cannot parse. The reader must fall back to JSONL
        # and nested provenance.affected_location must count as a source pointer.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            swival = base / "findings_go_swival.jsonl"
            swival.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "finding_id": "swival-go-001",
                                "bug_class": "go.integer.length_prefix_overflow",
                                "summary": "u64 length prefix truncation before allocation",
                                "provenance": {"affected_location": "src/foo.go:10"},
                            }
                        ),
                        "",
                        json.dumps(
                            {
                                "finding_id": "swival-go-002",
                                "bug_class": "go.tls.context_cancel",
                                "summary": "Relaxed atomic lifecycle state transition race",
                                "provenance": {"affected_location": "src/bar.go:20"},
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            payload = MOD.build_inventory(
                workspace=None,
                swival_json=[swival],
                rust_corpus_index=[],
                zkbugs_index=[],
                recon_json=[],
                source_mining_json=[],
            )
            by_id = {row["source_id"]: row for row in payload["rows"]}
            self.assertEqual(len(by_id), 2)
            self.assertEqual(by_id["swival-go-001"]["terminal_state"], "detectorized")
            self.assertEqual(by_id["swival-go-002"]["terminal_state"], "detectorized")

    def test_default_discovery_finds_real_repo_corpus(self) -> None:
        # Guards against the rows=0 regression: with no explicit inputs the tool
        # must discover the real shipped corpus artifacts under the repo root.
        payload = MOD.build_inventory(
            workspace=None,
            swival_json=[],
            rust_corpus_index=[],
            zkbugs_index=[],
            recon_json=[],
            source_mining_json=[],
        )
        self.assertGreater(payload["summary"]["row_count"], 0)
        inputs = payload["inputs"]
        self.assertTrue(inputs["swival_rust"], "swival corpus not discovered")
        self.assertTrue(inputs["zkbugs"], "zkbugs corpus not discovered")
        # No worktree/vendored mirror should be pulled in.
        for group in inputs.values():
            for path in group:
                self.assertNotIn(".claude", Path(path).parts)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            swival = base / "swival_findings_normalized.json"
            out = base / "out"
            swival.write_text(
                json.dumps(
                    [
                        {
                            "id": "SWIVAL-UNSAFE",
                            "title": "unsafe from_raw_parts length primitive",
                            "source_path": "library/std/src/slice.rs",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--swival-json",
                    str(swival),
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
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["row_count"], 1)
            self.assertTrue((out / "corpus_detectorization_inventory.json").is_file())
            self.assertTrue((out / "corpus_detectorization_inventory.md").is_file())


if __name__ == "__main__":
    unittest.main()
