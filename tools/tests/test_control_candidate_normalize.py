#!/usr/bin/env python3
"""Tests for control-plane promotion-candidate normalization."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.candidate_normalize import (
    SCHEMA,
    discover_normalized_candidate_rows,
    discover_wave_promotion_candidates,
    normalize_candidate_payload,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ControlCandidateNormalizeTests(unittest.TestCase):
    def test_simple_single_candidate_row_normalizes_to_stable_schema(self) -> None:
        rows = normalize_candidate_payload(
            {
                "schema": "auditooor.source_mining.promotion_candidate.v0",
                "candidate_id": "cache-poison",
                "bug_shape": "Public cache poisoning",
                "severity": "High",
                "likelihood": "Medium",
                "impact": "RPC denial of service",
                "status": "KEEP_FOR_LOCAL_VERIFICATION",
                "source_files": ["src/rpc/cache.rs:44"],
                "oos_risk": "low",
                "dupe_risk": "unknown",
            },
            source_file="/tmp/promotion_candidates.json",
        )

        self.assertEqual(len(rows), 1)
        row = rows[0].to_dict()
        self.assertEqual(row["schema"], SCHEMA)
        self.assertEqual(row["id"], "cache-poison")
        self.assertEqual(row["title"], "Public cache poisoning")
        self.assertEqual(row["source_schema"], "auditooor.source_mining.promotion_candidate.v0")
        self.assertEqual(row["severity"], "High")
        self.assertEqual(row["likelihood"], "Medium")
        self.assertEqual(row["impact"], "RPC denial of service")
        self.assertEqual(row["status"], "KEEP_FOR_LOCAL_VERIFICATION")
        self.assertEqual(row["proof_state"], "planned")
        self.assertEqual(row["source_paths"], ["src/rpc/cache.rs:44"])
        self.assertEqual(row["oos_risk"], "low")
        self.assertEqual(row["dupe_risk"], "unknown")
        self.assertEqual(row["errors"], [])

    def test_list_payload_normalizes_all_candidate_rows(self) -> None:
        rows = normalize_candidate_payload(
            [
                {
                    "id": "first",
                    "title": "First candidate",
                    "status": "candidate",
                    "files": "contracts/First.sol:10",
                },
                {
                    "candidate_id": "second",
                    "claim": "Second candidate",
                    "promotion_status": "poc_ready",
                    "source_paths": ["contracts/Second.sol:20"],
                    "poc_command": "forge test --match-test testSecond",
                },
            ],
            source_file="/tmp/list.json",
        )

        by_id = {row.id: row.to_dict() for row in rows}
        self.assertEqual(set(by_id), {"first", "second"})
        self.assertEqual(by_id["first"]["source_paths"], ["contracts/First.sol:10"])
        self.assertEqual(by_id["second"]["status"], "poc_ready")
        self.assertEqual(by_id["second"]["proof_state"], "scaffolded")

    def test_container_dicts_with_candidates_items_and_results_are_unwrapped(self) -> None:
        for key in ("candidates", "items", "results"):
            with self.subTest(container=key):
                rows = normalize_candidate_payload(
                    {
                        "schema_version": f"container.{key}.v1",
                        key: [
                            {
                                "candidate_id": f"{key}-row",
                                "description": f"{key} row",
                                "confidence": "high",
                                "selected_impact": "temporary consensus halt",
                                "line_cite": "node/src/payload.rs:99",
                            }
                        ],
                    },
                    source_file=f"/tmp/{key}.json",
                )

                self.assertEqual(len(rows), 1)
                row = rows[0].to_dict()
                self.assertEqual(row["source_schema"], f"container.{key}.v1")
                self.assertEqual(row["id"], f"{key}-row")
                self.assertEqual(row["likelihood"], "high")
                self.assertEqual(row["impact"], "temporary consensus halt")
                self.assertEqual(row["source_paths"], ["node/src/payload.rs:99"])

    def test_upstream_equivalent_gate_shape_preserves_gate_and_nested_candidate(self) -> None:
        rows = normalize_candidate_payload(
            {
                "schema": "auditooor.upstream_equivalent_gate.v1",
                "results": [
                    {
                        "upstream_candidate": {
                            "candidate_id": "upstream-parity",
                            "title": "Upstream fix parity missing",
                            "severity": "Medium",
                            "impact_contract": {
                                "listed_impact": "patched upstream invariant absent downstream"
                            },
                            "source_files": ["external/upstream/Fix.sol:12"],
                        },
                        "upstream_equivalent_gate": {
                            "status": "fail",
                            "upstream_pr": "base-org/base#123",
                            "reason": "downstream fork lacks equivalent guard",
                        },
                        "dupe_risk": {"risk": "low"},
                        "oos_risk": {"status": "needs_review"},
                    }
                ],
            },
            source_file="/tmp/equivalent.json",
        )

        self.assertEqual(len(rows), 1)
        row = rows[0].to_dict()
        self.assertEqual(row["id"], "upstream-parity")
        self.assertEqual(row["title"], "Upstream fix parity missing")
        self.assertEqual(row["severity"], "Medium")
        self.assertEqual(row["impact"], "patched upstream invariant absent downstream")
        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["proof_state"], "blocked")
        self.assertEqual(row["source_paths"], ["external/upstream/Fix.sol:12"])
        self.assertEqual(row["dupe_risk"], "low")
        self.assertEqual(row["oos_risk"], "needs_review")
        self.assertEqual(
            row["gate"]["upstream_equivalent_gate"]["upstream_pr"],
            "base-org/base#123",
        )

    def test_discovery_reads_wave_promotion_candidates_and_records_malformed_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "wave-001" / "promotion_candidates.json",
                {
                    "candidates": [
                        {
                            "candidate_id": "wave-one",
                            "bug_shape": "Wave one candidate",
                            "source_files": ["src/Wave.sol:1"],
                        }
                    ]
                },
            )
            malformed = ws / ".auditooor" / "wave-002" / "promotion_candidates.json"
            malformed.parent.mkdir(parents=True)
            malformed.write_text("{not valid json\n", encoding="utf-8")

            rows = discover_wave_promotion_candidates(ws)
            dict_rows = discover_normalized_candidate_rows(ws)

        by_id = {row.id: row.to_dict() for row in rows}
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(dict_rows), 2)
        self.assertEqual(by_id["wave-one"]["title"], "Wave one candidate")
        self.assertEqual(by_id["wave-002-promotion_candidates"]["status"], "blocked")
        self.assertEqual(by_id["wave-002-promotion_candidates"]["proof_state"], "blocked")
        self.assertEqual(by_id["wave-002-promotion_candidates"]["source_schema"], "malformed_json")
        self.assertTrue(by_id["wave-002-promotion_candidates"]["errors"])
        self.assertIn("invalid_json", by_id["wave-002-promotion_candidates"]["errors"][0])

    def test_unsupported_payload_records_blocked_error_row(self) -> None:
        rows = normalize_candidate_payload(
            {"schema": "empty.container.v1", "metadata": {"count": 0}},
            source_file="/tmp/empty.json",
        )

        self.assertEqual(len(rows), 1)
        row = rows[0].to_dict()
        self.assertEqual(row["schema"], SCHEMA)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["proof_state"], "blocked")
        self.assertEqual(row["source_schema"], "empty.container.v1")
        self.assertEqual(row["gate"]["status"], "blocked")
        self.assertIn("candidate_container_missing_rows", row["errors"])


if __name__ == "__main__":
    unittest.main()
