#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "batch-shape-cluster-predicates.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("batch_shape_cluster_predicates", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class BatchShapeClusterPredicateTests(unittest.TestCase):
    def test_clusters_by_shape_not_attack_class(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inv = root / "invariants.jsonl"
            idx = root / "by_function_shape.d"
            _write_jsonl(
                inv,
                [
                    {
                        "invariant_id": "INV-A",
                        "category": "authorization",
                        "target_lang": "solidity",
                        "source_finding_ids": ["src-a", "src-b"],
                    }
                ],
            )
            _write_jsonl(
                idx / "aa.jsonl",
                [
                    {
                        "record_id": "src-a",
                        "shape_hash": "same-shape",
                        "function_signature": "function withdraw(address to) external",
                        "target_language": "solidity",
                        "target_domain": "vault",
                        "attack_class": "auth-bypass",
                    },
                    {
                        "record_id": "src-b",
                        "shape_hash": "same-shape",
                        "function_signature": "function withdraw(address to) external",
                        "target_language": "solidity",
                        "target_domain": "lending",
                        "attack_class": "accounting-drift",
                    },
                ],
            )

            args = TOOL.parse_args(
                [
                    "--invariants",
                    str(inv),
                    "--shape-index-dir",
                    str(idx),
                    "--batch-size",
                    "1",
                ]
            )
            payload = TOOL.build_payload(args)
            candidates = payload["_predicate_candidates"]
            self.assertEqual(payload["annotation"]["annotation_rows"], 2)
            self.assertEqual(candidates[0]["shape_cluster_key"], "same-shape")
            self.assertEqual(candidates[0]["support_annotation_rows"], 2)
            self.assertEqual(
                set(candidates[0]["support_attack_classes_sample"]),
                {"accounting-drift", "auth-bypass"},
            )
            self.assertTrue(payload["constraints"]["cluster_key_excludes_attack_class"])

    def test_batch_annotation_uses_existing_index_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inv = root / "invariants.jsonl"
            idx = root / "by_function_shape.d"
            _write_jsonl(
                inv,
                [
                    {"invariant_id": "INV-1", "source_finding_ids": ["src-1"]},
                    {"invariant_id": "INV-2", "source_finding_ids": ["src-2"]},
                ],
            )
            _write_jsonl(
                idx / "aa.jsonl",
                [
                    {"record_id": "src-1", "shape_hash": "h1", "function_signature": "f(uint256)", "target_language": "solidity"},
                    {"record_id": "src-2", "shape_hash": "h2", "function_signature": "g(uint256)", "target_language": "solidity"},
                ],
            )
            args = TOOL.parse_args(["--invariants", str(inv), "--shape-index-dir", str(idx), "--batch-size", "1"])
            payload = TOOL.build_payload(args)
            annotations = payload["_annotations"]
            self.assertEqual(payload["annotation"]["batch_count"], 2)
            self.assertEqual([a["batch_index"] for a in annotations], [0, 1])
            self.assertEqual(
                {a["shape_annotation"]["annotation_method"] for a in annotations},
                {"precomputed-by_function_shape-index"},
            )
            self.assertFalse(payload["constraints"]["per_record_mining"])
            self.assertFalse(payload["constraints"]["network"])
            self.assertFalse(payload["constraints"]["provider_calls"])

    def test_fallback_shape_signature_is_deterministic(self) -> None:
        row_a = {"function_signature": "function  foo(uint256 x)  external", "target_language": "solidity"}
        row_b = {"function_signature": "function foo(uint256 x) external", "target_language": "solidity"}
        fields_a = TOOL._shape_fields(row_a)
        fields_b = TOOL._shape_fields(row_b)
        self.assertEqual(fields_a["shape_cluster_key"], fields_b["shape_cluster_key"])
        self.assertRegex(fields_a["shape_cluster_key"], r"^sig-[0-9a-f]{16}$")

    def test_false_positive_probe_checks_outside_cluster(self) -> None:
        annotations = [
            {"shape_annotation": {"shape_cluster_key": "h1", "shape_signature_hash": "s1"}, "record_id": "a", "invariant_id": "i"},
            {"shape_annotation": {"shape_cluster_key": "h2", "shape_signature_hash": "s2"}, "record_id": "b", "invariant_id": "i"},
        ]
        candidates, summary = TOOL.distill_clusters(
            annotations,
            max_predicates=10,
            target_coverage=0.8,
            false_positive_sample_size=10,
            emit_per_invariant_candidates=False,
        )
        self.assertEqual(summary["cluster_count"], 2)
        self.assertEqual(candidates[0]["validation"]["false_positive_count"], 0)
        self.assertEqual(candidates[0]["candidate_status"], "rejected-shape-validation")
        self.assertFalse(candidates[0]["validation"]["out_of_cluster_zero_fp_check"]["passed"])
        self.assertEqual(candidates[0]["validation"]["out_of_cluster_zero_fp_check"]["sample_size_selected"], 1)
        self.assertEqual(candidates[0]["validation"]["semantic_acceptance_status"], "pending-live-target-dogfood")

    def test_false_positive_probe_detects_cross_cluster_signature_collisions(self) -> None:
        annotations = [
            {"shape_annotation": {"shape_cluster_key": "h1", "shape_signature_hash": "s1"}, "record_id": "a", "invariant_id": "i1"},
            {"shape_annotation": {"shape_cluster_key": "h2", "shape_signature_hash": "s1"}, "record_id": "b", "invariant_id": "i2"},
            {"shape_annotation": {"shape_cluster_key": "h3", "shape_signature_hash": "s3"}, "record_id": "c", "invariant_id": "i3"},
        ]
        candidates, _ = TOOL.distill_clusters(
            annotations,
            max_predicates=10,
            target_coverage=0.8,
            false_positive_sample_size=2,
            emit_per_invariant_candidates=False,
        )
        lead = candidates[0]
        self.assertEqual(lead["shape_cluster_key"], "h1")
        self.assertEqual(lead["shape_signature_hash"], "s1")
        self.assertEqual(lead["validation"]["false_positive_count"], 1)
        self.assertEqual(lead["validation_status"], "rejected-shape-validation")
        self.assertFalse(lead["validation"]["out_of_cluster_zero_fp_check"]["passed"])

    def test_emits_live_target_adapter_fields_per_invariant(self) -> None:
        annotations = [
            {
                "shape_annotation": {"shape_cluster_key": "h1", "shape_signature_hash": "s1", "function_signature": "f()"},
                "record_id": "a",
                "invariant_id": "INV-A",
            },
            {
                "shape_annotation": {"shape_cluster_key": "h1", "shape_signature_hash": "s1", "function_signature": "f()"},
                "record_id": "b",
                "invariant_id": "INV-B",
            },
        ]
        candidates, _ = TOOL.distill_clusters(
            annotations,
            max_predicates=10,
            target_coverage=0.8,
            false_positive_sample_size=2,
            emit_per_invariant_candidates=True,
        )
        self.assertEqual(len(candidates), 2)
        self.assertEqual({c["cluster_id"] for c in candidates}, {"h1"})
        self.assertEqual({c["status"] for c in candidates}, {"pending-live-target-dogfood"})
        self.assertEqual({c["function_signature"] for c in candidates}, {"f()"})
        self.assertEqual({c["invariant_id"] for c in candidates}, {"INV-A", "INV-B"})

    def test_can_exceed_max_predicates_to_hit_target_coverage(self) -> None:
        annotations = []
        for i in range(4):
            annotations.append(
                {
                    "shape_annotation": {
                        "shape_cluster_key": f"h{i}",
                        "shape_signature_hash": f"s{i}",
                        "function_signature": f"f{i}()",
                    },
                    "record_id": f"r{i}",
                    "invariant_id": f"INV-{i}",
                }
            )
        candidates, summary = TOOL.distill_clusters(
            annotations,
            max_predicates=3,
            target_coverage=0.8,
            false_positive_sample_size=1,
            emit_per_invariant_candidates=False,
        )
        self.assertEqual(len(candidates), 4)
        self.assertGreaterEqual(summary["selected_annotation_coverage"], 0.8)

    def test_rejects_negative_false_positive_sample_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "false-positive-sample-size"):
            TOOL.distill_clusters(
                [],
                max_predicates=1,
                target_coverage=0.8,
                false_positive_sample_size=-1,
                emit_per_invariant_candidates=False,
            )


if __name__ == "__main__":
    unittest.main()
