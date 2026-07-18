from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-detectorization-map.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("zkbugs_detectorization_map", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["zkbugs_detectorization_map"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_index(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"records": records}), encoding="utf-8")


class ZkbugsDetectorizationMapTests(unittest.TestCase):
    def test_maps_existing_detector_rows_and_excludes_generic_noise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / "zkbugs_index.json"
            _write_index(
                index,
                [
                    {
                        "bug_id": "panther/num2bits",
                        "title": "Blacklist states not representable with Num2Bits(254)",
                        "dsl": "Circom",
                        "vulnerability": "Under-Constrained",
                        "root_cause": "Missing Input Constraints",
                        "impact": "Soundness",
                        "priority_score": 55,
                    },
                    {
                        "bug_id": "generic/halo2",
                        "title": "Generic Halo2 advice column unconstrained",
                        "dsl": "Halo2",
                        "vulnerability": "Under-Constrained",
                        "root_cause": "Assigned but Unconstrained",
                        "impact": "Soundness",
                        "priority_score": 30,
                    },
                ],
            )

            payload = MOD.build_payload(root, index)

        self.assertEqual(payload["summary"]["index_records"], 2)
        self.assertEqual(payload["summary"]["queued_rows"], 1)
        self.assertEqual(payload["summary"]["excluded_rows"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["rule_id"], "circom-num2bits-state-alias")
        self.assertEqual(row["lane"], "existing-circom-detector")
        self.assertEqual(row["severity"], "none")
        self.assertEqual(row["selected_impact"], "")
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(row["impact_contract_required"])
        self.assertIn("detectors/circom_wave1/zkbugs_num2bits_254_state_alias.py", row["detector_paths_present"])

    def test_maps_base_sp1_glue_invariant_without_existing_detector(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / "zkbugs_index.json"
            _write_index(
                index,
                [
                    {
                        "bug_id": "sp1/vk-root",
                        "title": "Missing vk_root validation in Rust verifier",
                        "dsl": "Plonky3",
                        "vulnerability": "Under-Constrained",
                        "root_cause": "Missing Input Constraints",
                        "impact": "Soundness",
                        "location_path": "crates/prover/src/verify.rs",
                        "priority_score": 40,
                    }
                ],
            )

            payload = MOD.build_payload(root, index)

        self.assertEqual(payload["summary"]["queued_rows"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["rule_id"], "base-sp1-verifier-metadata-binding")
        self.assertEqual(row["lane"], "base-zkverifier-invariant")
        self.assertIn("external/contracts/src/multiproof/zk/ZKVerifier.sol", row["base_anchors"])
        self.assertEqual(row["detector_paths"], [])

    def test_cli_writes_queue_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json"
            _write_index(
                index,
                [
                    {
                        "bug_id": "sp1/allocator",
                        "title": "Embedded allocator overflow vulnerabilities",
                        "dsl": "Plonky3",
                        "vulnerability": "Computational Issues",
                        "root_cause": "Other Programming Errors",
                        "impact": "Soundness",
                        "priority_score": 40,
                    }
                ],
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(root), "--print-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["queued_rows"], 1)
            self.assertTrue((root / ".auditooor" / "zkbugs_detectorization_map.json").is_file())
            self.assertTrue((root / ".auditooor" / "zkbugs_detectorization_map.md").is_file())
            self.assertEqual(payload["rows"][0]["rule_id"], "base-untrusted-length-allocation")


if __name__ == "__main__":
    unittest.main()
