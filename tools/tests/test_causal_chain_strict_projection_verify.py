from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXTRACTOR_PATH = REPO_ROOT / "tools" / "causal-chain-extract.py"
VERIFIER_PATH = REPO_ROOT / "tools" / "causal-chain-strict-projection-verify.py"


def _import_tool(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACTOR = _import_tool(EXTRACTOR_PATH, "causal_chain_extract_for_projection_verify_tests")
VERIFIER = _import_tool(VERIFIER_PATH, "causal_chain_strict_projection_verify_tests")


def _sample_rows() -> list[dict]:
    return [
        {
            "schema_version": EXTRACTOR.SCHEMA_VERSION,
            "chain_id": "chain:withdraw-001",
            "source_record_id": "audit:demo:withdraw-001",
            "source_refs": ["audit/corpus_tags/tags/demo/withdraw.yaml"],
            "preconditions": ["Victim has shares", "Public withdrawFor entrypoint"],
            "trigger": "Attacker calls withdrawFor(victim) without authorization",
            "defense": "Patch by binding msg.sender to owner or approved operator",
            "impact": [{"impact_class": "fund-loss", "severity_at_finding": "high"}],
            "verification_tier": "tier-2-verified-public-archive",
            "target_component": "DemoVault.withdraw",
            "target_domain": "vault",
            "target_language": "solidity",
            "requires_state": ["state:victim-balance-positive"],
            "produces_state": ["state:protocol-funds-displaced"],
        },
        {
            "schema_version": EXTRACTOR.SCHEMA_VERSION,
            "chain_id": "chain:oracle-002",
            "source_record_id": "audit:demo:oracle-002",
            "source_refs": ["audit/corpus_tags/tags/demo/oracle.yaml"],
            "preconditions": ["Oracle price is stale"],
            "trigger": "Attacker liquidates against stale price",
            "defense": "Reject stale oracle rounds",
            "impact": [{"impact_class": "fund-loss", "severity_at_finding": "medium"}],
            "verification_tier": "public-corpus",
            "target_component": "DemoOracle.update",
            "target_domain": "lending",
            "target_language": "solidity",
            "produces_state": ["state:stale-price-used", "state:position-liquidated"],
        },
    ]


class CausalChainStrictProjectionVerifyTests(unittest.TestCase):
    def _write_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        rows = _sample_rows()
        chains_path = root / "causal_chains.jsonl"
        index_path = root / "causal_chain_index.json"
        projection_path = root / "causal_chain_strict_projection.jsonl"
        EXTRACTOR.write_jsonl(chains_path, rows)
        strict_summary = EXTRACTOR.write_strict_projection_jsonl(projection_path, rows)
        EXTRACTOR.write_index(index_path, rows, strict_projection=strict_summary)
        return chains_path, index_path, projection_path

    def test_verifier_accepts_fresh_strict_projection_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-projection-verify-") as tmp:
            chains_path, index_path, projection_path = self._write_fixture(Path(tmp))

            summary = VERIFIER.verify_strict_projection(
                chains_jsonl=chains_path,
                index_json=index_path,
                strict_projection_jsonl=projection_path,
            )

            self.assertTrue(summary["met"], summary["errors"])
            self.assertEqual(summary["source_rows"], 2)
            self.assertEqual(summary["expected_summary"]["row_count"], 2)
            self.assertEqual(summary["expected_summary"]["four_block_rows"], 2)
            self.assertEqual(summary["actual_summary"]["row_count"], 2)

    def test_verifier_cli_emits_json_and_zero_exit_on_fresh_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-projection-verify-") as tmp:
            chains_path, index_path, projection_path = self._write_fixture(Path(tmp))

            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER_PATH),
                    "--chains-jsonl",
                    str(chains_path),
                    "--index-json",
                    str(index_path),
                    "--strict-projection-jsonl",
                    str(projection_path),
                    "--json",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["schema"], VERIFIER.SCHEMA)
            self.assertTrue(payload["met"], payload["errors"])

    def test_verifier_rejects_modified_projection_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-projection-verify-") as tmp:
            chains_path, index_path, projection_path = self._write_fixture(Path(tmp))
            rows = [
                json.loads(line)
                for line in projection_path.read_text(encoding="utf-8").splitlines()
            ]
            rows[0]["entry_point"]["caller_capability_required"] = "tampered"
            projection_path.write_text(
                "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                encoding="utf-8",
            )

            summary = VERIFIER.verify_strict_projection(
                chains_jsonl=chains_path,
                index_json=index_path,
                strict_projection_jsonl=projection_path,
            )

            self.assertFalse(summary["met"])
            self.assertIn("strict_projection_mismatched_rows", summary["error_codes"])


if __name__ == "__main__":
    unittest.main()
