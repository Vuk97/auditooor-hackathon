from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXTRACTOR_PATH = REPO_ROOT / "tools" / "causal-chain-extract.py"
VERIFIER_PATH = REPO_ROOT / "tools" / "causal-chain-reverse-lookup-verify.py"


def _import_tool(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACTOR = _import_tool(EXTRACTOR_PATH, "causal_chain_extract_for_verify_tests")
VERIFIER = _import_tool(VERIFIER_PATH, "causal_chain_reverse_lookup_verify_tests")


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


class CausalChainReverseLookupVerifyTests(unittest.TestCase):
    def _write_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        rows = _sample_rows()
        chains_path = root / "causal_chains.jsonl"
        index_path = root / "causal_chain_index.json"
        sqlite_path = root / "causal_chain_reverse_lookup.sqlite"
        EXTRACTOR.write_jsonl(chains_path, rows)
        reverse_summary = EXTRACTOR.write_reverse_lookup_sqlite(sqlite_path, rows)
        EXTRACTOR.write_index(index_path, rows, reverse_lookup=reverse_summary)
        return chains_path, index_path, sqlite_path

    def test_verifier_accepts_fresh_reverse_lookup_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-reverse-verify-") as tmp:
            chains_path, index_path, sqlite_path = self._write_fixture(Path(tmp))

            summary = VERIFIER.verify_reverse_lookup(
                chains_jsonl=chains_path,
                index_json=index_path,
                reverse_sqlite=sqlite_path,
            )

            self.assertTrue(summary["met"], summary["errors"])
            self.assertEqual(summary["source_rows"], 2)
            self.assertEqual(summary["expected_counts"]["chains_by_prefix_2"], 2)
            self.assertEqual(summary["expected_counts"]["chains_by_prefix_3"], 2)
            self.assertEqual(summary["expected_counts"], summary["actual_counts"])
            self.assertTrue(summary["sample_prefix_queries"]["prefix_2_exact"]["matched"])
            self.assertTrue(summary["sample_prefix_queries"]["prefix_3_exact"]["matched"])

    def test_verifier_cli_emits_json_and_zero_exit_on_fresh_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-reverse-verify-") as tmp:
            chains_path, index_path, sqlite_path = self._write_fixture(Path(tmp))

            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER_PATH),
                    "--chains-jsonl",
                    str(chains_path),
                    "--index-json",
                    str(index_path),
                    "--reverse-sqlite",
                    str(sqlite_path),
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

    def test_verifier_rejects_stale_missing_prefix_table_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="causal-chain-reverse-verify-") as tmp:
            chains_path, index_path, sqlite_path = self._write_fixture(Path(tmp))
            with closing(sqlite3.connect(sqlite_path)) as conn:
                conn.execute(
                    "DELETE FROM chains_by_prefix_2 WHERE chain_id = ?",
                    ("chain:withdraw-001",),
                )
                conn.commit()

            summary = VERIFIER.verify_reverse_lookup(
                chains_jsonl=chains_path,
                index_json=index_path,
                reverse_sqlite=sqlite_path,
            )

            self.assertFalse(summary["met"])
            self.assertIn("chains_by_prefix_2_count_mismatch", summary["error_codes"])
            self.assertIn("chains_by_prefix_2_missing_rows", summary["error_codes"])
            self.assertIn(
                "index_chains_by_prefix_2_rows_mismatch",
                summary["error_codes"],
            )
            self.assertEqual(summary["expected_counts"]["chains_by_prefix_2"], 2)
            self.assertEqual(summary["actual_counts"]["chains_by_prefix_2"], 1)


if __name__ == "__main__":
    unittest.main()
