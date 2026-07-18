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
TOOL_PATH = REPO_ROOT / "tools" / "causal-chain-extract.py"


def import_tool():
    spec = importlib.util.spec_from_file_location("causal_chain_extract", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


TOOL = import_tool()


class CausalChainExtractTests(unittest.TestCase):
    def sample_record(self) -> dict:
        return {
            "schema_version": "auditooor.hackerman_exploit_predicates.v1",
            "record_id": "demo:missing-auth",
            "source_audit_ref": "https://example.test/audit#finding-1",
            "tag_file": "demo/record.yaml",
            "target_component": "DemoVault.withdraw",
            "target_domain": "vault",
            "target_language": "solidity",
            "attack_class": "unauthorized-withdrawal",
            "bug_class": "access-control",
            "actions": [
                "Attacker calls withdrawFor(victim) without ownership validation.",
                "Patch by binding msg.sender to the account or approved operator.",
            ],
            "preconditions": [
                "Victim has deposited funds.",
                "withdrawFor is externally callable.",
                "verification_tier=tier-2-verified-public-archive",
            ],
            "impacts": [
                {
                    "impact_class": "fund-loss",
                    "impact_actor": "depositor",
                    "impact_dollar_class": "$100K-$1M",
                    "severity_at_finding": "high",
                }
            ],
            "requires_state": ["state:victim-balance-positive"],
            "produces_state": ["state:protocol-funds-displaced"],
        }

    def test_builds_required_schema_from_hackerman_predicate_record(self) -> None:
        row = TOOL.causal_chain_from_record(self.sample_record())
        assert row is not None
        TOOL.validate_chain(row)
        self.assertEqual(row["schema_version"], TOOL.SCHEMA_VERSION)
        self.assertEqual(row["source_record_id"], "demo:missing-auth")
        self.assertEqual(row["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(row["preconditions"][0], "Victim has deposited funds.")
        self.assertIn("withdrawFor", row["trigger"])
        self.assertIn("Patch", row["defense"])
        self.assertEqual(row["impact"][0]["impact_class"], "fund-loss")
        self.assertIn("https://example.test/audit#finding-1", row["source_refs"])

    def test_reverse_lookup_normalizes_function_signatures(self) -> None:
        self.assertEqual(
            TOOL.normalize_entry_signature(
                "function claimFixedPremium(uint256 amount, address asset) external nonReentrant"
            ),
            "claimfixedpremium(uint256,address)",
        )
        self.assertEqual(TOOL.normalize_entry_signature("DemoVault.withdraw"), "demovault.withdraw")

    def test_builds_strict_four_block_projection_from_compact_row(self) -> None:
        row = TOOL.causal_chain_from_record(self.sample_record())
        assert row is not None

        projection = TOOL.strict_projection_for_row(row)
        TOOL.validate_strict_projection(projection)

        self.assertEqual(projection["schema"], TOOL.STRICT_PROJECTION_SCHEMA)
        self.assertEqual(projection["chain_id"], row["chain_id"])
        self.assertEqual(projection["entry_point"]["function_signature"], "DemoVault.withdraw")
        self.assertEqual(
            projection["entry_point"]["caller_capability_required"],
            "unspecified-by-source",
        )
        self.assertEqual(
            projection["mutations"][0]["state_field_modified"],
            "state:protocol-funds-displaced",
        )
        self.assertTrue(projection["mutations"][0]["is_irrecoverable_commit"])
        self.assertEqual(
            projection["invariant_violation"]["invariant_id"],
            "state:protocol-funds-displaced",
        )
        self.assertEqual(projection["invariant_violation"]["violation_step"], 1)
        self.assertEqual(projection["impact"], row["impact"])
        self.assertIn(
            "mutations_projected_from_compact_state_fields",
            projection["projection_warnings"],
        )

    def test_uses_predicate_values_when_top_level_lists_are_absent(self) -> None:
        record = {
            "record_id": "demo:predicate-only",
            "source_refs": ["local:fixture"],
            "predicates": [
                {
                    "predicate_type": "action",
                    "ordinal": 2,
                    "value": "Second action. Consider checking the final recipient.",
                },
                {"predicate_type": "action", "ordinal": 1, "value": "First action."},
                {"predicate_type": "precondition", "ordinal": 1, "value": "Open public entrypoint."},
            ],
            "impact": "denial of service",
            "record_tier": "public-corpus",
        }
        row = TOOL.causal_chain_from_record(record)
        assert row is not None
        TOOL.validate_chain(row)
        self.assertEqual(row["trigger"], "First action.")
        self.assertEqual(row["preconditions"], ["Open public entrypoint."])
        self.assertEqual(row["defense"], "Second action. Consider checking the final recipient.")
        self.assertEqual(row["verification_tier"], "public-corpus")

    def test_cli_reads_jsonl_and_writes_jsonl_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "records.jsonl"
            output_path = root / "chains.jsonl"
            index_path = root / "index.json"
            sqlite_path = root / "reverse.sqlite"
            strict_projection_path = root / "strict_projection.jsonl"
            report_path = root / "report.md"
            input_path.write_text(json.dumps(self.sample_record()) + "\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--index-json",
                    str(index_path),
                    "--reverse-sqlite",
                    str(sqlite_path),
                    "--strict-projection-output",
                    str(strict_projection_path),
                    "--report-md",
                    str(report_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_record_id"], "demo:missing-auth")
            index = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(index["row_count"], 1)
            self.assertEqual(index["by_target_language"], {"solidity": 1})
            self.assertEqual(index["strict_projection"]["row_count"], 1)
            strict_rows = [
                json.loads(line)
                for line in strict_projection_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(strict_rows), 1)
            self.assertEqual(strict_rows[0]["schema"], TOOL.STRICT_PROJECTION_SCHEMA)
            self.assertEqual(
                strict_rows[0]["entry_point"]["function_signature_norm"],
                "demovault.withdraw",
            )
            self.assertEqual(
                index["reverse_lookup"]["tables"],
                ["chains_by_prefix_2", "chains_by_prefix_3", "chains_by_state_field"],
            )
            with closing(sqlite3.connect(sqlite_path)) as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                }
                self.assertEqual(
                    tables,
                    {"chains_by_prefix_2", "chains_by_prefix_3", "chains_by_state_field"},
                )
                prefix2 = conn.execute(
                    "SELECT entry_signature_norm, mutation_0_norm, chain_id FROM chains_by_prefix_2"
                ).fetchone()
                self.assertEqual(prefix2[0], "demovault.withdraw")
                self.assertEqual(prefix2[1], "state:protocol-funds-displaced")
                self.assertTrue(prefix2[2].startswith("chain:"))
                state_fields = [
                    row[0]
                    for row in conn.execute(
                        "SELECT state_field_norm FROM chains_by_state_field ORDER BY step"
                    )
                ]
                self.assertEqual(
                    state_fields,
                    ["state:protocol-funds-displaced", "state:victim-balance-positive"],
                )
            self.assertIn("P2 Causal Chain MVP Run", report_path.read_text(encoding="utf-8"))
            self.assertIn("Reverse Lookup SQLite", report_path.read_text(encoding="utf-8"))
            self.assertIn("Strict Four-Block Projection", report_path.read_text(encoding="utf-8"))

    def test_quality_gate_profiles_reject_expected_rows(self) -> None:
        accepted_row = TOOL.causal_chain_from_record(self.sample_record())
        assert accepted_row is not None
        unknown_tier_row = dict(accepted_row)
        unknown_tier_row["verification_tier"] = "unknown"
        placeholder_precondition_row = dict(accepted_row)
        placeholder_precondition_row["preconditions"] = ["tbd"]
        strict_only_bad_row = dict(accepted_row)
        strict_only_bad_row["defense"] = TOOL.FALLBACK_DEFENSE

        rows = [accepted_row, unknown_tier_row, placeholder_precondition_row, strict_only_bad_row]
        canonical_rows, canonical_summary = TOOL.apply_quality_gate(rows, profile="canonical")
        strict_rows, strict_summary = TOOL.apply_quality_gate(rows, profile="strict")

        self.assertEqual(len(canonical_rows), 1)
        self.assertEqual(canonical_summary["rejected_by_reason"]["verification_tier_unknown"], 1)
        self.assertEqual(canonical_summary["rejected_by_reason"]["preconditions_placeholder"], 1)
        self.assertEqual(canonical_summary["rejected_by_reason"]["defense_fallback_or_placeholder"], 1)
        self.assertEqual(len(strict_rows), 1)
        self.assertEqual(strict_summary["rejected_by_reason"]["defense_fallback_or_placeholder"], 1)

    def test_cli_canonical_writes_default_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "records.jsonl"
            input_path.write_text(json.dumps(self.sample_record()) + "\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--canonical",
                    "--input",
                    str(input_path),
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            canonical_output = root / "audit" / "corpus_tags" / "derived" / "causal_chains.jsonl"
            canonical_index = root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json"
            canonical_reverse = (
                root / "audit" / "corpus_tags" / "derived" / "causal_chain_reverse_lookup.sqlite"
            )
            canonical_projection = (
                root / "audit" / "corpus_tags" / "derived" / "causal_chain_strict_projection.jsonl"
            )
            self.assertTrue(canonical_output.is_file())
            self.assertTrue(canonical_index.is_file())
            self.assertTrue(canonical_reverse.is_file())
            self.assertTrue(canonical_projection.is_file())
            index = json.loads(canonical_index.read_text(encoding="utf-8"))
            self.assertEqual(index["quality_gate"]["profile"], "canonical")
            self.assertIn(
                "defense must not be fallback/placeholder",
                index["quality_gate"]["requirements"],
            )
            self.assertEqual(index["reverse_lookup"]["chains_by_prefix_2_rows"], 1)
            self.assertEqual(index["strict_projection"]["four_block_rows"], 1)


if __name__ == "__main__":
    unittest.main()
