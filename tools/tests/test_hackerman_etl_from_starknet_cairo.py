"""Tests for tools/hackerman-etl-from-starknet-cairo.py.

The miner is purpose-built for StarkNet / Cairo audit corpora. These tests
exercise:

  * Detection of StarkNet-specific attack classes (felt overflow,
    account-abstraction bypass, paymaster replay, multicall isolation,
    L1-L2 message replay, StarkNet system-contract rights escalation).
  * Non-StarkNet documents are skipped, leaving the record_id namespace
    clean of solidity-only fixtures.
  * Determinism: re-running the ETL produces byte-identical YAML output.
  * The emitted records validate against the canonical
    ``auditooor.hackerman_record.v1`` JSON schema.
  * The CLI ``--dry-run --limit --json-summary`` knobs honour the same
    semantics as the sibling ETL miners.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-starknet-cairo.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_ROOT = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_starknet_cairo"
ARGENT_FIXTURE = FIXTURE_ROOT / "workspaces" / "argent"
NON_STARKNET_FIXTURE = FIXTURE_ROOT / "workspaces" / "non_starknet"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_etl_from_starknet_cairo", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    spec = importlib.util.spec_from_file_location("_hackerman_record_validate_for_etl_sn", str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromStarknetCairoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.validator = _load_validator()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- core extraction --------------------------------------------------

    def test_extracts_multiple_starknet_findings_from_markdown(self) -> None:
        records, counters = self.tool.extract_records([ARGENT_FIXTURE])

        # 4 findings in the Nethermind report + 2 findings in the OZ report.
        self.assertEqual(len(records), 6)
        self.assertEqual(counters["documents_with_text"], 2)
        self.assertEqual(counters["documents_non_starknet"], 0)
        attack_classes = {r["attack_class"] for r in records}
        self.assertIn("account-abstraction-bypass", attack_classes)
        self.assertIn("cairo-felt-overflow", attack_classes)
        self.assertIn("starknet-system-contract-rights-escalation", attack_classes)
        self.assertIn("l1-l2-message-replay", attack_classes)
        self.assertIn("multicall-isolation-bypass", attack_classes)
        self.assertIn("paymaster-replay", attack_classes)
        # Every record must declare target_language == cairo.
        for record in records:
            self.assertEqual(record["target_language"], "cairo")

    def test_non_starknet_audit_is_skipped(self) -> None:
        records, counters = self.tool.extract_records([NON_STARKNET_FIXTURE])
        self.assertEqual(len(records), 0)
        self.assertEqual(counters["documents_non_starknet"], 1)
        self.assertEqual(counters["documents_with_text"], 0)

    def test_records_validate_against_canonical_schema(self) -> None:
        self.tool.main(
            [
                "--workspace",
                str(ARGENT_FIXTURE),
                "--out-dir",
                str(self.out_dir),
            ]
        )
        schema = self.validator.load_schema()
        paths = sorted(self.out_dir.glob("*.yaml"))
        self.assertGreaterEqual(len(paths), 6)
        for path in paths:
            status, errors = self.validator.validate_file(path, schema)
            self.assertEqual((status, errors), ("valid", []), msg=f"{path}: {errors}")

    def test_severity_critical_mapping_and_dollar_class(self) -> None:
        records, _ = self.tool.extract_records([ARGENT_FIXTURE])
        critical = [r for r in records if r["severity_at_finding"] == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["attack_class"], "account-abstraction-bypass")
        self.assertEqual(critical[0]["impact_class"], "theft")
        self.assertEqual(critical[0]["impact_dollar_class"], ">=$1M")
        self.assertEqual(critical[0]["bug_class"], "account-abstraction")

    def test_target_repo_inferred_from_github_url(self) -> None:
        records, _ = self.tool.extract_records([ARGENT_FIXTURE])
        # At least one record from the Nethermind fixture must capture the
        # GitHub URL repo slug; the OZ fixture maps via the normalisation map.
        repos = {r["target_repo"] for r in records}
        self.assertIn("argentlabs/argent-contracts-starknet", repos)
        self.assertIn("OpenZeppelin/cairo-contracts", repos)

    def test_attack_class_taxonomy_unit_calls(self) -> None:
        # Direct unit-level taxonomy checks - these are the
        # StarkNet-specific classes the brief asked for.
        cases = [
            ("a felt252 overflow in the deposit accounting", "cairo-felt-overflow"),
            ("missing __validate__ on this account contract", "account-abstraction-bypass"),
            ("paymaster signature replay across windows", "paymaster-replay"),
            ("execute calls reentrancy via tx_info reuse", "multicall-isolation-bypass"),
            ("replace_class_syscall reachable from fallback", "starknet-system-contract-rights-escalation"),
            ("storage var collision after cairo-0 to cairo-1 migration", "cairo-1-transition-storage-collision"),
            ("consume_message_from_l2 replay against starkgate", "l1-l2-message-replay"),
            ("unbounded syscall in library_call_l1_handler", "system-call-gas-abuse"),
        ]
        for text, expected_attack in cases:
            with self.subTest(text=text):
                _, attack_class = self.tool.infer_bug_and_attack(text)
                self.assertEqual(attack_class, expected_attack)

    def test_starknet_corpus_filter(self) -> None:
        # Path-token detection.
        self.assertTrue(self.tool.is_starknet_path(Path("audits/starknet/report.md")))
        self.assertTrue(self.tool.is_starknet_path(Path("nethermind_cairo_2025.pdf")))
        self.assertFalse(self.tool.is_starknet_path(Path("audits/evm-vault.md")))
        # Density check - random Solidity-only prose stays below threshold.
        self.assertFalse(self.tool.is_starknet_corpus(Path("evm.md"), "Solidity vault with ERC4626 shares."))
        # Cairo prose with multiple keyword hits crosses the threshold.
        text = (
            "Cairo 1 audit of the StarkNet account contract. The felt252 path "
            "calls syscall l1_handler with openzeppelin-cairo components."
        )
        self.assertTrue(self.tool.is_starknet_corpus(Path("anon.md"), text))

    # --- CLI / determinism ------------------------------------------------

    def test_dry_run_and_limit_plan_without_writing(self) -> None:
        rc = self.tool.main(
            [
                "--workspace",
                str(ARGENT_FIXTURE),
                "--out-dir",
                str(self.out_dir),
                "--dry-run",
                "--limit",
                "2",
            ]
        )
        self.assertEqual(rc, 0)
        # --dry-run must not create the output directory.
        self.assertFalse(self.out_dir.exists())

    def test_output_is_deterministic(self) -> None:
        first_out = self.tmp_path / "out_first"
        second_out = self.tmp_path / "out_second"
        self.tool.main(["--workspace", str(ARGENT_FIXTURE), "--out-dir", str(first_out)])
        self.tool.main(["--workspace", str(ARGENT_FIXTURE), "--out-dir", str(second_out)])
        first_files = sorted(p.name for p in first_out.glob("*.yaml"))
        second_files = sorted(p.name for p in second_out.glob("*.yaml"))
        self.assertEqual(first_files, second_files)
        for name in first_files:
            self.assertEqual(
                (first_out / name).read_text(encoding="utf-8"),
                (second_out / name).read_text(encoding="utf-8"),
            )

    def test_cli_json_summary_emits_counters(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main(
                [
                    "--workspace",
                    str(ARGENT_FIXTURE),
                    "--out-dir",
                    str(self.out_dir),
                    "--dry-run",
                    "--json-summary",
                ]
            )
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(payload["stage_schema_version"], self.tool.STAGE_SCHEMA_VERSION)
        self.assertEqual(payload["dry_run"], True)
        self.assertGreaterEqual(payload["records_emitted"], 6)
        self.assertEqual(payload["documents_non_starknet"], 0)

    def test_source_file_input_emits_corpus_records(self) -> None:
        source = ARGENT_FIXTURE / "prior_audits" / "nethermind_argent_account_2024.md"
        records, counters = self.tool.extract_records([], source_files=[source])
        self.assertGreaterEqual(len(records), 4)
        for record in records:
            self.assertTrue(str(record["source_audit_ref"]).startswith("starknet-cairo-corpus:"))
            self.assertTrue(str(record["record_id"]).startswith("starknet-cairo-corpus:"))
        self.assertGreaterEqual(counters["documents_with_text"], 1)

    def test_stage_artifact_is_emitted(self) -> None:
        stage_artifact = self.tmp_path / "stage.json"
        rc = self.tool.main(
            [
                "--workspace",
                str(ARGENT_FIXTURE),
                "--workspace",
                str(NON_STARKNET_FIXTURE),
                "--out-dir",
                str(self.out_dir),
                "--stage-artifact-out",
                str(stage_artifact),
                "--dry-run",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(stage_artifact.exists())
        payload = json.loads(stage_artifact.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], self.tool.STAGE_SCHEMA_VERSION)
        self.assertGreaterEqual(payload["summary"]["records_emitted"], 6)
        # The non-starknet workspace contributed one document; it must be
        # tagged as non-starknet in the stage rows.
        statuses = {row["status"] for row in payload["documents"]}
        self.assertIn("non-starknet", statuses)
        self.assertIn("processed", statuses)

    def test_cli_requires_workspace_or_source_file(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = self.tool.main(["--out-dir", str(self.out_dir)])
        self.assertEqual(rc, 2)
        self.assertIn("--workspace", stderr.getvalue())

    # --- helper-level coverage -------------------------------------------

    def test_infer_repo_handles_openzeppelin_alias(self) -> None:
        repo = self.tool.infer_repo("see openzeppelin-cairo audit", "")
        self.assertEqual(repo, "OpenZeppelin/cairo-contracts")

    def test_infer_repo_handles_cairo_lang_alias(self) -> None:
        repo = self.tool.infer_repo("issue inside cairo-lang fork", "")
        self.assertEqual(repo, "starkware-libs/cairo-lang")

    def test_infer_component_prefers_cairo_signature_shape(self) -> None:
        component = self.tool.infer_component(
            "C-01 Missing __validate__ binding",
            "The fn __execute__(self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> is reachable.",
        )
        self.assertIn("__execute__", component)

    def test_infer_signature_synthesises_cairo_stub(self) -> None:
        self.assertEqual(self.tool.infer_signature("validate_paymaster"), "fn validate_paymaster(...)")
        self.assertTrue(self.tool.infer_signature("fn ok(x: felt252) -> bool").startswith("fn ok"))

    def test_infer_dollar_class_walks_down_for_griefing(self) -> None:
        self.assertEqual(self.tool.infer_dollar_class("info", "griefing"), "non-financial")
        self.assertEqual(self.tool.infer_dollar_class("critical", "theft"), ">=$1M")
        self.assertEqual(self.tool.infer_dollar_class("high", "freeze"), "$100K-$1M")


if __name__ == "__main__":
    unittest.main()
