from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-substrate-cosmwasm-frost.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    import sys

    name = "_hackerman_etl_from_substrate_cosmwasm_frost"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    # Register the module in sys.modules *before* exec_module so that the
    # @dataclass decorator (Python 3.13+) can resolve cls.__module__ via
    # sys.modules during _process_class.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    import sys

    name = "_hackerman_record_validate_for_substrate_cosmwasm_frost_test"
    spec = importlib.util.spec_from_file_location(name, str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromSubstrateCosmwasmFrostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.validator = _load_validator()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_dry_run_emits_all_attack_classes_with_no_errors(self) -> None:
        summary = self.tool.run_etl(self.out_dir, dry_run=True)

        self.assertEqual(summary["errors"], [])
        # 21 curated attack classes; each fans out over 1+ source citations.
        self.assertGreaterEqual(summary["attack_class_count"], 20)
        self.assertGreaterEqual(summary["records_emitted"], 200)
        self.assertLessEqual(summary["records_emitted"], 500)
        self.assertEqual(set(summary["frameworks"].keys()), {"substrate", "cosmwasm", "frost"})
        # All known attack_class verbatim values are present.
        expected_classes = {
            # Substrate
            "pallet-storage-overflow",
            "runtime-upgrade-mid-block",
            "weight-mispricing-block-overflow",
            "dispatchable-permission-bypass",
            "parachain-validation-block-replay",
            "xcm-message-replay",
            "xcm-asset-id-confusion",
            "treasury-spend-bypass",
            "democracy-proposal-replay",
            # CosmWasm
            "contract-instantiate-replay",
            "cw20-token-extension-confusion",
            "migration-storage-collision",
            "sudo-msg-permission-bypass",
            "cw-bank-denom-confusion",
            "cw-ica-host-priv-escalation",
            # FROST
            "frost-share-recovery-bypass",
            "frost-aggregator-malicious",
            "nonce-reuse-attack",
            "dkg-malicious-dealer",
            "partial-sig-rebroadcast",
            "commitment-binding-failure",
        }
        self.assertEqual(set(summary["attack_class_breakdown"].keys()), expected_classes)

    def test_records_pass_schema_validation_when_written(self) -> None:
        summary = self.tool.run_etl(self.out_dir, dry_run=False, limit=12)

        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["records_emitted"], 12)
        files = sorted(self.out_dir.glob("*.yaml"))
        self.assertEqual(len(files), 12)
        schema = self.validator.load_schema()
        for path in files:
            status, errors = self.validator.validate_file(path, schema)
            self.assertEqual((status, errors), ("valid", []), msg=f"{path}: {errors}")

    def test_framework_filter_selects_subset_only(self) -> None:
        summary = self.tool.run_etl(self.out_dir, dry_run=True, frameworks=("frost",))

        self.assertEqual(summary["errors"], [])
        self.assertEqual(set(summary["frameworks"].keys()), {"frost"})
        # 6 FROST attack classes; should be present.
        self.assertEqual(summary["attack_class_count"], 6)
        # All FROST records cite frost source kinds; verify by inspecting record_ids.
        for path_str in summary["files"]:
            self.assertIn(":frost:", path_str)

    def test_attack_class_filter_selects_single_class(self) -> None:
        summary = self.tool.run_etl(
            self.out_dir,
            dry_run=True,
            attack_classes=("frost-share-recovery-bypass",),
        )

        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["attack_class_count"], 1)
        self.assertEqual(set(summary["attack_class_breakdown"].keys()), {"frost-share-recovery-bypass"})

    def test_source_filter_selects_single_citation_per_framework_match(self) -> None:
        summary = self.tool.run_etl(
            self.out_dir,
            dry_run=True,
            sources=("zellic-osmosis-2023",),
        )

        self.assertEqual(summary["errors"], [])
        # Only cosmwasm classes (15 of them) match zellic-osmosis-2023.
        self.assertEqual(summary["source_count"], 1)
        self.assertEqual(set(summary["frameworks"].keys()), {"cosmwasm"})

    def test_output_is_deterministic(self) -> None:
        first = self.tool.run_etl(self.out_dir, dry_run=False, limit=4)
        first_text = sorted(
            (path.name, path.read_text(encoding="utf-8"))
            for path in self.out_dir.glob("*.yaml")
        )

        # Rebuild into a fresh directory and confirm same names + contents.
        for path in self.out_dir.glob("*.yaml"):
            path.unlink()
        second = self.tool.run_etl(self.out_dir, dry_run=False, limit=4)
        second_text = sorted(
            (path.name, path.read_text(encoding="utf-8"))
            for path in self.out_dir.glob("*.yaml")
        )

        self.assertEqual(first["records_emitted"], second["records_emitted"])
        self.assertEqual(first_text, second_text)

    def test_yaml_scalar_quotes_yaml_indicator_prefixed_values(self) -> None:
        # `>=$1M` would be parsed as a YAML block scalar header without
        # quoting, so the scalar serializer must wrap it.
        self.assertEqual(self.tool.yaml_scalar(">=$1M"), '">=$1M"')
        self.assertEqual(self.tool.yaml_scalar("<$10K"), '"<$10K"')
        # Plain-safe strings stay unquoted (preserve readable diff).
        self.assertEqual(self.tool.yaml_scalar("critical"), "critical")
        self.assertEqual(self.tool.yaml_scalar("non-financial"), "non-financial")
        # Reserved YAML words are quoted.
        self.assertEqual(self.tool.yaml_scalar("true"), '"true"')

    def test_shape_tags_include_framework_prefix(self) -> None:
        # Build records via collect_records and assert framework-prefixed tags.
        records = self.tool.collect_records(
            frameworks=("substrate",),
            attack_classes=("pallet-storage-overflow",),
        )
        self.assertGreater(len(records), 0)
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn("pallet-storage-overflow", tags)
            self.assertTrue(
                any(tag.startswith("substrate-") for tag in tags),
                msg=f"missing substrate- prefixed tag in {tags}",
            )

    def test_target_language_is_rust_for_all_records(self) -> None:
        records = self.tool.collect_records()
        self.assertGreater(len(records), 0)
        # Schema enum constraint: target_language must be exactly "rust" for
        # this ETL. Framework identity rides on shape_tags + attack_class.
        for record in records:
            self.assertEqual(record["target_language"], "rust")

    def test_cli_json_summary(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main(
                [
                    "--out-dir",
                    str(self.out_dir),
                    "--dry-run",
                    "--json-summary",
                    "--limit",
                    "5",
                ]
            )

        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SUMMARY_SCHEMA)
        self.assertEqual(payload["records_emitted"], 5)
        self.assertEqual(payload["errors"], [])

    def test_record_id_is_within_schema_pattern(self) -> None:
        records = self.tool.collect_records(
            frameworks=("frost",),
            attack_classes=("commitment-binding-failure",),
        )
        self.assertGreater(len(records), 0)
        for record in records:
            record_id = record["record_id"]
            # Schema pattern: ^[A-Za-z0-9._:/-]{8,160}$
            self.assertGreaterEqual(len(record_id), 8)
            self.assertLessEqual(len(record_id), 160)
            self.assertRegex(record_id, r"^[A-Za-z0-9._:/-]+$")


if __name__ == "__main__":
    unittest.main()
