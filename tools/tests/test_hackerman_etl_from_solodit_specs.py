from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-solodit-specs.py"
SOLODIT_TO_SPECS = REPO_ROOT / "tools" / "solodit-to-specs.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromSoloditSpecsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_solodit_specs")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_solodit_specs")

    def test_converts_reported_date_to_audit_year(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-date-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "date.yaml").write_text(
                """
skeleton: name_match_missing_call
name: reported-date
severity: HIGH
source: "Solodit #65131 (Spearbit/Aragon Generic Money)"
source_date: "2026-05-04T12:00:00Z"
wiki_title: "Reported date"
wiki_description: "A dated Solodit finding."
solodit_id: "65131"
vuln_fn_name: mint
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(record["year"], 2026)

    def test_solodit_spec_generator_preserves_source_date(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_date_test")
        spec = generator.render_spec(
            {
                "id": 65131,
                "title": "Vault price manipulation allows yield manager to mint tokens",
                "content": "The `mint` path accepts stale price data and can mint too many shares.",
                "impact": "HIGH",
                "firm_name": "Spearbit",
                "protocol_name": "Aragon Generic Money",
                "slug": "vault-price-manipulation-spearbit-aragon-generic-money",
                "quality_score": 5,
                "general_score": 5,
                "_raw": {"published_at": "2026-05-04T12:00:00Z"},
            },
            "name_match_missing_call",
        )

        self.assertIsNotNone(spec)
        self.assertEqual(spec["source_date"], "2026-05-04T12:00:00Z")
        self.assertEqual(spec["solodit_date_field"], "published_at")

    def test_solodit_spec_generator_preserves_nested_raw_source_date(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_nested_date_test")
        spec = generator.render_spec(
            {
                "id": 63969,
                "title": "Adversary blocks volume decay when dt nears max dt",
                "content": "The `update` path can keep stale accounting when the decay window is near max dt.",
                "impact": "HIGH",
                "firm_name": "Pashov Audit Group",
                "protocol_name": "Ostium",
                "slug": "m-03-adversary-blocks-volume-decay-when-dt-nears-max-dt",
                "quality_score": 5,
                "general_score": 5,
                "_raw": {"audit": {"report_date": "2025-08-22"}},
            },
            "name_match_missing_call",
        )

        self.assertIsNotNone(spec)
        self.assertEqual(spec["source_date"], "2025-08-22")
        self.assertEqual(spec["solodit_date_field"], "_raw.audit.report_date")

    def test_solodit_spec_generator_preserves_language(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_language_test")
        spec = generator.render_spec(
            {
                "id": 70001,
                "title": "Rust bridge replay accepts consumed message",
                "content": "The `process_message` path accepts a consumed bridge message and replays state.",
                "impact": "HIGH",
                "language": "Rust",
                "firm_name": "Example",
                "protocol_name": "Bridge",
                "slug": "rust-bridge-replay-example",
                "quality_score": 5,
                "general_score": 5,
            },
            "name_match_missing_call",
        )

        self.assertIsNotNone(spec)
        self.assertEqual(spec["language"], "rust")

    def test_solodit_spec_generator_preserves_sway_language(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_sway_language_test")
        spec = generator.render_spec(
            {
                "id": 70002,
                "title": "Sway bridge payout omits message consumption",
                "content": "The Sway bridge payout path accepts a replayed payload and releases funds twice.",
                "impact": "HIGH",
                "language": "Sway",
                "firm_name": "Example",
                "protocol_name": "Fuel Bridge",
                "slug": "sway-bridge-payout-replay",
                "quality_score": 5,
                "general_score": 5,
            },
            "name_match_missing_call",
        )

        self.assertIsNotNone(spec)
        self.assertEqual(spec["language"], "sway")

    def test_solodit_spec_process_language_filter_drops_unlabeled(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_process_language_test")
        with tempfile.TemporaryDirectory(prefix="solodit-spec-language-") as tmp:
            root = Path(tmp)
            raw_dir = root / "raw"
            out_dir = root / "specs"
            raw_dir.mkdir()
            generator.SPECS_DRAFTS = out_dir
            content = "The `processMessage` path accepts invalid accounting and can drain a vault balance."
            (raw_dir / "page.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": 70010,
                                "title": "Solidity accounting drift",
                                "content": content,
                                "impact": "HIGH",
                                "language": "Solidity",
                                "firm_name": "Example",
                                "protocol_name": "Vault",
                                "slug": "solidity-accounting-drift",
                                "quality_score": 5,
                                "general_score": 5,
                            },
                            {
                                "id": 70011,
                                "title": "Rust bridge replay",
                                "content": content,
                                "impact": "HIGH",
                                "language": "Rust",
                                "firm_name": "Example",
                                "protocol_name": "Bridge",
                                "slug": "rust-bridge-replay",
                                "quality_score": 5,
                                "general_score": 5,
                            },
                            {
                                "id": 70012,
                                "title": "Unlabeled bridge replay",
                                "content": content,
                                "impact": "HIGH",
                                "language": "",
                                "firm_name": "Example",
                                "protocol_name": "Bridge",
                                "slug": "unlabeled-bridge-replay",
                                "quality_score": 5,
                                "general_score": 5,
                            },
                            {
                                "id": 70013,
                                "title": "Go IBC replay",
                                "content": content,
                                "impact": "HIGH",
                                "languages": [{"value": "Go"}],
                                "firm_name": "Example",
                                "protocol_name": "Bridge",
                                "slug": "go-ibc-replay",
                                "quality_score": 5,
                                "general_score": 5,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            stats = generator.process_raw_dir(raw_dir, min_quality=2.0, language_filter=["rust"])

            self.assertEqual(stats["processed"], 4)
            self.assertEqual(stats["emitted"], 1)
            self.assertEqual(stats["skipped"]["language"], 3)
            self.assertEqual(stats["language_filter"], ["rust"])
            emitted = sorted(p.name for p in out_dir.glob("*.yaml"))
            self.assertEqual(emitted, ["rust-bridge-replay.yaml"])

    def test_solodit_spec_process_has_no_default_language_filter(self) -> None:
        generator = _load(SOLODIT_TO_SPECS, "_solodit_to_specs_for_process_default_language_test")
        with tempfile.TemporaryDirectory(prefix="solodit-spec-no-default-language-") as tmp:
            root = Path(tmp)
            raw_dir = root / "raw"
            out_dir = root / "specs"
            raw_dir.mkdir()
            generator.SPECS_DRAFTS = out_dir
            content = "The `processMessage` path accepts invalid accounting and can drain a vault balance."
            (raw_dir / "page.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": 70100,
                                "title": "Unlabeled cached Solodit finding",
                                "content": content,
                                "impact": "HIGH",
                                "language": "",
                                "firm_name": "Example",
                                "protocol_name": "Vault",
                                "slug": "unlabeled-cached-solodit-finding",
                                "quality_score": 5,
                                "general_score": 5,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            stats = generator.process_raw_dir(raw_dir, min_quality=2.0)

            self.assertEqual(stats["processed"], 1)
            self.assertEqual(stats["emitted"], 1)
            self.assertEqual(stats["language_filter"], [])

    def test_converts_solidity_spec_to_valid_hackerman_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-etl-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "fee-on-transfer.yaml").write_text(
                """
skeleton: name_match_missing_call
name: fee-on-transfer-token-not-supported
severity: HIGH
source: "Solodit #22011 (Code4rena/Popcorn)"
wiki_title: "Fee on transfer token not supported"
wiki_description: "Vault accounting records the pre-fee amount."
wiki_exploit_scenario: "Attacker deposits fee-on-transfer token and claims more than received."
wiki_recommendation: "Record received amount after transfer."
contract_name: FeeOnTransferTokenNotSupported
solodit_id: "22011"
solodit_slug: "fee-on-transfer-token-not-supported-code4rena-popcorn-2024-04-git"
solodit_tags: "Weird ERC20, Fee On Transfer"
vuln_fn_name: lock
vuln_fn_params: "uint256 amount"
vuln_fn_mutability_clean: external
vuln_fn_return: bool
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["records_emitted"], 1)
            path = next(out_dir.glob("*.yaml"))
            status, errors = self.validator.validate_file(path, self.validator.load_schema())
            self.assertEqual(status, "valid", errors)
            record = self.validator.load_yaml(path)
            self.assertEqual(record["target_language"], "solidity")
            self.assertEqual(record["target_repo"], "code4rena/popcorn")
            self.assertEqual(record["attack_class"], "fee-on-transfer-accounting-drift")
            self.assertIn("function lock(uint256 amount) external returns (bool)", record["function_shape"]["raw_signature"])
            self.assertEqual(record["year"], 2024)
            self.assertNotIn("name_match_missing_call", record["function_shape"]["shape_tags"])

    def test_keeps_name_match_shape_tag_when_no_real_vulnerable_function_name_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-placeholder-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "placeholder.yaml").write_text(
                """
skeleton: name_match_missing_call
name: missing-function-name
severity: MEDIUM
source: "Solodit #20232 (Code4rena/Polynomial Protocol)"
wiki_title: "Missing function name"
wiki_description: "No real function metadata was extracted."
solodit_id: "20232"
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(record["year"], 2000)
            self.assertIn("name_match_missing_call", record["function_shape"]["shape_tags"])

    def test_weak_name_match_function_hint_does_not_emit_synthetic_signature(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-function-hint-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "hint.yaml").write_text(
                """
skeleton: name_match_missing_call
name: weak-name-hint
severity: HIGH
source: "Solodit #1000 (Code4rena/Example)"
wiki_title: "Weak name hint"
wiki_description: "The finding has only a detector-guessed function name."
solodit_id: "1000"
vuln_fn_name: pool0
vuln_fn_params: ""
vuln_fn_mutability: internal
vuln_fn_mutability_clean: internal
vuln_fn_return: bool
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(record["function_shape"]["raw_signature"], "function-name-hint: pool0")
            self.assertIn("name_match_missing_call", record["function_shape"]["shape_tags"])
            self.assertIn("inferred-function-name", record["function_shape"]["shape_tags"])

    def test_prefers_explicit_vulnerable_function_signature_when_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-signature-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "explicit-signature.yaml").write_text(
                """
skeleton: name_match_missing_call
name: explicit-signature
severity: HIGH
wiki_title: "Explicit signature"
wiki_description: "The finding includes a complete vulnerable function signature."
solodit_id: "777"
vuln_fn_name: fallbackName
vuln_fn_sig: "function execute(bytes calldata data, uint256 value) external payable returns (bool ok)"
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(
                record["function_shape"]["raw_signature"],
                "function execute(bytes calldata data, uint256 value) external payable returns (bool ok)",
            )

    def test_converts_move_spec_to_valid_hackerman_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-move-etl-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "volume-overflow-risk.yaml").write_text(
                """
id: volume-overflow-risk
title: Volume Overflow Risk
severity: Medium
language: move
source: solodit-move-p2
source_id: "M-47058"
bug_class: flash-loan
real_world_example: "Volume overflow risk can corrupt accounting."
suggested_remediation: "Bound volume arithmetic."
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["records_emitted"], 1)
            path = next(out_dir.glob("*.yaml"))
            status, errors = self.validator.validate_file(path, self.validator.load_schema())
            self.assertEqual(status, "valid", errors)
            record = self.validator.load_yaml(path)
            self.assertEqual(record["target_language"], "move")
            self.assertEqual(record["bug_class"], "flash-loan")
            self.assertEqual(record["attack_class"], "flash-loan")

    def test_cli_limit_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-cli-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            for idx in range(2):
                (spec_dir / f"spec-{idx}.yaml").write_text(
                    f"name: spec-{idx}\nseverity: LOW\nsolodit_id: \"{idx}\"\nwiki_title: spec {idx}\n",
                    encoding="utf-8",
                )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--spec-dir",
                        str(spec_dir),
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "1",
                        "--json-summary",
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted": 1', stdout.getvalue())
            self.assertEqual(len(list(out_dir.glob("*.yaml"))), 1)

    def test_tolerates_generated_literal_escape_quirks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-escape-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "escaped.yaml").write_text(
                'name: escaped\nseverity: MEDIUM\nsolodit_id: "6131"\n'
                'help: "Rewards fail for \\$TOKEN when fee is 10\\%"\n',
                encoding="utf-8",
            )

            summary = self.tool.convert_specs([spec_dir], out_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["records_emitted"], 1)
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertIn("$TOKEN", record["target_component"])

    def test_quotes_yaml_indicator_scalars_and_validates_dry_run_rendered_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-yaml-scalar-") as tmp:
            root = Path(tmp)
            spec_dir = root / "specs"
            out_dir = root / "out"
            spec_dir.mkdir()
            (spec_dir / "indicator.yaml").write_text(
                """
id: indicator
title: Burn scaled transfers full underlying on overshoot
severity: High
language: rust
source: code4rena-solodit-p1
source_id: "R-1"
bug_class: accounting
real_world_example: ">= threshold burns full underlying amount"
suggested_remediation: "Bound amount before burn."
""".lstrip(),
                encoding="utf-8",
            )

            dry_summary = self.tool.convert_specs([spec_dir], out_dir, dry_run=True)
            self.assertEqual(dry_summary["errors"], [])
            self.assertEqual(dry_summary["file_count"], 1)
            self.assertFalse(out_dir.exists())

            summary = self.tool.convert_specs([spec_dir], out_dir)
            self.assertEqual(summary["errors"], [])
            record = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
            self.assertEqual(record["target_language"], "rust")
            self.assertIn(">= threshold", record["attacker_action_sequence"])

    def test_non_primary_feed_ids_are_namespaced_without_destabilizing_primary_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-spec-feed-ids-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            out_dir = root / "out"
            primary_solodit = root / "drafts_solodit"
            primary_move = root / "drafts_solodit_move"
            rust_feed = root / "drafts_code4rena_rust"
            soroban_feed = root / "drafts_rust_soroban"
            solana_feed = root / "drafts_ottersec_solana"
            spec_dirs = [primary_solodit, primary_move, rust_feed, soroban_feed, solana_feed]
            for spec_dir in spec_dirs:
                spec_dir.mkdir()
                (spec_dir / "shared-source.yaml").write_text(
                    f"""
id: stable-move-id
title: Shared feed source should not collide
severity: Medium
language: {"move" if spec_dir is primary_move else "rust"}
source: {spec_dir.name}
source_id: "SHARED-42"
bug_class: accounting
real_world_example: "Accounting drift in {spec_dir.name}."
suggested_remediation: "Keep feed identity distinct."
""".lstrip(),
                    encoding="utf-8",
                )
            (primary_solodit / "shared-source.yaml").write_text(
                """
name: stable-solodit-id
severity: MEDIUM
solodit_id: "22011"
wiki_title: Shared Solodit primary ID remains stable
wiki_description: "Primary Solodit specs keep their historical identity seed."
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.convert_specs(spec_dirs, out_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["records_emitted"], 5)
            records = [self.validator.load_yaml(path) for path in sorted(out_dir.glob("*.yaml"))]
            by_source = {record["source_audit_ref"].split(":")[1].split("/")[-2]: record for record in records}

            self.assertEqual(len({record["record_id"] for record in records}), 5)
            self.assertEqual(len({record["source_audit_ref"] for record in records}), 5)
            self.assertRegex(by_source["drafts_solodit"]["record_id"], r"^solodit-spec:22011:[0-9a-f]{12}$")
            self.assertRegex(
                by_source["drafts_solodit_move"]["record_id"],
                r"^solodit-spec:shared-42:[0-9a-f]{12}$",
            )
            for feed_name in ("drafts_code4rena_rust", "drafts_rust_soroban", "drafts_ottersec_solana"):
                self.assertRegex(
                    by_source[feed_name]["record_id"],
                    rf"^solodit-spec:{feed_name}:shared-42:[0-9a-f]{{12}}$",
                )


class HackermanEtlFromSoloditSpecsB7DefaultDirsTests(unittest.TestCase):
    """B7 (EXEC-WAVE-2-MULTI): verify the 5 previously-unmined detector-spec
    draft dirs are registered in DEFAULT_SPEC_DIRS."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load(TOOL, "hackerman_etl_from_solodit_specs_b7")

    def test_b7_default_spec_dirs_includes_five_unmined_dirs(self) -> None:
        default_names = {Path(p).name for p in self.tool.DEFAULT_SPEC_DIRS}
        required = {
            "drafts_halborn-k2-2025-09",
            "drafts_halborn_soroban_general",
            "drafts_v12-critical",
            "drafts_v12-high",
            "drafts_v12-med-low",
        }
        missing = required - default_names
        self.assertEqual(
            missing,
            set(),
            f"B7: DEFAULT_SPEC_DIRS missing required draft dirs: {sorted(missing)}",
        )

    def test_b7_default_spec_dirs_resolve_under_repo_detectors_specs(self) -> None:
        for path in self.tool.DEFAULT_SPEC_DIRS:
            p = Path(path)
            self.assertEqual(
                p.parent.name,
                "_specs",
                f"DEFAULT_SPEC_DIRS entry not under detectors/_specs: {p}",
            )


if __name__ == "__main__":
    unittest.main()
