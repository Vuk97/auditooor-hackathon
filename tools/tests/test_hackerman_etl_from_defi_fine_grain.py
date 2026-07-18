from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-defi-fine-grain.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromDefiFineGrainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_defi_fine_grain")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_defi_fine_grain")

    # -----------------------------------------------------------------
    # Schema validation: every emitted record must validate.
    # -----------------------------------------------------------------
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-dry-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        self.assertEqual(summary["records_emitted"], summary["records_attempted"])

    def test_target_record_count_is_in_band(self) -> None:
        """Lift C7 target: ~1,200 records. We allow a ±25% band."""
        with tempfile.TemporaryDirectory(prefix="defi-fg-count-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertGreaterEqual(summary["records_emitted"], 900)
        self.assertLessEqual(summary["records_emitted"], 1600)

    def test_all_four_domains_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-domains-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        for domain_enum in ("vault", "lending", "dex", "staking"):
            self.assertIn(domain_enum, summary["by_domain"])
            self.assertGreater(summary["by_domain"][domain_enum], 0)

    def test_three_mitigation_states_present_for_significant_classes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-states-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        for state in ("proposed", "mitigated", "regressed"):
            self.assertIn(state, summary["by_mitigation_state"])
            self.assertGreater(summary["by_mitigation_state"][state], 0)
        # All three states should appear in roughly equal numbers because
        # every taxonomy row in the seed is severity >= medium.
        states = summary["by_mitigation_state"]
        max_state = max(states.values())
        min_state = min(states.values())
        self.assertLess(max_state - min_state, max_state * 0.6)

    # -----------------------------------------------------------------
    # Taxonomy coverage.
    # -----------------------------------------------------------------
    def test_taxonomy_covers_required_attack_classes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-tax-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        required_classes = {
            "erc4626-first-depositor-inflation",
            "vault-share-mint-rounding-favoring-attacker",
            "lending-liquidation-bonus-theft",
            "lending-bad-debt-socialization-bypass",
            "amm-stableswap-curve-tangent-attack",
            "amm-twap-window-too-short",
            "staking-reward-claim-replay",
            "staking-validator-slash-evasion",
        }
        for cls in required_classes:
            self.assertIn(cls, summary["by_attack_class"], f"missing taxonomy class {cls}")

    def test_filter_domain_restricts_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-filter-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out", dry_run=True, filter_domain="staking"
            )
        self.assertGreater(summary["records_emitted"], 0)
        self.assertEqual(set(summary["by_domain"]), {"staking"})

    # -----------------------------------------------------------------
    # Schema correctness on real write.
    # -----------------------------------------------------------------
    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir, limit=24)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    def test_emitted_record_has_required_fine_grain_signals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-detail-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=1)
            path = next(out_dir.glob("*.yaml"))
            record = self.validator.load_yaml(path)
        self.assertEqual(record["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(record["target_language"], "solidity")
        self.assertIn(record["target_domain"], {"vault", "lending", "dex", "staking"})
        self.assertIn(record["severity_at_finding"], {"critical", "high", "medium", "low", "info"})
        self.assertIn(record["record_tier"], {"public-corpus", "local-workspace", "submission-derived", "dydx-filed", "mezo-filed"})
        self.assertEqual(record["source_extraction_method"], "corpus-etl")
        # The mitigation-state marker is embedded in the action sequence.
        self.assertRegex(
            record["attacker_action_sequence"],
            r"\[mitigation-state=(proposed|mitigated|regressed);",
        )

    def test_record_ids_are_unique(self) -> None:
        records = self.tool.build_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "record_id collisions detected")

    # -----------------------------------------------------------------
    # YAML rendering: floats / ints / booleans / colons.
    # -----------------------------------------------------------------
    def test_yaml_scalar_emits_float_as_number(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(3.0), "3.0")
        self.assertEqual(self.tool.yaml_scalar(0.6), "0.6")

    def test_yaml_scalar_emits_bool_as_unquoted_bool(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")

    def test_yaml_scalar_quotes_trailing_colon(self) -> None:
        # Strings ending in colon must be JSON-quoted to remain YAML-safe.
        self.assertEqual(self.tool.yaml_scalar("foo:"), '"foo:"')

    # -----------------------------------------------------------------
    # CLI surface.
    # -----------------------------------------------------------------
    def test_cli_dry_run_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="defi-fg-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--limit",
                        "3",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted": 3', stdout.getvalue())
            self.assertFalse(out_dir.exists())  # dry-run must not create dir

    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(["--out-dir", "/tmp/should-not-be-created", "--limit", "-1"])
        self.assertEqual(rc, 2)

    def test_cli_filter_domain_amm_alias(self) -> None:
        """Taxonomy bucket `amm` is exposed as a CLI alias for schema enum `dex`."""
        with tempfile.TemporaryDirectory(prefix="defi-fg-amm-alias-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--filter-domain",
                        "amm",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"dex":', stdout.getvalue())
            self.assertNotIn('"vault":', stdout.getvalue().split('"by_domain"', 1)[-1])


if __name__ == "__main__":
    unittest.main()
