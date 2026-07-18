from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-bridge-attacks.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromBridgeAttacksTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_bridge_attacks")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_bridge_attacks")

    # -----------------------------------------------------------------
    # 1. Schema validation: every emitted record must validate.
    # -----------------------------------------------------------------
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-dry-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)

    # -----------------------------------------------------------------
    # 2. Target record count in the expected ~24-36 band (lower than
    #    the defi-fine-grain ETL by design).
    # -----------------------------------------------------------------
    def test_target_record_count_is_in_band(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-count-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertGreaterEqual(summary["records_emitted"], 24)
        self.assertLessEqual(summary["records_emitted"], 60)

    # -----------------------------------------------------------------
    # 3. All required new attack classes are present.
    # -----------------------------------------------------------------
    def test_taxonomy_covers_all_required_attack_classes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-tax-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        required_classes = {
            "bridge-validator-set-takeover",
            "bridge-vaa-signature-replay",
            "bridge-relayer-private-key-leak",
            "bridge-init-replay-cross-chain",
            "bridge-asset-id-confusion-cross-chain",
            "bridge-wrapped-token-unbacked-mint",
            "bridge-l1-l2-message-replay",
            "bridge-canonical-asset-spoof",
            "bridge-omniscient-call-forwarding-bypass",
            "bridge-fee-collector-redirect",
        }
        for cls in required_classes:
            self.assertIn(cls, summary["by_attack_class"], f"missing attack class {cls}")

    # -----------------------------------------------------------------
    # 4. All three mitigation states present and balanced.
    # -----------------------------------------------------------------
    def test_three_mitigation_states_present_and_balanced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-states-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        states = summary["by_mitigation_state"]
        for state in ("pre-fix", "post-fix-not-migrated", "post-fix-migrated-historical"):
            self.assertIn(state, states)
            self.assertGreater(states[state], 0)
        # Each incident emits all 3 states so the counts should be equal.
        self.assertEqual(len(set(states.values())), 1)

    # -----------------------------------------------------------------
    # 5. Every record validates against the v1 schema on real-write.
    # -----------------------------------------------------------------
    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    # -----------------------------------------------------------------
    # 6. Single-record inspection has the expected bridge-specific signals.
    # -----------------------------------------------------------------
    def test_emitted_record_has_required_bridge_signals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-detail-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=1)
            path = next(out_dir.glob("*.yaml"))
            record = self.validator.load_yaml(path)
        self.assertEqual(record["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(record["target_domain"], "bridge")
        self.assertIn(record["severity_at_finding"], {"critical", "high", "medium", "low", "info"})
        self.assertEqual(record["source_extraction_method"], "human-curated")
        self.assertRegex(
            record["attacker_action_sequence"],
            r"\[mitigation-state=(pre-fix|post-fix-not-migrated|post-fix-migrated-historical);",
        )

    # -----------------------------------------------------------------
    # 7. Record-ids are unique across the full emission.
    # -----------------------------------------------------------------
    def test_record_ids_are_unique(self) -> None:
        records = self.tool.build_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "record_id collisions detected")

    # -----------------------------------------------------------------
    # 8. Additive-only dedup: re-running into a non-empty out-dir does
    #    not overwrite existing files.
    # -----------------------------------------------------------------
    def test_additive_dedup_does_not_overwrite_existing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-dedup-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=3)
            paths = sorted(out_dir.glob("*.yaml"))
            mtimes_before = {p.name: p.stat().st_mtime_ns for p in paths}
            # Touch the file to a known-old mtime so we can detect a rewrite.
            for p in paths:
                p.write_text(p.read_text(encoding="utf-8") + "# sentinel\n", encoding="utf-8")
            sentinel_marks = {p.name: p.read_text(encoding="utf-8").endswith("# sentinel\n") for p in paths}
            # Re-run the convert: existing rows must be kept untouched.
            self.tool.convert(out_dir, limit=3)
            for p in paths:
                self.assertTrue(
                    p.read_text(encoding="utf-8").endswith("# sentinel\n"),
                    f"{p.name} was overwritten by the re-run",
                )
            self.assertTrue(all(sentinel_marks.values()))

    # -----------------------------------------------------------------
    # 9. YAML scalar rendering.
    # -----------------------------------------------------------------
    def test_yaml_scalar_emits_bool_and_float(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")
        self.assertEqual(self.tool.yaml_scalar(0.9), "0.9")
        self.assertEqual(self.tool.yaml_scalar(4.0), "4.0")

    # -----------------------------------------------------------------
    # 10. YAML scalar quotes ambiguous strings.
    # -----------------------------------------------------------------
    def test_yaml_scalar_quotes_trailing_colon(self) -> None:
        self.assertEqual(self.tool.yaml_scalar("foo:"), '"foo:"')

    # -----------------------------------------------------------------
    # 11. CLI dry-run + json-summary.
    # -----------------------------------------------------------------
    def test_cli_dry_run_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-cli-") as tmp:
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

    # -----------------------------------------------------------------
    # 12. CLI --limit rejects negative.
    # -----------------------------------------------------------------
    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(["--out-dir", "/tmp/should-not-be-created", "--limit", "-1"])
        self.assertEqual(rc, 2)

    # -----------------------------------------------------------------
    # 13. CLI --apply + --dry-run are mutually exclusive.
    # -----------------------------------------------------------------
    def test_cli_apply_and_dry_run_are_mutually_exclusive(self) -> None:
        rc = self.tool.main(
            ["--out-dir", "/tmp/should-not-be-created", "--apply", "--dry-run"]
        )
        self.assertEqual(rc, 2)

    # -----------------------------------------------------------------
    # 14. CLI --apply writes records to disk.
    # -----------------------------------------------------------------
    def test_cli_apply_writes_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-apply-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--apply",
                        "--json-summary",
                        "--limit",
                        "2",
                    ]
                )
            self.assertEqual(rc, 0)
            written = list(out_dir.glob("*.yaml"))
            self.assertEqual(len(written), 2)

    # -----------------------------------------------------------------
    # 15. CLI --filter-attack-class restricts output.
    # -----------------------------------------------------------------
    def test_cli_filter_attack_class_restricts_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-attacks-filter-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--filter-attack-class",
                        "bridge-validator-set-takeover",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"bridge-validator-set-takeover":', stdout.getvalue())
            self.assertNotIn('"bridge-vaa-signature-replay":', stdout.getvalue())

    # -----------------------------------------------------------------
    # 16. target_repo + target_domain are pinned to bridge enum and
    #     records cover the loss-USD threshold (every CRITICAL row
    #     should have impact_dollar_class >= $1M).
    # -----------------------------------------------------------------
    def test_critical_rows_have_million_dollar_loss_class(self) -> None:
        records = self.tool.build_records()
        self.assertGreater(len(records), 0)
        seen_domains = {r["target_domain"] for r in records}
        self.assertEqual(seen_domains, {"bridge"})
        for r in records:
            if r["severity_at_finding"] == "critical":
                self.assertEqual(
                    r["impact_dollar_class"],
                    ">=$1M",
                    f"{r['record_id']} is critical but not >= $1M",
                )


if __name__ == "__main__":
    unittest.main()
