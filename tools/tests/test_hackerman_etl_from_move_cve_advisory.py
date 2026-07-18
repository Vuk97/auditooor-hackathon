"""Tests for tools/hackerman-etl-from-move-cve-advisory.py.

Wave-5 lane EXEC-WAVE5-MOVE-CVE-RETAG / TIER-D Lift D13.

These tests cover:

* Move-resource-safety classifier wins over generic taxonomy when both fire
* Curated CVE / advisory baseline emits valid hackerman_record v1 records
* convert() emits >=50 records and <=80 records
* Each emitted record has target_language=move and "cve-backbone" in shape_tags
* CLI `--dry-run --json-summary` returns a valid JSON summary without writing files
* CLI `--no-include-baseline` skips the curated backbone
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-move-cve-advisory.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromMoveCveAdvisoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_move_cve_under_test")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_move_cve_test")

    # ------------------------------------------------------------------
    # Taxonomy classifier
    # ------------------------------------------------------------------

    def test_classifier_wins_for_signer_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "A friend module exposes &SignerCapability to a caller that round-trips "
            "into create_signer_with_capability."
        )
        self.assertEqual(bug_class, "signer-derived-resource-leak")
        self.assertEqual(attack_class, "signer-from-caller-controlled-path")

    def test_classifier_wins_for_acquires_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Function borrow_global_mut<State> is called without an acquires clause."
        )
        self.assertEqual(bug_class, "acquires-mismatch")
        self.assertEqual(attack_class, "missing-or-extra-acquires-clause")

    def test_classifier_wins_for_capability_leak(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "TreasuryCap leaks via public borrow allowing unbounded mint."
        )
        self.assertEqual(bug_class, "capability-pattern-bypass")
        self.assertEqual(attack_class, "capability-leak-or-unbounded-mint")

    def test_classifier_wins_for_aborts_if_divergence(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Spec aborts_if predicate diverges from runtime abort_with; totality gap."
        )
        self.assertEqual(bug_class, "aborts-if-policy-mismatch")
        self.assertEqual(attack_class, "aborts-if-divergence")

    def test_classifier_wins_for_double_move(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Function performs move_from<Resource> twice; drop ability bypasses second."
        )
        self.assertEqual(bug_class, "resource-safety-violation")
        self.assertEqual(attack_class, "double-move-or-dangling-resource")

    def test_classifier_generic_fallback(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack("Random observation")
        self.assertEqual(bug_class, "logic-error")
        self.assertEqual(attack_class, "protocol-invariant-bypass")

    # ------------------------------------------------------------------
    # Baseline curated records
    # ------------------------------------------------------------------

    def test_baseline_records_pass_schema(self) -> None:
        schema = self.validator.load_schema()
        emitted = 0
        for entry in self.tool.MOVE_CVE_ADVISORY_BACKBONE:
            record = self.tool.baseline_record(entry)
            errors = self.validator.validate_doc(record, schema)
            self.assertEqual(errors, [], f"{entry['slug']}: {errors}")
            self.assertEqual(record["target_language"], "move")
            self.assertIn("cve-backbone", record["function_shape"]["shape_tags"])
            self.assertIn("move-resource-safety", record["function_shape"]["shape_tags"])
            self.assertTrue(record["source_audit_ref"].startswith("move-cve-advisory:"))
            emitted += 1
        # Spec calls for 50-80 records; baseline alone should hit at least 50.
        self.assertGreaterEqual(emitted, 50)
        self.assertLessEqual(emitted, 80)

    def test_baseline_records_have_advisory_id(self) -> None:
        for entry in self.tool.MOVE_CVE_ADVISORY_BACKBONE:
            self.assertIn("advisory_id", entry, f"{entry['slug']} missing advisory_id")
            self.assertTrue(
                entry["advisory_id"], f"{entry['slug']} advisory_id empty"
            )

    def test_baseline_target_repo_coverage_includes_aptos_and_sui(self) -> None:
        # The backbone must cover both Aptos and Sui (and Move language)
        # so downstream callers can sanity-check cross-chain shape coverage.
        repos = {e.get("target_repo") for e in self.tool.MOVE_CVE_ADVISORY_BACKBONE}
        self.assertIn("aptos-labs/aptos-core", repos)
        self.assertIn("MystenLabs/sui", repos)
        self.assertIn("move-language/move", repos)

    # ------------------------------------------------------------------
    # End-to-end convert
    # ------------------------------------------------------------------

    def test_convert_end_to_end_emits_full_backbone(self) -> None:
        with tempfile.TemporaryDirectory(prefix="move-cve-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir=out_dir, dry_run=False)
            self.assertEqual(summary["errors"], [])
            self.assertGreaterEqual(
                summary["records_emitted"], 50,
                f"emitted {summary['records_emitted']}, want >=50",
            )
            self.assertLessEqual(
                summary["records_emitted"], 80,
                f"emitted {summary['records_emitted']}, want <=80",
            )
            schema = self.validator.load_schema()
            count = 0
            languages: set[str] = set()
            attack_classes: set[str] = set()
            for path in out_dir.glob("*.yaml"):
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
                doc = self.validator.load_yaml(path)
                languages.add(doc["target_language"])
                attack_classes.add(doc["attack_class"])
                count += 1
            self.assertEqual(count, summary["records_emitted"])
            self.assertEqual(languages, {"move"})
            # At least three of the five Move-resource-safety classes
            # surface in the backbone (some niches may be sparse).
            expected = {
                "double-move-or-dangling-resource",
                "capability-leak-or-unbounded-mint",
                "signer-from-caller-controlled-path",
                "aborts-if-divergence",
                "missing-or-extra-acquires-clause",
            }
            self.assertGreaterEqual(
                len(expected & attack_classes), 3,
                f"only {expected & attack_classes} of {expected} surfaced",
            )

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

    def test_cli_dry_run_does_not_write_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="move-cve-cli-") as tmp:
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
                        "10",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertLessEqual(payload["records_emitted"], 10)
            self.assertFalse(out_dir.exists())

    def test_cli_no_include_baseline_emits_zero_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="move-cve-no-baseline-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--no-include-baseline",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            # No baseline means no records (the script currently mines only
            # the curated backbone; this guards that downstream channels are
            # not silently ingested).
            self.assertEqual(payload["records_emitted"], 0)


if __name__ == "__main__":
    unittest.main()
