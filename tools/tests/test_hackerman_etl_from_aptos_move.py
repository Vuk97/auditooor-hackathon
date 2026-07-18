"""Tests for tools/hackerman-etl-from-aptos-move.py.

Wave-3 lane EXEC-WAVE3-APTOS-MOVE / TIER-C Lift C5.

These tests cover:

* baseline Aptos Labs curated record builder emits valid hackerman_record v1
* Move-resource-safety classifier wins over generic taxonomy when both fire
* Zellic audit-report parser extracts a finding section + severity
* Zellic DSL pattern parser tolerates form-feed-corrupted YAML and skips
  obvious noise (`disclaimer-*`, `about-*`)
* end-to-end convert() emits >=80 records with no schema validation errors
* CLI `--dry-run --json-summary` returns a valid JSON summary without
  writing files
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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-aptos-move.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromAptosMoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_aptos_move_under_test")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_aptos_move_test")

    # ------------------------------------------------------------------
    # Taxonomy classifier
    # ------------------------------------------------------------------

    def test_move_resource_safety_classifier_wins_for_signer_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Resource account exposes &signer to a public helper that calls "
            "create_signer_with_capability."
        )
        self.assertEqual(bug_class, "signer-derived-resource-leak")
        self.assertEqual(attack_class, "signer-from-caller-controlled-path")

    def test_move_resource_safety_classifier_wins_for_acquires_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Function borrow_global_mut<State> is called without an "
            "acquires clause and the verifier accepted the module."
        )
        self.assertEqual(bug_class, "acquires-mismatch")
        self.assertEqual(attack_class, "missing-or-extra-acquires-clause")

    def test_move_resource_safety_classifier_wins_for_capability_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "MintCapability is stored inside a shared resource and any caller "
            "can borrow it to mint freely."
        )
        self.assertEqual(bug_class, "capability-pattern-bypass")
        self.assertEqual(attack_class, "capability-leak-or-unbounded-mint")

    def test_move_resource_safety_classifier_wins_for_aborts_if_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Spec aborts_if predicate diverges from runtime abort_with code, "
            "creating a totality gap."
        )
        self.assertEqual(bug_class, "aborts-if-policy-mismatch")
        self.assertEqual(attack_class, "aborts-if-divergence")

    def test_move_resource_safety_classifier_wins_for_double_move(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Module performs move_from<Resource> twice through two entries; "
            "drop ability allows the second move to succeed silently."
        )
        self.assertEqual(bug_class, "resource-safety-violation")
        self.assertEqual(attack_class, "double-move-or-dangling-resource")

    def test_generic_fallback_for_unrelated_text(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack("Random observation")
        self.assertEqual(bug_class, "logic-error")
        self.assertEqual(attack_class, "protocol-invariant-bypass")

    # ------------------------------------------------------------------
    # Baseline curated record
    # ------------------------------------------------------------------

    def test_baseline_records_pass_schema(self) -> None:
        schema = self.validator.load_schema()
        emitted = 0
        for entry in self.tool.APTOS_LABS_KNOWN_DISCLOSURES:
            record = self.tool.baseline_record(entry)
            errors = self.validator.validate_doc(record, schema)
            self.assertEqual(errors, [], f"{entry['slug']}: {errors}")
            self.assertEqual(record["target_language"], "move")
            self.assertIn("move-aptos", record["function_shape"]["shape_tags"])
            self.assertIn("move-resource-safety", record["function_shape"]["shape_tags"])
            emitted += 1
        # The lane targets 80-150 records overall; baseline alone must
        # contribute at least 10 to guarantee taxonomy coverage even when
        # the live corpus is unavailable.
        self.assertGreaterEqual(emitted, 10)

    # ------------------------------------------------------------------
    # Audit-report parser
    # ------------------------------------------------------------------

    def test_audit_report_parser_extracts_finding_and_severity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aptos-move-report-") as tmp:
            root = Path(tmp)
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            sample = corpus_dir / "Sample Aptos - Zellic Audit Report.txt"
            sample.write_text(
                """\
                  Sample Aptos
                  Move Application Security Assessment

                  June 4, 2025

                3 Detailed Findings

                3.1 Capability leak via shared resource
                  Target  capability_module
                  Severity  Critical
                  Likelihood  High
                  Impact  Critical

                  Description
                  The module stores MintCapability inside a shared resource that
                  can be borrowed by any account. An attacker mints arbitrary
                  amounts by borrowing the capability and invoking mint.

                  Recommendations
                  Move MintCapability under a dedicated resource account.

                3.2 Acquires clause missing on borrow_global_mut
                  Target  rewards_module
                  Severity  Medium

                  Description
                  apply_update calls borrow_global_mut<State> without an
                  `acquires State` clause; the verifier did not enforce the
                  per-entry borrow set.

                4 Discussion

                4.1 Test suite
                  Some discussion text that should not become a finding.
                """,
                encoding="utf-8",
            )

            findings = self.tool.parse_audit_report(sample)
            self.assertGreaterEqual(len(findings), 2)
            titles = {f["title"].lower() for f in findings}
            self.assertTrue(any("capability leak" in t for t in titles))
            self.assertTrue(any("acquires clause" in t for t in titles))
            severities = {f["severity"] for f in findings}
            self.assertIn("critical", severities)
            self.assertIn("medium", severities)

    def test_is_aptos_move_report_filters_unrelated_filenames(self) -> None:
        self.assertTrue(
            self.tool.is_aptos_move_report(Path("Wormhole Aptos - Zellic Audit Report.txt"))
        )
        self.assertTrue(
            self.tool.is_aptos_move_report(Path("Thala Labs Move Dollar - Zellic Audit Report.txt"))
        )
        self.assertFalse(
            self.tool.is_aptos_move_report(Path("Some Solana Project - Zellic Audit Report.txt"))
        )

    # ------------------------------------------------------------------
    # DSL pattern channel
    # ------------------------------------------------------------------

    def test_pattern_filename_blocklist_skips_disclaimers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aptos-move-pattern-") as tmp:
            patterns_dir = Path(tmp) / "patterns"
            patterns_dir.mkdir()
            (patterns_dir / "disclaimer.yaml").write_text(
                "title: Disclaimer\nplatform: aptos\nreal_world_example: |\n  Should be skipped.\n",
                encoding="utf-8",
            )
            (patterns_dir / "ability-field-requirements-verifier.yaml").write_text(
                """\
id: ability-field-requirements-verifier
title: |
  Ability field requirements verifier
severity: Informational
language: rust
source: zellic-local-move-and-sui-security-assessment
source_id: "F-4-2"
bug_class: ability-policy
real_world_example: |
  The MoveVM bytecode verifier enforces the ability field requirements.
  Missing acquires clauses must abort.
suggested_remediation: |
  Re-run the move-bytecode-verifier after every release.
""",
                encoding="utf-8",
            )

            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                corpus_dirs=[],
                patterns_dirs=[patterns_dir],
                out_dir=out_dir,
                dry_run=True,
                include_baseline=False,
            )
            self.assertEqual(summary["errors"], [])
            # disclaimer skipped, the ability one survives because the stem
            # matches a relevant hint.
            self.assertGreaterEqual(summary["records_emitted"], 1)

    def test_pattern_loader_tolerates_form_feed_characters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aptos-move-formfeed-") as tmp:
            patterns_dir = Path(tmp) / "patterns"
            patterns_dir.mkdir()
            (patterns_dir / "ability-field-formfeed.yaml").write_text(
                "title: |\n  Ability field with form feed\x0c here\n"
                "source: zellic-local-aptos\nlanguage: rust\n"
                "real_world_example: |\n  An aptos finding with control char.\n",
                encoding="utf-8",
            )
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                corpus_dirs=[],
                patterns_dirs=[patterns_dir],
                out_dir=out_dir,
                dry_run=True,
                include_baseline=False,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreaterEqual(summary["records_emitted"], 1)

    # ------------------------------------------------------------------
    # End-to-end against the vendored Aptos / Move corpus
    # ------------------------------------------------------------------

    def test_convert_end_to_end_against_repo_corpus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aptos-move-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                corpus_dirs=[self.tool.DEFAULT_CORPUS_DIR.resolve()],
                patterns_dirs=[self.tool.DEFAULT_PATTERNS_DIR.resolve()],
                out_dir=out_dir,
                dry_run=False,
            )
            self.assertEqual(summary["errors"], [])
            # Target band: 80-150 records. Baseline alone has ~15, audit
            # reports surface ~50-90 findings, DSL fallback adds the rest.
            self.assertGreaterEqual(
                summary["records_emitted"], 80,
                f"emitted {summary['records_emitted']}, want >=80",
            )
            self.assertLessEqual(
                summary["records_emitted"], 200,
                f"emitted {summary['records_emitted']}, want <=200",
            )
            # All records must be valid hackerman_record v1.
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
            # surface in the emitted corpus (some niches may be sparse).
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
        with tempfile.TemporaryDirectory(prefix="aptos-move-cli-") as tmp:
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
                        "12",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertLessEqual(payload["records_emitted"], 12)
            self.assertFalse(out_dir.exists())

    def test_cli_no_include_baseline_skips_curated_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aptos-move-no-baseline-") as tmp:
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
            # No baseline record_ids should appear in dry-run files list.
            for fname in payload["files"]:
                self.assertNotIn("aptos-move-baseline", fname.lower().replace(":", "-"))


if __name__ == "__main__":
    unittest.main()
