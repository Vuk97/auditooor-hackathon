from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-backfill-solodit-years.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanBackfillSoloditYearsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_backfill_solodit_years_test")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_year_backfill_test")

    def test_backfills_year_from_explicit_source_date_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            spec_path = spec_dir / "dated.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: dated
severity: HIGH
source: "Solodit #63969 (Pashov Audit Group/Ostium_2025-08-22)"
audit_date: "2025-08-22"
wiki_title: "Dated source"
wiki_description: "The source name carries a report date."
solodit_id: "63969"
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1.1
record_id: solodit-spec:63969:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:63969
verification_tier: tier-2-verified-public-archive
target_domain: vault
target_language: solidity
target_repo: pashov-audit-group/ostium_2025-08-22
target_component: Dated
function_shape:
  raw_signature: "function-name-hint: dated"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit dated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            dry = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)
            self.assertEqual(dry["updated"], 1)
            self.assertEqual(dry["examples"][0]["evidence"], "audit_date")
            self.assertEqual(dry["records_with_safe_source_date_fields"], 1)
            self.assertEqual(dry["safe_source_date_field_counts"], {"audit_date": 1})
            self.assertEqual(dry["candidate_evidence_counts"], {"audit_date": 1})
            self.assertEqual(dry["status_message"], "safe_source_date_candidates_found")
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

            summary = self.tool.backfill_years(tag_dir, reference_dir=reference_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["updated"], 1)
            record = self.validator.load_yaml(tag_path)
            self.assertEqual(record["year"], 2025)

    def test_backfills_year_from_explicit_numeric_audit_year_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-audit-year-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            reference_dir.mkdir()
            spec_path = spec_dir / "dated.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: dated
severity: HIGH
source: "Solodit #7001 (Example Audit)"
audit_year: 2024
wiki_title: "Explicit audit year"
wiki_description: "The source carries a numeric audit year."
solodit_id: "7001"
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:7001:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:7001
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: Dated
function_shape:
  raw_signature: "function-name-hint: dated"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit dated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, reference_dir=reference_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["updated"], 1)
            self.assertEqual(summary["candidate_evidence_counts"], {"audit_year": 1})
            record = self.validator.load_yaml(tag_path)
            self.assertEqual(record["year"], 2024)

    def test_backfills_year_from_matching_reverse_ported_dsl_date_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-dsl-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            dsl_dir = reference_dir / "patterns.dsl.r94_solodit_test"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            dsl_dir.mkdir(parents=True)
            spec_path = spec_dir / "undated-omo.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: undated-omo
severity: HIGH
source: "Solodit #7777 (Omo)"
wiki_title: "Undated Omo source"
wiki_description: "The raw source spec carries no report date."
solodit_id: "7777"
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "omo.yaml").write_text(
                """
id: omo-source-url-date
title: Omo source URL date
severity: High
language: solidity
source: solodit
source_id: "7777"
source_url: https://solodit.cyfrin.io/issues/omo_2025-01-25-finding
published_at: "2025-01-25"
protocol: Omo
bug_class: accounting
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:7777:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:7777
target_domain: vault
target_language: solidity
target_repo: omo/protocol
target_component: UndatedOmo
function_shape:
  raw_signature: "function-name-hint: undatedOmo"
  shape_tags:
    - accounting
bug_class: logic-error
attack_class: accounting
attacker_role: unprivileged
attacker_action_sequence: exploit undated Omo finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            dry = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)
            self.assertEqual(dry["updated"], 1)
            self.assertTrue(str(dry["examples"][0]["evidence"]).startswith("dsl.published_at:"))
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

            summary = self.tool.backfill_years(tag_dir, reference_dir=reference_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["updated"], 1)
            record = self.validator.load_yaml(tag_path)
            self.assertEqual(record["year"], 2025)

    def test_reports_unresolved_when_source_spec_has_no_date_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-unresolved-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            dsl_dir = reference_dir / "patterns.dsl.r94_solodit_test"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            dsl_dir.mkdir(parents=True)
            spec_path = spec_dir / "undated.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: undated
severity: MEDIUM
source: "Solodit #1000 (Code4rena/Vader Protocol)"
wiki_title: "Undated source"
wiki_description: "No source date is present."
solodit_id: "1000"
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "nonmatching.yaml").write_text(
                """
id: nonmatching-source-url-date
title: Nonmatching source URL date
severity: Medium
language: solidity
source: solodit
source_id: "not-1000"
source_url: https://solodit.cyfrin.io/issues/not-1000_2025-01-25-finding
protocol: Other
bug_class: accounting
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:1000:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:1000
target_domain: vault
target_language: solidity
target_repo: code4rena/vader-protocol
target_component: Undated
function_shape:
  raw_signature: "function-name-hint: undated"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit undated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: medium
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)

            self.assertEqual(summary["updated"], 0)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["unresolved_reason_counts"], {"no_source_date_evidence": 1})
            self.assertEqual(summary["records_with_safe_source_date_fields"], 0)
            self.assertIn("intentionally_unresolved", summary["status_message"])

    def test_conflicting_explicit_source_date_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-conflict-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            reference_dir.mkdir()
            spec_path = spec_dir / "conflict.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: conflict
severity: HIGH
source: "Solodit #8001 (Example Audit)"
audit_date: "2024-05-01"
published_at: "2025-06-02"
wiki_title: "Conflicting explicit dates"
wiki_description: "Two explicit source-date fields disagree."
solodit_id: "8001"
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:8001:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:8001
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: Conflict
function_shape:
  raw_signature: "function-name-hint: conflict"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit conflicting finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)

            self.assertEqual(summary["updated"], 0)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["conflicting_source_date_records"], 1)
            self.assertEqual(
                summary["unresolved_reason_counts"],
                {"conflicting_source_date_evidence": 1},
            )
            self.assertEqual(
                summary["conflicting_source_date_field_counts"],
                {"audit_date": 1, "published_at": 1},
            )
            self.assertEqual(
                {row["year"] for row in summary["conflicting_source_date_examples"][0]["conflicting_evidence"]},
                {2024, 2025},
            )
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

    def test_unsafe_source_and_filename_dates_are_reported_but_not_used(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-unsafe-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            reference_dir.mkdir()
            spec_path = spec_dir / "dated-2025-08-22.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: dated-2025-08-22
severity: HIGH
source: "Solodit #63969 (Pashov Audit Group/Ostium_2025-08-22)"
wiki_title: "Dated source 2025-08-22"
wiki_description: "Narrative has 2025 but no explicit source-date field."
solodit_id: "63969"
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:63969:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:63969
target_domain: vault
target_language: solidity
target_repo: pashov-audit-group/ostium_2025-08-22
target_component: Dated
function_shape:
  raw_signature: "function-name-hint: dated"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit dated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)

            self.assertEqual(summary["updated"], 0)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["unsafe_hint_records"], 1)
            self.assertEqual(summary["unsafe_hint_field_counts"]["source"], 1)
            self.assertEqual(summary["unsafe_hint_field_counts"]["spec_path.stem"], 1)
            self.assertEqual(summary["unsafe_hint_examples"][0]["unsafe_hints"][0]["classification"], "unsafe_non_authoritative")
            fields = {hint["field"] for hint in summary["unsafe_hint_examples"][0]["unsafe_hints"]}
            self.assertIn("source", fields)
            self.assertIn("spec_path.stem", fields)
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

    def test_matching_dsl_source_url_date_is_unsafe_without_date_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-dsl-unsafe-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            dsl_dir = reference_dir / "patterns.dsl.r94_solodit_test"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            dsl_dir.mkdir(parents=True)
            spec_path = spec_dir / "undated-omo.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: undated-omo
severity: HIGH
source: "Solodit #7777 (Omo)"
wiki_title: "Undated Omo source"
wiki_description: "The raw source spec carries no report date."
solodit_id: "7777"
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "omo.yaml").write_text(
                """
id: omo-source-url-date
title: Omo source URL date
severity: High
language: solidity
source: solodit
source_id: "7777"
source_url: https://solodit.cyfrin.io/issues/omo_2025-01-25-finding
protocol: Omo
bug_class: accounting
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:7777:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:7777
target_domain: vault
target_language: solidity
target_repo: omo/protocol
target_component: UndatedOmo
function_shape:
  raw_signature: "function-name-hint: undatedOmo"
  shape_tags:
    - accounting
bug_class: logic-error
attack_class: accounting
attacker_role: unprivileged
attacker_action_sequence: exploit undated Omo finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)

            self.assertEqual(summary["updated"], 0)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["unsafe_hint_records"], 1)
            fields = {
                hint["field"]
                for example in summary["unsafe_hint_examples"]
                for hint in example["unsafe_hints"]
            }
            self.assertIn("dsl.source_url", fields)
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

    def test_conflicting_matching_dsl_explicit_date_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-dsl-conflict-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            dsl_dir = reference_dir / "patterns.dsl.r94_solodit_test"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            dsl_dir.mkdir(parents=True)
            spec_path = spec_dir / "undated-omo.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: undated-omo
severity: HIGH
source: "Solodit #7777 (Omo)"
wiki_title: "Undated Omo source"
wiki_description: "The raw source spec carries no report date."
solodit_id: "7777"
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "omo-a.yaml").write_text(
                """
id: omo-published-at
title: Omo published date
severity: High
language: solidity
source: solodit
source_id: "7777"
published_at: "2024-01-25"
protocol: Omo
bug_class: accounting
""".lstrip(),
                encoding="utf-8",
            )
            (dsl_dir / "omo-b.yaml").write_text(
                """
id: omo-report-date
title: Omo report date
severity: High
language: solidity
source: solodit
source_id: "7777"
report_date: "2025-01-25"
protocol: Omo
bug_class: accounting
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:7777:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:7777
target_domain: vault
target_language: solidity
target_repo: omo/protocol
target_component: UndatedOmo
function_shape:
  raw_signature: "function-name-hint: undatedOmo"
  shape_tags:
    - accounting
bug_class: logic-error
attack_class: accounting
attacker_role: unprivileged
attacker_action_sequence: exploit undated Omo finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_years(tag_dir, dry_run=True, reference_dir=reference_dir)

            self.assertEqual(summary["updated"], 0)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["conflicting_source_date_records"], 1)
            self.assertEqual(
                summary["unresolved_reason_counts"],
                {"dsl_conflicting_source_date_evidence": 1},
            )
            self.assertEqual(
                summary["conflicting_source_date_field_counts"],
                {"dsl.published_at": 1, "dsl.report_date": 1},
            )
            self.assertEqual(
                {row["year"] for row in summary["conflicting_source_date_examples"][0]["conflicting_evidence"]},
                {2024, 2025},
            )
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

    def test_emits_candidates_jsonl_with_resolved_year(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-year-backfill-candidates-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            reference_dir = root / "reference"
            candidates_path = root / "year-backfill-candidates.jsonl"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            reference_dir.mkdir()
            # Resolved record - safe source-date evidence available.
            spec_resolved = spec_dir / "dated-2025.yaml"
            spec_resolved.write_text(
                """
skeleton: name_match_missing_call
name: dated-2025
severity: HIGH
source: "Solodit #99 (Pashov Audit Group/Vader_2025-04-02)"
source_date: "2025-04-02"
wiki_title: "Pre-dated source"
wiki_description: "The slug carries a real audit date."
solodit_id: "99"
""".lstrip(),
                encoding="utf-8",
            )
            (tag_dir / "resolved.yaml").write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:99:facefacefac0
source_audit_ref: solodit-spec:{spec_resolved.relative_to(REPO_ROOT).as_posix()}:99
target_domain: vault
target_language: solidity
target_repo: pashov-audit-group/vader_2025-04-02
target_component: Resolved
function_shape:
  raw_signature: "function-name-hint: resolved"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit dated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )
            # Unresolved record - missing safe metadata.
            spec_unresolved = spec_dir / "undated.yaml"
            spec_unresolved.write_text(
                """
skeleton: name_match_missing_call
name: undated
severity: HIGH
source: "Solodit #100 (Some Auditor)"
wiki_title: "Undated"
wiki_description: "Source carries no date hint."
solodit_id: "100"
""".lstrip(),
                encoding="utf-8",
            )
            (tag_dir / "unresolved.yaml").write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:100:abcdef
source_audit_ref: solodit-spec:{spec_unresolved.relative_to(REPO_ROOT).as_posix()}:100
target_domain: vault
target_language: solidity
target_repo: unknown
target_component: Undated
function_shape:
  raw_signature: "function-name-hint: undated"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit undated finding
required_preconditions:
  - source spec exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: apply source remediation
fix_anti_pattern_avoided: inventing missing dates
severity_at_finding: high
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )
            summary = self.tool.backfill_years(
                tag_dir,
                dry_run=True,
                reference_dir=reference_dir,
                candidates_path=candidates_path,
            )
            self.assertEqual(summary["updated"], 1)
            self.assertEqual(summary["unresolved"], 1)
            self.assertEqual(summary["candidates_written"], 1)
            self.assertEqual(summary["records_with_safe_source_date_fields"], 1)
            self.assertEqual(summary["safe_source_date_field_counts"], {"source_date": 1})
            self.assertEqual(summary["candidate_evidence_counts"], {"source_date": 1})
            self.assertTrue(candidates_path.exists())
            import json as _json
            rows = [_json.loads(line) for line in candidates_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["new_year"], 2025)
            self.assertEqual(rows[0]["old_year"], 2000)
            self.assertEqual(rows[0]["tag_file"], "resolved.yaml")
            # The unresolved record must NOT appear in the candidates JSONL.
            self.assertNotIn("unresolved", _json.dumps(rows))


if __name__ == "__main__":
    unittest.main()
