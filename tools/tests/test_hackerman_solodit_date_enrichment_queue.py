from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-solodit-date-enrichment-queue.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanSoloditDateEnrichmentQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_solodit_date_enrichment_queue_test")

    def _write_record_fixture(self, root: Path, *, source: str, source_ref_id: str = "63969") -> tuple[Path, Path]:
        tag_dir = root / "tags"
        spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
        tag_dir.mkdir()
        spec_dir.mkdir(parents=True)
        spec_path = spec_dir / "finding.yaml"
        spec_path.write_text(
            f"""
skeleton: name_match_missing_call
name: finding
severity: HIGH
source: "{source}"
wiki_title: "Finding title"
wiki_description: "A finding description"
solodit_id: "{source_ref_id}"
""".lstrip(),
            encoding="utf-8",
        )
        tag_path = tag_dir / "record.yaml"
        tag_path.write_text(
            f"""
schema_version: auditooor.hackerman_record.v1.1
record_id: solodit-spec:{source_ref_id}:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:{source_ref_id}
verification_tier: tier-2-verified-public-archive
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: Finding
function_shape:
  raw_signature: "function-name-hint: finding"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit finding
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
        return tag_dir, tag_path

    def test_source_line_date_becomes_hint_not_backfill(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-date-queue-", dir=REPO_ROOT) as td:
            root = Path(td)
            tag_dir, tag_path = self._write_record_fixture(
                root,
                source="Solodit #63969 (Pashov Audit Group/Ostium_2025-08-22)",
            )
            rows, summary = self.tool.build_queue(tag_dir)

            self.assertEqual(summary["rows"], 1)
            self.assertFalse(summary["mutation_performed"])
            self.assertEqual(rows[0]["status"], "needs_explicit_source_date")
            self.assertEqual(rows[0]["solodit_id"], "63969")
            self.assertEqual(rows[0]["safe_date_fields_present"], {})
            self.assertTrue(rows[0]["unsafe_date_hints"])
            self.assertIn("year: 2000", tag_path.read_text(encoding="utf-8"))

    def test_safe_local_date_fields_are_not_queued_for_external_fetch_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-date-queue-safe-", dir=REPO_ROOT) as td:
            root = Path(td)
            tag_dir, _tag_path = self._write_record_fixture(
                root,
                source="Solodit #7001 (Example Audit)",
                source_ref_id="7001",
            )
            spec_path = next((root / "detectors" / "_specs" / "drafts_solodit").glob("*.yaml"))
            spec_path.write_text(spec_path.read_text(encoding="utf-8") + 'audit_date: "2025-08-22"\n', encoding="utf-8")

            rows, summary = self.tool.build_queue(tag_dir)
            self.assertEqual(rows, [])
            self.assertEqual(summary["status_counts"], {"local_safe_date_fields_present_run_backfill": 1})

            all_rows, all_summary = self.tool.build_queue(tag_dir, status_filter="all")
            self.assertEqual(all_summary["rows"], 1)
            self.assertEqual(all_rows[0]["safe_date_fields_present"], {"audit_date": 1})

    def test_limit_caps_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solodit-date-queue-limit-", dir=REPO_ROOT) as td:
            root = Path(td)
            self._write_record_fixture(root, source="Solodit #1 (Example)")
            tag_dir = root / "tags"
            first = tag_dir / "record.yaml"
            second = tag_dir / "record2.yaml"
            second.write_text(
                first.read_text(encoding="utf-8")
                .replace("solodit-spec:1:abcdefabcdef", "solodit-spec:2:abcdefabcdef")
                .replace(":1\n", ":2\n"),
                encoding="utf-8",
            )

            rows, summary = self.tool.build_queue(tag_dir, limit=1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(summary["rows"], 1)


if __name__ == "__main__":
    unittest.main()
