"""Tests for tools/hackerman-etl-from-audit-firm-public-reports.py.

The miner mines REAL public audit-firm report archives (trailofbits,
Zellic, spearbit, ChainSecurity, Cyfrin, pashov, SB-Security,
sherlock-protocol) via the GitHub recursive ``git/trees`` API. These tests drive the miner
through a cached fixture so they are deterministic and run offline (no
live ``gh api`` calls).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-audit-firm-public-reports.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = (
    REPO_ROOT
    / "tools"
    / "tests"
    / "fixtures"
    / "hackerman_etl_from_audit_firm_public_reports"
)
TREES_FIXTURE = FIXTURE_DIR / "trees.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromAuditFirmPublicReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_audit_firm_public_reports")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_audit_firm_public_reports_test"
        )
        self.assertTrue(
            TREES_FIXTURE.exists(), f"missing trees fixture: {TREES_FIXTURE}"
        )

    # -----------------------------------------------------------------
    # Smoke: end-to-end emit produces zero errors and a non-trivial
    # record count.
    # -----------------------------------------------------------------
    def test_full_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-full-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                trees_cache=TREES_FIXTURE,
            )
        self.assertEqual(summary["errors"], [])
        self.assertGreaterEqual(summary["records_emitted"], 20)
        self.assertEqual(
            summary["records_emitted"], summary["records_attempted"]
        )
        self.assertEqual(
            summary["verification_tier"], "tier-2-verified-public-archive"
        )

    # -----------------------------------------------------------------
    # Schema validation: every emitted YAML must validate.
    # -----------------------------------------------------------------
    def test_all_emitted_records_validate_against_declared_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-validate-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            seen = 0
            for path in out_dir.rglob("record.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    # -----------------------------------------------------------------
    # YAML + JSON dual emission per record.
    # -----------------------------------------------------------------
    def test_emit_writes_both_yaml_and_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-dual-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=5, trees_cache=TREES_FIXTURE)
            yamls = list(out_dir.rglob("record.yaml"))
            jsons = list(out_dir.rglob("record.json"))
            self.assertEqual(len(yamls), 5)
            self.assertEqual(len(jsons), 5)
            sample = json.loads(jsons[0].read_text(encoding="utf-8"))
            self.assertEqual(
                sample["schema_version"], "auditooor.hackerman_record.v1.1"
            )
            self.assertEqual(sample["attack_class"], "audit-firm-public-report")
            self.assertEqual(
                sample["verification_tier"], "tier-2-verified-public-archive"
            )
            self.assertTrue(sample["record_source_url"].startswith("https://raw.githubusercontent.com/"))

    # -----------------------------------------------------------------
    # Honest-zero: empty trees cache emits zero records (no fabrication).
    # -----------------------------------------------------------------
    def test_empty_trees_cache_emits_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-empty-") as tmp:
            empty = Path(tmp) / "empty.json"
            empty.write_text(json.dumps({}))
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                trees_cache=empty,
            )
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["records_attempted"], 0)
        self.assertEqual(summary["errors"], [])

    # -----------------------------------------------------------------
    # Multi-repo source attribution: at least 5 firm slugs surface.
    # -----------------------------------------------------------------
    def test_multiple_repos_contribute_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-src-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                trees_cache=TREES_FIXTURE,
            )
        for required in (
            "trailofbits-publications",
            "zellic-publications",
            "spearbit-portfolio",
            "chainsecurity-audits",
            "cyfrin-audit-reports",
            "sb-security-audits",
        ):
            self.assertGreaterEqual(
                summary["by_repo"].get(required, 0),
                1,
                f"missing repo attribution: {required} in {summary['by_repo']}",
            )

    # -----------------------------------------------------------------
    # Real-source hard rule: every record_id is prefixed with
    # ``audit-firm:`` AND every record cites a
    # raw.githubusercontent.com URL in record_source_url.
    # -----------------------------------------------------------------
    def test_every_record_cites_raw_github_url(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-urls-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            saw = 0
            for jp in out_dir.rglob("record.json"):
                doc = json.loads(jp.read_text(encoding="utf-8"))
                self.assertTrue(
                    doc["record_id"].startswith("audit-firm:"),
                    f"unexpected record_id: {doc['record_id']}",
                )
                # Confirm the canonical raw GitHub URL was hoisted into
                # the v1.1 source-url field.
                self.assertIn(
                    "raw.githubusercontent.com",
                    doc.get("record_source_url", ""),
                )
                saw += 1
            self.assertGreater(saw, 0)

    # -----------------------------------------------------------------
    # README + LICENSE files are filtered out, not emitted.
    # -----------------------------------------------------------------
    def test_readme_and_license_are_filtered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-filt-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            for jp in out_dir.rglob("record.json"):
                doc = json.loads(jp.read_text(encoding="utf-8"))
                ref = doc["source_audit_ref"].lower()
                self.assertNotIn("readme.md", ref)
                self.assertNotIn("license", ref)

    # -----------------------------------------------------------------
    # PNG / image files in the source tree are not emitted (only
    # PDF + markdown are accepted).
    # -----------------------------------------------------------------
    def test_non_pdf_md_files_filtered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-ext-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            for jp in out_dir.rglob("record.json"):
                doc = json.loads(jp.read_text(encoding="utf-8"))
                ref = doc["source_audit_ref"]
                self.assertTrue(
                    ref.lower().endswith(".pdf") or ref.lower().endswith(".md"),
                    f"unexpected extension in {ref}",
                )

    # -----------------------------------------------------------------
    # Trailofbits records with non-``reviews/`` prefix paths are dropped.
    # The fixture includes ``presentations/devcon-talk.pdf`` which must
    # NOT appear in the emit.
    # -----------------------------------------------------------------
    def test_trailofbits_prefix_filter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-prefix-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            for jp in out_dir.rglob("record.json"):
                doc = json.loads(jp.read_text(encoding="utf-8"))
                ref = doc["source_audit_ref"]
                if "trailofbits-publications" in ref:
                    self.assertIn("reviews/", ref, f"prefix leak: {ref}")
                    self.assertNotIn("presentations/", ref)

    # -----------------------------------------------------------------
    # Pashov dedup: md + pdf duplicates collapse on stem, preferring
    # the pdf variant. Fixture has 4 distinct stems and the emitted
    # count for pashov-audits must equal 4 (not 7).
    # -----------------------------------------------------------------
    def test_pashov_md_pdf_dedup_keeps_pdf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-pashov-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            self.assertEqual(summary["by_repo"].get("pashov-audits", 0), 4)
            # Verify that for each emitted pashov record, the pdf variant
            # was chosen when both md+pdf existed in the source tree.
            pashov_refs = []
            for jp in out_dir.rglob("record.json"):
                doc = json.loads(jp.read_text(encoding="utf-8"))
                if "pashov-audits" in doc["source_audit_ref"]:
                    pashov_refs.append(doc["source_audit_ref"])
            # Two of the four pashov fixture stems have BOTH md+pdf, so
            # at least those two must be emitted as .pdf.
            pdfs = [r for r in pashov_refs if r.lower().endswith(".pdf")]
            self.assertGreaterEqual(len(pdfs), 2)

    # -----------------------------------------------------------------
    # Refresh safety: live source-list refreshes must not erase local
    # classifier enrichments written by sibling backfill tools.
    # -----------------------------------------------------------------
    def test_refresh_preserves_existing_local_attack_class_backfill(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-preserve-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            target = next(out_dir.rglob("record.yaml"))

            doc = self.tool.yaml.safe_load(target.read_text(encoding="utf-8"))
            doc["attack_class"] = "bridge-proof-domain-bypass"
            doc["record_extensions"] = {
                "heuristic_attack_class_backfill": {
                    "tool": "hackerman-backfill-audit-firm-report-class.py",
                    "old_attack_class": "audit-firm-public-report",
                    "new_attack_class": "bridge-proof-domain-bypass",
                    "confidence": 0.92,
                    "match_type": "exact",
                    "matched_terms": ["bridge"],
                    "classification_scope": "report-title-and-metadata-only",
                }
            }
            doc["record_source_url"] = doc["record_source_url"].replace("%20", " ")
            target.write_text(self.tool.yaml_dump(doc), encoding="utf-8")

            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)

            refreshed = self.tool.yaml.safe_load(target.read_text(encoding="utf-8"))
            self.assertEqual(
                refreshed["attack_class"], "bridge-proof-domain-bypass"
            )
            self.assertIn("record_extensions", refreshed)
            self.assertIn(
                "heuristic_attack_class_backfill",
                refreshed["record_extensions"],
            )

    def test_raw_github_urls_are_percent_encoded(self) -> None:
        url = self.tool._raw_url(
            "SB-Security/audits",
            "master",
            "reports/Fairplay - Security Review.pdf",
        )
        self.assertNotIn(" ", url)
        self.assertIn("Fairplay%20-%20Security%20Review.pdf", url)

    def test_refresh_skips_semantically_identical_existing_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-no-churn-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)
            target = next(out_dir.rglob("record.yaml"))

            doc = self.tool.yaml.safe_load(target.read_text(encoding="utf-8"))
            target.write_text(
                self.tool.yaml.safe_dump(
                    doc,
                    sort_keys=False,
                    default_flow_style=False,
                    allow_unicode=True,
                    width=72,
                ),
                encoding="utf-8",
            )
            before = target.read_text(encoding="utf-8")

            self.tool.convert(out_dir, trees_cache=TREES_FIXTURE)

            self.assertEqual(target.read_text(encoding="utf-8"), before)

    # -----------------------------------------------------------------
    # Date inference: explicit YYYY-MM-DD prefixes recover full date.
    # -----------------------------------------------------------------
    def test_infer_date_full_iso(self) -> None:
        date, year = self.tool.infer_date(
            "reports/2023-03-07-linkpool_liquid_sd_index_pool.pdf"
        )
        self.assertEqual(date, "2023-03-07")
        self.assertEqual(year, 2023)

    def test_infer_date_year_only(self) -> None:
        date, year = self.tool.infer_date("reviews/0x-protocol.pdf")
        self.assertIsNone(date)
        self.assertIsNone(year)

    def test_infer_date_month_name(self) -> None:
        date, year = self.tool.infer_date(
            "pdfs/Aragon-Spearbit-Security-Review-July-2025.pdf"
        )
        self.assertEqual(year, 2025)
        self.assertTrue(date is not None and date.startswith("2025"))

    # -----------------------------------------------------------------
    # Helper: ``infer_project`` strips firm names + date noise.
    # -----------------------------------------------------------------
    def test_infer_project_strips_firm_and_date(self) -> None:
        self.assertEqual(
            self.tool.infer_project("pdfs/ArtGobblers-Spearbit-Security-Review.pdf"),
            "ArtGobblers",
        )
        # Trailofbits date-prefixed names: 2021-04-balancer-balancerv2-securityreview.pdf
        proj = self.tool.infer_project(
            "reviews/2021-04-balancer-balancerv2-securityreview.pdf"
        )
        self.assertIn("balancer", proj.lower())

    # -----------------------------------------------------------------
    # CLI smoke: --json-summary returns parseable JSON.
    # -----------------------------------------------------------------
    def test_cli_json_summary(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory(prefix="audit-firm-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--out-dir",
                    str(out_dir),
                    "--trees-cache",
                    str(TREES_FIXTURE),
                    "--dry-run",
                    "--json-summary",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["errors"], [])
            self.assertGreaterEqual(payload["records_emitted"], 20)

    # -----------------------------------------------------------------
    # Year aggregation surfaces in the summary by_year map.
    # -----------------------------------------------------------------
    def test_summary_has_by_year_aggregation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-firm-year-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                trees_cache=TREES_FIXTURE,
            )
        # The fixture spans 2020 (year-unknown default) through 2025.
        self.assertIn("2023", summary["by_year"])
        self.assertIn("2024", summary["by_year"])
        # All by_year counts sum to records_emitted.
        self.assertEqual(
            sum(summary["by_year"].values()), summary["records_emitted"]
        )


if __name__ == "__main__":
    unittest.main()
