from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-immunefi-public.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_from_immunefi_public" / "raw"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromImmunefiPublicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_immunefi_public")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_immunefi_public_test")

    # ------------------------------------------------------------------
    # Real-source contract: BLOCKED-NO-REAL-SOURCE when cache empty.
    # ------------------------------------------------------------------
    def test_blocked_when_cache_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-blocked-") as tmp:
            ghost = Path(tmp) / "no-such-dir"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main(
                    [
                        "--cache-dir",
                        str(ghost),
                        "--out-dir",
                        str(Path(tmp) / "out"),
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc, 3)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_blocked_when_cache_has_no_markdown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-empty-") as tmp:
            cache = Path(tmp) / "cache"
            cache.mkdir()
            (cache / "stray.txt").write_text("ignore", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main(
                    [
                        "--cache-dir",
                        str(cache),
                        "--out-dir",
                        str(Path(tmp) / "out"),
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc, 3)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    # ------------------------------------------------------------------
    # Fixture-driven happy path.
    # ------------------------------------------------------------------
    def test_fixture_dir_exists_with_real_disclosures(self) -> None:
        self.assertTrue(FIXTURE_DIR.is_dir(), f"fixture dir missing: {FIXTURE_DIR}")
        md_files = list(FIXTURE_DIR.rglob("*.md"))
        self.assertGreaterEqual(len(md_files), 3, "expected >=3 real fixture disclosures")

    def test_fixture_dry_run_emits_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-dry-") as tmp:
            summary = self.tool.convert(FIXTURE_DIR, Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["validation_errors"], [])
        self.assertEqual(summary["parse_errors"], [])
        self.assertGreaterEqual(summary["records_emitted"], 3)
        self.assertEqual(summary["records_emitted"], summary["records_attempted"])
        self.assertEqual(summary["records_emitted"], summary["file_count"])

    def test_severity_distribution_real(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-sev-") as tmp:
            summary = self.tool.convert(FIXTURE_DIR, Path(tmp) / "out", dry_run=True)
        # The 3 known fixtures: 1 Critical, 1 High, 1 Medium.
        self.assertIn("critical", summary["by_severity"])
        self.assertIn("high", summary["by_severity"])
        self.assertIn("medium", summary["by_severity"])

    def test_target_language_inference_picks_rust_for_firedancer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-lang-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(FIXTURE_DIR, out_dir)
            firedancer = [p for p in out_dir.glob("*.yaml") if "firedancer" in p.read_text(encoding="utf-8").lower()]
            self.assertGreaterEqual(len(firedancer), 1)
            body = firedancer[0].read_text(encoding="utf-8")
            self.assertIn("target_language: rust", body)

    def test_solidity_language_for_alchemix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-sol-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(FIXTURE_DIR, out_dir)
            alchemix = [
                p
                for p in out_dir.glob("*.yaml")
                if "alchemix" in p.read_text(encoding="utf-8").lower()
            ]
            self.assertGreaterEqual(len(alchemix), 1)
            for p in alchemix:
                body = p.read_text(encoding="utf-8")
                self.assertIn("target_language: solidity", body)

    # ------------------------------------------------------------------
    # Schema validation
    # ------------------------------------------------------------------
    def test_all_emitted_records_validate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(FIXTURE_DIR, out_dir)
            self.assertEqual(summary["validation_errors"], [])
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])
            self.assertGreater(seen, 0)

    def test_record_ids_are_unique(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-id-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(FIXTURE_DIR, out_dir)
            ids: list[str] = []
            for path in out_dir.glob("*.yaml"):
                body = path.read_text(encoding="utf-8")
                for line in body.splitlines():
                    if line.startswith("record_id:"):
                        ids.append(line.split(":", 1)[1].strip())
                        break
            self.assertEqual(len(ids), len(set(ids)), "record_id collisions")

    def test_record_has_required_immunefi_signals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-sig-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(FIXTURE_DIR, out_dir)
            sample = next(out_dir.glob("*.yaml"))
            body = sample.read_text(encoding="utf-8")
            self.assertIn("schema_version: auditooor.hackerman_record.v1", body)
            self.assertIn("record_tier: public-corpus", body)
            self.assertIn("source_extraction_method: corpus-etl", body)
            self.assertIn("mitigation-state-post-fix-released", body)
            self.assertIn(
                "https://github.com/immunefi-team/Past-Audit-Competitions",
                body,
                "source_audit_ref must cite the public Immunefi disclosure URL",
            )

    def test_severity_filter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-filter-") as tmp:
            summary = self.tool.convert(
                FIXTURE_DIR, Path(tmp) / "out", dry_run=True, severity_filter="critical"
            )
            self.assertGreaterEqual(summary["records_emitted"], 1)
            self.assertEqual(set(summary["by_severity"]), {"critical"})

    # ------------------------------------------------------------------
    # Header parsing unit checks
    # ------------------------------------------------------------------
    def test_parser_rejects_readme(self) -> None:
        result = self.tool.parse_disclosure_markdown(
            "# README\n\nWelcome to the audit competitions page.\n"
        )
        self.assertIsNone(result)

    def test_parser_parses_real_fixture(self) -> None:
        # Pick the Critical fixture by exact severity-tag substring (glob
        # character-class semantics would otherwise consume the brackets).
        candidates = [
            p
            for p in FIXTURE_DIR.rglob("*.md")
            if "[SC - Critical]" in p.name
        ]
        self.assertGreaterEqual(len(candidates), 1, "no Critical fixture found")
        fixture = candidates[0]
        text = fixture.read_text(encoding="utf-8")
        fields = self.tool.parse_disclosure_markdown(text)
        self.assertIsNotNone(fields)
        self.assertEqual(fields["severity"].lower(), "critical")
        self.assertTrue(fields["report_id"].isdigit())
        self.assertIn("github.com", fields.get("target", ""))
        self.assertGreater(len(fields["impacts"]), 0)

    # ------------------------------------------------------------------
    # CLI surface
    # ------------------------------------------------------------------
    def test_cli_dry_run_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="im-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--cache-dir",
                        str(FIXTURE_DIR),
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted":', stdout.getvalue())
            self.assertFalse(out_dir.exists())

    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(
            [
                "--cache-dir",
                str(FIXTURE_DIR),
                "--out-dir",
                "/tmp/should-not-be-created-immunefi-public",
                "--limit",
                "-1",
            ]
        )
        self.assertEqual(rc, 2)

    # ------------------------------------------------------------------
    # YAML rendering parity with sibling tools
    # ------------------------------------------------------------------
    def test_yaml_scalar_emits_floats_and_bools(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(0.85), "0.85")
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")

    # ------------------------------------------------------------------
    # Honest-impact-dollar-class contract.
    # ------------------------------------------------------------------
    def test_dollar_class_band_matches_severity_table(self) -> None:
        table = self.tool.SEVERITY_TO_DOLLAR_CLASS
        self.assertEqual(table["critical"], ">=$1M")
        self.assertEqual(table["high"], "$100K-$1M")
        self.assertEqual(table["medium"], "$10K-$100K")
        self.assertEqual(table["low"], "<$10K")
        self.assertEqual(table["insight"], "non-financial")


if __name__ == "__main__":
    unittest.main()
