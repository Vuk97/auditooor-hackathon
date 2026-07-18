"""Tests for tools/hackerman-retag-vyper-cve-2022-37937.py."""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-retag-vyper-cve-2022-37937.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "vyper_cve_retag"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RetagVyperCve20223793Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_retag_vyper_cve_2022_37937")
        # Build a tmp dir with one affected + one not-affected fixture.
        self.tmpdir = Path(tempfile.mkdtemp(prefix="vyper-retag-test-"))
        self.affected = self.tmpdir / (
            "vyper-cve-cve-2022-37937-curve-y-pool-virtual_price-feed-vyper-0.3.4"
            "-pre-fix-ac6ba39692e3-ac6ba39692e3.yaml"
        )
        self.other = self.tmpdir / (
            "vyper-cve-cve-2023-30547-vyper-bridge-raw_call-relay"
            "-post-fix-migrated-histor-6206aa818ca5-6206aa818ca5.yaml"
        )
        shutil.copy(FIXTURE_DIR / "sample_cve_2022_37937_record.yaml", self.affected)
        shutil.copy(FIXTURE_DIR / "sample_other_cve_record.yaml", self.other)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_constants_pin_fabricated_and_suggested_ids(self) -> None:
        self.assertEqual(self.tool.FABRICATED_CVE_ID, "CVE-2022-37937")
        self.assertEqual(self.tool.SUGGESTED_CVE_ID, "CVE-2023-39363")
        self.assertEqual(self.tool.SUGGESTED_GHSA, "GHSA-5824-cm3x-3c38")
        self.assertEqual(
            self.tool.ATTRIBUTION_VERDICT,
            "UNVERIFIED-ATTRIBUTION-REQUIRES-MANUAL-REVIEW",
        )

    def test_find_affected_yamls_matches_only_2022_37937(self) -> None:
        affected = self.tool.find_affected_yamls(self.tmpdir)
        self.assertEqual([p.name for p in affected], [self.affected.name])

    def test_find_affected_yamls_missing_dir_returns_empty(self) -> None:
        affected = self.tool.find_affected_yamls(self.tmpdir / "nope")
        self.assertEqual(affected, [])

    def test_build_candidate_has_required_fields(self) -> None:
        cand = self.tool.build_candidate(self.affected, "2026-05-15T00:00:00Z")
        self.assertEqual(cand["schema_version"], "auditooor.retag_candidate.v1")
        self.assertEqual(cand["cve_id_original"], "CVE-2022-37937")
        self.assertEqual(cand["cve_id_suggested"], "CVE-2023-39363")
        self.assertEqual(cand["ghsa_suggested"], "GHSA-5824-cm3x-3c38")
        self.assertEqual(
            cand["attribution_verdict"],
            "UNVERIFIED-ATTRIBUTION-REQUIRES-MANUAL-REVIEW",
        )
        self.assertEqual(len(cand["source_yaml_sha256"]), 64)
        self.assertTrue(cand["record_id"].startswith("vyper-cve:cve-2022-37937"))
        self.assertIn(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-37937",
            cand["verification_source_urls"],
        )

    def test_emit_candidates_writes_one_jsonl_line_per_match(self) -> None:
        out = self.tmpdir / "out.jsonl"
        count = self.tool.emit_candidates([self.affected], out)
        self.assertEqual(count, 1)
        lines = out.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["cve_id_original"], "CVE-2022-37937")
        self.assertEqual(row["cve_id_suggested"], "CVE-2023-39363")

    def test_main_dry_run_lists_affected_and_exit_zero(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.tool.main([
                "--vyper-cve-dir", str(self.tmpdir),
                "--out", str(self.tmpdir / "should-not-be-written.jsonl"),
                "--dry-run",
            ])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn(self.affected.name, out)
        self.assertNotIn(self.other.name, out)
        self.assertFalse((self.tmpdir / "should-not-be-written.jsonl").exists())

    def test_main_writes_jsonl_when_not_dry(self) -> None:
        out = self.tmpdir / "real.jsonl"
        rc = self.tool.main([
            "--vyper-cve-dir", str(self.tmpdir),
            "--out", str(out),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id_original"], "CVE-2022-37937")

    def test_main_missing_dir_returns_1(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            rc = self.tool.main([
                "--vyper-cve-dir", str(self.tmpdir / "does-not-exist"),
            ])
        self.assertEqual(rc, 1)
        self.assertIn("directory not found", err.getvalue())

    def test_main_empty_dir_returns_2(self) -> None:
        empty = self.tmpdir / "empty"
        empty.mkdir()
        err = io.StringIO()
        with redirect_stderr(err):
            rc = self.tool.main([
                "--vyper-cve-dir", str(empty),
            ])
        self.assertEqual(rc, 2)
        self.assertIn("sanity check failed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
