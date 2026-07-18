"""Tests for tools/starknet-cairo-real-pdfs-ingest.py.

The driver downloads real StarkNet/Cairo audit PDFs via ``gh api``, runs
``pdftotext`` against them, invokes Wave 3c's miner
(``tools/hackerman-etl-from-starknet-cairo.py``) on the extracted text,
and rewrites ``source_audit_ref`` on every emitted YAML to cite the
canonical public URL.

Tests cover:

  * Real-source contract: BLOCKED-NO-REAL-SOURCE (rc=3) when fetch
    impossible (no gh CLI or empty cache without --fetch).
  * The catalog enumerates known-public audit PDFs with valid repo+path
    coordinates.
  * canonical_url / html_blob_url render the expected raw + html URLs.
  * source_audit_ref rewrite preserves the L<line>:S<segment> anchor.
  * The driver's CLI surface is stable (``--catalog-only`` JSON shape).

Network-touching tests use a sentinel YAML written by hand to exercise
the rewrite path without invoking ``gh`` or ``pdftotext``.
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
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "starknet-cairo-real-pdfs-ingest.py"
WAVE3C_MINER = REPO_ROOT / "tools" / "hackerman-etl-from-starknet-cairo.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class StarknetCairoRealPdfsIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_starknet_cairo_real_pdfs_ingest")

    # ------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------

    def test_catalog_is_non_empty_and_well_formed(self) -> None:
        catalog = self.tool.CATALOG
        self.assertGreaterEqual(len(catalog), 20)
        for entry in catalog:
            self.assertIn("repo", entry)
            self.assertIn("path", entry)
            self.assertIsInstance(entry["repo"], str)
            self.assertIsInstance(entry["path"], str)
            # repo follows owner/name shape.
            self.assertEqual(entry["repo"].count("/"), 1, entry)
            # path must look like a PDF.
            self.assertTrue(entry["path"].lower().endswith(".pdf"), entry)

    def test_catalog_repos_are_known_starknet_cairo_auditors(self) -> None:
        repos = {entry["repo"] for entry in self.tool.CATALOG}
        # The catalog must include at least one entry from each of the
        # three primary auditor / project sources that ship StarkNet
        # / Cairo audits as public PDFs.
        self.assertIn("OpenZeppelin/cairo-contracts", repos)
        self.assertIn("NethermindEth/PublicAuditReports", repos)
        # Trail of Bits + Zellic + Argent are the other anchors.
        self.assertIn("trailofbits/publications", repos)
        self.assertIn("Zellic/publications", repos)
        self.assertIn("argentlabs/argent-contracts-starknet", repos)

    def test_catalog_only_flag_emits_json(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.tool.main([
                "--cache-dir",
                "/tmp/snr-catalog-only",
                "--catalog-only",
            ])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertGreaterEqual(payload["count"], 20)
        self.assertEqual(payload["count"], len(payload["entries"]))

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def test_canonical_url_uses_raw_githubusercontent(self) -> None:
        url = self.tool.canonical_url(
            "OpenZeppelin/cairo-contracts",
            "audits/2025-01-v1.0.0.pdf",
        )
        self.assertEqual(
            url,
            "https://raw.githubusercontent.com/OpenZeppelin/cairo-contracts/main/audits/2025-01-v1.0.0.pdf",
        )

    def test_canonical_url_url_encodes_spaces(self) -> None:
        url = self.tool.canonical_url(
            "Zellic/publications",
            "Hyperlane Starknet - Zellic Audit Report.pdf",
            branch="master",
        )
        self.assertIn("%20", url)
        self.assertIn("/master/", url)

    def test_html_blob_url_renders_blob_path(self) -> None:
        url = self.tool.html_blob_url(
            "NethermindEth/PublicAuditReports",
            "NM0058-FINAL_ZKLEND.pdf",
        )
        self.assertEqual(
            url,
            "https://github.com/NethermindEth/PublicAuditReports/blob/main/NM0058-FINAL_ZKLEND.pdf",
        )

    # ------------------------------------------------------------------
    # source_audit_ref rewrite
    # ------------------------------------------------------------------

    def test_rewrite_source_audit_ref_replaces_with_canonical_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "rec.yaml"
            yaml_path.write_text(
                "schema_version: auditooor.hackerman_record.v1\n"
                'record_id: "starknet-cairo-corpus:foo.txt:L42:S3:deadbeef00"\n'
                'source_audit_ref: "starknet-cairo-corpus:foo.txt:L42:S3"\n'
                "target_domain: vault\n",
                encoding="utf-8",
            )
            canonical = "https://raw.githubusercontent.com/foo/bar/main/audits/baz.pdf"
            ok = self.tool.rewrite_source_audit_ref(yaml_path, canonical)
            self.assertTrue(ok)
            new_text = yaml_path.read_text(encoding="utf-8")
            self.assertIn(
                f'source_audit_ref: "{canonical}#L42:S3"',
                new_text,
            )
            # Other fields untouched.
            self.assertIn("schema_version: auditooor.hackerman_record.v1", new_text)
            self.assertIn("target_domain: vault", new_text)

    def test_rewrite_source_audit_ref_preserves_segment_locator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "rec.yaml"
            yaml_path.write_text(
                'source_audit_ref: "starknet-cairo-corpus:x.txt:L7:S99"\n',
                encoding="utf-8",
            )
            self.tool.rewrite_source_audit_ref(yaml_path, "https://example/x.pdf")
            self.assertIn("#L7:S99", yaml_path.read_text(encoding="utf-8"))

    def test_rewrite_source_audit_ref_handles_missing_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "rec.yaml"
            yaml_path.write_text("schema_version: auditooor.hackerman_record.v1\n", encoding="utf-8")
            ok = self.tool.rewrite_source_audit_ref(yaml_path, "https://x")
            self.assertFalse(ok)

    # ------------------------------------------------------------------
    # Real-source contract
    # ------------------------------------------------------------------

    def test_blocked_when_cache_empty_and_no_fetch(self) -> None:
        # Skip on hosts without pdftotext (test surface deliberately
        # short-circuits on that pre-flight, so we exercise the
        # downstream "no records" branch only when pdftotext is
        # actually available).
        if not self.tool.pdftotext_available():
            self.skipTest("pdftotext missing; pre-flight branch covers this case")
        with tempfile.TemporaryDirectory() as tmp:
            ghost_cache = Path(tmp) / "no-such-cache"
            ghost_cache.mkdir()
            out_dir = Path(tmp) / "out"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = self.tool.main([
                    "--cache-dir",
                    str(ghost_cache),
                    "--out-dir",
                    str(out_dir),
                ])
            self.assertEqual(rc, 3)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_slugify_path_drops_path_separators(self) -> None:
        slug = self.tool.slugify_path(
            "NethermindEth/PublicAuditReports",
            "NM0057 - FINAL_SITHSWAP.pdf",
        )
        self.assertNotIn("/", slug)
        self.assertNotIn(" ", slug)
        self.assertTrue(slug.lower().endswith(".pdf") or slug.lower().endswith("sithswap.pdf") or slug.endswith("SITHSWAP.pdf"))

    def test_parse_segment_locator_extracts_suffix(self) -> None:
        suffix, _ = self.tool.parse_segment_locator(
            '"starknet-cairo-corpus:foo.txt:L42:S3"'
        )
        self.assertEqual(suffix, "L42:S3")

    def test_parse_segment_locator_handles_no_locator(self) -> None:
        suffix, _ = self.tool.parse_segment_locator(
            '"starknet-cairo-corpus:foo.txt"'
        )
        self.assertEqual(suffix, "")


if __name__ == "__main__":
    unittest.main()
