"""Tests for ``tools/hackerman-audit-firm-pdf-preview-extractor.py``.

Builds a small synthetic ``audit_firm_public_reports`` corpus on disk
under a tmp dir and exercises the YAML loader, field extractors,
walker, aggregators, and markdown renderer.

Coverage (>=8 cases):

  1.  ``_yaml_load`` parses the restricted schema (scalars + block list).
  2.  ``_extract_firm`` peels the firm prefix from a slug.
  3.  ``_extract_pdf_url`` finds the "Reference public audit report at" line.
  4.  ``_extract_inferred_project`` falls back when the precondition is missing.
  5.  ``_extract_date`` handles full-date / year-month / year-only / year-field-only.
  6.  ``extract_preview`` walks the tree and returns one record per slug.
  7.  ``extract_preview`` prefers ``record.yaml`` when both present.
  8.  ``firm_counts`` aggregates firms in desc order.
  9.  ``cross_firm_projects`` surfaces projects audited by >=2 firms.
  10. ``year_distribution`` buckets years incl. ``unknown``.
  11. ``render_markdown`` includes all required sections.
  12. CLI ``main`` dry-run path: no files written, exit 0.
  13. CLI ``main`` write path: produces JSONL + markdown.
  14. ``_normalize_project_for_coverage`` drops single-digit / short / empty.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-audit-firm-pdf-preview-extractor.py"


def _load_tool() -> Any:
    name = "_hackerman_audit_firm_pdf_preview_extractor_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _yaml_for(
    record_id: str,
    pdf_url: str,
    source_path: str,
    inferred_project: str,
    year: int,
) -> str:
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        "attack_class: audit-firm-public-report\n"
        f"year: {year}\n"
        "required_preconditions:\n"
        f"  - Reference public audit report at {pdf_url}\n"
        f"  - Source repo SomeOrg/some-audits\n"
        f"  - Source path {source_path}\n"
        "  - verification_tier=tier-2-verified-public-archive\n"
        f"  - Inferred project name {inferred_project}\n"
    )


def _write_record(
    root: Path,
    slug: str,
    *,
    pdf_url: str,
    source_path: str,
    inferred_project: str,
    year: int,
    fmt: str = "yaml",
    also_json: bool = False,
) -> Path:
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    yaml_text = _yaml_for(
        f"audit-firm:{slug}", pdf_url, source_path, inferred_project, year
    )
    if fmt == "yaml":
        (d / "record.yaml").write_text(yaml_text, encoding="utf-8")
    if fmt == "json" or also_json:
        rec = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": f"audit-firm:{slug}",
            "attack_class": "audit-firm-public-report",
            "year": year,
            "required_preconditions": [
                f"Reference public audit report at {pdf_url}",
                "Source repo SomeOrg/some-audits",
                f"Source path {source_path}",
                "verification_tier=tier-2-verified-public-archive",
                f"Inferred project name {inferred_project}",
            ],
        }
        (d / "record.json").write_text(json.dumps(rec), encoding="utf-8")
    return d


class YamlLoaderTests(unittest.TestCase):
    def test_yaml_load_scalars_and_block_list(self) -> None:
        text = (
            "schema_version: v1\n"
            "year: 2023\n"
            "is_test: true\n"
            "required_preconditions:\n"
            "  - alpha\n"
            "  - beta\n"
            "  - gamma\n"
        )
        out = tool._yaml_load(text)
        self.assertEqual(out["schema_version"], "v1")
        self.assertEqual(out["year"], 2023)
        self.assertIs(out["is_test"], True)
        self.assertEqual(out["required_preconditions"], ["alpha", "beta", "gamma"])


class FieldExtractorTests(unittest.TestCase):
    def test_extract_firm(self) -> None:
        self.assertEqual(
            tool._extract_firm("chainsecurity-audits__chainsecurity_blockimmo-xyz"),
            "chainsecurity-audits",
        )
        # no '__' -> slug is firm
        self.assertEqual(tool._extract_firm("standalone"), "standalone")

    def test_extract_pdf_url_from_preconds(self) -> None:
        preconds = [
            "Source repo Foo/bar",
            "Reference public audit report at https://raw.githubusercontent.com/Foo/bar/main/x.pdf",
            "Source path x.pdf",
        ]
        self.assertEqual(
            tool._extract_pdf_url(preconds),
            "https://raw.githubusercontent.com/Foo/bar/main/x.pdf",
        )
        self.assertIsNone(tool._extract_pdf_url(["unrelated"]))

    def test_extract_inferred_project_fallback(self) -> None:
        preconds = ["Source path reports/2023-03-07-thing.pdf"]
        self.assertIsNone(tool._extract_inferred_project(preconds))
        proj = tool._project_from_filename("reports/2023-03-07-thing.pdf")
        self.assertEqual(proj, "thing")

    def test_extract_date_all_branches(self) -> None:
        self.assertEqual(
            tool._extract_date("2023-03-07-linkpool", None), ("2023-03-07", 2023)
        )
        self.assertEqual(
            tool._extract_date("2022-10-Checkpoints", None), ("2022-10", 2022)
        )
        self.assertEqual(
            tool._extract_date("2017", None), ("2017", 2017)
        )
        self.assertEqual(
            tool._extract_date("ChainSecurity_Blockimmo", 2020), ("2020", 2020)
        )
        self.assertEqual(
            tool._extract_date("ChainSecurity_Blockimmo", None), ("unknown", None)
        )

    def test_normalize_project_for_coverage_drops_noise(self) -> None:
        self.assertEqual(tool._normalize_project_for_coverage("Aave V3"), "aave v3")
        self.assertIsNone(tool._normalize_project_for_coverage("10"))
        self.assertIsNone(tool._normalize_project_for_coverage("ab"))
        self.assertIsNone(tool._normalize_project_for_coverage(""))
        self.assertIsNone(tool._normalize_project_for_coverage(None))
        self.assertIsNone(tool._normalize_project_for_coverage("unknown"))


class ExtractPreviewTests(unittest.TestCase):
    def _build_corpus(self, root: Path) -> None:
        _write_record(
            root,
            "chainsecurity-audits__chainsecurity_aave_v3-abc",
            pdf_url="https://raw.githubusercontent.com/ChainSecurity/audits/master/ChainSecurity_Aave_v3.pdf",
            source_path="ChainSecurity_Aave_v3.pdf",
            inferred_project="Aave v3",
            year=2022,
        )
        _write_record(
            root,
            "spearbit-portfolio__spearbit_aave_v3-def",
            pdf_url="https://raw.githubusercontent.com/spearbit/portfolio/main/aave_v3.pdf",
            source_path="aave_v3.pdf",
            inferred_project="Aave v3",
            year=2023,
        )
        _write_record(
            root,
            "cyfrin-audit-reports__2023-03-07-linkpool-zzz",
            pdf_url="https://raw.githubusercontent.com/Cyfrin/cyfrin-audit-reports/main/reports/2023-03-07-linkpool.pdf",
            source_path="reports/2023-03-07-linkpool.pdf",
            inferred_project="03 07 linkpool",
            year=2023,
        )
        _write_record(
            root,
            "openzeppelin-contracts-audits__2017-03-qqq",
            pdf_url="https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/audits/2017-03.md",
            source_path="audits/2017-03.md",
            inferred_project="03",
            year=2017,
        )

    def test_extract_preview_walks_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_corpus(root)
            records = tool.extract_preview(root)
            self.assertEqual(len(records), 4)
            slugs = sorted(r["slug"] for r in records)
            self.assertEqual(slugs[0], "chainsecurity-audits__chainsecurity_aave_v3-abc")
            for r in records:
                self.assertIn("firm", r)
                self.assertIn("project_name", r)
                self.assertIn("pdf_url", r)
                self.assertIn("date", r)
                self.assertIn("year", r)
                self.assertEqual(r["schema"], tool.SCHEMA)

    def test_extract_preview_prefers_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # write yaml with project X, json with project Y; yaml must win
            d = root / "firm-x__slug-1"
            d.mkdir()
            (d / "record.yaml").write_text(
                _yaml_for("rid", "https://x/y.pdf", "y.pdf", "PROJECT_YAML", 2021),
                encoding="utf-8",
            )
            (d / "record.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.hackerman_record.v1",
                        "record_id": "rid",
                        "year": 2021,
                        "required_preconditions": [
                            "Reference public audit report at https://x/y.pdf",
                            "Source path y.pdf",
                            "Inferred project name PROJECT_JSON",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            records = tool.extract_preview(root)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["project_name"], "PROJECT_YAML")

    def test_extract_preview_json_only_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_record(
                root,
                "firm-y__slug-only-json",
                pdf_url="https://x/only.pdf",
                source_path="only.pdf",
                inferred_project="Only Json",
                year=2024,
                fmt="json",
            )
            records = tool.extract_preview(root)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["project_name"], "Only Json")


class AggregationTests(unittest.TestCase):
    def _records(self) -> list:
        return [
            {
                "slug": "a__1", "firm": "chainsec", "project_name": "Aave v3",
                "project_name_normalized": "aave v3", "date": "2022", "year": 2022,
                "pdf_url": "https://x/1.pdf", "file_ext": "pdf",
                "source_path": "1.pdf", "record_path": "x/record.json",
                "schema": tool.SCHEMA,
            },
            {
                "slug": "b__1", "firm": "spearbit", "project_name": "Aave v3",
                "project_name_normalized": "aave v3", "date": "2023", "year": 2023,
                "pdf_url": "https://x/2.pdf", "file_ext": "pdf",
                "source_path": "2.pdf", "record_path": "x/record.json",
                "schema": tool.SCHEMA,
            },
            {
                "slug": "c__1", "firm": "spearbit", "project_name": "Compound",
                "project_name_normalized": "compound", "date": "unknown", "year": None,
                "pdf_url": "https://x/3.pdf", "file_ext": "pdf",
                "source_path": "3.pdf", "record_path": "x/record.json",
                "schema": tool.SCHEMA,
            },
        ]

    def test_firm_counts_desc(self) -> None:
        counts = tool.firm_counts(self._records())
        # spearbit=2, chainsec=1
        self.assertEqual(counts[0], ("spearbit", 2))
        self.assertEqual(counts[1], ("chainsec", 1))

    def test_cross_firm_projects(self) -> None:
        cross = tool.cross_firm_projects(self._records())
        self.assertEqual(len(cross), 1)
        proj, n_firms, firms = cross[0]
        self.assertEqual(proj, "aave v3")
        self.assertEqual(n_firms, 2)
        self.assertEqual(firms, ["chainsec", "spearbit"])

    def test_year_distribution_includes_unknown(self) -> None:
        dist = dict(tool.year_distribution(self._records()))
        self.assertEqual(dist.get(2022), 1)
        self.assertEqual(dist.get(2023), 1)
        self.assertEqual(dist.get("unknown"), 1)


class RenderAndCLITests(unittest.TestCase):
    def test_render_markdown_sections(self) -> None:
        records = [
            {
                "slug": "a__1", "firm": "chainsec", "project_name": "Aave v3",
                "project_name_normalized": "aave v3", "date": "2022", "year": 2022,
                "pdf_url": "https://x/1.pdf", "file_ext": "pdf",
                "source_path": "1.pdf", "record_path": "x/record.json",
                "schema": tool.SCHEMA,
            },
            {
                "slug": "b__1", "firm": "spearbit", "project_name": "Aave v3",
                "project_name_normalized": "aave v3", "date": "2023", "year": 2023,
                "pdf_url": "https://x/2.pdf", "file_ext": "pdf",
                "source_path": "2.pdf", "record_path": "x/record.json",
                "schema": tool.SCHEMA,
            },
        ]
        md = tool.render_markdown(
            records, top_firms=10, top_projects=10,
            generated_at_iso="2026-05-16T00:00:00Z",
            jsonl_relpath=".auditooor/audit_firm_pdf_preview.jsonl",
        )
        self.assertIn("# Hackerman Audit-Firm PDF Preview", md)
        self.assertIn("## Scan stats", md)
        self.assertIn("Top", md)
        self.assertIn("firms by record count", md)
        self.assertIn("projects by cross-firm coverage", md)
        self.assertIn("## Year distribution", md)
        self.assertIn("aave v3", md)

    def test_cli_dry_run_no_files_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tags"
            root.mkdir()
            _write_record(
                root, "firm-a__slug",
                pdf_url="https://x/a.pdf", source_path="a.pdf",
                inferred_project="Aproj", year=2020,
            )
            jsonl = Path(tmp) / "out.jsonl"
            docs = Path(tmp) / "out.md"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = tool.main(
                    [
                        "--tags-dir", str(root),
                        "--output-jsonl", str(jsonl),
                        "--docs-path", str(docs),
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(jsonl.exists())
            self.assertFalse(docs.exists())
            self.assertIn("[preview]", buf.getvalue())

    def test_cli_write_path_produces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tags"
            root.mkdir()
            _write_record(
                root, "firm-a__slug",
                pdf_url="https://x/a.pdf", source_path="a.pdf",
                inferred_project="Aproj", year=2020,
            )
            _write_record(
                root, "firm-b__slug",
                pdf_url="https://x/b.pdf", source_path="b.pdf",
                inferred_project="Aproj", year=2021,
            )
            jsonl = Path(tmp) / "preview.jsonl"
            docs = Path(tmp) / "preview.md"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = tool.main(
                    [
                        "--tags-dir", str(root),
                        "--output-jsonl", str(jsonl),
                        "--docs-path", str(docs),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(jsonl.exists())
            self.assertTrue(docs.exists())
            jsonl_lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(jsonl_lines), 2)
            for line in jsonl_lines:
                obj = json.loads(line)
                self.assertEqual(obj["schema"], tool.SCHEMA)
                self.assertIn("firm", obj)
            md_text = docs.read_text(encoding="utf-8")
            self.assertIn("Aproj".lower(), md_text.lower())

    def test_cli_missing_tags_dir_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = tool.main(
                    [
                        "--tags-dir", str(missing),
                        "--output-jsonl", str(Path(tmp) / "x.jsonl"),
                        "--docs-path", str(Path(tmp) / "x.md"),
                    ]
                )
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
