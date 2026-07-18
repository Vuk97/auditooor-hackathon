"""Tests for ``tools/hackerman-audit-firm-pdf-url-sanity.py``.

Builds a small synthetic ``audit_firm_public_reports`` corpus on disk
under a tmp dir, monkey-patches the HEAD probe, and exercises the
walker, URL extractor, verdict classifier, retry logic, aggregator,
markdown renderer, and CLI ``main``.

Coverage (>=8 cases):

  1.  ``extract_url`` finds the canonical ``Reference public audit
      report at`` precondition.
  2.  ``extract_url`` falls back to scraping ``fix_pattern``.
  3.  ``classify_response`` returns ``pass`` for HTTP 200 +
      ``application/pdf``.
  4.  ``classify_response`` returns ``pass`` for HTTP 200 +
      ``application/octet-stream`` ONLY when URL ends in ``.pdf``.
  5.  ``classify_response`` returns ``fail-wrong-mime`` for HTTP 200 +
      ``text/html``.
  6.  ``classify_response`` returns ``fail-status`` for 404.
  7.  ``classify_response`` returns ``rate-limited`` for 429.
  8.  ``classify_response`` returns ``timeout`` for socket timeout.
  9.  ``probe_url`` retries on 5xx and converges to pass on success.
  10. ``walk_records`` returns one record per slug, sorted.
  11. ``check_records`` with ``--skip-network`` emits ``skip-network``
      verdicts and never calls HEAD.
  12. ``check_records`` with monkey-patched probe walks all jobs.
  13. ``summarize`` aggregates verdict counts + per-firm pass.
  14. ``render_markdown`` includes every required section.
  15. CLI ``main`` write path emits JSONL + markdown.
  16. CLI ``main`` returns exit 1 when any failure verdict present.
"""
from __future__ import annotations

import importlib.util
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-audit-firm-pdf-url-sanity.py"


def _load_tool() -> Any:
    name = "_hackerman_audit_firm_pdf_url_sanity_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _build_record(
    *,
    pdf_url: str = "https://raw.githubusercontent.com/spearbit/portfolio/master/pdfs/Foo.pdf",
    include_reference: bool = True,
    fix_pattern_url: str = "",
) -> Dict[str, Any]:
    preconds: List[str] = []
    if include_reference:
        preconds.append(f"Reference public audit report at {pdf_url}")
    preconds.append("Source repo spearbit/portfolio")
    fix = "Apply the recommendations in the published audit report at " + (
        fix_pattern_url or pdf_url
    ) + "."
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "required_preconditions": preconds,
        "fix_pattern": fix,
        "attack_class": "audit-firm-public-report",
    }


def _write_corpus(root: Path, layout: List[Dict[str, Any]]) -> Path:
    tags_dir = root / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
    tags_dir.mkdir(parents=True, exist_ok=True)
    for entry in layout:
        slug: str = entry["slug"]
        record: Dict[str, Any] = entry["record"]
        emit = entry.get("emit", "json")  # "json" or "yaml" or "both"
        d = tags_dir / slug
        d.mkdir(parents=True, exist_ok=True)
        if emit in ("json", "both"):
            (d / "record.json").write_text(json.dumps(record), encoding="utf-8")
        if emit in ("yaml", "both"):
            # Minimal YAML mirroring the loader's supported shape.
            yaml_lines = []
            for k, v in record.items():
                if isinstance(v, list):
                    yaml_lines.append(f"{k}:")
                    for item in v:
                        yaml_lines.append(f"- {item}")
                else:
                    yaml_lines.append(f"{k}: {v}")
            (d / "record.yaml").write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")
    return tags_dir


# ---------------------------------------------------------------------------
# 1-2: extract_url
# ---------------------------------------------------------------------------
class TestExtractURL(unittest.TestCase):
    def test_reference_line_priority(self) -> None:
        rec = _build_record(pdf_url="https://example.com/foo.pdf")
        self.assertEqual(tool.extract_url(rec), "https://example.com/foo.pdf")

    def test_fallback_to_fix_pattern(self) -> None:
        rec = _build_record(include_reference=False)
        rec["fix_pattern"] = (
            "Apply the recommendations in the published audit report at "
            "https://raw.githubusercontent.com/x/y/main/r.pdf."
        )
        rec["required_preconditions"] = ["Source repo x/y"]
        self.assertEqual(
            tool.extract_url(rec),
            "https://raw.githubusercontent.com/x/y/main/r.pdf",
        )

    def test_no_url_returns_none(self) -> None:
        rec = {"required_preconditions": ["Source repo x/y"], "fix_pattern": "no link here"}
        self.assertIsNone(tool.extract_url(rec))


# ---------------------------------------------------------------------------
# 3-8: classify_response
# ---------------------------------------------------------------------------
class TestClassifyResponse(unittest.TestCase):
    def test_pass_pdf_mime(self) -> None:
        probe = {"status": 200, "content_type": "application/pdf"}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe), tool.VERDICT_PASS
        )

    def test_pass_octet_stream_pdf_url(self) -> None:
        probe = {"status": 200, "content_type": "application/octet-stream"}
        self.assertEqual(
            tool.classify_response("https://raw.githubusercontent.com/x/y/main/r.pdf", probe),
            tool.VERDICT_PASS,
        )

    def test_octet_stream_non_pdf_url_is_wrong_mime(self) -> None:
        probe = {"status": 200, "content_type": "application/octet-stream"}
        self.assertEqual(
            tool.classify_response("https://x/y.bin", probe), tool.VERDICT_FAIL_WRONG_MIME
        )

    def test_html_is_wrong_mime(self) -> None:
        probe = {"status": 200, "content_type": "text/html"}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe),
            tool.VERDICT_FAIL_WRONG_MIME,
        )

    def test_404_is_fail_status(self) -> None:
        probe = {"status": 404, "content_type": "text/html"}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe), tool.VERDICT_FAIL_STATUS
        )

    def test_429_is_rate_limited(self) -> None:
        probe = {"status": 429, "content_type": "text/html", "rate_limited": True}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe),
            tool.VERDICT_RATE_LIMITED,
        )

    def test_timeout_is_timeout(self) -> None:
        probe = {"status": None, "timed_out": True, "transport_error": "timeout"}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe), tool.VERDICT_TIMEOUT
        )

    def test_transport_error_is_error(self) -> None:
        probe = {"status": None, "transport_error": "DNS"}
        self.assertEqual(
            tool.classify_response("https://x/foo.pdf", probe), tool.VERDICT_ERROR
        )


# ---------------------------------------------------------------------------
# 9: probe_url retries
# ---------------------------------------------------------------------------
class TestProbeURLRetry(unittest.TestCase):
    def test_retry_on_5xx_then_pass(self) -> None:
        calls: List[int] = []

        def fake_head(url: str, **_: Any) -> Dict[str, Any]:
            calls.append(1)
            if len(calls) == 1:
                return {
                    "status": 503,
                    "content_type": "text/html",
                    "final_url": url,
                    "transport_error": None,
                    "rate_limited": False,
                    "timed_out": False,
                }
            return {
                "status": 200,
                "content_type": "application/pdf",
                "final_url": url,
                "transport_error": None,
                "rate_limited": False,
                "timed_out": False,
            }

        with mock.patch.object(tool, "head_request", fake_head):
            verdict, probe = tool.probe_url(
                "https://x/foo.pdf", timeout=1.0, retries=2, rate_limit_sleep=0.0
            )
        self.assertEqual(verdict, tool.VERDICT_PASS)
        self.assertEqual(len(calls), 2)
        self.assertEqual(probe["status"], 200)

    def test_no_retry_on_4xx(self) -> None:
        calls: List[int] = []

        def fake_head(url: str, **_: Any) -> Dict[str, Any]:
            calls.append(1)
            return {
                "status": 404,
                "content_type": "text/html",
                "final_url": url,
                "transport_error": None,
                "rate_limited": False,
                "timed_out": False,
            }

        with mock.patch.object(tool, "head_request", fake_head):
            verdict, _ = tool.probe_url(
                "https://x/foo.pdf", timeout=1.0, retries=3, rate_limit_sleep=0.0
            )
        self.assertEqual(verdict, tool.VERDICT_FAIL_STATUS)
        self.assertEqual(len(calls), 1)


# ---------------------------------------------------------------------------
# 10-12: walker + driver
# ---------------------------------------------------------------------------
class TestWalkAndDrive(unittest.TestCase):
    def test_walk_records_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _write_corpus(
                Path(td),
                [
                    {"slug": "zfirm__zproj-abc", "record": _build_record()},
                    {"slug": "afirm__aproj-xyz", "record": _build_record()},
                ],
            )
            rows = tool.walk_records(tags_dir)
            slugs = [r[0] for r in rows]
            self.assertEqual(slugs, ["afirm__aproj-xyz", "zfirm__zproj-abc"])

    def test_skip_network_emits_skip_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _write_corpus(
                Path(td),
                [
                    {"slug": "spearbit-portfolio__foo-aaa", "record": _build_record()},
                    {
                        "slug": "cyfrin-audit-reports__bar-bbb",
                        "record": {
                            "required_preconditions": ["Source repo x/y"],
                            "fix_pattern": "no url",
                        },
                    },
                ],
            )
            records = tool.walk_records(tags_dir)
            rows = tool.check_records(records, skip_network=True, workers=1)
            verdicts = sorted(r["verdict"] for r in rows)
            self.assertEqual(verdicts, [tool.VERDICT_NO_URL, tool.VERDICT_SKIP_NETWORK])

    def test_check_records_with_monkey_patched_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _write_corpus(
                Path(td),
                [
                    {
                        "slug": "spearbit-portfolio__a-aaa",
                        "record": _build_record(pdf_url="https://x/a.pdf"),
                    },
                    {
                        "slug": "spearbit-portfolio__b-bbb",
                        "record": _build_record(pdf_url="https://x/b.pdf"),
                    },
                ],
            )
            records = tool.walk_records(tags_dir)

            def fake_probe(url: str, **_: Any):
                if url.endswith("a.pdf"):
                    return tool.VERDICT_PASS, {
                        "status": 200,
                        "content_type": "application/pdf",
                        "final_url": url,
                    }
                return tool.VERDICT_FAIL_STATUS, {
                    "status": 404,
                    "content_type": "text/html",
                    "final_url": url,
                }

            with mock.patch.object(tool, "probe_url", fake_probe):
                rows = tool.check_records(
                    records, workers=2, rate_limit_sleep=0.0, retries=0
                )
            self.assertEqual(len(rows), 2)
            verdicts = sorted(r["verdict"] for r in rows)
            self.assertEqual(verdicts, [tool.VERDICT_FAIL_STATUS, tool.VERDICT_PASS])


# ---------------------------------------------------------------------------
# 13-14: summarize + render_markdown
# ---------------------------------------------------------------------------
class TestSummarizeAndRender(unittest.TestCase):
    def _rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "slug": "spearbit-portfolio__a-aaa",
                "firm": "spearbit-portfolio",
                "pdf_url": "https://x/a.pdf",
                "verdict": tool.VERDICT_PASS,
                "status": 200,
                "content_type": "application/pdf",
                "final_url": "https://x/a.pdf",
                "transport_error": None,
            },
            {
                "slug": "spearbit-portfolio__b-bbb",
                "firm": "spearbit-portfolio",
                "pdf_url": "https://x/b.pdf",
                "verdict": tool.VERDICT_FAIL_STATUS,
                "status": 404,
                "content_type": "text/html",
                "final_url": "https://x/b.pdf",
                "transport_error": None,
            },
            {
                "slug": "cyfrin-audit-reports__c-ccc",
                "firm": "cyfrin-audit-reports",
                "pdf_url": None,
                "verdict": tool.VERDICT_NO_URL,
                "status": None,
                "content_type": None,
                "final_url": None,
                "transport_error": None,
            },
        ]

    def test_summarize_counts(self) -> None:
        summary = tool.summarize(self._rows())
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_verdict"][tool.VERDICT_PASS], 1)
        self.assertEqual(summary["by_verdict"][tool.VERDICT_FAIL_STATUS], 1)
        self.assertEqual(summary["by_verdict"][tool.VERDICT_NO_URL], 1)
        self.assertEqual(summary["firm_totals"]["spearbit-portfolio"], 2)
        self.assertEqual(summary["firm_pass"]["spearbit-portfolio"], 1)
        self.assertEqual(len(summary["failures"]), 2)  # fail-status + no-url

    def test_render_markdown_has_required_sections(self) -> None:
        summary = tool.summarize(self._rows())
        md = tool.render_markdown(
            summary,
            generated_at="2026-05-16T00:00:00Z",
            sample=None,
            workers=4,
            timeout=5.0,
            skip_network=False,
        )
        self.assertIn("# Hackerman Audit-Firm PDF URL Sanity 2026-05-16", md)
        self.assertIn("## Totals", md)
        self.assertIn("## Verdict legend", md)
        self.assertIn("## Per-firm pass rate", md)
        self.assertIn("## Top 20 failure URLs", md)
        self.assertIn("## How to re-run", md)
        self.assertIn("spearbit-portfolio", md)


# ---------------------------------------------------------------------------
# 15-16: CLI main
# ---------------------------------------------------------------------------
class TestCLIMain(unittest.TestCase):
    def test_main_write_path_emits_artifacts_and_exit_1_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tags_dir = _write_corpus(
                root,
                [
                    {
                        "slug": "spearbit-portfolio__a-aaa",
                        "record": _build_record(pdf_url="https://x/a.pdf"),
                    },
                    {
                        "slug": "cyfrin-audit-reports__b-bbb",
                        "record": {
                            "required_preconditions": ["Source repo x/y"],
                            "fix_pattern": "no url",
                        },
                    },
                ],
            )
            jsonl = root / ".auditooor" / "audit_firm_pdf_url_sanity.jsonl"
            md = root / "docs" / "HACKERMAN_AUDIT_FIRM_PDF_URL_SANITY_2026-05-16.md"
            argv = [
                "--tags-dir",
                str(tags_dir),
                "--output-jsonl",
                str(jsonl),
                "--output-md",
                str(md),
                "--skip-network",  # avoid real HTTP in the test
            ]
            rc = tool.main(argv)
            # one record has no URL -> failure -> exit 1
            self.assertEqual(rc, 1)
            self.assertTrue(jsonl.is_file())
            self.assertTrue(md.is_file())
            lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            row0 = json.loads(lines[0])
            self.assertIn("schema", row0)
            self.assertEqual(row0["schema"], tool.SCHEMA)

    def test_main_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tags_dir = _write_corpus(
                root,
                [
                    {
                        "slug": "spearbit-portfolio__a-aaa",
                        "record": _build_record(pdf_url="https://x/a.pdf"),
                    },
                ],
            )
            jsonl = root / ".auditooor" / "audit_firm_pdf_url_sanity.jsonl"
            md = root / "docs" / "HACKERMAN_AUDIT_FIRM_PDF_URL_SANITY_2026-05-16.md"
            argv = [
                "--tags-dir",
                str(tags_dir),
                "--output-jsonl",
                str(jsonl),
                "--output-md",
                str(md),
                "--skip-network",
                "--dry-run",
            ]
            rc = tool.main(argv)
            self.assertEqual(rc, 0)
            self.assertFalse(jsonl.exists())
            self.assertFalse(md.exists())

    def test_main_missing_tags_dir_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "nope"
            argv = ["--tags-dir", str(missing)]
            rc = tool.main(argv)
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
