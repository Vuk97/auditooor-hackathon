#!/usr/bin/env python3
"""Tests for tools/case-study-emitter.py.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. Covers:

1. --dry-run on synthetic workspace + retrospective.json prints expected path +
   frontmatter header (no file written).
2. Real run writes file with correct frontmatter (``layer: L2`` verbatim).
3. Skip-if-exists default behavior (second run does not overwrite).
4. --force overrides skip.
5. Missing retrospective → exits non-zero with clear error message.
6. MD-only fallback (no retrospective.json, only RETROSPECTIVE.md).
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "case-study-emitter.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("case_study_emitter", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["case_study_emitter"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _make_retro_json(
    ws: Path,
    lessons: list[dict] | None = None,
    submissions_count: int = 3,
    accepted_count: int = 1,
) -> None:
    data = {
        "schema_version": "1.0",
        "workspace": str(ws),
        "generated_at": "2026-05-10T00:00:00+00:00",
        "metrics": {
            "submissions_count": {"value": submissions_count, "provenance": "test"},
            "accepted_count": {"value": accepted_count, "provenance": "test"},
        },
        "lessons": lessons
        or [
            {
                "text": "Always run docs-check before committing.",
                "extraction_method": "structured",
            },
            {
                "text": "AP-01 reentrancy guard missing on claim path.",
                "extraction_method": "regex_fallback",
            },
        ],
        "exit_criteria": [
            {"criterion": "≥1 High+ accepted", "status": "PASS"},
            {"criterion": "cost within budget", "status": "UNKNOWN"},
        ],
    }
    (ws / "retrospective.json").write_text(json.dumps(data), encoding="utf-8")


def _make_retro_md(ws: Path) -> None:
    content = """# Engagement Retrospective

## Honest-Tone Summary

3 submissions filed. 1 accepted.

## Lessons

- Use MCP recall before spawning workers.
- Do not rely on mocked callbacks for Critical claims.

## Exit Criteria

| criterion | status |
|-----------|--------|
| ≥1 High+  | PASS   |
"""
    (ws / "RETROSPECTIVE.md").write_text(content, encoding="utf-8")


class TestNoRetrospective(unittest.TestCase):
    """A missing retrospective is a graceful advisory skip (rc=0) by default, so
    it does NOT abort audit-closeout; --require-retrospective restores hard-fail."""

    def test_no_retro_skips_with_rc0_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "honest-zero-engagement"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            # NOTE: no retrospective.json / RETROSPECTIVE.md written.

            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(
                    ["--workspace", str(ws), "--vault-dir", str(vault)]
                )

            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertEqual(
                rc, 0, f"missing retrospective must skip with rc=0, got {rc}. output: {output}"
            )
            self.assertIn("SKIP", output)
            # Graceful skip writes nothing.
            self.assertFalse((vault / "case_study").exists())

    def test_no_retro_hard_fails_under_require_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "honest-zero-engagement"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()

            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(
                    [
                        "--workspace", str(ws),
                        "--vault-dir", str(vault),
                        "--require-retrospective",
                    ]
                )

            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertEqual(
                rc, 1, f"--require-retrospective must hard-fail (rc=1), got {rc}. output: {output}"
            )
            self.assertIn("ERROR", output)


class TestDryRun(unittest.TestCase):
    """--dry-run prints destination path + frontmatter header, writes nothing."""

    def test_dry_run_prints_path_and_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "my-engagement"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_json(ws)

            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(
                    [
                        "--workspace", str(ws),
                        "--vault-dir", str(vault),
                        "--dry-run",
                    ]
                )

            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertEqual(rc, 0, f"expected rc=0, got {rc}. output: {output}")

            # Must print the destination path
            self.assertIn("case_study/", output)
            self.assertIn("my-engagement-r1.md", output)

            # Must print frontmatter header with layer: L2
            self.assertIn("layer: L2", output)
            self.assertIn("engagement: my-engagement", output)
            self.assertIn("round: 1", output)
            self.assertIn("submissions_count: 3", output)
            self.assertIn("accepted_count: 1", output)

            # Must NOT write any file
            case_study_dir = vault / "case_study"
            self.assertFalse(
                case_study_dir.exists(),
                "dry-run must not create case_study directory",
            )


class TestRealWrite(unittest.TestCase):
    """Real run writes file with correct frontmatter."""

    def test_writes_file_with_layer_l2(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "spark-engagement"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_json(ws)

            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(
                    [
                        "--workspace", str(ws),
                        "--vault-dir", str(vault),
                    ]
                )

            output = buf_out.getvalue() + buf_err.getvalue()
            self.assertEqual(rc, 0, f"expected rc=0. output: {output}")

            dest = vault / "case_study" / "spark-engagement-r1.md"
            self.assertTrue(dest.exists(), f"expected {dest} to be written")

            content = dest.read_text(encoding="utf-8")
            # Frontmatter verbatim checks
            self.assertIn("layer: L2", content)
            self.assertIn("engagement: spark-engagement", content)
            self.assertIn("round: 1", content)
            self.assertIn("submissions_count: 3", content)
            self.assertIn("accepted_count: 1", content)
            # Body checks
            self.assertIn("## Lessons", content)
            self.assertIn("Always run docs-check", content)

    def test_round_flag_used_in_filename_and_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "dydx"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_json(ws)

            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(buf):
                rc = MOD.main(
                    [
                        "--workspace", str(ws),
                        "--vault-dir", str(vault),
                        "--round", "3",
                    ]
                )

            self.assertEqual(rc, 0)
            dest = vault / "case_study" / "dydx-r3.md"
            self.assertTrue(dest.exists(), f"{dest} should exist")
            content = dest.read_text(encoding="utf-8")
            self.assertIn("round: 3", content)


class TestSkipIfExists(unittest.TestCase):
    """Second run without --force skips existing file."""

    def test_skip_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "morpho"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_json(ws)

            # First write
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(buf):
                rc1 = MOD.main(["--workspace", str(ws), "--vault-dir", str(vault)])
            self.assertEqual(rc1, 0)

            dest = vault / "case_study" / "morpho-r1.md"
            original_content = dest.read_text()

            # Modify to detect overwrite
            sentinel = "SENTINEL_CONTENT_DO_NOT_OVERWRITE"
            dest.write_text(sentinel)

            buf2 = io.StringIO()
            with redirect_stdout(buf2), redirect_stderr(buf2):
                rc2 = MOD.main(["--workspace", str(ws), "--vault-dir", str(vault)])

            output2 = buf2.getvalue()
            self.assertEqual(rc2, 0)
            self.assertIn("SKIP", output2, "expected SKIP message on second run")
            # Content should be unchanged (still sentinel)
            self.assertEqual(dest.read_text(), sentinel)


class TestForceOverwrite(unittest.TestCase):
    """--force overwrites existing file."""

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "base-azul"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_json(ws)

            # First write
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(buf):
                MOD.main(["--workspace", str(ws), "--vault-dir", str(vault)])

            dest = vault / "case_study" / "base-azul-r1.md"
            dest.write_text("OLD_CONTENT_SENTINEL")

            buf2 = io.StringIO()
            with redirect_stdout(buf2), redirect_stderr(buf2):
                rc = MOD.main(
                    ["--workspace", str(ws), "--vault-dir", str(vault), "--force"]
                )

            self.assertEqual(rc, 0)
            new_content = dest.read_text(encoding="utf-8")
            self.assertNotEqual(new_content, "OLD_CONTENT_SENTINEL")
            self.assertIn("layer: L2", new_content)


class TestMissingRetrospective(unittest.TestCase):
    """Missing retrospective exits non-zero with clear error ONLY under
    --require-retrospective; the default is a graceful advisory skip (covered by
    TestNoRetrospective) so audit-closeout is never aborted."""

    def test_no_retro_exits_nonzero_under_require_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "empty-engagement"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            # No retrospective.json, no RETROSPECTIVE.md

            buf_err = io.StringIO()
            buf_out = io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = MOD.main(
                    [
                        "--workspace", str(ws),
                        "--vault-dir", str(vault),
                        "--require-retrospective",
                    ]
                )

            self.assertNotEqual(rc, 0, "should return non-zero when retro missing under --require-retrospective")
            err = buf_err.getvalue()
            self.assertTrue(
                "ERROR" in err or "not found" in err,
                f"expected error message, got: {err!r}",
            )


class TestMdFallback(unittest.TestCase):
    """No retrospective.json, only RETROSPECTIVE.md — should succeed."""

    def test_md_fallback_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ws = tmp / "centrifuge"
            ws.mkdir()
            vault = tmp / "vault"
            vault.mkdir()
            _make_retro_md(ws)  # no JSON, only MD

            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(buf):
                rc = MOD.main(["--workspace", str(ws), "--vault-dir", str(vault)])

            self.assertEqual(rc, 0, f"expected rc=0. output: {buf.getvalue()}")
            dest = vault / "case_study" / "centrifuge-r1.md"
            self.assertTrue(dest.exists())
            content = dest.read_text(encoding="utf-8")
            self.assertIn("layer: L2", content)
            # lessons from MD
            self.assertIn("MCP recall", content)
            # counts should be "unknown" since no JSON
            self.assertIn("submissions_count: unknown", content)
            self.assertIn("accepted_count: unknown", content)


if __name__ == "__main__":
    unittest.main()
