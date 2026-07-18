"""Tests for tools/hackerman-docs-cross-link-audit.py."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


THIS_FILE = pathlib.Path(__file__).resolve()
REPO = THIS_FILE.parent.parent.parent
TOOL_PATH = REPO / "tools" / "hackerman-docs-cross-link-audit.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_docs_cross_link_audit", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


HM = _load_module()


class HackermanDocsCrossLinkAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "docs").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel: str, body: str) -> pathlib.Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    # 1. Tool file exists and is well-formed.
    def test_tool_file_exists(self):
        self.assertTrue(TOOL_PATH.exists(), f"missing: {TOOL_PATH}")
        text = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("def main", text)
        self.assertIn("def audit", text)

    # 2. Clean doc with valid sibling link is `clean`.
    def test_clean_doc_passes(self):
        self._write("docs/HACKERMAN_TARGET.md", "target\n")
        self._write(
            "docs/HACKERMAN_SRC.md",
            "See [target](HACKERMAN_TARGET.md) for details.\n",
        )
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        self.assertEqual(result["docs_audited"], 2)
        self.assertEqual(result["total_broken_links"], 0)
        for d in result["per_doc"]:
            self.assertEqual(d["verdict"], "clean", d)

    # 3. Broken link is reported.
    def test_broken_link_detected(self):
        self._write(
            "docs/HACKERMAN_BAD.md",
            "Missing: [x](does-not-exist.md)\n",
        )
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        self.assertEqual(result["total_broken_links"], 1)
        bad = next(d for d in result["per_doc"] if d["doc"].endswith("HACKERMAN_BAD.md"))
        self.assertEqual(bad["verdict"], "broken-links")
        self.assertEqual(bad["broken"][0]["target"], "does-not-exist.md")

    # 4. External http(s) links are skipped.
    def test_external_links_skipped(self):
        self._write(
            "docs/HACKERMAN_EXT.md",
            "External [g](https://example.com) and [m](mailto:a@b.c).\n",
        )
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        doc = result["per_doc"][0]
        self.assertEqual(doc["links_checked"], 0)
        self.assertEqual(doc["skipped_external"], 2)
        self.assertEqual(doc["verdict"], "clean")

    # 5. Anchor-only links are skipped.
    def test_anchor_only_links_skipped(self):
        self._write(
            "docs/HACKERMAN_ANCH.md",
            "See [top](#summary) and [other](#x).\n",
        )
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        doc = result["per_doc"][0]
        self.assertEqual(doc["skipped_anchor_only"], 2)
        self.assertEqual(doc["links_checked"], 0)
        self.assertEqual(doc["verdict"], "clean")

    # 6. Fragment after path is stripped before existence check.
    def test_link_with_fragment_resolved(self):
        self._write("docs/HACKERMAN_T.md", "# Section\n")
        self._write(
            "docs/HACKERMAN_S.md",
            "See [x](HACKERMAN_T.md#section).\n",
        )
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        self.assertEqual(result["total_broken_links"], 0)

    # 7. Code fences are ignored.
    def test_fenced_code_ignored(self):
        body = "```\n[fake](nonexistent.md)\n```\n[real](other.md)\n"
        self._write("docs/other.md", "x\n")
        self._write("docs/HACKERMAN_FENCE.md", body)
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        # Only [real](other.md) is checked; [fake] is inside fence
        doc = next(d for d in result["per_doc"] if d["doc"].endswith("HACKERMAN_FENCE.md"))
        self.assertEqual(doc["links_checked"], 1)
        self.assertEqual(len(doc["broken"]), 0)

    # 8. Globs combine HACKERMAN, WAVE, and PR_726 prefixes.
    def test_default_globs_cover_three_families(self):
        self._write("docs/HACKERMAN_A.md", "a\n")
        self._write("docs/WAVE2_B.md", "b\n")
        self._write("docs/PR_726_C.md", "c\n")
        self._write("docs/UNRELATED.md", "skip\n")
        result = HM.audit(self.root, list(HM.DEFAULT_GLOBS))
        doc_names = {d["doc"] for d in result["per_doc"]}
        self.assertIn("docs/HACKERMAN_A.md", doc_names)
        self.assertIn("docs/WAVE2_B.md", doc_names)
        self.assertIn("docs/PR_726_C.md", doc_names)
        self.assertNotIn("docs/UNRELATED.md", doc_names)

    # 9. Render markdown is well-formed.
    def test_render_markdown_contains_summary(self):
        self._write("docs/HACKERMAN_X.md", "no links\n")
        result = HM.audit(self.root, ["docs/HACKERMAN*.md"])
        md = HM.render_markdown(result)
        self.assertIn("# Hackerman Docs Cross-Link Audit", md)
        self.assertIn("## Summary", md)
        self.assertIn("Docs audited", md)

    # 10. CLI --strict returns 1 when broken links present, 0 otherwise.
    def test_cli_strict_exit_codes(self):
        clean_root = pathlib.Path(self.tmp.name) / "clean"
        clean_root.mkdir()
        (clean_root / "docs").mkdir()
        (clean_root / "docs" / "HACKERMAN_OK.md").write_text("no links here\n", encoding="utf-8")
        rc_clean = HM.main(["--root", str(clean_root), "--strict"])
        self.assertEqual(rc_clean, 0)

        bad_root = pathlib.Path(self.tmp.name) / "bad"
        bad_root.mkdir()
        (bad_root / "docs").mkdir()
        (bad_root / "docs" / "HACKERMAN_BAD.md").write_text(
            "[x](missing.md)\n", encoding="utf-8"
        )
        rc_bad = HM.main(["--root", str(bad_root), "--strict"])
        self.assertEqual(rc_bad, 1)

    # 11. --report-out writes a markdown file at the requested path.
    def test_report_out_writes_file(self):
        out_dir = self.root / "out"
        out_dir.mkdir()
        report_path = out_dir / "audit.md"
        self._write("docs/HACKERMAN_R.md", "[bad](nope.md)\n")
        rc = HM.main([
            "--root", str(self.root),
            "--report-out", str(report_path),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(report_path.exists())
        content = report_path.read_text(encoding="utf-8")
        self.assertIn("# Hackerman Docs Cross-Link Audit", content)
        self.assertIn("## Broken Links", content)
        self.assertIn("nope.md", content)


if __name__ == "__main__":
    unittest.main()
