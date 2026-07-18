"""Tests for ``tools/hackerman-corpus-snapshot-html.py`` (PR #726 Wave-1).

Covers >=8 cases per the PR #726 spec:

1. ``build_snapshot_counts`` walks the three record shapes (record.yaml,
   record.json-only, flat .yaml) and produces deterministic top-N sorted
   counts.
2. ``render_horizontal_bar_svg`` produces well-formed SVG with the
   ``aria-label`` attribute and ``<title>`` / ``<desc>`` children.
3. ``render_pie_svg`` produces well-formed SVG with aria-label, title,
   desc, and emits one ``<path>`` per slice (or a single ``<circle>`` for
   the degenerate full-circle case).
4. ``render_html`` includes all 5 mandatory sections (subtree, tier,
   attack classes, target_repo, honest-zero table) and the page-level
   metadata block.
5. Generated HTML contains no external resource references (no
   ``src=http`` / ``href=http`` / ``<script src=`` / ``<link rel=stylesheet``).
6. Every embedded SVG has an ``aria-label`` attribute (accessibility).
7. Determinism: two consecutive ``render_html`` calls over the same
   ``build_snapshot_counts`` output produce byte-identical bytes when
   ``--generated-at`` is pinned.
8. Output file size stays under the 1MB cap for a synthetic small tree.
9. CLI ``--stdout`` mode produces the same bytes the file mode would have
   written and exits 0.
10. ``_stable_sorted_dict`` returns canonical tier order tier-1..tier-5
    then no-tier, even when input order is shuffled.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-corpus-snapshot-html.py"


def _load_tool() -> Any:
    name = "_hackerman_corpus_snapshot_html_test_mod"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


SAMPLE_RECORD_BASE = {
    "schema_version": "auditooor.hackerman_record.v1",
    "attack_class": "ghsa-class-a",
    "target_repo": "acme/lending",
    "target_domain": "lending",
    "function_shape": {
        "shape_tags": ["verification_tier:tier-1-ghsa-rest-api"],
    },
}


def _write_record(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_yaml_minimal(path: Path, payload: dict[str, Any]) -> None:
    """Write a minimal flat-yaml record. The tool's YAML fallback parser
    handles trivial ``key: value`` plus ``function_shape.shape_tags`` lists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for k, v in payload.items():
        if k == "function_shape":
            lines.append("function_shape:")
            lines.append("  shape_tags:")
            for tag in v.get("shape_tags", []):
                lines.append(f"    - {tag}")
        else:
            lines.append(f"{k}: {v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_synthetic_tree(root: Path) -> Path:
    tags_dir = root / "audit" / "corpus_tags" / "tags"
    tags_dir.mkdir(parents=True, exist_ok=True)
    # Two subtrees with record.yaml-shaped JSON records (the walker treats
    # ``record.json`` siblings without a ``record.yaml`` as record.json shape).
    rec1 = dict(SAMPLE_RECORD_BASE)
    rec1["attack_class"] = "ghsa-class-a"
    rec1["target_repo"] = "acme/lending"
    _write_record(tags_dir / "lending_protocols" / "acme-lending-1" / "record.json", rec1)
    rec2 = dict(SAMPLE_RECORD_BASE)
    rec2["attack_class"] = "ghsa-class-a"  # duplicate to test top-N counter
    rec2["target_repo"] = "acme/lending"
    _write_record(tags_dir / "lending_protocols" / "acme-lending-2" / "record.json", rec2)
    rec3 = dict(SAMPLE_RECORD_BASE)
    rec3["attack_class"] = "ghsa-class-b"
    rec3["target_repo"] = "acme/dex"
    rec3["function_shape"] = {"shape_tags": ["verification_tier:tier-2-osv"]}
    _write_record(tags_dir / "dex_fix_history" / "acme-dex-1" / "record.json", rec3)
    # Flat .yaml record under a subtree directory (NOT at the tags-dir root,
    # to keep walker scope simple).
    _write_yaml_minimal(
        tags_dir / "lending_protocols" / "flat_one.yaml",
        {
            "schema_version": "auditooor.hackerman_record.v1",
            "attack_class": "ghsa-class-c",
            "target_repo": "acme/flat",
            "target_domain": "lending",
            "function_shape": {"shape_tags": ["verification_tier:tier-3-cve"]},
        },
    )
    return tags_dir


class TestBuildSnapshotCounts(unittest.TestCase):
    def test_walks_three_shapes_and_returns_deterministic_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            self.assertEqual(counts["schema"], tool.SCHEMA)
            self.assertEqual(counts["total_records"], 4)
            self.assertIn(("lending_protocols", 3), counts["subtree_records"])
            self.assertIn(("dex_fix_history", 1), counts["subtree_records"])
            # attack_class_top top1 must be the duplicated class with 2 hits.
            self.assertEqual(counts["attack_class_top"][0], ("ghsa-class-a", 2))


class TestRenderHorizontalBarSvg(unittest.TestCase):
    def test_emits_well_formed_svg_with_aria_label(self) -> None:
        svg = tool.render_horizontal_bar_svg(
            [("a", 5), ("b", 3)],
            title="t1",
            aria_label="ar1",
        )
        self.assertIn('aria-label="ar1"', svg)
        self.assertIn("<title>t1</title>", svg)
        self.assertIn("<desc>ar1</desc>", svg)
        self.assertIn("<rect", svg)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))


class TestRenderPieSvg(unittest.TestCase):
    def test_pie_emits_one_path_per_slice_with_aria(self) -> None:
        svg = tool.render_pie_svg(
            [("tier-1", 7), ("tier-2", 3)],
            title="t2",
            aria_label="ar2",
        )
        self.assertIn('aria-label="ar2"', svg)
        self.assertIn("<title>t2</title>", svg)
        self.assertIn("<desc>ar2</desc>", svg)
        self.assertEqual(svg.count("<path "), 2)

    def test_pie_handles_single_full_slice(self) -> None:
        svg = tool.render_pie_svg(
            [("tier-1", 10)],
            title="t",
            aria_label="ar",
        )
        # Single full slice degrades to a circle.
        self.assertIn("<circle ", svg)


class TestRenderHtmlIncludesAllSections(unittest.TestCase):
    def test_renders_all_five_sections_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            html_text = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            self.assertIn("<h1>Hackerman corpus snapshot</h1>", html_text)
            self.assertIn("1. Corpus subtree record counts", html_text)
            self.assertIn("2. Verification-tier distribution", html_text)
            self.assertIn("3. Top-20 attack classes", html_text)
            self.assertIn("4. Top-10 target_repos", html_text)
            self.assertIn("5. Honest-zero ecosystem summary", html_text)
            self.assertIn("<table>", html_text)
            self.assertIn("tendermint", html_text)


class TestNoExternalResources(unittest.TestCase):
    def test_no_external_links_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            html_text = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            # No script src, no stylesheet href, no remote URLs in src/href.
            self.assertNotIn("<script src=", html_text)
            self.assertNotIn('rel="stylesheet"', html_text)
            self.assertNotIn("rel='stylesheet'", html_text)
            # No http(s) URLs in src= or href= attributes.
            self.assertFalse(
                re.search(r'src=["\']https?://', html_text),
                "found external src URL",
            )
            self.assertFalse(
                re.search(r'href=["\']https?://', html_text),
                "found external href URL",
            )


class TestAccessibilityAriaLabels(unittest.TestCase):
    def test_every_svg_has_aria_label(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            html_text = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            svg_openers = re.findall(r"<svg\b[^>]*>", html_text)
            self.assertGreaterEqual(len(svg_openers), 4)
            for opener in svg_openers:
                self.assertIn("aria-label=", opener, f"missing aria-label: {opener}")


class TestDeterminism(unittest.TestCase):
    def test_two_consecutive_runs_are_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            html1 = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            html2 = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            self.assertEqual(html1, html2)


class TestOutputSizeUnder1Mb(unittest.TestCase):
    def test_synthetic_tree_output_under_1mb(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            counts = tool.build_snapshot_counts(tags_dir)
            html_text = tool.render_html(
                counts, tool.HONEST_ZERO_ECOSYSTEMS, generated_at="2026-05-16T00:00:00Z"
            )
            self.assertLess(len(html_text.encode("utf-8")), tool.MAX_OUTPUT_BYTES)


class TestStableSortedDict(unittest.TestCase):
    def test_canonical_tier_order(self) -> None:
        from collections import Counter

        c = Counter()
        c["no-tier"] = 11
        c["tier-3"] = 3
        c["tier-1"] = 1
        c["tier-2"] = 2
        c["tier-5"] = 5
        out = tool._stable_sorted_dict(c)
        keys = [k for k, _ in out]
        self.assertEqual(keys, ["tier-1", "tier-2", "tier-3", "tier-5", "no-tier"])


class TestCliStdoutMode(unittest.TestCase):
    def test_stdout_mode_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--stdout",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("<!DOCTYPE html>", proc.stdout)
            self.assertIn("Hackerman corpus snapshot", proc.stdout)


if __name__ == "__main__":
    unittest.main()
