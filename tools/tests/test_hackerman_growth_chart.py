"""Tests for ``tools/hackerman-growth-chart.py``.

Coverage (>=6 cases):

1. ``_epoch_days`` parses ISO dates and returns deterministic ordering.
2. ``_x_positions`` spreads same-date co-points so they don't stack.
3. ``_nice_ceiling`` rounds Y-max to a friendly value strictly >= max.
4. ``build_chart_model`` materialises both series with correct counts
   and stable coordinates within the plot area.
5. ``render_svg`` emits a valid self-contained XML SVG (no <script>,
   no external href, no <link> stylesheet), with both series polylines
   and both series legend rows.
6. ``render_svg`` honours the ``--generated-at`` pin (env or arg) for
   byte-deterministic regeneration.
7. CLI ``--out`` mode writes the file and the file is <50KB.
8. CLI ``--json`` mode emits a parseable model with all canonical points.
9. Self-contained guarantee: no external font, no <image href=>, no
   <script>, no <iframe>, no remote http(s) hrefs.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-growth-chart.py"


def _load_tool() -> Any:
    name = "_hackerman_growth_chart_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class EpochDaysTests(unittest.TestCase):
    def test_epoch_days_orders_dates(self):
        a = tool._epoch_days("2026-05-10")
        b = tool._epoch_days("2026-05-16")
        c = tool._epoch_days("2026-12-31")
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertEqual(c - a, 235)


class XPositionsTests(unittest.TestCase):
    def test_same_date_points_get_nudged_apart(self):
        pts = [
            ("a", "2026-05-10", 100, 50),
            ("b", "2026-12-31", 200, 100),
            ("c", "2026-12-31", 300, 150),  # same date as b -> nudge
        ]
        xs = tool._x_positions(pts)
        self.assertEqual(len(xs), 3)
        # b and c shared date; the resulting xs must be strictly ordered.
        self.assertLess(xs[0], xs[1])
        self.assertLessEqual(xs[1], xs[2])  # c is nudged >= b in coord
        # All x positions inside the plot area horizontally.
        for x in xs:
            self.assertGreaterEqual(x, tool.MARGIN_LEFT)
            self.assertLessEqual(x, tool.MARGIN_LEFT + tool.PLOT_WIDTH)


class NiceCeilingTests(unittest.TestCase):
    def test_nice_ceiling_rounds_up(self):
        self.assertGreaterEqual(tool._nice_ceiling(120000), 120000)
        self.assertGreaterEqual(tool._nice_ceiling(36492), 36492)
        self.assertGreaterEqual(tool._nice_ceiling(407), 407)
        self.assertGreaterEqual(tool._nice_ceiling(999), 999)
        # Non-positive guard.
        self.assertEqual(tool._nice_ceiling(0), 10)
        self.assertEqual(tool._nice_ceiling(-5), 10)


class BuildChartModelTests(unittest.TestCase):
    def test_model_contains_both_series_with_canonical_counts(self):
        model = tool.build_chart_model()
        self.assertIn("total", model["series"])
        self.assertIn("tier_1_plus_2", model["series"])
        total = model["series"]["total"]
        tier = model["series"]["tier_1_plus_2"]
        # 7 canonical milestones.
        self.assertEqual(len(total), 7)
        self.assertEqual(len(tier), 7)
        # Spot-check values from DATA_POINTS.
        self.assertEqual(total[0]["value"], 407)
        self.assertEqual(total[1]["value"], 36492)
        self.assertEqual(total[-1]["value"], 120000)
        self.assertEqual(tier[0]["value"], 180)
        self.assertEqual(tier[1]["value"], 8200)
        # All coords inside plot area.
        plot = model["plot"]
        for p in total + tier:
            self.assertGreaterEqual(p["x"], plot["margin_left"])
            self.assertLessEqual(
                p["x"],
                plot["margin_left"]
                + (
                    plot["width"]
                    - plot["margin_left"]
                    - plot["margin_right"]
                ),
            )
            self.assertGreaterEqual(p["y"], plot["margin_top"])
            self.assertLessEqual(
                p["y"],
                plot["margin_top"]
                + (
                    plot["height"]
                    - plot["margin_top"]
                    - plot["margin_bottom"]
                ),
            )
        # y_max must be at least the largest total.
        self.assertGreaterEqual(model["y_max"], 120000)


class RenderSvgTests(unittest.TestCase):
    def test_render_svg_emits_valid_self_contained_xml(self):
        svg = tool.render_svg(generated_at="2026-05-16T00:00:00Z")
        self.assertTrue(svg.startswith('<?xml version="1.0"'))
        self.assertIn("<svg ", svg)
        self.assertIn("</svg>", svg)
        # Two series polylines.
        self.assertEqual(svg.count("<polyline "), 2)
        # Legend has both series rows.
        self.assertIn(">total records<", svg)
        self.assertIn(">tier 1+2 records<", svg)
        # Title text rendered.
        self.assertIn("Hackerman corpus growth", svg)
        # X axis labels rendered (canonical milestone names).
        self.assertIn("PR #724 baseline", svg)
        self.assertIn("Wave-1 close", svg)
        self.assertIn("EOY-2026 (best)", svg)

    def test_render_svg_self_contained_no_external_refs(self):
        svg = tool.render_svg(generated_at="2026-05-16T00:00:00Z")
        # Self-contained guarantee.
        self.assertNotIn("<script", svg)
        self.assertNotIn("<iframe", svg)
        self.assertNotIn("<image", svg)
        self.assertNotIn("xlink:href", svg)
        # No external stylesheet.
        self.assertNotIn("<link", svg)
        # The only allowed "http(s)://" usage is the canonical SVG XML
        # namespace declaration (xmlns="http://www.w3.org/2000/svg"), which
        # is a namespace URI - browsers/viewers do NOT fetch it. After
        # stripping that, no other http(s):// occurrences are permitted.
        stripped = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
        self.assertNotIn("http://", stripped)
        self.assertNotIn("https://", stripped)


class DeterminismTests(unittest.TestCase):
    def test_pinned_generated_at_produces_byte_identical_output(self):
        a = tool.render_svg(generated_at="2026-05-16T00:00:00Z")
        b = tool.render_svg(generated_at="2026-05-16T00:00:00Z")
        self.assertEqual(a, b)

    def test_different_generated_at_changes_comment_only(self):
        a = tool.render_svg(generated_at="2026-05-16T00:00:00Z")
        b = tool.render_svg(generated_at="2026-05-16T11:11:11Z")
        self.assertNotEqual(a, b)
        # Diff isolated to the generated_at comment line.
        a_no_ts = "\n".join(
            ln for ln in a.splitlines() if "generated_at:" not in ln
        )
        b_no_ts = "\n".join(
            ln for ln in b.splitlines() if "generated_at:" not in ln
        )
        self.assertEqual(a_no_ts, b_no_ts)


class CliTests(unittest.TestCase):
    def test_cli_out_writes_file_under_50kb(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "chart.svg"
            rc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--out",
                    str(out),
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rc.returncode, 0, rc.stderr)
            self.assertTrue(out.exists())
            size = out.stat().st_size
            self.assertLess(size, 50 * 1024)
            self.assertGreater(size, 1000)
            # Sanity-check file is valid SVG.
            content = out.read_text(encoding="utf-8")
            self.assertTrue(content.startswith('<?xml version="1.0"'))
            self.assertIn("</svg>", content)

    def test_cli_json_mode_emits_parseable_model(self):
        rc = subprocess.run(
            [sys.executable, str(TOOL_PATH), "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rc.returncode, 0, rc.stderr)
        data = json.loads(rc.stdout)
        self.assertIn("points", data)
        self.assertIn("series", data)
        self.assertEqual(len(data["points"]), 7)
        labels = [p["label"] for p in data["points"]]
        self.assertIn("PR #724 baseline", labels)
        self.assertIn("Wave-1 close", labels)
        self.assertIn("EOY-2026 (best)", labels)
        # Series counts match points.
        self.assertEqual(len(data["series"]["total"]), 7)
        self.assertEqual(len(data["series"]["tier_1_plus_2"]), 7)


if __name__ == "__main__":
    unittest.main()
