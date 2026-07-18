#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - corpus growth SVG chart.

Emits a single self-contained SVG file showing Hackerman corpus growth
across Wave-0 baseline through Wave-1 close, Wave-2/Wave-3/Wave-4
projections, and EOY-2026 best/worst case envelopes.

Series rendered (two lines):

- ``total``           Total records (PR #724 baseline -> Wave-1 close -> projections)
- ``tier_1_plus_2``   Tier-1 + Tier-2 records (subset of total)

Data points (anchored against PR #726 milestone notes - see
``docs/HACKERMAN_CORPUS_EXPANSION_2026-05-15.md`` and PR #724 baseline):

  Milestone               Date       total   tier_1+2
  PR #724 baseline        2026-05-10    407       180
  Wave-1 close            2026-05-16  36492      8200
  Wave-2 projected close  2026-05-30  63500     16500
  Wave-3 projected close  2026-06-15  66500     19000
  Wave-4 projected close  2026-07-15  74400     24000
  EOY-2026 (worst)        2026-12-31  90000     32000
  EOY-2026 (best)         2026-12-31 120000     48000

The chart is rendered as a self-contained SVG (no external CSS, no
external fonts, no <script>) so it survives offline view, Markdown
embedding, and GitHub raw display. Output stays well under 50KB.

Determinism: stable point list, stable axis ticks, stable element order.
A ``--generated-at`` override (env ``AUDITOOOR_HACKERMAN_CHART_GENERATED_AT``)
pins the timestamp comment for byte-identical regeneration in tests.

Usage::

    python3 tools/hackerman-growth-chart.py --out docs/HACKERMAN_CORPUS_GROWTH_CHART_2026-05-16.svg
    python3 tools/hackerman-growth-chart.py --json   # emit data points as JSON for debugging
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


# Canonical data points. Tuples of (label, iso_date, total, tier_1_plus_2).
# Order is left-to-right on the X axis. Keep in sync with
# docs/HACKERMAN_CORPUS_EXPANSION_2026-05-15.md milestones.
DATA_POINTS: List[Tuple[str, str, int, int]] = [
    ("PR #724 baseline", "2026-05-10", 407, 180),
    ("Wave-1 close", "2026-05-16", 36492, 8200),
    ("Wave-2 projected", "2026-05-30", 63500, 16500),
    ("Wave-3 projected", "2026-06-15", 66500, 19000),
    ("Wave-4 projected", "2026-07-15", 74400, 24000),
    ("EOY-2026 (worst)", "2026-12-31", 90000, 32000),
    ("EOY-2026 (best)", "2026-12-31", 120000, 48000),
]


CHART_WIDTH = 960
CHART_HEIGHT = 540
MARGIN_LEFT = 90
MARGIN_RIGHT = 40
MARGIN_TOP = 60
MARGIN_BOTTOM = 110

PLOT_WIDTH = CHART_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
PLOT_HEIGHT = CHART_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM


def _epoch_days(iso_date: str) -> int:
    """Parse ``YYYY-MM-DD`` to days-since-1970 (epoch days) for axis spacing."""
    d = _dt.date.fromisoformat(iso_date)
    return (d - _dt.date(1970, 1, 1)).days


def _x_positions(points: Sequence[Tuple[str, str, int, int]]) -> List[float]:
    """Map each point's date to an X coordinate inside the plot area.

    Edge case: when two points share the same ISO date (e.g. EOY worst+best),
    we still preserve list order along the X axis by adding a small ordinal
    nudge so they don't stack on top of each other. The nudge is fixed
    (per-position offset in epoch-days/2 units) so the rendering is
    deterministic.
    """
    days = [_epoch_days(p[1]) for p in points]
    # Ordinal nudge so co-dated points spread out.
    for i in range(1, len(days)):
        if days[i] <= days[i - 1]:
            days[i] = days[i - 1] + 1
    if not days:
        return []
    lo, hi = min(days), max(days)
    span = max(hi - lo, 1)
    return [MARGIN_LEFT + (d - lo) * PLOT_WIDTH / span for d in days]


def _nice_ceiling(max_val: int) -> int:
    """Round a max value up to a 'nice' Y-axis ceiling.

    Examples: 120000 -> 120000, 99999 -> 100000, 36492 -> 40000.
    Returns the smallest multiple of 10**(floor(log10(max_val))-1) * 5 not
    less than max_val, with a small bump (+5%) so the top label is visible.
    """
    if max_val <= 0:
        return 10
    target = int(max_val * 1.05)
    # Round to nearest 10000 for our scale; for small values, finer.
    if target <= 1000:
        step = 100
    elif target <= 10000:
        step = 1000
    elif target <= 100000:
        step = 10000
    else:
        step = 20000
    return ((target + step - 1) // step) * step


def _y_position(value: int, y_max: int) -> float:
    if y_max <= 0:
        return MARGIN_TOP + PLOT_HEIGHT
    frac = value / y_max
    return MARGIN_TOP + PLOT_HEIGHT - frac * PLOT_HEIGHT


def _format_count(n: int) -> str:
    if n >= 1000:
        return f"{n:,}"
    return str(n)


def build_chart_model(
    points: Sequence[Tuple[str, str, int, int]] = None,
) -> dict:
    """Build a structured chart model (data + computed coordinates).

    Useful for tests (assert without parsing SVG) and for the ``--json``
    debug output.
    """
    pts = list(points if points is not None else DATA_POINTS)
    xs = _x_positions(pts)
    max_total = max((p[2] for p in pts), default=0)
    y_max = _nice_ceiling(max_total)
    series_total = [
        {
            "label": p[0],
            "date": p[1],
            "value": p[2],
            "x": xs[i],
            "y": _y_position(p[2], y_max),
        }
        for i, p in enumerate(pts)
    ]
    series_tier12 = [
        {
            "label": p[0],
            "date": p[1],
            "value": p[3],
            "x": xs[i],
            "y": _y_position(p[3], y_max),
        }
        for i, p in enumerate(pts)
    ]
    return {
        "y_max": y_max,
        "points": pts,
        "series": {
            "total": series_total,
            "tier_1_plus_2": series_tier12,
        },
        "plot": {
            "width": CHART_WIDTH,
            "height": CHART_HEIGHT,
            "margin_left": MARGIN_LEFT,
            "margin_right": MARGIN_RIGHT,
            "margin_top": MARGIN_TOP,
            "margin_bottom": MARGIN_BOTTOM,
        },
    }


def _y_ticks(y_max: int, n: int = 6) -> List[int]:
    """Generate evenly spaced Y ticks from 0 to y_max inclusive."""
    if n < 2:
        return [0, y_max]
    step = y_max // (n - 1)
    if step == 0:
        return [0, y_max]
    return [step * i for i in range(n)]


def _polyline_points(series: Iterable[dict]) -> str:
    return " ".join(f"{p['x']:.2f},{p['y']:.2f}" for p in series)


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def render_svg(
    points: Sequence[Tuple[str, str, int, int]] = None,
    generated_at: str = None,
) -> str:
    """Render the corpus growth chart as a self-contained SVG string."""
    model = build_chart_model(points)
    y_max = model["y_max"]
    s_total = model["series"]["total"]
    s_tier = model["series"]["tier_1_plus_2"]

    ts = (
        generated_at
        or os.environ.get("AUDITOOOR_HACKERMAN_CHART_GENERATED_AT")
        or _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    out: List[str] = []
    out.append('<?xml version="1.0" encoding="UTF-8"?>')
    out.append(f"<!-- generated_at: {_xml_escape(ts)} -->")
    out.append(
        '<!-- generator: tools/hackerman-growth-chart.py (PR #726 wave-1) -->'
    )
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {CHART_WIDTH} {CHART_HEIGHT}" '
        f'width="{CHART_WIDTH}" height="{CHART_HEIGHT}" '
        f'role="img" aria-label="Hackerman corpus growth chart">'
    )

    # Background.
    out.append(
        f'<rect x="0" y="0" width="{CHART_WIDTH}" height="{CHART_HEIGHT}" '
        f'fill="#ffffff" stroke="none"/>'
    )

    # Title.
    out.append(
        f'<text x="{CHART_WIDTH / 2:.0f}" y="28" '
        f'text-anchor="middle" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="20" '
        f'font-weight="bold" fill="#111">'
        f'Hackerman corpus growth: Wave-0 baseline -&gt; EOY-2026'
        f'</text>'
    )
    out.append(
        f'<text x="{CHART_WIDTH / 2:.0f}" y="48" '
        f'text-anchor="middle" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="12" '
        f'fill="#444">'
        f'PR #724 baseline -&gt; Wave-1 close -&gt; Wave-2/3/4 projected -&gt; EOY worst/best'
        f'</text>'
    )

    # Plot area background.
    out.append(
        f'<rect x="{MARGIN_LEFT}" y="{MARGIN_TOP}" '
        f'width="{PLOT_WIDTH}" height="{PLOT_HEIGHT}" '
        f'fill="#f9fafb" stroke="#d1d5db" stroke-width="1"/>'
    )

    # Y gridlines + labels.
    ticks = _y_ticks(y_max, n=6)
    for t in ticks:
        y = _y_position(t, y_max)
        out.append(
            f'<line x1="{MARGIN_LEFT}" y1="{y:.2f}" '
            f'x2="{MARGIN_LEFT + PLOT_WIDTH}" y2="{y:.2f}" '
            f'stroke="#e5e7eb" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{MARGIN_LEFT - 8}" y="{y + 4:.2f}" '
            f'text-anchor="end" '
            f'font-family="Helvetica, Arial, sans-serif" font-size="11" '
            f'fill="#374151">{_format_count(t)}</text>'
        )

    # Y axis label.
    out.append(
        f'<text x="20" y="{MARGIN_TOP + PLOT_HEIGHT / 2:.0f}" '
        f'transform="rotate(-90 20,{MARGIN_TOP + PLOT_HEIGHT / 2:.0f})" '
        f'text-anchor="middle" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="13" '
        f'fill="#111" font-weight="bold">Record count</text>'
    )

    # X axis labels (one per point, rotated 30deg to avoid collisions).
    for i, p in enumerate(s_total):
        x = p["x"]
        out.append(
            f'<line x1="{x:.2f}" y1="{MARGIN_TOP + PLOT_HEIGHT}" '
            f'x2="{x:.2f}" y2="{MARGIN_TOP + PLOT_HEIGHT + 6}" '
            f'stroke="#9ca3af" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x:.2f}" y="{MARGIN_TOP + PLOT_HEIGHT + 22:.2f}" '
            f'transform="rotate(30 {x:.2f},{MARGIN_TOP + PLOT_HEIGHT + 22:.2f})" '
            f'text-anchor="start" '
            f'font-family="Helvetica, Arial, sans-serif" font-size="11" '
            f'fill="#374151">'
            f'{_xml_escape(p["label"])} ({_xml_escape(p["date"])})'
            f'</text>'
        )

    # X axis label.
    out.append(
        f'<text x="{MARGIN_LEFT + PLOT_WIDTH / 2:.0f}" '
        f'y="{CHART_HEIGHT - 12}" '
        f'text-anchor="middle" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="13" '
        f'fill="#111" font-weight="bold">Milestone (date)</text>'
    )

    # Series: total (blue).
    out.append(
        f'<polyline points="{_polyline_points(s_total)}" '
        f'fill="none" stroke="#1d4ed8" stroke-width="2.5" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
    )
    for p in s_total:
        out.append(
            f'<circle cx="{p["x"]:.2f}" cy="{p["y"]:.2f}" r="4" '
            f'fill="#1d4ed8" stroke="#ffffff" stroke-width="1.5">'
            f'<title>total {_xml_escape(p["label"])} '
            f'({_xml_escape(p["date"])}): {_format_count(p["value"])}</title>'
            f'</circle>'
        )
        out.append(
            f'<text x="{p["x"]:.2f}" y="{p["y"] - 10:.2f}" '
            f'text-anchor="middle" '
            f'font-family="Helvetica, Arial, sans-serif" font-size="10" '
            f'fill="#1d4ed8" font-weight="bold">{_format_count(p["value"])}</text>'
        )

    # Series: tier 1+2 (orange).
    out.append(
        f'<polyline points="{_polyline_points(s_tier)}" '
        f'fill="none" stroke="#ea580c" stroke-width="2.5" '
        f'stroke-linecap="round" stroke-linejoin="round" '
        f'stroke-dasharray="6,3"/>'
    )
    for p in s_tier:
        out.append(
            f'<circle cx="{p["x"]:.2f}" cy="{p["y"]:.2f}" r="4" '
            f'fill="#ea580c" stroke="#ffffff" stroke-width="1.5">'
            f'<title>tier_1+2 {_xml_escape(p["label"])} '
            f'({_xml_escape(p["date"])}): {_format_count(p["value"])}</title>'
            f'</circle>'
        )

    # Legend (top-right of plot area).
    legend_x = MARGIN_LEFT + PLOT_WIDTH - 220
    legend_y = MARGIN_TOP + 14
    out.append(
        f'<rect x="{legend_x}" y="{legend_y}" width="210" height="58" '
        f'fill="#ffffff" stroke="#d1d5db" stroke-width="1" '
        f'rx="4" ry="4"/>'
    )
    # total
    out.append(
        f'<line x1="{legend_x + 12}" y1="{legend_y + 20}" '
        f'x2="{legend_x + 42}" y2="{legend_y + 20}" '
        f'stroke="#1d4ed8" stroke-width="2.5"/>'
    )
    out.append(
        f'<text x="{legend_x + 50}" y="{legend_y + 24}" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="12" '
        f'fill="#111">total records</text>'
    )
    # tier 1+2
    out.append(
        f'<line x1="{legend_x + 12}" y1="{legend_y + 42}" '
        f'x2="{legend_x + 42}" y2="{legend_y + 42}" '
        f'stroke="#ea580c" stroke-width="2.5" '
        f'stroke-dasharray="6,3"/>'
    )
    out.append(
        f'<text x="{legend_x + 50}" y="{legend_y + 46}" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="12" '
        f'fill="#111">tier 1+2 records</text>'
    )

    out.append('</svg>')
    return "\n".join(out) + "\n"


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render Hackerman corpus growth SVG chart (PR #726 Wave-1)."
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Path to write the SVG output. If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit chart model as JSON to stdout instead of SVG (debug).",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="Pin the generator-timestamp comment (deterministic test runs).",
    )
    args = parser.parse_args(argv)

    if args.json:
        model = build_chart_model()
        # Strip raw 'points' tuple (not JSON-friendly) - re-emit as dicts.
        out = {
            "y_max": model["y_max"],
            "plot": model["plot"],
            "points": [
                {"label": p[0], "date": p[1], "total": p[2], "tier_1_plus_2": p[3]}
                for p in model["points"]
            ],
            "series": model["series"],
        }
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    svg = render_svg(generated_at=args.generated_at)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(svg, encoding="utf-8")
        print(f"wrote {out_path} ({len(svg.encode('utf-8'))} bytes)")
    else:
        sys.stdout.write(svg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
