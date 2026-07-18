#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - static HTML / SVG snapshot.

Emits a single self-contained HTML file with embedded SVG charts summarising
the live state of the hackerman corpus tree (``audit/corpus_tags/tags/``).

Design constraints (from PR #726 spec):

- Single self-contained HTML file (<1MB).
- NO external dependencies: no JS frameworks, no remote fetches, no CDN
  links, no ``<script src>`` / ``<link rel=stylesheet href>`` to anything.
  All styles inline, all SVG inline.
- Pure HTML5 + inline SVG. Static, no JS required to view the page.
- Deterministic output: stable sort within every section so two consecutive
  runs over the same tree produce byte-identical HTML when ``--generated-at``
  is pinned (or env ``AUDITOOOR_CORPUS_SNAPSHOT_GENERATED_AT`` set).
- Accessibility: every SVG carries an ``aria-label`` describing the chart.

Sections (fixed order):

1. Header (schema, generated_at, tags_dir, total_records).
2. Corpus subtree record counts: top-25 horizontal bar chart.
3. Tier distribution: pie chart over ``verification_tier`` (tier-1 .. tier-5
   + no-tier).
4. Top-20 attack classes: horizontal bar chart.
5. Top-10 ``target_repo`` values: horizontal bar chart.
6. Honest-zero ecosystem summary: table enumerating ecosystems that the
   Wave-1 audit found to be honest-zero (no records, or only umbrella
   records), with the planned Wave-2 / Wave-6 mining lane.

The walker / aggregator logic reuses ``tools/hackerman-corpus-stats.py``
(imported as a sibling module) to avoid drift between the textual stats
report and this HTML snapshot.

CLI:

    python3 tools/hackerman-corpus-snapshot-html.py \\
      [--tags-dir <path>] \\
      [--out docs/HACKERMAN_CORPUS_SNAPSHOT_2026-05-16.html] \\
      [--generated-at <iso-ts>]

Wired into Makefile as ``make hackerman-corpus-snapshot-html``.
"""
from __future__ import annotations

import argparse
import datetime
import html
import importlib.util
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT = REPO_ROOT / "docs" / "HACKERMAN_CORPUS_SNAPSHOT_2026-05-16.html"
SCHEMA = "auditooor.hackerman_corpus_snapshot_html.v1"

TOP_N_SUBTREES = 25
TOP_N_ATTACK_CLASSES = 20
TOP_N_TARGET_REPOS = 10
MAX_OUTPUT_BYTES = 1_000_000  # <1MB hard cap per PR #726 spec.


# Honest-zero ecosystem inventory taken from docs/HACKERMAN_WAVE2_ROADMAP_2026-05-16.md
# §1.6. Static (Wave-1 audit verdict). Each row: (ecosystem, status, lane).
HONEST_ZERO_ECOSYSTEMS: list[tuple[str, str, str]] = [
    (
        "tendermint",
        "0 dedicated subtree (partial via cosmos-sdk-ibc)",
        "Wave-2: Tendermint GHSA / CVE miner",
    ),
    (
        "cosmos-sdk per-module (ibc-go, group, authz, gov, bank, staking)",
        "bundled under one umbrella; per-module disaggregation absent",
        "Wave-2: per-module disaggregator",
    ),
    (
        "near",
        "partial via Wave-6; not parity with EVM",
        "Wave-2: NEAR deep-mine",
    ),
    (
        "ink!",
        "partial via Wave-6; not parity with EVM",
        "Wave-2: ink! deep-mine",
    ),
    (
        "aleph-zero",
        "umbrella records only (L2-rollup-class)",
        "Wave-2: aleph-zero protocol-specific miner",
    ),
    (
        "mina",
        "umbrella records only (L2-rollup-class)",
        "Wave-2: mina protocol-specific miner",
    ),
    (
        "aztec",
        "umbrella records only (L2-rollup-class)",
        "Wave-2: aztec protocol-specific miner",
    ),
    (
        "linea per-rollup",
        "covered in aggregate by l2_rollup_advisories / l2_zkrollup",
        "Wave-2: per-rollup attribution miner",
    ),
    (
        "scroll per-rollup",
        "covered in aggregate by l2_rollup_advisories / l2_zkrollup",
        "Wave-2: per-rollup attribution miner",
    ),
    (
        "zksync-era per-rollup",
        "covered in aggregate by l2_rollup_advisories / l2_zkrollup",
        "Wave-2: per-rollup attribution miner",
    ),
    (
        "eigenlayer-avs per-operator",
        "Wave-5 restaking-LRT covers protocol layer only",
        "Wave-2: per-AVS-operator miner",
    ),
]


# ---------------------------------------------------------------------------
# Reuse the corpus-stats walker / loader so the two tools never drift.
# ---------------------------------------------------------------------------


def _load_stats_tool() -> Any:
    name = "_hackerman_corpus_stats_for_snapshot"
    if name in sys.modules:
        return sys.modules[name]
    tool_path = REPO_ROOT / "tools" / "hackerman-corpus-stats.py"
    spec = importlib.util.spec_from_file_location(name, str(tool_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {tool_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Aggregation tailored to the snapshot's five sections.
# ---------------------------------------------------------------------------


def build_snapshot_counts(tags_dir: Path) -> dict[str, Any]:
    """Walk the corpus and return deterministic per-section counts."""
    stats_tool = _load_stats_tool()
    subtree_records: Counter[str] = Counter()
    attack_class: Counter[str] = Counter()
    target_repo: Counter[str] = Counter()
    tier_hist: Counter[str] = Counter()
    total = 0

    for path, rec, _shape in stats_tool._walk_records(tags_dir):
        total += 1
        subtree = stats_tool._subtree_of(path, tags_dir)
        subtree_records[subtree] += 1
        ac = str(rec.get("attack_class") or "").strip() or "<missing-attack-class>"
        attack_class[ac] += 1
        tr = str(rec.get("target_repo") or "").strip() or "<missing-target-repo>"
        target_repo[tr] += 1
        tier = stats_tool._extract_verification_tier(rec)
        tier_key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        tier_hist[tier_key] += 1

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total,
        "subtree_records": _stable_top_n(subtree_records, TOP_N_SUBTREES),
        "attack_class_top": _stable_top_n(attack_class, TOP_N_ATTACK_CLASSES),
        "target_repo_top": _stable_top_n(target_repo, TOP_N_TARGET_REPOS),
        "tier_distribution": _stable_sorted_dict(tier_hist),
    }


def _stable_top_n(counter: Counter[str], n: int) -> list[tuple[str, int]]:
    items = [(k, int(v)) for k, v in counter.items() if k]
    items.sort(key=lambda kv: (-kv[1], kv[0]))
    return items[:n]


def _stable_sorted_dict(counter: Counter[str]) -> list[tuple[str, int]]:
    """Sort tier keys with a stable canonical order: tier-1..tier-5 then no-tier."""
    canonical = ["tier-1", "tier-2", "tier-3", "tier-4", "tier-5", "no-tier"]
    rows: list[tuple[str, int]] = []
    for key in canonical:
        if key in counter:
            rows.append((key, int(counter[key])))
    # Any other tier keys (defensive).
    for key in sorted(k for k in counter if k not in canonical):
        rows.append((key, int(counter[key])))
    return rows


# ---------------------------------------------------------------------------
# SVG primitives. No external dependencies; output is inline SVG fragments.
# ---------------------------------------------------------------------------


_BAR_PALETTE = [
    "#1f6feb", "#3081ed", "#4493f8", "#58a6ff", "#7cbcff",
    "#9ecbff", "#bedaff", "#cfe5ff",
]

_PIE_PALETTE = [
    "#1f6feb", "#2ea043", "#d29922", "#f85149", "#a371f7", "#8b949e",
]


def _svg_escape(s: str) -> str:
    return html.escape(str(s), quote=True)


def render_horizontal_bar_svg(
    items: list[tuple[str, int]],
    *,
    title: str,
    aria_label: str,
    bar_height: int = 18,
    bar_gap: int = 4,
    label_width: int = 240,
    value_pad: int = 8,
    chart_width: int = 460,
) -> str:
    """Emit a deterministic inline SVG horizontal bar chart.

    Items are drawn top-to-bottom in the order provided (caller controls sort).
    """
    if not items:
        return (
            f'<svg role="img" aria-label="{_svg_escape(aria_label)}" '
            f'class="auditooor-svg-bar" width="640" height="60" '
            f'xmlns="http://www.w3.org/2000/svg">'
            f'<title>{_svg_escape(title)}</title>'
            f'<desc>{_svg_escape(aria_label)}</desc>'
            f'<text x="10" y="30" font-family="monospace" font-size="13" '
            f'fill="#8b949e">(no data)</text>'
            f"</svg>"
        )
    max_val = max(v for _, v in items) or 1
    total_height = len(items) * (bar_height + bar_gap) + 20
    total_width = label_width + chart_width + 80
    parts: list[str] = []
    parts.append(
        f'<svg role="img" aria-label="{_svg_escape(aria_label)}" '
        f'class="auditooor-svg-bar" width="{total_width}" '
        f'height="{total_height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
    )
    parts.append(f"<title>{_svg_escape(title)}</title>")
    parts.append(f"<desc>{_svg_escape(aria_label)}</desc>")
    for idx, (name, value) in enumerate(items):
        y = 10 + idx * (bar_height + bar_gap)
        bar_w = int(round((value / max_val) * chart_width))
        color = _BAR_PALETTE[idx % len(_BAR_PALETTE)]
        text_y = y + bar_height - 5
        parts.append(
            f'<text x="{label_width - 6}" y="{text_y}" '
            f'font-family="monospace" font-size="12" fill="#c9d1d9" '
            f'text-anchor="end">{_svg_escape(name)}</text>'
        )
        parts.append(
            f'<rect x="{label_width}" y="{y}" width="{bar_w}" '
            f'height="{bar_height}" fill="{color}" '
            f'aria-hidden="true"></rect>'
        )
        parts.append(
            f'<text x="{label_width + bar_w + value_pad}" y="{text_y}" '
            f'font-family="monospace" font-size="12" fill="#c9d1d9">'
            f"{value}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def render_pie_svg(
    items: list[tuple[str, int]],
    *,
    title: str,
    aria_label: str,
    radius: int = 110,
) -> str:
    """Emit a deterministic inline SVG pie chart.

    Slice order = caller-provided order. Uses ``A`` arc commands; pure SVG.
    """
    if not items or sum(v for _, v in items) == 0:
        return (
            f'<svg role="img" aria-label="{_svg_escape(aria_label)}" '
            f'class="auditooor-svg-pie" width="320" height="60" '
            f'xmlns="http://www.w3.org/2000/svg">'
            f'<title>{_svg_escape(title)}</title>'
            f'<desc>{_svg_escape(aria_label)}</desc>'
            f'<text x="10" y="30" font-family="monospace" font-size="13" '
            f'fill="#8b949e">(no data)</text>'
            f"</svg>"
        )
    total = sum(v for _, v in items) or 1
    cx = radius + 10
    cy = radius + 10
    width = (radius + 10) * 2 + 280
    height = max((radius + 10) * 2, len(items) * 22 + 20)
    parts: list[str] = []
    parts.append(
        f'<svg role="img" aria-label="{_svg_escape(aria_label)}" '
        f'class="auditooor-svg-pie" width="{width}" '
        f'height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
    )
    parts.append(f"<title>{_svg_escape(title)}</title>")
    parts.append(f"<desc>{_svg_escape(aria_label)}</desc>")
    import math

    angle_start = -math.pi / 2.0
    for idx, (name, value) in enumerate(items):
        frac = value / total
        angle_end = angle_start + frac * 2.0 * math.pi
        x1 = cx + radius * math.cos(angle_start)
        y1 = cy + radius * math.sin(angle_start)
        x2 = cx + radius * math.cos(angle_end)
        y2 = cy + radius * math.sin(angle_end)
        large_arc = 1 if (angle_end - angle_start) > math.pi else 0
        color = _PIE_PALETTE[idx % len(_PIE_PALETTE)]
        if frac >= 0.999:
            # Single full-circle slice (degenerate); draw a circle.
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="{color}" '
                f"aria-hidden=\"true\"></circle>"
            )
        else:
            d = (
                f"M {cx:.2f} {cy:.2f} "
                f"L {x1:.2f} {y1:.2f} "
                f"A {radius} {radius} 0 {large_arc} 1 {x2:.2f} {y2:.2f} Z"
            )
            parts.append(
                f'<path d="{d}" fill="{color}" aria-hidden="true"></path>'
            )
        # Legend row.
        legend_x = (radius + 10) * 2 + 20
        legend_y = 20 + idx * 22
        pct = (value / total) * 100.0
        parts.append(
            f'<rect x="{legend_x}" y="{legend_y - 12}" width="14" '
            f'height="14" fill="{color}" aria-hidden="true"></rect>'
        )
        parts.append(
            f'<text x="{legend_x + 22}" y="{legend_y}" '
            f'font-family="monospace" font-size="12" fill="#c9d1d9">'
            f"{_svg_escape(name)}: {value} ({pct:.1f}%)</text>"
        )
        angle_start = angle_end
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML composition.
# ---------------------------------------------------------------------------


_INLINE_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
       background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }
h1 { color: #58a6ff; font-size: 22px; margin: 0 0 8px 0; }
h2 { color: #79c0ff; font-size: 17px; margin: 28px 0 10px 0;
     border-bottom: 1px solid #30363d; padding-bottom: 4px; }
table { border-collapse: collapse; margin: 8px 0 16px 0;
        font-family: monospace; font-size: 12px; }
th, td { border: 1px solid #30363d; padding: 6px 10px; text-align: left;
         vertical-align: top; }
th { background: #161b22; color: #58a6ff; }
.meta { font-family: monospace; font-size: 12px; color: #8b949e;
        margin-bottom: 16px; }
.meta code { color: #c9d1d9; }
.section-body { margin-left: 12px; }
.auditooor-svg-bar, .auditooor-svg-pie { display: block; margin: 6px 0; }
.footer { color: #8b949e; font-family: monospace; font-size: 11px;
          margin-top: 24px; border-top: 1px solid #30363d; padding-top: 10px; }
"""


def render_html(
    counts: dict[str, Any],
    honest_zero: list[tuple[str, str, str]],
    *,
    generated_at: str,
) -> str:
    subtree_items = counts["subtree_records"]
    tier_items = counts["tier_distribution"]
    attack_items = counts["attack_class_top"]
    repo_items = counts["target_repo_top"]
    total_records = counts["total_records"]
    tags_dir = counts["tags_dir"]
    schema = counts["schema"]

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append(
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
    )
    parts.append(
        "<title>Hackerman corpus snapshot - "
        f"{_svg_escape(generated_at)}</title>"
    )
    parts.append(f"<style>{_INLINE_CSS}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<h1>Hackerman corpus snapshot</h1>")
    parts.append(
        '<div class="meta">'
        f"schema: <code>{_svg_escape(schema)}</code><br>"
        f"generated_at: <code>{_svg_escape(generated_at)}</code><br>"
        f"tags_dir: <code>{_svg_escape(tags_dir)}</code><br>"
        f"total_records: <code>{total_records}</code><br>"
        f"branch: <code>wave-1-hackerman-capability-lift</code> "
        f"(PR #726)"
        "</div>"
    )

    # Section 1 - subtree record counts.
    parts.append('<h2>1. Corpus subtree record counts (top 25)</h2>')
    parts.append('<div class="section-body">')
    parts.append(
        render_horizontal_bar_svg(
            subtree_items,
            title="Corpus subtree record counts (top 25)",
            aria_label=(
                "Horizontal bar chart of the top 25 corpus subtrees by record "
                "count under audit/corpus_tags/tags."
            ),
        )
    )
    parts.append("</div>")

    # Section 2 - tier distribution pie.
    parts.append("<h2>2. Verification-tier distribution</h2>")
    parts.append('<div class="section-body">')
    parts.append(
        render_pie_svg(
            tier_items,
            title="Verification-tier distribution",
            aria_label=(
                "Pie chart of records by verification_tier (tier-1 to tier-5 "
                "plus no-tier)."
            ),
        )
    )
    parts.append("</div>")

    # Section 3 - top-20 attack classes.
    parts.append("<h2>3. Top-20 attack classes</h2>")
    parts.append('<div class="section-body">')
    parts.append(
        render_horizontal_bar_svg(
            attack_items,
            title="Top-20 attack classes",
            aria_label=(
                "Horizontal bar chart of the top 20 attack_class values "
                "across all hackerman corpus records."
            ),
        )
    )
    parts.append("</div>")

    # Section 4 - top-10 target_repos.
    parts.append("<h2>4. Top-10 target_repos</h2>")
    parts.append('<div class="section-body">')
    parts.append(
        render_horizontal_bar_svg(
            repo_items,
            title="Top-10 target_repos",
            aria_label=(
                "Horizontal bar chart of the top 10 target_repo values "
                "across all hackerman corpus records."
            ),
        )
    )
    parts.append("</div>")

    # Section 5 - honest-zero ecosystem table.
    parts.append("<h2>5. Honest-zero ecosystem summary</h2>")
    parts.append('<div class="section-body">')
    parts.append("<table>")
    parts.append(
        "<thead><tr><th>Ecosystem</th><th>Status</th><th>Planned mining lane</th></tr></thead>"
    )
    parts.append("<tbody>")
    for ecosystem, status, lane in honest_zero:
        parts.append(
            "<tr>"
            f"<td>{_svg_escape(ecosystem)}</td>"
            f"<td>{_svg_escape(status)}</td>"
            f"<td>{_svg_escape(lane)}</td>"
            "</tr>"
        )
    parts.append("</tbody></table>")
    parts.append("</div>")

    parts.append(
        '<div class="footer">'
        "Static HTML / inline SVG snapshot. No external links, no JS. "
        "Generated by tools/hackerman-corpus-snapshot-html.py "
        f"(schema {_svg_escape(schema)})."
        "</div>"
    )
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# CLI / generated_at resolver.
# ---------------------------------------------------------------------------


def _generated_at(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_CORPUS_SNAPSHOT_GENERATED_AT")
    if env:
        return env
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hackerman-corpus-snapshot-html")
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of hackerman corpus tag records.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output HTML path (default: docs/HACKERMAN_CORPUS_SNAPSHOT_2026-05-16.html).",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="Override generated_at timestamp.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Write HTML to stdout instead of --out.",
    )
    args = parser.parse_args(argv)

    tags_dir = args.tags_dir.resolve()
    if not tags_dir.is_dir():
        sys.stderr.write(
            f"[hackerman-corpus-snapshot-html] tags_dir not found: {tags_dir}\n"
        )
        return 2

    counts = build_snapshot_counts(tags_dir)
    generated_at = _generated_at(args.generated_at)
    html_text = render_html(counts, HONEST_ZERO_ECOSYSTEMS, generated_at=generated_at)
    payload = html_text.encode("utf-8")
    if len(payload) >= MAX_OUTPUT_BYTES:
        sys.stderr.write(
            f"[hackerman-corpus-snapshot-html] output exceeds 1MB cap: "
            f"{len(payload)} bytes\n"
        )
        return 3

    if args.stdout:
        sys.stdout.write(html_text)
    else:
        out = args.out.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(payload)
        sys.stderr.write(
            f"[hackerman-corpus-snapshot-html] wrote {out} ({len(payload)} bytes)\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
