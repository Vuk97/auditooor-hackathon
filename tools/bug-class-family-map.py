#!/usr/bin/env python3
"""bug-class-family-map.py — cluster BUG_CLASSES into families via the
analogical-neighbour graph, emit a Markdown family map + SVG treemap.

Phase 34 follow-on to novel-bug-class-surfacer.py (Phase 32). Where the
parity report lists classes and DETECTOR_COVERAGE_MATRIX tabulates them by
topic × language, this tool shows *relationships* between classes:

  1. Load BUG_CLASSES from tools/parity-report.py.
  2. For each class, shell out to exploit-chain-correlator.py --analogical
     and capture the top-5 neighbours (by cosine).
  3. Agglomerative cluster (average-link, Jaccard distance on neighbour-
     sets) — stdlib only, tunable --threshold.
  4. Emit docs/BUG_CLASS_FAMILY_MAP.md with:
       - 10–15 top-level families
       - Member list per family (alphabetical) + 1-line description
       - Cross-family links (classes whose neighbour-set straddles two
         families)
       - Coverage matrix: family × language (Solidity / Rust) counts
  5. Emit docs/BUG_CLASS_FAMILY_MAP.html with an SVG treemap
     (squarified-lite layout, pure stdlib).
  6. Always exits 0 — advisory, never gating.

Usage:
    python3 tools/bug-class-family-map.py
    python3 tools/bug-class-family-map.py --threshold 0.25 --top-k 5
    python3 tools/bug-class-family-map.py --out-md <path> --out-html <path>
"""
from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORRELATOR = ROOT / "tools" / "exploit-chain-correlator.py"
PARITY = ROOT / "tools" / "parity-report.py"
SOL_PATTERNS = ROOT / "reference" / "patterns.dsl"
RUST_DETECTORS = ROOT / "detectors" / "rust_wave1"
DEFAULT_MD = ROOT / "docs" / "BUG_CLASS_FAMILY_MAP.md"
DEFAULT_HTML = ROOT / "docs" / "BUG_CLASS_FAMILY_MAP.html"


# ─── BUG_CLASSES loader (mirrors novel-bug-class-surfacer) ────────────────

def load_bug_classes() -> dict:
    src = PARITY.read_text()
    m = re.search(r"BUG_CLASSES\s*=\s*\{", src)
    if not m:
        return {}
    start = m.end() - 1
    depth, i = 0, start
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        i += 1
    else:
        return {}
    try:
        return eval(src[start:end], {"__builtins__": {}}, {})
    except Exception as e:
        print(f"[warn] eval BUG_CLASSES failed: {e}", file=sys.stderr)
        return {}


# ─── Per-class language counts (re-uses parity-report classify logic) ─────

def classify(name: str, classes: dict) -> list[str]:
    name_low = name.lower().replace("_", "-")
    matches = []
    for cls, meta in classes.items():
        for kw in meta.get("keywords", []):
            if kw in name_low:
                matches.append(cls)
                break
    return matches


def language_counts(classes: dict) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {
        n: {"solidity": 0, "rust": 0} for n in classes
    }
    if SOL_PATTERNS.exists():
        for p in SOL_PATTERNS.glob("*.yaml"):
            for cls in classify(p.stem, classes):
                counts[cls]["solidity"] += 1
    if RUST_DETECTORS.exists():
        for p in RUST_DETECTORS.glob("*.py"):
            if p.name.startswith("_"):
                continue
            for cls in classify(p.stem, classes):
                counts[cls]["rust"] += 1
    return counts


# ─── Analogical neighbour graph ───────────────────────────────────────────

def run_analogical(name: str, timeout: int = 30) -> list[dict]:
    try:
        out = subprocess.run(
            ["python3", str(CORRELATOR), "--analogical", name, "--export-json"],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        )
        if out.returncode != 0:
            return []
        data = json.loads(out.stdout or "{}")
        return data.get("analogs", []) or []
    except Exception:
        return []


def build_neighbour_sets(classes: dict, top_k: int) -> dict[str, set[str]]:
    nbrs: dict[str, set[str]] = {}
    names = list(classes.keys())
    for i, name in enumerate(names):
        analogs = run_analogical(name)
        nbrs[name] = {a.get("detector", "") for a in analogs[:top_k]
                      if a.get("detector")}
        if i % 25 == 0:
            print(f"[graph] {i}/{len(names)}", file=sys.stderr)
    return nbrs


# ─── Agglomerative clustering (average-link, Jaccard) ─────────────────────

def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    u = a | b
    if not u:
        return 1.0
    return 1.0 - (len(a & b) / len(u))


def agglomerative(nbrs: dict[str, set[str]], threshold: float
                  ) -> list[list[str]]:
    """Average-link agglomerative clustering. Returns list of clusters."""
    # singletons, each cluster = list of class-names; track union of neighbour-
    # sets per cluster for average-link distance.
    clusters: list[dict] = [
        {"members": [n], "nset": set(s)} for n, s in nbrs.items()
    ]
    # Include each node itself in its own neighbour-set (so closely-linked
    # pairs that name each other get distance 0).
    for c in clusters:
        c["nset"] |= set(c["members"])

    while True:
        best = None
        best_d = 1.01
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                d = jaccard(clusters[i]["nset"], clusters[j]["nset"])
                if d < best_d:
                    best_d = d
                    best = (i, j)
        if best is None or best_d > threshold:
            break
        i, j = best
        merged = {
            "members": clusters[i]["members"] + clusters[j]["members"],
            "nset": clusters[i]["nset"] | clusters[j]["nset"],
        }
        # delete higher index first
        del clusters[j]
        del clusters[i]
        clusters.append(merged)

    return [sorted(c["members"]) for c in clusters]


# ─── Family naming & descriptions ─────────────────────────────────────────

_STOP = {"the", "and", "with", "from", "that", "when", "into", "over", "only",
         "this", "both", "have", "has", "does", "been", "not", "for", "are"}


def family_name(members: list[str], classes: dict) -> tuple[str, str]:
    """Pick a representative name + description by shared tokens across
    member class names + keywords."""
    toks: dict[str, int] = defaultdict(int)
    for m in members:
        meta = classes.get(m, {})
        for w in re.split(r"[-_\s]+", m.lower()):
            if len(w) >= 4 and w not in _STOP:
                toks[w] += 1
        for kw in meta.get("keywords", []) or []:
            for w in re.split(r"[-_\s]+", str(kw).lower()):
                if len(w) >= 4 and w not in _STOP:
                    toks[w] += 1
    # rank by frequency then length
    ranked = sorted(toks.items(), key=lambda kv: (-kv[1], -len(kv[0])))
    top = [t for t, _ in ranked[:3]]
    if not top:
        top = [members[0]]
    name = "-".join(top[:2]) if len(members) > 1 else members[0]
    desc = (
        f"{len(members)} classes sharing primitives: "
        + ", ".join(top[:3])
    )
    return name, desc


# ─── Cross-family links ───────────────────────────────────────────────────

def cross_family_links(clusters: list[list[str]],
                       nbrs: dict[str, set[str]]) -> list[dict]:
    """A class spans two families if ≥2 of its top-5 neighbours live in a
    family other than its own."""
    cls_to_fam: dict[str, int] = {}
    for idx, members in enumerate(clusters):
        for m in members:
            cls_to_fam[m] = idx

    links = []
    for cls, neigh in nbrs.items():
        home = cls_to_fam.get(cls)
        if home is None:
            continue
        fam_tally: dict[int, int] = defaultdict(int)
        for n in neigh:
            f = cls_to_fam.get(n)
            if f is not None and f != home:
                fam_tally[f] += 1
        for f, count in fam_tally.items():
            if count >= 2:
                links.append({"class": cls, "home": home, "other": f,
                              "count": count})
    links.sort(key=lambda d: -d["count"])
    return links


# ─── Markdown emitter ─────────────────────────────────────────────────────

def emit_markdown(path: Path, families: list[dict], links: list[dict],
                  lang_counts: dict, classes: dict) -> None:
    lines = [
        "# Bug-Class Family Map",
        "",
        "Clusters BUG_CLASSES (registered in `tools/parity-report.py`) by",
        "agglomerative Jaccard over their top-5 analogical neighbours",
        "(via `tools/exploit-chain-correlator.py --analogical`).",
        "",
        "Complementary to `docs/DETECTOR_COVERAGE_MATRIX.md`, which tabulates",
        "topic × language. This map shows the *relationships* between",
        "classes — which ones belong to the same attack family.",
        "",
        "Generated by `tools/bug-class-family-map.py` (stdlib-only, advisory).",
        "",
        f"**Families:** {len(families)} · **Classes:** {sum(len(f['members']) for f in families)}",
        "",
        "## Families",
        "",
    ]
    for idx, fam in enumerate(families):
        lines.append(f"### F{idx:02d} · {fam['name']} ({len(fam['members'])})")
        lines.append("")
        lines.append(f"_{fam['description']}_")
        lines.append("")
        for m in fam["members"]:
            desc = classes.get(m, {}).get("description", "")
            desc = desc.split("—")[0].split(";")[0].strip()
            if len(desc) > 120:
                desc = desc[:117] + "…"
            lines.append(f"- `{m}` — {desc}")
        lines.append("")

    lines += ["## Cross-Family Links", "",
              "Classes whose analogical neighbour-set straddles ≥2 families.",
              "Candidates for promotion to a new family or for cross-refs.",
              ""]
    if links:
        lines.append("| class | home family | other family | shared neighbours |")
        lines.append("|-------|-------------|--------------|-------------------|")
        for l in links[:40]:
            lines.append(
                f"| `{l['class']}` | F{l['home']:02d} {families[l['home']]['name']} "
                f"| F{l['other']:02d} {families[l['other']]['name']} | {l['count']} |"
            )
    else:
        lines.append("_No cross-family links detected at this threshold._")
    lines.append("")

    lines += ["## Coverage: Family × Language", "",
              "| family | classes | Solidity detectors | Rust detectors |",
              "|--------|---------|--------------------|----------------|"]
    for idx, fam in enumerate(families):
        sol = sum(lang_counts.get(m, {}).get("solidity", 0)
                  for m in fam["members"])
        rust = sum(lang_counts.get(m, {}).get("rust", 0)
                   for m in fam["members"])
        lines.append(
            f"| F{idx:02d} {fam['name']} | {len(fam['members'])} | {sol} | {rust} |"
        )
    lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


# ─── SVG treemap (stdlib squarified-lite) ─────────────────────────────────

def emit_html(path: Path, families: list[dict], lang_counts: dict) -> None:
    W, H = 1100, 700
    # treemap sizes proportional to member count
    items = sorted(
        [(f["name"], len(f["members"]), f["members"]) for f in families],
        key=lambda t: -t[1],
    )
    total = sum(n for _, n, _ in items) or 1

    # squarified-lite: stripe by rows, widest-first.
    rects = []
    x, y = 0, 0
    row_h = max(60, H // max(1, len(items) // 3))
    remaining = items[:]
    while remaining:
        # one row ~= up to 4 families
        row = remaining[:4]
        remaining = remaining[4:]
        row_sum = sum(n for _, n, _ in row) or 1
        rx = 0
        for name, count, members in row:
            w = int(W * (count / row_sum))
            rects.append((rx, y, max(40, w), row_h, name, count, members))
            rx += w
        y += row_h
    # rescale vertically
    if rects:
        max_y = max(r[1] + r[3] for r in rects)
        if max_y > H:
            scale = H / max_y
            rects = [(r[0], int(r[1] * scale), r[2], max(30, int(r[3] * scale)),
                      r[4], r[5], r[6]) for r in rects]

    palette = ["#4e79a7", "#f28e2b", "#59a14f", "#e15759", "#76b7b2",
               "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
               "#1b9e77", "#d95f02", "#7570b3", "#e7298a", "#66a61e"]

    svg_parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" '
                 f'height="{H}" viewBox="0 0 {W} {H}">']
    for i, (rx, ry, rw, rh, name, count, members) in enumerate(rects):
        color = palette[i % len(palette)]
        tooltip = html.escape(
            f"{name} — {count} classes\n" + "\n".join(members[:12])
            + ("\n…" if len(members) > 12 else "")
        )
        svg_parts.append(
            f'<g><title>{tooltip}</title>'
            f'<rect x="{rx}" y="{ry}" width="{rw}" height="{rh}" '
            f'fill="{color}" stroke="#222" stroke-width="1"/>'
            f'<text x="{rx + 6}" y="{ry + 18}" fill="#fff" font-size="12" '
            f'font-family="system-ui,sans-serif">'
            f'{html.escape(name[:28])}</text>'
            f'<text x="{rx + 6}" y="{ry + 34}" fill="#fff" font-size="11" '
            f'font-family="system-ui,sans-serif" opacity="0.85">'
            f'{count} classes</text></g>'
        )
    svg_parts.append("</svg>")
    svg = "\n".join(svg_parts)

    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Bug-Class Family Map</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #111; }}
h1 {{ margin-bottom: 4px; }}
p.sub {{ color: #666; margin-top: 0; }}
.legend {{ margin-top: 16px; font-size: 13px; color: #333; }}
</style></head><body>
<h1>Bug-Class Family Map</h1>
<p class="sub">{len(families)} families · {sum(len(f['members']) for f in families)} classes · area ∝ class count · hover for members.</p>
{svg}
<p class="legend">Generated by <code>tools/bug-class-family-map.py</code>. See <a href="BUG_CLASS_FAMILY_MAP.md">Markdown companion</a>.</p>
</body></html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc)


# ─── Main ─────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.30,
                    help="Jaccard distance cutoff for merging (default 0.30)")
    ap.add_argument("--top-k", type=int, default=5,
                    help="Top-k analogical neighbours per class (default 5)")
    ap.add_argument("--out-md", type=Path, default=DEFAULT_MD)
    ap.add_argument("--out-html", type=Path, default=DEFAULT_HTML)
    ap.add_argument("--cache", type=Path, default=None,
                    help="Optional JSON cache for the neighbour graph")
    args = ap.parse_args()

    try:
        classes = load_bug_classes()
        if not classes:
            print("[info] no BUG_CLASSES registry found — nothing to do",
                  file=sys.stderr)
            return 0

        if args.cache and args.cache.exists():
            try:
                nbrs_raw = json.loads(args.cache.read_text())
                nbrs = {k: set(v) for k, v in nbrs_raw.items()}
                print(f"[cache] loaded {len(nbrs)} neighbour sets",
                      file=sys.stderr)
            except Exception:
                nbrs = build_neighbour_sets(classes, args.top_k)
        else:
            nbrs = build_neighbour_sets(classes, args.top_k)

        if args.cache:
            try:
                args.cache.write_text(json.dumps(
                    {k: sorted(v) for k, v in nbrs.items()}))
            except Exception:
                pass

        clusters = agglomerative(nbrs, args.threshold)
        # Sort families by size desc
        clusters.sort(key=lambda m: (-len(m), m[0] if m else ""))

        families = []
        for members in clusters:
            name, desc = family_name(members, classes)
            families.append({"name": name, "description": desc,
                             "members": members})

        lang_counts = language_counts(classes)
        links = cross_family_links(clusters, nbrs)

        emit_markdown(args.out_md, families, links, lang_counts, classes)
        emit_html(args.out_html, families, lang_counts)

        print(f"[ok] wrote {args.out_md} and {args.out_html}",
              file=sys.stderr)
        print(f"[ok] families={len(families)} classes={len(classes)} "
              f"cross_links={len(links)}", file=sys.stderr)
    except Exception as e:
        print(f"[warn] family-map failed: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
