#!/usr/bin/env python3
"""novel-bug-class-surfacer.py — analogical-reasoning gap surfacer.

Complementary to tools/gap-analyzer.py (which is corpus-comparison based).
This tool treats the BUG_CLASSES registry as a similarity graph via the
`exploit-chain-correlator.py --analogical` primitive, and looks for:

  1. "Triangles with a missing vertex" — three classes A, B, C that are
     mutually analogical, where their shared-token neighbourhoods imply
     a fourth class D (a token-suffix / primitive variant) that is NOT
     present in the registry.
  2. Exploit-anchor mining gaps — for each public exploit fixture, if the
     correlator surfaces bug-phrases that no detector covers (via the same
     gap-surface heuristic), flag the phrase as a novel-class candidate.

Usage:
    python3 tools/novel-bug-class-surfacer.py
    python3 tools/novel-bug-class-surfacer.py --top 20
    python3 tools/novel-bug-class-surfacer.py --out docs/archive/NOVEL_BUG_CANDIDATES.md

Stdlib only. Shells out to tools/exploit-chain-correlator.py.
Surfaces patterns — does NOT invent bug classes.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORRELATOR = ROOT / "tools" / "exploit-chain-correlator.py"
PARITY = ROOT / "tools" / "parity-report.py"
FIXTURE_DIR = ROOT / "tools" / "exploit-anchor-fixtures"
DEFAULT_OUT = ROOT / "docs" / "NOVEL_BUG_CANDIDATES.md"


# ─── BUG_CLASSES loader (mirrors exploit-chain-correlator) ────────────────

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


# ─── Correlator shell-outs ────────────────────────────────────────────────

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


def run_gap_surface(path: Path, timeout: int = 30) -> list[dict]:
    try:
        out = subprocess.run(
            ["python3", str(CORRELATOR), str(path),
             "--gap-surface", "--export-json"],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        )
        if out.returncode != 0:
            return []
        rep = json.loads(out.stdout or "{}")
        return rep.get("gap_surface", []) or []
    except Exception:
        return []


# ─── Graph construction & triangle-with-missing-vertex detection ──────────

def build_graph(classes: dict, top_k: int = 10) -> dict[str, list[dict]]:
    graph: dict[str, list[dict]] = {}
    names = list(classes.keys())
    for i, name in enumerate(names):
        analogs = run_analogical(name)
        graph[name] = analogs[:top_k]
        if i % 25 == 0:
            print(f"[graph] {i}/{len(names)}", file=sys.stderr)
    return graph


def _tokset(meta: dict) -> set[str]:
    """Domain tokens for a class (name + keywords), minus trivia."""
    toks: set[str] = set()
    for word in re.split(r"[-_\s]+", (meta.get("_name") or "")):
        if len(word) >= 4:
            toks.add(word.lower())
    for kw in meta.get("keywords", []) or []:
        for w in re.split(r"[-_\s]+", str(kw).lower()):
            if len(w) >= 4:
                toks.add(w)
    return toks


def find_missing_vertices(graph: dict, classes: dict, limit: int = 40
                          ) -> list[dict]:
    """Scan every (A,B,C) mutual-neighbour triangle. Synthesise a candidate
    vertex D by combining the dominant shared primitive tokens that show up
    across the triangle but whose combo isn't a registered class name.
    """
    # Build quick neighbour lookup per node
    neighbours: dict[str, set[str]] = {
        n: {a["detector"] for a in graph.get(n, [])} for n in graph
    }
    # score weights by cosine for ranking later
    cos_map: dict[tuple, float] = {}
    for n, analogs in graph.items():
        for a in analogs:
            cos_map[(n, a["detector"])] = a["cosine"]

    candidates: dict[str, dict] = {}
    registered = {n.lower() for n in classes.keys()}

    nodes = list(neighbours.keys())
    for a in nodes:
        nbrs_a = neighbours[a]
        if len(nbrs_a) < 2:
            continue
        # pick triangle pairs inside a's neighbourhood that are also mutual
        for b, c in combinations(nbrs_a, 2):
            if b not in neighbours or c not in neighbours:
                continue
            if c not in neighbours[b] and b not in neighbours[c]:
                continue
            # token-intersection across the triangle (≥3 shared primitives)
            t_a = _tokset({**classes.get(a, {}), "_name": a})
            t_b = _tokset({**classes.get(b, {}), "_name": b})
            t_c = _tokset({**classes.get(c, {}), "_name": c})
            shared = t_a & t_b & t_c
            if len(shared) < 3:
                continue
            # surface the "odd token" — tokens in (a|b|c) that don't repeat
            # in others; combinations of these are candidate primitives
            odd_tokens: Counter = Counter()
            for t in (t_a ^ t_b) | (t_b ^ t_c) | (t_a ^ t_c):
                if t in shared:
                    continue
                if len(t) < 4:
                    continue
                odd_tokens[t] += 1
            top_odd = [t for t, _ in odd_tokens.most_common(3)]
            if len(top_odd) < 2:
                continue
            dsl_name = "-".join(sorted(top_odd[:2]) + sorted(shared)[:1])
            if dsl_name in registered:
                continue
            # synthesis score: cosine-sum across triangle edges + token fit
            score = (
                cos_map.get((a, b), 0) + cos_map.get((b, a), 0)
                + cos_map.get((a, c), 0) + cos_map.get((c, a), 0)
                + cos_map.get((b, c), 0) + cos_map.get((c, b), 0)
            ) + 0.1 * len(shared)

            key = dsl_name
            prior = candidates.get(key)
            if prior and prior["score"] >= score:
                continue
            candidates[key] = {
                "suggested_dsl": dsl_name,
                "triangle": [a, b, c],
                "shared_primitives": sorted(shared)[:8],
                "novel_tokens": top_odd,
                "score": round(score, 3),
                "source": "triangle",
            }
            if len(candidates) >= limit * 4:
                break
    ranked = sorted(candidates.values(), key=lambda r: -r["score"])
    return ranked[:limit]


# ─── Exploit-anchor surfaces ──────────────────────────────────────────────

def anchor_candidates(classes: dict) -> list[dict]:
    registered = {n.lower() for n in classes.keys()}
    out: list[dict] = []
    if not FIXTURE_DIR.is_dir():
        return out
    for p in sorted(FIXTURE_DIR.glob("*.txt")):
        gaps = run_gap_surface(p)
        for g in gaps:
            phrase = (g.get("phrase") or "").strip()
            if not phrase:
                continue
            slug = re.sub(r"[^a-z0-9]+", "-", phrase.lower()).strip("-")[:40]
            if not slug or slug in registered:
                continue
            out.append({
                "suggested_dsl": slug,
                "triangle": [g.get("best_nearby_detector", "")],
                "shared_primitives": [phrase],
                "novel_tokens": phrase.split()[:3],
                "score": 1.0 - float(g.get("best_nearby_cosine") or 0),
                "source": f"anchor:{p.stem}",
            })
    # dedupe by slug, keep max score
    by_slug: dict[str, dict] = {}
    for r in out:
        k = r["suggested_dsl"]
        if k not in by_slug or by_slug[k]["score"] < r["score"]:
            by_slug[k] = r
    return sorted(by_slug.values(), key=lambda r: -r["score"])


# ─── Render ───────────────────────────────────────────────────────────────

def rationale(cand: dict) -> str:
    triangle = ", ".join(cand["triangle"][:3]) or "(anchor fixture)"
    prims = ", ".join(cand["shared_primitives"][:5]) or "—"
    novel = ", ".join(cand["novel_tokens"][:3]) or "—"
    if cand["source"] == "triangle":
        return (
            f"Classes {triangle} cluster around shared primitives "
            f"[{prims}] and individually drift on novel tokens [{novel}]. "
            "The combination appears in the analogical graph but no class "
            "currently owns it — likely mineable as a sibling detector."
        )
    return (
        f"Exploit-anchor ({cand['source']}) surfaces phrase '{prims}' with no "
        f"covering detector (nearest: {triangle}). Mining candidate for a "
        "dedicated primitive."
    )


def action(cand: dict) -> str:
    if cand["score"] >= 2.0:
        return "dispatch agent to mine"
    if cand["score"] >= 1.0:
        return "run hypothesis-to-detector"
    return "gather more signal"


def render(candidates: list[dict], stats: dict) -> str:
    lines = [
        "# NOVEL_BUG_CANDIDATES",
        "",
        "Analogical-reasoning surface of classes that the BUG_CLASSES registry",
        "may be missing. Generated by `tools/novel-bug-class-surfacer.py`.",
        "",
        "**Complements** `tools/gap-analyzer.py` (which answers the same question",
        "via corpus-comparison). This tool looks *inside* the analogical graph",
        "of existing classes, and at public exploit-anchor fixtures.",
        "",
        "## Stats",
        f"- Classes scanned: {stats.get('classes', 0)}",
        f"- Triangle candidates: {stats.get('triangles', 0)}",
        f"- Anchor-fixture candidates: {stats.get('anchors', 0)}",
        f"- Total candidates surfaced: {stats.get('total', 0)}",
        "",
        "## Top Candidates",
        "",
    ]
    for i, c in enumerate(candidates, 1):
        lines += [
            f"### {i}. `{c['suggested_dsl']}`  (score={c['score']}, source={c['source']})",
            "",
            f"**Analogical neighbours:** {', '.join(c['triangle'][:3]) or '—'}",
            "",
            f"**Shared primitives:** {', '.join(c['shared_primitives'][:6]) or '—'}",
            "",
            f"**Novel tokens:** {', '.join(c['novel_tokens'][:3]) or '—'}",
            "",
            f"**Rationale:** {rationale(c)}",
            "",
            f"**Action:** {action(c)}",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    classes = load_bug_classes()
    if not classes:
        print("[err] could not load BUG_CLASSES", file=sys.stderr)
        return 2
    print(f"[surfacer] loaded {len(classes)} classes", file=sys.stderr)

    graph = build_graph(classes)
    triangles = find_missing_vertices(graph, classes, limit=args.top * 3)
    anchors = anchor_candidates(classes)

    combined = triangles + anchors
    combined.sort(key=lambda r: -r["score"])
    top = combined[: args.top]

    stats = {
        "classes": len(classes),
        "triangles": len(triangles),
        "anchors": len(anchors),
        "total": len(combined),
    }
    md = render(top, stats)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md)
    print(f"[surfacer] wrote {out_path}  (top {len(top)} of {len(combined)})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
