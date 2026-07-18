#!/usr/bin/env python3
"""
pattern-dedupe.py — find semantically-similar DSL patterns (Issue #92).

Embeds each pattern's YAML description field with sentence-transformers,
pairwise cosine similarity, reports pairs above threshold for human review.

Usage:
    python3 tools/pattern-dedupe.py --threshold 0.85   # default
    python3 tools/pattern-dedupe.py --top 20           # top N similar pairs
    python3 tools/pattern-dedupe.py --export dedupe.md # markdown report
"""

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("need PyYAML: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"


def load_patterns():
    """Return list of (slug, text-to-embed)."""
    rows = []
    for f in sorted(PATTERNS_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        title = data.get("name") or f.stem
        desc = data.get("description") or ""
        # Concat title + desc — we want semantic dedupe over *what* the pattern is.
        text = f"{title}. {desc}"
        rows.append((f.stem, text))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.85)
    ap.add_argument("--top", type=int, default=0, help="show top N pairs regardless of threshold")
    ap.add_argument("--export", help="write markdown report to file")
    args = ap.parse_args()

    try:
        from sentence_transformers import SentenceTransformer, util
    except ImportError:
        print("need sentence-transformers: pip install sentence-transformers", file=sys.stderr)
        sys.exit(1)

    rows = load_patterns()
    print(f"[dedupe] loaded {len(rows)} patterns", file=sys.stderr)

    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [t for _, t in rows]
    slugs = [s for s, _ in rows]
    emb = model.encode(texts, convert_to_tensor=True, show_progress_bar=False)
    sim = util.cos_sim(emb, emb).cpu().numpy()

    pairs = []
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            pairs.append((sim[i][j].item(), slugs[i], slugs[j]))
    pairs.sort(reverse=True)

    if args.top:
        shown = pairs[: args.top]
    else:
        shown = [p for p in pairs if p[0] >= args.threshold]

    lines = []
    lines.append(f"# Pattern dedupe report")
    lines.append(f"Threshold: {args.threshold} | Pairs shown: {len(shown)} | Total patterns: {len(rows)}")
    lines.append("")
    lines.append("| Similarity | Pattern A | Pattern B |")
    lines.append("|---:|---|---|")
    for score, a, b in shown:
        lines.append(f"| {score:.3f} | `{a}` | `{b}` |")
    report = "\n".join(lines)

    if args.export:
        Path(args.export).write_text(report + "\n")
        print(f"[dedupe] wrote {args.export} ({len(shown)} pairs)")
    else:
        print(report)


if __name__ == "__main__":
    main()
