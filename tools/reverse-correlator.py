#!/usr/bin/env python3
"""reverse-correlator.py — detector hit → ranked historical exploit anchors.

The forward correlator (exploit-chain-correlator.py) takes an exploit
postmortem and returns ranked detector classes. This is the REVERSE:
given a detector name (and optionally a code snippet / file), rank which
historical exploit anchors the hit most resembles. Used by `make engage`
to give the auditor instant context: "this looks like Euler/Cream/Curve
because <shared tokens>".

Usage:
    tools/reverse-correlator.py --detector <name> [--code <file>] [--top 5]
    tools/reverse-correlator.py --detector <name> --export-json

Anchor corpus: tools/exploit-anchor-fixtures/*.txt + the curated
expected_detectors list from tools/exploit-anchor-regression.py ANCHORS.

Stdlib only. Reuses tokenize / TF-IDF helpers from
tools/exploit-chain-correlator.py via in-process import.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
FIXTURES = TOOLS / "exploit-anchor-fixtures"

MIN_COSINE = 0.05  # below this we say "no close anchor"

# Postmortem URLs / refs for the bundled anchors (best-effort, used in output).
ANCHOR_REFS: dict[str, str] = {
    "kelp-rseth-2024": "https://medium.com/@KelpDAO (rseth bridge incident)",
    "euler-2023": "https://blog.euler.finance/euler-exploit-1.0-postmortem-43f5c47b4e",
    "curve-vyper-2023": "https://hackmd.io/@vyperlang/curve-vyper-070-074-incident",
    "cream-yusd-2021": "https://blog.cream.finance/c-r-e-a-m-finance-post-mortem-amp-exploit",
    "radiant-2024": "https://medium.com/@RadiantCapital",
    "sentiment-curve-2023": "https://medium.com/sentimentxyz/post-mortem",
    "beanstalk-2022": "https://bean.money/blog/beanstalk-governance-exploit",
    "nomad-bridge-2022": "https://medium.com/nomad-xyz/nomad-bridge-hack",
    "bitkeep-oracle-2022": "https://www.bitkeep.com (oracle staleness incident)",
    "wormhole-2022": "https://wormhole.com/security/incident-report",
    "mango-markets-2022": "https://blog.mango.markets/mango-incident-report",
    "the-dao-2016": "https://www.coindesk.com/learn/2016/06/25/understanding-the-dao-attack",
}


# ─── Load helpers from forward correlator + anchor registry ────────────────

def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def load_anchors() -> dict:
    mod = _load_module(TOOLS / "exploit-anchor-regression.py", "_anchor_reg")
    return mod.ANCHORS


# ─── Per-anchor document construction ──────────────────────────────────────

def build_anchor_docs(anchors: dict, classes: dict) -> dict[str, str]:
    """For each anchor: anchor-text + expected_detector names + their kw/desc.

    Returns slug → big text blob (used by tokenize()).
    """
    docs: dict[str, str] = {}
    for slug, cfg in anchors.items():
        fix = FIXTURES / cfg["fixture"]
        if not fix.exists():
            continue
        parts: list[str] = [fix.read_text(encoding="utf-8", errors="replace")]
        for det_name in cfg.get("expected_detectors", []):
            # detector name itself is signal — both kebab and split form
            parts.append(det_name)
            parts.append(det_name.replace("-", " "))
            meta = classes.get(det_name)
            if not meta:
                continue
            parts.append(" ".join(str(k) for k in meta.get("keywords", [])))
            parts.append(meta.get("description", ""))
        docs[slug] = "\n".join(parts)
    return docs


# ─── Detector hit → query document ─────────────────────────────────────────

def build_query_text(detector: str, classes: dict, code_path: Path | None) -> str:
    parts: list[str] = [detector, detector.replace("-", " ")]
    meta = classes.get(detector, {})
    if meta:
        parts.append(" ".join(str(k) for k in meta.get("keywords", [])))
        parts.append(meta.get("description", ""))
    else:
        # Unregistered detector — use just the name (still rankable).
        print(f"[warn] detector {detector!r} not in BUG_CLASSES; ranking on "
              f"name tokens only", file=sys.stderr)
    if code_path is not None:
        if not code_path.exists():
            print(f"[warn] --code path does not exist: {code_path}",
                  file=sys.stderr)
        else:
            parts.append(code_path.read_text(encoding="utf-8",
                                             errors="replace"))
    return "\n".join(parts)


# ─── Hand-rolled TF-IDF over the per-anchor corpus ─────────────────────────

def build_tfidf(docs: dict[str, str], tokenize) -> tuple[dict, dict]:
    tokens_per_doc: dict[str, list[str]] = {
        slug: tokenize(text) for slug, text in docs.items()
    }
    N = max(1, len(tokens_per_doc))
    df: Counter = Counter()
    for toks in tokens_per_doc.values():
        for t in set(toks):
            df[t] += 1
    idf = {t: math.log((N + 1) / (c + 1)) + 1.0 for t, c in df.items()}
    vecs: dict[str, dict[str, float]] = {}
    for slug, toks in tokens_per_doc.items():
        if not toks:
            vecs[slug] = {}
            continue
        tf = Counter(toks)
        L = sum(tf.values())
        v = {t: (n / L) * idf.get(t, 0.0) for t, n in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs[slug] = {t: x / norm for t, x in v.items()}
    return vecs, idf


def query_vec(tokens: list[str], idf: dict) -> dict[str, float]:
    if not tokens:
        return {}
    tf = Counter(tokens)
    L = sum(tf.values())
    v = {t: (n / L) * idf.get(t, 0.0) for t, n in tf.items() if t in idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {t: x / norm for t, x in v.items()}


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return sum(v * long_.get(k, 0.0) for k, v in short.items())


def matched_terms(q: dict[str, float], v: dict[str, float],
                  top_n: int = 8) -> list[str]:
    pairs = []
    for t, w in q.items():
        contrib = w * v.get(t, 0.0)
        if contrib > 0:
            pairs.append((contrib, t))
    pairs.sort(reverse=True)
    return [t for _, t in pairs[:top_n]]


# ─── Ranking ───────────────────────────────────────────────────────────────

def rank_anchors(detector: str, code_path: Path | None, classes: dict,
                 anchors: dict, fwd_mod, top: int) -> list[dict]:
    docs = build_anchor_docs(anchors, classes)
    if not docs:
        return []
    vecs, idf = build_tfidf(docs, fwd_mod.tokenize)
    q_text = build_query_text(detector, classes, code_path)
    q_tokens = fwd_mod.tokenize(q_text)
    q = query_vec(q_tokens, idf)
    rows: list[dict] = []
    for slug, vec in vecs.items():
        cos = cosine(q, vec)
        terms = matched_terms(q, vec)
        rows.append({
            "anchor": slug,
            "score": round(cos, 4),
            "matched_terms": terms,
            "url": ANCHOR_REFS.get(slug, ""),
            "expected_detectors": list(
                anchors[slug].get("expected_detectors", [])
            ),
        })
    rows.sort(key=lambda r: -r["score"])
    return rows[:top]


# ─── Output ────────────────────────────────────────────────────────────────

def one_line_explainer(row: dict) -> str:
    if row["score"] < MIN_COSINE:
        return f"no close anchor (score={row['score']:.3f} below {MIN_COSINE})"
    terms = ", ".join(row["matched_terms"][:5]) or "(no shared terms)"
    return (f"looks like {row['anchor']} because shared: {terms}")


def print_text(detector: str, rows: list[dict]) -> None:
    print()
    print("=" * 70)
    print(f"Reverse correlator: detector → historical exploit anchors")
    print("=" * 70)
    print(f"detector:    {detector}")
    print(f"anchors:     {len(rows)} ranked")
    print()
    if not rows or rows[0]["score"] < MIN_COSINE:
        print("(no anchor exceeded threshold — this looks novel)")
        print()
    for r in rows:
        marker = "  " if r["score"] >= MIN_COSINE else "* "
        print(f"{marker}[{r['score']:.4f}]  {r['anchor']}")
        print(f"      url:     {r['url'] or '(none)'}")
        print(f"      shared:  {', '.join(r['matched_terms']) or '(none)'}")
        print(f"      → {one_line_explainer(r)}")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Detector-hit → historical exploit-anchor ranker."
    )
    ap.add_argument("--detector", required=True,
                    help="Detector slug (must match BUG_CLASSES key for best "
                         "results).")
    ap.add_argument("--code", default=None,
                    help="Optional path to a code snippet/file to enrich "
                         "the query.")
    ap.add_argument("--top", type=int, default=5,
                    help="Show top-N anchors (default 5).")
    ap.add_argument("--export-json", action="store_true",
                    help="Emit machine-readable JSON to stdout.")
    args = ap.parse_args()

    fwd_mod = _load_module(
        TOOLS / "exploit-chain-correlator.py", "_fwd_correlator"
    )
    classes = fwd_mod.load_bug_classes()
    if not classes:
        print("[err] failed to load BUG_CLASSES", file=sys.stderr)
        return 2
    anchors = load_anchors()

    code_path = Path(args.code) if args.code else None
    rows = rank_anchors(args.detector, code_path, classes, anchors, fwd_mod,
                        args.top)

    if args.export_json:
        out = {
            "detector": args.detector,
            "code": str(code_path) if code_path else None,
            "min_cosine_threshold": MIN_COSINE,
            "anchors": [
                {**r, "explainer": one_line_explainer(r)} for r in rows
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        print_text(args.detector, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
