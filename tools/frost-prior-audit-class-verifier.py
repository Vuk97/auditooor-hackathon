#!/usr/bin/env python3
"""FROST prior-audit class verifier.

Loads a YAML database of known FROST bug classes (from Zcash NCC,
Trail of Bits, ZF RFC review notes, etc.) and classifies a candidate
finding via TF-IDF-like keyword-density scoring.

Verdicts:
  DROP-class-b      score >= threshold  -> already-known class in prior audit
  NOVEL-CANDIDATE   score <  threshold  -> not a clean match; do further review

Empirical anchor: PR #659 W2 hacker-brief demo on FROST-vs-Zcash upstream
fixes (4 DROP-class-b verdicts).

CLI:
  --list                emit all classes (JSON)
  --classify <path>     classify markdown file
  --classify-stdin      classify stdin text
  --threshold FLOAT     decision threshold (default 0.4)
  --top N               include top-N matches in --classify output (default 3)
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "ERROR: PyYAML not installed. pip install pyyaml\n"
    )
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = REPO_ROOT / "reference" / "frost_prior_audit_classes.yaml"
DEFAULT_THRESHOLD = 0.4

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def load_classes(db_path: Path) -> list[dict[str, Any]]:
    if not db_path.exists():
        raise FileNotFoundError(f"class DB not found: {db_path}")
    with db_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    classes = data.get("classes") or []
    if not isinstance(classes, list):
        raise ValueError(f"malformed DB: 'classes' must be a list, got {type(classes)}")
    return classes


def _compute_idf(classes: list[dict[str, Any]]) -> dict[str, float]:
    """IDF over keywords across all classes (document frequency)."""
    n_docs = max(len(classes), 1)
    df: dict[str, int] = {}
    for cls in classes:
        seen: set[str] = set()
        for kw in cls.get("keywords", []) or []:
            kwl = str(kw).lower()
            if kwl and kwl not in seen:
                df[kwl] = df.get(kwl, 0) + 1
                seen.add(kwl)
    # smoothed idf
    return {k: math.log((n_docs + 1) / (v + 1)) + 1.0 for k, v in df.items()}


def score_candidate(
    text: str, classes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return list of {class_id, score, hits} sorted by score desc.

    Scoring: for each class, sum tf*idf for class.keywords found in candidate
    tokens, normalized by the class's max-possible score (every keyword hit at
    least once). Final score is clamped to [0, 1].
    """
    tokens = _tokenize(text)
    if not tokens:
        return [
            {"class_id": cls["class_id"], "score": 0.0, "hits": []}
            for cls in classes
        ]
    tf: dict[str, int] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    idf = _compute_idf(classes)
    results: list[dict[str, Any]] = []
    for cls in classes:
        kws = [str(k).lower() for k in (cls.get("keywords") or [])]
        if not kws:
            results.append(
                {"class_id": cls["class_id"], "score": 0.0, "hits": []}
            )
            continue
        # raw tf*idf sum over hits
        raw = 0.0
        hits: list[str] = []
        for kw in kws:
            count = tf.get(kw, 0)
            if count > 0:
                # log-dampened tf
                raw += (1.0 + math.log(count)) * idf.get(kw, 1.0)
                hits.append(kw)
        # normalize: max possible = sum of idf over all class keywords
        # (each appearing exactly once with tf=1, log(1)=0 -> contribution = idf)
        max_possible = sum(idf.get(kw, 1.0) for kw in kws) or 1.0
        score = min(raw / max_possible, 1.0)
        results.append(
            {"class_id": cls["class_id"], "score": round(score, 4), "hits": hits}
        )
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def classify(
    text: str,
    classes: list[dict[str, Any]],
    threshold: float = DEFAULT_THRESHOLD,
    top_n: int = 3,
) -> dict[str, Any]:
    scored = score_candidate(text, classes)
    best = scored[0] if scored else {"class_id": None, "score": 0.0, "hits": []}
    verdict = "DROP-class-b" if best["score"] >= threshold else "NOVEL-CANDIDATE"
    return {
        "best_match_class_id": best["class_id"],
        "score": best["score"],
        "hits": best["hits"],
        "verdict": verdict,
        "threshold": threshold,
        "top": scored[:top_n],
    }


def _cmd_list(classes: list[dict[str, Any]]) -> int:
    # Emit a compact JSON line per class for readability under `head`.
    out = {
        "count": len(classes),
        "classes": [
            {
                "class_id": c["class_id"],
                "name": c.get("name", ""),
                "severity_class": c.get("severity_class", ""),
                "keywords": c.get("keywords", []),
                "prior_audit_refs": c.get("prior_audit_refs", []),
            }
            for c in classes
        ],
    }
    print(json.dumps(out, indent=2, sort_keys=False))
    return 0


def _cmd_classify(
    classes: list[dict[str, Any]],
    text: str,
    threshold: float,
    top_n: int,
) -> int:
    result = classify(text, classes, threshold=threshold, top_n=top_n)
    print(json.dumps(result, indent=2, sort_keys=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="FROST prior-audit class verifier"
    )
    p.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help=f"YAML class DB (default: {DEFAULT_DB})",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"DROP-class-b decision threshold (default: {DEFAULT_THRESHOLD})",
    )
    p.add_argument(
        "--top",
        type=int,
        default=3,
        help="include top-N matches in --classify output (default: 3)",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="emit all classes as JSON")
    g.add_argument(
        "--classify",
        metavar="FILE",
        type=Path,
        help="classify candidate finding from file",
    )
    g.add_argument(
        "--classify-stdin",
        action="store_true",
        help="classify candidate finding from stdin",
    )
    args = p.parse_args(argv)

    classes = load_classes(args.db)

    if args.list:
        return _cmd_list(classes)
    if args.classify:
        text = args.classify.read_text(encoding="utf-8")
        return _cmd_classify(classes, text, args.threshold, args.top)
    if args.classify_stdin:
        text = sys.stdin.read()
        return _cmd_classify(classes, text, args.threshold, args.top)
    return 1


if __name__ == "__main__":
    sys.exit(main())
