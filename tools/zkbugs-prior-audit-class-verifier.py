#!/usr/bin/env python3
"""zkBugs prior-audit class verifier.

Classifies a candidate finding description against the curated zkBugs
prior-audit vulnerability class database. Returns DROP-class-b when the
finding matches a known prior-audit class above the similarity threshold,
or NOVEL-CANDIDATE otherwise.

Usage:
    python3 tools/zkbugs-prior-audit-class-verifier.py --list
    python3 tools/zkbugs-prior-audit-class-verifier.py --classify finding.md
    python3 tools/zkbugs-prior-audit-class-verifier.py --classify-stdin < finding.md
    python3 tools/zkbugs-prior-audit-class-verifier.py --classify finding.md --threshold 0.5
    python3 tools/zkbugs-prior-audit-class-verifier.py --classify finding.md --framework circom
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    import yaml  # type: ignore
    _YAML_OK = True
except ImportError:
    _YAML_OK = False


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLASS_DB = ROOT / "reference" / "zkbugs_prior_audit_classes.yaml"
DEFAULT_THRESHOLD = 0.4

# Map framework aliases to canonical DSL names used in the class DB
_FRAMEWORK_ALIASES: dict[str, str] = {
    "circom": "Circom",
    "halo2": "Halo2",
    "cairo": "Cairo",
    "plonky3": "Plonky3",
    "bellperson": "Bellperson",
    "arkworks": "Arkworks",
    "risc0": "risc0",
    "pil": "PIL",
    "gnark": "gnark",
}


def _load_class_db(path: Path) -> list[dict[str, Any]]:
    """Load the YAML class database; fall back to hand-parsing if PyYAML unavailable."""
    text = path.read_text(encoding="utf-8")
    if _YAML_OK:
        data = yaml.safe_load(text)
        if not isinstance(data, list):
            raise ValueError(f"Expected a YAML list in {path}")
        return data
    # Minimal fallback: parse class_id and keywords lines only
    classes: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    in_keywords = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- class_id:"):
            if current:
                classes.append(current)
            current = {"class_id": stripped.split(":", 1)[1].strip(), "keywords": [], "name": "", "frameworks": [], "description": ""}
            in_keywords = False
        elif stripped.startswith("name:") and current:
            current["name"] = stripped.split(":", 1)[1].strip().strip('"')
            in_keywords = False
        elif stripped.startswith("description:") and current:
            current["description"] = stripped.split(":", 1)[1].strip()
            in_keywords = False
        elif stripped.startswith("frameworks:") and current:
            in_keywords = False
            # Inline list: frameworks: [Circom, Halo2]
            m = re.search(r"\[([^\]]*)\]", stripped)
            if m:
                current["frameworks"] = [f.strip() for f in m.group(1).split(",") if f.strip()]
        elif stripped.startswith("keywords:") and current:
            in_keywords = True
        elif in_keywords and stripped.startswith("- "):
            kw = stripped[2:].strip().strip('"').strip("'")
            current["keywords"].append(kw)
        elif stripped.startswith("severity_class:") and current:
            current["severity_class"] = stripped.split(":", 1)[1].strip()
            in_keywords = False
    if current:
        classes.append(current)
    return classes


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumeric boundaries, remove stopwords."""
    _STOPWORDS = {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "shall", "can", "to", "of", "in", "on",
        "at", "by", "for", "with", "without", "from", "into", "through",
        "during", "before", "after", "above", "below", "between", "this",
        "that", "these", "those", "or", "and", "not", "no", "nor", "but",
        "if", "when", "than", "so", "yet", "it", "its", "it's", "as",
    }
    raw = re.split(r"[^a-z0-9_\-]+", text.lower())
    return [t for t in raw if t and t not in _STOPWORDS and len(t) > 1]


def _build_idf(classes: list[dict[str, Any]]) -> dict[str, float]:
    """Build IDF weights from keyword fields across all classes."""
    doc_count: dict[str, int] = {}
    n_docs = len(classes)
    for cls in classes:
        keywords = cls.get("keywords") or []
        desc = str(cls.get("description") or "")
        tokens = set(_tokenize(" ".join(str(k) for k in keywords) + " " + desc))
        for t in tokens:
            doc_count[t] = doc_count.get(t, 0) + 1
    idf: dict[str, float] = {}
    for term, count in doc_count.items():
        idf[term] = math.log((n_docs + 1) / (count + 1)) + 1.0  # smoothed
    return idf


def _tf_vec(tokens: list[str]) -> dict[str, float]:
    freq: dict[str, int] = {}
    for t in tokens:
        freq[t] = freq.get(t, 0) + 1
    total = max(len(tokens), 1)
    return {t: c / total for t, c in freq.items()}


def _cosine(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    dot = sum(vec_a.get(t, 0.0) * v for t, v in vec_b.items())
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _class_tfidf_vec(cls: dict[str, Any], idf: dict[str, float]) -> dict[str, float]:
    keywords: list[str] = cls.get("keywords") or []
    desc = str(cls.get("description") or "")
    name = str(cls.get("name") or "")
    all_text = " ".join(str(k) for k in keywords) + " " + desc + " " + name
    tokens = _tokenize(all_text)
    tf = _tf_vec(tokens)
    return {t: tf_val * idf.get(t, 1.0) for t, tf_val in tf.items()}


def _doc_tfidf_vec(text: str, idf: dict[str, float]) -> dict[str, float]:
    tokens = _tokenize(text)
    tf = _tf_vec(tokens)
    return {t: tf_val * idf.get(t, 1.0) for t, tf_val in tf.items()}


def _keyword_boost(cls: dict[str, Any], doc_text: str) -> float:
    """Exact-keyword bonus: 0.15 per keyword phrase found in document."""
    keywords: list[str] = cls.get("keywords") or []
    doc_lower = doc_text.lower()
    hits = sum(1 for kw in keywords if str(kw).lower() in doc_lower)
    # Normalize: cap at 1.0, each keyword adds 0.15 raw score
    return min(hits * 0.15, 0.6)


def classify_text(
    text: str,
    classes: list[dict[str, Any]],
    idf: dict[str, float],
    *,
    threshold: float = DEFAULT_THRESHOLD,
    framework: str | None = None,
) -> list[dict[str, Any]]:
    """Return scored classification results sorted by score descending."""
    canonical_fw = _FRAMEWORK_ALIASES.get((framework or "").lower())
    doc_vec = _doc_tfidf_vec(text, idf)
    results: list[dict[str, Any]] = []
    for cls in classes:
        # Framework filter: skip if framework specified and class doesn't include it
        if canonical_fw:
            cls_frameworks = [str(f) for f in (cls.get("frameworks") or [])]
            if cls_frameworks and canonical_fw not in cls_frameworks:
                continue
        cls_vec = _class_tfidf_vec(cls, idf)
        tfidf_score = _cosine(doc_vec, cls_vec)
        boost = _keyword_boost(cls, text)
        # Weighted blend: 60% TF-IDF cosine + 40% keyword boost
        combined = 0.6 * tfidf_score + 0.4 * boost
        results.append({
            "class_id": cls.get("class_id", ""),
            "name": cls.get("name", ""),
            "severity_class": cls.get("severity_class", ""),
            "tfidf_score": round(tfidf_score, 4),
            "keyword_boost": round(boost, 4),
            "combined_score": round(combined, 4),
            "verdict": "DROP-class-b" if combined >= threshold else "NOVEL-CANDIDATE",
        })
    results.sort(key=lambda r: -r["combined_score"])
    return results


def cmd_list(classes: list[dict[str, Any]], *, json_out: bool = False) -> None:
    if json_out:
        print(json.dumps([
            {
                "class_id": cls.get("class_id"),
                "name": cls.get("name"),
                "severity_class": cls.get("severity_class"),
                "frameworks": cls.get("frameworks"),
                "keyword_count": len(cls.get("keywords") or []),
            }
            for cls in classes
        ], indent=2))
        return
    print(f"{'CLASS_ID':<50} {'SEVERITY':<10} FRAMEWORKS")
    print("-" * 90)
    for cls in classes:
        fws = ", ".join(str(f) for f in (cls.get("frameworks") or []))
        print(f"{cls.get('class_id',''):<50} {cls.get('severity_class',''):<10} {fws}")
    print(f"\nTotal: {len(classes)} classes")


def cmd_classify(
    text: str,
    classes: list[dict[str, Any]],
    idf: dict[str, float],
    *,
    threshold: float,
    framework: str | None,
    top_n: int = 5,
    json_out: bool = False,
) -> int:
    """Classify text; return 0 for NOVEL-CANDIDATE, 1 for DROP-class-b."""
    results = classify_text(text, classes, idf, threshold=threshold, framework=framework)
    top = results[:top_n]
    top_verdict = top[0]["verdict"] if top else "NOVEL-CANDIDATE"

    if json_out:
        print(json.dumps({
            "verdict": top_verdict,
            "threshold": threshold,
            "framework_filter": framework,
            "top_matches": top,
        }, indent=2))
    else:
        verdict_label = top_verdict
        print(f"Verdict: {verdict_label}")
        print(f"Threshold: {threshold}")
        if framework:
            print(f"Framework filter: {framework}")
        print()
        print(f"{'RANK':<5} {'CLASS_ID':<45} {'COMBINED':>8} {'TFIDF':>8} {'KW_BOOST':>9} VERDICT")
        print("-" * 100)
        for i, r in enumerate(top, 1):
            print(
                f"{i:<5} {r['class_id']:<45} {r['combined_score']:>8.4f} "
                f"{r['tfidf_score']:>8.4f} {r['keyword_boost']:>9.4f} {r['verdict']}"
            )
        if top and top[0]["verdict"] == "DROP-class-b":
            print(f"\n  Best match: {top[0]['name']}")

    return 1 if top_verdict == "DROP-class-b" else 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--class-db", type=Path, default=DEFAULT_CLASS_DB,
                        help="Path to zkbugs_prior_audit_classes.yaml (default: reference/)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List all classes")
    group.add_argument("--classify", metavar="FILE", help="Classify a finding file")
    group.add_argument("--classify-stdin", action="store_true", help="Read finding from stdin")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"DROP-class-b threshold (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--framework", metavar="DSL",
                        help="Filter classes to this framework (circom|halo2|cairo|plonky3|...)")
    parser.add_argument("--top", type=int, default=5, help="Number of top matches to show (default: 5)")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Output JSON")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.class_db.is_file():
        print(f"[zkbugs-prior-audit-class-verifier] ERR class DB not found: {args.class_db}",
              file=sys.stderr)
        return 2
    classes = _load_class_db(args.class_db)
    if not classes:
        print("[zkbugs-prior-audit-class-verifier] ERR empty class DB", file=sys.stderr)
        return 2

    idf = _build_idf(classes)

    if args.list:
        cmd_list(classes, json_out=args.json_out)
        return 0

    if args.classify_stdin:
        text = sys.stdin.read()
    else:
        classify_path = Path(args.classify)
        if not classify_path.is_file():
            print(f"[zkbugs-prior-audit-class-verifier] ERR file not found: {classify_path}",
                  file=sys.stderr)
            return 2
        text = classify_path.read_text(encoding="utf-8")

    return cmd_classify(
        text,
        classes,
        idf,
        threshold=args.threshold,
        framework=args.framework,
        top_n=args.top,
        json_out=args.json_out,
    )


if __name__ == "__main__":
    raise SystemExit(main())
