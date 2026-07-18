#!/usr/bin/env python3
"""cross-workspace-lookup.py — Phase 38

Query prior submitted findings across READ-ONLY sister audit workspaces under
~/audits/. Used during `make engage`: when a detector fires on
(contract, function), ask "have we seen this exact pattern in another
workspace's prior submissions?"

  ~/audits/<ws>/SUBMISSIONS.md            (centrifuge-v3, kiln-v1, snowbridge)
  ~/audits/<ws>/submissions/SUBMISSIONS.md (polymarket, morpho)

Stdlib only. Re-indexes on every invocation (corpus is small).

CLI:
  cross-workspace-lookup.py --contract <Name> --function <name>
                            [--workspaces all|<ws>,<ws>] [--top 5] [--export-json]
  cross-workspace-lookup.py --query "free text"
                            [--workspaces ...] [--top 5] [--export-json]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

AUDITS_ROOT = Path(os.environ.get("AUDITOOOR_AUDITS_ROOT", Path.home() / "audits"))
KNOWN_WORKSPACES = ["polymarket", "centrifuge-v3", "morpho", "kiln-v1", "snowbridge", "k2"]

# Section headers in SUBMISSIONS.md that delimit a finding block.
# Findings tend to be `## ` (top-level) or `### ` (sub-finding inside a wrapper).
HEADER_RE = re.compile(r"^(#{2,4})\s+(.+?)\s*$", re.M)
STOPWORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "any", "has",
    "was", "via", "with", "from", "this", "that", "into", "when", "than", "then",
    "there", "their", "have", "been", "will", "what", "which", "would", "could",
    "should", "such", "also", "where", "while", "they", "them", "these", "those",
    "above", "below", "after", "before", "does", "doing", "done", "off",
}
SECTION_BLACKLIST = {
    "submitted to cantina",
    "active submissions",
    "ready to submit",
    "not submitted",
    "out of scope",
    "totals",
    "legend",
    "tracker format",
    "status",
    "footnotes",
    "appendix",
    "6-point rubric review",
    "form-ready drafts",
    "form-ready index",
}


def tokenize(text: str) -> list[str]:
    text = text.lower()
    # Keep camelCase pieces by splitting on non-alphanumeric; also explode dashes.
    raw = re.split(r"[^a-z0-9_]+", text)
    out: list[str] = []
    for tok in raw:
        if not tok:
            continue
        # also split snake_case for partial matches; keep both whole + parts
        if "_" in tok:
            for sub in tok.split("_"):
                if sub and len(sub) >= 3 and sub not in STOPWORDS:
                    out.append(sub)
        if len(tok) >= 3 and tok not in STOPWORDS:
            out.append(tok)
    return out


def split_camel(name: str) -> list[str]:
    """CollateralToken -> ['collateraltoken','collateral','token']."""
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+", name)
    out = [name.lower()]
    out.extend(p.lower() for p in parts if p and len(p) >= 3)
    return out


def detect_current_workspace() -> str | None:
    cwd = Path.cwd().resolve()
    try:
        rel = cwd.relative_to(AUDITS_ROOT.resolve())
        return rel.parts[0] if rel.parts else None
    except ValueError:
        return None


def find_submissions_path(ws: str) -> Path | None:
    a = AUDITS_ROOT / ws / "SUBMISSIONS.md"
    if a.is_file():
        return a
    b = AUDITS_ROOT / ws / "submissions" / "SUBMISSIONS.md"
    if b.is_file():
        return b
    return None


def parse_findings(ws: str, path: Path) -> list[dict]:
    """Split SUBMISSIONS.md into per-finding dicts.

    A finding = `## ` or `### ` header whose title is not in SECTION_BLACKLIST
    and contains either an em-dash, a colon, or function-call backtick — i.e.
    looks like a finding title rather than a structural section.
    """
    text = path.read_text(errors="replace")
    headers = list(HEADER_RE.finditer(text))
    findings: list[dict] = []
    for i, m in enumerate(headers):
        level = len(m.group(1))
        title = m.group(2).strip()
        title_low = title.lower()
        if any(b in title_low for b in SECTION_BLACKLIST):
            continue
        # Heuristic: a finding title is descriptive (>= 25 chars) or contains
        # a backtick (function/contract reference) or an em-dash.
        if len(title) < 25 and "`" not in title and "—" not in title and "-" not in title[3:]:
            continue
        # Skip headers that are pure "## N. Section name" enumerations.
        if re.match(r"^\d+\.\s+[A-Z][a-z]+\s+", title) and len(title) < 50:
            continue
        body_start = m.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[body_start:body_end].strip()
        summary = re.sub(r"\s+", " ", body)[:300]
        findings.append({
            "workspace": ws,
            "title": title,
            "summary": summary,
            "level": level,
            "source": str(path),
        })
    return findings


def build_index() -> list[dict]:
    docs: list[dict] = []
    for ws in KNOWN_WORKSPACES:
        p = find_submissions_path(ws)
        if p is None:
            continue
        docs.extend(parse_findings(ws, p))
    return docs


def build_tfidf(docs: list[dict]) -> tuple[list[dict[str, float]], dict[str, float]]:
    tokens_per_doc = [tokenize(f"{d['title']} {d['summary']}") for d in docs]
    N = max(1, len(docs))
    df: Counter = Counter()
    for toks in tokens_per_doc:
        for t in set(toks):
            df[t] += 1
    idf = {t: math.log((N + 1) / (c + 1)) + 1.0 for t, c in df.items()}
    vecs: list[dict[str, float]] = []
    for toks in tokens_per_doc:
        if not toks:
            vecs.append({})
            continue
        tf = Counter(toks)
        L = sum(tf.values())
        v = {t: (n / L) * idf.get(t, 0.0) for t, n in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs.append({t: x / norm for t, x in v.items()})
    return vecs, idf


def query_vec(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
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


def rationale(query_tokens: set[str], doc: dict) -> str:
    doc_tokens = set(tokenize(f"{doc['title']} {doc['summary']}"))
    overlap = sorted(query_tokens & doc_tokens, key=len, reverse=True)[:6]
    if not overlap:
        return "weak match (no shared tokens, vector partial)"
    return "shared: " + ", ".join(overlap)


def main() -> int:
    ap = argparse.ArgumentParser(description="Cross-workspace finding lookup")
    ap.add_argument("--contract", help="Contract name (e.g. CollateralToken)")
    ap.add_argument("--function", help="Function name (e.g. unwrap)")
    ap.add_argument("--query", help="Free-text query (overrides contract/function)")
    ap.add_argument("--workspaces", default="all",
                    help="Comma list, or 'all' (default). Excludes current workspace.")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--export-json", action="store_true",
                    help="Emit JSON for `make engage` consumption")
    ap.add_argument("--include-self", action="store_true",
                    help="Don't exclude current workspace (for sanity testing)")
    args = ap.parse_args()

    if not AUDITS_ROOT.exists():
        print(f"[xws-lookup] SKIPPED — {AUDITS_ROOT} does not exist", file=sys.stderr)
        return 0

    if not args.query and not (args.contract or args.function):
        ap.error("provide --query OR at least one of --contract/--function")

    # Build query token list
    if args.query:
        q_tokens = tokenize(args.query)
    else:
        q_tokens = []
        if args.contract:
            q_tokens.extend(split_camel(args.contract))
        if args.function:
            q_tokens.extend(split_camel(args.function))

    docs = build_index()
    if not docs:
        msg = "[xws-lookup] no SUBMISSIONS.md indexed (audits/ is empty?)"
        if args.export_json:
            print(json.dumps({"matches": [], "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 0

    # Workspace filter
    current = detect_current_workspace()
    if args.workspaces.lower() == "all":
        wanted = set(KNOWN_WORKSPACES)
    else:
        wanted = {w.strip() for w in args.workspaces.split(",") if w.strip()}
    if current and not args.include_self:
        wanted.discard(current)

    docs = [d for d in docs if d["workspace"] in wanted]
    coverage = sorted({d["workspace"] for d in docs})

    if not docs:
        msg = f"[xws-lookup] no findings after workspace filter (wanted={sorted(wanted)})"
        if args.export_json:
            print(json.dumps({"matches": [], "coverage": coverage, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 0

    vecs, idf = build_tfidf(docs)
    qv = query_vec(q_tokens, idf)

    scored = []
    qset = set(q_tokens)
    for doc, dv in zip(docs, vecs):
        score = cosine(qv, dv)
        if score <= 0.0:
            continue
        scored.append((score, doc))
    scored.sort(key=lambda x: -x[0])
    top = scored[: args.top]

    matches = []
    for score, doc in top:
        matches.append({
            "workspace": doc["workspace"],
            "title": doc["title"],
            "score": round(score, 4),
            "rationale": rationale(qset, doc),
            "source": doc["source"],
        })

    if args.export_json:
        print(json.dumps({
            "query_tokens": q_tokens,
            "current_workspace": current,
            "workspaces_indexed": coverage,
            "total_findings_indexed": len(docs),
            "matches": matches,
        }, indent=2))
        return 0

    qdesc = args.query or f"contract={args.contract} function={args.function}"
    print(f"[xws-lookup] query: {qdesc}")
    print(f"[xws-lookup] indexed {len(docs)} findings across {len(coverage)} workspaces: {coverage}")
    if current:
        excl = " (excluded)" if not args.include_self else " (included via --include-self)"
        print(f"[xws-lookup] current workspace: {current}{excl}")
    print()
    if not matches:
        print("[xws-lookup] NO MATCHES — novel combination in our corpus.")
        return 0
    print(f"[xws-lookup] top {len(matches)} matches:")
    for i, m in enumerate(matches, 1):
        print(f"  {i}. [{m['workspace']:14s}] score={m['score']:.4f}  {m['title']}")
        print(f"       {m['rationale']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
