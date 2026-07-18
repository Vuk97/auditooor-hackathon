#!/usr/bin/env python3
"""gap-analyzer.py — surface gaps between our detector library and recent audit findings.

Phase 12 of PR #84.

Input: a JSON corpus of findings (same format as mine-solodit.py output):
    [ {id, title, content, tags, severity, ...}, ... ]

For each finding:
  * Score every BUG_CLASS in our registry by keyword/token overlap (same logic
    as exploit-chain-correlator.py).
  * If the top score crosses --threshold, the finding is "covered".
  * Otherwise it is a "gap" — an attack class we may not have mined yet.

Writes a Markdown report to docs/GAP_ANALYSIS.md with:
  1. Summary (N scanned, M covered, K gaps, percentages).
  2. Gap table: id | title | top-3 near-misses (class + score).
  3. Covered findings tail sample (last 5-10).

Usage:
    python3 tools/gap-analyzer.py <corpus.json>
    python3 tools/gap-analyzer.py <corpus.json> --threshold 8
    python3 tools/gap-analyzer.py <corpus.json> --top 3
    python3 tools/gap-analyzer.py <corpus.json> --out docs/GAP_ANALYSIS.md
    python3 tools/gap-analyzer.py --smoke --out /tmp/gap-analysis-smoke.md
    python3 tools/gap-analyzer.py --smoke --manifest /tmp/smoke.json

Smoke mode:
    --smoke runs against a tiny hermetic in-memory fixture
    (see SMOKE_FINDINGS) that exercises all four buckets:
      - covered-keyword  : finding hits a Tier-A keyword-only class
      - covered-semantic : finding hits a class via the description
                           bigram (semantic-predicate) path
      - negative-clean   : benign prose; must score zero
      - gap-novel        : synthetic vocabulary; must score below threshold

    Smoke mode also writes a JSON manifest (default
    `<repo>/.auditooor/gap_analysis_smoke.json`) with per-finding score
    breakdowns and an `expected_violations` list. The manifest is loudly
    annotated as NOT a real-corpus parity measurement.

Exit codes:
    0 — report written (even if gaps found; gaps are informational).
    2 — failed to load corpus / registry.
    3 — --smoke mechanics check failed (an expectation was violated).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SMOKE_CORPUS_LABEL = "hermetic-smoke-fixture"
SMOKE_MANIFEST_SCHEMA = "auditooor.gap_analysis_smoke.v1"
SMOKE_DEFAULT_MANIFEST_REL = Path(".auditooor") / "gap_analysis_smoke.json"

# Each fixture finding is annotated with the role it plays in the smoke
# coverage matrix. We assert these expectations in the test suite so the
# fixture cannot silently regress.
#
# fixture_kind values:
#   "covered-keyword"   — Tier-A regex/keyword-only score should clear threshold
#                         (a single class wins on simple keyword overlap).
#   "covered-semantic"  — score must include description-bigram overlap
#                         (the "semantic predicate" path: kws + desc tokens
#                         + desc bigrams all contribute).
#   "negative-clean"    — benign prose; MUST NOT clear threshold for any class.
#   "gap-novel"         — synthetic vocabulary; exercises the gap branch.
SMOKE_FINDINGS = [
    {
        "id": "SMOKE-COVERED-REGEX-LIQUIDATION",
        "title": "Liquidation close-factor seize bad-debt rounding",
        "content": (
            "During liquidation the close-factor is applied before the "
            "health-factor recheck, so the liquidator can seize collateral "
            "that should have left bad-debt on the protocol."
        ),
        "tags": ["liquidation", "close-factor", "health-factor", "seize",
                 "bad-debt"],
        "protocol": "hermetic-smoke",
        "firm": "auditooor",
        "fixture_kind": "covered-keyword",
        # Tracked class to assert mechanics against (NOT a parity claim — the
        # registry has many sub-classes that may rank higher than the canonical
        # one; the assertion only checks that this canonical class fires).
        "expected_class_fires": "liquidation",
    },
    {
        "id": "SMOKE-COVERED-REENTRANCY",
        "title": "Callback reentrancy before CEI state update",
        "content": (
            "The withdraw path performs an external callback before updating "
            "state, allowing a reentrant call to drain funds."
        ),
        "tags": ["reentrancy", "cei", "callback"],
        "protocol": "hermetic-smoke",
        "firm": "auditooor",
        "fixture_kind": "covered-keyword",
        "expected_class_fires": "reentrancy",
    },
    {
        "id": "SMOKE-COVERED-SEMANTIC-ORACLE",
        "title": "Oracle freshness staleness cascade failure on spot-price read",
        "content": (
            "The price-feed integration with chainlink/pyth uses latestRound "
            "without verifying staleness/freshness. A stale spot-price read "
            "causes an oracle cascade failure during liquidation routing."
        ),
        "tags": ["oracle", "price-feed", "chainlink", "pyth", "staleness",
                 "freshness", "spot-price"],
        "protocol": "hermetic-smoke",
        "firm": "auditooor",
        "fixture_kind": "covered-semantic",
        "expected_class_fires": "oracle-cascade",
    },
    {
        "id": "SMOKE-NEGATIVE-CLEAN",
        "title": "Vfqf qzxpdr lmnbtu pqrstu xyzwvb",
        "content": (
            "Hgzqfb mnpvtw lkjqyx pqdsbn vbqxlm xyzwvb. Vbqxlm pqdsbn "
            "kjwxyz mnpvtw kqzpvb lkjqyx zxpdr xyzwvb qzxpdr."
        ),
        "tags": ["vfqf-qzxpdr", "xyzwvb"],
        "protocol": "hermetic-smoke",
        "firm": "auditooor",
        "fixture_kind": "negative-clean",
        "expected_class_fires": None,
    },
    {
        "id": "SMOKE-GAP-NOVEL",
        "title": "Frobnosticator lavender eclipse",
        "content": (
            "Synthetic zarpel blenno words intentionally avoid registry "
            "keywords so the smoke report exercises the gap table."
        ),
        "tags": ["frobnosticator", "zarpel-blenno"],
        "protocol": "hermetic-smoke",
        "firm": "auditooor",
        "fixture_kind": "gap-novel",
        "expected_class_fires": None,
    },
]

# Public smoke-mode contract — used by the test suite and by anyone
# inspecting the manifest. These are the invariants the smoke fixture
# must hold for the gap-analyzer mechanics to be considered "proven".
SMOKE_EXPECTATIONS: dict = {
    "min_covered": 3,           # at least 3 hits over threshold
    "min_negative_clean": 1,    # at least 1 finding scoring 0
    "min_gap_novel": 1,         # at least 1 finding below threshold (>0 ok)
    "regex_only_id": "SMOKE-COVERED-REENTRANCY",
    "semantic_id": "SMOKE-COVERED-SEMANTIC-ORACLE",
    "negative_id": "SMOKE-NEGATIVE-CLEAN",
    # Threshold the test asserts against; CLI default may shift but the
    # smoke contract pins this explicitly to keep CI deterministic.
    "threshold": 5,
}

# Stopwords — mirror exploit-chain-correlator.py so scoring is consistent.
STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "is", "it", "and", "or", "for",
    "on", "by", "with", "that", "this", "was", "are", "be", "as", "at",
    "from", "has", "have", "had", "not", "but", "can", "will", "would",
    "could", "should", "been", "were", "its", "if", "when", "then",
    "any", "all", "may", "more", "also", "one", "two", "new",
}


# ─── Tokenizer (copy from exploit-chain-correlator.py) ─────────────────────

def tokenize(text: str) -> list[str]:
    text = (text or "").lower()
    tokens = re.split(r"[^a-z0-9_\-]+", text)
    return [t for t in tokens if t and len(t) >= 3 and t not in STOPWORDS]


# ─── BUG_CLASSES loader (copy from exploit-chain-correlator.py) ────────────

def load_bug_classes() -> dict:
    """Import BUG_CLASSES from tools/parity-report.py without executing it."""
    parity = REPO / "tools" / "parity-report.py"
    if not parity.exists():
        return {}
    src = parity.read_text()
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
    literal = src[start:end]
    try:
        return eval(literal, {"__builtins__": {}}, {})
    except Exception as e:
        print(f"[warn] failed to eval BUG_CLASSES: {e}", file=sys.stderr)
        return {}


# ─── Scoring (copy from exploit-chain-correlator.py) ───────────────────────

def score_class(cls_meta: dict, tokens: set[str], bigrams: set[str]) -> int:
    desc = (cls_meta.get("description") or "").lower()
    kws = cls_meta.get("keywords", [])
    score = 0
    for kw in kws:
        for part in re.split(r"[-\s]+", kw.lower()):
            if len(part) >= 3 and part in tokens:
                score += 3
            if part in STOPWORDS:
                continue
    desc_tokens = set(tokenize(desc))
    score += len(desc_tokens & tokens)
    desc_bigrams = set(
        " ".join(p) for p in zip(tokenize(desc), tokenize(desc)[1:])
    )
    score += 2 * len(desc_bigrams & bigrams)
    return score


# ─── Per-finding analysis ──────────────────────────────────────────────────

def finding_text(f: dict) -> str:
    """Concatenate the fields we score against."""
    parts = [
        f.get("title") or "",
        f.get("content") or "",
        " ".join(f.get("tags") or []),
        f.get("protocol") or "",
        f.get("firm") or "",
    ]
    return " ".join(p for p in parts if p)


def analyse_finding(f: dict, classes: dict) -> list[tuple[int, str]]:
    """Return ranked [(score, class_name), ...] descending."""
    text = finding_text(f)
    toks = tokenize(text)
    tokens = set(toks)
    bigrams = {" ".join(p) for p in zip(toks, toks[1:])}
    ranked = []
    for name, meta in classes.items():
        s = score_class(meta, tokens, bigrams)
        if s > 0:
            ranked.append((s, name))
    # Stable sort: primary by score desc, secondary by class name asc.
    # Without the secondary key, two classes scoring equal could swap
    # positions across registry-order changes and break determinism.
    ranked.sort(key=lambda sc: (-sc[0], sc[1]))
    return ranked


def score_breakdown(meta: dict, tokens: set[str], bigrams: set[str]) -> dict:
    """Decompose `score_class` into its keyword/desc-token/bigram components.

    Used by the smoke manifest so reviewers can see *why* a finding scored —
    in particular, whether the description-bigram (semantic-predicate) path
    contributed. This mirrors `score_class` exactly; the sum of the three
    parts equals the integer it returns.
    """
    desc = (meta.get("description") or "").lower()
    kws = meta.get("keywords", [])
    kw_score = 0
    for kw in kws:
        for part in re.split(r"[-\s]+", kw.lower()):
            if len(part) >= 3 and part in tokens:
                kw_score += 3
    desc_toks = tokenize(desc)
    desc_tokens_set = set(desc_toks)
    desc_token_score = len(desc_tokens_set & tokens)
    desc_bigrams = {" ".join(p) for p in zip(desc_toks, desc_toks[1:])}
    bigram_score = 2 * len(desc_bigrams & bigrams)
    return {
        "keyword": kw_score,
        "desc_token": desc_token_score,
        "desc_bigram": bigram_score,
        "total": kw_score + desc_token_score + bigram_score,
    }


def analyse_finding_for_class(
    f: dict, classes: dict, class_name: str
) -> dict | None:
    """Return the score breakdown for `class_name` only, or None if missing."""
    meta = classes.get(class_name)
    if meta is None:
        return None
    text = finding_text(f)
    toks = tokenize(text)
    return score_breakdown(meta, set(toks), {" ".join(p) for p in zip(toks, toks[1:])})


# ─── Report rendering ──────────────────────────────────────────────────────

def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def render_report(
    corpus_path: str,
    findings: list[dict],
    classes: dict,
    threshold: int,
    top_n: int,
) -> str:
    results = []  # (finding, ranked)
    for f in findings:
        ranked = analyse_finding(f, classes)
        results.append((f, ranked))

    gaps = [(f, r) for f, r in results if (not r) or r[0][0] < threshold]
    covered = [(f, r) for f, r in results if r and r[0][0] >= threshold]

    total = len(results)
    g = len(gaps)
    c = len(covered)
    pct_cov = (100.0 * c / total) if total else 0.0
    pct_gap = (100.0 * g / total) if total else 0.0

    out = []
    out.append("# Gap Analysis")
    out.append("")
    out.append(f"_Generated by `tools/gap-analyzer.py` — corpus: `{corpus_path}`_")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- Findings scanned: **{total}**")
    out.append(f"- Covered (top score ≥ {threshold}): **{c}** ({pct_cov:.1f}%)")
    out.append(f"- Gaps (top score < {threshold} or no match): **{g}** ({pct_gap:.1f}%)")
    out.append(f"- Bug classes in registry: **{len(classes)}**")
    out.append("")

    out.append("## Gaps")
    out.append("")
    if not gaps:
        out.append("_No gaps — all findings matched a class above threshold._")
        out.append("")
    else:
        out.append(f"| id | title | top-{top_n} near-misses |")
        out.append("|---|---|---|")
        for f, ranked in gaps:
            near = ranked[:top_n]
            if near:
                near_s = ", ".join(f"`{n}`({s})" for s, n in near)
            else:
                near_s = "_no nonzero matches_"
            out.append(
                f"| {md_escape(str(f.get('id', '')))} "
                f"| {md_escape(f.get('title', ''))[:120]} "
                f"| {near_s} |"
            )
        out.append("")

    out.append("## Covered (tail sample)")
    out.append("")
    sample = covered[-10:] if len(covered) > 10 else covered
    if not sample:
        out.append("_No covered findings._")
        out.append("")
    else:
        out.append("<details><summary>last {} of {} covered findings</summary>".format(
            len(sample), len(covered)))
        out.append("")
        out.append("| id | title | top match (score) |")
        out.append("|---|---|---|")
        for f, ranked in sample:
            top = ranked[0]
            out.append(
                f"| {md_escape(str(f.get('id', '')))} "
                f"| {md_escape(f.get('title', ''))[:120]} "
                f"| `{top[1]}` ({top[0]}) |"
            )
        out.append("")
        out.append("</details>")
        out.append("")

    return "\n".join(out)


def load_corpus(path: str) -> list[dict]:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError(f"corpus must be a JSON list, got {type(data).__name__}")
    # solodit_raw files: each item has {"findings": [{"findings": [...]}]} — flatten 2 levels deep
    flat = []
    for item in data:
        batches = item.get("findings", [])
        if isinstance(batches, list):
            for batch in batches:
                findings = batch.get("findings", [])
                if isinstance(findings, list):
                    flat.extend(findings)
                else:
                    flat.append(batch)  # already a finding dict
        else:
            flat.append(batches)  # already a finding dict
    return flat


def load_smoke_corpus() -> list[dict]:
    """Tiny deterministic corpus that proves analyzer mechanics, not parity."""
    return [dict(item) for item in SMOKE_FINDINGS]


# ─── Smoke manifest ────────────────────────────────────────────────────────

def _bucket(score: int, threshold: int) -> str:
    if score <= 0:
        return "no-match"
    if score < threshold:
        return "below-threshold"
    return "covered"


def build_smoke_manifest(
    findings: list[dict],
    classes: dict,
    threshold: int,
) -> dict:
    """Return a JSON-serialisable manifest describing the smoke run.

    Schema: ``auditooor.gap_analysis_smoke.v1``.

    Loud "not real parity" annotation in the top-level keys so any downstream
    consumer (CI, dashboards, humans) cannot mistake this for a real-corpus
    measurement.
    """
    rows: list[dict] = []
    expected_fires_failures: list[str] = []
    n_covered = 0
    n_negative_clean = 0
    n_gap_novel = 0

    for f in findings:
        ranked = analyse_finding(f, classes)
        top_score, top_class = (ranked[0] if ranked else (0, None))
        kind = f.get("fixture_kind") or "unspecified"
        bucket = _bucket(top_score, threshold)

        # Optional per-finding pinned-class breakdown — used to assert the
        # semantic-predicate path actually contributes.
        pinned_class = f.get("expected_class_fires")
        pinned_breakdown = None
        if pinned_class:
            bd = analyse_finding_for_class(f, classes, pinned_class)
            if bd is None:
                expected_fires_failures.append(
                    f"{f.get('id')}: expected_class_fires={pinned_class!r} not in registry"
                )
            else:
                pinned_breakdown = bd
                if bd["total"] <= 0:
                    expected_fires_failures.append(
                        f"{f.get('id')}: expected_class_fires={pinned_class!r} did not fire"
                    )

        if kind == "negative-clean":
            if top_score > 0:
                expected_fires_failures.append(
                    f"{f.get('id')}: negative-clean fixture scored {top_score} "
                    f"(top={top_class!r}); expected zero matches"
                )
            else:
                n_negative_clean += 1
        elif kind == "gap-novel":
            if top_score >= threshold:
                expected_fires_failures.append(
                    f"{f.get('id')}: gap-novel fixture scored {top_score} >= "
                    f"threshold {threshold}; expected to land in gap bucket"
                )
            else:
                n_gap_novel += 1
        elif kind in ("covered-keyword", "covered-semantic"):
            if top_score >= threshold:
                n_covered += 1
            else:
                expected_fires_failures.append(
                    f"{f.get('id')}: {kind} fixture scored {top_score} "
                    f"< threshold {threshold}; expected to land in covered bucket"
                )
            if kind == "covered-semantic" and pinned_breakdown is not None:
                # Smoke contract: semantic-predicate fixture MUST score
                # against the description-bigram path, not just keywords.
                if pinned_breakdown["desc_bigram"] <= 0:
                    expected_fires_failures.append(
                        f"{f.get('id')}: covered-semantic fixture has "
                        f"desc_bigram=0 against {pinned_class!r}; "
                        f"semantic-predicate path did not contribute"
                    )

        rows.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "fixture_kind": kind,
            "top_score": top_score,
            "top_class": top_class,
            "bucket": bucket,
            "nonzero_match_count": len(ranked),
            "near_misses": [
                {"class": n, "score": s} for s, n in ranked[:3]
            ],
            "expected_class_fires": pinned_class,
            "pinned_breakdown": pinned_breakdown,
        })

    pass_fail = "PASS" if not expected_fires_failures else "FAIL"
    summary = (
        f"[gap-analyzer:smoke] {pass_fail} — findings={len(findings)} "
        f"covered={n_covered} negative_clean={n_negative_clean} "
        f"gap_novel={n_gap_novel} threshold={threshold} "
        f"violations={len(expected_fires_failures)}"
    )

    return {
        "schema_version": SMOKE_MANIFEST_SCHEMA,
        "mode": "smoke",
        "is_real_corpus": False,
        "real_corpus_disclaimer": (
            "This is the hermetic-smoke fixture for tools/gap-analyzer.py. "
            "It exercises parser/scoring/report mechanics on a tiny "
            "synthetic corpus. It DOES NOT measure real-corpus parity, "
            "and downstream tools must not interpret these counts as "
            "Solodit/audit-corpus coverage. For real-corpus runs use "
            "`make gaps CORPUS=<path>`."
        ),
        "corpus_label": SMOKE_CORPUS_LABEL,
        "threshold": threshold,
        "registry_class_count": len(classes),
        "findings_total": len(findings),
        "covered_total": n_covered,
        "negative_clean_total": n_negative_clean,
        "gap_novel_total": n_gap_novel,
        "pass": pass_fail == "PASS",
        "summary_line": summary,
        "expected_violations": expected_fires_failures,
        "expectations": dict(SMOKE_EXPECTATIONS),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Gap analyzer: findings corpus → detector-coverage report.",
    )
    ap.add_argument("corpus", nargs="?", help="Path to JSON corpus of findings")
    ap.add_argument(
        "--smoke",
        action="store_true",
        help=(
            "Use a tiny hermetic fixture corpus to prove analyzer mechanics; "
            "does not measure real corpus parity"
        ),
    )
    ap.add_argument("--threshold", type=int, default=5,
                    help="Confidence threshold for a finding to count as covered (default 5)")
    ap.add_argument("--top", type=int, default=3,
                    help="Number of near-miss classes to show per gap (default 3)")
    ap.add_argument("--out", default=str(REPO / "docs" / "GAP_ANALYSIS.md"),
                    help="Output Markdown path (default docs/GAP_ANALYSIS.md)")
    ap.add_argument(
        "--manifest",
        default=None,
        help=(
            "Optional JSON manifest path. In --smoke mode this defaults to "
            "<repo>/.auditooor/gap_analysis_smoke.json so CI can consume "
            "the run results in machine-readable form."
        ),
    )
    args = ap.parse_args()

    if args.smoke:
        findings = load_smoke_corpus()
        corpus_label = SMOKE_CORPUS_LABEL
    else:
        if not args.corpus:
            print("[err] corpus path required unless --smoke is set", file=sys.stderr)
            return 2
        try:
            findings = load_corpus(args.corpus)
        except Exception as e:
            print(f"[err] failed to load corpus: {e}", file=sys.stderr)
            return 2
        corpus_label = args.corpus

    classes = load_bug_classes()
    if not classes:
        print("[err] failed to load BUG_CLASSES from tools/parity-report.py", file=sys.stderr)
        return 2

    mode = "smoke" if args.smoke else "real-corpus"
    print(f"[gap-analyzer] mode: {mode}  corpus: {corpus_label}  findings: {len(findings)}  "
          f"classes: {len(classes)}  threshold: {args.threshold}",
          file=sys.stderr)

    report = render_report(
        corpus_path=corpus_label,
        findings=findings,
        classes=classes,
        threshold=args.threshold,
        top_n=args.top,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    # Manifest emission. In smoke mode we always emit a manifest because the
    # whole point of smoke is "CI-readable proof that mechanics work".
    manifest_path: Path | None = None
    if args.smoke:
        manifest_path = Path(
            args.manifest or (REPO / SMOKE_DEFAULT_MANIFEST_REL)
        )
    elif args.manifest:
        manifest_path = Path(args.manifest)

    smoke_pass = True
    smoke_summary_line = ""
    if args.smoke:
        manifest = build_smoke_manifest(findings, classes, args.threshold)
        smoke_pass = bool(manifest["pass"])
        smoke_summary_line = manifest["summary_line"]
        if manifest_path is not None:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    # Console summary (one line for the caller)
    total = len(findings)
    # Re-count from report lines to stay truthful.
    gap_line = next((ln for ln in report.splitlines() if ln.startswith("- Gaps")), "")
    cov_line = next((ln for ln in report.splitlines() if ln.startswith("- Covered")), "")
    print(f"[gap-analyzer] wrote {out_path}  scanned={total}  "
          f"{cov_line.lstrip('- ').strip()}  /  {gap_line.lstrip('- ').strip()}")

    if args.smoke:
        if manifest_path is not None:
            print(f"[gap-analyzer] smoke manifest: {manifest_path}")
        # PASS/FAIL line on stdout for grep-friendly CI consumption.
        print(smoke_summary_line)
        if not smoke_pass:
            print(
                "[gap-analyzer] smoke mechanics check FAILED — see manifest "
                "expected_violations[] for details",
                file=sys.stderr,
            )
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
