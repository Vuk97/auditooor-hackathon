#!/usr/bin/env python3
"""hunt-question-relevance-filter.py - drop codebase-irrelevant per-fn hunt tasks.

The corpus-driven per-fn hunt worklist (per-fn-mimo-batch-gen.py output) pairs each
in-scope target function with corpus-expanded hacker-questions + economic hypotheses.
On a NON-DeFi target (a bridge / MPC signer / light client) the corpus floods the
worklist with lending / AMM / oracle / rollup / ZK-circuit / Monero attack-class
questions whose load-bearing identifiers (`liquidate`, `totalAssets`, `latestRoundData`,
`slot0`, `keyImage`, `accrueInterest`, ...) HAVE NO MATCHING CODE in scope. Measured on
near-intents 2026-06-26: 145 dispatched tasks, 0 applicable, ~90% OOS-protocol templates -
each one a full sonnet agent burned refuting an irrelevant question.

This filter keeps a task ONLY when at least one of its question's load-bearing
identifiers actually grep-exists in the in-scope source (targets.tsv dirs). A task with
zero source presence is `irrelevant` (emit a lightweight scanned-verdict for coverage
credit instead of dispatching an agent). A task whose identifiers cannot be extracted is
KEPT (fail-open: never silently drop a possibly-real lead - R76 recall-floor discipline).

Generic + language-agnostic (sol/rust/go/cairo/move): identifier extraction + a source
substring index, no protocol assumptions baked in beyond a small vuln-domain lexicon used
ONLY to seed extraction (never to hard-classify).

Usage:
  python3 tools/hunt-question-relevance-filter.py --workspace <ws> --batch <in.jsonl> \
      --out <kept.jsonl> [--dropped <dropped.jsonl>] [--min-hits 1] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Vuln-domain seed terms: multi-word / lowercase domain nouns that camelCase/snake
# extraction alone would miss. Used ONLY to widen identifier extraction from free text,
# never to hard-classify a task. Each is matched case-insensitively as a substring of the
# source corpus, so `liquidat` catches liquidate/liquidation/liquidator.
_DOMAIN_SEED_TERMS = (
    "liquidat", "totalassets", "totalsupply", "latestrounddata", "slot0", "consult",
    "twap", "accrueinterest", "interestrate", "fundingrate", "collateral", "borrow",
    "ltv", "isfrozen", "setltv", "exitmarket", "flashloan", "flash_loan", "premium",
    "bondingcurve", "graduation", "scalefactor", "outstandingwithdrawals", "wadmul",
    "keyimage", "key_image", "ringsignature", "ring_signature", "pedersen", "rangeproof",
    "range_proof", "blockhash", "challengeendtime", "disputegame", "assertion",
    "validatorset", "bitfield", "_beforetokentransfer", "delegate", "checkpoint",
    "snapshot", "oracle", "rebase", "vault", "cdp", "amm", "swap", "reserve",
)

# Generic stop-identifiers: appear in nearly any codebase, so their presence does NOT
# signal that the question's specific class is in scope. Extraction ignores these.
_STOP_IDENTS = {
    "self", "address", "amount", "value", "result", "error", "data", "bytes", "string",
    "uint", "bool", "true", "false", "none", "some", "ok", "err", "new", "get", "set",
    "the", "and", "for", "this", "that", "with", "from", "into", "must", "should",
    "function", "return", "require", "assert", "msg", "sender", "owner", "token",
    "account", "balance", "transfer", "call", "hash", "verify", "check", "valid",
    "state", "config", "init", "test", "contract", "struct", "impl", "pub", "fn",
}

_CAMEL = re.compile(r"\b[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+\b")        # camelCase
_SNAKE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")            # snake_case
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _targets_inscope_roots(ws: Path) -> list[Path]:
    """In-scope source roots from <ws>/targets.tsv (repo_url<TAB>pin<TAB>local_name)."""
    roots: list[Path] = []
    tsv = ws / "targets.tsv"
    if tsv.is_file():
        for line in tsv.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            local = parts[2].strip() if len(parts) >= 3 else ""
            if local:
                d = ws / "src" / local
                if d.is_dir():
                    roots.append(d)
    if not roots and (ws / "src").is_dir():
        roots.append(ws / "src")
    return roots


def build_source_corpus(ws: Path) -> str:
    """Lowercased concatenation of in-scope source IDENTIFIER tokens (excludes vendored
    deps, tests, build artifacts, and the economic_hypotheses stubs that seeded the
    questions). Comments/strings are kept lowercased too - we match class-terms as
    substrings, and a class-term appearing even in a comment is weak evidence the class
    is at least referenced in scope (fail-toward-keep)."""
    roots = _targets_inscope_roots(ws)
    skip = ("/node_modules/", "/.cargo/", "/vendor/", "/lib/forge-std/", "/target/",
            "/build/", "/.git/", "/economic_hypotheses/", "/tests/", "/test/")
    exts = (".sol", ".rs", ".go", ".cairo", ".move", ".ts")
    chunks: list[str] = []
    for root in roots:
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix not in exts:
                continue
            sp = str(p).replace("\\", "/")
            if any(s in sp for s in skip):
                continue
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="replace").lower())
            except OSError:
                continue
    return "\n".join(chunks)


def extract_identifiers(text: str) -> set[str]:
    """Load-bearing identifiers from a question: camelCase + snake_case + multi-char
    domain words, minus generic stop-identifiers. Lowercased."""
    if not text:
        return set()
    idents: set[str] = set()
    for m in _CAMEL.findall(text):
        idents.add(m.lower())
    for m in _SNAKE.findall(text):
        idents.add(m.lower())
    low = text.lower()
    for term in _DOMAIN_SEED_TERMS:
        if term in low:
            idents.add(term)
    # bare significant words (>=5 chars) that are not stop-words: catch single-word
    # domain nouns like "liquidation", "oracle" written in prose.
    for w in _WORD.findall(low):
        if len(w) >= 5 and w not in _STOP_IDENTS:
            idents.add(w)
    return {i for i in idents if i not in _STOP_IDENTS and len(i) >= 4}


_HYP_BLOCK = re.compile(
    r"HYPOTHESIS\s*\(source:[^)]*\):\s*(.+?)(?:\n===|\n\n[A-Z][A-Z _-]{4,}|\Z)",
    re.DOTALL)


def _task_question_text(task: dict) -> str:
    """The relevance-bearing text of a task: its actual hacker-question / hypothesis,
    NOT the boilerplate JSON-schema + R-rule preamble (identical across tasks). The
    real question lives in the prompt's `HYPOTHESIS (source: ...):` block (a JSON of
    sub_question_variants). We extract ONLY that block - extracting the whole prompt
    matches generic boilerplate words present in any codebase and defeats the filter."""
    parts: list[str] = []
    prompt = task.get("prompt")
    if isinstance(prompt, str):
        m = _HYP_BLOCK.search(prompt)
        if m:
            parts.append(m.group(1)[:1600])
    # structured fallbacks (used when the prompt has no HYPOTHESIS block)
    if not parts:
        for k in ("candidate_finding", "hypothesis", "differential_test_idea"):
            v = task.get(k)
            if isinstance(v, str) and v:
                parts.append(v)
        feed = task.get("mimo_context_feed")
        if isinstance(feed, dict):
            for k in ("hypothesis", "question", "summary"):
                v = feed.get(k)
                if isinstance(v, str) and v:
                    parts.append(v)
    return " ".join(parts)


# OOS-protocol CLASS terms: distinctive vocabulary of attack classes that recur in the
# DeFi-dominated corpus but have no surface in a bridge / MPC / light-client target. A
# question is judged irrelevant ONLY when it leans on >=1 of these AND none appear in the
# in-scope source. A question with NO class-term (e.g. a generic bridge replay/binding
# question) is always kept (fail-open). Each term is matched case-insensitively as a
# substring of the lowercased source so `liquidat` catches liquidate/liquidation/-or.
_OOS_CLASS_TERMS = (
    # lending / CDP / money-market
    # NOTE: avoid language-generic terms (e.g. Rust "borrow"/"borrowed" from the borrow
    # checker would false-match); use protocol-distinctive spellings only.
    "liquidat", "collateralratio", "collateralfactor", "ltv", "accountborrows",
    "accrueinterest", "interestrate", "interestindex", "debtindex", "totaldebt",
    "totalborrow", "healthfactor",
    "isfrozen", "setltv", "exitmarket", "ctoken", "atoken", "reservefactor",
    # vault / ERC4626 / share accounting
    "totalassets", "convertto", "previewredeem", "previewmint", "sharepric",
    "inflationattack", "donationattack", "firstdepositor",
    # AMM / DEX / oracle / pricing
    "getreserves", "slot0", "twap", "latestrounddata", "consult(", "spotprice",
    "uniswap", "curvepool", "bondingcurve", "graduation", "swapfee", "amountout",
    # rollup / optimistic / fraud-proof
    "assertion", "disputegame", "challengeperiod", "challengeend", "fastconfirm",
    "fraudproof", "validatorset", "bitfield", "checkpointroot",
    # ZK-circuit (constraint systems, not Sigma protocols which the MPC lib uses)
    "underconstrained", "unconstrained", "r1cs", "witnesswire", "plonk", "groth16",
    # privacy-coin / ring sigs (Monero class)
    "keyimage", "ringsignature", "ringct", "pedersen", "rangeproof", "bulletproof",
    # lending-launchpad / governance-token
    "votingpower", "delegatevotes", "wrapperrole", "rebase",
    # funding / perps
    "fundingrate", "openinterest", "markprice", "indexprice",
)


def relevance(task: dict, corpus: str) -> dict:
    qtext = _task_question_text(task).lower()
    if not qtext:
        return {"verdict": "keep", "reason": "no-question-text (fail-open)",
                "class_terms": [], "present": []}
    class_terms = sorted({t for t in _OOS_CLASS_TERMS if t in qtext})
    if not class_terms:
        return {"verdict": "keep", "reason": "no OOS-class term in question (fail-open)",
                "class_terms": [], "present": []}
    present = sorted(t for t in class_terms if t in corpus)
    if present:
        return {"verdict": "keep",
                "reason": f"class term(s) present in scope: {present[:5]}",
                "class_terms": class_terms, "present": present}
    return {"verdict": "irrelevant",
            "reason": f"OOS-class term(s) {class_terms[:5]} absent from in-scope source",
            "class_terms": class_terms, "present": []}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Drop codebase-irrelevant per-fn hunt tasks.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--batch", required=True, help="input task batch jsonl")
    ap.add_argument("--out", required=True, help="kept tasks jsonl")
    ap.add_argument("--dropped", help="irrelevant tasks jsonl (for coverage scanned-verdicts)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    batch = Path(args.batch)
    if not batch.is_file():
        print(f"[relevance-filter] ERR batch not found: {batch}", file=sys.stderr)
        return 2
    corpus = build_source_corpus(ws)
    if not corpus:
        # fail-open: no readable source -> keep everything, never silently drop
        print(f"[relevance-filter] WARN no in-scope source read for {ws}; keeping all tasks",
              file=sys.stderr)

    kept, dropped = [], []
    for line in batch.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            task = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        rel = relevance(task, corpus) if corpus else {"verdict": "keep",
                                                       "reason": "no-source (fail-open)"}
        task["_relevance"] = rel
        (kept if rel["verdict"] == "keep" else dropped).append(task)

    Path(args.out).write_text(
        "".join(json.dumps(t) + "\n" for t in kept), encoding="utf-8")
    if args.dropped:
        Path(args.dropped).write_text(
            "".join(json.dumps(t) + "\n" for t in dropped), encoding="utf-8")

    result = {
        "schema": "auditooor.hunt_question_relevance_filter.v1",
        "workspace": ws.name,
        "total": len(kept) + len(dropped),
        "kept": len(kept),
        "dropped_irrelevant": len(dropped),
        "out": str(args.out),
        "dropped_out": args.dropped or None,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[relevance-filter] {result['kept']} kept / {result['dropped_irrelevant']} "
              f"irrelevant of {result['total']} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
