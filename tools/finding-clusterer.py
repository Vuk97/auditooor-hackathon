#!/usr/bin/env python3
"""finding-clusterer.py — Solodit corpus → mining-priority report.

Scan a Solodit-export JSON corpus (the same shape `tools/mine-solodit.py`
produces), cluster by normalized title / tags, cross-reference against
existing BUG_CLASSES, and surface clusters that have >= N findings but
zero Auditooor coverage.

This is the "what to mine next" prioritizer — replaces the by-feel topic
picking we do today. Part of Phase 4 of the megaplan (PR #84).

Usage:
    finding-clusterer.py <corpus.json>
    finding-clusterer.py <corpus.json> --min-cluster 10  # only clusters >=10 findings

Corpus format (same as mine-solodit.py input):
    [
      {"id": "12345", "title": "...", "content": "...", "tags": [...], ...},
      ...
    ]

NOTE: This is a SIMPLE deterministic clusterer (normalized-title +
keyword buckets). An embedding-based clusterer is a natural next step
once the corpus grows beyond ~10k findings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# ─── Normalization ─────────────────────────────────────────────────────────

# Rough keyword buckets — sentences with these words go into these buckets
BUCKETS = [
    ("reentrancy",                  ["reentran", "reenter", "callback-reenter"]),
    ("oracle-manipulation",         ["oracle", "price-feed", "chainlink", "twap", "flashloan"]),
    ("slippage-sandwich",           ["slippage", "sandwich", "amountoutmin", "minamount"]),
    ("bridge-layerzero",            ["bridge", "layerzero", "lzreceive", "oft", "ccip", "stargate", "cross-chain"]),
    ("governance-voting",           ["governor", "governance", "vote", "quorum", "proposal", "veToken", "ve-token"]),
    ("vesting-unlock",              ["vesting", "cliff", "unlock", "grant", "claim-schedule"]),
    ("liquidation",                 ["liquidat", "zombie", "bad-debt", "insolven"]),
    ("lp-amm",                      ["uniswap", "liquidity", "cpmm", "stableswap", "curve", "v4-hook", "tick"]),
    ("access-control",              ["only-owner", "only-admin", "access-control", "role", "auth-missing"]),
    ("erc20-token",                 ["erc20", "permit", "allowance", "approve", "transferFrom", "safeERC20",
                                     "fee-on-transfer", "rebasing"]),
    ("perps-derivatives",           ["perpetual", "perps", "funding", "mark-price", "position"]),
    ("signature-replay",            ["signature-replay", "sig-replay", "domain-separator", "eip-712", "ecdsa",
                                     "malleabili", "chainid"]),
    ("zk-crypto",                   ["zk-vm", "merkle", "bls", "kzg", "fiat-shamir", "proof-depth"]),
    ("aa-wallet",                   ["erc-4337", "4337", "userOp", "paymaster", "validation-module", "aa-"]),
    ("nft",                         ["erc721", "nft", "royalty", "1155", "tokensReceived"]),
    ("stablecoin",                  ["stablecoin", "peg-keeper", "collateral-ratio", "dsr"]),
    ("restaking",                   ["eigenlayer", "restaking", "lrt", "operator", "validator"]),
]


def tokens_of(text: str) -> set[str]:
    return set(re.findall(r"[a-z][a-z\-]{2,}", text.lower()))


def bucket_of(finding: dict) -> str:
    """Classify a finding into a bucket by keyword match.

    When multiple keywords match, pick the LONGEST matching keyword
    (most specific). Tie-break by alphabetical order on bucket name
    for determinism. Returns "unclassified" if nothing matches.

    Previously this iterated BUCKETS in declaration order and returned
    the first hit, which mis-classified findings whose preferred bucket
    had a longer (more specific) keyword. PR #481 follow-up fix.
    """
    haystack = " ".join([
        (finding.get("title") or ""),
        " ".join(finding.get("tags", []) or []),
        (finding.get("content") or "")[:500],
    ]).lower()
    best: tuple[int, str, str] | None = None  # (-len(k), label, k) for sort
    for label, keys in BUCKETS:
        for k in keys:
            if k.lower() in haystack:
                # Sort key: longer keyword wins (negate length), then
                # alphabetical bucket name for tie-break determinism.
                cand = (-len(k), label, k)
                if best is None or cand < best:
                    best = cand
    if best is None:
        return "unclassified"
    return best[1]


# ─── BUG_CLASSES coverage (delegate to parity-report snapshot) ─────────────

def load_bug_classes() -> dict:
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
    except Exception:
        return {}


def covered_buckets(classes: dict) -> set[str]:
    """Rough assessment of which buckets have any coverage."""
    covered = set()
    for name, meta in classes.items():
        hay = (name + " " + (meta.get("description") or "")).lower()
        for label, keys in BUCKETS:
            for k in keys:
                if k in hay:
                    covered.add(label)
                    break
    return covered


def main() -> int:
    ap = argparse.ArgumentParser(description="Solodit corpus → mining priorities.")
    ap.add_argument("corpus", help="Path to Solodit findings JSON")
    ap.add_argument("--min-cluster", type=int, default=5,
                    help="Minimum cluster size to surface (default 5)")
    ap.add_argument("--dump", action="store_true",
                    help="Dump ALL clusters (ignores --min-cluster)")
    args = ap.parse_args()

    p = Path(args.corpus)
    if not p.exists():
        print(f"[err] corpus not found: {p}", file=sys.stderr)
        return 2
    try:
        findings = json.loads(p.read_text())
    except Exception as e:
        print(f"[err] failed to parse corpus: {e}", file=sys.stderr)
        return 2

    print(f"[clusterer] findings: {len(findings)}", file=sys.stderr)

    buckets: dict[str, list] = defaultdict(list)
    for f in findings:
        buckets[bucket_of(f)].append(f)

    classes = load_bug_classes()
    covered = covered_buckets(classes)
    print(f"[clusterer] bug classes registered: {len(classes)}", file=sys.stderr)
    print(f"[clusterer] buckets with coverage: {len(covered)}/{len(BUCKETS)+1}", file=sys.stderr)

    # ─── Report ────────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("Finding clusterer — mining-priority report")
    print("=" * 70)
    print(f"corpus:   {p}")
    print(f"findings: {len(findings)}")
    print(f"bug classes: {len(classes)}")
    print()

    # Sort by size desc
    sorted_buckets = sorted(buckets.items(), key=lambda x: -len(x[1]))

    print("Bucket → findings count → coverage:")
    print()
    print(f"  {'bucket':<28}  {'count':>6}  coverage")
    for label, items in sorted_buckets:
        c = len(items)
        if c < args.min_cluster and not args.dump:
            continue
        cov = "✅ covered" if label in covered else "⚠  UNCOVERED (mine candidate)"
        print(f"  {label:<28}  {c:>6}  {cov}")
    print()

    print("Top uncovered mining candidates (by size):")
    print()
    uncov = [(label, items) for label, items in sorted_buckets if label not in covered]
    for label, items in uncov[:10]:
        print(f"  [{len(items):>4}]  {label}")
        for f in items[:3]:
            title = (f.get("title") or "(untitled)")[:70]
            print(f"            - {title}")
        if len(items) > 3:
            print(f"            ... +{len(items) - 3} more")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
