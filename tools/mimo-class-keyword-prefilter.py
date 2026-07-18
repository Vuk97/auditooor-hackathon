#!/usr/bin/env python3
"""mimo-class-keyword-prefilter.py - pre-MIMO surface check.

r36-rebuttal: lane mega-learn-2026-05-28 pathspec-registered

OPERATES ON per-fn questions JSONL BEFORE MIMO dispatch. For each question:
  1. derive a class-keyword set from the question's attack_class
     (flashloan -> {flashLoan, onFlashLoan, FlashLoanReceiver, IERC3156...}).
  2. grep the workspace src/ for the keyword (any match).
  3. If keyword is ABSENT, drop the question (the surface to attack doesn't
     exist in this workspace; MIMO would necessarily hallucinate a
     code_excerpt to satisfy the "applies=yes" shape).

WHY THIS EXISTS (operator pain anchor, 2026-05-28):
  6,558 sidecars mined; ~130 hallucination-class entries. superearn_1491
  claimed "missing zero-address constructor validation" but
  src/contracts/.../OriginVault.sol line 54-55 has `constructor() {}` (OZ
  upgradeable: real init in `initialize()`). MIMO didn't read the file.
  Same shape: any class-keyword-absent question. Prefiltering catches this
  BEFORE MIMO burns tokens hallucinating evidence.

RELATED TOOLS (read these BEFORE building anything overlapping):
  - tools/agent-prompt-hacker-augmenter.py: PULL-mode cheat sheet injector
    (writes "consider these attack classes" up-front). Distinct from this
    tool — it AUGMENTS, this tool FILTERS.
  - tools/r76-hallucination-guard.py: POST-mining mechanical gate. Detects
    CONFIRMED+conceptual-pattern + grep-verifies code_excerpt AFTER
    MIMO emits the verdict. R76 catches a hallucination after spend; this
    prefilter prevents the spend in the first place.
  - tools/per-fn-question-ranker.py: ranks questions per fn. Distinct —
    this filter is APPLIED to the ranked output before dispatch.

SCHEMA: auditooor.mimo_class_keyword_prefilter.v1

USAGE:
  python3 tools/mimo-class-keyword-prefilter.py \\
    --workspace /Users/wolf/audits/<ws> \\
    --questions reports/<ws>/questions_per_fn.jsonl \\
    --output reports/<ws>/questions_per_fn_prefiltered.jsonl \\
    [--keep-unknown-class] [--json]

  --keep-unknown-class: if attack_class has no keyword bag entry, keep the
    question (conservative default: drop, since unknown means we can't
    surface-check).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mimo_class_keyword_prefilter.v1"

# Class -> keyword-bag (regex alternation suitable for ripgrep).
# Add cautiously; over-aggressive bags = more dropped. Start narrow.
CLASS_KEYWORD_BAGS = {
    # Loan / lending
    "flashloan": r"flashLoan|onFlashLoan|FlashLoanReceiver|IERC3156|flash_loan",
    "lending": r"borrow|repay|liquidate|collateral|debt|LTV|ltv",
    "liquidation": r"liquidate|Liquidat|seize|absorb",
    # Oracle
    "oracle": r"oracle|Oracle|Chainlink|Pyth|aggregator|getRoundData|latestAnswer",
    "price-manipulation": r"price|Price|getPrice|oracle|TWAP|twap|spot",
    "stale-price": r"updatedAt|roundId|answeredInRound|StaleAnswer|stale",
    # Reentrancy / call
    "reentrancy": r"nonReentrant|ReentrancyGuard|reentran|_status|_NOT_ENTERED|noReentrant",
    "callback": r"callback|onERC721|onERC1155|onFlashLoan|tokensReceived",
    # Auth / access
    "access-control": r"onlyOwner|onlyRole|AccessControl|hasRole|Ownable|onlyAdmin",
    "signature": r"ecrecover|EIP712|EIP-712|EIP-1271|isValidSignature|sign|Signature",
    "permit": r"permit|EIP-2612|nonces\\(",
    "uninitialized-impl": r"initializer|initialize\\(|_disableInitializers|Initializable",
    "uups": r"UUPS|_authorizeUpgrade|upgradeTo",
    # Token math
    "rounding": r"div|mulDiv|/|rounding|Round|roundDown|roundUp|FixedPoint",
    "overflow": r"unchecked|SafeMath|overflow|Overflow|underflow|Underflow",
    "decimals": r"decimals|10\\*\\*|10 \\*\\* |WAD|RAY",
    "ratio": r"ratio|Ratio|share|Share|exchangeRate",
    # Bridges / cross-chain
    "bridge": r"bridge|Bridge|relay|Relay|deposit|withdraw|chainId|domain",
    "cross-chain": r"chainId|crossChain|cross_chain|domain|origin|target",
    "replay": r"nonce|Nonce|usedSignatures|processedHashes|replay|Replay",
    "merkle": r"merkle|Merkle|MerkleProof|verify|root|leaf",
    "light-client": r"light.client|lightClient|consensus|finalized|header",
    "header-validation": r"header|Header|verifyHeader|blockHash|difficulty",
    # MPC / threshold
    "threshold-sig": r"threshold|Threshold|FROST|frost|shamir|Shamir|partial|SignShare",
    "dkg": r"dkg|DKG|distributedKey|ceremony|VSS",
    "key-rotation": r"rotate|Rotate|resharing|reshare|epoch|Epoch",
    "mpc": r"mpc|MPC|partyIndex|partyId|threshold",
    # Generic patterns
    "delegatecall": r"delegatecall|DelegateCall",
    "selfdestruct": r"selfdestruct|SelfDestruct|destruct",
    "front-running": r"deadline|expiry|expir|slippage|minOut|maxIn",
    "slippage": r"slippage|minOut|maxIn|deadline|amountOutMin",
    "denial-of-service": r"loop|while|for \\(|gas|unbounded|gasleft",
    "gas-griefing": r"gasleft|gas\\(\\)|out of gas|gas limit|gasLimit",
    "storage-collision": r"slot|Slot|sstore|sload|EternalStorage|StorageSlot",
    "fee-on-transfer": r"feeOn|feeOnTransfer|deflationary|rebase|elastic",
    # NEAR / MPC-specific
    "near-runtime": r"near_sdk|env::predecessor|env::current|env::signer|state_read|state_write",
    "wasm-host": r"wasm|host_function|memory_read|memory_write",
}

# Synonyms / class aliases (lowercase, dash-or-underscore-normalized).
CLASS_ALIAS = {
    "reentrancy-attack": "reentrancy",
    "reentrant": "reentrancy",
    "flash-loan": "flashloan",
    "oracle-attack": "oracle",
    "oracle-manipulation": "price-manipulation",
    "price-oracle": "oracle",
    "access-control-bypass": "access-control",
    "uups-upgrade": "uups",
    "uups-authorize": "uups",
    "missing-zero-address-check": "uninitialized-impl",
    "constructor-missing-validation": "uninitialized-impl",
    "rounding-error": "rounding",
    "integer-overflow": "overflow",
    "denial-of-service-dos": "denial-of-service",
    "dos": "denial-of-service",
    "front-running-attack": "front-running",
    "signature-replay": "replay",
    "merkle-tree": "merkle",
    "merkle-proof": "merkle",
    "light-client-bypass": "light-client",
}


def _normalize_class(klass: str) -> str:
    k = (klass or "").strip().lower()
    k = re.sub(r"[_\s]+", "-", k)
    if k in CLASS_ALIAS:
        return CLASS_ALIAS[k]
    return k


def _resolve_bag(klass: str) -> str | None:
    """Map an attack_class to its keyword-bag regex. Returns None if no bag."""
    if not klass:
        return None
    norm = _normalize_class(klass)
    if norm in CLASS_KEYWORD_BAGS:
        return CLASS_KEYWORD_BAGS[norm]
    # Substring match (helps catch prose like "flashloan-attack-on-router")
    for key, pattern in CLASS_KEYWORD_BAGS.items():
        if key in norm:
            return pattern
    return None


def _grep_workspace(workspace: Path, pattern: str, scope_globs: list[str]) -> bool:
    """Return True if pattern is found anywhere in scope_globs of workspace."""
    if not workspace.exists():
        return False
    # Build a single rg invocation: silent, case-insensitive, no-line-numbers,
    # exit-zero-if-found
    src_dirs = []
    for g in scope_globs:
        for p in workspace.glob(g):
            if p.is_dir() or p.is_file():
                src_dirs.append(str(p))
    if not src_dirs:
        # Fallback: workspace root
        src_dirs = [str(workspace)]
    try:
        proc = subprocess.run(
            ["rg", "-l", "-i", "--no-messages",
             "--type-add=sol:*.sol", "--type-add=rs:*.rs",
             "--type-add=go:*.go", "--type-add=ts:*.ts",
             "-e", pattern,
             *src_dirs],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        return proc.returncode == 0 and bool(proc.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # No rg or timeout: be conservative, KEEP the question
        return True


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True, type=Path)
    p.add_argument("--questions", required=True, type=Path,
                   help="Input JSONL: one ranked question per line")
    p.add_argument("--output", required=True, type=Path,
                   help="Output JSONL: pre-filtered questions")
    p.add_argument("--keep-unknown-class", action="store_true",
                   help="Keep questions whose attack_class isn't in any keyword bag")
    p.add_argument("--scope-globs", default="src,src/*,src/*/src,src/*/contracts",
                   help="Comma-sep globs (relative to workspace) to grep")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    workspace = args.workspace.resolve()
    if not workspace.exists():
        sys.stderr.write(f"workspace not found: {workspace}\n")
        return 2
    if not args.questions.exists():
        sys.stderr.write(f"questions not found: {args.questions}\n")
        return 2

    scope_globs = [g.strip() for g in args.scope_globs.split(",") if g.strip()]

    # Cache per (pattern) result to avoid re-greping the workspace 1000x
    grep_cache: dict[str, bool] = {}

    def cached_grep(pat: str) -> bool:
        if pat not in grep_cache:
            grep_cache[pat] = _grep_workspace(workspace, pat, scope_globs)
        return grep_cache[pat]

    in_count = 0
    kept = 0
    dropped_no_keyword = 0
    dropped_no_bag = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.questions.open() as fin, args.output.open("w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            in_count += 1
            try:
                q = json.loads(line)
            except json.JSONDecodeError:
                continue
            klass = q.get("attack_class", "") or q.get("question_class", "")
            bag = _resolve_bag(klass)
            if bag is None:
                if args.keep_unknown_class:
                    kept += 1
                    fout.write(line + "\n")
                else:
                    dropped_no_bag += 1
                continue
            if cached_grep(bag):
                kept += 1
                # Annotate so MIMO knows which keyword satisfied the prefilter
                q["prefilter_class_keyword_satisfied"] = True
                q["prefilter_bag_pattern"] = bag[:200]
                fout.write(json.dumps(q) + "\n")
            else:
                dropped_no_keyword += 1

    summary = {
        "schema_version": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(workspace),
        "input_questions": in_count,
        "kept": kept,
        "dropped_no_class_keyword_match": dropped_no_keyword,
        "dropped_no_bag_for_class": dropped_no_bag,
        "kept_fraction": round(kept / in_count, 4) if in_count else 0.0,
        "scope_globs": scope_globs,
        "cache_size": len(grep_cache),
        "output_path": str(args.output),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Input questions: {in_count}")
        print(f"Kept: {kept} ({summary['kept_fraction']:.1%})")
        print(f"Dropped (no class-keyword in workspace): {dropped_no_keyword}")
        print(f"Dropped (no bag for attack_class): {dropped_no_bag}")
        print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
