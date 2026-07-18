#!/usr/bin/env python3
"""coverage-introspect.py — V5 Gap-46 / Codex P0 #3 (Tier-B advisory).

Surfaces "find problems we don't have detectors for" by enumerating the
external surface of a workspace's Solidity sources and cross-checking that
surface against `reference/patterns.dsl/*.yaml`. Sparse / uncovered surface
categories are then offered to Kimi (gap-claim) + Minimax (red-team) for a
bounded LLM gap-surfacing pass. Claude-side M14-trap and ranking happens at
the end.

Background
----------
Per `docs/V5_CAPABILITY_GAPS_2026-04-26.md` Gap 46 and Codex's PR #253 final
pass comment, this is OPT-IN by design. It MUST NOT enter the
`DEEP_PROFILE=all` chain until 3-5 real-workspace runs have proven signal
quality. It is wired as `DEEP_PROFILE=coverage-gaps make audit-deep WS=...`
only.

Tier discipline
---------------
- Tier B / advisory.
- Outputs are CANDIDATE bug-class shapes (not findings). Every candidate
  needs source-line verification, production-path proof, and a PoC or
  equivalent before filing.
- M14-trap (foot-gun #11): every LLM "missing-X / covered-by-Y" claim is
  re-verified against the actual library and workspace source. Untrusted
  until verified.

What it does (5 phases, stdlib-only)
------------------------------------
1. **Surface enumeration** (no LLM). Walk `<ws>/src/**.sol`, skip
   lib/test/mock/_archive, regex-classify imports + opcode signatures +
   token standards + oracle/bridge/crypto primitives + storage patterns +
   custom precompiles. Emit `<ws>/coverage_surface.json`.

2. **Library-coverage cross-check** (no LLM). For each surface category,
   search `reference/patterns.dsl/*.yaml` for pattern names/descriptions
   that mention category keywords. Tag each category WELL_COVERED /
   SPARSE / UNCOVERED. Emit `<ws>/coverage_by_category.json`.

3. **LLM gap-surfacing** (BOUNDED ≤30 calls combined). For each SPARSE or
   UNCOVERED category, build a bounded packet (category + ≤3 workspace
   excerpts + ≤30 existing pattern names) and dispatch via
   `tools/llm-dispatch.py --provider kimi` then `--provider minimax`.
   `AUDITOOOR_LLM_BUDGET_GUARD=1` is set in the child env. Outputs:
   `<ws>/coverage_gaps_kimi.md`, `<ws>/coverage_gaps_minimax.md`.

4. **M14-trap + ranking** (Claude-side). Keep only candidates that BOTH
   Kimi flagged novel AND Minimax did NOT flag as covered/single-protocol.
   Independently grep `reference/patterns.dsl/` for close matches the LLMs
   may have missed. Emit `<ws>/coverage_gaps_ranked.md`.

5. **Manifest**. Write
   `<ws>/.audit_logs/coverage_introspect_manifest.json` listing
   phase-1..4 outputs + LLM call count + runtime + gap counts by status.

Stdlib only. No new pip deps. Always exit 0 unless the workspace argument
itself is invalid (exit 2). LLM dispatch failures are a per-category WARN,
never fail the run.

Usage
-----

    python3 tools/coverage-introspect.py <workspace>
    python3 tools/coverage-introspect.py <workspace> --providers kimi,minimax
    python3 tools/coverage-introspect.py <workspace> --no-llm   # phases 1-2 only
    python3 tools/coverage-introspect.py <workspace> --dry-run

Exit codes
----------
  0  normal (even when zero candidates were found)
  2  argument or filesystem error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Repo paths
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[1]
PATTERNS_DSL_DIR = REPO / "reference" / "patterns.dsl"
LLM_DISPATCH = REPO / "tools" / "llm-dispatch.py"

SCHEMA_VERSION = "auditooor.coverage_introspect.v1"
TIER = "B"
MAX_LLM_CALLS_PER_RUN = 30  # hard bound (Codex P0 #3 spec)
DEFAULT_LLM_MAX_TOKENS = 12000  # Gap 1+12 fix from V5 doc
DEFAULT_LLM_TIMEOUT = 90.0
DEFAULT_PROVIDERS = ("kimi", "minimax")


# ---------------------------------------------------------------------------
# Phase 1 — Surface enumeration (deterministic, no LLM)
# ---------------------------------------------------------------------------

# Directory exclusion patterns (path *segments* — case-insensitive).
SKIP_DIR_SEGMENTS = (
    "lib",
    "node_modules",
    "test",
    "tests",
    "mocks",
    "mock",
    "_archive",
    "_archived",
    "out",
    "cache",
    "artifacts",
    "fuzz_runs",
    "symbolic_runs",
    "concolic",
    "fork_runs",
    "fork_replay_runs",
    "math_invariants",
    "monitoring",
    "swarm",
    "poc-tests",
    "prior_audits",
    "agent_outputs",
    "broadcast",
    "script",
)

# Category -> list of (name, regex) signatures. Ordered for stable JSON output.
# Each regex is compiled with re.IGNORECASE | re.MULTILINE.
SURFACE_RULES: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    # ---- Token standards ------------------------------------------------
    (
        "erc20",
        (
            ("import-erc20", r'import\s+["\'][^"\']*(IERC20|ERC20|SafeERC20|IERC20Metadata)[^"\']*["\']'),
            ("interface-erc20", r"\b(IERC20|ERC20)\b"),
            ("fn-transfer", r"function\s+transfer\s*\(\s*address[^)]*\)"),
            ("fn-transferFrom", r"function\s+transferFrom\s*\("),
        ),
    ),
    (
        "erc721",
        (
            ("import-erc721", r'import\s+["\'][^"\']*(IERC721|ERC721)[^"\']*["\']'),
            ("interface-erc721", r"\bIERC721\b|\bERC721\b"),
            ("fn-safeTransferFrom-721", r"function\s+safeTransferFrom\s*\(\s*address[^)]*uint256\s+tokenId"),
        ),
    ),
    (
        "erc1155",
        (
            ("import-erc1155", r'import\s+["\'][^"\']*(IERC1155|ERC1155)[^"\']*["\']'),
            ("interface-erc1155", r"\bIERC1155\b|\bERC1155\b"),
            ("fn-safeBatchTransferFrom", r"function\s+safeBatchTransferFrom\s*\("),
        ),
    ),
    (
        "erc4626",
        (
            ("import-erc4626", r'import\s+["\'][^"\']*(IERC4626|ERC4626)[^"\']*["\']'),
            ("interface-erc4626", r"\bIERC4626\b|\bERC4626\b"),
            ("fn-redeem-4626", r"function\s+(redeem|withdraw|deposit|mint)\s*\([^)]*assets[^)]*\)"),
        ),
    ),
    (
        "erc6909",
        (
            ("import-erc6909", r'import\s+["\'][^"\']*(IERC6909|ERC6909)[^"\']*["\']'),
            ("interface-erc6909", r"\bIERC6909\b|\bERC6909\b"),
        ),
    ),
    # ---- Oracles --------------------------------------------------------
    (
        "oracle-pyth",
        (
            ("import-pyth", r'import\s+["\'][^"\']*(IPyth|pyth)[^"\']*["\']'),
            ("call-pyth-getPriceUnsafe", r"\bgetPriceUnsafe\s*\("),
            ("call-pyth-getPriceNoOlderThan", r"\bgetPriceNoOlderThan\s*\("),
            ("call-pyth-getEmaPriceUnsafe", r"\bgetEmaPriceUnsafe\s*\("),
            ("interface-pyth", r"\bIPyth\b"),
        ),
    ),
    (
        "oracle-chainlink",
        (
            ("import-chainlink", r'import\s+["\'][^"\']*(AggregatorV3|chainlink|IChainlink)[^"\']*["\']'),
            ("call-chainlink-latestRoundData", r"\blatestRoundData\s*\("),
            ("call-chainlink-latestAnswer", r"\blatestAnswer\s*\("),
            ("call-chainlink-getRoundData", r"\bgetRoundData\s*\("),
            ("interface-chainlink", r"\bAggregatorV3Interface\b|\bIChainlinkAggregator\b|\bIAggregator\b"),
        ),
    ),
    (
        "oracle-redstone",
        (
            ("import-redstone", r'import\s+["\'][^"\']*(redstone|RedStone)[^"\']*["\']'),
            ("call-redstone", r"\bgetOracleNumericValueFromTxMsg\s*\("),
        ),
    ),
    # ---- DEX / AMM ------------------------------------------------------
    (
        "uniswap",
        (
            ("import-uniswap", r'import\s+["\'][^"\']*(IUniswap|uniswap)[^"\']*["\']'),
            ("call-uni-swap", r"\b(swap|swapExactTokensForTokens|exactInput|exactOutput)\s*\("),
            ("interface-uni-pool", r"\bIUniswapV[23]Pool\b|\bIUniswapV[23]Pair\b"),
        ),
    ),
    (
        "curve",
        (
            ("import-curve", r'import\s+["\'][^"\']*(curve|ICurve)[^"\']*["\']'),
            ("call-curve-exchange", r"\bexchange(_underlying)?\s*\("),
            ("interface-curve", r"\bICurvePool\b|\bICurveStableSwap\b"),
        ),
    ),
    # ---- Bridges --------------------------------------------------------
    (
        "bridge-layerzero",
        (
            ("import-lz", r'import\s+["\'][^"\']*(LayerZero|OFT|layerzero|@lz)[^"\']*["\']'),
            ("interface-lz", r"\bILayerZeroEndpoint\b|\bOFT(V2|Core|Adapter)?\b|\bILayerZeroReceiver\b"),
            ("fn-lzReceive", r"function\s+(lzReceive|_lzReceive)\s*\("),
        ),
    ),
    (
        "bridge-wormhole",
        (
            ("import-wh", r'import\s+["\'][^"\']*(wormhole|IWormhole)[^"\']*["\']'),
            ("interface-wh", r"\bIWormhole\b|\bIWormholeRelayer\b"),
            ("call-wh-publish", r"\bpublishMessage\s*\("),
        ),
    ),
    (
        "bridge-hyperlane",
        (
            ("import-hyperlane", r'import\s+["\'][^"\']*(hyperlane|Mailbox|IInterchain)[^"\']*["\']'),
            ("interface-hyperlane", r"\b(Mailbox|IInterchainSecurityModule|IMessageRecipient)\b"),
            ("fn-handle", r"function\s+handle\s*\(\s*uint32"),
        ),
    ),
    (
        "bridge-across",
        (
            ("import-across", r'import\s+["\'][^"\']*(across|SpokePool)[^"\']*["\']'),
            ("interface-across", r"\bSpokePool\b|\bV3SpokePool\b"),
        ),
    ),
    (
        "bridge-arbitrum",
        (
            ("import-arb", r'import\s+["\'][^"\']*(arbitrum|IInbox|IBridge)[^"\']*["\']'),
            ("interface-arb-inbox", r"\bIInbox\b|\bIArbSys\b|\bArbRetryableTx\b"),
        ),
    ),
    # ---- Cryptography ---------------------------------------------------
    (
        "crypto-ecdsa",
        (
            ("import-ecdsa", r'import\s+["\'][^"\']*ECDSA[^"\']*["\']'),
            ("call-ecdsa-recover", r"\bECDSA\.\s*recover\s*\("),
            ("call-ecrecover", r"\becrecover\s*\("),
        ),
    ),
    (
        "crypto-eip712",
        (
            ("import-eip712", r'import\s+["\'][^"\']*EIP712[^"\']*["\']'),
            ("call-hash-typed", r"\b_hashTypedDataV4\s*\("),
            ("call-domain-sep", r"\bDOMAIN_SEPARATOR\b|\b_domainSeparatorV4\s*\("),
        ),
    ),
    (
        "crypto-bls",
        (
            ("import-bls", r'import\s+["\'][^"\']*(BLS|bls12)[^"\']*["\']'),
            ("interface-bls", r"\bBLS\b\.|\bBLSSignature\b"),
        ),
    ),
    (
        "crypto-zk",
        (
            ("import-zk", r'import\s+["\'][^"\']*(Plonk|Groth|Risc0|SP1|Snark|gnark|Verifier)[^"\']*["\']'),
            ("contract-verifier", r"\bcontract\s+\w*Verifier\b"),
            ("contract-plonk", r"\bcontract\s+(Plonk|Groth16|Risc0|SP1)\w*\b"),
        ),
    ),
    (
        "crypto-merkle",
        (
            ("import-merkle", r'import\s+["\'][^"\']*MerkleProof[^"\']*["\']'),
            ("call-merkle-verify", r"\bMerkleProof\.\s*verify\s*\("),
        ),
    ),
    # ---- Storage / proxy patterns --------------------------------------
    (
        "storage-uups",
        (
            ("import-uups", r'import\s+["\'][^"\']*UUPSUpgradeable[^"\']*["\']'),
            ("fn-authorize-upgrade", r"function\s+_authorizeUpgrade\s*\("),
        ),
    ),
    (
        "storage-diamond",
        (
            ("import-diamond", r'import\s+["\'][^"\']*(LibDiamond|IDiamond)[^"\']*["\']'),
            ("interface-diamond", r"\bIDiamond(Cut|Loupe)?\b|\bLibDiamond\b"),
        ),
    ),
    (
        "storage-erc7201",
        (
            ("annotation-erc7201", r"erc7201:"),
        ),
    ),
    # ---- Inline assembly / opcode-level --------------------------------
    (
        "asm-assembly",
        (
            ("kw-assembly", r"\bassembly\s*\{"),
        ),
    ),
    (
        "asm-staticcall",
        (
            ("op-staticcall", r"\bstaticcall\s*\("),
        ),
    ),
    (
        "asm-delegatecall",
        (
            ("op-delegatecall", r"\bdelegatecall\s*\("),
        ),
    ),
    (
        "asm-extcodesize",
        (
            ("op-extcodesize", r"\bextcodesize\s*\("),
        ),
    ),
    (
        "asm-tload-tstore",
        (
            ("op-tload", r"\btload\s*\("),
            ("op-tstore", r"\btstore\s*\("),
        ),
    ),
    (
        "asm-blobhash",
        (
            ("op-blobhash", r"\bblobhash\s*\("),
        ),
    ),
    (
        "asm-selfdestruct",
        (
            ("op-selfdestruct", r"\bselfdestruct\s*\("),
        ),
    ),
    (
        "asm-chainid",
        (
            ("op-chainid", r"\bchainid\s*\(\)"),
        ),
    ),
    # ---- Custom precompiles (HyperEVM-style 0x800+) ---------------------
    (
        "custom-precompile-hyperevm",
        (
            ("addr-0x800-range", r"address\s*\(\s*0x80[0-9A-Fa-f]\s*\)"),
        ),
    ),
)


def _is_excluded_path(rel: Path) -> bool:
    """True iff any path segment is in SKIP_DIR_SEGMENTS."""
    for part in rel.parts:
        if part.lower() in SKIP_DIR_SEGMENTS:
            return True
    return False


def _iter_solidity_files(workspace: Path) -> list[Path]:
    """Return all .sol files under <ws>/src/, skipping excluded segments.

    Falls back to <ws>/contracts/ if <ws>/src/ does not exist (some
    repos use contracts/ as the canonical source root). If neither
    exists, scans <ws> directly minus excluded segments.
    """
    candidates: list[Path] = []
    roots = []
    if (workspace / "src").is_dir():
        roots.append(workspace / "src")
    elif (workspace / "contracts").is_dir():
        roots.append(workspace / "contracts")
    else:
        roots.append(workspace)

    for root in roots:
        for path in sorted(root.rglob("*.sol")):
            try:
                rel = path.relative_to(workspace)
            except ValueError:
                rel = path
            if _is_excluded_path(rel):
                continue
            candidates.append(path)
    return candidates


def _compile_rules() -> dict[str, list[tuple[str, re.Pattern[str]]]]:
    compiled: dict[str, list[tuple[str, re.Pattern[str]]]] = {}
    for cat, rules in SURFACE_RULES:
        compiled[cat] = [
            (name, re.compile(pat, re.IGNORECASE | re.MULTILINE))
            for (name, pat) in rules
        ]
    return compiled


def _scan_file(path: Path, compiled: dict[str, list[tuple[str, re.Pattern[str]]]]) -> dict[str, list[dict[str, Any]]]:
    """Return {category: [{rule, line, snippet}]} for a single .sol file.

    Snippets are truncated to 240 chars and stripped of leading whitespace
    so the LLM packet stays bounded.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    hits: dict[str, list[dict[str, Any]]] = {}
    # Pre-split lines once — keeps per-rule cost low. We build a (offset, lineno) array
    # to map regex match offset back to a line number deterministically.
    line_offsets: list[int] = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_offsets.append(i + 1)
    # Binary search for line number from byte offset.
    import bisect

    def offset_to_line(off: int) -> int:
        return bisect.bisect_right(line_offsets, off)

    for cat, rules in compiled.items():
        for name, rx in rules:
            for m in rx.finditer(text):
                line = offset_to_line(m.start())
                # Capture up to 240 chars from line start.
                line_start = line_offsets[line - 1] if 0 < line <= len(line_offsets) else m.start()
                snippet = text[line_start:line_start + 240].splitlines()[0] if text[line_start:line_start + 240] else ""
                hits.setdefault(cat, []).append({
                    "rule": name,
                    "line": line,
                    "snippet": snippet.strip()[:240],
                })
                # Cap per-rule hits at 5 to keep the surface JSON bounded.
                if len([h for h in hits[cat] if h["rule"] == name]) >= 5:
                    break
    return hits


def phase1_surface(workspace: Path) -> dict[str, Any]:
    """Run Phase 1. Return the surface dict in a deterministic shape."""
    compiled = _compile_rules()
    files = _iter_solidity_files(workspace)
    by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}
    by_category: dict[str, list[str]] = {cat: [] for cat, _ in SURFACE_RULES}

    for path in files:
        try:
            rel = str(path.relative_to(workspace))
        except ValueError:
            rel = str(path)
        hits = _scan_file(path, compiled)
        if hits:
            by_file[rel] = hits
            for cat in hits:
                if rel not in by_category[cat]:
                    by_category[cat].append(rel)

    # Drop empty buckets from by_category for compactness.
    by_category_compact = {cat: sorted(files_) for cat, files_ in by_category.items() if files_}

    return {
        "schema": SCHEMA_VERSION + ".surface",
        "tier": TIER,
        "workspace": str(workspace),
        "scanned_files": len(files),
        "files_with_hits": len(by_file),
        "categories_present": sorted(by_category_compact.keys()),
        "by_file": by_file,
        "by_category": by_category_compact,
    }


# ---------------------------------------------------------------------------
# Phase 2 — Library-coverage cross-check (deterministic, no LLM)
# ---------------------------------------------------------------------------

# Per-category keyword lists for searching reference/patterns.dsl/*.yaml.
# Keep these conservative — false positives just mean we under-report
# uncovered categories, which biases toward NOT pestering Kimi/Minimax with
# bogus "everything is uncovered!" claims.
CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "erc20": ("erc20", "ierc20", "transfer", "transferfrom", "allowance", "approve"),
    "erc721": ("erc721", "ierc721", "tokenid", "safetransferfrom"),
    "erc1155": ("erc1155", "ierc1155", "safebatchtransferfrom"),
    "erc4626": ("erc4626", "ierc4626", "vault", "shares", "assets", "preview"),
    "erc6909": ("erc6909", "ierc6909"),
    "oracle-pyth": ("pyth", "getpriceunsafe", "getpricenoolderthan", "ipyth"),
    "oracle-chainlink": ("chainlink", "latestrounddata", "latestanswer", "aggregator", "stalencheck", "stale-price"),
    "oracle-redstone": ("redstone",),
    "uniswap": ("uniswap", "swap", "exactinput", "exactoutput", "uniswapv2", "uniswapv3"),
    "curve": ("curve", "icurve", "exchange_underlying"),
    "bridge-layerzero": ("layerzero", "lzreceive", "oft", "ilayerzero"),
    "bridge-wormhole": ("wormhole", "publishmessage"),
    "bridge-hyperlane": ("hyperlane", "mailbox", "interchainsecuritymodule"),
    "bridge-across": ("across", "spokepool"),
    "bridge-arbitrum": ("iinbox", "arbitrum", "arbsys"),
    "crypto-ecdsa": ("ecdsa", "ecrecover", "signature-malleability", "siglen"),
    "crypto-eip712": ("eip712", "domain_separator", "hashtypeddata"),
    "crypto-bls": ("bls", "bls12"),
    "crypto-zk": ("verifier", "plonk", "groth", "risc0", "sp1", "snark", "zk-"),
    "crypto-merkle": ("merkleproof", "merkle"),
    "storage-uups": ("uups", "_authorizeupgrade"),
    "storage-diamond": ("diamond", "libdiamond"),
    "storage-erc7201": ("erc7201", "namespace-storage"),
    "asm-assembly": ("assembly", "inline-asm"),
    "asm-staticcall": ("staticcall",),
    "asm-delegatecall": ("delegatecall",),
    "asm-extcodesize": ("extcodesize",),
    "asm-tload-tstore": ("tload", "tstore", "transient"),
    "asm-blobhash": ("blobhash",),
    "asm-selfdestruct": ("selfdestruct",),
    "asm-chainid": ("chainid", "cross-chain-replay"),
    "custom-precompile-hyperevm": ("hyperevm", "0x800", "0x801", "precompile"),
}

WELL_COVERED_RATIO = 0.5
SPARSE_LO_RATIO = 0.1
WELL_COVERED_ABS = 8  # absolute counter-check
SPARSE_LO_ABS = 2


def _load_pattern_corpus(patterns_dir: Path) -> list[dict[str, str]]:
    """Load minimal pattern info: name + description fields.

    Pure regex, no YAML parser dependency. Matches `pattern: <name>` and
    `wiki_description:` / `description:` / `help:` fields.
    """
    corpus: list[dict[str, str]] = []
    if not patterns_dir.is_dir():
        return corpus
    for path in sorted(patterns_dir.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name_m = re.search(r"^pattern:\s*(\S+)", text, re.MULTILINE)
        name = name_m.group(1).strip() if name_m else path.stem
        # Aggregate the human-readable text fields into one searchable blob.
        blobs: list[str] = []
        for field in ("help", "description", "wiki_title", "wiki_description"):
            m = re.search(rf'^{field}:\s*"?(.*)"?$', text, re.MULTILINE)
            if m:
                blobs.append(m.group(1))
        # Also include match.body_contains_regex bodies — those are where
        # specific opcode/function names live.
        for m in re.finditer(r"body_contains_regex:\s*'([^']+)'", text):
            blobs.append(m.group(1))
        for m in re.finditer(r'body_contains_regex:\s*"([^"]+)"', text):
            blobs.append(m.group(1))
        corpus.append({
            "name": name,
            "filename": path.name,
            "search_blob": (" ".join(blobs)).lower(),
        })
    return corpus


def _classify_coverage(num: int, denom: int) -> str:
    if denom == 0:
        return "UNCOVERED"
    ratio = num / max(denom, 1)
    if num >= WELL_COVERED_ABS or ratio >= WELL_COVERED_RATIO:
        return "WELL_COVERED"
    if num >= SPARSE_LO_ABS or ratio >= SPARSE_LO_RATIO:
        return "SPARSE"
    return "UNCOVERED"


def phase2_library_crosscheck(
    surface: dict[str, Any],
    patterns_dir: Path = PATTERNS_DSL_DIR,
) -> dict[str, Any]:
    corpus = _load_pattern_corpus(patterns_dir)
    by_cat: dict[str, dict[str, Any]] = {}
    categories = surface.get("categories_present", [])
    # Denominator is intentionally the total pattern count — it gives a
    # stable absolute baseline. Per-category absolute count + ratio both
    # gate the classification.
    total_patterns = max(len(corpus), 1)

    for cat in categories:
        keywords = CATEGORY_KEYWORDS.get(cat, (cat.replace("-", " "),))
        matching: list[str] = []
        for pat in corpus:
            blob = pat["search_blob"] + " " + pat["name"].lower()
            for kw in keywords:
                if kw.lower() in blob:
                    matching.append(pat["name"])
                    break
        matching = sorted(set(matching))
        status = _classify_coverage(len(matching), total_patterns)
        by_cat[cat] = {
            "status": status,
            "matching_patterns_count": len(matching),
            "matching_patterns_sample": matching[:30],
            "keywords_used": list(keywords),
            "files_in_workspace": surface.get("by_category", {}).get(cat, []),
            "files_in_workspace_count": len(surface.get("by_category", {}).get(cat, [])),
        }

    return {
        "schema": SCHEMA_VERSION + ".coverage_by_category",
        "tier": TIER,
        "patterns_dsl_total": total_patterns,
        "well_covered_threshold_ratio": WELL_COVERED_RATIO,
        "well_covered_threshold_abs": WELL_COVERED_ABS,
        "sparse_lo_threshold_ratio": SPARSE_LO_RATIO,
        "sparse_lo_threshold_abs": SPARSE_LO_ABS,
        "categories": by_cat,
    }


# ---------------------------------------------------------------------------
# Phase 3 — LLM gap-surfacing (BOUNDED, opt-out via --no-llm)
# ---------------------------------------------------------------------------

KIMI_PROMPT_TEMPLATE = """\
You are evaluating coverage gaps for a Solidity codebase.

Category: {category}
Workspace surface evidence (excerpts):
{excerpts}

Existing pattern names in this taxonomy bucket (sample, ≤30):
{existing_patterns}

Question: List the canonical bug classes for [{category}] that are NOT in the supplied patterns. \
For each, output ONE JSON line:
{{"bug_class": "<5-15 word phrase>", "regex_positive": "<body_contains>", "regex_negative": "<body_not_contains>", "fixture_signature": "<function shape>", "exhibited_in_workspace": true|false, "severity": "HIGH|MEDIUM|LOW"}}

`exhibited_in_workspace`: true if the supplied excerpts show the bug shape; false if it's a doctrine gap (likely-needed-elsewhere). Output ONLY JSON lines, no prose.
"""

MINIMAX_PROMPT_TEMPLATE = """\
You are red-teaming Kimi's gap claims for a Solidity codebase.

Category: {category}
Workspace surface evidence (excerpts):
{excerpts}

Existing pattern names in this taxonomy bucket (sample, ≤30):
{existing_patterns}

Kimi's gap candidates (one JSON per line):
{kimi_claims}

For EACH Kimi claim, output ONE JSON line:
{{"id": <0-based index of the Kimi claim>, "false_positive_in_supplied_excerpts": true|false, "actually_covered_by_existing_pattern": "<name>" | null, "single_protocol_only": true|false}}

Use ONLY the supplied files. No external knowledge. Output ONLY JSON lines, no prose.
"""


def _build_excerpts(surface: dict[str, Any], category: str, max_files: int = 3) -> tuple[str, list[str]]:
    """Return (excerpts_block, file_list) for a category.

    Pulls up to `max_files` files where the category fired, and within each
    file up to 3 hit lines, formatted as ``path:line: snippet``.
    """
    files = surface.get("by_category", {}).get(category, [])[:max_files]
    by_file = surface.get("by_file", {})
    excerpts: list[str] = []
    for f in files:
        per_file_hits = by_file.get(f, {}).get(category, [])[:3]
        if not per_file_hits:
            continue
        excerpts.append(f"--- {f} ---")
        for h in per_file_hits:
            excerpts.append(f"L{h.get('line')}: {h.get('snippet', '')}")
    return "\n".join(excerpts) or "(no excerpts)", files


def _build_kimi_prompt(category: str, surface: dict[str, Any], coverage: dict[str, Any]) -> str:
    excerpts, _ = _build_excerpts(surface, category)
    existing = coverage.get("categories", {}).get(category, {}).get("matching_patterns_sample", [])
    existing_block = "\n".join(f"- {n}" for n in existing) or "(none)"
    return KIMI_PROMPT_TEMPLATE.format(
        category=category,
        excerpts=excerpts,
        existing_patterns=existing_block,
    )


def _build_minimax_prompt(
    category: str,
    surface: dict[str, Any],
    coverage: dict[str, Any],
    kimi_claims_text: str,
) -> str:
    excerpts, _ = _build_excerpts(surface, category)
    existing = coverage.get("categories", {}).get(category, {}).get("matching_patterns_sample", [])
    existing_block = "\n".join(f"- {n}" for n in existing) or "(none)"
    return MINIMAX_PROMPT_TEMPLATE.format(
        category=category,
        excerpts=excerpts,
        existing_patterns=existing_block,
        kimi_claims=kimi_claims_text or "(none)",
    )


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse JSON-lines, tolerantly. Skips non-JSON lines."""
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _dispatch_llm(
    prompt: str,
    provider: str,
    *,
    max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
    timeout: float = DEFAULT_LLM_TIMEOUT,
    consent_env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Invoke tools/llm-dispatch.py with the prompt as a tempfile.

    Returns ``(exit_code, stdout, stderr)``. Never raises. Inherits
    AUDITOOOR_LLM_BUDGET_GUARD/CONSENT from the supplied env (or the
    process env when consent_env is None).
    """
    env = os.environ.copy()
    if consent_env:
        env.update(consent_env)
    # Force budget-guard accounting for this run (Codex P0 #3 spec).
    env.setdefault("AUDITOOOR_LLM_BUDGET_GUARD", "1")

    # Hand-off: write the prompt to a tempfile (--prompt-file) so we don't
    # leak anything via argv on operator shells.
    tf = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".prompt.txt", delete=False
    )
    try:
        tf.write(prompt)
        tf.close()
        cmd = [
            sys.executable,
            str(LLM_DISPATCH),
            "--prompt-file", tf.name,
            "--provider", provider,
            "--max-tokens", str(max_tokens),
            "--timeout", str(timeout),
        ]
        try:
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=max(timeout * 1.5 + 30, 90),
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "subprocess.TimeoutExpired"
        except OSError as e:
            return 127, "", f"OSError: {e}"
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass


def phase3_llm_surface(
    surface: dict[str, Any],
    coverage: dict[str, Any],
    workspace: Path,
    *,
    providers: tuple[str, ...] = DEFAULT_PROVIDERS,
    dry_run: bool = False,
    max_calls: int = MAX_LLM_CALLS_PER_RUN,
    dispatcher=None,
) -> dict[str, Any]:
    """Phase 3.

    For every category whose coverage status is SPARSE or UNCOVERED, build
    a Kimi prompt, dispatch it, then build a Minimax red-team prompt and
    dispatch that. Stay under ``max_calls`` total LLM invocations.

    `dispatcher` is a callable for dependency injection in tests; defaults
    to `_dispatch_llm`. Signature:
        dispatcher(prompt: str, provider: str, **kwargs) -> (rc, stdout, stderr)
    """
    if dispatcher is None:
        dispatcher = _dispatch_llm

    sparse_cats = sorted(
        cat
        for cat, info in coverage.get("categories", {}).items()
        if info.get("status") in ("SPARSE", "UNCOVERED")
    )

    per_category: dict[str, dict[str, Any]] = {}
    calls = 0

    if dry_run:
        return {
            "schema": SCHEMA_VERSION + ".llm",
            "tier": TIER,
            "providers": list(providers),
            "dry_run": True,
            "categories_targeted": sparse_cats,
            "calls": 0,
            "max_calls": max_calls,
            "per_category": {},
        }

    for cat in sparse_cats:
        cat_record: dict[str, Any] = {
            "providers": list(providers),
            "kimi_claims": [],
            "minimax_judgements": [],
            "kimi_raw": "",
            "minimax_raw": "",
            "errors": [],
        }

        # Each category costs at most len(providers) calls. If the next
        # category would exceed the budget, mark it skipped_budget.
        if calls + len(providers) > max_calls:
            cat_record["errors"].append(f"skipped_budget (calls={calls} max={max_calls})")
            per_category[cat] = cat_record
            continue

        # --- Kimi pass ---
        kimi_text = ""
        if "kimi" in providers:
            prompt = _build_kimi_prompt(cat, surface, coverage)
            rc, out, err = dispatcher(prompt, "kimi")
            calls += 1
            cat_record["kimi_raw"] = out
            if rc != 0:
                cat_record["errors"].append(f"kimi rc={rc}: {(err or '')[:200]}")
            else:
                cat_record["kimi_claims"] = _parse_jsonl(out)

        # --- Minimax red-team pass ---
        if "minimax" in providers:
            kimi_lines = "\n".join(json.dumps(c, sort_keys=True) for c in cat_record["kimi_claims"])
            prompt = _build_minimax_prompt(cat, surface, coverage, kimi_lines)
            rc, out, err = dispatcher(prompt, "minimax")
            calls += 1
            cat_record["minimax_raw"] = out
            if rc != 0:
                cat_record["errors"].append(f"minimax rc={rc}: {(err or '')[:200]}")
            else:
                cat_record["minimax_judgements"] = _parse_jsonl(out)

        per_category[cat] = cat_record

    return {
        "schema": SCHEMA_VERSION + ".llm",
        "tier": TIER,
        "providers": list(providers),
        "dry_run": False,
        "categories_targeted": sparse_cats,
        "calls": calls,
        "max_calls": max_calls,
        "per_category": per_category,
    }


# ---------------------------------------------------------------------------
# Phase 4 — M14-trap + ranking (Claude-side; deterministic helpers)
# ---------------------------------------------------------------------------


def _independent_pattern_check(claim_phrase: str, corpus: list[dict[str, str]]) -> list[str]:
    """Re-grep the pattern corpus for the claim text + light token splits.

    The goal is to catch cases where Minimax MISSED a covering pattern.
    Returns up to 3 pattern names that look related, sorted by name.
    """
    if not claim_phrase:
        return []
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_]+", claim_phrase.lower())
    # Drop obvious stopwords so `in` / `the` / `for` don't match every pattern.
    stop = {
        "the", "and", "for", "with", "from", "into", "via", "when", "where", "that",
        "this", "of", "to", "in", "on", "by", "as", "is", "or", "but", "not", "no",
        "a", "an", "are", "be", "may", "can", "if", "vs", "without",
    }
    keep = [t for t in tokens if len(t) >= 4 and t not in stop]
    if not keep:
        return []
    matches: list[str] = []
    for pat in corpus:
        blob = pat["search_blob"] + " " + pat["name"].lower()
        # Require at least 2 of the keyword tokens to appear (rough proxy
        # for "this is roughly the same idea"). Tunable; we err on
        # surfacing rather than hiding.
        hits = sum(1 for k in keep if k in blob)
        if hits >= 2:
            matches.append(pat["name"])
    return sorted(set(matches))[:3]


def phase4_m14_rank(
    surface: dict[str, Any],
    coverage: dict[str, Any],
    llm: dict[str, Any],
    patterns_dir: Path = PATTERNS_DSL_DIR,
) -> dict[str, Any]:
    corpus = _load_pattern_corpus(patterns_dir)
    ranked: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for cat, rec in (llm.get("per_category") or {}).items():
        kimi = rec.get("kimi_claims") or []
        minimax = rec.get("minimax_judgements") or []
        # Build a minimax verdict map keyed by claim id (or ordinal).
        verdicts: dict[int, dict[str, Any]] = {}
        for idx, j in enumerate(minimax):
            try:
                key = int(j.get("id", idx))
            except (TypeError, ValueError):
                key = idx
            verdicts[key] = j

        for idx, claim in enumerate(kimi):
            verdict = verdicts.get(idx, {})
            covered_by = verdict.get("actually_covered_by_existing_pattern")
            single_proto = bool(verdict.get("single_protocol_only", False))
            kimi_says_covered = bool(claim.get("covered_by_existing"))
            independent = _independent_pattern_check(
                str(claim.get("bug_class", "")), corpus
            )

            entry = {
                "category": cat,
                "kimi_claim": claim,
                "minimax_verdict": verdict,
                "independent_pattern_matches": independent,
            }

            # Reject if EITHER LLM flagged it covered or single-protocol.
            if covered_by:
                entry["status"] = "REJECTED_minimax_covered_by"
                rejected.append(entry)
                continue
            if kimi_says_covered:
                entry["status"] = "REJECTED_kimi_self_covered"
                rejected.append(entry)
                continue
            if single_proto:
                entry["status"] = "REJECTED_single_protocol_only"
                rejected.append(entry)
                continue
            if independent:
                # Minimax missed a likely covering pattern — Claude-side M14 trap.
                entry["status"] = "REJECTED_independent_match"
                rejected.append(entry)
                continue

            # Survivor — rank by exhibited_in_workspace + severity weight.
            exhibited = bool(claim.get("exhibited_in_workspace"))
            severity = str(claim.get("severity", "")).upper()
            severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 0)
            entry["status"] = "SURVIVOR_immediate" if exhibited else "SURVIVOR_doctrine_gap"
            entry["rank_score"] = (3 if exhibited else 0) + severity_rank
            ranked.append(entry)

    ranked.sort(key=lambda e: (-int(e.get("rank_score", 0)), e["category"], json.dumps(e["kimi_claim"], sort_keys=True)))

    return {
        "schema": SCHEMA_VERSION + ".m14",
        "tier": TIER,
        "ranked": ranked,
        "rejected": rejected,
        "ranked_count": len(ranked),
        "rejected_count": len(rejected),
    }


# ---------------------------------------------------------------------------
# Markdown emitters
# ---------------------------------------------------------------------------


def render_kimi_md(llm: dict[str, Any]) -> str:
    lines: list[str] = ["# Coverage gaps — Kimi pass", ""]
    lines.append(f"- providers: `{', '.join(llm.get('providers', []))}`")
    lines.append(f"- categories targeted: {len(llm.get('categories_targeted', []))}")
    lines.append(f"- LLM calls used: {llm.get('calls', 0)} / {llm.get('max_calls', 0)}")
    lines.append("")
    if llm.get("dry_run"):
        lines.append("(dry-run — no calls made)")
        return "\n".join(lines) + "\n"
    for cat, rec in sorted((llm.get("per_category") or {}).items()):
        lines.append(f"## {cat}")
        lines.append("")
        if rec.get("errors"):
            for e in rec["errors"]:
                lines.append(f"- WARN: {e}")
            lines.append("")
        claims = rec.get("kimi_claims") or []
        if not claims:
            lines.append("(no claims)")
        else:
            for c in claims:
                lines.append(f"- `{c.get('bug_class', '?')}`")
                lines.append(f"  - exhibited_in_workspace: {c.get('exhibited_in_workspace')}")
                lines.append(f"  - severity: {c.get('severity')}")
                if c.get("regex_positive"):
                    lines.append(f"  - regex+: `{c.get('regex_positive')}`")
                if c.get("regex_negative"):
                    lines.append(f"  - regex-: `{c.get('regex_negative')}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_minimax_md(llm: dict[str, Any]) -> str:
    lines: list[str] = ["# Coverage gaps — Minimax red-team pass", ""]
    if llm.get("dry_run"):
        lines.append("(dry-run — no calls made)")
        return "\n".join(lines) + "\n"
    for cat, rec in sorted((llm.get("per_category") or {}).items()):
        lines.append(f"## {cat}")
        lines.append("")
        if rec.get("errors"):
            for e in rec["errors"]:
                lines.append(f"- WARN: {e}")
            lines.append("")
        verdicts = rec.get("minimax_judgements") or []
        if not verdicts:
            lines.append("(no judgements)")
        else:
            for v in verdicts:
                lines.append(f"- id={v.get('id')}: covered_by={v.get('actually_covered_by_existing_pattern')!r}, single_protocol_only={v.get('single_protocol_only')}, fp_in_excerpts={v.get('false_positive_in_supplied_excerpts')}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_ranked_md(m14: dict[str, Any]) -> str:
    lines: list[str] = ["# Coverage gaps — ranked (M14-trap survivors)", ""]
    lines.append("Tier: B (advisory). Each survivor is a CANDIDATE bug-class shape.")
    lines.append("Production-path proof + PoC required before filing.")
    lines.append("")
    lines.append(f"- ranked survivors: {m14.get('ranked_count', 0)}")
    lines.append(f"- rejected: {m14.get('rejected_count', 0)}")
    lines.append("")
    if not m14.get("ranked"):
        lines.append("(no survivors)")
        return "\n".join(lines) + "\n"
    lines.append("## Survivors")
    lines.append("")
    for i, e in enumerate(m14["ranked"], 1):
        c = e["kimi_claim"]
        lines.append(f"### {i}. `{c.get('bug_class', '?')}`")
        lines.append("")
        lines.append(f"- category: `{e['category']}`")
        lines.append(f"- status: `{e['status']}`")
        lines.append(f"- exhibited_in_workspace: {c.get('exhibited_in_workspace')}")
        lines.append(f"- severity (Kimi-claimed, advisory): {c.get('severity')}")
        lines.append(f"- rank_score: {e.get('rank_score')}")
        if c.get("regex_positive"):
            lines.append(f"- regex+: `{c.get('regex_positive')}`")
        if c.get("regex_negative"):
            lines.append(f"- regex-: `{c.get('regex_negative')}`")
        lines.append("")
    if m14.get("rejected"):
        lines.append("## Rejected (audit trail)")
        lines.append("")
        for e in m14["rejected"][:50]:
            c = e["kimi_claim"]
            lines.append(f"- `{c.get('bug_class', '?')}` — {e['status']} (cat={e['category']})")
        if len(m14["rejected"]) > 50:
            lines.append(f"- ... ({len(m14['rejected']) - 50} more)")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def write_manifest(
    workspace: Path,
    started_at: float,
    surface_path: Path,
    coverage_path: Path,
    kimi_md_path: Path,
    minimax_md_path: Path,
    ranked_md_path: Path,
    llm: dict[str, Any],
    m14: dict[str, Any],
    coverage: dict[str, Any],
) -> Path:
    log_dir = workspace / ".audit_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = log_dir / "coverage_introspect_manifest.json"
    elapsed = time.time() - started_at

    counts = {"WELL_COVERED": 0, "SPARSE": 0, "UNCOVERED": 0}
    for info in (coverage.get("categories") or {}).values():
        s = info.get("status", "UNCOVERED")
        if s in counts:
            counts[s] += 1

    manifest = {
        "schema": SCHEMA_VERSION + ".manifest",
        "tier": TIER,
        "workspace": str(workspace),
        "elapsed_seconds": round(elapsed, 3),
        "outputs": {
            "coverage_surface": str(surface_path),
            "coverage_by_category": str(coverage_path),
            "coverage_gaps_kimi_md": str(kimi_md_path),
            "coverage_gaps_minimax_md": str(minimax_md_path),
            "coverage_gaps_ranked_md": str(ranked_md_path),
        },
        "llm_calls_used": llm.get("calls", 0),
        "llm_calls_max": llm.get("max_calls", 0),
        "llm_providers": llm.get("providers", []),
        "llm_dry_run": bool(llm.get("dry_run")),
        "category_counts": counts,
        "categories_targeted_for_llm": llm.get("categories_targeted", []),
        "ranked_survivor_count": m14.get("ranked_count", 0),
        "rejected_count": m14.get("rejected_count", 0),
        "guardrails": [
            "Tier B / advisory; not proof or a submission gate.",
            "Survivors are CANDIDATE bug-class shapes; production-path verification + PoC required.",
            "Phase-4 M14-trap re-greps reference/patterns.dsl/ to catch Minimax misses.",
            "Opt-in only: NOT in DEEP_PROFILE=all until 3-5 real-workspace runs prove signal.",
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# V5 deep-candidate emission (opt-in, lane=source_mine)
# ---------------------------------------------------------------------------


def _load_deep_candidate_lib() -> Optional[Any]:
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_cov", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_cov", module)
    spec.loader.exec_module(module)
    return module


def _emit_coverage_candidates(workspace: Path, m14: dict[str, Any]) -> int:
    """Emit deep_candidate.v1 docs for M14-trap survivors only.

    Rejected entries (covered_by_existing_pattern / single_protocol_only /
    independent_match) MUST NOT be emitted — the rank phase already
    filtered them, and re-emitting would defeat M14 discipline.
    """
    lib = _load_deep_candidate_lib()
    if lib is None:
        return 0
    survivors = m14.get("ranked") or []
    if not survivors:
        return 0
    count = 0
    for idx, entry in enumerate(survivors):
        claim = entry.get("kimi_claim") or {}
        bug_class = str(claim.get("bug_class", f"survivor-{idx}"))
        category = str(entry.get("category", "uncategorized"))
        files = claim.get("files") or claim.get("file_paths") or claim.get("paths") or []
        if isinstance(files, str):
            files = [files]
        if not files:
            files = [f"<workspace-relative path TBD for {category}>"]
        # Sanitise file entries to workspace-relative best-effort (strip
        # leading slash / dot-dot is left for the validator to reject so
        # the operator sees explicit failure rather than a silent mangle).
        files = [str(f).lstrip("./") or f"<unknown for {category}>" for f in files]
        exhibited = bool(claim.get("exhibited_in_workspace"))
        promotion = "investigate" if exhibited else "hold"
        doc = lib.build_candidate(
            lane="source_mine",
            candidate_id=f"source_mine.{category}.{bug_class}.{idx}",
            files=files,
            claim=(
                f"M14-trap survivor in category `{category}`: "
                f"{claim.get('description') or bug_class}."
            ),
            trigger=(
                claim.get("trigger")
                or "See linked Kimi claim for trigger sequence; "
                "promote only after independent reproduction."
            ),
            impact=(
                claim.get("impact")
                or "Tier-B advisory; impact must be confirmed against "
                "production code path before any submission."
            ),
            reproduction=(
                claim.get("repro")
                or claim.get("reproduction")
                or (
                    "manual: open the cited file(s), reproduce the trigger "
                    "sequence in a Foundry test, and link the test path here"
                )
            ),
            blocking_questions=[
                "Has an independent re-reading of the cited file confirmed the trigger?",
                "Is the bug class actually covered by an existing reference/patterns.dsl entry?",
                "Does the workspace exhibit this on a production path (not lib/test/mock)?",
            ],
            promotion_status=promotion,
            tool="coverage-introspect.py",
            workspace=workspace,
            lane_payload={
                "category": category,
                "rank_score": entry.get("rank_score"),
                "status": entry.get("status"),
                "minimax_verdict": entry.get("minimax_verdict"),
                "kimi_claim": claim,
            },
        )
        lib.write_candidate(doc, workspace=workspace)
        count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="coverage-introspect.py",
        description=(
            "Surface enumeration + library-coverage cross-check + bounded "
            "Kimi/Minimax gap-surfacing pass for a workspace's Solidity "
            "sources. Stdlib only. Tier-B / advisory; opt-in deep profile."
        ),
    )
    parser.add_argument("workspace", help="Workspace root (must exist; .sol scanned under src/ or contracts/)")
    parser.add_argument(
        "--providers",
        default=",".join(DEFAULT_PROVIDERS),
        help=f"Comma list of LLM providers (default: {','.join(DEFAULT_PROVIDERS)}).",
    )
    parser.add_argument("--no-llm", action="store_true", help="Run phases 1-2 only (no LLM dispatch).")
    parser.add_argument("--dry-run", action="store_true", help="Simulate phase-3 LLM dispatch (no calls).")
    parser.add_argument(
        "--max-calls",
        type=int,
        default=MAX_LLM_CALLS_PER_RUN,
        help=f"Hard cap on combined LLM dispatch calls (default {MAX_LLM_CALLS_PER_RUN}).",
    )
    parser.add_argument(
        "--patterns-dir",
        default=str(PATTERNS_DSL_DIR),
        help="Path to reference/patterns.dsl/ (default: repo's reference/patterns.dsl/).",
    )
    parser.add_argument(
        "--emit-candidate",
        action="store_true",
        help=(
            "Opt-in V5 deep-lane emission (lane=source_mine). Writes one "
            "deep_candidate.v1 JSON per M14-trap survivor to "
            "<workspace>/deep_candidates/. Rejected entries do NOT emit — "
            "the M14 phase already filtered them."
        ),
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"[coverage-introspect] ERR workspace not found or not a directory: {ws}", file=sys.stderr)
        return 2

    started_at = time.time()
    providers = tuple(p.strip() for p in args.providers.split(",") if p.strip())
    patterns_dir = Path(args.patterns_dir)

    # ---- Phase 1 ----------------------------------------------------------
    surface = phase1_surface(ws)
    surface_path = ws / "coverage_surface.json"
    _atomic_write(surface_path, json.dumps(surface, indent=2, sort_keys=True) + "\n")

    # ---- Phase 2 ----------------------------------------------------------
    coverage = phase2_library_crosscheck(surface, patterns_dir=patterns_dir)
    coverage_path = ws / "coverage_by_category.json"
    _atomic_write(coverage_path, json.dumps(coverage, indent=2, sort_keys=True) + "\n")

    # ---- Phase 3 ----------------------------------------------------------
    if args.no_llm:
        llm = {
            "schema": SCHEMA_VERSION + ".llm",
            "tier": TIER,
            "providers": list(providers),
            "dry_run": True,
            "categories_targeted": [],
            "calls": 0,
            "max_calls": args.max_calls,
            "per_category": {},
        }
    else:
        llm = phase3_llm_surface(
            surface,
            coverage,
            ws,
            providers=providers,
            dry_run=bool(args.dry_run),
            max_calls=args.max_calls,
        )

    kimi_md_path = ws / "coverage_gaps_kimi.md"
    minimax_md_path = ws / "coverage_gaps_minimax.md"
    _atomic_write(kimi_md_path, render_kimi_md(llm))
    _atomic_write(minimax_md_path, render_minimax_md(llm))

    # ---- Phase 4 ----------------------------------------------------------
    m14 = phase4_m14_rank(surface, coverage, llm, patterns_dir=patterns_dir)
    ranked_md_path = ws / "coverage_gaps_ranked.md"
    _atomic_write(ranked_md_path, render_ranked_md(m14))

    # ---- Phase 5 ----------------------------------------------------------
    manifest_path = write_manifest(
        workspace=ws,
        started_at=started_at,
        surface_path=surface_path,
        coverage_path=coverage_path,
        kimi_md_path=kimi_md_path,
        minimax_md_path=minimax_md_path,
        ranked_md_path=ranked_md_path,
        llm=llm,
        m14=m14,
        coverage=coverage,
    )

    if args.emit_candidate:
        try:
            emitted = _emit_coverage_candidates(ws, m14)
            print(f"[coverage-introspect]    emitted     : {emitted} deep_candidates")
        except Exception as exc:  # pragma: no cover — emission is opt-in
            print(
                f"[coverage-introspect] WARN deep-candidate emission failed: {exc}",
                file=sys.stderr,
            )

    print(f"[coverage-introspect] OK workspace={ws}")
    print(f"[coverage-introspect]    surface     : {surface_path}")
    print(f"[coverage-introspect]    coverage    : {coverage_path}")
    print(f"[coverage-introspect]    kimi md     : {kimi_md_path}")
    print(f"[coverage-introspect]    minimax md  : {minimax_md_path}")
    print(f"[coverage-introspect]    ranked md   : {ranked_md_path}")
    print(f"[coverage-introspect]    manifest    : {manifest_path}")
    print(f"[coverage-introspect]    llm calls   : {llm.get('calls', 0)} / {llm.get('max_calls', 0)}")
    print(f"[coverage-introspect]    survivors   : {m14.get('ranked_count', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
