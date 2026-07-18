#!/usr/bin/env python3
"""Convert prior-audit/extracted-audit text into hackerman_record v1 YAML.

The extractor is intentionally conservative: it only treats heading-delimited
sections as findings when the heading looks like a finding title. Documents
without usable headings are emitted as a single low-confidence record.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
# r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
# Rule 37: schema v1.1 is additive over v1 (adds an optional verification_tier
# field). Used only when --verification-tier is passed; the validator
# auto-detects the version per-record.
SCHEMA_VERSION_V11 = "auditooor.hackerman_record.v1.1"
# Rule 37 tier vocabulary that is meaningful for a prior-audit / public-archive
# source. tier-1 (live-API / officially-disclosed) is excluded on purpose: this
# miner reads archived audit text, never a live advisory API.
VALID_PRIOR_AUDIT_TIERS = (
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
)
AUDIT_DIR_NAMES = ("prior_audits", "extracted_audits")
CORPUS_TEXT_WORKSPACE = Path("corpus-txt")
CORPUS_TEXT_AUDIT_KIND = "audit_text_corpus"
TEXT_EXTENSIONS = {".md", ".markdown", ".txt"}
PDF_EXTENSIONS = {".pdf"}
SOURCE_EXTENSIONS = TEXT_EXTENSIONS | PDF_EXTENSIONS
SOURCE_SUFFIX_PRIORITY = {
    ".md": 0,
    ".markdown": 1,
    ".txt": 2,
    ".pdf": 3,
}
STAGE_SCHEMA_VERSION = "auditooor.hackerman_prior_audit_stage.v1"

SEVERITY_ALIASES = (
    ("critical", ("critical", "crit", "c-")),
    ("high", ("high", "h-", "[h", "(h")),
    ("medium", ("medium", "med", "m-", "[m", "(m")),
    ("low", ("low", "l-", "[l", "(l")),
    ("info", ("informational", "info", "note", "n-")),
)

LANGUAGE_KEYWORDS = (
    ("cairo", ("cairo", "starknet")),
    ("rust", ("rust", "anchor", "solana", "cargo", ".rs")),
    (
        "go",
        (
            "golang",
            " cosmos ",
            "go module",
            ".go",
            "geth",
            "cosmos-sdk",
            "msgserver",
            " keeper ",
            "x/clob",
            "x/gov",
            "x/bank",
            "module account",
            "ibc",
            "cometbft",
            "iavl",
            "slinky",
            "prepareproposal",
            "extendvote",
            "validatebasic",
            "finalizeblock",
            "beginblocker",
            "endblocker",
            "antehandler",
            "statechain",
            "chain watcher",
            "chain-watcher",
            "coop_exit",
            "cooperative exit",
            "txid",
            "utxo",
            "key tweak",
            "leaf status",
        ),
    ),
    ("move", ("move module", "sui::", "aptos")),
    ("vyper", ("vyper", ".vy")),
    ("huff", ("huff", ".huff")),
    ("assembly", ("yul", "assembly")),
    ("typescript-onchain", ("typescript", "ts-node")),
    ("python-onchain", ("python", "vyper script")),
    ("solidity", ("solidity", "smart contract", "erc", "function ", ".sol", "msg.sender")),
)

DOMAIN_KEYWORDS = (
    ("zk-proof", ("zk", "zero-knowledge", "circuit", "constraint", "proof", "witness", "halo2", "circom")),
    ("bridge", ("bridge", "cross-chain", "cross chain", "messaging", "l1", "l2")),
    ("rollup", ("rollup", "sequencer", "fraud proof", "state root")),
    ("oracle", ("oracle", "price feed", "chainlink", "pyth", "twap")),
    ("governance", ("governance", "proposal", "vote", "timelock", "quorum", "x/gov")),
    ("dex", ("dex", "swap", "amm", "liquidity pool", "uniswap", "curve", "slippage", "clob", "x/clob")),
    ("lending", ("borrow", "lend", "loan", "liquidation", "collateral", "debt")),
    ("staking", ("stake", "staking", "validator", "delegator", "slash")),
    ("nft", ("nft", "erc721", "erc-721", "royalty")),
    ("dao", ("dao", "ragequit", "treasury")),
    ("escrow", ("escrow", "vesting", "lockup")),
    ("gaming", ("game", "randomness", "loot")),
    (
        "consensus",
        (
            "consensus",
            "validator set",
            "block proposer",
            "cometbft",
            "prepareproposal",
            "extendvote",
            "ibc",
            "iavl",
            "msgserver",
            " keeper ",
            "x/bank",
            "module account",
            "validatebasic",
            "finalizeblock",
            "beginblocker",
            "endblocker",
            "antehandler",
            "statechain",
            "chain watcher",
            "chain-watcher",
            "cooperative exit",
            "txid",
            "utxo",
        ),
    ),
    ("rpc-infra", ("rpc", "mempool", "node", "slinky")),
    ("l1-client", ("evm client", "execution client", "reth", "geth")),
    ("vault", ("vault", "erc4626", "erc-4626", "shares", "deposit", "withdraw")),
)

CLASS_KEYWORDS = (
    ("access-control", "admin-bypass", ("access control", "unauthorized", "onlyowner", "permission", "privilege")),
    ("reentrancy", "callback-reentrancy", ("reentrancy", "reentrant", "callback")),
    ("oracle-manipulation", "stale-or-manipulated-oracle", ("oracle", "stale price", "twap", "price manipulation")),
    ("signature-replay", "signature-replay", ("signature", "replay", "eip712", "permit")),
    ("share-inflation", "first-deposit-share-inflation", ("share inflation", "first depositor", "erc4626", "donation")),
    ("precision-loss", "rounding-precision-loss", ("rounding", "precision", "truncation", "division")),
    ("denial-of-service", "dos-griefing", ("denial of service", "dos", "grief", "blocked", "stuck")),
    (
        "input-validation",
        "missing-input-validation",
        (
            "missing validation",
            "input validation",
            "unchecked",
            "not validated",
            "validatebasic",
            "txid validation",
            "transaction id validation",
            "exit txid",
            "chain watcher",
        ),
    ),
    ("accounting", "state-accounting-drift", ("accounting", "balance", "state", "debt", "reward")),
    ("zk-constraint", "missing-zk-constraint", ("constraint", "unconstrained", "witness", "range check")),
)

IMPACT_KEYWORDS = (
    ("theft", ("steal", "theft", "drain", "loss of funds", "fund loss")),
    ("freeze", ("freeze", "locked", "stuck funds", "cannot withdraw")),
    ("dos", ("denial of service", "dos", "revert", "blocked")),
    ("griefing", ("grief", "censor")),
    ("yield-redistribution", ("reward", "yield", "interest")),
    ("precision-loss", ("rounding", "precision", "truncation")),
    ("governance-takeover", ("governance takeover", "quorum", "proposal")),
    ("privilege-escalation", ("privilege", "unauthorized", "admin")),
)

FINDING_ANCHOR_RE = re.compile(
    r"^(?:\s*(?:[-*>\d.()]+\s*)?(?:#{1,6}\s*)?)?"
    r"(?:\[[hmlc]\]|\([hmlc]\)|[hmlc][-_ ]?\d{1,3}\b|(?:finding|issue|vulnerability)\s*(?:#|no\.?)?\s*\d+\b)",
    re.IGNORECASE,
)
AUDIT_FIELD_RE = re.compile(r"^(?:Project|Type|Severity|Impact|Exploitability|Status|Issue)\b", re.IGNORECASE)
SEVERITY_FIELD_RE = re.compile(r"\bSeverity\s+(Critical|High|Medium|Low|Informational|Info)\b", re.IGNORECASE)

# B8: ZK-specialized parsing branch (EXEC-WAVE-2-MULTI).
# Operator-caught regression on extracted_audits/zkbugs/*: the generic
# infer_component falls back to bare paragraph words like `out`, generic
# builtins like `into()`, or truncated call expressions, producing
# garbage raw_signature values like "fn out". The ZK-specialized branch
# uses STRICTER regex (only `fn name(args) -> ret` / `pub fn` / `struct
# Name` shapes) and a ZK-aware attack-class taxonomy.

ZK_PATH_TOKEN_RE = re.compile(r"extracted_audits[/\\]zkbugs[/\\]|\bzkbugs\b", re.IGNORECASE)
ZK_KEYWORD_DENSITY_TERMS = ("circuit", "constraint", "witness", "prover", "verifier")
ZK_KEYWORD_DENSITY_THRESHOLD = 5

# Strict signature shapes accepted by the ZK branch. Each pattern's
# group(1) is the raw signature text. The patterns ONLY accept things
# that look like real function/struct declarations - they refuse bare
# identifiers.
ZK_SIGNATURE_PATTERNS = (
    # rust: fn name(args) -> ret
    re.compile(r"\b((?:pub(?:\([^)]+\))?\s+)?(?:unsafe\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]{0,80}>)?\s*\([^)]{0,240}\)(?:\s*->\s*[A-Za-z_][^{;\n]{0,120})?)"),
    # rust: pub fn / async fn variants
    re.compile(r"\b((?:pub(?:\([^)]+\))?\s+)?async\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,240}\))"),
    # rust: impl method declared inline
    re.compile(r"\b(impl(?:\s*<[^>]{0,80}>)?\s+[A-Za-z_][A-Za-z0-9_:]{0,80}(?:\s+for\s+[A-Za-z_][A-Za-z0-9_:]{0,80})?)"),
    # rust struct
    re.compile(r"\b((?:pub(?:\([^)]+\))?\s+)?struct\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^>]{0,80}>)?)"),
    # rust trait
    re.compile(r"\b((?:pub(?:\([^)]+\))?\s+)?trait\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^>]{0,80}>)?)"),
    # go: func (Recv) Name(args) ret
    re.compile(r"\b(func\s+(?:\([^)]{1,80}\)\s+)?[A-Z][A-Za-z0-9_]*\s*\([^)]{0,240}\))"),
    # circom/cairo template/signal declarations
    re.compile(r"\b(template\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,240}\))"),
    re.compile(r"\b(component\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]{0,60}\([^)]{0,120}\))"),
)

# ZK-aware attack-class taxonomy. Specific to circuit / witness / proof
# bug families - distinct from the generic CLASS_KEYWORDS taxonomy.
ZK_CLASS_KEYWORDS = (
    ("zk-constraint", "unconstrained-variable", ("unconstrained", "no constraint", "missing constraint", "not constrained")),
    ("zk-constraint", "missing-range-check", ("range check", "range-check", "not in range", "modulus overflow", "bit-decomposition")),
    ("zk-constraint", "missing-zk-constraint", ("constraint", "witness", "circuit")),
    ("zk-soundness", "aliased-witness", ("aliased witness", "witness aliasing", "duplicate witness", "non-deterministic witness")),
    ("zk-soundness", "proof-malleability", ("proof malleability", "malleable proof", "non-unique proof", "proof forgery")),
    ("zk-soundness", "frozen-heart", ("fiat-shamir", "fiat shamir", "frozen heart", "non-binding commitment")),
    ("zk-completeness", "completeness-failure", ("honest prover", "completeness", "valid witness rejected")),
    ("zk-trusted-setup", "trusted-setup-leak", ("trusted setup", "powers of tau", "ceremony", "toxic waste")),
)


def is_zk_source_path(path: Path) -> bool:
    """B8: return True if path is under extracted_audits/zkbugs/."""
    return bool(ZK_PATH_TOKEN_RE.search(str(path)))


def is_zk_content(text: str) -> bool:
    """B8: density check - returns True if the ZK keyword corpus appears
    at least ZK_KEYWORD_DENSITY_THRESHOLD times across all terms combined.
    """
    low = text.lower()
    total = 0
    for term in ZK_KEYWORD_DENSITY_TERMS:
        total += low.count(term)
        if total >= ZK_KEYWORD_DENSITY_THRESHOLD:
            return True
    return False


def is_zk_signature_shape(text: str) -> bool:
    """B8: return True if text looks like an accepted ZK signature shape."""
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 4:
        return False
    return any(pattern.search(stripped) for pattern in ZK_SIGNATURE_PATTERNS)


def infer_zk_component(title: str, body: str) -> str:
    """B8: ZK-specialized component extractor. Refuses bare words and
    generic builtins; only returns strings that match a known signature
    shape (fn name(args), pub fn, struct/trait, func recv, template).
    Falls back to `<unresolved-zk-component>` rather than emitting noise.
    """
    haystack = f"{title}\n{body}"
    for pattern in ZK_SIGNATURE_PATTERNS:
        match = pattern.search(haystack)
        if match:
            candidate = match.group(1).strip()[:240]
            if candidate and not is_generic_component(candidate):
                return candidate
    # Backtick-quoted identifiers, only if they look like real fn names
    # (contain `(` or end with a callable shape). Refuse bare words.
    for raw in re.findall(r"`([^`\n]{1,120})`", haystack):
        cand = raw.strip()
        if "(" in cand and ")" in cand and len(cand.split("(", 1)[0]) > 1:
            return cand[:240]
    return "<unresolved-zk-component>"


def infer_zk_signature(component: str, language: str) -> str:
    """B8: refuse to synthesize `fn <bareword>`. Only accept shapes that
    already look like signatures, otherwise emit `<unresolved-zk-signature>`.
    """
    if not component or component == "<unresolved-zk-component>":
        return "<unresolved-zk-signature>"
    if is_zk_signature_shape(component):
        return component
    # Some legitimate components are bare identifiers that the body
    # confirms as fn names (e.g. "IsZero" appears as `func IsZero`).
    # The generic infer_signature would handle these correctly. To stay
    # conservative on ZK paths, refuse anything that looks like a paragraph
    # word.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", component) and len(component) >= 3:
        if language == "rust":
            return f"fn {component}(...)"
        if language == "go":
            return f"func {component}(...)"
        return f"function {component}(...)"
    return "<unresolved-zk-signature>"


def infer_zk_bug_and_attack(text: str) -> Tuple[str, str]:
    """B8: ZK-specialized attack classifier - prefers ZK taxonomy over
    the generic CLASS_KEYWORDS list.
    """
    low = text.lower()
    for bug_class, attack_class, needles in ZK_CLASS_KEYWORDS:
        if any(needle in low for needle in needles):
            return bug_class, attack_class
    return infer_bug_and_attack(text)


class FindingSegment(NamedTuple):
    title: str
    body: str
    heading_line: int
    ordinal: int


class SourceDoc(NamedTuple):
    workspace: Path
    audit_kind: str
    path: Path
    rel_path: Path


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug[:max_len].strip("-._") or "record")


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def first_match(text: str, choices: Sequence[Tuple[str, Sequence[str]]], default: str) -> str:
    for value, needles in choices:
        if contains_any(text, needles):
            return value
    return default


def infer_severity(text: str) -> str:
    field_match = SEVERITY_FIELD_RE.search(text)
    if field_match:
        field_value = field_match.group(1).strip().lower()
        for severity, needles in SEVERITY_ALIASES:
            if severity == field_value or any(needle.strip("-[]()") == field_value for needle in needles):
                return severity
    low = text.lower()
    for severity, needles in SEVERITY_ALIASES:
        for needle in needles:
            if needle.endswith("-"):
                if re.search(rf"(^|[\s\[(]){re.escape(needle)}\s*\d+", low):
                    return severity
            elif needle in low:
                return severity
    return "info"


def infer_language(text: str) -> str:
    return first_match(text, LANGUAGE_KEYWORDS, "solidity")


def infer_domain(text: str) -> str:
    return first_match(text, DOMAIN_KEYWORDS, "vault")


def infer_bug_and_attack(text: str) -> Tuple[str, str]:
    for bug_class, attack_class, needles in CLASS_KEYWORDS:
        if contains_any(text, needles):
            return bug_class, attack_class
    return "logic-error", "protocol-invariant-bypass"


def infer_impact(text: str) -> str:
    return first_match(text, IMPACT_KEYWORDS, "griefing")


def infer_attacker_role(text: str) -> str:
    low = text.lower()
    if contains_any(low, ("validator", "validator set")):
        return "validator"
    if "sequencer" in low:
        return "sequencer"
    if contains_any(low, ("governance", "proposal", "voter")):
        return "governance"
    if contains_any(low, ("admin", "owner", "privileged", "role")):
        return "privileged-compromised"
    if "block proposer" in low or "proposer" in low:
        return "block-proposer"
    return "unprivileged"


def infer_impact_actor(text: str) -> str:
    low = text.lower()
    if contains_any(low, ("treasury", "protocol")):
        return "protocol-treasury"
    if contains_any(low, ("validator", "validator set")):
        return "validator-set"
    if "sequencer" in low:
        return "sequencer"
    if contains_any(low, ("depositor", "lender", "borrower", "lp", "liquidity provider")):
        return "depositor-class"
    if contains_any(low, ("reward", "yield")):
        return "yield-recipient"
    if contains_any(low, ("victim", "specific user")):
        return "specific-user"
    return "arbitrary-user"


def infer_dollar_class(severity: str, impact_class: str) -> str:
    if impact_class in {"griefing", "dos"} and severity in {"low", "info"}:
        return "non-financial"
    if severity == "critical":
        return ">=$1M"
    if severity == "high":
        return "$100K-$1M"
    if severity == "medium":
        return "$10K-$100K"
    if severity == "low":
        return "<$10K"
    return "non-financial"


def infer_year(text: str, path: Path) -> int:
    sources = [str(path), path.name, text[:4000]]
    if path.exists():
        try:
            sources.append(path.read_text(encoding="utf-8", errors="replace")[:4000])
        except OSError:
            pass
    joined = " ".join(sources)
    candidates = re.findall(r"(?<!\d)(20[0-9]{2})(?!\d)", joined)
    # File names often encode dates as 20210323 or 2021-03-23.
    candidates.extend(re.findall(r"(?<!\d)(20[0-9]{2})(?=[._-]?\d{2}[._-]?\d{2})(?!\d{9})", joined))
    for raw in candidates:
        year = int(raw)
        if 2000 <= year <= 2100:
            return year
    return 2000


PATHLIKE_REPO_OWNERS = {
    "x",
    "ibc",
    "protocol",
    "proto",
    "types",
    "ante",
    "daemons",
    "consensus",
    "timeout",
    "hours",
    "risk",
    "fok",
    "subaccounts",
    "clob",
    "perpetuals",
    "prices",
    "epochs",
    "src",
    "contracts",
    "deposits",
    "deposit",
    "github.com",
    "cantina.xyz",
    "critical",
    "resolved",
    "and",
    "try",
    "bin",
    "style",
    "transfer",
    "functions",
    "upgrade",
    "contract",
    "erc20",
    "enabling",
    "l2",
    "n",
}
PATHLIKE_REPO_NAMES = {
    "common",
    "core",
    "adapters",
    "contracts",
    "src",
    "redemptions",
    "redeem",
    "major",
    "partially",
    "u",
    "or",
    "catch",
    "cantina",
    "bash",
    "naming",
    "mint",
    "events",
    "version",
    "disabling",
    "staking",
    "a",
    "eoa",
    "no-hook",
}


def is_pathlike_repo_candidate(candidate: str) -> bool:
    if "/" not in candidate:
        return True
    owner, repo = candidate.split("/", 1)
    owner_low = owner.lower()
    repo_low = repo.lower()
    if owner_low in PATHLIKE_REPO_OWNERS or repo_low in PATHLIKE_REPO_NAMES:
        return True
    if repo_low.endswith((".go", ".rs", ".sol", ".md", ".txt")):
        return True
    if re.fullmatch(r"\d+", owner) or re.fullmatch(r"\d+", repo):
        return True
    if candidate.upper() == "N/A":
        return True
    return False


def _normalize_repo_slug(repo: str) -> str:
    repo = repo.rstrip("-.")
    if repo.lower() in {"dydxprotocol/v4", "dydxprotocol/v4-chain"} or repo.lower().startswith("dydxprotocol/v4-"):
        return "dydxprotocol/v4-chain"
    return repo


def infer_repo(text: str, context: str = "") -> str:
    combined = f"{text}\n{context}"
    github_matches = re.findall(r"github\.com[:/]+([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", combined, re.IGNORECASE)
    if github_matches:
        segment_low = text.lower()
        for candidate in github_matches:
            repo = _normalize_repo_slug(candidate)
            repo_name = repo.split("/", 1)[1].lower() if "/" in repo else repo.lower()
            if repo_name and repo_name in segment_low:
                return repo
        repo = _normalize_repo_slug(github_matches[0])
        if repo.lower() in {"dydxprotocol/v4", "dydxprotocol/v4-chain"} or repo.lower().startswith("dydxprotocol/v4-"):
            return "dydxprotocol/v4-chain"
        return repo
    if re.search(r"\bdydx\b|v4-chain|protocol/x/", combined, re.IGNORECASE):
        return "dydxprotocol/v4-chain"
    matches = re.findall(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", text)
    if not matches:
        return "unknown"
    for candidate in matches:
        if is_pathlike_repo_candidate(candidate):
            continue
        return candidate
    return "unknown"


def source_doc_context(path: Path, max_chars: int = 8000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


def is_generic_component(component: str) -> bool:
    low = component.strip().lower()
    generic_prefixes = (
        "function contains",
        "function in",
        "function as",
        "function to",
        "function that",
        "function of",
        "function calls",
        "function has",
        "function allows",
        "function provides",
        "function inside",
        "function with",
        "function on",
        "function should",
        "function can",
        "function could",
        "function is",
        "function does",
        "function will",
        "the function",
    )
    return any(low.startswith(prefix) for prefix in generic_prefixes)


def infer_component(title: str, body: str) -> str:
    patterns = (
        r"`([^`\n]{1,120})`",
        r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
        r"\b((?:MsgServer|Keeper|keeper)\.[A-Za-z_][A-Za-z0-9_]{2,})\b",
        r"\b((?:PrepareProposal|ExtendVote|ValidateBasic)\([^)]{0,120}\))",
        r"\b(x/[a-z0-9_./-]{2,})\b",
        r"\b(module account|CometBFT|IAVL|Slinky)\b",
        r"\b([A-Z][A-Za-z0-9_]{2,}\.[A-Za-z_][A-Za-z0-9_]{2,})\b",
        r"\b([A-Za-z_][A-Za-z0-9_]{2,}\([^)]{0,120}\))",
    )
    haystack = f"{title}\n{body}"
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            component = match.group(1).strip()[:240]
            if not is_generic_component(component):
                return component
    return title[:240] or "unknown-component"


def infer_signature(component: str, language: str) -> str:
    if component.startswith("function ") or "(" in component:
        return component
    if language == "go":
        return f"func {component}"
    if language == "rust":
        return f"fn {component}"
    return f"function {component}"


def shape_tags(language: str, bug_class: str, attack_class: str, component: str) -> List[str]:
    tags = [slugify(attack_class), slugify(f"{language}-{bug_class}")]
    comp = slugify(component, max_len=48)
    if comp and comp not in tags:
        tags.append(comp)
    return tags[:3]


def extract_preconditions(text: str, domain: str, bug_class: str) -> List[str]:
    bullets = []
    for line in text.splitlines():
        stripped = line.strip(" \t-*")
        if len(stripped) < 8:
            continue
        if contains_any(stripped, ("precondition", "requires", "when ", "if ", "attacker can", "user can")):
            bullets.append(stripped[:220])
    if bullets:
        return list(dict.fromkeys(bullets))[:3]
    return [f"{domain} component exposes behavior consistent with {bug_class}"]


def one_line(text: str, fallback: str) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    return (cleaned[:800] if cleaned else fallback)


def looks_like_finding_heading(title: str) -> bool:
    low = title.lower().strip()
    if re.search(r"\b([hmlc]-\s*\d+|\[[hmlc]\]|\([hmlc]\)|finding\s+\d+|issue\s+\d+)\b", low):
        return True
    return contains_any(low, ("critical", "high", "medium", "low", "vulnerability", "finding", "issue"))


def looks_like_finding_anchor(line: str) -> bool:
    candidate = line.strip().strip("#").strip()
    if len(candidate) < 8:
        return False
    return bool(FINDING_ANCHOR_RE.search(candidate))


def segment_findings_by_line_anchors(lines: Sequence[str]) -> List[FindingSegment]:
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if not looks_like_finding_anchor(line):
            continue
        title = line.strip().lstrip("#").strip()
        anchors.append((idx, title))

    segments: List[FindingSegment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start + 1 : end]).strip()
        if len(body) < 20:
            continue
        segments.append(FindingSegment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def is_pdf_page_artifact(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("© ") or stripped.startswith("\f© "):
        return True
    if re.fullmatch(r"Findings\s+\d+", stripped):
        return True
    if re.fullmatch(r"Audit Overview\s+\d+", stripped):
        return True
    return False


def segment_findings_by_audit_field_blocks(lines: Sequence[str]) -> List[FindingSegment]:
    """Split PDF-extracted reports where each finding is Title + Project/Severity fields."""
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if not re.match(r"^\s*Project\s{2,}\S+", line):
            continue
        title_indexes: List[int] = []
        j = idx - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        while j >= 0 and len(title_indexes) < 5:
            stripped = lines[j].strip()
            if not stripped or is_pdf_page_artifact(stripped) or AUDIT_FIELD_RE.match(stripped):
                break
            title_indexes.append(j)
            j -= 1
        if not title_indexes:
            continue
        title_indexes.reverse()
        title = " ".join(lines[i].strip() for i in title_indexes)
        title = re.sub(r"\s+", " ", title).strip()
        if len(title) < 8:
            continue
        if title.lower() in {"the project", "audit dashboard", "target summary", "engagement summary"}:
            continue
        anchors.append((title_indexes[0], title))

    segments: List[FindingSegment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start:end]).strip()
        if len(body) < 80:
            continue
        segments.append(FindingSegment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def numbered_finding_title(line: str) -> str:
    stripped = re.sub(r"\s+", " ", line.strip())
    matches = list(re.finditer(r"\b\d+\.\d+\.?\s+\S.+", stripped))
    if not matches:
        return ""
    title = matches[-1].group(0).strip()
    title = re.sub(r"\s{2,}\d+\s*$", "", title).strip()
    return title if len(title) >= 8 else ""


def segment_findings_by_numbered_sections(lines: Sequence[str]) -> List[FindingSegment]:
    """Split audit reports that use "3.1 Title" style detailed findings."""
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        title = numbered_finding_title(line)
        if title:
            anchors.append((idx, title))

    segments: List[FindingSegment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start + 1 : end]).strip()
        body_low = body.lower()
        if len(body) < 80:
            continue
        # Table-of-contents and methodology rows also look like "3.1 Title".
        # Real detailed findings in these extracted reports carry a local
        # "Severity <tier>" field near the heading, not just prose mentioning
        # severity classes later in the report.
        prefix = body[:2500]
        if not SEVERITY_FIELD_RE.search(prefix):
            continue
        if not contains_any(body_low[:2500], ("impact", "description", "recommend", "category")):
            continue
        segments.append(FindingSegment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def segment_findings(text: str) -> List[FindingSegment]:
    heading_re = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
    headings: List[Tuple[int, str, int]] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        match = heading_re.match(line)
        if match:
            headings.append((idx, match.group(2).strip().strip("#").strip(), len(match.group(1))))

    segments: List[FindingSegment] = []
    for pos, (start, title, level) in enumerate(headings):
        if not looks_like_finding_heading(title):
            continue
        end = len(lines)
        for next_start, _next_title, next_level in headings[pos + 1 :]:
            if next_level <= level:
                end = next_start
                break
        body = "\n".join(lines[start + 1 : end]).strip()
        if len(body) < 20:
            continue
        segments.append(FindingSegment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))

    if not segments:
        segments = segment_findings_by_line_anchors(lines)

    if len(segments) <= 1:
        numbered_segments = segment_findings_by_numbered_sections(lines)
        if len(numbered_segments) > len(segments):
            segments = numbered_segments

    if len(segments) <= 1:
        field_segments = segment_findings_by_audit_field_blocks(lines)
        if len(field_segments) > len(segments):
            segments = field_segments

    if not segments and text.strip():
        title = infer_title_from_text(text)
        segments.append(FindingSegment(title=title, body=text.strip(), heading_line=1, ordinal=1))
    return segments


def infer_title_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip("# \t")
        if len(stripped) >= 8:
            return stripped[:120]
    return "untitled finding"


def discover_workspace(audits_root: Optional[Path], workspace_arg: str) -> Path:
    raw = Path(workspace_arg).expanduser()
    if raw.is_absolute():
        return raw.resolve()
    if audits_root is not None:
        return (audits_root / raw).expanduser().resolve()
    return raw.resolve()


def source_priority(path: Path) -> int:
    return SOURCE_SUFFIX_PRIORITY.get(path.suffix.lower(), 99)


def discover_docs(workspaces: Iterable[Path]) -> List[SourceDoc]:
    docs: List[SourceDoc] = []
    for workspace in workspaces:
        for audit_kind in AUDIT_DIR_NAMES:
            base = workspace / audit_kind
            if not base.is_dir():
                continue
            selected: Dict[str, Path] = {}
            for path in sorted(base.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in SOURCE_EXTENSIONS:
                    continue
                stem_key = path.relative_to(base).with_suffix("").as_posix()
                current = selected.get(stem_key)
                if current is None or source_priority(path) < source_priority(current):
                    selected[stem_key] = path
            for rel_stem in sorted(selected):
                path = selected[rel_stem]
                docs.append(
                    SourceDoc(
                        workspace=workspace,
                        audit_kind=audit_kind,
                        path=path,
                        rel_path=path.relative_to(workspace),
                    )
                )
    return docs


def discover_source_file_docs(source_files: Iterable[Path]) -> List[SourceDoc]:
    docs: List[SourceDoc] = []
    for raw_path in source_files:
        path = raw_path.expanduser().resolve()
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            rel_path = path.relative_to(REPO_ROOT)
        except ValueError:
            rel_path = Path(path.name)
        docs.append(
            SourceDoc(
                workspace=CORPUS_TEXT_WORKSPACE,
                audit_kind=CORPUS_TEXT_AUDIT_KIND,
                path=path,
                rel_path=rel_path,
            )
        )
    return sorted(docs, key=lambda doc: doc.rel_path.as_posix())


def normalize_source_text(text: str) -> str:
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").strip()


def extract_pdf_text(path: Path) -> Tuple[Optional[str], str]:
    pdftotext = shutil.which("pdftotext")
    if pdftotext:
        proc = subprocess.run(
            [pdftotext, "-layout", str(path), "-"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        text = normalize_source_text(proc.stdout)
        if proc.returncode == 0 and text:
            return text, "pdftotext"

    try:
        from pdfminer.high_level import extract_text as pdfminer_extract_text  # type: ignore

        text = normalize_source_text(pdfminer_extract_text(str(path)) or "")
        if text:
            return text, "pdfminer"
    except Exception:
        pass

    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        text = normalize_source_text("\n".join(pages))
        if text:
            return text, "pypdf"
    except Exception:
        pass

    return None, "unavailable"


def read_source_text(doc: SourceDoc) -> Tuple[Optional[str], str]:
    suffix = doc.path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        try:
            text = normalize_source_text(doc.path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return None, "read-error"
        return (text or None), "existing-text"
    if suffix in PDF_EXTENSIONS:
        return extract_pdf_text(doc.path)
    return None, "unsupported"


def build_record(
    doc: SourceDoc,
    segment: FindingSegment,
    verification_tier: Optional[str] = None,
) -> Dict[str, object]:
    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    text = f"{segment.title}\n{segment.body}"
    doc_context = source_doc_context(doc.path)
    severity = infer_severity(text)
    language = infer_language(text)
    domain = infer_domain(text)
    # B8: ZK-specialized branch fires when source path is under
    # extracted_audits/zkbugs/ OR the body text has ZK keyword density
    # >= ZK_KEYWORD_DENSITY_THRESHOLD. Uses stricter signature extraction
    # and ZK-aware attack-class taxonomy.
    zk_path_match = is_zk_source_path(doc.path)
    zk_content_match = is_zk_content(text)
    zk_branch_active = zk_path_match or zk_content_match
    if zk_branch_active:
        bug_class, attack_class = infer_zk_bug_and_attack(text)
        component = infer_zk_component(segment.title, segment.body)
        raw_signature = infer_zk_signature(component, language)
        if domain == "vault":  # default fallback - override to zk-proof
            domain = "zk-proof"
    else:
        bug_class, attack_class = infer_bug_and_attack(text)
        component = infer_component(segment.title, segment.body)
        raw_signature = infer_signature(component, language)
    impact_class = infer_impact(text)
    if doc.audit_kind == CORPUS_TEXT_AUDIT_KIND:
        source_ref = f"corpus-txt:{doc.rel_path.as_posix()}:L{segment.heading_line}:S{segment.ordinal}"
        record_prefix = f"corpus-txt:{slugify(doc.rel_path.as_posix(), max_len=96)}"
    else:
        source_ref = (
            f"prior-audit:{doc.workspace.name}:{doc.rel_path.as_posix()}:"
            f"L{segment.heading_line}:S{segment.ordinal}"
        )
        record_prefix = (
            f"prior-audit:{slugify(doc.workspace.name, max_len=32)}:"
            f"{slugify(doc.rel_path.as_posix(), max_len=72)}"
        )
    digest = hashlib.sha256(f"{source_ref}\n{segment.title}\n{segment.body}".encode("utf-8")).hexdigest()[:12]
    record_id = f"{record_prefix}:L{segment.heading_line}:S{segment.ordinal}:{digest}"
    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    # Rule 37: when a verification tier is requested, emit a v1.1 record that
    # carries the tier as a first-class field (additive over v1; the validator
    # auto-detects the version). Default (tier=None) preserves the legacy v1
    # shape byte-for-byte so existing consumers are unaffected.
    schema_version = SCHEMA_VERSION_V11 if verification_tier else SCHEMA_VERSION
    record: Dict[str, object] = {
        "schema_version": schema_version,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": language,
        "target_repo": infer_repo(text, doc_context),
        "target_component": component,
        "function_shape": {
            "raw_signature": raw_signature,
            "shape_tags": shape_tags(language, bug_class, attack_class, component),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": infer_attacker_role(text),
        "attacker_action_sequence": one_line(
            segment.body,
            f"Attacker exercises the {component} path described by {segment.title}.",
        ),
        "required_preconditions": extract_preconditions(text, domain, bug_class),
        "impact_class": impact_class,
        "impact_actor": infer_impact_actor(text),
        "impact_dollar_class": infer_dollar_class(severity, impact_class),
        "fix_pattern": infer_fix_pattern(text, bug_class),
        "fix_anti_pattern_avoided": infer_fix_anti_pattern(bug_class),
        "severity_at_finding": severity,
        "year": infer_year(text, doc.path),
        "cross_language_analogues": [],
        "related_records": [],
    }
    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    if verification_tier:
        record["verification_tier"] = verification_tier
    return record


def infer_fix_pattern(text: str, bug_class: str) -> str:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip(" \t-*")
        if len(stripped) > 8 and contains_any(stripped, ("recommend", "mitigation", "fix", "remediate")):
            if stripped.lower().rstrip(":") in {"recommendation", "recommendations", "mitigation", "mitigations"}:
                for next_line in lines[idx + 1 : idx + 8]:
                    next_stripped = next_line.strip(" \t-*")
                    if len(next_stripped) > 8:
                        return next_stripped[:1000]
                continue
            return stripped[:1000]
    fixes = {
        "access-control": "enforce explicit authorization checks on every privileged state transition",
        "reentrancy": "move state updates before external calls and add a targeted reentrancy guard",
        "oracle-manipulation": "validate oracle freshness and bound price deviation against independent sources",
        "signature-replay": "bind signatures to chain, contract, nonce, signer, and action-specific payload",
        "share-inflation": "seed virtual shares and compute shares from internal accounting",
        "precision-loss": "use full-precision math and define rounding direction per actor",
        "denial-of-service": "bound iteration and isolate failing user-controlled operations",
        "input-validation": "validate all externally supplied identifiers, amounts, and account relationships",
        "accounting": "update internal accounting atomically with asset movement",
        "zk-constraint": "constrain every witness value used by the verifier-relevant computation",
    }
    return fixes.get(bug_class, "add explicit invariant checks around the affected state transition")


def infer_fix_anti_pattern(bug_class: str) -> str:
    avoided = {
        "access-control": "relying on caller conventions or UI-only restrictions",
        "reentrancy": "adding a broad guard while leaving callback-observable state inconsistent",
        "oracle-manipulation": "trusting a single spot price without freshness or deviation checks",
        "signature-replay": "hashing a payload that omits domain or nonce fields",
        "share-inflation": "using raw token balance as the sole exchange-rate source",
        "precision-loss": "silently truncating actor-favorable division results",
        "denial-of-service": "letting one user-controlled failure block unrelated users",
        "input-validation": "assuming upstream callers already checked the input",
        "accounting": "deriving owed balances from mutable external balances only",
        "zk-constraint": "using witness values in logic without corresponding constraints",
    }
    return avoided.get(bug_class, "patching symptoms without binding the violated invariant")


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if value == "":
        return '""'
    text = str(value)
    if ":" in text:
        return json.dumps(text, ensure_ascii=False)
    ambiguous_yaml = {
        "true",
        "false",
        "null",
        "yes",
        "no",
        "on",
        "off",
        "~",
    }
    numeric_like = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?(?:[eE][-+]?[0-9_]+)?", text)
    if re.fullmatch(r"[A-Za-z0-9._:/-]+", text) and text.lower() not in ambiguous_yaml and not numeric_like:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, object]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def output_filename(record: Dict[str, object]) -> str:
    record_id = str(record["record_id"])
    digest = record_id.rsplit(":", 1)[-1]
    source = str(record["source_audit_ref"])
    return f"{slugify(source, max_len=100)}-{digest}.yaml"


def extract_records(
    workspaces: Iterable[Path],
    limit: Optional[int] = None,
    source_files: Iterable[Path] = (),
    verification_tier: Optional[str] = None,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    docs = discover_docs(workspaces) + discover_source_file_docs(source_files)
    records: List[Dict[str, object]] = []
    segments_seen = 0
    documents_with_text = 0
    documents_skipped = 0
    pdf_documents = 0
    pdf_text_extracted = 0
    extraction_methods: Counter[str] = Counter()
    document_rows: List[Dict[str, object]] = []
    for doc in docs:
        if doc.path.suffix.lower() in PDF_EXTENSIONS:
            pdf_documents += 1
        text, extraction_method = read_source_text(doc)
        extraction_methods[extraction_method] += 1
        stage_row: Dict[str, object] = {
            "workspace": doc.workspace.name,
            "audit_kind": doc.audit_kind,
            "source_rel_path": doc.rel_path.as_posix(),
            "source_suffix": doc.path.suffix.lower(),
            "source_kind": "pdf" if doc.path.suffix.lower() in PDF_EXTENSIONS else "text",
            "text_extraction_method": extraction_method,
        }
        if not text:
            documents_skipped += 1
            stage_row["status"] = "skipped"
            stage_row["records_emitted"] = 0
            document_rows.append(stage_row)
            continue
        documents_with_text += 1
        if doc.path.suffix.lower() in PDF_EXTENSIONS and extraction_method != "unavailable":
            pdf_text_extracted += 1
        doc_records_before = len(records)
        for segment in segment_findings(text):
            segments_seen += 1
            # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
            records.append(build_record(doc, segment, verification_tier=verification_tier))
            if limit is not None and len(records) >= limit:
                stage_row["status"] = "processed"
                stage_row["records_emitted"] = len(records) - doc_records_before
                document_rows.append(stage_row)
                return records, {
                    "documents_scanned": len(docs),
                    "documents_with_text": documents_with_text,
                    "documents_skipped": documents_skipped,
                    "pdf_documents": pdf_documents,
                    "pdf_text_extracted": pdf_text_extracted,
                    "segments_seen": segments_seen,
                    "extraction_methods": dict(sorted(extraction_methods.items())),
                    "document_rows": document_rows,
                }
        stage_row["status"] = "processed"
        stage_row["records_emitted"] = len(records) - doc_records_before
        document_rows.append(stage_row)
    return records, {
        "documents_scanned": len(docs),
        "documents_with_text": documents_with_text,
        "documents_skipped": documents_skipped,
        "pdf_documents": pdf_documents,
        "pdf_text_extracted": pdf_text_extracted,
        "segments_seen": segments_seen,
        "extraction_methods": dict(sorted(extraction_methods.items())),
        "document_rows": document_rows,
    }


def write_records(records: Sequence[Dict[str, object]], out_dir: Path, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", action="append", default=[], help="Workspace root; repeatable.")
    parser.add_argument(
        "--source-file",
        action="append",
        default=[],
        help="Standalone audit text/PDF source file; repeatable. Emits corpus-txt records.",
    )
    parser.add_argument("--audits-root", help="Base directory used to resolve relative --workspace values.")
    parser.add_argument("--out-dir", required=True, help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument("--dry-run", action="store_true", help="Build records and summary without writing YAML files.")
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument(
        "--stage-artifact-out",
        help="Optional JSON stage artifact describing which text/PDF sources were consumed.",
    )
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    parser.add_argument(
        "--verification-tier",
        choices=VALID_PRIOR_AUDIT_TIERS,
        help=(
            "Rule 37: stamp this verification tier as a first-class field and "
            "emit v1.1 records. Default (unset) keeps the legacy v1 shape. "
            "Use tier-2-verified-public-archive for archived audit reports."
        ),
    )
    args = parser.parse_args(argv)

    if not args.workspace and not args.source_file:
        print("at least one --workspace or --source-file is required", file=sys.stderr)
        return 2
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    audits_root = Path(args.audits_root).expanduser().resolve() if args.audits_root else None
    workspaces = [discover_workspace(audits_root, item) for item in args.workspace]
    source_files = [Path(item) for item in args.source_file]
    records, counters = extract_records(
        workspaces,
        args.limit,
        source_files=source_files,
        verification_tier=args.verification_tier,
    )
    out_dir = Path(args.out_dir).expanduser().resolve()
    paths = write_records(records, out_dir, args.dry_run)

    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    summary = {
        "schema_version": SCHEMA_VERSION_V11 if args.verification_tier else SCHEMA_VERSION,
        "verification_tier": args.verification_tier,
        "workspaces": [str(path) for path in workspaces],
        "source_files": [str(path.expanduser().resolve()) for path in source_files],
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "documents_scanned": counters["documents_scanned"],
        "documents_with_text": counters["documents_with_text"],
        "documents_skipped": counters["documents_skipped"],
        "pdf_documents": counters["pdf_documents"],
        "pdf_text_extracted": counters["pdf_text_extracted"],
        "segments_seen": counters["segments_seen"],
        "records_emitted": len(records),
        "extraction_methods": counters["extraction_methods"],
        "files": [str(path) for path in paths],
    }
    if args.stage_artifact_out:
        stage_path = Path(args.stage_artifact_out).expanduser().resolve()
        stage_path.parent.mkdir(parents=True, exist_ok=True)
        stage_payload = {
            "schema_version": STAGE_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "summary": summary,
            "documents": counters["document_rows"],
        }
        stage_path.write_text(json.dumps(stage_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["stage_artifact_out"] = str(stage_path)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman prior-audit ETL: "
            f"documents={summary['documents_scanned']} records={summary['records_emitted']} "
            f"pdfs={summary['pdf_documents']} pdf_text={summary['pdf_text_extracted']} "
            f"dry_run={summary['dry_run']} out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
