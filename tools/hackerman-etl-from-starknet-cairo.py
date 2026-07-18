#!/usr/bin/env python3
"""Convert StarkNet / Cairo audit reports into hackerman_record v1 YAML.

This miner is purpose-built for StarkNet / Cairo audit corpora published by
firms such as Nethermind, Trail of Bits, Spearbit, OpenZeppelin and Zellic.
It reuses the conservative segmentation strategy from
``hackerman-etl-from-prior-audits.py`` but swaps in a StarkNet-specific
attack-class taxonomy that surfaces novel Cairo / StarkNet bug classes
(felt overflow, system-call gas abuse, account-abstraction bypass,
storage collisions across the Cairo 0 -> Cairo 1 transition, paymaster
replay, multicall isolation bypass, StarkNet system-contract rights
escalation).

Scope:
  - Sources: heading-delimited markdown / plain text audit reports plus
    text extracted from PDFs (pdftotext / pdfminer / pypdf fallback chain).
  - Filter: documents are accepted only when they look like StarkNet /
    Cairo audit reports (heading text, file extensions, or domain keyword
    density). Non-Cairo audit reports are skipped so that the
    StarkNet-specific record_id prefix stays clean.
  - Output: ``auditooor.hackerman_record.v1`` YAML records, one per
    detected finding segment.

CLI parity with ``hackerman-etl-from-prior-audits.py``: same
``--workspace`` / ``--source-file`` / ``--out-dir`` / ``--dry-run`` /
``--limit`` / ``--stage-artifact-out`` / ``--json-summary`` flags.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
STAGE_SCHEMA_VERSION = "auditooor.hackerman_starknet_cairo_stage.v1"

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

# ---------------------------------------------------------------------------
# StarkNet / Cairo attack-class taxonomy
# ---------------------------------------------------------------------------
#
# Each entry is (bug_class, attack_class, needle_tuple). Needles are matched
# case-insensitive against the finding title + body. The taxonomy is ordered
# from most specific to most generic; the first hit wins. Generic Solidity-
# era classes (reentrancy, oracle, share inflation) are intentionally kept
# at the end of the list so that StarkNet-specific patterns claim findings
# first.

CAIRO_CLASS_KEYWORDS: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "felt-arithmetic",
        "cairo-felt-overflow",
        (
            "felt overflow",
            "felt252 overflow",
            "felt wraparound",
            "p-1 overflow",
            "stark prime",
            "modulus overflow",
            "felt range check",
            "missing range check on felt",
            "u256 from felt",
            "uint256 from felt",
        ),
    ),
    (
        "felt-arithmetic",
        "cairo-1-transition-storage-collision",
        (
            "cairo 1 transition",
            "cairo1 migration",
            "cairo-0 to cairo-1",
            "cairo-0 -> cairo-1",
            "legacy storage layout",
            "storage var collision",
            "storage address collision",
            "starknet_storage::",
            "starknet::storage_access",
            "ported storage var",
        ),
    ),
    (
        "system-call-abuse",
        "system-call-gas-abuse",
        (
            "syscall gas",
            "syscall_ptr abuse",
            "system call gas",
            "library_call gas",
            "library_call_l1_handler",
            "call_contract_syscall",
            "send_message_to_l1 gas",
            "deploy_syscall gas",
            "unbounded syscall",
            "syscall reentrancy",
        ),
    ),
    # NOTE on ordering: system-contract-rights is intentionally placed
    # BEFORE the account-abstraction family. A finding that uses
    # `replace_class_syscall` to escalate privileges typically also mentions
    # `__validate__` / `__execute__` / paymaster-originated calldata; the
    # right primary classification is the system-contract-rights bug class
    # because the privileged syscall is the load-bearing primitive, not
    # the account-abstraction surface that exposed it.
    (
        "system-contract-rights",
        "starknet-system-contract-rights-escalation",
        (
            "starknet system contract",
            "deploy_account permission",
            "udc permission",
            "universal deployer",
            "starknet-os",
            "starknet os escalation",
            "class hash replace",
            "replace_class_syscall",
            "replace class syscall",
            "upgrade class hash",
            "system contract rights",
        ),
    ),
    (
        "account-abstraction",
        "paymaster-replay",
        (
            "paymaster replay",
            "paymaster nonce",
            "paymaster signature replay",
            "fee_token replay",
            "outside_execution replay",
            "outsideexecution replay",
            "snip-9 replay",
            "snip9 replay",
            "outside_execution signature",
            "outside_execution window",
        ),
    ),
    (
        "account-abstraction",
        "multicall-isolation-bypass",
        (
            "multicall isolation",
            "multicall reentrancy",
            "multi-call bypass",
            "execute calls reentrancy",
            "execute_calls reentrancy",
            "calls array reentrancy",
            "tx_info.account_contract_address",
            "tx_info reuse",
            "account multicall bypass",
        ),
    ),
    (
        "account-abstraction",
        "account-abstraction-bypass",
        (
            "__validate__",
            "__execute__",
            "validate_declare",
            "validate_deploy",
            "is_valid_signature",
            "isvalidsignature",
            "account contract bypass",
            "account abstraction bypass",
            "skipping validation",
            "__validate_declare__",
            "__validate_deploy__",
            "missing __validate__",
        ),
    ),
    (
        "signature-validation",
        "stark-curve-signature-replay",
        (
            "stark curve",
            "ecdsa replay",
            "stark signature replay",
            "starknet signature replay",
            "tx_hash replay",
            "transaction hash collision",
            "missing chain_id binding",
            "missing chain id in hash",
            "missing nonce in hash",
        ),
    ),
    (
        "l1-l2-messaging",
        "l1-l2-message-replay",
        (
            "l1 handler replay",
            "l1_handler replay",
            "send_message_to_l1 replay",
            "message_nonce reuse",
            "l1->l2 replay",
            "l1-l2 replay",
            "l2->l1 replay",
            "consume_message_from_l2",
            "cancel_l1_to_l2_message bypass",
        ),
    ),
    (
        "access-control",
        "openzeppelin-cairo-ownable-bypass",
        (
            "ownable component",
            "ownable_cpt",
            "ownable cairo",
            "ownable.cairo bypass",
            "two_step ownership",
            "transfer_ownership cairo",
            "renounce_ownership cairo",
            "access component bypass",
            "accesscontrol_cpt",
            "accesscontrol component",
        ),
    ),
    (
        "access-control",
        "openzeppelin-cairo-upgradeable-bypass",
        (
            "upgradeable component",
            "upgradeable_cpt",
            "upgradeable.cairo bypass",
            "upgrade impl bypass",
            "_upgrade missing auth",
            "upgrade class hash missing auth",
        ),
    ),
    (
        "input-validation",
        "missing-cairo-input-validation",
        (
            "missing validation",
            "input not validated",
            "unchecked array length",
            "unchecked span length",
            "span<felt252> length",
            "assert_lt_felt missing",
            "assert_le_felt missing",
            "unchecked low / high",
            "low/high split missing check",
        ),
    ),
    (
        "reentrancy",
        "cairo-callback-reentrancy",
        (
            "reentrancy cairo",
            "cairo reentrancy",
            "external call cairo",
            "call_contract reentrancy",
            "library_call reentrancy",
            "missing reentrancyguard",
            "reentrancyguard_cpt",
            "reentrancy guard component",
        ),
    ),
    (
        "oracle-manipulation",
        "cairo-stale-or-manipulated-oracle",
        (
            "pragma oracle",
            "empiric oracle",
            "stark oracle",
            "stale oracle cairo",
            "oracle staleness cairo",
            "median price cairo",
            "twap cairo",
        ),
    ),
    (
        "share-inflation",
        "cairo-first-depositor-share-inflation",
        (
            "first depositor cairo",
            "share inflation cairo",
            "erc4626 cairo",
            "openzeppelin erc4626 cairo",
        ),
    ),
    (
        "denial-of-service",
        "cairo-dos-griefing",
        (
            "unbounded loop cairo",
            "loop cairo dos",
            "n step cairo griefing",
            "steps limit cairo",
            "n_steps overflow",
        ),
    ),
)

# ---------------------------------------------------------------------------
# Domain inference
# ---------------------------------------------------------------------------

CAIRO_DOMAIN_KEYWORDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "consensus",
        (
            "system contract",
            "starknet os",
            "starknet-os",
            "sequencer",
            "block_hash_contract",
            "deploy_account",
            "class hash",
            "replace_class_syscall",
            "l1_handler",
            "send_message_to_l1",
            "consume_message_from_l2",
            "starkgate",
            "stark gate",
            "messaging bridge",
        ),
    ),
    (
        "rollup",
        (
            "rollup",
            "fraud proof cairo",
            "state root cairo",
            "starknet l2",
        ),
    ),
    (
        "bridge",
        (
            "bridge cairo",
            "starkgate bridge",
            "l1 to l2",
            "l2 to l1",
            "l1->l2",
            "l2->l1",
        ),
    ),
    (
        "zk-proof",
        (
            "stark proof",
            "stwo prover",
            "stone prover",
            "trace polynomial",
            "fri prover",
            "fri verifier",
            "ec_op",
            "pedersen builtin",
            "poseidon builtin",
            "stark constraint",
        ),
    ),
    (
        "dex",
        (
            "ekubo",
            "jediswap",
            "myswap",
            "10kswap",
            "sithswap",
            "starkdefi",
            "amm cairo",
            "swap cairo",
            "liquidity pool cairo",
            "clob cairo",
        ),
    ),
    (
        "lending",
        (
            "nostra",
            "zklend",
            "carmine",
            "vesu",
            "starkfish",
            "lending cairo",
            "borrow cairo",
            "collateral cairo",
            "liquidation cairo",
        ),
    ),
    (
        "vault",
        (
            "erc4626 cairo",
            "vault cairo",
            "deposit/withdraw cairo",
        ),
    ),
    (
        "governance",
        (
            "governor cairo",
            "snapshot cairo",
            "proposal cairo",
            "voting cairo",
            "timelock cairo",
        ),
    ),
    (
        "staking",
        (
            "stake cairo",
            "staking cairo",
            "validator cairo",
            "delegator cairo",
        ),
    ),
    (
        "nft",
        (
            "erc721 cairo",
            "nft cairo",
            "starknet.id",
            "starknetid",
        ),
    ),
)

IMPACT_KEYWORDS = (
    ("theft", ("steal", "theft", "drain", "loss of funds", "fund loss", "withdraw arbitrary")),
    ("freeze", ("freeze", "locked", "stuck funds", "cannot withdraw", "permanently locked")),
    ("dos", ("denial of service", " dos ", "revert", "blocked", "stuck transaction")),
    ("griefing", ("grief", "censor")),
    ("yield-redistribution", ("reward", "yield", "interest")),
    ("precision-loss", ("rounding", "precision", "truncation")),
    ("governance-takeover", ("governance takeover", "quorum", "proposal hijack")),
    ("privilege-escalation", ("privilege", "unauthorized owner", "admin bypass", "class hash replace")),
)

SEVERITY_ALIASES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("critical", ("critical", "crit", "c-", "[c]", "(c)")),
    ("high", ("high", "h-", "[h]", "(h)")),
    ("medium", ("medium", "med", "m-", "[m]", "(m)")),
    ("low", ("low", "l-", "[l]", "(l)")),
    ("info", ("informational", "info", "note", "n-")),
)

# Heuristics that classify a document as StarkNet / Cairo audit text.
# Path-token detector. We split on `_` / `-` / `.` / `/` boundaries and
# check whether ANY token equals (case-insensitive) one of the StarkNet
# tokens. This avoids false matches like `non_starknet` while keeping
# real signals (`nethermind_cairo_2025.pdf`, `audits/starknet/report.md`,
# `argent-contracts-starknet`) intact. The regex form is a fallback for
# code that wants pure regex semantics.
STARKNET_PATH_TOKENS = frozenset(
    {
        "cairo",
        "cairo1",
        "cairo-1",
        "starknet",
        "starkware",
        "nethermind",
        "starkgate",
        "openzeppelin-cairo",
        "starknet-id",
        "starknet_id",
        "argent-contracts-starknet",
    }
)
STARKNET_PATH_NEGATIVE_TOKENS = frozenset({"non_starknet", "non-starknet"})
STARKNET_FILE_TOKEN_RE = re.compile(
    r"\b(cairo|starknet|starkware|nethermind|cairo-1|cairo1|starkgate|"
    r"openzeppelin-cairo|starknet-id|starknet_id)\b",
    re.IGNORECASE,
)
STARKNET_KEYWORD_DENSITY_TERMS = (
    "cairo",
    "starknet",
    "felt252",
    "starkware",
    "syscall",
    "l1_handler",
    "starkgate",
    "openzeppelin-cairo",
    "account contract",
    "snip-",
)
STARKNET_KEYWORD_DENSITY_THRESHOLD = 3

SEVERITY_FIELD_RE = re.compile(r"\bSeverity\s+(Critical|High|Medium|Low|Informational|Info)\b", re.IGNORECASE)
FINDING_ANCHOR_RE = re.compile(
    r"^(?:\s*(?:[-*>\d.()]+\s*)?(?:#{1,6}\s*)?)?"
    r"(?:\[[hmlc]\]|\([hmlc]\)|[hmlc][-_ ]?\d{1,3}\b|(?:finding|issue|vulnerability)\s*(?:#|no\.?)?\s*\d+\b)",
    re.IGNORECASE,
)
AUDIT_FIELD_RE = re.compile(r"^(?:Project|Type|Severity|Impact|Exploitability|Status|Issue)\b", re.IGNORECASE)
YEAR_RE = re.compile(r"(?<!\d)(20[0-9]{2})(?!\d)")

# Strict Cairo signature shapes accepted by the signature extractor. Each
# pattern's group(1) is the raw signature text.
CAIRO_SIGNATURE_PATTERNS = (
    # Cairo 1 / Cairo: fn / func name(args) -> ret
    re.compile(r"\b(fn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]{0,80}>)?\s*\([^)]{0,240}\)(?:\s*->\s*[A-Za-z_][^{;\n]{0,120})?)"),
    re.compile(r"\b(func\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\{[^}]{0,80}\})?\s*\([^)]{0,240}\)(?:\s*->\s*\([^)]{0,160}\))?)"),
    # Cairo storage var declaration
    re.compile(r"\b(@storage_var\s*\n?\s*func\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,160}\))"),
    # Cairo external / view declarations
    re.compile(r"\b(@(?:external|view|l1_handler|constructor)\s*\n?\s*func\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,200}\))"),
    # Cairo 1 trait method signature
    re.compile(r"\b(trait\s+[A-Za-z_][A-Za-z0-9_]*<[^>]{0,80}>)"),
    # Cairo 1 #[abi(embed_v0)] impl
    re.compile(r"\b(impl\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^>]{0,80}>)?\s+of\s+[A-Za-z_][A-Za-z0-9_:]{0,80}(?:<[^>]{0,80}>)?)"),
)


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def first_match(
    text: str,
    choices: Sequence[Tuple[str, Sequence[str]]],
    default: str,
) -> str:
    for value, needles in choices:
        if contains_any(text, needles):
            return value
    return default


def is_starknet_path(path: Path) -> bool:
    """True iff any path token equals a StarkNet token.

    Tokens are split on `_`, `-`, `.`, `/`. Path components like
    ``non_starknet`` deliberately do NOT match because no token equals a
    listed StarkNet term in isolation. This keeps fixture/test scaffolding
    out of the StarkNet bucket while still catching real signals such as
    ``argent-contracts-starknet`` or ``nethermind_cairo_2025.pdf``.
    """
    raw = str(path).lower()
    if any(token in raw for token in STARKNET_PATH_NEGATIVE_TOKENS):
        return False
    tokens = re.split(r"[_\-./\\]+", raw)
    for token in tokens:
        if token in STARKNET_PATH_TOKENS:
            return True
    return False


def starknet_keyword_density(text: str) -> int:
    low = text.lower()
    total = 0
    for term in STARKNET_KEYWORD_DENSITY_TERMS:
        total += low.count(term)
    return total


def is_starknet_corpus(path: Path, text: str) -> bool:
    """Return True if the document looks like a StarkNet / Cairo audit."""
    if is_starknet_path(path):
        return True
    return starknet_keyword_density(text) >= STARKNET_KEYWORD_DENSITY_THRESHOLD


def normalize_source_text(text: str) -> str:
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").strip()


def source_doc_context(path: Path, max_chars: int = 8000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------


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


def infer_target_language(text: str, path: Path) -> str:
    """All flavors of Cairo (Cairo 0, Cairo 1, Cairo 2.x) normalise to `cairo`.

    The schema's target_language enum does not contain a `cairo-1` value;
    keeping a single `cairo` bucket lets downstream tooling treat every
    StarkNet record uniformly.
    """
    low = f"{path.name}\n{text}".lower()
    if "cairo" in low or "starknet" in low or "starkware" in low or "felt252" in low:
        return "cairo"
    return "cairo"


def infer_domain(text: str) -> str:
    return first_match(text, CAIRO_DOMAIN_KEYWORDS, "vault")


def infer_bug_and_attack(text: str) -> Tuple[str, str]:
    low = text.lower()
    for bug_class, attack_class, needles in CAIRO_CLASS_KEYWORDS:
        if any(needle in low for needle in needles):
            return bug_class, attack_class
    return "logic-error", "cairo-protocol-invariant-bypass"


def infer_impact(text: str) -> str:
    return first_match(text, IMPACT_KEYWORDS, "griefing")


def infer_attacker_role(text: str) -> str:
    low = text.lower()
    if "sequencer" in low:
        return "sequencer"
    if "validator" in low:
        return "validator"
    if contains_any(low, ("governance", "proposal", "voter")):
        return "governance"
    if contains_any(low, ("admin", "owner", "privileged", "class hash replace")):
        return "privileged-compromised"
    if "proposer" in low or "block proposer" in low:
        return "block-proposer"
    return "unprivileged"


def infer_impact_actor(text: str) -> str:
    low = text.lower()
    if contains_any(low, ("treasury", "protocol", "fee_token")):
        return "protocol-treasury"
    if "sequencer" in low:
        return "sequencer"
    if "validator" in low:
        return "validator-set"
    if contains_any(low, ("depositor", "lp", "liquidity provider", "borrower", "lender")):
        return "depositor-class"
    if contains_any(low, ("reward", "yield")):
        return "yield-recipient"
    if contains_any(low, ("victim", "specific user", "specific account")):
        return "specific-user"
    return "arbitrary-user"


def infer_dollar_class(severity: str, impact_class: str) -> str:
    if impact_class in {"griefing", "dos"} and severity in {"low", "info"}:
        return "non-financial"
    return {
        "critical": ">=$1M",
        "high": "$100K-$1M",
        "medium": "$10K-$100K",
        "low": "<$10K",
        "info": "non-financial",
    }[severity]


def infer_year(text: str, path: Path) -> int:
    sources = [str(path), path.name, text[:4000]]
    joined = " ".join(sources)
    for raw in YEAR_RE.findall(joined):
        year = int(raw)
        if 2000 <= year <= 2100:
            return year
    return 2000


def is_generic_component(component: str) -> bool:
    low = component.strip().lower()
    generic_prefixes = (
        "function contains",
        "function in",
        "function as",
        "function to",
        "function that",
        "function of",
        "the function",
        "function with",
        "function for",
        "the cairo",
        "this cairo",
    )
    return any(low.startswith(prefix) for prefix in generic_prefixes)


def infer_component(title: str, body: str) -> str:
    haystack = f"{title}\n{body}"
    # Prefer strict Cairo signature shapes first.
    for pattern in CAIRO_SIGNATURE_PATTERNS:
        match = pattern.search(haystack)
        if match:
            component = match.group(1).strip()[:240]
            if not is_generic_component(component):
                return component
    # Backtick identifiers that look like callable shapes.
    for raw in re.findall(r"`([^`\n]{1,120})`", haystack):
        cand = raw.strip()
        if cand and (
            "(" in cand
            or cand.startswith("@")
            or cand.startswith("__")
            or "::" in cand
            or cand.endswith("_syscall")
        ):
            return cand[:240]
    # Generic fallbacks.
    patterns = (
        r"\b((?:@(?:external|view|l1_handler|constructor|storage_var)\s+)?func\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,200}\))",
        r"\b(__[a-z_][a-z0-9_]*__)",
        r"\b([A-Za-z_][A-Za-z0-9_]{2,}_syscall)",
        r"\b((?:I[A-Z][A-Za-z0-9_]+)::[A-Za-z_][A-Za-z0-9_]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            component = match.group(1).strip()[:240]
            if not is_generic_component(component):
                return component
    return title[:240] or "unknown-cairo-component"


def is_cairo_signature_shape(text: str) -> bool:
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 4:
        return False
    return any(pattern.search(stripped) for pattern in CAIRO_SIGNATURE_PATTERNS)


def infer_signature(component: str) -> str:
    if is_cairo_signature_shape(component):
        return component
    if "(" in component:
        return component
    # Bare identifiers - synthesise a Cairo-style signature stub.
    bare = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,}", component)
    if bare:
        return f"fn {component}(...)"
    return component


def shape_tags(bug_class: str, attack_class: str, component: str) -> List[str]:
    tags = [slugify(attack_class), slugify(f"cairo-{bug_class}")]
    comp = slugify(component, max_len=48)
    if comp and comp not in tags:
        tags.append(comp)
    return tags[:3]


def extract_preconditions(text: str, domain: str, bug_class: str) -> List[str]:
    bullets: List[str] = []
    for line in text.splitlines():
        stripped = line.strip(" \t-*")
        if len(stripped) < 8:
            continue
        if contains_any(
            stripped,
            (
                "precondition",
                "requires",
                "when ",
                "if ",
                "attacker can",
                "user can",
                "after",
                "deployed",
            ),
        ):
            bullets.append(stripped[:220])
    if bullets:
        return list(dict.fromkeys(bullets))[:3]
    return [f"StarkNet {domain} contract exposes behavior consistent with {bug_class}."]


def infer_fix_pattern(text: str, bug_class: str) -> str:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip(" \t-*")
        if len(stripped) > 8 and contains_any(
            stripped, ("recommend", "mitigation", "fix", "remediate", "remediation")
        ):
            if stripped.lower().rstrip(":") in {
                "recommendation",
                "recommendations",
                "mitigation",
                "mitigations",
                "remediation",
            }:
                for next_line in lines[idx + 1 : idx + 8]:
                    next_stripped = next_line.strip(" \t-*")
                    if len(next_stripped) > 8:
                        return next_stripped[:1000]
                continue
            return stripped[:1000]
    fixes = {
        "felt-arithmetic": (
            "split values into low/high u128 halves before arithmetic and assert via "
            "assert_lt_felt252 / assert_le_felt252; never assume felt252 wraps like u256"
        ),
        "system-call-abuse": (
            "bound syscall iteration, validate syscall return data, and avoid nested "
            "library_call / call_contract loops that the caller cannot meter"
        ),
        "account-abstraction": (
            "bind __validate__ / __execute__ to chain_id, account address, nonce, and "
            "the exact calls array; reject paymaster-originated calldata when nonce is "
            "already consumed"
        ),
        "system-contract-rights": (
            "gate replace_class_syscall / upgrade behind an Ownable2Step + Timelock; do "
            "not let __default__ or fallback paths invoke privileged system calls"
        ),
        "signature-validation": (
            "include chain_id, contract_address, and a strictly-increasing nonce inside "
            "the Pedersen / Poseidon hash that the StarkCurve signature commits to"
        ),
        "l1-l2-messaging": (
            "track consumed L1->L2 message hashes in a Map<felt252, bool>; refuse to "
            "consume a message twice and bind every payload to a unique message_nonce"
        ),
        "access-control": (
            "delegate authorisation to the OpenZeppelin Ownable / AccessControl Cairo "
            "components and assert ownership on every privileged entrypoint"
        ),
        "input-validation": (
            "validate every Span<felt252> length, every low/high pair, and every external "
            "contract address before the state transition runs"
        ),
        "reentrancy": (
            "guard external call_contract / library_call paths with the OpenZeppelin "
            "ReentrancyGuard Cairo component and apply checks-effects-interactions"
        ),
        "oracle-manipulation": (
            "validate pragma / empiric oracle freshness using last_updated_timestamp and "
            "bound deviation versus an independent feed"
        ),
        "share-inflation": (
            "seed virtual shares inside the Cairo ERC4626 component and derive shares "
            "from internal accounting instead of get_balance_of"
        ),
        "denial-of-service": (
            "bound n_steps usage per entrypoint and isolate user-controlled failures so "
            "one caller cannot block unrelated multicall siblings"
        ),
    }
    return fixes.get(bug_class, "add explicit invariant checks around the affected StarkNet state transition")


def infer_fix_anti_pattern(bug_class: str) -> str:
    avoided = {
        "felt-arithmetic": "performing arithmetic directly on felt252 values and assuming Solidity-style u256 wraparound",
        "system-call-abuse": "trusting syscall return data without bounding gas / iteration on call_contract / library_call",
        "account-abstraction": "treating __validate__ as a stub that only checks signatures without binding to the calls array",
        "system-contract-rights": "leaving replace_class_syscall reachable from non-owner entrypoints",
        "signature-validation": "hashing a payload that omits chain_id / contract_address / nonce before passing it to StarkCurve verify",
        "l1-l2-messaging": "marking an L1->L2 message consumed only after side effects, which lets the same message replay on revert",
        "access-control": "implementing ad-hoc owner checks rather than reusing the audited Ownable / AccessControl Cairo components",
        "input-validation": "assuming Span lengths or low/high splits were validated by an upstream entrypoint",
        "reentrancy": "patching one entrypoint while leaving the storage write order inconsistent on the callback path",
        "oracle-manipulation": "trusting a single Pragma / Empiric spot price without freshness or deviation checks",
        "share-inflation": "using ERC20.balance_of as the sole exchange-rate source in a Cairo ERC4626",
        "denial-of-service": "leaving one user-controlled call inside a multicall capable of failing every sibling",
    }
    return avoided.get(bug_class, "patching symptoms without binding the violated StarkNet invariant")


# ---------------------------------------------------------------------------
# Repo inference
# ---------------------------------------------------------------------------

PATHLIKE_REPO_OWNERS = {
    "x",
    "src",
    "scripts",
    "github.com",
    "starknet.io",
    "starkware.co",
    "cairo-lang",
    "tests",
    "audits",
    "audit",
    "docs",
}
PATHLIKE_REPO_NAMES = {
    "common",
    "core",
    "src",
    "tests",
    "audits",
    "docs",
    "openzeppelin",
}


def is_pathlike_repo_candidate(candidate: str) -> bool:
    if "/" not in candidate:
        return True
    owner, repo = candidate.split("/", 1)
    owner_low = owner.lower()
    repo_low = repo.lower()
    if owner_low in PATHLIKE_REPO_OWNERS or repo_low in PATHLIKE_REPO_NAMES:
        return True
    if repo_low.endswith((".cairo", ".sol", ".md", ".txt", ".pdf", ".json")):
        return True
    if re.fullmatch(r"\d+", owner) or re.fullmatch(r"\d+", repo):
        return True
    if candidate.upper() == "N/A":
        return True
    return False


def _normalize_repo_slug(repo: str) -> str:
    repo = repo.rstrip("-.")
    low = repo.lower()
    if low in {"openzeppelin/cairo-contracts", "openzeppelin/openzeppelin-cairo"}:
        return "OpenZeppelin/cairo-contracts"
    if low in {"starkware-libs/cairo-lang", "starkware-libs/cairolang"}:
        return "starkware-libs/cairo-lang"
    if low in {"argentlabs/argent-contracts-starknet", "argentlabs/argent-contracts"}:
        return "argentlabs/argent-contracts-starknet"
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
        return _normalize_repo_slug(github_matches[0])
    if re.search(r"\bopenzeppelin[- _]cairo\b", combined, re.IGNORECASE):
        return "OpenZeppelin/cairo-contracts"
    if re.search(r"\bcairo-lang\b|\bstarknet-os\b", combined, re.IGNORECASE):
        return "starkware-libs/cairo-lang"
    matches = re.findall(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", text)
    if not matches:
        return "unknown"
    for candidate in matches:
        if is_pathlike_repo_candidate(candidate):
            continue
        return _normalize_repo_slug(candidate)
    return "unknown"


# ---------------------------------------------------------------------------
# Segmentation (heading + numbered-section fallbacks)
# ---------------------------------------------------------------------------


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


def numbered_finding_title(line: str) -> str:
    stripped = re.sub(r"\s+", " ", line.strip())
    matches = list(re.finditer(r"\b\d+\.\d+\.?\s+\S.+", stripped))
    if not matches:
        return ""
    title = matches[-1].group(0).strip()
    title = re.sub(r"\s{2,}\d+\s*$", "", title).strip()
    return title if len(title) >= 8 else ""


def segment_findings_by_numbered_sections(lines: Sequence[str]) -> List[FindingSegment]:
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
        numbered = segment_findings_by_numbered_sections(lines)
        if len(numbered) > len(segments):
            segments = numbered

    if not segments and text.strip():
        title = infer_title_from_text(text)
        segments.append(FindingSegment(title=title, body=text.strip(), heading_line=1, ordinal=1))
    return segments


def infer_title_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip("# \t")
        if len(stripped) >= 8:
            return stripped[:120]
    return "untitled cairo finding"


def one_line(text: str, fallback: str) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    return cleaned[:800] if cleaned else fallback


# ---------------------------------------------------------------------------
# Workspace discovery / IO
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Record build / serialisation
# ---------------------------------------------------------------------------


def build_record(doc: SourceDoc, segment: FindingSegment) -> Dict[str, object]:
    text = f"{segment.title}\n{segment.body}"
    doc_context = source_doc_context(doc.path)

    severity = infer_severity(text)
    domain = infer_domain(text)
    bug_class, attack_class = infer_bug_and_attack(text)
    component = infer_component(segment.title, segment.body)
    raw_signature = infer_signature(component)
    impact_class = infer_impact(text)
    target_language = infer_target_language(text, doc.path)

    if doc.audit_kind == CORPUS_TEXT_AUDIT_KIND:
        source_ref = f"starknet-cairo-corpus:{doc.rel_path.as_posix()}:L{segment.heading_line}:S{segment.ordinal}"
        record_prefix = f"starknet-cairo-corpus:{slugify(doc.rel_path.as_posix(), max_len=80)}"
    else:
        source_ref = (
            f"starknet-cairo:{doc.workspace.name}:{doc.rel_path.as_posix()}:"
            f"L{segment.heading_line}:S{segment.ordinal}"
        )
        record_prefix = (
            f"starknet-cairo:{slugify(doc.workspace.name, max_len=32)}:"
            f"{slugify(doc.rel_path.as_posix(), max_len=64)}"
        )
    digest = hashlib.sha256(
        f"{source_ref}\n{segment.title}\n{segment.body}".encode("utf-8")
    ).hexdigest()[:12]
    record_id = f"{record_prefix}:L{segment.heading_line}:S{segment.ordinal}:{digest}"

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": target_language,
        "target_repo": infer_repo(text, doc_context),
        "target_component": component,
        "function_shape": {
            "raw_signature": raw_signature,
            "shape_tags": shape_tags(bug_class, attack_class, component),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": infer_attacker_role(text),
        "attacker_action_sequence": one_line(
            segment.body,
            f"Attacker exercises the {component} StarkNet path described by {segment.title}.",
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
    ambiguous_yaml = {"true", "false", "null", "yes", "no", "on", "off", "~"}
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
                    lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def output_filename(record: Dict[str, object]) -> str:
    record_id = str(record["record_id"])
    digest = record_id.rsplit(":", 1)[-1]
    source = str(record["source_audit_ref"])
    return f"{slugify(source, max_len=100)}-{digest}.yaml"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def extract_records(
    workspaces: Iterable[Path],
    limit: Optional[int] = None,
    source_files: Iterable[Path] = (),
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    docs = discover_docs(workspaces) + discover_source_file_docs(source_files)
    records: List[Dict[str, object]] = []
    segments_seen = 0
    documents_with_text = 0
    documents_skipped = 0
    documents_non_starknet = 0
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
        if not is_starknet_corpus(doc.path, text):
            documents_non_starknet += 1
            stage_row["status"] = "non-starknet"
            stage_row["records_emitted"] = 0
            document_rows.append(stage_row)
            continue
        documents_with_text += 1
        if doc.path.suffix.lower() in PDF_EXTENSIONS and extraction_method != "unavailable":
            pdf_text_extracted += 1
        doc_records_before = len(records)
        for segment in segment_findings(text):
            segments_seen += 1
            records.append(build_record(doc, segment))
            if limit is not None and len(records) >= limit:
                stage_row["status"] = "processed"
                stage_row["records_emitted"] = len(records) - doc_records_before
                document_rows.append(stage_row)
                return records, {
                    "documents_scanned": len(docs),
                    "documents_with_text": documents_with_text,
                    "documents_skipped": documents_skipped,
                    "documents_non_starknet": documents_non_starknet,
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
        "documents_non_starknet": documents_non_starknet,
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
        help="Standalone StarkNet / Cairo audit text/PDF source file; repeatable.",
    )
    parser.add_argument(
        "--audits-root",
        help="Base directory used to resolve relative --workspace values.",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory for emitted hackerman_record YAML files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build records and summary without writing YAML files.",
    )
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument(
        "--stage-artifact-out",
        help="Optional JSON stage artifact describing which text/PDF sources were consumed.",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a machine-readable JSON summary.",
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
    records, counters = extract_records(workspaces, args.limit, source_files=source_files)
    out_dir = Path(args.out_dir).expanduser().resolve()
    paths = write_records(records, out_dir, args.dry_run)

    summary: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "stage_schema_version": STAGE_SCHEMA_VERSION,
        "workspaces": [str(path) for path in workspaces],
        "source_files": [str(path.expanduser().resolve()) for path in source_files],
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "documents_scanned": counters["documents_scanned"],
        "documents_with_text": counters["documents_with_text"],
        "documents_skipped": counters["documents_skipped"],
        "documents_non_starknet": counters["documents_non_starknet"],
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
            "hackerman starknet-cairo ETL: "
            f"documents={summary['documents_scanned']} records={summary['records_emitted']} "
            f"non_starknet={summary['documents_non_starknet']} pdfs={summary['pdf_documents']} "
            f"pdf_text={summary['pdf_text_extracted']} dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
