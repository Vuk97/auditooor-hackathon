#!/usr/bin/env python3
"""Hackerman record ETL from public bounty/audit-platform report archives.

Wave-5 TIER D Lift D5: ingest fresh records from public report archives shipped
by Cantina, Cyfrin, Hats Finance and Pashov Audit Group into hackerman_record
v1 YAML. The target is breadth (~2,500 records) across the four platforms with
honest deduplication against the existing canonical corpus.

Network policy: this tool is strictly offline. It walks a curated local mirror
passed via --platform-mirror (typically a clone of github.com/Cyfrin/audit-
reports, github.com/pashov/audits, or an operator-scraped Cantina/Hats dump).
The mirror layout is auto-detected by directory name; nothing is fetched.

Inputs:
  --platform-mirror PLATFORM=PATH    Repeatable. PLATFORM is one of
                                     cantina|cyfrin|hats|pashov (case-insensitive).
                                     Each PATH is walked recursively for .md /
                                     .markdown / .txt / .pdf reports.
  --existing-index PATH              Optional. Path to the canonical
                                     audit/corpus_tags/index/by_target_repo.jsonl
                                     index. Records whose (target_repo, title
                                     slug) pair is already present are skipped
                                     (additive-only contract).
  --out-dir PATH                     Directory to emit per-record YAML.
  --stage-artifact-out PATH          Optional JSON stage artifact: original
                                     severity tracking + 3 mitigation states
                                     (disclosed / acknowledged / fixed) per
                                     finding (the canonical schema is locked,
                                     so this rides as a sidecar).

The tool is intentionally conservative: missing-status fields stay null rather
than guessing, and the additive-only contract is enforced via the existing
target_repo index. See tools/hackerman-etl-from-prior-audits.py for the
sibling ETL pattern this file follows.
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
STAGE_SCHEMA_VERSION = "auditooor.hackerman_platform_stage.v1"

TEXT_EXTENSIONS = {".md", ".markdown", ".txt"}
PDF_EXTENSIONS = {".pdf"}
SOURCE_EXTENSIONS = TEXT_EXTENSIONS | PDF_EXTENSIONS

SUPPORTED_PLATFORMS = {
    "cantina": {
        "default_year": 2024,
        "ref_prefix": "cantina",
        "title_repo_hint": ("cantina.xyz", "competitions", "bounties"),
    },
    "cyfrin": {
        "default_year": 2024,
        "ref_prefix": "cyfrin",
        "title_repo_hint": ("cyfrin.io", "github.com/cyfrin/audit-reports"),
    },
    "hats": {
        "default_year": 2024,
        "ref_prefix": "hats-finance",
        "title_repo_hint": ("hats.finance",),
    },
    "pashov": {
        "default_year": 2024,
        "ref_prefix": "pashov-audit-group",
        "title_repo_hint": ("github.com/pashov/audits",),
    },
}

SEVERITY_ALIASES = (
    ("critical", ("critical", "crit", "c-")),
    ("high", ("high", "h-", "[h", "(h")),
    ("medium", ("medium", "med", "m-", "[m", "(m")),
    ("low", ("low", "l-", "[l", "(l")),
    ("info", ("informational", "info", "note", "n-", "gas", "qa")),
)

# Reused minimal versions of the prior-audits keyword tables. Tight by design;
# we lean on the existing schema enum and let the validator surface drift.
LANGUAGE_KEYWORDS = (
    ("rust", ("rust", "anchor", "solana", "cargo", ".rs")),
    ("go", ("golang", " cosmos ", ".go ", "geth", "cosmos-sdk", "msgserver", "cometbft")),
    ("move", ("move module", "sui::", "aptos")),
    ("vyper", ("vyper", ".vy")),
    ("cairo", ("cairo", "starknet")),
    ("solidity", ("solidity", "smart contract", "erc20", "erc721", "erc4626", ".sol", "msg.sender", "uint256")),
)

DOMAIN_KEYWORDS = (
    ("bridge", ("bridge", "cross-chain", "messaging", "lz", "layerzero", "wormhole")),
    ("rollup", ("rollup", "sequencer", "fraud proof", "state root")),
    ("oracle", ("oracle", "price feed", "chainlink", "pyth", "twap")),
    ("governance", ("governance", "proposal", "vote", "timelock", "quorum")),
    ("dex", ("dex", "swap", "amm", "liquidity pool", "uniswap", "curve", "slippage")),
    ("lending", ("borrow", "lend", "loan", "liquidation", "collateral", "debt")),
    ("staking", ("stake", "staking", "validator", "delegator", "slash")),
    ("nft", ("nft", "erc721", "erc-721", "royalty")),
    ("dao", ("dao", "ragequit", "treasury")),
    ("escrow", ("escrow", "vesting", "lockup")),
    ("zk-proof", ("zk", "zero-knowledge", "circuit", "constraint", "witness", "halo2", "circom")),
    ("consensus", ("consensus", "validator set", "cometbft", "block proposer")),
    ("rpc-infra", ("rpc", "mempool", "node")),
    ("l1-client", ("evm client", "execution client", "reth", "geth")),
    ("vault", ("vault", "erc4626", "shares", "deposit", "withdraw")),
)

CLASS_KEYWORDS = (
    ("access-control", "admin-bypass", ("access control", "unauthorized", "onlyowner", "permission", "privilege")),
    ("reentrancy", "callback-reentrancy", ("reentrancy", "reentrant", "callback")),
    ("oracle-manipulation", "stale-or-manipulated-oracle", ("oracle", "stale price", "twap", "price manipulation")),
    ("signature-replay", "signature-replay", ("signature", "replay", "eip712", "permit")),
    ("share-inflation", "first-deposit-share-inflation", ("share inflation", "first depositor", "erc4626", "donation")),
    ("precision-loss", "rounding-precision-loss", ("rounding", "precision", "truncation", "division")),
    ("denial-of-service", "dos-griefing", ("denial of service", "dos", "grief", "stuck")),
    ("input-validation", "missing-input-validation", ("missing validation", "input validation", "unchecked", "not validated")),
    ("accounting", "state-accounting-drift", ("accounting", "balance drift", "debt", "reward accounting")),
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

# Mitigation state heuristics. We use three distinct slots so triagers can see
# which states are unknown vs. observed.
MITIGATION_DISCLOSED_PATTERNS = (
    "disclosed",
    "reported by",
    "reporter",
    "submitted",
    "publicly disclosed",
)
MITIGATION_ACK_PATTERNS = (
    "acknowledged",
    "wont fix",
    "won't fix",
    "by design",
    "informational",
    "no action",
    "accepted",
    "ack",
)
MITIGATION_FIXED_PATTERNS = (
    "fixed",
    "patched",
    "mitigated",
    "resolved",
    "remediated",
    "addressed",
    "fix at",
    "commit",
    "pull request",
    "pr #",
)

FINDING_ANCHOR_RE = re.compile(
    r"^(?:\s*(?:[-*>\d.()]+\s*)?(?:#{1,6}\s*)?)?"
    r"(?:\[[hmlc]\]|\([hmlc]\)|[hmlc][-_ ]?\d{1,3}\b|(?:finding|issue|vulnerability)\s*(?:#|no\.?)?\s*\d+\b)",
    re.IGNORECASE,
)
SEVERITY_FIELD_RE = re.compile(
    r"\b(?:Severity|Risk|Impact Rating)\s*[:\-]?\s*(Critical|High|Medium|Low|Informational|Info|Gas|QA)\b",
    re.IGNORECASE,
)


class FindingSegment(NamedTuple):
    title: str
    body: str
    heading_line: int
    ordinal: int


class PlatformDoc(NamedTuple):
    platform: str
    mirror_root: Path
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
        if field_value in {"gas", "qa", "informational", "info", "note"}:
            return "info"
        for severity, _ in SEVERITY_ALIASES:
            if severity == field_value:
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
    if contains_any(low, ("validator set", "validator can ")):
        return "validator"
    if "sequencer" in low:
        return "sequencer"
    if contains_any(low, ("governance", "proposal", "voter")):
        return "governance"
    if contains_any(low, ("admin", "owner", "privileged", "role")):
        return "privileged-compromised"
    if "block proposer" in low:
        return "block-proposer"
    return "unprivileged"


def infer_impact_actor(text: str) -> str:
    low = text.lower()
    if contains_any(low, ("treasury", "protocol")):
        return "protocol-treasury"
    if contains_any(low, ("validator set",)):
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


def infer_year(text: str, path: Path, default: int) -> int:
    joined = " ".join((str(path), path.name, text[:4000]))
    candidates = re.findall(r"(?<!\d)(20[0-9]{2})(?!\d)", joined)
    for raw in candidates:
        year = int(raw)
        if 2015 <= year <= 2100:
            return year
    return default


PATHLIKE_REPO_OWNERS = {
    "x",
    "github.com",
    "cantina.xyz",
    "src",
    "contracts",
    "common",
    "core",
    "n",
}
PATHLIKE_REPO_NAMES = {
    "common",
    "core",
    "src",
    "contracts",
    "cantina",
    "bash",
    "version",
    "no-hook",
}


def is_pathlike_repo_candidate(candidate: str) -> bool:
    if "/" not in candidate:
        return True
    owner, repo = candidate.split("/", 1)
    if owner.lower() in PATHLIKE_REPO_OWNERS or repo.lower() in PATHLIKE_REPO_NAMES:
        return True
    if repo.lower().endswith((".go", ".rs", ".sol", ".md", ".txt", ".pdf")):
        return True
    if re.fullmatch(r"\d+", owner) or re.fullmatch(r"\d+", repo):
        return True
    if candidate.upper() == "N/A":
        return True
    return False


def infer_repo(text: str, *, file_rel_path: str = "") -> str:
    combined = f"{text}\n{file_rel_path}"
    github_matches = re.findall(
        r"github\.com[:/]+([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)",
        combined,
        re.IGNORECASE,
    )
    for raw in github_matches:
        candidate = raw.rstrip("-.")
        if is_pathlike_repo_candidate(candidate):
            continue
        return candidate
    matches = re.findall(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", text)
    for candidate in matches:
        if is_pathlike_repo_candidate(candidate):
            continue
        return candidate
    return "unknown"


def is_generic_component(component: str) -> bool:
    low = component.strip().lower()
    return low.startswith(("the function", "function contains", "function in", "function as"))


def infer_component(title: str, body: str) -> str:
    patterns = (
        r"`([^`\n]{1,120})`",
        r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
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
    return (title[:240] or "unknown-component")


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
    bullets: List[str] = []
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


def segment_findings(text: str) -> List[FindingSegment]:
    heading_re = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
    lines = text.splitlines()
    headings: List[Tuple[int, str, int]] = []
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

    if segments:
        return segments

    # Fallback: line-anchor segmentation for plain-text reports.
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if looks_like_finding_anchor(line):
            anchors.append((idx, line.strip().lstrip("#").strip()))
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start + 1 : end]).strip()
        if len(body) < 20:
            continue
        segments.append(FindingSegment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))

    if not segments and text.strip():
        first_real = next(
            (line.strip("# \t") for line in lines if len(line.strip("# \t")) >= 8),
            "untitled finding",
        )
        segments.append(FindingSegment(title=first_real[:120], body=text.strip(), heading_line=1, ordinal=1))
    return segments


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
    defaults = {
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
    return defaults.get(bug_class, "add explicit invariant checks around the affected state transition")


def infer_fix_anti_pattern(bug_class: str) -> str:
    defaults = {
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
    return defaults.get(bug_class, "patching symptoms without binding the violated invariant")


def detect_mitigation_states(text: str) -> Dict[str, str]:
    """Return three mitigation slots with values in {observed, unknown}.

    The canonical hackerman_record.v1 schema is locked, so these states ride as
    sidecar metadata on the stage artifact rather than on the record itself.
    Triagers downstream can consume the stage artifact to know which of the
    disclosed / acknowledged / fixed states were observed in the source text.
    """

    low = text.lower()
    states: Dict[str, str] = {}
    states["disclosed"] = "observed" if any(p in low for p in MITIGATION_DISCLOSED_PATTERNS) else "unknown"
    states["acknowledged"] = "observed" if any(p in low for p in MITIGATION_ACK_PATTERNS) else "unknown"
    states["fixed"] = "observed" if any(p in low for p in MITIGATION_FIXED_PATTERNS) else "unknown"
    return states


def detect_platform_from_path(path: Path) -> Optional[str]:
    low = path.as_posix().lower()
    for platform in SUPPORTED_PLATFORMS:
        if f"/{platform}/" in low or low.endswith(f"/{platform}") or f"-{platform}-" in low:
            return platform
    return None


def parse_mirror_arg(value: str) -> Tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            f"--platform-mirror expects PLATFORM=PATH; got '{value}'"
        )
    platform, raw_path = value.split("=", 1)
    platform = platform.strip().lower()
    if platform not in SUPPORTED_PLATFORMS:
        raise argparse.ArgumentTypeError(
            f"platform '{platform}' is not one of {sorted(SUPPORTED_PLATFORMS)}"
        )
    path = Path(raw_path).expanduser()
    return platform, path


def discover_docs(mirrors: Sequence[Tuple[str, Path]]) -> List[PlatformDoc]:
    docs: List[PlatformDoc] = []
    seen: set[Path] = set()
    for platform, mirror_root in mirrors:
        if not mirror_root.exists() or not mirror_root.is_dir():
            continue
        for path in sorted(mirror_root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                rel_path = path.relative_to(mirror_root)
            except ValueError:
                rel_path = Path(path.name)
            docs.append(
                PlatformDoc(
                    platform=platform,
                    mirror_root=mirror_root,
                    path=path,
                    rel_path=rel_path,
                )
            )
    return docs


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


def read_source_text(doc: PlatformDoc) -> Tuple[Optional[str], str]:
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


def load_existing_repo_title_pairs(index_path: Optional[Path]) -> set[str]:
    """Read by_target_repo.jsonl and return the set of (repo, slugified-title)
    hashes already represented in the canonical corpus.
    """

    pairs: set[str] = set()
    if index_path is None or not index_path.exists():
        return pairs
    try:
        with index_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                repo = (row.get("target_repo") or "").strip().lower()
                source_ref = (row.get("source_audit_ref") or "").strip().lower()
                if not repo:
                    continue
                # The index already deduplicates per (repo, source_audit_ref).
                # We also fold in a slugified-source-ref tail so the platform
                # ETL skips any same-source reingest.
                pair_hash = hashlib.sha256(f"{repo}\n{source_ref}".encode("utf-8")).hexdigest()[:16]
                pairs.add(pair_hash)
    except OSError:
        return pairs
    return pairs


def build_record(
    doc: PlatformDoc,
    segment: FindingSegment,
    *,
    doc_context: str = "",
) -> Tuple[Dict[str, object], Dict[str, object]]:
    text = f"{segment.title}\n{segment.body}"
    repo_haystack = f"{text}\n{doc_context}"
    platform_meta = SUPPORTED_PLATFORMS[doc.platform]
    severity = infer_severity(text)
    language = infer_language(text)
    domain = infer_domain(text)
    bug_class, attack_class = infer_bug_and_attack(text)
    impact_class = infer_impact(text)
    component = infer_component(segment.title, segment.body)
    rel = doc.rel_path.as_posix()
    source_ref = (
        f"{platform_meta['ref_prefix']}:{rel}:L{segment.heading_line}:S{segment.ordinal}"
    )
    digest = hashlib.sha256(
        f"{source_ref}\n{segment.title}\n{segment.body}".encode("utf-8")
    ).hexdigest()[:12]
    record_id = (
        f"{platform_meta['ref_prefix']}:{slugify(rel, max_len=96)}:"
        f"L{segment.heading_line}:S{segment.ordinal}:{digest}"
    )
    record: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": language,
        "target_repo": infer_repo(repo_haystack, file_rel_path=rel),
        "target_component": component,
        "function_shape": {
            "raw_signature": infer_signature(component, language),
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
        "year": infer_year(text, doc.path, platform_meta["default_year"]),
        "cross_language_analogues": [],
        "related_records": [],
    }
    sidecar: Dict[str, object] = {
        "record_id": record_id,
        "platform": doc.platform,
        "source_audit_ref": source_ref,
        "original_severity": severity,
        "mitigation_states": detect_mitigation_states(text),
        "source_rel_path": rel,
    }
    return record, sidecar


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
    numeric_like = re.fullmatch(
        r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?(?:[eE][-+]?[0-9_]+)?",
        text,
    )
    if (
        re.fullmatch(r"[A-Za-z0-9._:/-]+", text)
        and text.lower() not in ambiguous_yaml
        and not numeric_like
    ):
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


def extract_records(
    mirrors: Sequence[Tuple[str, Path]],
    existing_pairs: Optional[set[str]] = None,
    limit: Optional[int] = None,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, object]]:
    existing_pairs = existing_pairs or set()
    docs = discover_docs(mirrors)
    records: List[Dict[str, object]] = []
    sidecars: List[Dict[str, object]] = []
    segments_seen = 0
    documents_with_text = 0
    documents_skipped = 0
    pdf_documents = 0
    pdf_text_extracted = 0
    skipped_as_duplicate = 0
    extraction_methods: Counter[str] = Counter()
    per_platform_counts: Counter[str] = Counter()
    document_rows: List[Dict[str, object]] = []

    for doc in docs:
        if doc.path.suffix.lower() in PDF_EXTENSIONS:
            pdf_documents += 1
        text, method = read_source_text(doc)
        extraction_methods[method] += 1
        stage_row: Dict[str, object] = {
            "platform": doc.platform,
            "mirror_root": str(doc.mirror_root),
            "source_rel_path": doc.rel_path.as_posix(),
            "source_kind": "pdf" if doc.path.suffix.lower() in PDF_EXTENSIONS else "text",
            "text_extraction_method": method,
        }
        if not text:
            documents_skipped += 1
            stage_row["status"] = "skipped"
            stage_row["records_emitted"] = 0
            document_rows.append(stage_row)
            continue
        documents_with_text += 1
        if doc.path.suffix.lower() in PDF_EXTENSIONS and method != "unavailable":
            pdf_text_extracted += 1
        doc_records_before = len(records)
        # Pre-segment header context (up to first finding heading) preserves
        # doc-level metadata (Repository:, project name, audit-pin reference)
        # so per-segment inference does not lose it.
        doc_context_head = text[:8000]
        for segment in segment_findings(text):
            segments_seen += 1
            record, sidecar = build_record(doc, segment, doc_context=doc_context_head)
            pair_hash = hashlib.sha256(
                f"{record['target_repo']}\n{record['source_audit_ref']}".lower().encode("utf-8")
            ).hexdigest()[:16]
            if pair_hash in existing_pairs:
                skipped_as_duplicate += 1
                continue
            existing_pairs.add(pair_hash)
            records.append(record)
            sidecars.append(sidecar)
            per_platform_counts[doc.platform] += 1
            if limit is not None and len(records) >= limit:
                stage_row["status"] = "processed-limit"
                stage_row["records_emitted"] = len(records) - doc_records_before
                document_rows.append(stage_row)
                return (
                    records,
                    sidecars,
                    {
                        "documents_scanned": len(docs),
                        "documents_with_text": documents_with_text,
                        "documents_skipped": documents_skipped,
                        "pdf_documents": pdf_documents,
                        "pdf_text_extracted": pdf_text_extracted,
                        "segments_seen": segments_seen,
                        "skipped_as_duplicate": skipped_as_duplicate,
                        "per_platform_counts": dict(sorted(per_platform_counts.items())),
                        "extraction_methods": dict(sorted(extraction_methods.items())),
                        "document_rows": document_rows,
                    },
                )
        stage_row["status"] = "processed"
        stage_row["records_emitted"] = len(records) - doc_records_before
        document_rows.append(stage_row)

    return (
        records,
        sidecars,
        {
            "documents_scanned": len(docs),
            "documents_with_text": documents_with_text,
            "documents_skipped": documents_skipped,
            "pdf_documents": pdf_documents,
            "pdf_text_extracted": pdf_text_extracted,
            "segments_seen": segments_seen,
            "skipped_as_duplicate": skipped_as_duplicate,
            "per_platform_counts": dict(sorted(per_platform_counts.items())),
            "extraction_methods": dict(sorted(extraction_methods.items())),
            "document_rows": document_rows,
        },
    )


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
    parser.add_argument(
        "--platform-mirror",
        action="append",
        default=[],
        type=parse_mirror_arg,
        help=(
            "PLATFORM=PATH; PLATFORM is one of "
            f"{sorted(SUPPORTED_PLATFORMS)}; repeatable."
        ),
    )
    parser.add_argument(
        "--existing-index",
        help="Optional path to audit/corpus_tags/index/by_target_repo.jsonl for dedup.",
    )
    parser.add_argument("--out-dir", required=True, help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument(
        "--stage-artifact-out",
        help="Optional JSON stage artifact with mitigation-state sidecars.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Build records without writing YAML files.")
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    args = parser.parse_args(argv)

    if not args.platform_mirror:
        print("at least one --platform-mirror PLATFORM=PATH is required", file=sys.stderr)
        return 2
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    existing_pairs = load_existing_repo_title_pairs(
        Path(args.existing_index).expanduser().resolve() if args.existing_index else None
    )
    records, sidecars, counters = extract_records(
        args.platform_mirror,
        existing_pairs=existing_pairs,
        limit=args.limit,
    )
    out_dir = Path(args.out_dir).expanduser().resolve()
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "stage_schema_version": STAGE_SCHEMA_VERSION,
        "platform_mirrors": [
            {"platform": platform, "path": str(path)}
            for platform, path in args.platform_mirror
        ],
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "existing_pairs_loaded": len(existing_pairs),
        "documents_scanned": counters["documents_scanned"],
        "documents_with_text": counters["documents_with_text"],
        "documents_skipped": counters["documents_skipped"],
        "pdf_documents": counters["pdf_documents"],
        "pdf_text_extracted": counters["pdf_text_extracted"],
        "segments_seen": counters["segments_seen"],
        "skipped_as_duplicate": counters["skipped_as_duplicate"],
        "records_emitted": len(records),
        "per_platform_counts": counters["per_platform_counts"],
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
            "sidecars": sidecars,
        }
        stage_path.write_text(
            json.dumps(stage_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary["stage_artifact_out"] = str(stage_path)

    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        per_platform = ", ".join(
            f"{platform}={count}"
            for platform, count in summary["per_platform_counts"].items()
        ) or "none"
        print(
            "hackerman platform ETL: "
            f"documents={summary['documents_scanned']} "
            f"records={summary['records_emitted']} "
            f"dupes_skipped={summary['skipped_as_duplicate']} "
            f"per_platform=[{per_platform}] "
            f"dry_run={summary['dry_run']} out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
