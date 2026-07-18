#!/usr/bin/env python3
"""Convert reference/corpus_mined markdown slices into hackerman_record v1 YAML."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_CORPUS_DIR = Path(__file__).resolve().parent.parent / "reference" / "corpus_mined"
TEXT_EXTENSIONS = {".md", ".markdown"}
SEVERITIES = {"critical", "high", "medium"}

LANGUAGE_KEYWORDS = (
    ("cairo", ("cairo", "starknet")),
    ("rust", ("rust", "cosmwasm", "anchor", "solana", "stylus", ".rs")),
    ("go", ("golang", "go consensus", "cosmos", "geth", ".go")),
    ("move", ("move module", "sui::", "aptos")),
    ("vyper", ("vyper", ".vy")),
    ("huff", ("huff", ".huff")),
    ("assembly", ("yul", "assembly", "mips vm")),
    ("typescript-onchain", ("typescript", "ts-node")),
    ("python-onchain", ("python", "vyper script")),
    ("solidity", ("solidity", "evm", "erc", "function ", ".sol", "msg.sender")),
)

DOMAIN_KEYWORDS = (
    ("zk-proof", ("zk", "zero-knowledge", "circuit", "constraint", "proof", "witness", "halo2", "circom")),
    ("bridge", ("bridge", "cross-chain", "cross chain", "messaging", "layerzero", "oft", "l1", "l2")),
    ("rollup", (
        # generic rollup terminology
        "rollup", "sequencer", "fraud proof", "state root",
        # op-stack
        "optimism", "op-stack", "op stack", "op-geth", "op-node",
        "op-batcher", "op-proposer", "op-program", "ethereum-optimism",
        # arbitrum
        "arbitrum", "offchainlabs", "offchain labs", "nitro",
        "arbitrum-nitro", "arbitrum-stylus", "arb-os",
        # zksync
        "zksync", "zk-sync", "zk sync", "boojum", "matterlabs", "matter-labs",
        # scroll
        "scroll-tech", "scroll-zkevm", "scroll/", "/scroll", "scrollowner",
        # linea
        "consensys/linea", "openzeppelin/linea", "cyfrin/linea",
        "linea-besu", "linea zkevm", "linea-zkevm",
        # polygon zkevm
        "polygonzkevm", "polygon-zkevm", "polygon_zkevm", "polygon zkevm",
        # starknet
        "starknet", "starkware", "starknet-cairo",
        # base
        "base-org", "base-azul", "base-l2",
        # mantle / taiko / fraxtal / blast / metis / kroma
        "mantlenetworkio", "mantle-v2", "mantle l2", "mantle-l2",
        "taikoxyz", "taiko-l2",
        "fraxtal", "frax-l2",
        "blast-io", "blast-l2", "blast network",
        "metis-l2",
        "kroma", "kroma-l2",
    )),
    ("oracle", ("oracle", "price feed", "chainlink", "pyth", "twap", "get_virtual_price")),
    ("governance", ("governance", "proposal", "vote", "timelock", "quorum")),
    ("dex", ("dex", "swap", "amm", "liquidity pool", "uniswap", "curve", "slippage", "balancer")),
    ("lending", ("borrow", "lend", "loan", "liquidation", "collateral", "debt")),
    ("staking", ("stake", "staking", "validator", "delegator", "slash", "restaking")),
    ("nft", ("nft", "erc721", "erc-721", "erc1155", "royalty")),
    ("dao", ("dao", "ragequit", "treasury")),
    ("escrow", ("escrow", "vesting", "lockup")),
    ("gaming", ("game", "randomness", "loot")),
    ("consensus", ("consensus", "validator set", "block proposer")),
    ("rpc-infra", ("rpc", "mempool", "node", "dns rebinding")),
    ("l1-client", ("evm client", "execution client", "reth", "geth")),
    ("vault", ("vault", "erc4626", "erc-4626", "shares", "deposit", "withdraw")),
)

CLASS_KEYWORDS = (
    ("access-control", "admin-bypass", ("access control", "unauthorized", "onlyowner", "permission", "privilege", "whitelist-bypass")),
    ("reentrancy", "callback-reentrancy", ("reentrancy", "reentrant", "callback", "erc777")),
    ("oracle-manipulation", "stale-or-manipulated-oracle", ("oracle", "stale price", "twap", "price manipulation", "spot", "getreserves", "virtual_price")),
    ("signature-replay", "signature-replay", ("signature", "replay", "eip712", "eip-712", "permit", "nonce")),
    ("share-inflation", "first-deposit-share-inflation", ("share inflation", "first depositor", "first-deposit", "erc4626", "donation", "totalSupply == 0")),
    ("precision-loss", "rounding-precision-loss", ("rounding", "precision", "truncation", "division", "denominator", "invariant")),
    ("denial-of-service", "dos-griefing", ("denial of service", "dos", "grief", "blocked", "stuck", "infinite loop")),
    ("input-validation", "missing-input-validation", ("missing validation", "input validation", "unchecked", "not validated", "unvalidated", "bounds")),
    ("accounting", "state-accounting-drift", ("accounting", "balance", "state", "debt", "reward", "fee", "overcount", "undercharge")),
    ("arbitrary-call", "arbitrary-target-approval-drain", ("arbitrary-target", "arbitrary target", "user-supplied target", "unvalidated-target", ".call")),
    ("zk-constraint", "missing-zk-constraint", ("constraint", "unconstrained", "witness", "range check")),
    # Solana-native classes (B6). EVM rows above MUST NOT be modified;
    # these rows live at the tail because first_match() walks top-down and
    # we want EVM-specific keywords to keep their precedence on EVM corpora.
    ("solana-signer", "missing-signer-check", ("is_signer", "missing signer", "required_signers", "signer<", "signer check", "no signer check")),
    ("solana-pda", "pda-collision", ("pda collision", "pda-collision", "find_program_address", "program_derived_address", "create_program_address", "colliding pda")),
    ("solana-pda-seeds", "pda-seed-confusion", ("seed confusion", "pda seed", "seeds = [", "predictable seed", "seed manipulation")),
    ("solana-account-confusion", "account-confusion", ("account confusion", "wrong account", "accountinfo<", "type confusion")),
    ("solana-account-reinit", "account-reinitialization", ("reinitialization", "reinitialisation", "reinit", "re-initialize", "re-initialise")),
    ("solana-cpi", "cpi-arbitrary-target", ("arbitrary cpi", "cpi target", "cross_program_invocation", "cross-program invocation", "invoke_signed", "arbitrary program id", "unchecked program id")),
    ("solana-sysvar", "sysvar-spoof", ("sysvar spoof", "fake sysvar", "spoof clock", "clock sysvar", "rent sysvar", "instructions sysvar", "sysvar account")),
    ("solana-token-2022", "token-2022-extension-confusion", ("token-2022", "spl_token_2022", "spl-token-2022", "transfer hook", "transfer fee extension", "permanent delegate", "confidential transfer")),
    ("solana-anchor-ctx", "anchor-context-misuse", ("anchor context", "context<", "ctx.accounts", "#[derive(accounts)]", "accounts struct")),
    ("solana-realloc", "realloc-attack", ("realloc", "account.realloc", "account_realloc", "resize account")),
    ("solana-close", "close-attack", ("close = ", "close=destination", "close attribute", "close account", "lamports drain", "drain lamports", "close_account")),
    ("solana-init-if-needed", "init-if-needed-bypass", ("init_if_needed", "init-if-needed", "init if needed")),
    ("solana-discriminator", "account-discriminator-spoof", ("discriminator", "anchor discriminator", "discriminator collision", "8-byte discriminator", "type cosplay")),
    ("solana-lookup-table", "lookup-table-poisoning", ("address lookup table", "lookup-table", "lookup table poison", "alt poisoning", "address_lookup_table")),
)

IMPACT_KEYWORDS = (
    ("theft", ("steal", "theft", "drain", "loss of funds", "fund loss", "over-valued", "borrowed against")),
    ("freeze", ("freeze", "locked", "stuck funds", "cannot withdraw", "strand")),
    ("dos", ("denial of service", "dos", "revert", "blocked", "bricked")),
    ("griefing", ("grief", "censor")),
    ("yield-redistribution", ("reward", "yield", "interest")),
    ("precision-loss", ("rounding", "precision", "truncation")),
    ("governance-takeover", ("governance takeover", "quorum", "proposal")),
    ("privilege-escalation", ("privilege", "unauthorized", "admin")),
)


class Candidate(NamedTuple):
    title: str
    body: str
    path: Path
    line_no: int
    ordinal: int
    severity_hint: Optional[str]
    novel: bool
    source_kind: str
    context_heading: str


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


def normalize_severity(raw: Optional[str], text: str) -> str:
    if raw:
        value = raw.lower()
        if value in {"c", "crit"}:
            return "critical"
        if value == "h":
            return "high"
        if value == "m":
            return "medium"
        if value in {"critical", "high", "medium"}:
            return value
    low = text.lower()
    for severity in ("critical", "high", "medium"):
        if re.search(rf"\b{severity}\b", low):
            return severity
    for short, severity in (("c", "critical"), ("h", "high"), ("m", "medium")):
        if re.search(rf"(^|[\s\[(]){short}[-\])\s]*\d*\b", low):
            return severity
    if re.search(r"\$[0-9][0-9.,]*\s*[bm]\b", low):
        return "critical"
    return "high"


def is_explicit_novel(text: str) -> bool:
    low = text.lower()
    return bool(
        re.search(r"\bnovel(?: pattern)? candidate:\s*(?:\*\*)?\s*(?:\*\*)?\s*(yes|unknown|maybe)\b", low)
        or re.search(r"\bnovel:\s*(?:\*\*)?\s*(?:\*\*)?\s*(yes|unknown|maybe)\b", low)
    )


def is_explicit_novel_heading(text: str) -> bool:
    return bool(
        re.search(
            r"\bnovel pattern candidate:\s*(?:\*\*)?\s*(?:\*\*)?\s*(yes|unknown|maybe)\b",
            text.lower(),
        )
    )


def parse_bullet(line: str) -> Optional[Tuple[str, Optional[str], str]]:
    stripped = line.strip()
    if not stripped.startswith(("- ", "* ")):
        return None
    body = stripped[2:].strip()
    match = re.match(r"\*\*(.+?)\*\*\s*(?:\(([^)]+)\))?\s*(?:[-\u2013\u2014:]+)?\s*(.*)$", body)
    if not match:
        return None
    title = match.group(1).strip()
    severity = match.group(2).strip() if match.group(2) else None
    rest = match.group(3).strip()
    return title, severity, rest


def severity_is_in_scope(raw: Optional[str], text: str) -> bool:
    if raw:
        value = raw.strip().lower()
        if value in {"critical", "crit", "c", "high", "h", "medium", "m"}:
            return True
        return False
    return bool(re.search(r"\b(CRITICAL|HIGH|MEDIUM|[CHM])\b", text))


def discover_markdown(corpus_dir: Path) -> List[Path]:
    if not corpus_dir.is_dir():
        raise FileNotFoundError(f"corpus dir not found: {corpus_dir}")
    return sorted(
        path
        for path in corpus_dir.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TEXT_EXTENSIONS
        and path.name.lower() != "index.md"
    )


def collect_heading_body(lines: List[str], start_idx: int, level: int) -> str:
    body: List[str] = []
    for line in lines[start_idx + 1 :]:
        match = re.match(r"^(#{1,6})\s+", line)
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body).strip()


def segment_file(path: Path) -> List[Candidate]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    candidates: List[Candidate] = []
    heading_stack: List[Tuple[int, str]] = []

    for idx, line in enumerate(lines):
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip().strip("#").strip()
            heading_stack = [(lvl, text) for lvl, text in heading_stack if lvl < level]
            heading_stack.append((level, title))
            body = collect_heading_body(lines, idx, level)
            full = f"{title}\n{body}"
            if level >= 3 and is_explicit_novel_heading(full):
                candidates.append(
                    Candidate(
                        title=title,
                        body=body,
                        path=path,
                        line_no=idx + 1,
                        ordinal=len(candidates) + 1,
                        severity_hint=None,
                        novel=True,
                        source_kind="heading",
                        context_heading=" > ".join(text for _, text in heading_stack[:-1]),
                    )
                )
            continue

        parsed = parse_bullet(line)
        if parsed is None:
            continue
        title, severity_hint, rest = parsed
        context = " > ".join(text for _, text in heading_stack)
        full = f"{context}\n{title}\n{rest}"
        novel = is_explicit_novel(rest)
        if not (severity_is_in_scope(severity_hint, full) or novel):
            continue
        candidates.append(
            Candidate(
                title=title,
                body=rest,
                path=path,
                line_no=idx + 1,
                ordinal=len(candidates) + 1,
                severity_hint=severity_hint,
                novel=novel,
                source_kind="bullet",
                context_heading=context,
            )
        )
    return candidates


def infer_language(text: str) -> str:
    return first_match(text, LANGUAGE_KEYWORDS, "solidity")


def infer_domain(text: str) -> str:
    return first_match(text, DOMAIN_KEYWORDS, "vault")


def infer_bug_and_attack(text: str, fallback_title: str) -> Tuple[str, str]:
    for bug_class, attack_class, needles in CLASS_KEYWORDS:
        if contains_any(text, needles):
            return bug_class, attack_class
    slug = slugify(fallback_title, max_len=72)
    return slug or "logic-error", slug or "protocol-invariant-bypass"


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
    if "block proposer" in low or re.search(r"\bproposer\b", low):
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
    if contains_any(low, ("depositor", "lender", "borrower", "lp", "liquidity provider", "vault")):
        return "depositor-class"
    if contains_any(low, ("reward", "yield", "interest")):
        return "yield-recipient"
    if contains_any(low, ("victim", "specific user")):
        return "specific-user"
    return "arbitrary-user"


def infer_dollar_class(severity: str, text: str, impact_class: str) -> str:
    low = text.lower()
    if re.search(r"\$[0-9][0-9.,]*\s*b\b", low) or re.search(r"\$[1-9][0-9.,]*\s*m\b", low):
        return ">=$1M"
    if re.search(r"\$[1-9][0-9.,]*\s*k\b", low):
        return "$10K-$100K"
    if impact_class in {"griefing", "dos"} and severity == "medium":
        return "non-financial"
    if severity == "critical":
        return ">=$1M"
    if severity == "high":
        return "$100K-$1M"
    return "$10K-$100K"


def infer_year(text: str, path: Path) -> int:
    candidates = re.findall(r"\b(20[0-9]{2})\b", f"{path} {text[:1500]}")
    for raw in candidates:
        year = int(raw)
        if 2000 <= year <= 2100:
            return year
    return 2000


def infer_repo(text: str) -> str:
    match = re.search(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", text)
    return match.group(1) if match else "unknown"


def infer_component(title: str, body: str) -> str:
    haystack = f"{title}\n{body}"
    patterns = (
        r"`([^`\n]{1,120})`",
        r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
        r"\b([A-Z][A-Za-z0-9_]{2,}\.[A-Za-z_][A-Za-z0-9_]{2,})\b",
        r"\b([A-Za-z_][A-Za-z0-9_]{2,}\([^)]{0,120}\))",
    )
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            return match.group(1).strip()[:240]
    return title[:240] or "unknown-component"


def infer_signature(component: str, language: str) -> str:
    if component.startswith("function ") or "(" in component:
        return component
    if language == "go":
        return f"func {component}"
    if language == "rust":
        return f"fn {component}"
    return f"function {component}"


def infer_fix_pattern(text: str, bug_class: str) -> str:
    for line in text.splitlines():
        stripped = line.strip(" \t-*")
        if len(stripped) > 8 and contains_any(stripped, ("recommend", "mitigation", "fix", "remediate")):
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
        "arbitrary-call": "allowlist external call targets and bind approvals to validated protocol adapters",
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
        "arbitrary-call": "calling user-supplied targets while holding reusable user approvals",
        "zk-constraint": "using witness values in logic without corresponding constraints",
    }
    return avoided.get(bug_class, "patching symptoms without binding the violated invariant")


def shape_tags(language: str, bug_class: str, attack_class: str, component: str) -> List[str]:
    tags = [slugify(attack_class), slugify(f"{language}-{bug_class}")]
    comp = slugify(component, max_len=48)
    if comp and comp not in tags:
        tags.append(comp)
    return tags[:3]


def extract_preconditions(text: str, domain: str, bug_class: str) -> List[str]:
    found: List[str] = []
    for line in text.splitlines():
        stripped = line.strip(" \t-*")
        if len(stripped) < 8:
            continue
        if contains_any(stripped, ("precondition", "requires", "when ", "if ", "attacker can", "user can", "without")):
            found.append(stripped[:220])
    if found:
        return list(dict.fromkeys(found))[:3]
    return [f"{domain} component exposes behavior consistent with {bug_class}"]


def one_line(text: str, fallback: str) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    return (cleaned[:1000] if cleaned else fallback)


def build_record(corpus_dir: Path, candidate: Candidate) -> Dict[str, object]:
    rel = candidate.path.relative_to(corpus_dir)
    text = f"{candidate.context_heading}\n{candidate.title}\n{candidate.body}"
    severity = normalize_severity(candidate.severity_hint, text)
    language = infer_language(text)
    domain = infer_domain(text)
    bug_class, attack_class = infer_bug_and_attack(text, candidate.title)
    impact_class = infer_impact(text)
    component = candidate.title[:240] if candidate.source_kind == "heading" else infer_component(candidate.title, candidate.body)
    source_ref = f"corpus-mined:{rel.as_posix()}:L{candidate.line_no}:S{candidate.ordinal}"
    digest = hashlib.sha256(f"{source_ref}\n{candidate.title}\n{candidate.body}".encode("utf-8")).hexdigest()[:12]
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"{source_ref}:{digest}",
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": language,
        "target_repo": infer_repo(text),
        "target_component": component,
        "function_shape": {
            "raw_signature": infer_signature(component, language),
            "shape_tags": shape_tags(language, bug_class, attack_class, component),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": infer_attacker_role(text),
        "attacker_action_sequence": one_line(
            candidate.body,
            f"Attacker exercises the {component} path described by {candidate.title}.",
        ),
        "required_preconditions": extract_preconditions(text, domain, bug_class),
        "impact_class": impact_class,
        "impact_actor": infer_impact_actor(text),
        "impact_dollar_class": infer_dollar_class(severity, text, impact_class),
        "fix_pattern": infer_fix_pattern(text, bug_class),
        "fix_anti_pattern_avoided": infer_fix_anti_pattern(bug_class),
        "severity_at_finding": severity,
        "year": infer_year(text, candidate.path),
        "cross_language_analogues": [],
        "related_records": [],
    }


def extract_records(corpus_dir: Path, limit: Optional[int] = None) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    docs = discover_markdown(corpus_dir)
    records: List[Dict[str, object]] = []
    candidates_seen = 0
    for path in docs:
        for candidate in segment_file(path):
            candidates_seen += 1
            records.append(build_record(corpus_dir, candidate))
            if limit is not None and len(records) >= limit:
                return records, {"documents_scanned": len(docs), "candidates_seen": candidates_seen}
    return records, {"documents_scanned": len(docs), "candidates_seen": candidates_seen}


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    if value == "":
        return '""'
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._:/<>$-]+", text) and text.lower() not in {"true", "false", "null"}:
        return text
    return json.dumps(text, ensure_ascii=True)


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
    parser.add_argument("--corpus-dir", default=str(DEFAULT_CORPUS_DIR))
    parser.add_argument("--out-dir", required=True, help="Directory for emitted hackerman_record YAML files.")
    parser.add_argument("--dry-run", action="store_true", help="Build records and summary without writing YAML files.")
    parser.add_argument("--limit", type=int, help="Maximum records to emit.")
    parser.add_argument("--json-summary", action="store_true", help="Print a machine-readable JSON summary.")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    try:
        records, counters = extract_records(corpus_dir, args.limit)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "corpus_dir": str(corpus_dir),
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "documents_scanned": counters["documents_scanned"],
        "candidates_seen": counters["candidates_seen"],
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman corpus-mined ETL: "
            f"documents={summary['documents_scanned']} records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
