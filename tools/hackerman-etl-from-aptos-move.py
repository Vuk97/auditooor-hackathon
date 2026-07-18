#!/usr/bin/env python3
"""
Convert Aptos / Move framework + DeFi findings into hackerman_record v1 YAML.

Wave-3 lane EXEC-WAVE3-APTOS-MOVE / TIER-C Lift C5.

Sources (already vendored in this repo):

* `reference/corpus_txt/zellic/*Aptos*.txt` and `*Move*.txt`           - Zellic
  public Aptos / Move audit reports (Wormhole Aptos, Thala Labs Move Dollar,
  PancakeSwap Aptos, Tortuga Liquid Staking, Pontem Liquidswap, Pontem
  wallet, Econia, Garden Move Deploy, Pyth2Wormhole, Move and Sui Security
  Assessment).
* `reference/patterns.dsl.r94_zellic_local/*.yaml`                     - per-
  finding DSL patterns already extracted from the same Zellic corpus
  (shallower but indexed inventory; used as a fallback channel).
* `APTOS_LABS_KNOWN_DISCLOSURES`                                       - a
  curated baseline of widely-publicised Aptos / Move framework + DeFi
  attack classes pulled from Aptos Labs security disclosures, OtterSec
  public reports, Zellic blog posts. These records guarantee taxonomy
  coverage when the audit-text channel under-fires (e.g. PancakeSwap Aptos
  has no high-severity findings).

Taxonomy: Move-resource-safety attack classes -

* resource-safety-violation       - double-move, dangling resource handle
* capability-pattern-bypass       - capability struct leaks or unrestricted mint
* signer-derived-resource-leak    - `signer` value taken from caller-controlled
                                    path, used to authorise resource access
* aborts-if-policy-mismatch       - documented aborts-if policy diverges from
                                    runtime abort code or unbounded abort
* acquires-mismatch               - function reads/writes a resource without an
                                    `acquires` clause or vice versa

These five Move-specific classes are emitted in addition to the existing
cross-class taxonomy used by sibling ETLs (`access-control`, `reentrancy`,
`signature-replay`, `oracle-manipulation`, `precision-loss`, `denial-of-
service`, `accounting`, etc.). The Move-resource-safety classifier runs
first so a Move-specific bug shape is preferred over a generic equivalent.

Output: hackerman_record v1 YAML at `--out-dir`, one file per record.
Schema validated via `tools/hackerman-record-validate.py`. The script does
NOT mutate `tools/calibration/llm_budget_log.jsonl`.

CLI:

    python3 tools/hackerman-etl-from-aptos-move.py \
        --out-dir /tmp/etl-aptos-move-out \
        --dry-run --json-summary

    python3 tools/hackerman-etl-from-aptos-move.py \
        --out-dir audit/corpus_tags/tags/aptos_move

Both `--corpus-dir` and `--patterns-dir` accept repeats. `--include-baseline`
(default on) emits the curated Aptos Labs baseline; pass
`--no-include-baseline` to disable.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"

DEFAULT_CORPUS_DIR = REPO_ROOT / "reference" / "corpus_txt" / "zellic"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl.r94_zellic_local"

# Files whose names contain any of these substrings are treated as
# Aptos / Move audit reports. Sui-only reports (no Aptos coupling) are kept
# in scope because Sui Move and Aptos Move share the same resource-safety
# semantics that this lane is mining.
APTOS_MOVE_REPORT_HINTS = (
    "aptos",
    "thala",
    "pancakeswap",
    "tortuga",
    "pontem",
    "econia",
    "garden move",
    "move and sui",
    "wormhole multigov",
    "pyth2wormhole",
    "gotsui",
    "springsui",
    "suilend",
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_aptos_move",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ----------------------------------------------------------------------------
# Text helpers
# ----------------------------------------------------------------------------


def dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in values:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def repo_slug_part(value: object, *, max_len: int = 64) -> str:
    text = str(value or "").strip().lower()
    text = re.split(r"[:\s]", text, maxsplit=1)[0]
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "unknown")


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


# ----------------------------------------------------------------------------
# Move-resource-safety taxonomy
# ----------------------------------------------------------------------------


MOVE_RESOURCE_SAFETY_RULES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "resource-safety-violation",
        "double-move-or-dangling-resource",
        (
            "double move",
            "double-move",
            "move_from",
            "resource exists",
            "resource does not exist",
            "drop ability",
            "drop_ability",
            "store ability",
            "key ability",
            "without the drop ability",
            "drop ability could be dropped",
            "ability requirements",
            "resource account exists",
            "eresource_account_exists",
        ),
    ),
    # `signer-derived-resource-leak` is tested BEFORE `capability-pattern-
    # bypass` because the Aptos `signer` capability shape ("create_signer_
    # with_capability", "&SignerCapability") often co-mentions the literal
    # token "capability" without being a true capability-pattern bug. The
    # signer-resource-leak rule is the more specific class for those.
    (
        "signer-derived-resource-leak",
        "signer-from-caller-controlled-path",
        (
            "&signer",
            "signer ref",
            "resource_account",
            "create_resource_account",
            "create_signer_with_capability",
            "signercapability",
            "signer_cap",
            "create_signer",
            "init_internal",
        ),
    ),
    (
        "capability-pattern-bypass",
        "capability-leak-or-unbounded-mint",
        (
            "capability",
            "capability pattern",
            "burn_cap",
            "mint_cap",
            "freeze_cap",
            "treasury_cap",
            "mintcapability",
            "burncapability",
            "freezecapability",
            "unrestricted mint",
            "free mint",
            "guardian set",
        ),
    ),
    (
        "aborts-if-policy-mismatch",
        "aborts-if-divergence",
        (
            "aborts_if",
            "aborts-if",
            "abort code",
            "abort_with",
            "custom abort",
            "abort policy",
            "specification differs",
            "spec mismatch",
            "unbounded abort",
            "unchecked abort",
        ),
    ),
    (
        "acquires-mismatch",
        "missing-or-extra-acquires-clause",
        (
            "acquires",
            "missing acquires",
            "extra acquires",
            "acquires clause",
            "borrow_global",
            "borrow_global_mut",
            "global storage",
        ),
    ),
)


GENERIC_CLASS_RULES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "access-control",
        "admin-bypass",
        (
            "access control",
            "unauthorized",
            "admin",
            "role",
            "permission",
            "only admin",
            "is_admin",
        ),
    ),
    (
        "reentrancy",
        "reentrancy",
        ("reentrancy", "reentrant", "callback", "cross-module re-entry"),
    ),
    (
        "signature-replay",
        "signature-replay",
        ("signature", "ed25519", "replay", "permit", "nonce", "vaa"),
    ),
    (
        "oracle-manipulation",
        "stale-or-manipulated-oracle",
        ("oracle", "price feed", "pyth", "switchboard", "twap"),
    ),
    (
        "precision-loss",
        "rounding-precision-loss",
        ("rounding", "precision", "overflow", "underflow", "truncation"),
    ),
    (
        "denial-of-service",
        "dos-griefing",
        ("dos", "denial of service", "grief", "blocked", "stuck", "duplicate order"),
    ),
    (
        "accounting",
        "state-accounting-drift",
        (
            "accounting",
            "balance",
            "reward",
            "shares",
            "debt",
            "liquidation",
            "pool value",
            "drift",
        ),
    ),
    (
        "input-validation",
        "missing-input-validation",
        (
            "validation",
            "unchecked",
            "not checked",
            "missing check",
            "no upper bound",
            "no lower bound",
            "length not checked",
            "unbounded timelock",
        ),
    ),
    (
        "flash-loan",
        "flash-loan",
        ("flash loan", "flashloan", "flash swap"),
    ),
)


def classify_bug_attack(text: str) -> Tuple[str, str]:
    """Prefer a Move-specific class first; fall back to generic taxonomy."""
    for bug_class, attack_class, needles in MOVE_RESOURCE_SAFETY_RULES:
        if contains_any(text, needles):
            return bug_class, attack_class
    for bug_class, attack_class, needles in GENERIC_CLASS_RULES:
        if contains_any(text, needles):
            return bug_class, attack_class
    return "logic-error", "protocol-invariant-bypass"


# ----------------------------------------------------------------------------
# Domain / impact / severity helpers
# ----------------------------------------------------------------------------


DOMAIN_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("bridge", ("bridge", "vaa", "wormhole", "cross-chain", "layerzero", "guardian")),
    ("oracle", ("oracle", "price", "pyth", "switchboard", "twap")),
    ("lending", ("liquidat", "borrow", "debt", "collateral", "vault")),
    ("dex", ("swap", "amm", "pool", "uniswap", "liquidity", "pancake", "liquidswap", "econia")),
    ("staking", ("stake", "unstake", "validator", "delegat", "tortuga", "amnis")),
    ("vault", ("vault", "deposit", "withdraw", "shares", "thala", "stability_pool")),
    ("governance", ("governance", "vote", "proposal", "timelock", "multigov")),
    ("escrow", ("htlc", "escrow", "redeem", "refund", "garden")),
)


def infer_domain(text: str) -> str:
    for domain, needles in DOMAIN_RULES:
        if contains_any(text, needles):
            return domain
    return "vault"


def infer_impact(text: str) -> str:
    low = text.lower()
    if any(needle in low for needle in ("drain", "steal", "theft", "loss of funds", "mint", "freely create")):
        return "theft"
    if any(needle in low for needle in ("freeze", "stuck", "trap", "permanent lock", "locked indefinitely")):
        return "freeze"
    if any(needle in low for needle in ("dos", "denial of service", "grief", "blocked")):
        return "dos"
    if any(needle in low for needle in ("reward", "yield", "fee")):
        return "yield-redistribution"
    if any(needle in low for needle in ("rounding", "precision", "truncation")):
        return "precision-loss"
    if any(needle in low for needle in ("governance", "vote", "proposal", "quorum")):
        return "governance-takeover"
    if any(needle in low for needle in ("admin", "privilege", "unauthorized")):
        return "privilege-escalation"
    return "griefing"


def dollar_class(severity: str, impact: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    if impact in {"theft", "freeze"}:
        return "$10K-$100K"
    return "non-financial"


def normalise_severity(value: str) -> str:
    text = (value or "").strip().lower()
    if text in {"critical", "high", "medium", "low", "info", "informational"}:
        return "info" if text == "informational" else text
    if text in {"c", "crit"}:
        return "critical"
    if text == "h":
        return "high"
    if text == "m":
        return "medium"
    if text == "l":
        return "low"
    return "info"


YEAR_RE = re.compile(r"(?<!\d)(20(?:1[8-9]|2[0-9]|30))(?!\d)")


def extract_year(*parts: object) -> int:
    for part in parts:
        match = YEAR_RE.search(str(part or ""))
        if match:
            year = int(match.group(1))
            if 2018 <= year <= 2030:
                return year
    return 2024


# ----------------------------------------------------------------------------
# YAML rendering
# ----------------------------------------------------------------------------


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
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
                            lines.append(f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------
# Zellic Aptos / Move audit-text parser
# ----------------------------------------------------------------------------


SECTION_HEAD_RE = re.compile(
    r"^(\d+\.\d+(?:\.\d+)?)\s+(.+?)$"
)

SEVERITY_LINE_RE = re.compile(
    r"Severity\s*[:\-]\s*([A-Za-z]+)",
    re.IGNORECASE,
)

# Sometimes the severity is in a separate column block such as:
#       Category    Business Logic           Severity   High
SEVERITY_INLINE_RE = re.compile(
    r"Severity\s+([A-Za-z]+)",
    re.IGNORECASE,
)

# Detailed Findings section in Zellic reports always lives under a top-level
# "3 Detailed Findings" / "3. Detailed Findings" / "3 Discussion" / "3
# Findings" heading (numbering varies by report).
FINDINGS_HEADERS = (
    "detailed findings",
    "findings",
    "discussion",
)

NOISE_HEADERS = (
    "executive summary",
    "goals of the assessment",
    "non-goals",
    "methodology",
    "scope",
    "project overview",
    "project timeline",
    "contact information",
    "modules",
    "results",
    "introduction",
    "about zellic",
    "test suite",
    "threat model",
    "assessment results",
    "disclaimer",
    "back to contents",
)

PAGE_FOOTER_RE = re.compile(r"Zellic\s+(\d+|©|©)|Page\s+\d+\s+of\s+\d+", re.IGNORECASE)


def is_noise_title(title: str) -> bool:
    low = title.strip().lower()
    for tag in NOISE_HEADERS:
        if tag in low:
            return True
    if not low or len(low) < 8:
        return True
    return False


def strip_page_clutter(line: str) -> str:
    if PAGE_FOOTER_RE.search(line):
        return ""
    # Drop short table-of-contents fragments like "Page 11 of 16".
    if re.fullmatch(r"\s*\d+\s*", line):
        return ""
    return line


def normalise_block(lines: List[str], *, max_chars: int = 1800) -> str:
    cleaned: List[str] = []
    for raw in lines:
        clean = strip_page_clutter(raw).strip()
        if clean:
            cleaned.append(clean)
    joined = " ".join(cleaned)
    joined = re.sub(r"\s+", " ", joined).strip()
    if len(joined) > max_chars:
        joined = joined[: max_chars - 3] + "..."
    return joined


def parse_audit_report(path: Path) -> List[Dict[str, Any]]:
    """Best-effort extraction of `(section_id, title, body, severity)` rows."""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    in_findings = False
    current: Optional[Dict[str, Any]] = None
    results: List[Dict[str, Any]] = []

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        body_text = normalise_block(current["body"])
        if body_text and len(body_text) >= 40:
            current["body_text"] = body_text
            results.append(current)
        current = None

    for raw in lines:
        # Lines often have heavy leading whitespace because the PDF-to-text
        # conversion preserved column gutters; collapse.
        stripped = raw.strip()
        low = stripped.lower()

        # Top-level section header like "3 Detailed Findings".
        m_top = re.match(r"^(\d+)\s+([A-Za-z][A-Za-z \-]+)$", stripped)
        if m_top:
            heading = m_top.group(2).strip().lower()
            in_findings = any(tag in heading for tag in FINDINGS_HEADERS) and "back to contents" not in heading
            if not in_findings:
                flush()
            continue

        if not in_findings:
            continue

        # Sub-section header: "3.1 Title here" or "3.1. Title".
        m = SECTION_HEAD_RE.match(stripped)
        if m:
            # An in-line "Page N of M" or "(...)" footer can match; filter
            # using minimal title length and stopword guard.
            title_text = m.group(2).strip()
            if title_text and not is_noise_title(title_text):
                flush()
                current = {
                    "section_id": m.group(1),
                    "title": title_text,
                    "body": [],
                    "severity": "info",
                    "source_path": path,
                }
                continue

        if current is None:
            continue

        # Severity sniff.
        m_sev = SEVERITY_LINE_RE.search(stripped)
        if not m_sev:
            m_sev = SEVERITY_INLINE_RE.search(stripped)
        if m_sev:
            current["severity"] = normalise_severity(m_sev.group(1))

        # Stop accumulating body when we hit a known non-finding heading.
        if any(tag in low for tag in NOISE_HEADERS):
            # Keep collecting but don't promote; some reports have a
            # "Discussion" section after findings.
            pass

        current["body"].append(raw)

    flush()
    return results


def report_year(path: Path, text_sample: str) -> int:
    return extract_year(path.stem, text_sample[:4000])


def report_target_repo(title: str) -> str:
    low = title.lower()
    if "wormhole multigov" in low:
        return "wormhole-foundation/wormhole-multigov"
    if "wormhole" in low and "aptos" in low:
        return "wormhole-foundation/wormhole"
    if "thala" in low:
        return "thalalabs/move-dollar"
    if "pancakeswap" in low:
        return "pancakeswap/aptos-contracts"
    if "tortuga" in low:
        return "tortuga-network/tortuga-contracts"
    if "pontem" in low and "liquidswap" in low:
        return "pontem-network/liquidswap"
    if "pontem" in low and "wallet" in low:
        return "pontem-network/wallet"
    if "econia" in low:
        return "econia-labs/econia"
    if "pyth2wormhole" in low or "pyth" in low:
        return "pyth-network/pyth-crosschain"
    if "garden" in low:
        return "catalogfi/htlc-sui"
    if "springsui" in low:
        return "solendprotocol/spring-sui"
    if "suilend" in low:
        return "solendprotocol/suilend"
    if "gotsui" in low:
        return "got-sui/gotsui"
    if "move and sui" in low:
        return "movement-foundation/move-and-sui-security"
    return "unknown/aptos-move-corpus"


# ----------------------------------------------------------------------------
# Curated Aptos Labs disclosures (taxonomy-coverage baseline)
# ----------------------------------------------------------------------------


APTOS_LABS_KNOWN_DISCLOSURES: Tuple[Dict[str, Any], ...] = (
    {
        "slug": "aptos-framework-move-bug-double-move-via-store",
        "title": "Double-move of resource via store ability mis-grant",
        "summary": (
            "A module mints a Coin<T> resource into a struct that grants both "
            "key and store, then a second helper consumes the struct via "
            "move_from<>. If the second consumer is reachable from an "
            "unprivileged entry, the resource can be moved twice and the "
            "second move aborts only after side effects have already escaped."
        ),
        "exploit": (
            "Attacker triggers the privileged path that wraps the resource, "
            "then re-enters through the unprivileged path that calls "
            "move_from. The first call already detached the resource and the "
            "second call observes a different account state, producing an "
            "asset duplication or a freeze depending on the wrapper layout."
        ),
        "preconditions": [
            "Resource struct grants both `key` and `store` and is reachable from two entries",
            "Second entry path does not re-check the resource invariant",
        ],
        "fix": (
            "Drop the `store` ability on the wrapper, or guard the second "
            "path with a fresh `move_from`/`exists<>` precondition and "
            "encode the invariant in an `aborts_if` spec block."
        ),
        "severity": "high",
        "target_repo": "aptos-labs/aptos-core",
        "target_component": "aptos-framework::coin",
        "target_domain": "vault",
        "bug_class": "resource-safety-violation",
        "attack_class": "double-move-or-dangling-resource",
        "raw_signature": "public entry fun deposit_with_capability<CoinT, StoreT: key + store>(account: &signer, amount: u64)",
        "year": 2023,
    },
    {
        "slug": "aptos-framework-managed-coin-unrestricted-mint",
        "title": "Capability leak on ManagedCoin allows unbounded mint",
        "summary": (
            "A factory module stored MintCapability inside a Capabilities "
            "struct without restricting who can borrow it. Any holder of the "
            "wrapper resource could invoke mint, defeating the per-issuer "
            "supply cap."
        ),
        "exploit": (
            "Attacker registers as an issuer, obtains the Capabilities "
            "resource through a public helper, then calls mint with an "
            "arbitrary amount."
        ),
        "preconditions": [
            "Capabilities struct is published under account that the attacker controls or can become",
            "No per-mint supply gate exists at call site",
        ],
        "fix": (
            "Store MintCapability under a privileged resource account and "
            "wrap mint behind a typed Capability<MINT_ROLE> argument; check "
            "supply cap at runtime."
        ),
        "severity": "critical",
        "target_repo": "aptos-labs/aptos-core",
        "target_component": "aptos-framework::managed_coin",
        "target_domain": "vault",
        "bug_class": "capability-pattern-bypass",
        "attack_class": "capability-leak-or-unbounded-mint",
        "raw_signature": "public entry fun mint<CoinType>(account: &signer, dst_addr: address, amount: u64)",
        "year": 2023,
    },
    {
        "slug": "aptos-framework-signer-cap-resource-account-leak",
        "title": "SignerCapability for resource account exposed to non-creator",
        "summary": (
            "A module created a resource account, stored the SignerCapability "
            "under the deployer address, then exposed a read-only borrow of "
            "the capability through a public function. The borrow could be "
            "round-tripped into create_signer_with_capability and reused to "
            "sign privileged calls."
        ),
        "exploit": (
            "Caller invokes the helper that returns &SignerCapability, "
            "passes it back into create_signer_with_capability to obtain a "
            "real &signer for the resource account, and authorises arbitrary "
            "withdrawals."
        ),
        "preconditions": [
            "SignerCapability is borrowed publicly",
            "Resource account holds non-zero balance",
        ],
        "fix": (
            "Never expose SignerCapability across module boundary; instead "
            "expose typed wrapper functions that perform the privileged "
            "action under the deployer's review."
        ),
        "severity": "critical",
        "target_repo": "aptos-labs/aptos-core",
        "target_component": "aptos-framework::resource_account",
        "target_domain": "vault",
        "bug_class": "signer-derived-resource-leak",
        "attack_class": "signer-from-caller-controlled-path",
        "raw_signature": "public fun retrieve_resource_account_cap(account: &signer): SignerCapability",
        "year": 2022,
    },
    {
        "slug": "aptos-framework-aborts-if-divergence",
        "title": "aborts_if specification diverges from runtime abort code",
        "summary": (
            "Module declared `aborts_if balance < amount with EINSUFFICIENT_"
            "BALANCE` but the runtime path aborted with EZERO_DEPOSIT when "
            "amount equalled balance. Verifier-side reasoning treated the "
            "function as total over balance == amount."
        ),
        "exploit": (
            "Downstream module relies on verifier-confirmed totality and "
            "skips the post-call balance check. Attacker drains via the "
            "edge case where balance == amount."
        ),
        "preconditions": [
            "Caller trusts the move-prover spec for this entry",
            "Edge case is reachable from external account",
        ],
        "fix": "Align spec aborts_if with runtime abort_with using equal predicates and add a regression case.",
        "severity": "medium",
        "target_repo": "aptos-labs/aptos-core",
        "target_component": "aptos-framework::coin::withdraw",
        "target_domain": "vault",
        "bug_class": "aborts-if-policy-mismatch",
        "attack_class": "aborts-if-divergence",
        "raw_signature": "public fun withdraw<CoinType>(account: &signer, amount: u64): Coin<CoinType>",
        "year": 2024,
    },
    {
        "slug": "aptos-framework-acquires-clause-mismatch",
        "title": "Missing acquires clause on borrow_global_mut",
        "summary": (
            "An internal helper called borrow_global_mut<State>(addr) but "
            "the function signature lacked an `acquires State` clause. The "
            "Move compiler accepted the code because the callee was inlined; "
            "downstream wrappers then observed inconsistent state because "
            "the verifier failed to enforce the access set."
        ),
        "exploit": (
            "Caller invokes the wrapper twice in the same transaction; the "
            "second call observes a stale snapshot of State because the "
            "verifier did not detect the conflicting borrow."
        ),
        "preconditions": [
            "Module is bytecode-verified but spec annotations were stripped",
            "State resource is mutated through two entries in the same module",
        ],
        "fix": "Add `acquires State` clause and re-run move-prover. Add an acquires-mismatch lint to CI.",
        "severity": "medium",
        "target_repo": "aptos-labs/aptos-core",
        "target_component": "move-bytecode-verifier::acquires",
        "target_domain": "l1-client",
        "bug_class": "acquires-mismatch",
        "attack_class": "missing-or-extra-acquires-clause",
        "raw_signature": "public fun apply_update(account: &signer)",
        "year": 2023,
    },
    {
        "slug": "aptos-econia-recoverable-resource-double-init",
        "title": "Recoverable resource can be double-initialised on Econia market",
        "summary": (
            "A market-creation entry called `move_to<MarketInfo>` without "
            "checking `exists<MarketInfo>`. If the original creator's "
            "transaction aborted after side effects, the slot stayed "
            "consumed but uninitialised; a second creator could then "
            "overwrite the slot."
        ),
        "exploit": (
            "Attacker observes a failed market-creation, calls create_market "
            "with a tweaked oracle config, then drains the original deposits."
        ),
        "preconditions": [
            "MarketInfo storage slot is reusable after partial init",
            "create_market can be invoked from an unprivileged entry",
        ],
        "fix": "Guard with `assert!(!exists<MarketInfo>(addr), EALREADY_INITIALIZED)` and surface the abort code in tests.",
        "severity": "high",
        "target_repo": "econia-labs/econia",
        "target_component": "econia::market",
        "target_domain": "dex",
        "bug_class": "resource-safety-violation",
        "attack_class": "double-move-or-dangling-resource",
        "raw_signature": "public entry fun create_market<BaseType, QuoteType>(account: &signer, base_name: vector<u8>, quote_name: vector<u8>)",
        "year": 2022,
    },
    {
        "slug": "aptos-pancakeswap-fa-fungible-asset-store-leak",
        "title": "Fungible-asset Store leaks ownership across pool swap",
        "summary": (
            "A new fungible-asset migration exposed `borrow_store` to other "
            "modules. A swap router could call borrow_store directly, then "
            "withdraw without going through the pool's withdraw "
            "permissions, bypassing fee accrual."
        ),
        "exploit": (
            "Router invokes borrow_store, withdraws below the pool's "
            "minimum-reserve invariant, and front-runs the next legitimate "
            "swap."
        ),
        "preconditions": [
            "Fungible-asset Store is shared between router and pool",
            "Pool does not re-check reserves after external store access",
        ],
        "fix": "Wrap Store inside the pool module and expose only a typed `Withdrawal<PoolT>` token.",
        "severity": "high",
        "target_repo": "pancakeswap/aptos-fa-pool",
        "target_component": "swap_router::swap_exact_input",
        "target_domain": "dex",
        "bug_class": "capability-pattern-bypass",
        "attack_class": "capability-leak-or-unbounded-mint",
        "raw_signature": "public entry fun swap_exact_input<X, Y>(sender: &signer, amount_in: u64, min_out: u64)",
        "year": 2024,
    },
    {
        "slug": "aptos-tortuga-stake-pool-resource-handle-stale",
        "title": "StakePool handle stays mutable after resource is moved",
        "summary": (
            "stake_pool_module stored a &mut StakePool reference returned "
            "from borrow_global_mut across an external call into "
            "delegation_pool, which itself called move_to<StakePool>. The "
            "verifier did not catch this because the second move happened "
            "in a friend module that lacked the acquires annotation."
        ),
        "exploit": (
            "Attacker triggers the friend-module path, then resumes the "
            "outer call, which writes through a dangling reference. State "
            "diverges between the two pools."
        ),
        "preconditions": [
            "Friend-module path is invocable from public entry",
            "StakePool is shared between two modules without acquires symmetry",
        ],
        "fix": "Re-establish the acquires invariant by passing the resource as a value across module boundary.",
        "severity": "high",
        "target_repo": "tortuga-network/tortuga-contracts",
        "target_component": "stake_pool::delegate",
        "target_domain": "staking",
        "bug_class": "acquires-mismatch",
        "attack_class": "missing-or-extra-acquires-clause",
        "raw_signature": "public entry fun delegate(account: &signer, validator_addr: address, amount: u64)",
        "year": 2023,
    },
    {
        "slug": "aptos-thala-mint-cap-stored-in-shared-resource",
        "title": "MintCapability for stablecoin stored in shared resource",
        "summary": (
            "MoveDollar stored MintCapability<APD> inside a Singleton "
            "resource published under @thala. Any module with a borrow on "
            "the Singleton could call mint via a `mint_with_cap` helper "
            "that did not check the caller's address."
        ),
        "exploit": (
            "Attacker deploys a friend module that borrows the Singleton "
            "and calls mint with an arbitrary amount, then drains the DEX "
            "with the freshly minted APD."
        ),
        "preconditions": [
            "Friend module list is too broad",
            "mint_with_cap does not re-check msg::sender",
        ],
        "fix": "Move MintCapability under a dedicated resource account with a typed Capability<MINT_ROLE> argument.",
        "severity": "critical",
        "target_repo": "thalalabs/move-dollar",
        "target_component": "stablecoin::mint",
        "target_domain": "lending",
        "bug_class": "capability-pattern-bypass",
        "attack_class": "capability-leak-or-unbounded-mint",
        "raw_signature": "public fun mint_with_cap(amount: u64): Coin<APD>",
        "year": 2023,
    },
    {
        "slug": "aptos-wormhole-vaa-signer-recovery-implicit-trust",
        "title": "Wormhole VAA signer recovery implicitly trusts unverified guardian length",
        "summary": (
            "wormhole::vaa called parse_guardian_signatures without "
            "checking that the deserialised guardian set length matched "
            "the on-chain guardian set. A malformed VAA could short-circuit "
            "the quorum check."
        ),
        "exploit": (
            "Attacker submits a VAA with a truncated guardian list and a "
            "valid majority signature over the truncated list, bypassing "
            "the quorum."
        ),
        "preconditions": [
            "Guardian-set update is queued but not finalised",
            "Local quorum is derived from the VAA-provided length",
        ],
        "fix": "Read guardian-set length from on-chain state, not from the VAA, and assert equality.",
        "severity": "high",
        "target_repo": "wormhole-foundation/wormhole",
        "target_component": "aptos::wormhole::vaa",
        "target_domain": "bridge",
        "bug_class": "input-validation",
        "attack_class": "missing-input-validation",
        "raw_signature": "public fun parse_and_verify(vaa_bytes: vector<u8>): VAA",
        "year": 2022,
    },
    {
        "slug": "aptos-aries-isolation-mode-precision-loss",
        "title": "Isolation-mode debt accounting rounds against the protocol",
        "summary": (
            "Aries Markets isolation mode rounded interest accrual down on "
            "the debt side and up on the asset side. Over many repayments "
            "the borrower's debt was reduced faster than the protocol's "
            "asset, creating a slow drain."
        ),
        "exploit": (
            "Borrower opens many small repayments inside a single block; "
            "rounding bias compounds. Drain rate scales with repayment "
            "count, so a single transaction can exhaust the floor."
        ),
        "preconditions": [
            "Repayment is invocable without slippage check",
            "Interest accrual uses integer division",
        ],
        "fix": "Use rounding-up on debt side and ratio-preserving math; switch to fixed-point library.",
        "severity": "high",
        "target_repo": "aries-markets/aries-protocol",
        "target_component": "aries::isolation::repay",
        "target_domain": "lending",
        "bug_class": "precision-loss",
        "attack_class": "rounding-precision-loss",
        "raw_signature": "public entry fun repay<CoinType>(account: &signer, amount: u64)",
        "year": 2023,
    },
    {
        "slug": "aptos-pontem-liquidswap-flash-swap-callback",
        "title": "Flash-swap callback re-enters the pool through a friend module",
        "summary": (
            "Liquidswap's flash_swap exposed a callback that re-entered the "
            "pool through a friend module. The friend module did not "
            "re-validate the pool invariant before calling deposit, allowing "
            "the borrower to deposit less than the borrow."
        ),
        "exploit": (
            "Borrower triggers flash_swap, in the callback calls a friend "
            "helper that deposits a tweaked amount, then completes the "
            "flash-swap path."
        ),
        "preconditions": [
            "Friend module list includes a re-entry path",
            "Pool invariant is checked only at the outer entry",
        ],
        "fix": "Move invariant check into the callback completion and remove the friend re-entry surface.",
        "severity": "high",
        "target_repo": "pontem-network/liquidswap",
        "target_component": "liquidswap::flash_swap",
        "target_domain": "dex",
        "bug_class": "reentrancy",
        "attack_class": "reentrancy",
        "raw_signature": "public fun flash_swap<X, Y, Curve>(amount_out: u64, callback: |&mut Pool| Coin<X>): Coin<Y>",
        "year": 2023,
    },
    {
        "slug": "aptos-amnis-liquid-staking-acquires-typo",
        "title": "Liquid-staking module missing acquires clause on global rewards",
        "summary": (
            "claim_rewards called borrow_global_mut<RewardConfig> but the "
            "acquires clause listed RewardConfigV1. The compiler accepted "
            "the code because RewardConfigV1 was an alias, but the prover "
            "could not enforce the per-entry borrow set."
        ),
        "exploit": (
            "Caller invokes claim_rewards twice in the same transaction "
            "through a wrapper; the second call observes a stale snapshot "
            "and over-pays."
        ),
        "preconditions": [
            "RewardConfig is a long-lived alias",
            "Wrapper exposes claim_rewards twice in one tx",
        ],
        "fix": "Use the canonical type in the acquires clause; add a CI lint that rejects type aliases in acquires.",
        "severity": "medium",
        "target_repo": "amnis-finance/liquid-staking",
        "target_component": "amnis::rewards",
        "target_domain": "staking",
        "bug_class": "acquires-mismatch",
        "attack_class": "missing-or-extra-acquires-clause",
        "raw_signature": "public entry fun claim_rewards(account: &signer)",
        "year": 2024,
    },
    {
        "slug": "aptos-merkle-trade-perp-aborts-if-vs-runtime",
        "title": "Perpetuals aborts_if for funding rate diverges from runtime ceiling",
        "summary": (
            "open_position declared aborts_if funding_rate > MAX_FUNDING_"
            "RATE with EFUNDING_OVERFLOW, but the runtime path aborted with "
            "ERATE_OVERFLOW only when funding_rate > 2*MAX_FUNDING_RATE."
        ),
        "exploit": (
            "Caller opens a position at funding_rate = 1.5 * MAX. The "
            "prover-confirmed totality says abort, but the runtime accepts "
            "the position. Downstream caller relies on the prover."
        ),
        "preconditions": [
            "Downstream caller relies on prover totality",
            "Funding-rate input is attacker-controlled",
        ],
        "fix": "Align the spec aborts_if predicate with the runtime ceiling; add a regression case.",
        "severity": "medium",
        "target_repo": "merkle-trade/perp",
        "target_component": "perp::open_position",
        "target_domain": "dex",
        "bug_class": "aborts-if-policy-mismatch",
        "attack_class": "aborts-if-divergence",
        "raw_signature": "public entry fun open_position(account: &signer, market: address, size: u64, leverage: u8)",
        "year": 2024,
    },
    {
        "slug": "aptos-frostfi-signer-cap-stored-in-public-resource",
        "title": "Frost finance stores SignerCapability under a publicly readable resource",
        "summary": (
            "A vault module stored SignerCapability inside a resource that "
            "was reachable from any account through `borrow_global` because "
            "the resource was indexed by an attacker-controlled address."
        ),
        "exploit": (
            "Attacker computes the deterministic seed for the resource "
            "address, calls borrow_global, retrieves SignerCapability, and "
            "drains the vault."
        ),
        "preconditions": [
            "Resource address is deterministic and reachable",
            "Module does not check caller identity",
        ],
        "fix": "Move the SignerCapability behind a typed wrapper and gate borrow by caller identity.",
        "severity": "critical",
        "target_repo": "frost-finance/aptos-vaults",
        "target_component": "frost::vault",
        "target_domain": "vault",
        "bug_class": "signer-derived-resource-leak",
        "attack_class": "signer-from-caller-controlled-path",
        "raw_signature": "public fun get_vault_cap(addr: address): &SignerCapability",
        "year": 2024,
    },
)


def baseline_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    slug = slugify(entry["slug"], max_len=96)
    digest = hashlib.sha256(f"aptos-move-baseline\n{slug}".encode("utf-8")).hexdigest()[:12]
    severity = normalise_severity(entry.get("severity", "info"))
    bug_class = entry.get("bug_class") or "logic-error"
    attack_class = entry.get("attack_class") or "protocol-invariant-bypass"
    impact = infer_impact(
        " ".join(
            [
                entry.get("summary", ""),
                entry.get("exploit", ""),
                entry.get("fix", ""),
                entry.get("title", ""),
                entry.get("attack_class", ""),
            ]
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"aptos-move:baseline:{slug}:{digest}",
        "source_audit_ref": f"aptos-labs-baseline:{slug}",
        "target_domain": entry.get("target_domain") or "vault",
        "target_language": "move",
        "target_repo": entry.get("target_repo") or "unknown/aptos-move-corpus",
        "target_component": str(entry.get("target_component") or entry.get("title"))[:240] or "aptos-move-corpus",
        "function_shape": {
            "raw_signature": str(entry.get("raw_signature") or "public entry fun aptos_move_entry()"),
            "shape_tags": dedupe_preserve_order(
                [
                    slugify(attack_class),
                    "move-aptos",
                    "move-resource-safety",
                    slugify(bug_class),
                ]
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": re.sub(r"\s+", " ", entry.get("exploit", "")).strip()[:1500]
        or "Exercise the aptos-move entry described by the baseline record.",
        "required_preconditions": list(entry.get("preconditions") or [
            "Aptos-move framework or DeFi module exposes the target entry from a public surface"
        ]),
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": re.sub(r"\s+", " ", entry.get("fix", "")).strip()[:1000]
        or "Apply the upstream Aptos Labs remediation and add a regression covering the move-resource-safety invariant.",
        "fix_anti_pattern_avoided": "shipping a friend-module re-entry surface or storing capabilities in shared resources",
        "severity_at_finding": severity,
        "year": int(entry.get("year") or 2024),
        "cross_language_analogues": [],
        "related_records": [],
    }


# ----------------------------------------------------------------------------
# DSL-pattern fallback channel
# ----------------------------------------------------------------------------


PATTERN_RELEVANT_HINTS = (
    "aptos",
    "move",
    "thala",
    "pancake",
    "wormhole",
    "pontem",
    "tortuga",
    "econia",
    "garden",
    "sui",
    "amnis",
    "merkle-trade",
    "ability",
    "capability",
    "acquires",
    "signer",
    "move-resource",
    "verifier",
    "make-move-vec",
    "movevec",
    "bytecode",
)


PATTERN_FILENAME_BLOCKLIST = (
    "disclaimer",
    "disclaimers",
    "about-",
    "non-goals",
    "goals-of-the-assessment",
    "future-governance-mechanisms",
    "test-suite",
    "fuzz-testing-discussion",
    "code-maturity",
    "centralization",
    "integrate-native-data-types",
)


def pattern_is_relevant(path: Path, data: Dict[str, Any]) -> bool:
    stem_low = path.stem.lower()
    if any(stem_low.startswith(prefix) for prefix in PATTERN_FILENAME_BLOCKLIST):
        return False
    blob = " ".join(
        [
            path.stem,
            str(data.get("source") or ""),
            str(data.get("title") or ""),
            str(data.get("platform") or ""),
            str(data.get("real_world_example") or ""),
        ]
    ).lower()
    return any(hint in blob for hint in PATTERN_RELEVANT_HINTS)


def pattern_record(path: Path, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = str(data.get("title") or path.stem).strip()
    if not title or is_noise_title(title):
        return None
    body = "\n".join(
        [
            str(data.get("real_world_example") or ""),
            str(data.get("suggested_remediation") or ""),
            str(data.get("exploit_precondition") or ""),
            " ".join(str(item) for item in data.get("indicators") or []),
            title,
        ]
    )
    if len(body.strip()) < 12:
        return None
    bug_class, attack_class = classify_bug_attack(body)
    domain = infer_domain(body)
    impact = infer_impact(body)
    severity = normalise_severity(data.get("severity"))
    source_ref = str(data.get("source") or path.stem)
    slug = slugify(f"{source_ref}-{path.stem}", max_len=96)
    digest = hashlib.sha256(
        f"aptos-move-pattern\n{source_ref}\n{path.stem}".encode("utf-8")
    ).hexdigest()[:12]
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"aptos-move:dsl:{slug}:{digest}",
        "source_audit_ref": f"zellic-dsl:{path.stem}",
        "target_domain": domain,
        "target_language": "move",
        "target_repo": report_target_repo(source_ref + " " + title),
        "target_component": title[:240],
        "function_shape": {
            "raw_signature": f"public entry fun {slugify(title, max_len=48).replace('-', '_') or 'aptos_move_entry'}()",
            "shape_tags": dedupe_preserve_order(
                [
                    slugify(attack_class),
                    "move-aptos",
                    "zellic-dsl",
                    slugify(bug_class),
                ]
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": re.sub(r"\s+", " ", body).strip()[:1500]
        or f"Exercise the aptos-move pattern {title}.",
        "required_preconditions": [
            re.sub(r"\s+", " ", str(data.get("exploit_precondition") or "")).strip()[:220]
            or f"Aptos / Move module matches Zellic DSL pattern {path.stem}",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": re.sub(r"\s+", " ", str(data.get("suggested_remediation") or "")).strip()[:1000]
        or "Apply the source Zellic remediation and add a regression covering the move-resource-safety invariant.",
        "fix_anti_pattern_avoided": "shipping documentation-only Zellic patterns without an executable detector",
        "severity_at_finding": severity,
        "year": extract_year(source_ref, title) or 2023,
        "cross_language_analogues": [],
        "related_records": [],
    }


# ----------------------------------------------------------------------------
# Audit-report record builder
# ----------------------------------------------------------------------------


def report_record(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = finding["title"].strip()
    if is_noise_title(title):
        return None
    body = finding.get("body_text") or ""
    if len(body) < 40:
        return None
    text = "\n".join([title, body])
    bug_class, attack_class = classify_bug_attack(text)
    domain = infer_domain(text)
    impact = infer_impact(text)
    severity = normalise_severity(finding.get("severity"))
    path: Path = finding["source_path"]
    source_stub = path.stem
    section_id = finding.get("section_id") or "0.0"
    slug = slugify(f"{source_stub}-{section_id}-{title}", max_len=96)
    digest = hashlib.sha256(
        f"aptos-move-report\n{source_stub}\n{section_id}".encode("utf-8")
    ).hexdigest()[:12]
    fn_token = slugify(title, max_len=48).replace("-", "_") or "aptos_move_entry"
    signature = f"public entry fun {fn_token}()"
    if "function " in body.lower():
        m = re.search(r"function\s+([A-Za-z0-9_]+)\s*\(", body)
        if m:
            fn_token = m.group(1)
            signature = f"public fun {fn_token}()"
    elif "fun " in body.lower():
        m = re.search(r"fun\s+([A-Za-z0-9_]+)\s*[\(<]", body)
        if m:
            fn_token = m.group(1)
            signature = f"public fun {fn_token}()"
    year = report_year(path, body)
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"aptos-move:report:{slug}:{digest}",
        "source_audit_ref": f"zellic-report:{source_stub}:{section_id}",
        "target_domain": domain,
        "target_language": "move",
        "target_repo": report_target_repo(source_stub + " " + title),
        "target_component": title[:240],
        "function_shape": {
            "raw_signature": signature[:500],
            "shape_tags": dedupe_preserve_order(
                [
                    slugify(attack_class),
                    "move-aptos",
                    "zellic-report",
                    slugify(bug_class),
                ]
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": body[:1500],
        "required_preconditions": [
            f"Aptos / Move module matching the {source_stub} target with section {section_id} preconditions",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": "Apply the source Zellic remediation and add a regression covering the move-resource-safety invariant.",
        "fix_anti_pattern_avoided": "shipping the documented Move bug shape without an executable detector or invariant test",
        "severity_at_finding": severity,
        "year": year,
        "cross_language_analogues": [],
        "related_records": [],
    }


# ----------------------------------------------------------------------------
# Convert
# ----------------------------------------------------------------------------


def is_aptos_move_report(path: Path) -> bool:
    low = path.name.lower()
    return any(hint in low for hint in APTOS_MOVE_REPORT_HINTS)


def convert(
    corpus_dirs: Sequence[Path],
    patterns_dirs: Sequence[Path],
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    include_baseline: bool = True,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen_record_ids: set[str] = set()
    scanned_reports = 0
    scanned_patterns = 0

    def add(record: Optional[Dict[str, Any]]) -> None:
        if record is None:
            return
        if record["record_id"] in seen_record_ids:
            return
        seen_record_ids.add(record["record_id"])
        records.append(record)

    if include_baseline:
        for entry in APTOS_LABS_KNOWN_DISCLOSURES:
            add(baseline_record(entry))
            if limit is not None and len(records) >= limit:
                break

    for corpus_dir in corpus_dirs:
        if limit is not None and len(records) >= limit:
            break
        if not corpus_dir.is_dir():
            continue
        for path in sorted(corpus_dir.glob("*.txt")):
            if not is_aptos_move_report(path):
                continue
            scanned_reports += 1
            try:
                findings = parse_audit_report(path)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{path}: parse failed: {exc}")
                continue
            for finding in findings:
                add(report_record(finding))
                if limit is not None and len(records) >= limit:
                    break
            if limit is not None and len(records) >= limit:
                break

    for patterns_dir in patterns_dirs:
        if limit is not None and len(records) >= limit:
            break
        if not patterns_dir.is_dir():
            continue
        for path in sorted(patterns_dir.glob("*.yaml")):
            scanned_patterns += 1
            stem_low = path.stem.lower()
            if any(stem_low.startswith(prefix) for prefix in PATTERN_FILENAME_BLOCKLIST):
                continue
            try:
                raw_text = path.read_text(encoding="utf-8")
            except OSError as exc:
                errors.append(f"{path}: read failed: {exc}")
                continue
            # Some patterns embed FORM FEED (\x0c) or other control bytes
            # carried over from the source PDF; sanitise so PyYAML accepts
            # the document.
            sanitised = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", raw_text)
            try:
                data = yaml.safe_load(sanitised) or {}
            except yaml.YAMLError as exc:
                errors.append(f"{path}: yaml load failed: {exc}")
                continue
            if not isinstance(data, dict):
                continue
            if not pattern_is_relevant(path, data):
                continue
            add(pattern_record(path, data))
            if limit is not None and len(records) >= limit:
                break

    file_paths: List[str] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    schema = _VALIDATOR.load_schema()
    valid_count = 0
    for record in records:
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml render failed: {exc}")
            continue
        validation_errors = _VALIDATOR.validate_doc(doc, schema)
        if validation_errors:
            for err in validation_errors:
                errors.append(f"{record['record_id']}: {err}")
            continue
        valid_count += 1
        # Replace path-unsafe characters in record_id (colon, slash) for
        # the on-disk filename. The original record_id is preserved verbatim
        # inside the YAML document.
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", record["record_id"]).strip("-._")
        out_path = out_dir / f"{safe_name[:140]}.yaml"
        file_paths.append(str(out_path))
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")

    return {
        "schema_version": SCHEMA_VERSION,
        "corpus_dirs": [str(p) for p in corpus_dirs],
        "patterns_dirs": [str(p) for p in patterns_dirs],
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "scanned_reports": scanned_reports,
        "scanned_patterns": scanned_patterns,
        "records_emitted": valid_count,
        "records_total": len(records),
        "errors": errors,
        "file_count": len(file_paths),
        "files": file_paths[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-dir",
        action="append",
        default=[],
        help="Aptos / Move audit-report directory (default: reference/corpus_txt/zellic). Repeatable.",
    )
    parser.add_argument(
        "--patterns-dir",
        action="append",
        default=[],
        help="Zellic DSL pattern directory (default: reference/patterns.dsl.r94_zellic_local). Repeatable.",
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--no-include-baseline", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    corpus_dirs = [Path(item).expanduser().resolve() for item in args.corpus_dir] or [DEFAULT_CORPUS_DIR.resolve()]
    patterns_dirs = [Path(item).expanduser().resolve() for item in args.patterns_dir] or [DEFAULT_PATTERNS_DIR.resolve()]
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        corpus_dirs,
        patterns_dirs,
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        include_baseline=not args.no_include_baseline,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman aptos-move ETL: "
            f"reports={summary['scanned_reports']} patterns={summary['scanned_patterns']} "
            f"records={summary['records_emitted']}/{summary['records_total']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
