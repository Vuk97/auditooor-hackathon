#!/usr/bin/env python3
"""Backfill Solana-native attack_class labels onto hackerman_record v1 YAML.

Today the corpus carries ~400 records that mention Solana / Anchor / SPL but
zero are tagged with the Solana-native attack-class taxonomy:

    missing-signer-check
    pda-collision
    account-confusion
    account-reinitialization
    cpi-arbitrary-target
    sysvar-spoof
    token-2022-extension-confusion
    anchor-context-misuse
    realloc-attack
    close-attack
    pda-seed-confusion
    init-if-needed-bypass
    account-discriminator-spoof
    lookup-table-poisoning

This tool scans every hackerman_record YAML for Solana-ecosystem signal in
``target_language`` / ``target_repo`` / body text. For each Solana-ecosystem
record it then scans body text for keyword indicators of one of the 14
Solana-native attack classes and emits a candidate to
``.auditooor/solana-retag-candidates.jsonl``.

Phase 1 (this commit): emit candidate rows only. ``--apply`` will rewrite the
``attack_class:`` line in the YAML body; rollback information stays in the
JSONL ledger (the strict hackerman_record schema disallows additional
top-level properties).

Usage:
    python3 tools/hackerman-backfill-solana-class.py --dry-run
    python3 tools/hackerman-backfill-solana-class.py --dry-run --json-summary
    python3 tools/hackerman-backfill-solana-class.py --apply
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "auditooor.hackerman_backfill_solana_class.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_LEDGER_PATH = REPO_ROOT / ".auditooor" / "solana-retag-candidates.jsonl"

HACKERMAN_SCHEMA_RE = re.compile(
    r"^schema_version:\s+auditooor\.hackerman_record\.v1\s*$", re.MULTILINE
)
ATTACK_CLASS_RE = re.compile(
    r"^(attack_class:\s*)([\"']?)([A-Za-z0-9._\-]+)\2\s*$", re.MULTILINE
)
TARGET_REPO_RE = re.compile(
    r"^target_repo:\s*([\"']?)(.+?)\1\s*$", re.MULTILINE
)
TARGET_LANGUAGE_RE = re.compile(
    r"^target_language:\s*([\"']?)([A-Za-z0-9._\-]+)\1\s*$", re.MULTILINE
)


# Solana-ecosystem signals (any one match makes a record eligible).
SOLANA_ECOSYSTEM_SIGNALS: Tuple[str, ...] = (
    "solana",
    "anchor::",
    "anchor_lang",
    "anchor_spl",
    "#[program]",
    "#[derive(accounts)]",
    "spl_token",
    "spl-token",
    "spl_token_2022",
    "token-2022",
    "ottersec_solana",
    "ottersec/solana",
    "drafts_ottersec_solana",
    "solana_program",
    "solana-program",
    "metaplex",
    "raydium",
    "serum",
    "mango",
    "jupiter",
    "drift-labs",
    "openbook",
    "jet-protocol",
    "marinade",
    "lido-solana",
    "solend",
    "pyth-network",
    "switchboard-xyz",
)


# Per-class keyword indicators. Order matters: more specific classes first
# so e.g. token-2022 confusion is matched before generic account-confusion.
# Each entry: (attack_class, indicators) where ``indicators`` is a tuple of
# lowercase substrings.
SOLANA_CLASS_INDICATORS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "token-2022-extension-confusion",
        (
            "token-2022", "token 2022", "spl_token_2022", "spl-token-2022",
            "transfer hook", "transfer fee extension", "permanent delegate",
            "confidential transfer", "extension confusion",
        ),
    ),
    (
        "lookup-table-poisoning",
        (
            "address lookup table", "lookup-table", "lookup table poison",
            "alt poisoning", "address_lookup_table",
        ),
    ),
    (
        "init-if-needed-bypass",
        (
            "init_if_needed", "init-if-needed", "init if needed",
            "initialise if needed", "re-initialise",
        ),
    ),
    (
        "account-discriminator-spoof",
        (
            "discriminator", "anchor discriminator", "discriminator collision",
            "8-byte discriminator", "type cosplay",
        ),
    ),
    (
        "account-reinitialization",
        (
            "reinitialization", "reinitialisation", "reinit",
            "re-initialize", "re-initialise", "init twice",
        ),
    ),
    (
        "realloc-attack",
        (
            "realloc", "account.realloc", "account_realloc", "resize account",
        ),
    ),
    (
        "close-attack",
        (
            "close = ", "close=destination", "close attribute",
            "close account", "lamports drain", "drain lamports",
            "close_account",
        ),
    ),
    (
        "cpi-arbitrary-target",
        (
            "arbitrary cpi", "cpi target", "cross_program_invocation",
            "cross-program invocation", "invoke_signed", "invoke(",
            "arbitrary program id", "unchecked program id",
        ),
    ),
    (
        "sysvar-spoof",
        (
            "sysvar spoof", "fake sysvar", "spoof clock", "clock sysvar",
            "rent sysvar", "instructions sysvar", "sysvar account",
        ),
    ),
    (
        "pda-collision",
        (
            "pda collision", "pda-collision", "find_program_address",
            "program_derived_address", "create_program_address",
            "colliding pda",
        ),
    ),
    (
        "pda-seed-confusion",
        (
            "seed confusion", "pda seed", "seeds = [", "seeds=[",
            "predictable seed", "seed manipulation",
        ),
    ),
    (
        "anchor-context-misuse",
        (
            "anchor context", "context<", "ctx.accounts", "anchor accounts",
            "#[derive(accounts)]", "accounts struct",
        ),
    ),
    (
        "missing-signer-check",
        (
            "is_signer", "missing signer", "missing_signer",
            "required_signers", "signer<", "signer check",
            "no signer check", "missing-signer", "unauthorized-signer",
            "signer-validation", "signer authority",
        ),
    ),
    (
        "account-confusion",
        (
            "account confusion", "wrong account", "accountinfo<",
            "type confusion", "account type", "account-confusion",
            "wrong-account", "account substitution", "account-substitution",
            "unchecked account",
        ),
    ),
)


# Title-slug indicators (lower priority but useful when body is "tbd").
# These deliberately re-target a few classes via solodit title patterns.
SOLANA_TITLE_INDICATORS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("account-reinitialization", (
        "reinitialization", "reinitialisation", "reinit",
        "ability-to-initialize-multiple-times",
        "double-initialization", "multiple-times",
        "re-initialize",
    )),
    ("account-discriminator-spoof", (
        "discriminator-spoof", "discriminator-collision",
        "account-discriminator", "discriminator-check-bypass",
        "account-tag-collision", "dynamic-field-hash-collision",
    )),
    ("token-2022-extension-confusion", (
        "token-2022", "transfer-hook", "transfer-fee-extension",
        "permanent-delegate", "transferring-with-fees",
    )),
    ("close-attack", (
        "close-attack", "lamports-drain", "close-account-attack",
        "account-closing", "account-closing-is-not-atomic",
        "custody-token-account-closing",
    )),
    ("realloc-attack", (
        "account-resize",
    )),
    ("init-if-needed-bypass", (
        "init-if-needed", "ability-to-initialize", "init-multiple",
    )),
    ("anchor-context-misuse", (
        "missing-has-one", "anchor-context-misuse",
        "missing-validation-in-accounts",
        "account-trigger-validation",
    )),
    ("pda-seed-confusion", (
        "missing-account-seed", "account-seed-verification",
        "incorrect-pda-seed", "seed-collision",
        "absence-of-bank-account-validation",
        "absence-of-oracle-account-validation",
        "absence-of-destination-domain-validation",
        "absence-of-verification-of-issuance-account-index",
        "absence-of-index-validation",
        "absence-of-state-variable-update-on-wallet-removal",
        "bypassing-output-token-account-check",
        "bypassing-token-account-initialization",
        "missing-tokenaccount-checks",
        "missing-mango-account-check",
        "missing-receipt-token-balance-check",
        "missing-transactionpayload-type-validation",
    )),
    ("missing-signer-check", (
        "missing-signer", "missing-authority-check",
        "unauthorized-signer", "incorrect-signer-check",
        "signer-validation",
        "bypass-of-authority-access-control-checks",
        "critical-access-control-check",
        "ability-to-update-signer-key",
        "denial-of-service-due-to-authority-change",
    )),
    ("account-confusion", (
        "account-confusion", "wrong-account-type",
        "incorrect-account", "account-substitution",
        "type-cosplay", "account-type-confusion",
        "account-inconsistencies",
        "elevation-group-id-mismatch",
        "balance-entry-overwrite",
        "assignment-of-incorrect-reward-escrow",
        "epoch-mismatch-in-storage-reclamation",
        "discrepancy-in-deposit-functionality",
        "discrepancies-in-deposit-functionality",
        "discrepancies-in-updating-investor-count",
        "executor-cache-inconsistency",
        "balance-cache-inconsistency",
    )),
    ("cpi-arbitrary-target", (
        "arbitrary-cpi", "unchecked-cpi", "arbitrary-program-id",
        "arbitrary-amm-config-possible-usage",
        "arbitrary-price-feed-utilization",
        "bypassing-of-nft-collection-integrity-checks",
        "discrepancies-in-payload-format",
    )),
)


def _is_hackerman_record(text: str) -> bool:
    return bool(HACKERMAN_SCHEMA_RE.search(text))


def _extract(text: str, pattern: re.Pattern, group: int) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    return m.group(group).strip()


EVM_DISQUALIFIERS: Tuple[str, ...] = (
    "msg.sender", "erc721", "erc20", "erc-20", "erc4626", "erc-4626",
    "evm", "solidity", "uniswap", "_writecheckpoint",
    "function ",  # solidity function declaration
)


def _looks_evm(body: str) -> bool:
    low = body.lower()
    # Count strong EVM signals; require >=2 to disqualify a borderline record
    # so a stray ERC mention does not block a legitimate Solana finding.
    hits = sum(1 for needle in EVM_DISQUALIFIERS if needle in low)
    return hits >= 2


def is_solana_record(target_repo: str, target_language: str, body: str) -> bool:
    repo_low = (target_repo or "").lower()
    body_low = (body or "").lower()
    # Strong signals: explicit Solana-ecosystem mention in target_repo or
    # explicit Anchor/SPL/Solana literal in body wins regardless.
    STRONG_REPO_SIGNALS = (
        "solana", "anchor", "ottersec/solana", "drafts_ottersec_solana",
        "metaplex", "raydium", "serum", "drift-labs", "openbook",
        "jet-protocol", "marinade", "solend", "pyth-network",
        "switchboard-xyz",
    )
    for needle in STRONG_REPO_SIGNALS:
        if needle in repo_low:
            return True
    STRONG_BODY_SIGNALS = (
        "anchor::", "anchor_lang", "anchor_spl", "#[program]",
        "#[derive(accounts)]", "spl_token", "spl_token_2022",
        "solana_program", "ottersec_solana", "drafts_ottersec_solana",
    )
    for needle in STRONG_BODY_SIGNALS:
        if needle in body_low:
            return True
    # Soft signals (target_language=rust + any-Solana-signal-in-body) but
    # disqualify clearly-EVM records.
    if target_language and target_language.lower() == "rust":
        if any(sig in body_low for sig in SOLANA_ECOSYSTEM_SIGNALS) and not _looks_evm(body_low):
            return True
    return False


def classify(body: str) -> Tuple[str, str]:
    """Return (attack_class, matched_indicator) or ("", "").

    Pass 1: high-confidence body-text indicators (SOLANA_CLASS_INDICATORS).
    Pass 2: title-slug indicators (SOLANA_TITLE_INDICATORS) - useful when the
    body is a stub like "tbd" but the source_audit_ref / target_component
    carries a kebab-case title that names the bug class.
    """
    low = body.lower()
    for cls, indicators in SOLANA_CLASS_INDICATORS:
        for needle in indicators:
            if needle in low:
                return cls, needle
    for cls, indicators in SOLANA_TITLE_INDICATORS:
        for needle in indicators:
            if needle in low:
                return cls, needle
    return "", ""


def _build_candidate(
    path: Path,
    text: str,
    target_repo: str,
    target_language: str,
    current_attack_class: str,
    new_attack_class: str,
    matched_indicator: str,
) -> Dict[str, Any]:
    record_id_match = re.search(r"^record_id:\s*(.+?)\s*$", text, re.MULTILINE)
    return {
        "tag_file": path.name,
        "record_id": record_id_match.group(1).strip().strip("'\"") if record_id_match else "",
        "target_repo": target_repo,
        "target_language": target_language,
        "attack_class_original": current_attack_class,
        "attack_class_new": new_attack_class,
        "matched_indicator": matched_indicator,
    }


def _rewrite_attack_class(text: str, new_value: str) -> str:
    def repl(m: re.Match) -> str:
        prefix, quote, _ = m.group(1), m.group(2), m.group(3)
        return f"{prefix}{quote}{new_value}{quote}"
    return ATTACK_CLASS_RE.sub(repl, text, count=1)


def scan(
    tag_dir: Path,
    *,
    apply: bool = False,
    limit: int = 0,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    scanned = 0
    solana_eligible = 0
    classified = 0
    no_class_match = 0
    already_native_skip = 0
    updated_files: List[str] = []
    class_counts: Dict[str, int] = {}

    native_classes = {cls for cls, _ in SOLANA_CLASS_INDICATORS}

    paths = sorted(p for p in tag_dir.glob("*.yaml") if p.is_file())
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not _is_hackerman_record(text):
            continue
        scanned += 1
        target_repo = _extract(text, TARGET_REPO_RE, 2)
        target_language = _extract(text, TARGET_LANGUAGE_RE, 2)
        if not is_solana_record(target_repo, target_language, text):
            continue
        solana_eligible += 1
        current_attack_class = _extract(text, ATTACK_CLASS_RE, 3)
        if current_attack_class in native_classes:
            already_native_skip += 1
            continue
        new_cls, matched_indicator = classify(text)
        if not new_cls:
            no_class_match += 1
            continue
        classified += 1
        class_counts[new_cls] = class_counts.get(new_cls, 0) + 1
        cand = _build_candidate(
            path,
            text,
            target_repo,
            target_language,
            current_attack_class,
            new_cls,
            matched_indicator,
        )
        candidates.append(cand)

        if apply:
            new_text = _rewrite_attack_class(text, new_cls)
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
                updated_files.append(path.name)

        if limit and len(candidates) >= limit:
            break

    summary = {
        "schema": SCHEMA,
        "scanned": scanned,
        "solana_eligible": solana_eligible,
        "candidate_count": len(candidates),
        "classified": classified,
        "no_class_match": no_class_match,
        "already_native_class_skipped": already_native_skip,
        "class_counts": dict(sorted(class_counts.items(), key=lambda kv: -kv[1])),
        "applied": apply,
        "updated_files": updated_files,
    }
    return candidates, summary


def write_ledger(candidates: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in candidates:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag-dir", type=Path, default=DEFAULT_TAG_DIR,
        help=f"Directory of YAML records (default: {DEFAULT_TAG_DIR})",
    )
    parser.add_argument(
        "--ledger", type=Path, default=DEFAULT_LEDGER_PATH,
        help=f"Output JSONL ledger (default: {DEFAULT_LEDGER_PATH})",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Scan only, never modify YAML.",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Rewrite attack_class in matched YAML files.",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Stop after N candidates.",
    )
    parser.add_argument(
        "--json-summary", action="store_true",
        help="Emit a JSON summary line to stdout instead of human text.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.dry_run:
        print("ERROR: --apply and --dry-run are mutually exclusive", file=sys.stderr)
        return 2

    apply = bool(args.apply)
    candidates, summary = scan(args.tag_dir, apply=apply, limit=args.limit)
    write_ledger(candidates, args.ledger)
    summary["ledger_path"] = str(args.ledger)

    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            f"[backfill-solana-class] scanned={summary['scanned']} "
            f"solana_eligible={summary['solana_eligible']} "
            f"classified={summary['classified']} "
            f"no_class_match={summary['no_class_match']} "
            f"applied={summary['applied']} "
            f"ledger={summary['ledger_path']}"
        )
        for cls, count in summary["class_counts"].items():
            print(f"    {cls}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
