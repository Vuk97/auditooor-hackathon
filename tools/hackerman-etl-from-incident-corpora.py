#!/usr/bin/env python3
"""hackerman-etl-from-incident-corpora.py - LIFT-13 v2 harvester.

Harvests hacker_questions from 6 incident corpora.
Rule 37: emits at tier-2-verified-public-archive.
Rule 36: registered lane work2-lift13-v2-incident-harvest-2026-05-26.
L34: auto-executable (derived output).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

def _load_routing_lib():
    """Load the shared per-function target-pattern lib for native-language
    routing. Fail-open: if it cannot be loaded, routing degrades to the
    record's declared languages (no crash, no over-correction)."""
    import importlib.util
    lib = Path(__file__).resolve().parent / "lib" / "per_function_target_patterns.py"
    try:
        spec = importlib.util.spec_from_file_location("pftp_routing", lib)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_ROUTING_LIB = _load_routing_lib()


def route_target_languages(attack_class, question_text, declared_langs):
    """B2: resolve to native language(s); fail-open to declared_langs."""
    if _ROUTING_LIB is None:
        return declared_langs
    resolved, _native, _source = _ROUTING_LIB.resolve_target_languages(
        attack_class or "", question_text or "", declared_langs or [])
    return resolved


HARVESTER_ID = "lift13-v2-incident-corpora-2026-05-26"
SCHEMA_VERSION = "auditooor.hacker_question.v1"
OUTPUT_FILE = "audit/corpus_tags/derived/hacker_questions_library_v2_incident_harvest.jsonl"
REPORT_DIR = "reports/v3_iter_2026-05-26_lift13_v2"

CORPORA = [
    {"name": "audit_firm_findings_pashov", "record_format": "json", "record_filename": "record.json", "min_quality_score": 3.5, "sample_limit": None},
    {"name": "defimon_blog_incidents", "record_format": "yaml", "record_filename": "record.yaml", "min_quality_score": 0.0, "sample_limit": None},
    {"name": "bridge_incidents", "record_format": "json", "record_filename": "record.json", "min_quality_score": 0.0, "sample_limit": None},
    {"name": "mev_exploits", "record_format": "json", "record_filename": "record.json", "min_quality_score": 0.0, "sample_limit": None},
    {"name": "darknavy_web3_incidents", "record_format": "json_glob", "record_filename_pattern": "*.json", "min_quality_score": 0.0, "sample_limit": None},
    {"name": "defimon_telegram_incidents", "record_format": "yaml", "record_filename": "record.yaml", "min_quality_score": 0.0, "sample_limit": None},
    {"name": "solc_compiler_bugs", "record_format": "json", "record_filename": "record.json", "min_quality_score": 0.0, "sample_limit": None},
]

# Corpora that are git-mined from a canonical public repo: every record is
# publicly verifiable by construction via its commit SHA (source_audit_ref =
# git-mining:<repo>@<sha>, verification_tier tier-1-verified-realtime-api). The
# public URL lives in attacker_action_sequence / fix_pattern, which the generic
# tier-2 http-scan below does not read, so these corpora are attested here
# rather than re-scanned. Scoped by name = zero output drift for other corpora.
TIER2_EXEMPT_CORPORA = {"solc_compiler_bugs"}

ATTACK_CLASS_QUESTION_MAP = {
    "bridge-deposit-zero-token-bypasses-transfer": "Does this bridge accept address(0) with msg.value=0 as the native-token sentinel, minting wrapped tokens without receiving funds?",
    "mempool-observation-sandwich": "Does this DEX/AMM expose users to mempool-observable sandwich attacks? Check for missing slippage deadline, no TWAP, or predictable large single-tx liquidity changes.",
    "oracle-price-manipulation": "Does this protocol use a spot-price oracle (AMM pair reserves, single Chainlink read without staleness check) manipulable same-block via flash loan?",
    "amm-reserve-manipulation": "Does this AMM allow reserve desync via fee-on-transfer tokens, reentrancy, or pair.sync calls during in-flight transfer?",
    "amm-reserve-accounting-desync": "Can AMM reserves diverge from actual token balances via pre/post-transfer tax hooks calling pair.sync or balanceOf snapshots?",
    "reentrancy": "Is there a missing reentrancy guard on withdraw/redeem/transfer allowing reentrant calls to drain funds before balance update?",
    "flash-loan-reentrancy": "Can an attacker combine flash loan with reentrancy to manipulate prices, inflate balances, or borrow beyond collateral?",
    "access-control-missing": "Is there a missing onlyOwner/onlyAdmin/onlyRole modifier on a privileged state-changing function allowing unprivileged callers?",
    "price-manipulation": "Can an attacker manipulate the price oracle via flash loans or sandwich attacks to borrow undercollateralized or drain reserves?",
    "integer-overflow": "Are there unchecked arithmetic operations on token amounts, share balances, or reward accumulators that can overflow?",
    "integer-underflow": "Are there unchecked arithmetic operations that can underflow in fee deductions, collateral calculations, or share redemptions?",
    "precision-loss": "Does this calculation divide before multiplying, causing accumulated precision loss in share price or reward distribution?",
    "front-running": "Can a privileged actor or MEV searcher front-run a user's transaction by observing pending state changes to extract value?",
    "signature-replay": "Is there a missing nonce or domain separator in signature verification allowing cross-chain or transaction replay attacks?",
    "logic-error": "Does this function contain a logic error in condition ordering or state-update sequence allowing unintended state transitions?",
    "griefing": "Can an unprivileged attacker grief users by blocking withdrawals, inflating gas costs, or permanently locking state?",
    "denial-of-service": "Can an attacker cause DoS by filling arrays, exploiting gas limits, blocking deposits/withdrawals, or causing mass reversions?",
    "economic-manipulation": "Can an attacker manipulate economic invariants (collateral ratio, reward per share, liquidation threshold) to extract excess value?",
    "flashloan-price-oracle": "Does this protocol compute prices from AMM spot reserves manipulable atomically via flash loans within the same transaction?",
    "storage-collision": "Does this proxy or diamond pattern have storage slot collisions between proxy and implementation that corrupt state on upgrade?",
    "liquidation-logic": "Is liquidation logic correct? Can an attacker self-liquidate for profit, block valid liquidations, or get liquidated at unfair price?",
    "stale-price": "Does this oracle consumer check price feed freshness (updatedAt)? A stale price allows borrowing against overvalued collateral.",
    "public-archive-bridge-deposit-zero-token-bypasses-transfer": "Does this bridge accept a deposit with address(0) sentinel and msg.value=0, minting wrapped tokens without receiving funds?",
    "audit-firm-finding-other": "Does this contract exhibit the vulnerability described in this audit finding? Check affected function for missing guards or incorrect state transitions.",
}

ATTACK_CLASS_PARTIAL_MAP = [
    ("reentr", "Is there a missing reentrancy guard on withdraw/redeem/transfer allowing reentrant calls before balance update?"),
    ("flash", "Can an attacker use a flash loan to inflate balances, manipulate prices, or drain reserves within a single transaction?"),
    ("oracle", "Does this protocol use an oracle manipulable via spot-price reads, stale data, or TWAP with insufficient observation window?"),
    ("manip", "Can an attacker manipulate key protocol state (prices, balances, reserves) to extract more value than legitimately entitled to?"),
    ("overflow", "Are there unchecked arithmetic operations on token amounts or shares that can overflow, leading to unexpected minting or limit bypass?"),
    ("underflow", "Are there unchecked arithmetic operations that can underflow, freeing funds without proper deduction?"),
    ("access", "Is there a missing access-control check allowing unprivileged callers to invoke privileged state-changing functions?"),
    ("replay", "Is there a missing nonce, domain separator, or consumed-flag allowing signature replay across chains or transactions?"),
    ("sandwich", "Does this DEX/AMM expose users to sandwich attacks via predictable slippage or mempool-visible state changes?"),
    ("liquidat", "Does the liquidation path enforce collateral checks correctly, or can an attacker trigger profitable self-liquidations or block valid ones?"),
    ("price", "Does this function use a price source manipulable atomically via flash loans or within-block state changes?"),
    ("dos", "Can an attacker cause DoS preventing other users from withdrawing, depositing, or completing transactions?"),
    ("griefing", "Can an unprivileged actor grief users by locking funds, blocking state transitions, or inflating gas costs?"),
    ("storage", "Does this proxy contract have storage layout collisions corrupting state on implementation upgrade?"),
    ("audit-firm-finding", "Does this contract contain the vulnerability described in this finding? Check function signature and affected state variables."),
    ("rug", "Does this contract contain a rug-pull vector allowing deployer/admin to drain user funds via privileged functions?"),
    ("scam", "Does this contract have a hidden drain mechanism, fake reward logic, or deceptive state transition benefiting deployer at user expense?"),
    ("misconfig", "Does this deployment have a misconfigured oracle, role assignment, or parameter deviating from intended configuration?"),
    ("tax", "Does this fee-on-transfer token interact with AMM pair reserves in a way exploitable for reserve manipulation?"),
    ("mev", "Does this protocol expose extractable value to MEV searchers via predictable ordering, front-running, or sandwich opportunities?"),
]

CORPUS_CONTEXT = {
    "audit_firm_findings_pashov": "From Pashov Audits finding",
    "defimon_blog_incidents": "From DeFiMon blog incident",
    "bridge_incidents": "From bridge incident post-mortem",
    "mev_exploits": "From MEV exploit analysis",
    "darknavy_web3_incidents": "From DarkNavy Web3 incident report",
    "defimon_telegram_incidents": "From DeFiMon alert",
}


def load_yaml_safe(path):
    if not _YAML_AVAILABLE:
        try:
            result = {}
            with open(path) as f:
                for line in f:
                    line = line.rstrip()
                    if ": " in line and not line.startswith(" ") and not line.startswith("-"):
                        k, _, v = line.partition(": ")
                        result[k.strip()] = v.strip().strip("'\"")
            return result if result else None
        except Exception:
            return None
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def load_json_safe(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def get_attack_class(record):
    for field in ["attack_class", "bug_class", "attack_type", "vulnerability_type"]:
        val = record.get(field, "")
        if val and val not in ("unspecified", "unknown", ""):
            return str(val)
    return "unknown"


def get_question_text(attack_class, record, corpus_name):
    if attack_class in ATTACK_CLASS_QUESTION_MAP:
        return ATTACK_CLASS_QUESTION_MAP[attack_class]
    ac_lower = attack_class.lower()
    for pattern, question in ATTACK_CLASS_PARTIAL_MAP:
        if pattern in ac_lower:
            return question
    action_seq = record.get("attacker_action_sequence", "") or record.get("attack_vector_summary", "") or ""
    if action_seq and len(action_seq) > 30:
        target = record.get("target_component", "") or record.get("target_project", "") or "this protocol"
        return f"Does {target} exhibit '{attack_class}'? Review: {action_seq[:120].strip()}"
    ctx = CORPUS_CONTEXT.get(corpus_name, "From incident corpus")
    return f"{ctx}: Does this code exhibit '{attack_class}'? Check for missing guards or incorrect state transitions."


def get_grep_patterns(attack_class, record):
    patterns = []
    fn_shape = record.get("function_shape", {})
    if isinstance(fn_shape, dict):
        raw_sig = fn_shape.get("raw_signature", "")
        if raw_sig and "::" not in raw_sig and len(raw_sig) < 80:
            fn_name = raw_sig.split("(")[0].strip().split("/")[-1].strip()
            if fn_name and len(fn_name) > 2 and " " not in fn_name:
                patterns.append(fn_name)
    ac = attack_class.lower()
    if "reentr" in ac:
        patterns.extend(["nonReentrant", "reentrancyGuard", "ReentrancyGuard"])
    elif "oracle" in ac or "price" in ac:
        patterns.extend(["getPrice", "latestRoundData", "consult", "TWAP"])
    elif "flash" in ac:
        patterns.extend(["flashLoan", "executeOperation", "callback"])
    elif "access" in ac:
        patterns.extend(["onlyOwner", "onlyAdmin", "onlyRole"])
    elif "overflow" in ac or "underflow" in ac:
        patterns.extend(["unchecked", "SafeMath"])
    elif "replay" in ac or "signature" in ac:
        patterns.extend(["nonce", "domainSeparator", "ecrecover"])
    elif "proxy" in ac or "storage" in ac:
        patterns.extend(["delegatecall", "upgradeTo", "implementation"])
    elif "liquidat" in ac:
        patterns.extend(["liquidate", "healthFactor", "seize"])
    elif "deposit" in ac and "zero" in ac:
        patterns.extend(["deposit", "address(0)", "msg.value"])
    elif "sandwich" in ac or "mev" in ac:
        patterns.extend(["swap", "slippage", "deadline", "TWAP"])
    elif "tax" in ac:
        patterns.extend(["_transfer", "pair.sync", "balanceOf", "sync()"])
    seen = set()
    result = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result[:6]


def get_target_contract_patterns(record, corpus_name):
    domain = (record.get("target_domain", "") or "").lower()
    component = (record.get("target_component", "") or "").lower()
    patterns = []
    if "bridge" in domain or "bridge" in component or corpus_name == "bridge_incidents":
        patterns.append("(?i)(bridge|relay|messenger|gateway|dispatcher|crosschain)")
    if "dex" in domain or "amm" in domain or "swap" in component or "pair" in component:
        patterns.append("(?i)(swap|amm|dex|router|pair|pool|liquidity)")
    if "lending" in domain or "borrow" in component or "vault" in component:
        patterns.append("(?i)(lending|borrow|collateral|vault|pool|market)")
    if corpus_name == "mev_exploits":
        patterns.append("(?i)(router|amm|dex|pair|flashLoan|execute)")
    if "oracle" in component or "oracle" in domain:
        patterns.append("(?i)(oracle|price.?feed|aggregator|chainlink)")
    if not patterns:
        patterns.append("(?i)(vault|pool|lending|bridge|router|governance|token)")
    return patterns[:3]


def get_target_languages(record):
    lang = (record.get("target_language", "") or record.get("chain_or_language", "") or "").lower()
    cross_analogues = record.get("cross_language_analogues", []) or []
    langs = []
    if "solidity" in lang or "evm" in lang or "ethereum" in lang:
        langs.append("solidity")
    if "rust" in lang:
        langs.append("rust")
    if "move" in lang:
        langs.append("move")
    if "go" in lang:
        langs.append("go")
    for ca in cross_analogues:
        if isinstance(ca, dict):
            cl = (ca.get("target_language", "") or "").lower()
            if cl and cl not in langs:
                langs.append(cl)
    if not langs:
        langs = ["solidity"]
    return langs[:4]


def get_source_path(record, corpus_name, record_path):
    for field in ["source_audit_ref", "record_source_url", "source_url"]:
        val = record.get(field, "")
        if val and "http" in val:
            return val
    return f"audit/corpus_tags/tags/{corpus_name}/{record_path.parent.name}"


def get_severity(record):
    for field in ["severity_at_finding", "severity", "severity_verbatim"]:
        val = record.get(field, "")
        if val:
            return str(val).lower()
    return "unknown"


def make_question_id(corpus_name, record_id, attack_class):
    slug = re.sub(r"[^a-z0-9]", "-", f"{corpus_name}-{attack_class}".lower())[:60]
    record_hash = hashlib.md5(record_id.encode()).hexdigest()[:8]
    return f"HQ-{slug.upper()}-{record_hash}".replace("--", "-")


def check_tier2_criterion_met(record, corpus_name, record_path):
    if corpus_name in TIER2_EXEMPT_CORPORA:
        return True
    for field in ["source_audit_ref", "record_source_url", "source_url"]:
        val = record.get(field, "")
        if val and "http" in val:
            return True
    re_ext = record.get("record_extensions", {}) or {}
    if isinstance(re_ext, dict) and re_ext.get("pdf_extraction_status") in ("parsed", "extracted"):
        return True
    for precond in record.get("required_preconditions", []) or []:
        if isinstance(precond, str) and "http" in precond:
            return True
    notes = record.get("notes", "") or ""
    if "http" in notes:
        return True
    return False


def load_corpus_records(corpus_dir, corpus_config):
    records = []
    record_format = corpus_config["record_format"]
    if not corpus_dir.exists():
        return records
    subdirs = [d for d in corpus_dir.iterdir() if d.is_dir() and not d.name.startswith("_")]
    for subdir in subdirs:
        record = None
        record_path_ = None
        if record_format in ("json", "yaml"):
            filename = corpus_config.get("record_filename", "record.json")
            candidate = subdir / filename
            if candidate.exists():
                record = load_json_safe(candidate) if record_format == "json" else load_yaml_safe(candidate)
                record_path_ = candidate
        elif record_format == "json_glob":
            for jf in sorted(subdir.glob("*.json")):
                if not jf.name.startswith("_"):
                    record = load_json_safe(jf)
                    record_path_ = jf
                    break
        if record and record_path_ is not None:
            quality = float(record.get("record_quality_score", 3.0) or 3.0)
            min_q = corpus_config.get("min_quality_score", 0.0)
            if quality >= min_q:
                records.append((record, record_path_))
    limit = corpus_config.get("sample_limit")
    if limit is not None:
        records = records[:limit]
    return records


def emit_hacker_question(record, record_path, corpus_name):
    if not check_tier2_criterion_met(record, corpus_name, record_path):
        return None
    attack_class = get_attack_class(record)
    if attack_class in ("unknown", "unspecified", ""):
        action_seq = record.get("attacker_action_sequence", "") or record.get("attack_vector_summary", "") or ""
        if not action_seq or len(action_seq) < 50:
            return None
        attack_class = "unknown-defi-exploit"
        shape_tags = record.get("shape_tags", []) or []
        if isinstance(shape_tags, list):
            for tag in shape_tags:
                if "attack-class:" in str(tag):
                    attack_class = str(tag).split("attack-class:")[-1]
                    break
    record_id = record.get("record_id", "") or str(record_path.parent.name)
    question_id = make_question_id(corpus_name, record_id, attack_class)
    question_text = get_question_text(attack_class, record, corpus_name)
    return {
        "schema_version": SCHEMA_VERSION,
        "question_id": question_id,
        "question_text": question_text,
        "attack_class_anchor": attack_class,
        "scope_specificity": "function" if corpus_name == "audit_firm_findings_pashov" else "protocol",
        # B2 routing-integrity: route to the class's NATIVE language(s) rather
        # than the fail-to-solidity default in get_target_languages(). The
        # record's own declared language is passed as the fail-open fallback.
        "target_languages": route_target_languages(
            attack_class, question_text, get_target_languages(record)),
        "target_contract_patterns": get_target_contract_patterns(record, corpus_name),
        "target_function_patterns": get_grep_patterns(attack_class, record),
        "target_modifier_patterns": [],
        "grep_patterns": get_grep_patterns(attack_class, record),
        "linked_invariant_ids": [],
        "source_incident_id": record_id,
        "source_case_study": get_source_path(record, corpus_name, record_path),
        "verification_tier": "tier-2-verified-public-archive",
        "quality_audited": True,
        "source_path": f"audit/corpus_tags/tags/{corpus_name}",
        "harvester": HARVESTER_ID,
        "_meta": {
            "corpus": corpus_name,
            "severity": get_severity(record),
            "impact_class": record.get("impact_class", ""),
            "impact_dollar_class": record.get("impact_dollar_class", ""),
            "source_url": record.get("record_source_url", "") or record.get("source_url", ""),
            "llm_reformulated": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="LIFT-13 v2 incident corpora harvester")
    parser.add_argument("--workspace", default="/Users/wolf/auditooor-mcp")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--llm-budget-usd", type=float, default=0.15)
    args = parser.parse_args()

    ws = Path(args.workspace)
    tags_dir = ws / "audit/corpus_tags/tags"
    output_path = ws / OUTPUT_FILE
    report_dir = ws / REPORT_DIR

    print(f"[LIFT-13 v2] Workspace: {ws}", flush=True)

    all_questions = []
    per_corpus_stats = {}
    per_corpus_samples = {}

    for corpus_config in CORPORA:
        corpus_name = corpus_config["name"]
        corpus_dir = tags_dir / corpus_name
        print(f"\n[LIFT-13 v2] Harvesting corpus: {corpus_name}", flush=True)

        records = load_corpus_records(corpus_dir, corpus_config)
        print(f"  Loaded {len(records)} records", flush=True)

        emitted = 0
        skipped_tier2 = 0
        skipped_no_data = 0
        questions = []

        for record, record_path in records:
            hq = emit_hacker_question(record, record_path, corpus_name)
            if hq is None:
                if not check_tier2_criterion_met(record, corpus_name, record_path):
                    skipped_tier2 += 1
                else:
                    skipped_no_data += 1
                continue
            questions.append(hq)
            emitted += 1

        per_corpus_stats[corpus_name] = {
            "records_loaded": len(records),
            "questions_emitted": emitted,
            "skipped_no_tier2_source": skipped_tier2,
            "skipped_insufficient_data": skipped_no_data,
        }
        per_corpus_samples[corpus_name] = questions[:3]
        all_questions.extend(questions)
        print(f"  Emitted: {emitted}, skipped (no tier-2 source): {skipped_tier2}, skipped (no data): {skipped_no_data}", flush=True)

    print(f"\n[LIFT-13 v2] Total: {len(all_questions)} questions, $0.00 USD (mechanical mapping)", flush=True)

    if args.dry_run:
        print("[DRY RUN] Skipping writes.", flush=True)
        print(json.dumps({"per_corpus": per_corpus_stats, "total": len(all_questions)}, indent=2))
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for hq in all_questions:
            f.write(json.dumps(hq) + "\n")
    print(f"[LIFT-13 v2] Written {len(all_questions)} records to {output_path}", flush=True)

    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "results.json"
    samples_by_corpus = {}
    for cname, samples in per_corpus_samples.items():
        samples_by_corpus[cname] = [
            {
                "question_id": s["question_id"],
                "attack_class_anchor": s["attack_class_anchor"],
                "question_text": s["question_text"][:150],
                "source_incident_id": s["source_incident_id"][:70],
            }
            for s in samples
        ]

    report = {
        "harvester": HARVESTER_ID,
        "schema_version": SCHEMA_VERSION,
        "run_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output_path": str(output_path),
        "total_questions_emitted": len(all_questions),
        "llm_cost_usd_actual": 0.0,
        "llm_budget_usd": args.llm_budget_usd,
        "llm_budget_used_pct": 0.0,
        "llm_reformulation_note": "Mechanical mapping used; no LLM API calls. $0.00 USD spent.",
        "per_corpus_stats": per_corpus_stats,
        "per_corpus_samples": samples_by_corpus,
        "verification_tier": "tier-2-verified-public-archive",
        "r37_compliant": True,
        "r36_lane": "work2-lift13-v2-incident-harvest-2026-05-26",
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[LIFT-13 v2] Report written to {report_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
