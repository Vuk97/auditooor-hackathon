#!/usr/bin/env python3
"""Backfill attack_class labels for audit-firm public-report index records.

The ``audit_firm_public_reports/`` subtree contains one record per public
report URL. Those records are valuable for source recall, but most carry the
opaque ``attack_class: audit-firm-public-report`` label because the PDF body was
not parsed at listing time. This tool performs a conservative regex-tier pass
over report metadata and ``attacker_action_sequence`` text to emit candidate
class replacements.

Default mode is review-only. ``--apply`` mutates ``record.yaml`` and the JSON
sibling, if present, and writes a rollback ledger. The classification is
metadata-level only; it makes a report ranker-indexable but does not promote it
to a per-finding proof record.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, NamedTuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
DEFAULT_CANDIDATES_PATH = REPO_ROOT / ".auditooor" / "audit-firm-report-class-candidates.jsonl"
DEFAULT_ROLLBACK_PATH = REPO_ROOT / ".auditooor" / "audit-firm-report-class-rollback.jsonl"
SCHEMA = "auditooor.hackerman_audit_firm_report_class_backfill.v1"
OPAQUE_CLASS = "audit-firm-public-report"


class Rule(NamedTuple):
    attack_class: str
    exact_phrases: tuple[str, ...]
    indicators: tuple[str, ...]
    veto_phrases: tuple[str, ...] = ()
    min_hits: int = 2
    base_confidence: float = 0.62


RULES: tuple[Rule, ...] = (
    # Bridge / cross-chain:
    # Strong exact_phrases include well-known protocol names (wormhole, layerzero,
    # ccip, etc.) so a single name-match in metadata is enough for classification.
    Rule(
        "bridge-proof-domain-bypass",
        (
            "bridge proof",
            "cross-chain message",
            "cross chain message",
            "wormhole executor",
            "layerzero dvn",
            "omnichain fungible token",
            "token bridge",
            "teleporter",
            # single-term strong signals: protocol names unique to bridge domain
            "wormhole",
            "layerzero",
            "axelar",
            "debridge",
            "stargate",
            "interchain",
        ),
        (
            "bridge",
            "cross-chain",
            "cross chain",
            "wormhole",
            "layerzero",
            "omnichain",
            "teleporter",
            "gateway",
            "vaa",
            "executor",
            "message",
            "domain",
            "source chain",
            "destination chain",
        ),
        # Veto: front-end only or off-chain bridge UIs are not on-chain bridge bugs
        veto_phrases=("front end", "frontend", "web ui"),
        min_hits=2,
        base_confidence=0.68,
    ),
    Rule(
        "reentrancy-external-call",
        (
            "reentrancy",
            "reentrant",
            "callback reentrancy",
            "external call before state update",
        ),
        (
            "reentrancy",
            "reentrant",
            "callback",
            "external call",
            "hook",
            "uniswap hook",
            "before state update",
        ),
        min_hits=2,
        base_confidence=0.66,
    ),
    Rule(
        "signature-replay",
        (
            "signature replay",
            "replay signature",
            "permit replay",
            "eip-712 replay",
            "signed message replay",
        ),
        (
            "signature",
            "signed message",
            "eip-712",
            "permit",
            "nonce",
            "replay",
            "domain separator",
            "paymaster",
            "delegation",
        ),
        min_hits=2,
        base_confidence=0.66,
    ),
    Rule(
        "missing-modifier-on-state-write",
        (
            "missing access control",
            "access control",
            "unauthorized",
            "privilege escalation",
            "missing onlyowner",
            "missing role check",
        ),
        (
            "access control",
            "unauthorized",
            "permissionless",
            "permission",
            "privilege",
            "onlyowner",
            "role",
            "admin",
            "owner",
            "setter",
        ),
        min_hits=3,
        base_confidence=0.60,
    ),
    Rule(
        "stale-or-manipulated-oracle",
        (
            "oracle manipulation",
            "stale oracle",
            "stale price",
            "price feed",
            "twap manipulation",
            # single-term strong signals: oracle-specific protocol names
            "chainlink",
            "pyth network",
            "pyth oracle",
            "redstone",
        ),
        (
            "oracle",
            "price feed",
            "chainlink",
            "pyth",
            "twap",
            "stale price",
            "pricing",
            "exchange rate",
        ),
        min_hits=2,
        base_confidence=0.66,
    ),
    Rule(
        "fund-loss-via-arithmetic",
        (
            "integer overflow",
            "integer underflow",
            "arithmetic overflow",
            "precision loss",
            "rounding error",
        ),
        (
            "overflow",
            "underflow",
            "precision",
            "rounding",
            "truncation",
            "decimal",
            "muldiv",
            "math",
            "exp",
        ),
        min_hits=2,
        base_confidence=0.64,
    ),
    # ERC-4626 vault share accounting:
    # "erc4626" alone is a strong exact signal - the entire report is about that standard.
    Rule(
        "share-accounting",
        (
            "erc4626",
            "erc-4626",
            "share inflation",
            "first deposit",
            "donation attack",
            "share price",
        ),
        (
            "erc4626",
            "erc-4626",
            "share",
            "shares",
            "share price",
            "donation",
            "first deposit",
            "totalsupply",
            "redeem",
        ),
        min_hits=2,
        base_confidence=0.64,
    ),
    # Staking / reward distribution:
    # "staking" alone in a report title signals a staking contract audit.
    Rule(
        "staking-reward-theft",
        (
            "staking reward",
            "reward theft",
            "drain rewards",
            "reward distribution",
            # single-term strong signal for staking-specific reports
            "staking",
        ),
        (
            "staking",
            "reward",
            "rewards",
            "emission",
            "harvest",
            "staker",
            "validator reward",
        ),
        min_hits=2,
        base_confidence=0.64,
    ),
    Rule(
        "protocol-fee-theft",
        (
            "fee theft",
            "fee wrapper",
            "fee flow",
            "fee collector",
            "management fee",
            "performance fee",
        ),
        (
            "fee",
            "fees",
            "collector",
            "treasury",
            "wrapper",
            "performance",
            "management",
        ),
        min_hits=2,
        base_confidence=0.62,
    ),
    # Lending / liquidation:
    # Protocol names (aave, compound, morpho, euler) are strong single signals.
    Rule(
        "liquidation-mispricing",
        (
            "liquidation mispricing",
            "bad debt",
            "health factor",
            "ltv",
            # single-term strong signals: well-known lending protocol names
            "aave",
            "compound",
            "morpho",
            "euler",
            "silo",
            "benqi",
            "venus",
            "radiant",
        ),
        (
            "liquidation",
            "liquidate",
            "collateral",
            "health factor",
            "ltv",
            "margin",
            "bad debt",
        ),
        # Veto: governance reviews of lending protocols or oracle modules are not
        # liquidation bugs - they concern voting / price feeds respectively
        veto_phrases=("governance", "oracle"),
        min_hits=2,
        base_confidence=0.64,
    ),
    # Governance / DAO voting:
    # "governance" or "dao" alone in a report title is a strong signal.
    Rule(
        "governance-vote-manipulation",
        (
            "governance voting",
            "voting power",
            "vote manipulation",
            "snapshot manipulation",
            # single-term strong signals
            "governance",
            "dao",
        ),
        (
            "governance",
            "voting",
            "vote",
            "delegate",
            "proposal",
            "snapshot",
            "governor",
        ),
        min_hits=2,
        base_confidence=0.62,
    ),
    Rule(
        "fund-lock",
        (
            "funds stuck",
            "stuck funds",
            "unable to withdraw",
            "withdrawal queue",
            "permanent freeze",
        ),
        (
            "withdrawal",
            "withdraw",
            "queue",
            "stuck",
            "locked",
            "freeze",
            "frozen",
            "claim",
        ),
        min_hits=2,
        base_confidence=0.62,
    ),
    # AMM / DEX price manipulation:
    # Well-known DEX protocol names are strong single signals.
    Rule(
        "amm-price-manipulation",
        (
            "amm price manipulation",
            "pool price manipulation",
            "sandwich attack",
            "front running",
            "frontrun",
            # single-term strong signals: DEX protocol names
            "uniswap",
            "curve",
            "balancer",
            "velodrome",
            "aerodrome",
            "camelot",
            "ramses",
            "solidly",
            "solidlyv3",
        ),
        (
            "amm",
            "dex",
            "pool",
            "swap",
            "liquidity",
            "price impact",
            "slippage",
        ),
        # Veto: oracle-only reports, wallet/UX reviews, and validator-only
        # reviews about these protocols are not AMM price-manipulation bugs
        veto_phrases=("oracle", "price feed", "chainlink", "wallet", "validator"),
        min_hits=2,
        base_confidence=0.62,
    ),
)


def _normalise(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[_/.:#]+", " ", text)
    text = re.sub(r"[-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _contains_phrase(normalized_text: str, phrase: str) -> bool:
    normalized_phrase = _normalise(phrase)
    if not normalized_phrase:
        return False
    pattern = r"(?<![a-z0-9])" + re.escape(normalized_phrase).replace(r"\ ", r"\s+") + r"(?![a-z0-9])"
    return re.search(pattern, normalized_text) is not None


def _flatten(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (int, float, bool)):
        yield str(value)
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from _flatten(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            yield from _flatten(child)


def scannable_text(record: dict[str, Any], *, record_path: Path | None = None) -> str:
    """Build a scannable text corpus from all metadata fields.

    Includes the record file's parent directory name (the slug) as an
    additional field because it contains the project name in a clean,
    hyphen-delimited form that is often more keyword-dense than the
    attacker_action_sequence boilerplate.
    """
    fields = [
        record.get("record_id"),
        record.get("source_audit_ref"),
        record.get("target_component"),
        record.get("function_shape", {}).get("raw_signature"),
        record.get("function_shape", {}).get("shape_tags"),
        record.get("attacker_action_sequence"),
        record.get("required_preconditions"),
        record.get("fix_pattern"),
        record.get("record_source_url"),
    ]
    parts = [part for field in fields for part in _flatten(field) if part]
    # Also include the directory slug (parent folder name) as a bonus field.
    # The slug carries the project name in a hyphen-delimited form that is not
    # duplicated verbatim in the other fields.
    if record_path is not None:
        parts.append(record_path.parent.name)
    return "\n".join(parts)


def classify_text(text: str, *, min_confidence: float = 0.65) -> dict[str, Any] | None:
    low = _normalise(text)
    best: dict[str, Any] | None = None
    for order, rule in enumerate(RULES):
        veto_hits = [phrase for phrase in rule.veto_phrases if _contains_phrase(low, phrase)]
        if veto_hits:
            continue
        exact_hits = [phrase for phrase in rule.exact_phrases if _contains_phrase(low, phrase)]
        indicator_hits = [phrase for phrase in rule.indicators if _contains_phrase(low, phrase)]
        if exact_hits:
            confidence = min(0.95, rule.base_confidence + 0.18 + 0.02 * len(indicator_hits))
            match_type = "exact"
            matched_terms = sorted(set(exact_hits + indicator_hits))
        elif len(set(indicator_hits)) >= rule.min_hits:
            confidence = min(0.90, rule.base_confidence + 0.04 * len(set(indicator_hits)))
            match_type = "indicator"
            matched_terms = sorted(set(indicator_hits))
        else:
            continue
        if confidence < min_confidence:
            continue
        candidate = {
            "new_attack_class": rule.attack_class,
            "confidence": round(confidence, 3),
            "match_type": match_type,
            "matched_terms": matched_terms,
            "rule_order": order,
        }
        if best is None:
            best = candidate
            continue
        if (candidate["confidence"], -candidate["rule_order"]) > (
            best["confidence"],
            -best["rule_order"],
        ):
            best = candidate
    return best


def iter_record_paths(tag_dir: Path) -> Iterable[Path]:
    yield from sorted(tag_dir.rglob("record.yaml"))


def load_yaml(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected mapping")
    return doc


def candidate_for_path(path: Path, tag_dir: Path, *, min_confidence: float) -> dict[str, Any] | None:
    record = load_yaml(path)
    old_class = str(record.get("attack_class") or "")
    if old_class != OPAQUE_CLASS:
        return None
    if record.get("bug_class") != "audit-firm-public-report-index":
        return None
    match = classify_text(scannable_text(record, record_path=path), min_confidence=min_confidence)
    if not match:
        return None
    rel = path.relative_to(REPO_ROOT).as_posix() if path.is_relative_to(REPO_ROOT) else path.as_posix()
    sibling_json = path.with_name("record.json")
    row = {
        "schema": SCHEMA,
        "record_id": record.get("record_id"),
        "tag_file": rel,
        "json_file": (
            sibling_json.relative_to(REPO_ROOT).as_posix()
            if sibling_json.exists() and sibling_json.is_relative_to(REPO_ROOT)
            else None
        ),
        "old_attack_class": old_class,
        "new_attack_class": match["new_attack_class"],
        "confidence": match["confidence"],
        "match_type": match["match_type"],
        "matched_terms": match["matched_terms"],
        "classification_scope": "report-title-and-metadata-only",
    }
    return row


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _replace_yaml_attack_class(text: str, old: str, new: str) -> str:
    pattern = re.compile(rf"^(attack_class:\s*){re.escape(old)}\s*$", re.MULTILINE)
    replaced, count = pattern.subn(rf"\g<1>{new}", text, count=1)
    if count != 1:
        raise ValueError("expected exactly one attack_class line to replace")
    return replaced


def apply_candidate(row: dict[str, Any], *, rollback_fh: Any) -> None:
    yaml_path = REPO_ROOT / str(row["tag_file"])
    old_class = str(row["old_attack_class"])
    new_class = str(row["new_attack_class"])
    doc = load_yaml(yaml_path)
    if doc.get("attack_class") != old_class:
        raise ValueError(f"{yaml_path}: expected attack_class {old_class!r}")
    doc["attack_class"] = new_class
    extensions = doc.setdefault("record_extensions", {})
    if not isinstance(extensions, dict):
        raise ValueError(f"{yaml_path}: record_extensions must be a mapping")
    extensions["heuristic_attack_class_backfill"] = {
        "tool": "hackerman-backfill-audit-firm-report-class.py",
        "old_attack_class": old_class,
        "new_attack_class": new_class,
        "confidence": row.get("confidence"),
        "match_type": row.get("match_type"),
        "matched_terms": row.get("matched_terms") or [],
        "classification_scope": row.get("classification_scope"),
    }
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    json_file = row.get("json_file")
    if json_file:
        json_path = REPO_ROOT / str(json_file)
        if json_path.exists():
            doc = json.loads(json_path.read_text(encoding="utf-8"))
            if doc.get("attack_class") == old_class:
                doc["attack_class"] = new_class
                extensions = doc.setdefault("record_extensions", {})
                if isinstance(extensions, dict):
                    extensions["heuristic_attack_class_backfill"] = {
                        "tool": "hackerman-backfill-audit-firm-report-class.py",
                        "old_attack_class": old_class,
                        "new_attack_class": new_class,
                        "confidence": row.get("confidence"),
                        "match_type": row.get("match_type"),
                        "matched_terms": row.get("matched_terms") or [],
                        "classification_scope": row.get("classification_scope"),
                    }
                json_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rollback = {
        "schema": f"{SCHEMA}.rollback",
        "record_id": row["record_id"],
        "tag_file": row["tag_file"],
        "json_file": row.get("json_file"),
        "old_attack_class": old_class,
        "new_attack_class": new_class,
    }
    rollback_fh.write(json.dumps(rollback, sort_keys=True) + "\n")


def run(
    tag_dir: Path,
    candidates_path: Path,
    *,
    min_confidence: float = 0.65,
    apply: bool = False,
    rollback_path: Path = DEFAULT_ROLLBACK_PATH,
) -> dict[str, Any]:
    if not tag_dir.is_dir():
        raise FileNotFoundError(f"tag dir not found: {tag_dir}")
    rows: list[dict[str, Any]] = []
    scanned = 0
    dark = 0
    for path in iter_record_paths(tag_dir):
        scanned += 1
        try:
            doc = load_yaml(path)
        except Exception:
            continue
        if doc.get("attack_class") == OPAQUE_CLASS:
            dark += 1
        row = candidate_for_path(path, tag_dir, min_confidence=min_confidence)
        if row:
            rows.append(row)

    write_jsonl(candidates_path, rows)
    applied = 0
    if apply:
        rollback_path.parent.mkdir(parents=True, exist_ok=True)
        with rollback_path.open("a", encoding="utf-8") as rollback_fh:
            for row in rows:
                apply_candidate(row, rollback_fh=rollback_fh)
                applied += 1

    by_class: dict[str, int] = {}
    for row in rows:
        cls = str(row["new_attack_class"])
        by_class[cls] = by_class.get(cls, 0) + 1
    return {
        "schema": SCHEMA,
        "tag_dir": tag_dir.as_posix(),
        "scanned_records": scanned,
        "opaque_records": dark,
        "candidate_count": len(rows),
        "applied_writes": applied,
        "min_confidence": min_confidence,
        "by_new_attack_class": dict(sorted(by_class.items())),
        "candidates_path": candidates_path.as_posix(),
        "rollback_path": rollback_path.as_posix() if apply else None,
        "classification_scope": "report-title-and-metadata-only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--out", default=str(DEFAULT_CANDIDATES_PATH))
    parser.add_argument("--rollback-out", default=str(DEFAULT_ROLLBACK_PATH))
    parser.add_argument("--min-confidence", type=float, default=0.65)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    try:
        summary = run(
            Path(args.tag_dir),
            Path(args.out),
            min_confidence=args.min_confidence,
            apply=args.apply,
            rollback_path=Path(args.rollback_out),
        )
    except Exception as exc:
        print(f"hackerman-backfill-audit-firm-report-class: {exc}", file=sys.stderr)
        return 1

    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            "audit-firm-report-class-backfill: "
            f"scanned={summary['scanned_records']} "
            f"opaque={summary['opaque_records']} "
            f"candidates={summary['candidate_count']} "
            f"applied={summary['applied_writes']} "
            f"out={summary['candidates_path']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
