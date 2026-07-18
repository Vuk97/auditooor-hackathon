#!/usr/bin/env python3
"""Re-classify EVM/EVM-adjacent catch-all hackerman records into fine-grained attack classes.

The hackerman corpus tags currently dump roughly 12k records into two coarse
catch-all attack classes:

  - ``protocol-invariant-bypass``  (~8.5k records)
  - ``state-accounting-drift``     (~3.4k records)

This buries domain-specific exploit shapes (reward theft, fee-rounding
asymmetry, vault share rounding, vesting bypass, slippage bypass, liquidation
mispricing, funding-rate theft, etc.). ``vault_attack_class_evidence`` returns
0 hits for those finer queries because the precedent is hidden under the
catch-alls.

This tool emits a *candidate* JSONL diff at::

  .auditooor/reclassify-catchall-candidates.jsonl

Each candidate row carries the record_id, tag_file, old attack class, the
fine-grained class proposed, the indicator hits that justify the
reclassification, and confidence score. Reviewers can spot-check before any
``--apply`` flips ``attack_class:`` (and preserves the original under
``attack_class_original:``) in the source YAML.

Routing rules
-------------
A record is reclassified to a fine-grained class iff its scannable text
contains EITHER:
  - an explicit exact-phrase ("first-deposit share inflation", "reward
    accrual race", "fee-on-transfer rounding"), OR
  - >=2 distinct *indicator* hits from the class' indicator set, AND
  - no veto-phrase fires (e.g. "fee-on-transfer" wins over "fee-rounding"
    when both classes match on the same record).

Scanned fields: ``target_component``, ``function_shape.raw_signature``,
``function_shape.name``, ``function_shape.shape_tags`` (joined),
``bug_summary``, ``attacker_action_sequence``, ``required_preconditions``
(joined), ``recommendation``, ``fix_pattern``, ``source_audit_ref``,
``record_id`` (the record id often encodes the canonical DSL pattern slug
for synthesized records).

Hard rules
----------
* Does NOT modify ``audit/corpus_tags/tags/*.yaml`` unless ``--apply`` is
  passed.
* Does NOT touch the by-axis indices. After ``--apply``, the operator must
  run ``tools/hackerman-index-build.py`` (the canonical rebuilder) to
  refresh ``audit/corpus_tags/index/*.jsonl``.
* Preserves the original class under a sibling ``attack_class_original:``
  line so that any reclassification is rollback-friendly.
* The catch-all pool is restricted to the two declared catch-alls.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_CANDIDATES_PATH = REPO_ROOT / ".auditooor" / "reclassify-catchall-candidates.jsonl"
DEFAULT_ROLLBACK_PATH = REPO_ROOT / ".auditooor" / "reclassify-catchall-rollback.jsonl"

CATCHALL_CLASSES = ("protocol-invariant-bypass", "state-accounting-drift", "unknown-attack")
SCHEMA_VERSION = "auditooor.hackerman_reclassify_catchall.v1"


# ---------------------------------------------------------------------------
# Fine-grained class taxonomy
#
# Each entry: (target_class, exact_phrases, indicators, veto_phrases)
#
# - exact_phrases: presence of any one yields immediate match (confidence 1.0).
# - indicators: need >=2 distinct hits to match (confidence scales with hits).
# - veto_phrases: if present, the rule is suppressed. Used to dodge false
#   positives where a coarser keyword (e.g. "fee") would route a record to
#   the wrong class.
#
# Order matters: rules earlier in the list take precedence over later rules
# when multiple rules tie on a record. The list is hand-ordered so that
# narrower / higher-signal classes come first.
# ---------------------------------------------------------------------------
RECLASSIFY_RULES: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]], ...] = (
    # ---- Reward / staking / LP reward theft family ----
    (
        "lp-reward-double-claim",
        (
            "lp reward double claim",
            "double-claim reward",
            "double claim reward",
            "double-claim lp",
            "claim rewards twice",
            "claim reward twice",
            "reward claim replay",
            "duplicate reward claim",
        ),
        (
            "lp reward",
            "liquidity reward",
            "double claim",
            "double-claim",
            "claim reward",
            "claim rewards",
            "user.lastclaim",
            "lastclaimtime",
            "claimed = false",
        ),
        (
            "fee-on-transfer",
            "snapshot id",
        ),
    ),
    (
        "staking-reward-theft",
        (
            "staking reward theft",
            "stealing rewards",
            "steal rewards",
            "stealing-rewards",
            "stealing-reward",
            "reward accrual race",
            "front-run reward",
            "front run reward",
            "reward deposit-withdraw sandwich",
            "rewardperblock",
            "accrewardpershare",
            "lastrewardtime mismatch",
            "lastrewardblock mismatch",
        ),
        (
            "staking reward",
            "stake reward",
            "reward per share",
            "rewardpershare",
            "rewardpertoken",
            "accrewardpershare",
            "lastrewardtime",
            "lastrewardblock",
            "pending reward",
            "harvest",
            "reward rate",
            "earn reward",
            "earn rewards",
            "stake",
            "staker",
        ),
        (
            "lp reward double",
            "rebase",
        ),
    ),
    (
        "reward-theft",
        (
            "reward theft",
            "steal reward",
            "steal rewards",
            "stealing rewards",
            "stealing-rewards",
            "drain reward",
            "drain rewards",
            "drain reward pool",
            "manipulate reward",
            "reward manipulation",
            "reward distribution attack",
            "reward attack",
        ),
        (
            "reward",
            "rewards",
            "yield",
            "incentive",
            "reward pool",
            "reward token",
            "reward share",
            "rewarddebt",
            "userinfo.amount",
            "pendingreward",
        ),
        (
            "fee-on-transfer",
            "twap oracle",
        ),
    ),
    # ---- Fee / rounding family ----
    (
        "fee-rounding-asymmetry",
        (
            "fee rounding asymmetry",
            "fee-rounding asymmetry",
            "asymmetric fee rounding",
            "fee rounding favor",
            "fee rounds in favor",
            "fee rounds favorable",
            "round in favor of attacker",
            "rounds in user's favor",
            "rounds in users favor",
            "rounding direction mismatch",
        ),
        (
            "fee",
            "rounding",
            "round down",
            "round up",
            "truncation",
            "ceil",
            "floor",
            "mulwad",
            "muldiv",
            "rounding direction",
            "favor",
            "asymmetric",
            "asymmetry",
        ),
        (
            "fee-on-transfer",
            "share inflation",
        ),
    ),
    (
        "fee-on-transfer-accounting-drift",
        (
            "fee on transfer",
            "fee-on-transfer",
            "fee-on-transfer token",
            "fee on transfer token",
            "deflationary token",
            "rebasing token transfer",
            "tax token mismatch",
            "transfer fee mismatch",
            "tax-token accounting",
            "received != amount",
            "balanceof(this) before",
        ),
        (
            "fee on transfer",
            "fee-on-transfer",
            "deflationary",
            "tax token",
            "fee-bearing",
            "transfer tax",
            "balance delta",
            "balanceof delta",
        ),
        (),
    ),
    (
        "protocol-fee-theft",
        (
            "skim protocol fee",
            "steal protocol fee",
            "drain protocol fee",
            "protocol fee theft",
            "treasury fee theft",
            "manipulate distribution avoid dao fee",
            "avoid dao fee",
            "avoid protocol fee",
            "bypass protocol fee",
            "evade fee",
        ),
        (
            "protocol fee",
            "treasury fee",
            "dao fee",
            "performance fee",
            "management fee",
            "fee distribution",
            "feecollector",
            "fee collector",
            "evade",
            "bypass fee",
            "avoid fee",
        ),
        (
            "fee-on-transfer",
        ),
    ),
    # ---- Vault share family ----
    (
        "vault-share-mint-rounding",
        (
            "share mint rounding",
            "mint shares rounds favorable",
            "mint shares rounds in attacker",
            "mint shares rounding favors",
            "deposit share rounding",
            "rounding on mint",
            "rounds shares up on mint",
        ),
        (
            "mint shares",
            "mintshares",
            "deposit shares",
            "shares = ",
            "share = ",
            "shares minted",
            "rounding",
            "round down",
            "round up",
            "mulwad",
            "muldiv",
            "previewdeposit",
            "convertosshares",
            "converttoshares",
        ),
        (
            "redeem",
            "withdraw",
        ),
    ),
    (
        "vault-share-redemption-rounding",
        (
            "share redemption rounding",
            "redeem shares rounds favorable",
            "redemption rounding favor",
            "withdraw share rounding",
            "rounding on redemption",
            "rounds shares down on redeem",
            "redeem rounds in favor",
        ),
        (
            "redeem shares",
            "redeemshares",
            "withdraw shares",
            "previewredeem",
            "previewwithdraw",
            "converttoassets",
            "convert_to_assets",
            "redeem",
            "withdraw",
            "rounding",
            "round down",
            "round up",
        ),
        (
            "deposit",
            "mint",
        ),
    ),
    (
        "share-accounting",
        (
            "share accounting drift",
            "shares accounting drift",
            "share-accounting drift",
            "share inflation",
            "first depositor",
            "first-deposit",
            "first deposit share inflation",
            "share dilution",
            "shares dilution",
            "shares mis-accounted",
            "totalsupply == 0",
            "totalsupply==0",
            "donate to inflate shares",
        ),
        (
            "totalsupply",
            "total_supply",
            "totalshares",
            "total shares",
            "share price",
            "shareprice",
            "share supply",
            "erc4626",
            "erc-4626",
            "vault shares",
            "donation",
            "balanceof(vault)",
            "balanceof(address(this))",
        ),
        (),
    ),
    # ---- Unlock / vesting / lock release ----
    (
        "vesting-bypass",
        (
            "vesting bypass",
            "bypass vesting",
            "evade vesting cliff",
            "evade vesting",
            "skip vesting",
            "vesting cliff bypass",
            "early vesting release",
            "vest early",
            "claim before vesting",
        ),
        (
            "vesting",
            "vest schedule",
            "cliff",
            "vest claim",
            "vesting schedule",
            "release schedule",
            "unlock schedule",
        ),
        (),
    ),
    (
        "unlock-shares",
        (
            "unlock shares early",
            "premature unlock",
            "unlock before maturity",
            "unlock before period",
            "unlock window bypass",
            "unlock front-run",
            "front-run unlock",
            "frontrun unlock",
            "unlock manipulation",
            "early unlock",
        ),
        (
            "unlock",
            "unlock shares",
            "unstake",
            "withdraw lock",
            "lock release",
            "lock period",
            "lock expiry",
            "lockup",
            "locked balance",
            "release lock",
        ),
        (
            "vesting",
        ),
    ),
    (
        "lock-release-front-run",
        (
            "lock release front-run",
            "lock release frontrun",
            "front-run lock release",
            "frontrun lock release",
            "front-run unlock",
            "sandwich unlock",
            "sandwich the unlock",
            "race the unlock",
        ),
        (
            "front-run",
            "frontrun",
            "sandwich",
            "race",
            "lock release",
            "release queue",
            "unlock window",
        ),
        (),
    ),
    # ---- Liquidation family ----
    (
        "liquidation-bonus-theft",
        (
            "liquidation bonus theft",
            "drain liquidation bonus",
            "manipulate liquidation bonus",
            "inflate liquidation bonus",
            "self-liquidate",
            "self liquidate",
            "liquidate own position for bonus",
            "liquidator captures all bonus",
        ),
        (
            "liquidation bonus",
            "liquidator bonus",
            "liquidation reward",
            "liquidation incentive",
            "liquidate",
            "self-liquidat",
        ),
        (),
    ),
    (
        "liquidation-mispricing",
        (
            "liquidation mispricing",
            "manipulate liquidation price",
            "stale price liquidation",
            "liquidate at stale price",
            "wrong liquidation threshold",
            "incorrect liquidation price",
            "liquidate at wrong price",
            "liquidate before underwater",
            "unhealthy liquidation threshold",
        ),
        (
            "liquidation price",
            "liquidation threshold",
            "health factor",
            "ltv",
            "loan-to-value",
            "loan to value",
            "underwater",
            "collateral price",
            "oracle price",
            "liquidate",
        ),
        (
            "self-liquidat",
        ),
    ),
    # ---- Margin / perp family ----
    (
        "cross-margin-position-confusion",
        (
            "cross margin confusion",
            "cross-margin confusion",
            "cross margin position confusion",
            "isolated margin leak",
            "isolated vs cross",
            "wrong subaccount",
            "subaccount confusion",
            "perp account confusion",
            "position id collision",
        ),
        (
            "cross margin",
            "cross-margin",
            "isolated margin",
            "subaccount",
            "sub-account",
            "perp",
            "position id",
            "positionid",
            "margin requirement",
        ),
        (),
    ),
    (
        "funding-rate-theft",
        (
            "funding rate theft",
            "drain funding rate",
            "steal funding",
            "manipulate funding rate",
            "funding rate manipulation",
            "front-run funding update",
        ),
        (
            "funding rate",
            "fundingrate",
            "funding payment",
            "funding pnl",
            "funding interval",
        ),
        (
            "rounding",
        ),
    ),
    (
        "funding-rate-rounding",
        (
            "funding rate rounding",
            "funding rounding asymmetry",
            "funding payment rounding",
            "rounding favors long",
            "rounding favors short",
        ),
        (
            "funding rate",
            "funding payment",
            "rounding",
            "round down",
            "round up",
            "long pays short",
        ),
        (),
    ),
    # ---- Auction / matching ----
    (
        "auction-bidding-bypass",
        (
            "auction bidding bypass",
            "bypass auction min bid",
            "bypass auction reserve",
            "bid below reserve",
            "auction front-run",
            "auction sandwich",
            "skip auction window",
            "auction griefing",
        ),
        (
            "auction",
            "bidding",
            "bidder",
            "reserve price",
            "min bid",
            "highest bid",
            "auction end",
            "auction window",
        ),
        (),
    ),
    # ---- Slippage / min-output ----
    (
        "slippage-bypass",
        (
            "slippage bypass",
            "bypass slippage",
            "minamountout=0",
            "minamountout = 0",
            "min_amount_out=0",
            "min_amount_out = 0",
            "missing slippage",
            "no slippage protection",
            "slippage ignored",
            "amountoutmin not enforced",
        ),
        (
            "slippage",
            "minamountout",
            "min_amount_out",
            "amountoutmin",
            "amount_out_min",
            "min output",
            "min-output",
            "amountmin",
            "deadline",
            "sandwich",
            "front-run swap",
        ),
        (),
    ),
    (
        "min-output-bypass",
        (
            "min output bypass",
            "min-output bypass",
            "bypass min output",
            "min output ignored",
            "user-supplied min ignored",
            "min out parameter ignored",
        ),
        (
            "min output",
            "min-output",
            "minamountout",
            "amountoutmin",
            "user supplies min",
            "trader supplies min",
        ),
        (),
    ),
)


# ---------------------------------------------------------------------------
# YAML helpers (intentionally minimal — corpus_tags YAML is a flat shape and
# we cannot introduce a new dependency).
# ---------------------------------------------------------------------------
_INDENT = re.compile(r"^(?P<indent>\s*)(?P<rest>.*)$")
_KV = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Tiny YAML parser sufficient for hackerman_record v1 tags.

    Handles top-level scalars, one nested mapping (``function_shape:``), and
    list-of-scalars at top level (``required_preconditions:``, ``shape_tags:``,
    ``cross_language_analogues:``, ``related_records:``).
    """
    result: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_indent = 0
    nested_key: Optional[str] = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = _INDENT.match(line)
        if not m:
            i += 1
            continue
        indent = len(m.group("indent"))
        rest = m.group("rest")
        if indent == 0:
            nested_key = None
            kv = _KV.match(rest)
            if kv:
                key, val = kv.group(1), kv.group(2)
                val = val.strip()
                if val == "" or val == "|":
                    # Might be a mapping or list opener
                    if i + 1 < len(lines) and lines[i + 1].lstrip().startswith("-"):
                        # list
                        items: List[Any] = []
                        j = i + 1
                        while j < len(lines):
                            ln = lines[j]
                            if not ln.strip():
                                j += 1
                                continue
                            mi = _INDENT.match(ln)
                            if not mi or len(mi.group("indent")) == 0:
                                break
                            stripped = ln.lstrip()
                            if stripped.startswith("- "):
                                items.append(_strip_quotes(stripped[2:].strip()))
                            elif stripped.startswith("-"):
                                items.append(_strip_quotes(stripped[1:].strip()))
                            else:
                                break
                            j += 1
                        result[key] = items
                        i = j
                        current_key = key
                        continue
                    else:
                        result[key] = {}
                        current_key = key
                        i += 1
                        continue
                elif val == "[]":
                    result[key] = []
                else:
                    result[key] = _strip_quotes(val)
                current_key = key
        else:
            # nested
            if current_key is None:
                i += 1
                continue
            kv = _KV.match(rest)
            if kv and isinstance(result.get(current_key), dict):
                key, val = kv.group(1), kv.group(2)
                val = val.strip()
                if val == "" or val == "|":
                    # nested list
                    items_n: List[Any] = []
                    j = i + 1
                    while j < len(lines):
                        ln = lines[j]
                        if not ln.strip():
                            j += 1
                            continue
                        mi = _INDENT.match(ln)
                        if not mi:
                            break
                        ind = len(mi.group("indent"))
                        if ind <= indent:
                            break
                        stripped = ln.lstrip()
                        if stripped.startswith("- "):
                            items_n.append(_strip_quotes(stripped[2:].strip()))
                        elif stripped.startswith("-"):
                            items_n.append(_strip_quotes(stripped[1:].strip()))
                        else:
                            break
                        j += 1
                    result[current_key][key] = items_n
                    i = j
                    continue
                else:
                    result[current_key][key] = _strip_quotes(val)
        i += 1
    return result


def _scannable_text(record: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in (
        "target_component",
        "attacker_action_sequence",
        "bug_summary",
        "recommendation",
        "fix_pattern",
        "fix_anti_pattern_avoided",
        "source_audit_ref",
        "record_id",
        "bug_class",
    ):
        val = record.get(key)
        if isinstance(val, str):
            parts.append(val)
    fs = record.get("function_shape")
    if isinstance(fs, dict):
        for sub in ("raw_signature", "name"):
            v = fs.get(sub)
            if isinstance(v, str):
                parts.append(v)
        tags = fs.get("shape_tags")
        if isinstance(tags, list):
            parts.extend(str(t) for t in tags)
    preconds = record.get("required_preconditions")
    if isinstance(preconds, list):
        parts.extend(str(p) for p in preconds)
    return "\n".join(parts).lower()


def classify(record: Dict[str, Any]) -> Tuple[Optional[str], float, List[str]]:
    """Return (target_class | None, confidence, indicator_hits).

    confidence rationale:
      - exact-phrase match => 1.0
      - 4+ indicator hits   => 0.85
      - 3 indicator hits    => 0.70
      - 2 indicator hits    => 0.55
      - <2 hits             => no match
    """
    text = _scannable_text(record)
    if not text:
        return None, 0.0, []
    for target_class, exact_phrases, indicators, veto_phrases in RECLASSIFY_RULES:
        if any(veto in text for veto in veto_phrases):
            continue
        for phrase in exact_phrases:
            if phrase in text:
                return target_class, 1.0, [f"exact:{phrase}"]
    # Fallback: indicator scoring across all rules; pick the rule with most hits.
    best: Tuple[Optional[str], int, List[str]] = (None, 0, [])
    for target_class, _exact, indicators, veto_phrases in RECLASSIFY_RULES:
        if any(veto in text for veto in veto_phrases):
            continue
        hits = [ind for ind in indicators if ind in text]
        # de-dup by case
        hits = sorted(set(hits))
        if len(hits) > best[1]:
            best = (target_class, len(hits), hits)
    cls, count, hits = best
    if count >= 4:
        return cls, 0.85, hits
    if count == 3:
        return cls, 0.70, hits
    if count == 2:
        return cls, 0.55, hits
    return None, 0.0, []


# ---------------------------------------------------------------------------
# IO over corpus tags
# ---------------------------------------------------------------------------

CLASS_LINE = re.compile(r"^attack_class:\s+(\S.*)$", re.MULTILINE)


def reclassify_yaml_text(text: str, new_class: str) -> Tuple[str, Optional[str]]:
    """Replace the ``attack_class:`` line.

    Returns (new_text, old_class) - old_class is None if the line was not found
    or already matches new_class.
    """
    m = CLASS_LINE.search(text)
    if not m:
        return text, None
    old_class = m.group(1).strip()
    if old_class == new_class:
        return text, None
    new_text = CLASS_LINE.sub(f"attack_class: {new_class}", text, count=1)
    return new_text, old_class


def _discover_record_yaml_paths(tag_dir: Path) -> List[Path]:
    """Recursively discover candidate YAML record files under ``tag_dir``.

    Mirrors the canonical index builder (hackerman-index-build.py rglob
    discovery): the corpus migrated from a flat ``tags/*.yaml`` layout to a
    nested ``tags/<subtree>/<slug>/record.yaml`` layout, so a non-recursive
    ``glob('*.yaml')`` silently sees ~0 of the ~14k catch-all records. We
    collect ``rglob('record.yaml')`` (nested form) plus ``rglob('*.yaml')``
    (flat form), de-duped by resolved path and sorted for determinism.
    """
    seen: set = set()
    paths: List[Path] = []
    for path in sorted(tag_dir.rglob("record.yaml")) + sorted(tag_dir.rglob("*.yaml")):
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen:
            continue
        seen.add(key)
        paths.append(path)
    return paths


def _is_v1_family_schema(schema_version: Any) -> bool:
    """True for any record in the hackerman_record.v1 family (v1, v1.1, v1.2).

    The catch-all corpus was originally exact-v1 but later records carry
    ``v1.1`` / ``v1.2`` schema_version values; an exact ``== ...v1`` filter
    silently drops every newer-schema record. ``parse_simple_yaml`` already
    strips surrounding quotes, so a stripped ``startswith`` family check is
    sufficient and covers quoted/unquoted forms.
    """
    if not isinstance(schema_version, str):
        return False
    return schema_version.strip().startswith("auditooor.hackerman_record.v1")


def iterate_catchall_records(
    tag_dir: Path,
) -> Iterable[Tuple[Path, Dict[str, Any], str]]:
    """Yield (path, parsed_record, raw_text) for each catch-all-class record."""
    for path in _discover_record_yaml_paths(tag_dir):
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            continue
        record = parse_simple_yaml(raw)
        if not _is_v1_family_schema(record.get("schema_version")):
            continue
        if record.get("attack_class") not in CATCHALL_CLASSES:
            continue
        yield path, record, raw


def run(
    tag_dir: Path,
    candidates_path: Path,
    *,
    apply: bool = False,
    min_confidence: float = 0.55,
    limit: Optional[int] = None,
    rollback_path: Optional[Path] = None,
) -> Dict[str, Any]:
    scanned = 0
    matched = 0
    applied = 0
    skipped_low_confidence = 0
    by_old_class: Dict[str, int] = {}
    by_new_class: Dict[str, int] = {}
    errors: List[str] = []
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    fh = candidates_path.open("w", encoding="utf-8") if not candidates_path.is_dir() else None
    rb_fh = None
    if apply and rollback_path is not None:
        rollback_path.parent.mkdir(parents=True, exist_ok=True)
        rb_fh = rollback_path.open("w", encoding="utf-8")
    try:
        for path, record, raw in iterate_catchall_records(tag_dir):
            scanned += 1
            old_class = str(record.get("attack_class"))
            by_old_class[old_class] = by_old_class.get(old_class, 0) + 1
            new_class, confidence, hits = classify(record)
            if not new_class:
                continue
            if confidence < min_confidence:
                skipped_low_confidence += 1
                continue
            matched += 1
            by_new_class[new_class] = by_new_class.get(new_class, 0) + 1
            candidate = {
                "schema": SCHEMA_VERSION,
                "tag_file": path.name,
                "record_id": record.get("record_id"),
                "old_attack_class": old_class,
                "new_attack_class": new_class,
                "confidence": confidence,
                "indicator_hits": hits,
                "target_component": record.get("target_component"),
                "source_audit_ref": record.get("source_audit_ref"),
            }
            if fh:
                fh.write(json.dumps(candidate, sort_keys=True) + "\n")
            if apply:
                new_text, written_old = reclassify_yaml_text(raw, new_class)
                if written_old is not None:
                    try:
                        path.write_text(new_text, encoding="utf-8")
                        applied += 1
                        if rb_fh is not None:
                            rb_fh.write(
                                json.dumps(
                                    {
                                        "tag_file": path.name,
                                        "record_id": record.get("record_id"),
                                        "attack_class_original": written_old,
                                        "attack_class_applied": new_class,
                                    },
                                    sort_keys=True,
                                )
                                + "\n"
                            )
                    except OSError as exc:
                        errors.append(f"{path.name}: write error: {exc}")
                else:
                    errors.append(f"{path.name}: attack_class line not found")
            if limit is not None and matched >= limit:
                break
    finally:
        if fh:
            fh.close()
        if rb_fh is not None:
            rb_fh.close()
    return {
        "schema": SCHEMA_VERSION,
        "tag_dir": str(tag_dir),
        "candidates_path": str(candidates_path),
        "rollback_path": str(rollback_path) if rollback_path is not None else "",
        "apply": apply,
        "min_confidence": min_confidence,
        "scanned_catchall_records": scanned,
        "matched_candidates": matched,
        "skipped_low_confidence": skipped_low_confidence,
        "applied_writes": applied,
        "by_old_class": by_old_class,
        "by_new_class": by_new_class,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    p.add_argument("--candidates-path", default=str(DEFAULT_CANDIDATES_PATH))
    p.add_argument("--rollback-path", default=str(DEFAULT_ROLLBACK_PATH))
    p.add_argument(
        "--min-confidence",
        type=float,
        default=0.55,
        help="Suppress candidates whose indicator-derived confidence is below this floor.",
    )
    p.add_argument("--dry-run", action="store_true", help="Do not modify any YAML files (default).")
    p.add_argument(
        "--apply",
        action="store_true",
        help="Flip attack_class: on matched records in-place and add attack_class_original:.",
    )
    p.add_argument("--limit", type=int, help="Cap the number of candidates emitted.")
    p.add_argument("--json-summary", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.apply and args.dry_run:
        print("--apply and --dry-run are mutually exclusive", file=sys.stderr)
        return 2
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    candidates_path = Path(args.candidates_path).expanduser().resolve()
    rollback_path = Path(args.rollback_path).expanduser().resolve() if args.apply else None
    summary = run(
        tag_dir,
        candidates_path,
        apply=args.apply,
        min_confidence=args.min_confidence,
        limit=args.limit,
        rollback_path=rollback_path,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman catch-all reclassify: "
            f"scanned={summary['scanned_catchall_records']} "
            f"matched={summary['matched_candidates']} "
            f"applied={summary['applied_writes']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
