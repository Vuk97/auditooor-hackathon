#!/usr/bin/env python3
"""Backfill REAL routable (attack_class, bug_class) onto solodit hackerman records.

~43,675 body-rich solodit corpus records sit at ``bug_class: unknown-class`` /
``attack_class: unknown-attack``. They were ingested with
``taxonomy_source: unknown`` because the upstream Solodit row carried no class
and the fresh-ingest fallback classifier (``solodit-rest-direct.py``) found no
keyword group. This tool re-runs THAT SAME classifier over the persisted record
body (target_component title + attacker_action_sequence narrative) and flips
only the records where the classifier returns a CONFIDENT, specific class that
maps to a canonical-enum member.

REUSE, NOT REBUILD
==================
The keyword rules live in ``tools/solodit-rest-direct.py``:
  - ``TAXONOMY_FALLBACK_RULES``      (the keyword groups)
  - ``_classify_taxonomy_fallback``  (the (attack_class, bug_class) generator)
We import that function verbatim (the module name has hyphens, so we load it via
importlib). We do NOT reimplement the rules.

CANONICAL-ENUM HONESTY GATE (R76 / R80)
=======================================
The classifier's native output vocabulary (e.g. ``access-control-bypass``,
``reentrancy``) is NOT the canonical corpus enum. The ONLY allowed output values
are the ``class_id`` members of:
  - reference/attack_class_vocab.yaml   (104 canonical attack_class ids)
  - reference/bug_class_taxonomy.yaml   (canonical bug_class ids)
So we apply a deterministic, audited 1:1 map from each classifier rule to a
canonical (attack_class, bug_class) pair (``CLASSIFIER_TO_CANONICAL`` below). A
record is flipped ONLY when ALL of the following hold:
  1. the classifier returns a non-``unknown`` rule (``confidence`` in
     {high, medium} -- never the ``confidence: none`` fallback bucket), AND
  2. that rule has an entry in ``CLASSIFIER_TO_CANONICAL`` (i.e. it maps to a
     SPECIFIC canonical pair, not a vague catch-all), AND
  3. BOTH the mapped attack_class AND the mapped bug_class are live members of
     the canonical enums.
If any check fails the record is LEFT as unknown-class / unknown-attack. A
wrong-but-confident class is worse than an honest unknown -- the generic buckets
the classifier emits that have no SPECIFIC canonical home (denial-of-service,
liquidation-bypass, staking-reward-theft, state-accounting-drift) are
deliberately left unknown rather than stamped with an over-broad class.

Idempotent: the scan excludes records whose bug_class AND attack_class are both
already real (not in the unknown set), so re-runs after ``--apply`` are no-ops.

Usage:
    python3 tools/hackerman-backfill-solodit-class.py --dry-run
    python3 tools/hackerman-backfill-solodit-class.py --dry-run --json-summary
    python3 tools/hackerman-backfill-solodit-class.py --apply
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "auditooor.hackerman_backfill_solodit_class.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_CANDIDATE_PATH = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "solodit_class_backfill_candidates.jsonl"
DEFAULT_ROLLBACK_PATH = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "solodit_class_backfill_rollback.jsonl"
ATTACK_VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"
BUG_VOCAB_PATH = REPO_ROOT / "reference" / "bug_class_taxonomy.yaml"

UNKNOWN_VALUES = {
    "unknown-class", "unknown", "unknown-attack",
    "unclassified", "uncategorized",
}

# YAML line matchers. Records are flat-key hackerman_record YAML; bug_class /
# attack_class are top-level scalar lines.
BUG_CLASS_RE = re.compile(r"^(bug_class:\s*)([\"']?)([A-Za-z0-9._\-]+)\2\s*$", re.MULTILINE)
ATTACK_CLASS_RE = re.compile(r"^(attack_class:\s*)([\"']?)([A-Za-z0-9._\-]+)\2\s*$", re.MULTILINE)
RECORD_ID_RE = re.compile(r"^record_id:\s*([\"']?)(.+?)\1\s*$", re.MULTILINE)
TARGET_COMPONENT_RE = re.compile(r"^target_component:\s*([\"']?)(.*?)\1\s*$", re.MULTILINE)
SCHEMA_RE = re.compile(r"^schema_version:\s+auditooor\.hackerman_record\.", re.MULTILINE)


# --------------------------------------------------------------------------
# Reuse the existing classifier from solodit-rest-direct.py (do NOT reimplement)
# --------------------------------------------------------------------------
def _load_classifier_module():
    path = REPO_ROOT / "tools" / "solodit-rest-direct.py"
    spec = importlib.util.spec_from_file_location("_solodit_rest_direct", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load classifier module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "_classify_taxonomy_fallback"):
        raise ImportError("solodit-rest-direct.py missing _classify_taxonomy_fallback")
    return module


# Source-of-truth pointer for the StructuredOutput report.
CLASSIFIER_REUSED_FROM = "tools/solodit-rest-direct.py:798 _classify_taxonomy_fallback"


# --------------------------------------------------------------------------
# Deterministic map: classifier rule -> canonical (attack_class, bug_class).
# Keys are the classifier's ``attack_class`` rule id (TAXONOMY_FALLBACK_RULES).
# Only SPECIFIC rules that have a precise canonical home appear here. Rules that
# resolve only to a vague bucket (denial-of-service, liquidation-bypass,
# staking-reward-theft, state-accounting-drift) are DELIBERATELY ABSENT so those
# records stay honest-unknown rather than get an over-broad stamp.
# --------------------------------------------------------------------------
CLASSIFIER_TO_CANONICAL: Dict[str, Tuple[str, str]] = {
    # classifier rule id        -> (canonical attack_class, canonical bug_class)
    "reentrancy": ("reentrancy-cross-contract", "reentrancy-cross-contract"),
    "access-control-bypass": ("admin-bypass", "missing-authority-check"),
    "signature-replay": ("signature-replay-cross-domain", "signature-validation-gap"),
    "oracle-price-manipulation": ("oracle-price-manipulation", "oracle-price-manipulation"),
    "stale-or-manipulated-oracle": ("oracle-price-manipulation", "oracle-price-manipulation"),
    "rounding-precision-loss": ("rounding-direction-attack", "decimal-precision-loss"),
    "first-deposit-share-inflation": ("first-depositor-inflation", "erc4626-first-depositor-share-skew"),
    # NOTE: the 'bridge-proof-bypass' classifier rule was REMOVED from this map
    # (2026-06-18, ACCEPT_WITH_FIX). The underlying TAXONOMY_FALLBACK_RULES rule
    # in tools/solodit-rest-direct.py over-fires: it triggers on ANY text
    # mentioning bridge / cross-chain / proof / verify, so mapping it to the
    # specific (bridge-proof-domain-bypass, bridge-proof-domain-bypass) pair
    # produced wrong-but-confident stamps. Sampling showed ~half of the 115
    # bridge flips were actually missing-access-control, fee-manipulation,
    # gas-undercounting, migration-DoS, or consensus-validation -- NOT
    # proof/domain bypass. Per R76/R80 a wrong-but-confident class is worse than
    # an honest unknown, so bridge-classified records are LEFT honest-unknown
    # (exactly like the generic DoS / liquidation / staking buckets that have no
    # SPECIFIC canonical home).
}


def _load_canonical_ids(path: Path) -> set[str]:
    """Parse class_id members from a canonical vocab YAML.

    We avoid a hard PyYAML dependency for the membership set: the vocab files are
    a flat ``- class_id: <slug>`` list, so a line regex is sufficient and keeps
    the tool runnable in minimal environments. (PyYAML is still used by the test
    for an independent cross-check.)
    """
    ids: set[str] = set()
    line_re = re.compile(r"^\s*-?\s*class_id:\s*([\"']?)([A-Za-z0-9._\-]+)\1\s*$")
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = line_re.match(line)
        if m:
            ids.add(m.group(2))
    return ids


def _is_unknown(value: str) -> bool:
    return value.strip().strip("\"'").lower() in UNKNOWN_VALUES


def _extract(text: str, pattern: re.Pattern, group: int) -> str:
    m = pattern.search(text)
    return m.group(group).strip() if m else ""


def _extract_body(text: str) -> str:
    """Return the attacker_action_sequence block-scalar body, code-stripped enough.

    The classifier's own ``_first_narrative_text`` strips code fences when handed
    the body as a ``description`` field, so we pass the raw block-scalar text
    through and let the classifier do the prose extraction.
    """
    m = re.search(r"^attacker_action_sequence:\s*\|[+-]?\s*$", text, re.MULTILINE)
    if not m:
        # single-line form
        m2 = re.search(r"^attacker_action_sequence:\s*(.+)$", text, re.MULTILINE)
        return m2.group(1).strip() if m2 else ""
    start = m.end()
    lines: List[str] = []
    for line in text[start:].splitlines():
        if line and not line[0].isspace():
            break  # next top-level key ends the block scalar
        lines.append(line)
    # dedent two spaces (block-scalar indent) where present
    dedented = [l[2:] if l.startswith("  ") else l for l in lines]
    return "\n".join(dedented).strip()


def classify_record(module, title: str, body: str) -> Dict[str, Any]:
    """Run the reused classifier and apply the canonical-enum honesty gate.

    Returns a dict with the classifier verdict plus the canonical mapping result.
    ``would_flip`` is True only when the honesty gate passes.
    """
    raw = {"description": body}
    verdict = module._classify_taxonomy_fallback(raw, title)
    classifier_attack = verdict.get("attack_class", "unknown-attack")
    confidence = verdict.get("confidence", "none")
    rule = verdict.get("rule")

    result: Dict[str, Any] = {
        "classifier_attack_class": classifier_attack,
        "classifier_bug_class": verdict.get("bug_class", "unknown-class"),
        "classifier_confidence": confidence,
        "classifier_rule": rule,
        "would_flip": False,
        "new_attack_class": None,
        "new_bug_class": None,
        "left_unknown_reason": None,
    }

    # Honesty gate layer 1: classifier must return a confident, specific rule.
    if classifier_attack in UNKNOWN_VALUES or confidence == "none" or rule is None:
        result["left_unknown_reason"] = "classifier-fallback-no-confident-rule"
        return result

    # Honesty gate layer 2: the rule must map to a SPECIFIC canonical pair.
    canonical = CLASSIFIER_TO_CANONICAL.get(rule)
    if canonical is None:
        result["left_unknown_reason"] = f"no-specific-canonical-home:{rule}"
        return result

    new_attack, new_bug = canonical
    # Honesty gate layer 3: both mapped values must be live canonical-enum members.
    if new_attack not in CANONICAL_ATTACK or new_bug not in CANONICAL_BUG:
        result["left_unknown_reason"] = f"mapped-value-not-canonical:{new_attack}/{new_bug}"
        return result

    result["would_flip"] = True
    result["new_attack_class"] = new_attack
    result["new_bug_class"] = new_bug
    return result


# Populated in main() after enum load; module-level so classify_record sees them.
CANONICAL_ATTACK: set[str] = set()
CANONICAL_BUG: set[str] = set()


def _rewrite_class_line(text: str, pattern: re.Pattern, new_value: str) -> str:
    def repl(m: re.Match) -> str:
        prefix, quote = m.group(1), m.group(2)
        return f"{prefix}{quote}{new_value}{quote}"
    return pattern.sub(repl, text, count=1)


def scan(
    tag_dir: Path,
    module,
    *,
    apply: bool = False,
    limit: int = 0,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    rollback: List[Dict[str, Any]] = []
    scanned = 0
    eligible = 0
    would_flip = 0
    left_unknown = 0
    applied = 0
    left_reasons: Dict[str, int] = {}
    class_pairs: Dict[str, int] = {}
    attack_dist: Dict[str, int] = {}
    bug_dist: Dict[str, int] = {}

    solodit_dirs = sorted(d for d in tag_dir.iterdir() if d.is_dir() and "solodit" in d.name)
    for d in solodit_dirs:
        for path in sorted(d.rglob("*.yaml")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if not SCHEMA_RE.search(text):
                continue
            cur_bug = _extract(text, BUG_CLASS_RE, 3)
            cur_attack = _extract(text, ATTACK_CLASS_RE, 3)
            if not cur_bug and not cur_attack:
                continue
            scanned += 1
            # Idempotency / scope: only records that are still unknown on EITHER axis.
            if not (_is_unknown(cur_bug) or _is_unknown(cur_attack)):
                continue
            eligible += 1

            title = _extract(text, TARGET_COMPONENT_RE, 2)
            body = _extract_body(text)
            if len(body.split()) < 20:
                left_unknown += 1
                left_reasons["trivial-body"] = left_reasons.get("trivial-body", 0) + 1
                continue

            verdict = classify_record(module, title, body)
            if not verdict["would_flip"]:
                left_unknown += 1
                reason = verdict["left_unknown_reason"] or "no-flip"
                # bucket the per-rule no-home reasons together for readability
                if reason.startswith("no-specific-canonical-home"):
                    reason = "no-specific-canonical-home"
                left_reasons[reason] = left_reasons.get(reason, 0) + 1
                continue

            would_flip += 1
            new_attack = verdict["new_attack_class"]
            new_bug = verdict["new_bug_class"]
            pair = f"{new_attack} / {new_bug}"
            class_pairs[pair] = class_pairs.get(pair, 0) + 1
            attack_dist[new_attack] = attack_dist.get(new_attack, 0) + 1
            bug_dist[new_bug] = bug_dist.get(new_bug, 0) + 1

            record_id = _extract(text, RECORD_ID_RE, 2)
            cand = {
                "tag_file": str(path.relative_to(tag_dir)),
                "record_id": record_id,
                "old_attack": cur_attack,
                "old_bug": cur_bug,
                "new_attack": new_attack,
                "new_bug": new_bug,
                "classifier_rule": verdict["classifier_rule"],
                "classifier_confidence": verdict["classifier_confidence"],
                "title": title[:160],
            }
            candidates.append(cand)

            if apply:
                new_text = text
                new_text = _rewrite_class_line(new_text, ATTACK_CLASS_RE, new_attack)
                new_text = _rewrite_class_line(new_text, BUG_CLASS_RE, new_bug)
                if new_text != text:
                    path.write_text(new_text, encoding="utf-8")
                    applied += 1
                    rollback.append({
                        "record_id": record_id,
                        "tag_file": str(path.relative_to(tag_dir)),
                        "old_attack": cur_attack,
                        "old_bug": cur_bug,
                        "new_attack": new_attack,
                        "new_bug": new_bug,
                    })

            if limit and would_flip >= limit:
                break
        if limit and would_flip >= limit:
            break

    summary = {
        "schema": SCHEMA,
        "solodit_dirs": len(solodit_dirs),
        "scanned": scanned,
        "eligible_unknown": eligible,
        "would_flip": would_flip,
        "left_unknown_honest": left_unknown,
        "applied_flips": applied,
        "left_unknown_reasons": dict(sorted(left_reasons.items(), key=lambda kv: -kv[1])),
        "class_pairs": dict(sorted(class_pairs.items(), key=lambda kv: -kv[1])),
        "attack_class_distribution": dict(sorted(attack_dist.items(), key=lambda kv: -kv[1])),
        "bug_class_distribution": dict(sorted(bug_dist.items(), key=lambda kv: -kv[1])),
        "applied": apply,
    }
    return candidates, rollback, summary


def write_jsonl(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def merge_rollback_ledger(new_rows: List[Dict[str, Any]], path: Path) -> int:
    """Merge new rollback rows into the existing ledger, keyed by record_id.

    The ledger is the authoritative record of EVERY flip ever applied. Because
    --apply is idempotent (a re-run flips nothing), naively rewriting the ledger
    would erase the history on a no-op re-run. We therefore MERGE: existing rows
    are preserved and new rows are added/updated. The merge key is ``tag_file``
    (the unit of edit) -- two distinct tag files may legitimately share a
    ``record_id`` (the same upstream finding ingested into two backfill batches)
    and each needs its own rollback row. Returns the total ledger row count.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = str(row.get("tag_file") or row.get("record_id") or "")
            if key and key not in merged:
                order.append(key)
            merged[key] = row
    for row in new_rows:
        key = str(row.get("tag_file") or row.get("record_id") or "")
        if key and key not in merged:
            order.append(key)
        merged[key] = row
    with path.open("w", encoding="utf-8") as fh:
        for rid in order:
            fh.write(json.dumps(merged[rid], sort_keys=True) + "\n")
    return len(order)


def main(argv: Optional[List[str]] = None) -> int:
    global CANONICAL_ATTACK, CANONICAL_BUG
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag-dir", type=Path, default=DEFAULT_TAG_DIR)
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATE_PATH)
    parser.add_argument("--rollback", type=Path, default=DEFAULT_ROLLBACK_PATH)
    parser.add_argument("--attack-vocab", type=Path, default=ATTACK_VOCAB_PATH)
    parser.add_argument("--bug-vocab", type=Path, default=BUG_VOCAB_PATH)
    parser.add_argument("--dry-run", action="store_true", help="Scan only, never modify YAML.")
    parser.add_argument("--apply", action="store_true", help="Flip bug_class AND attack_class in place + write rollback ledger.")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N would-flip rows.")
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    if args.apply and args.dry_run:
        print("ERROR: --apply and --dry-run are mutually exclusive", file=sys.stderr)
        return 2

    CANONICAL_ATTACK = _load_canonical_ids(args.attack_vocab)
    CANONICAL_BUG = _load_canonical_ids(args.bug_vocab)
    if not CANONICAL_ATTACK or not CANONICAL_BUG:
        print("ERROR: failed to load canonical enums", file=sys.stderr)
        return 2

    # Fail-closed sanity: the deterministic map must only target canonical ids.
    for rule, (a, b) in CLASSIFIER_TO_CANONICAL.items():
        if a not in CANONICAL_ATTACK or b not in CANONICAL_BUG:
            print(f"ERROR: map entry {rule} -> {a}/{b} not in canonical enums", file=sys.stderr)
            return 2

    module = _load_classifier_module()
    apply = bool(args.apply)
    candidates, rollback, summary = scan(args.tag_dir, module, apply=apply, limit=args.limit)

    # Candidate JSONL is always written (dry-run preview or apply record).
    write_jsonl(candidates, args.candidates)
    summary["candidates_path"] = str(args.candidates)
    if apply:
        # Merge (do not truncate): an idempotent no-op re-run must preserve the
        # full flip history in the rollback ledger.
        total = merge_rollback_ledger(rollback, args.rollback)
        summary["rollback_path"] = str(args.rollback)
        summary["rollback_ledger_total_rows"] = total

    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            f"[backfill-solodit-class] scanned={summary['scanned']} "
            f"eligible_unknown={summary['eligible_unknown']} "
            f"would_flip={summary['would_flip']} "
            f"left_unknown_honest={summary['left_unknown_honest']} "
            f"applied_flips={summary['applied_flips']} applied={summary['applied']}"
        )
        print("  class pairs (attack / bug):")
        for pair, n in summary["class_pairs"].items():
            print(f"    {pair}: {n}")
        print("  left-unknown reasons:")
        for reason, n in summary["left_unknown_reasons"].items():
            print(f"    {reason}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
