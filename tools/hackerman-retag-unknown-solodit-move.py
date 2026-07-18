#!/usr/bin/env python3
"""
Re-tag the 200+ existing `target_repo: unknown/solodit` Move records into
properly-attributed Aptos / Sui / Move-language records.

Wave-5 lane EXEC-WAVE5-MOVE-CVE-RETAG / TIER-D Lift D14 (sibling of D13).

This is the corpus-hygiene cleanup that complements the new
`hackerman-etl-from-move-cve-advisory.py` backbone (Lift D13). When
Wave-2 imported the original solodit specs corpus, many Move-language
records were tagged with the catch-all `target_repo: unknown/solodit`
because the spec text did not directly reference the upstream repo.
Indicator-literal mining of the title / component / signature / spec
text lets us assign:

* `aptos`, `AptosFramework`, `AptosVM`, `aptos-core`, `aptos_framework::`
  -> `target_repo: aptos-labs/aptos-core` + `shape_tags: [..., "move-aptos"]`
* `sui::`, `mysten`, `narwhal`, `bullshark`, `object::`, `sui_framework::`
  -> `target_repo: MystenLabs/sui` + `shape_tags: [..., "move-sui"]`
* Both classifiers + Move-resource-safety indicators
  -> also append the fine-grained Move attack class (mirror of Lift D13
  taxonomy)

Hard rules (per the Wave-5 EVM catch-all reclassify precedent):

* Do NOT write back to `audit/corpus_tags/tags/` directly.
* Preserve `target_repo_original` and `shape_tags_original` for rollback.
* Emit candidates JSONL to `.auditooor/move-retag-candidates.jsonl`
  (one JSON line per proposed retag).
* The operator does the actual apply step; this tool is read-only.

CLI:

    python3 tools/hackerman-retag-unknown-solodit-move.py \
        --tags-dir audit/corpus_tags/tags \
        --out-jsonl .auditooor/move-retag-candidates.jsonl \
        --dry-run --json-summary

    python3 tools/hackerman-retag-unknown-solodit-move.py \
        --tags-dir audit/corpus_tags/tags \
        --out-jsonl .auditooor/move-retag-candidates.jsonl

`--limit N` caps the candidate count for fast smoke-tests.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_JSONL = REPO_ROOT / ".auditooor" / "move-retag-candidates.jsonl"


# ----------------------------------------------------------------------------
# Indicator-literal classifier
# ----------------------------------------------------------------------------
#
# Indicators are evaluated case-insensitively. A record may match BOTH
# Aptos and Sui indicators (typical of the rare cross-chain Move record);
# in that case the candidate emits `proposed_target_repo: ambiguous` and
# the operator decides at apply time.


APTOS_INDICATORS: Tuple[str, ...] = (
    "aptos",
    "aptosframework",
    "aptosvm",
    "aptos-core",
    "aptos_framework::",
    "aptos_token::",
    "aptos_std::",
    "aptos-stdlib",
    "managed_coin",
    "thala",
    "tortuga",
    "amnis",
    "merkle-trade",
    "petra-wallet",
    "pontem",
    "econia",
    "aries-markets",
    "drafts_solodit_aptos",
)


# The `drafts_solodit_move` corpus source is Move-language-generic; on
# its own it should fall through to language-only-fallback rather than
# bias the classifier toward Aptos. Only treat it as a tie-breaker when
# at least one other indicator (Aptos OR Sui) also fires.


SUI_INDICATORS: Tuple[str, ...] = (
    "sui::",
    "sui_framework::",
    "sui-framework",
    "mysten",
    "narwhal",
    "bullshark",
    "deepbook",
    "suilend",
    "scallop",
    "navi-protocol",
    "cetus-protocol",
    "turbos",
    "object::transfer",
    "tx_context::",
    "treasurycap",
    "kioskownercap",
    "walrus",
    "zk_login",
    "drafts_solodit_sui",
)


MOVE_RESOURCE_SAFETY_INDICATORS: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "resource-safety-violation",
        "double-move-or-dangling-resource",
        ("double move", "move_from", "resource exists", "drop ability", "store ability", "key ability"),
    ),
    (
        "signer-derived-resource-leak",
        "signer-from-caller-controlled-path",
        (
            "&signer",
            "signercapability",
            "signer_cap",
            "create_signer_with_capability",
            "create_resource_account",
            "tx_context::sender",
        ),
    ),
    (
        "capability-pattern-bypass",
        "capability-leak-or-unbounded-mint",
        (
            "mintcapability",
            "burncapability",
            "freezecapability",
            "treasurycap",
            "treasury_cap",
            "mint_cap",
            "burn_cap",
            "freeze_cap",
            "capability pattern",
        ),
    ),
    (
        "aborts-if-policy-mismatch",
        "aborts-if-divergence",
        ("aborts_if", "aborts-if", "abort_with", "spec mismatch", "totality gap", "unchecked abort"),
    ),
    (
        "acquires-mismatch",
        "missing-or-extra-acquires-clause",
        ("acquires", "missing acquires", "borrow_global", "borrow_global_mut", "global storage"),
    ),
)


def _classify(text: str) -> Tuple[bool, bool, Optional[Tuple[str, str]]]:
    """Return (is_aptos, is_sui, optional move-resource-safety class).

    Move-resource-safety class is the first matching rule (most specific
    first), mirroring the Lift D13 classifier ordering.
    """
    low = text.lower()
    is_aptos = any(indicator in low for indicator in APTOS_INDICATORS)
    is_sui = any(indicator in low for indicator in SUI_INDICATORS)
    rs_class: Optional[Tuple[str, str]] = None
    for bug_class, attack_class, needles in MOVE_RESOURCE_SAFETY_INDICATORS:
        if any(needle in low for needle in needles):
            rs_class = (bug_class, attack_class)
            break
    return is_aptos, is_sui, rs_class


# ----------------------------------------------------------------------------
# Lightweight YAML reader
# ----------------------------------------------------------------------------
#
# These corpus YAMLs use a flat, line-oriented format (look at a few of
# them: they're all the same shape). Rather than pulling PyYAML and
# round-tripping (which loses comments and rewrites quoting), we do a
# line-level scan and extract the four scalars + the shape_tags block we
# care about. Anything we don't recognise stays untouched in the original
# file; the candidate JSONL carries the proposed edits only.


SCALAR_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1]
    return value


def read_record(path: Path) -> Optional[Dict[str, Any]]:
    """Parse the subset of the YAML record we need.

    Returns a dict with keys: target_language, target_repo,
    target_component, raw_signature, shape_tags (list), attacker_action,
    bug_class, attack_class, record_id, source_audit_ref.

    Returns None if the file is unreadable.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    lines = text.splitlines()
    record: Dict[str, Any] = {
        "target_language": "",
        "target_repo": "",
        "target_component": "",
        "raw_signature": "",
        "shape_tags": [],
        "attacker_action": "",
        "bug_class": "",
        "attack_class": "",
        "record_id": "",
        "source_audit_ref": "",
    }
    in_function_shape = False
    in_shape_tags = False
    fn_shape_indent: Optional[int] = None
    for raw in lines:
        if not raw.strip():
            in_shape_tags = False
            continue
        stripped = raw.rstrip()
        leading = len(stripped) - len(stripped.lstrip(" "))
        bare = stripped.lstrip(" ")
        # End of function_shape block?
        if in_function_shape and leading == 0 and ":" in bare and not bare.startswith("-"):
            in_function_shape = False
            in_shape_tags = False
            fn_shape_indent = None

        if not in_function_shape:
            m = SCALAR_LINE_RE.match(bare)
            if not m:
                continue
            key, value = m.group(1), m.group(2)
            if key == "function_shape" and value == "":
                in_function_shape = True
                fn_shape_indent = leading
                continue
            value_stripped = _strip_quotes(value)
            if key == "target_language":
                record["target_language"] = value_stripped
            elif key == "target_repo":
                record["target_repo"] = value_stripped
            elif key == "target_component":
                record["target_component"] = value_stripped
            elif key == "attacker_action_sequence":
                record["attacker_action"] = value_stripped
            elif key == "bug_class":
                record["bug_class"] = value_stripped
            elif key == "attack_class":
                record["attack_class"] = value_stripped
            elif key == "record_id":
                record["record_id"] = value_stripped
            elif key == "source_audit_ref":
                record["source_audit_ref"] = value_stripped
            continue

        # in_function_shape: handle nested keys
        if leading <= (fn_shape_indent or 0):
            in_function_shape = False
            in_shape_tags = False
            fn_shape_indent = None
            continue
        if in_shape_tags and bare.startswith("- "):
            tag = _strip_quotes(bare[2:].strip())
            if tag:
                record["shape_tags"].append(tag)
            continue
        in_shape_tags = False
        m = SCALAR_LINE_RE.match(bare)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if key == "shape_tags" and value == "":
            in_shape_tags = True
            continue
        if key == "raw_signature":
            record["raw_signature"] = _strip_quotes(value)
    return record


# ----------------------------------------------------------------------------
# Candidate builder
# ----------------------------------------------------------------------------


def build_candidate(path: Path, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if record["target_language"] != "move":
        return None
    if record["target_repo"] != "unknown/solodit":
        return None
    haystack = " ".join(
        [
            record.get("record_id") or "",
            record.get("source_audit_ref") or "",
            record.get("target_component") or "",
            record.get("raw_signature") or "",
            record.get("attacker_action") or "",
            " ".join(record.get("shape_tags") or []),
        ]
    )
    is_aptos, is_sui, rs_class = _classify(haystack)
    proposed_repo = "ambiguous"
    proposed_chain_tag: Optional[str] = None
    if is_aptos and is_sui:
        proposed_repo = "ambiguous"
        proposed_chain_tag = None
    elif is_aptos:
        proposed_repo = "aptos-labs/aptos-core"
        proposed_chain_tag = "move-aptos"
    elif is_sui:
        proposed_repo = "MystenLabs/sui"
        proposed_chain_tag = "move-sui"
    else:
        # No chain indicator surfaced: fall back to language-only attribution.
        # The operator may still want to retag these (e.g. to
        # `move-language/move`) but we mark the verdict
        # `language-only-fallback` and let them choose. Default proposal:
        # `move-language/move` keeps the language anchor without claiming
        # a specific chain.
        proposed_repo = "move-language/move"
        proposed_chain_tag = "move-language"

    proposed_shape_tags = list(record["shape_tags"])
    if proposed_chain_tag and proposed_chain_tag not in proposed_shape_tags:
        proposed_shape_tags.append(proposed_chain_tag)
    if rs_class is not None:
        bug_class, attack_class = rs_class
        ac_slug = re.sub(r"[^a-z0-9._:/-]+", "-", attack_class.lower()).strip("-._")
        bc_slug = re.sub(r"[^a-z0-9._:/-]+", "-", bug_class.lower()).strip("-._")
        if "move-resource-safety" not in proposed_shape_tags:
            proposed_shape_tags.append("move-resource-safety")
        if ac_slug and ac_slug not in proposed_shape_tags:
            proposed_shape_tags.append(ac_slug)
        if bc_slug and bc_slug not in proposed_shape_tags:
            proposed_shape_tags.append(bc_slug)

    verdict = (
        "retag-aptos"
        if proposed_repo == "aptos-labs/aptos-core"
        else "retag-sui"
        if proposed_repo == "MystenLabs/sui"
        else "language-only-fallback"
        if proposed_repo == "move-language/move"
        else "ambiguous-needs-operator"
    )

    return {
        "schema_version": "auditooor.move-retag-candidate.v1",
        "verdict": verdict,
        "file_path": str(path),
        "record_id": record.get("record_id") or path.stem,
        "source_audit_ref": record.get("source_audit_ref") or "",
        "target_language": "move",
        "target_repo_original": "unknown/solodit",
        "target_repo_proposed": proposed_repo,
        "shape_tags_original": list(record["shape_tags"]),
        "shape_tags_proposed": proposed_shape_tags,
        "indicators": {
            "is_aptos": is_aptos,
            "is_sui": is_sui,
            "rs_class": list(rs_class) if rs_class else None,
        },
        "target_component": record.get("target_component") or "",
        "raw_signature_preview": (record.get("raw_signature") or "")[:160],
    }


# ----------------------------------------------------------------------------
# Convert
# ----------------------------------------------------------------------------


def convert(
    tags_dir: Path,
    out_jsonl: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned = 0
    matched_move_unknown = 0
    errors: List[str] = []
    if not tags_dir.is_dir():
        return {
            "schema_version": "auditooor.move-retag.v1",
            "tags_dir": str(tags_dir),
            "out_jsonl": str(out_jsonl),
            "dry_run": dry_run,
            "scanned": 0,
            "matched_move_unknown": 0,
            "candidates_emitted": 0,
            "verdict_counts": {},
            "errors": [f"tags_dir not found: {tags_dir}"],
        }
    for path in sorted(tags_dir.rglob("*.yaml")):
        scanned += 1
        record = read_record(path)
        if record is None:
            errors.append(f"{path}: unreadable")
            continue
        if record["target_language"] != "move" or record["target_repo"] != "unknown/solodit":
            continue
        matched_move_unknown += 1
        candidate = build_candidate(path, record)
        if candidate is None:
            continue
        candidates.append(candidate)
        if limit is not None and len(candidates) >= limit:
            break

    verdict_counts: Dict[str, int] = {}
    for c in candidates:
        verdict_counts[c["verdict"]] = verdict_counts.get(c["verdict"], 0) + 1

    if not dry_run:
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with out_jsonl.open("w", encoding="utf-8") as fh:
            for candidate in candidates:
                fh.write(json.dumps(candidate, sort_keys=True))
                fh.write("\n")

    return {
        "schema_version": "auditooor.move-retag.v1",
        "tags_dir": str(tags_dir),
        "out_jsonl": str(out_jsonl),
        "dry_run": dry_run,
        "scanned": scanned,
        "matched_move_unknown": matched_move_unknown,
        "candidates_emitted": len(candidates),
        "verdict_counts": verdict_counts,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--out-jsonl", default=str(DEFAULT_OUT_JSONL))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.tags_dir).expanduser().resolve(),
        Path(args.out_jsonl).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman move-retag: "
            f"scanned={summary['scanned']} matched={summary['matched_move_unknown']} "
            f"candidates={summary['candidates_emitted']} "
            f"verdicts={summary['verdict_counts']} errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
