#!/usr/bin/env python3
"""wave2-w25-tier3-promotion-verify.

Wave-2 PR-A independent verification tool for the W2.5 tier-3 backfill
commit ``d0e3722d0b3eaa698aa2681aea08ad671063f7a8`` ("W2.3-residual:
promote 13 real-archive prefixes tier-3 to tier-2 (2098 records)").

The W2.5 commit claims that 2,098 records across 13 record_id prefixes
were promoted from ``tier-3-synthetic-taxonomy-anchored`` to
``tier-2-verified-public-archive``. This tool independently re-derives
that claim from three live evidence sources:

  1. ``git show --stat --name-only d0e3722d0b`` -- enumerate every tag
     YAML/JSON file the commit actually touched.
  2. The on-disk corpus state under ``audit/corpus_tags/tags/`` -- for
     every touched record, parse the ``record_id`` (which encodes the
     canonical prefix) and read the current ``verification_tier``
     signal (legacy ``function_shape.shape_tags`` value, since the
     v1 -> v1.1 migrator hasn't necessarily run on every record yet).
  3. The additive index at ``audit/corpus_tags/index/by_verification_tier.jsonl``
     -- cross-check that the per-prefix tier-2 totals are consistent
     between the corpus YAMLs and the index.

Expected counts are NOT hard-coded; they are parsed from the commit
message body so the tool stays in sync with whatever commit it is
pointed at via ``--commit-sha``.

The tool emits a JSON status pack of schema
``auditooor.wave2_w25_tier3_promotion_verify.v1`` and, when run with
``--strict``, exits non-zero on overall_status=FAIL.

CLI::

    python3 tools/wave2-w25-tier3-promotion-verify.py \\
        --workspace /Users/wolf/auditooor-702-full --strict --json

Exit codes::

    0  - PASS (or non-strict mode and FAIL)
    1  - FAIL (only when ``--strict``)
    2  - error (corpus dir missing, git unavailable, etc.)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.wave2_w25_tier3_promotion_verify.v1"
DEFAULT_COMMIT_SHA = "d0e3722d0b"

# Canonical expected total from the commit message. NOT used as a
# hard-coded gate; the tool re-parses the per-prefix breakdown from
# the commit message body so the canonical figure can update with a
# different commit. Kept only as a defensive fallback when the
# commit message parse yields no rows.
DEFAULT_EXPECTED_TOTAL = 2098

TIER2_TAG = "tier-2-verified-public-archive"
TIER3_TAG = "tier-3-synthetic-taxonomy-anchored"

# regex: e.g. "  zk-auditor:            401 records  (..."
_PREFIX_LINE_RE = re.compile(
    r"^\s*([a-z][a-z0-9-]*):\s+(\d+)\s+records\b", re.IGNORECASE
)
# regex: "  total:                2098 records"
_TOTAL_LINE_RE = re.compile(r"^\s*total:\s+(\d+)\s+records?\b", re.IGNORECASE)

_VERIFICATION_TIER_VALUE_RE = re.compile(
    r"^verification_tier:(tier-[1-5]-[a-z0-9][a-z0-9-]*)$"
)


# --------------------------------------------------------------------------- #
# git plumbing
# --------------------------------------------------------------------------- #


def _git(args: List[str], cwd: Path) -> str:
    """Run a git command and return stdout. Raises on non-zero exit."""
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def git_show_message(commit_sha: str, workspace: Path) -> str:
    """Return the raw commit message body for ``commit_sha``."""
    return _git(["show", "--no-patch", "--pretty=%B", commit_sha], workspace)


def git_show_name_only(commit_sha: str, workspace: Path) -> List[str]:
    """Return every path the commit touched (one per line, sans header)."""
    out = _git(
        ["diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha], workspace
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# commit-message parsing -> expected counts
# --------------------------------------------------------------------------- #


def parse_expected_breakdown(message: str) -> Tuple[Dict[str, int], Optional[int]]:
    """Parse the per-prefix expected-count rows out of the commit message.

    Returns ``(per_prefix_expected, total_expected)``. ``total_expected`` is
    ``None`` if the message did not contain a ``total: N records`` line.

    The parser walks the message line-by-line, picking up rows of the form::

        zk-auditor:            401 records  (asymmetric-research / ...
        mev-flashloan:         393 records  (canonical flash-loan ...
        total:                2098 records

    Lines that don't match are skipped. Duplicate prefixes raise to
    flag a malformed commit message.
    """
    per_prefix: Dict[str, int] = {}
    total: Optional[int] = None
    for raw in message.splitlines():
        line = raw.rstrip()
        total_m = _TOTAL_LINE_RE.match(line)
        if total_m:
            total = int(total_m.group(1))
            continue
        m = _PREFIX_LINE_RE.match(line)
        if m:
            prefix = m.group(1).lower()
            count = int(m.group(2))
            if prefix in per_prefix:
                raise ValueError(
                    f"commit message has duplicate prefix row: {prefix!r}"
                )
            per_prefix[prefix] = count
    return per_prefix, total


# --------------------------------------------------------------------------- #
# corpus parsing -> actual state
# --------------------------------------------------------------------------- #


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and (
        (v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")
    ):
        return v[1:-1]
    return v


def parse_record(path: Path) -> Dict[str, Any]:
    """Extract ``record_id``, top-level ``verification_tier``, and the
    legacy ``function_shape.shape_tags`` tier signal from a single
    record YAML or JSON file.

    Returns a dict with keys ``record_id``, ``verification_tier``,
    ``shape_tag_tier``, ``prefix`` (substring of record_id before the
    first colon), or ``_error`` for unparseable files.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"_error": f"unreadable: {exc}"}

    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return {"_error": f"json decode: {exc}"}
        if not isinstance(payload, dict):
            return {"_error": "json root is not an object"}
        record_id = payload.get("record_id") or ""
        verification_tier = payload.get("verification_tier")
        fn_shape = payload.get("function_shape") or {}
        shape_tags = fn_shape.get("shape_tags") if isinstance(fn_shape, dict) else []
        shape_tag_tier: Optional[str] = None
        if isinstance(shape_tags, list):
            for t in shape_tags:
                if not isinstance(t, str):
                    continue
                m = _VERIFICATION_TIER_VALUE_RE.match(t.strip())
                if m:
                    shape_tag_tier = m.group(1)
                    break
        prefix = record_id.split(":", 1)[0] if record_id else ""
        return {
            "record_id": record_id,
            "verification_tier": verification_tier,
            "shape_tag_tier": shape_tag_tier,
            "prefix": prefix,
        }

    # YAML scan (minimal -- consistent with sibling tools)
    record_id_value: str = ""
    verification_tier: Optional[str] = None
    shape_tag_tier: Optional[str] = None
    in_fs = False
    in_tags = False
    tags_indent: Optional[int] = None

    for raw in text.splitlines():
        if not raw.strip():
            continue
        stripped = raw.strip()
        is_top_level = not (raw.startswith(" ") or raw.startswith("\t"))

        if is_top_level:
            in_fs = False
            in_tags = False
            if stripped.startswith("record_id:"):
                _, _, rhs = stripped.partition(":")
                val = _strip_yaml_quotes(rhs.strip())
                if val:
                    record_id_value = val
            elif stripped.startswith("verification_tier:"):
                _, _, rhs = stripped.partition(":")
                val = _strip_yaml_quotes(rhs.strip())
                if val:
                    verification_tier = val
            elif stripped.startswith("function_shape:"):
                in_fs = True
            continue

        if not in_fs:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("shape_tags:"):
            in_tags = True
            tags_indent = indent
            continue
        if in_tags:
            if stripped.startswith("- "):
                if tags_indent is not None and indent >= tags_indent:
                    val = _strip_yaml_quotes(stripped[2:].strip())
                    if shape_tag_tier is None:
                        m = _VERIFICATION_TIER_VALUE_RE.match(val)
                        if m:
                            shape_tag_tier = m.group(1)
                    continue
                else:
                    in_tags = False
            else:
                if tags_indent is not None and indent <= tags_indent:
                    in_tags = False

    prefix = record_id_value.split(":", 1)[0] if record_id_value else ""
    return {
        "record_id": record_id_value,
        "verification_tier": verification_tier,
        "shape_tag_tier": shape_tag_tier,
        "prefix": prefix,
    }


def effective_tier(rec: Dict[str, Any]) -> Optional[str]:
    """Return the canonical tier string for a parsed record.

    The v1.1 top-level ``verification_tier`` wins when present;
    otherwise we fall back to the legacy ``function_shape.shape_tags``
    ``verification_tier:tier-N-*`` entry. Returns ``None`` when neither
    is present.
    """
    top = rec.get("verification_tier")
    if isinstance(top, str) and top.strip():
        return top.strip()
    legacy = rec.get("shape_tag_tier")
    if isinstance(legacy, str) and legacy.strip():
        return legacy.strip()
    return None


# --------------------------------------------------------------------------- #
# index cross-check
# --------------------------------------------------------------------------- #


def count_tier_in_index(index_path: Path) -> Tuple[int, Counter]:
    """Count tier-2 records in ``by_verification_tier.jsonl`` and return
    a per-prefix breakdown derived from record_id.

    Returns ``(tier2_total, tier2_per_prefix_counter)``. If the index
    is missing or unparseable, returns ``(0, Counter())``.
    """
    if not index_path.exists():
        return 0, Counter()
    total = 0
    per_prefix: Counter = Counter()
    try:
        with index_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("key") != TIER2_TAG:
                    continue
                total += 1
                rid = obj.get("record_id") or ""
                prefix = rid.split(":", 1)[0] if rid else ""
                if prefix:
                    per_prefix[prefix] += 1
    except OSError:
        pass
    return total, per_prefix


# --------------------------------------------------------------------------- #
# main verification flow
# --------------------------------------------------------------------------- #


def verify(
    workspace: Path,
    commit_sha: str = DEFAULT_COMMIT_SHA,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Build the JSON status pack.

    Returns a dict with overall_status ``PASS``, ``WARNING``, or ``FAIL``.
    """
    index_path = (
        workspace / "audit" / "corpus_tags" / "index" / "by_verification_tier.jsonl"
    )

    discrepancies: List[str] = []
    per_file_detail: List[Dict[str, Any]] = []

    # 1. Read the commit message & touched paths.
    try:
        message = git_show_message(commit_sha, workspace)
        touched_paths = git_show_name_only(commit_sha, workspace)
    except RuntimeError as exc:
        return {
            "schema": SCHEMA,
            "commit_sha": commit_sha,
            "overall_status": "FAIL",
            "discrepancies": [f"git read failed: {exc}"],
            "total_files_modified": 0,
            "total_records_at_tier_2": 0,
            "prefix_breakdown": {},
            "top_3_verification": {},
            "index_cross_check": {},
        }

    expected_per_prefix, expected_total = parse_expected_breakdown(message)
    if not expected_per_prefix:
        discrepancies.append(
            "commit message yielded zero prefix-row matches; falling back to "
            f"DEFAULT_EXPECTED_TOTAL={DEFAULT_EXPECTED_TOTAL}"
        )

    # 2. Filter to tag YAML/JSON files under audit/corpus_tags/tags/.
    tag_paths = [
        p for p in touched_paths if p.startswith("audit/corpus_tags/tags/")
        and (p.endswith(".yaml") or p.endswith(".json"))
    ]

    # 3. Parse each file (current state on disk) and bucket by prefix.
    actual_per_prefix_tier2: Counter = Counter()
    actual_per_prefix_total: Counter = Counter()
    missing_files: List[str] = []
    parse_errors: List[str] = []
    not_tier2: List[Dict[str, str]] = []

    for rel in tag_paths:
        abs_path = workspace / rel
        if not abs_path.exists():
            missing_files.append(rel)
            continue
        rec = parse_record(abs_path)
        if "_error" in rec:
            parse_errors.append(f"{rel}: {rec['_error']}")
            continue
        prefix = rec.get("prefix") or ""
        tier = effective_tier(rec)
        actual_per_prefix_total[prefix] += 1
        if tier == TIER2_TAG:
            actual_per_prefix_tier2[prefix] += 1
        else:
            not_tier2.append(
                {
                    "path": rel,
                    "prefix": prefix,
                    "current_tier": tier or "(none)",
                }
            )
        if verbose:
            per_file_detail.append(
                {
                    "path": rel,
                    "prefix": prefix,
                    "tier": tier,
                    "record_id": rec.get("record_id", ""),
                }
            )

    total_files_modified = len(tag_paths)
    total_records_at_tier_2 = sum(actual_per_prefix_tier2.values())

    if missing_files:
        discrepancies.append(
            f"{len(missing_files)} commit-touched file(s) missing on disk "
            f"(first: {missing_files[0]})"
        )
    if parse_errors:
        discrepancies.append(
            f"{len(parse_errors)} parse error(s) (first: {parse_errors[0]})"
        )
    if not_tier2:
        discrepancies.append(
            f"{len(not_tier2)} commit-touched record(s) NOT at {TIER2_TAG} "
            f"(first: {not_tier2[0]['path']} -> {not_tier2[0]['current_tier']})"
        )

    # 4. Build per-prefix breakdown {expected, actual, delta}.
    prefix_breakdown: Dict[str, Dict[str, int]] = {}
    all_prefixes = set(expected_per_prefix.keys()) | set(actual_per_prefix_tier2.keys())
    for prefix in sorted(all_prefixes):
        expected = expected_per_prefix.get(prefix, 0)
        actual = actual_per_prefix_tier2.get(prefix, 0)
        prefix_breakdown[prefix] = {
            "expected": expected,
            "actual": actual,
            "delta": actual - expected,
        }
        if expected and actual != expected:
            discrepancies.append(
                f"prefix {prefix!r}: expected {expected}, found {actual}, "
                f"delta {actual - expected:+d}"
            )
        if not expected and actual:
            discrepancies.append(
                f"prefix {prefix!r}: unexpected (no expected count in commit "
                f"message), actual={actual}"
            )

    # 5. Top-3 verification (zk-auditor / mev-flashloan / mev-exploits).
    top_3_verification: Dict[str, Dict[str, Any]] = {}
    for prefix in ("zk-auditor", "mev-flashloan", "mev-exploits"):
        b = prefix_breakdown.get(prefix, {"expected": 0, "actual": 0, "delta": 0})
        status = "PASS" if b["delta"] == 0 and b["expected"] > 0 else "FAIL"
        if b["expected"] == 0:
            status = "FAIL"
        top_3_verification[prefix] = {
            "expected": b["expected"],
            "actual": b["actual"],
            "delta": b["delta"],
            "status": status,
        }
        if status != "PASS":
            discrepancies.append(
                f"top-3 prefix {prefix!r} verification FAIL: "
                f"expected={b['expected']} actual={b['actual']}"
            )

    # 6. Index cross-check.
    index_tier2_total, index_tier2_per_prefix = count_tier_in_index(index_path)
    index_cross_check: Dict[str, Any] = {
        "index_path": str(
            index_path.relative_to(workspace) if index_path.is_absolute() else index_path
        ),
        "index_present": index_path.exists(),
        "index_tier2_total": index_tier2_total,
        "per_prefix_consistency": {},
    }
    inconsistent: List[str] = []
    for prefix, breakdown in prefix_breakdown.items():
        if breakdown["expected"] == 0:
            continue
        actual_corpus = breakdown["actual"]
        actual_index = index_tier2_per_prefix.get(prefix, 0)
        cmp = {
            "corpus": actual_corpus,
            "index": actual_index,
            "delta": actual_index - actual_corpus,
        }
        index_cross_check["per_prefix_consistency"][prefix] = cmp
        if actual_index < actual_corpus:
            inconsistent.append(
                f"index undercounts prefix {prefix!r}: corpus={actual_corpus}, "
                f"index={actual_index}"
            )
    if inconsistent and index_cross_check["index_present"]:
        discrepancies.extend(inconsistent)

    # 7. Overall status.
    fail_signals = (
        bool(missing_files)
        or bool(parse_errors)
        or bool(not_tier2)
        or any(b["delta"] != 0 and b["expected"] > 0 for b in prefix_breakdown.values())
        or any(b["expected"] == 0 and b["actual"] > 0 for b in prefix_breakdown.values())
        or any(v["status"] != "PASS" for v in top_3_verification.values())
    )
    warning_signals = bool(inconsistent) and not fail_signals
    if fail_signals:
        overall = "FAIL"
    elif warning_signals:
        overall = "WARNING"
    else:
        overall = "PASS"

    # Compare expected_total from commit msg vs sum of expected_per_prefix.
    expected_sum = sum(expected_per_prefix.values())
    total_check = {
        "commit_message_total_field": expected_total,
        "commit_message_per_prefix_sum": expected_sum,
        "actual_tier2_among_touched": total_records_at_tier_2,
        "default_expected_total_fallback": DEFAULT_EXPECTED_TOTAL,
    }
    if expected_total is not None and expected_total != expected_sum:
        discrepancies.append(
            f"commit message total ({expected_total}) != sum of "
            f"per-prefix rows ({expected_sum})"
        )

    out: Dict[str, Any] = {
        "schema": SCHEMA,
        "commit_sha": commit_sha,
        "total_files_modified": total_files_modified,
        "total_records_at_tier_2": total_records_at_tier_2,
        "prefix_breakdown": prefix_breakdown,
        "top_3_verification": top_3_verification,
        "index_cross_check": index_cross_check,
        "total_check": total_check,
        "discrepancies": discrepancies,
        "overall_status": overall,
    }
    if verbose:
        out["per_file_detail"] = per_file_detail
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wave2-w25-tier3-promotion-verify",
        description=(
            "Independently verify the W2.5 tier-3 -> tier-2 promotion claim "
            "(commit d0e3722d0b, 2098 records across 13 prefixes)."
        ),
    )
    p.add_argument(
        "--workspace",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repo root containing audit/corpus_tags/ (default: parent of tools/).",
    )
    p.add_argument(
        "--commit-sha",
        default=DEFAULT_COMMIT_SHA,
        help="Commit SHA to verify (default: d0e3722d0b).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the full JSON status pack (otherwise prints a short summary).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on overall_status=FAIL.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Include per-file detail in JSON output.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)
    try:
        result = verify(
            workspace=args.workspace.resolve(),
            commit_sha=args.commit_sha,
            verbose=args.verbose,
        )
    except Exception as exc:  # noqa: BLE001 -- top-level CLI guard
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"commit:               {result['commit_sha']}")
        print(f"overall_status:       {result['overall_status']}")
        print(f"total_files_modified: {result['total_files_modified']}")
        print(f"total_records_at_tier_2: {result['total_records_at_tier_2']}")
        print("top_3_verification:")
        for prefix, info in result["top_3_verification"].items():
            print(
                f"  {prefix:15s} expected={info['expected']:>4}  "
                f"actual={info['actual']:>4}  delta={info['delta']:+d}  "
                f"status={info['status']}"
            )
        if result["discrepancies"]:
            print(f"discrepancies ({len(result['discrepancies'])}):")
            for d in result["discrepancies"][:10]:
                print(f"  - {d}")
            if len(result["discrepancies"]) > 10:
                print(f"  ... ({len(result['discrepancies']) - 10} more)")

    if args.strict and result["overall_status"] == "FAIL":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
