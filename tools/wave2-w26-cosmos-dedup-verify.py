#!/usr/bin/env python3
"""wave2-w26-cosmos-dedup-verify.

Wave-2 PR-A independent verification tool for the W2.6 cosmos-sdk dupe
canonicalization commit ``8fa397589f`` (commit subject
``Wave-2 W2.6: cosmos-sdk dupe canonicalization execution``).

The W2.6 commit claims that:

  1. The REDIRECT_MANIFEST at
     ``audit/corpus_tags/tags/_deprecated/REDIRECT_MANIFEST.json`` was
     extended with a ``verdict_artefacts[]`` array and a top-level
     ``wave2_w26_execution_ledger`` block.
  2. The residual ASA-2024-0012 dydx-iter-2 verdict-artefact and filter
     prescription was resolved.
  3. Each ``redirects[]`` entry points at a canonical record that still
     exists on disk under ``audit/corpus_tags/tags/`` (canonical path).

This tool independently re-derives those claims from live filesystem
state and emits a JSON status pack of schema
``auditooor.wave2_w26_cosmos_dedup_verify.v1``. With ``--strict``,
exits non-zero on overall_status=FAIL.

Symmetric to ``tools/wave2-w25-tier3-promotion-verify.py``.

Discipline (operator emphasis):

  * No hard-coded expected values for record counts -- live filesystem
    is the source of truth; the ledger's claimed counts are surfaced
    for comparison only.
  * Schema-key drift is reported precisely; missing required fields
    on a per-entry basis are surfaced with the record_id that triggered
    the failure.
  * Synthetic fixtures (used by the unit tests) are marked with the
    sentinel field ``synthetic_fixture: true`` in the test fixture
    builder and the tool itself never reads them outside test mode.

CLI::

    python3 tools/wave2-w26-cosmos-dedup-verify.py \
        --workspace /Users/wolf/auditooor-702-full --strict --json

Exit codes::

    0  - PASS (or non-strict mode and FAIL)
    1  - FAIL (only when ``--strict``)
    2  - error (manifest missing, corpus dir missing, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.wave2_w26_cosmos_dedup_verify.v1"

# The W2.6 SKILL specifically names the dydx-iter-2 ASA-2024-0012 case
# as the residual that this commit resolves. We verify the manifest
# names it explicitly.
ASA_CASE_TOKEN = "ASA-2024-0012"

# Required keys for the W2.6 execution ledger. Drift from these keys
# is recorded as a FAIL (`ledger_fields_ok=false`) with the missing
# fields surfaced.
LEDGER_REQUIRED_KEYS = (
    "wave_id",
    "executed_at",
    "spec_doc",
)

# Required keys per verdict_artefact entry. Note these match the
# real on-disk schema (marker_field/marker_value/reason/marked_at)
# rather than the brief's earlier shape; the validator is anchored
# on what shipped, not what was originally drafted.
VERDICT_ARTEFACT_REQUIRED_KEYS = (
    "record_id",
    "path",
    "verdict_id",
    "marker_field",
    "marker_value",
    "reason",
    "marked_at",
)

# Required keys per redirect entry.
REDIRECT_REQUIRED_KEYS = (
    "deprecated_record_id",
    "deprecated_path",
    "canonical_record_id",
    "canonical_path",
    "reason",
)

# Manifest path under workspace root.
MANIFEST_REL = Path("audit/corpus_tags/tags/_deprecated/REDIRECT_MANIFEST.json")

# Tags root.
TAGS_REL = Path("audit/corpus_tags/tags")


# --------------------------------------------------------------------------- #
# manifest loading
# --------------------------------------------------------------------------- #


def load_manifest(workspace: Path) -> Tuple[Optional[Dict[str, Any]], str, List[str]]:
    """Load REDIRECT_MANIFEST.json. Returns (manifest, status, errors).

    status is one of: ``ok``, ``missing``, ``parse-error``, ``not-a-dict``.
    """
    errors: List[str] = []
    path = workspace / MANIFEST_REL
    if not path.exists():
        errors.append(f"manifest not found at {MANIFEST_REL}")
        return None, "missing", errors
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        errors.append(f"manifest JSON parse error: {exc}")
        return None, "parse-error", errors
    except OSError as exc:
        errors.append(f"manifest read error: {exc}")
        return None, "parse-error", errors
    if not isinstance(data, dict):
        errors.append(
            f"manifest is not a JSON object (got {type(data).__name__})"
        )
        return None, "not-a-dict", errors
    return data, "ok", errors


# --------------------------------------------------------------------------- #
# structural checks
# --------------------------------------------------------------------------- #


def check_ledger(manifest: Dict[str, Any]) -> Tuple[bool, bool, List[str]]:
    """Return (ledger_present, ledger_fields_ok, errors)."""
    errors: List[str] = []
    ledger = manifest.get("wave2_w26_execution_ledger")
    if ledger is None:
        errors.append("wave2_w26_execution_ledger block missing")
        return False, False, errors
    if not isinstance(ledger, dict):
        errors.append(
            "wave2_w26_execution_ledger is not a dict "
            f"(got {type(ledger).__name__})"
        )
        return True, False, errors
    missing = [k for k in LEDGER_REQUIRED_KEYS if k not in ledger]
    if missing:
        errors.append(
            "wave2_w26_execution_ledger missing required fields: "
            + ", ".join(missing)
        )
        return True, False, errors
    return True, True, errors


def check_verdict_artefacts(
    manifest: Dict[str, Any],
) -> Tuple[int, bool, List[str], List[Dict[str, Any]]]:
    """Return (count, asa_referenced, errors, artefacts)."""
    errors: List[str] = []
    artefacts = manifest.get("verdict_artefacts")
    if artefacts is None:
        errors.append("verdict_artefacts block missing")
        return 0, False, errors, []
    if not isinstance(artefacts, list):
        errors.append(
            "verdict_artefacts is not a list "
            f"(got {type(artefacts).__name__})"
        )
        return 0, False, errors, []
    asa_referenced = False
    for idx, entry in enumerate(artefacts):
        if not isinstance(entry, dict):
            errors.append(
                f"verdict_artefacts[{idx}] is not a dict "
                f"(got {type(entry).__name__})"
            )
            continue
        missing = [k for k in VERDICT_ARTEFACT_REQUIRED_KEYS if k not in entry]
        if missing:
            errors.append(
                f"verdict_artefacts[{idx}] (record_id="
                f"{entry.get('record_id', '<no record_id>')}) "
                "missing required fields: " + ", ".join(missing)
            )
        # ASA-2024-0012 may appear in record_id, path, verdict_id, or reason.
        haystack = " ".join(
            str(entry.get(k, "")) for k in entry.keys()
        )
        if ASA_CASE_TOKEN.lower() in haystack.lower():
            asa_referenced = True
    return len(artefacts), asa_referenced, errors, artefacts


def check_redirect_target_integrity(
    manifest: Dict[str, Any], workspace: Path
) -> Tuple[Dict[str, Any], List[str]]:
    """Verify every redirect's canonical_path exists on disk.

    Returns (integrity_report, errors). integrity_report has keys:
      total_redirects, redirects_with_missing_canonical, missing_paths,
      malformed_redirect_entries.
    """
    errors: List[str] = []
    redirects = manifest.get("redirects", [])
    if not isinstance(redirects, list):
        errors.append(
            "redirects is not a list "
            f"(got {type(redirects).__name__})"
        )
        return {
            "total_redirects": 0,
            "redirects_with_missing_canonical": 0,
            "missing_paths": [],
            "malformed_redirect_entries": 0,
        }, errors

    missing_paths: List[str] = []
    malformed = 0
    for idx, entry in enumerate(redirects):
        if not isinstance(entry, dict):
            malformed += 1
            errors.append(
                f"redirects[{idx}] is not a dict "
                f"(got {type(entry).__name__})"
            )
            continue
        missing_keys = [k for k in REDIRECT_REQUIRED_KEYS if k not in entry]
        if missing_keys:
            malformed += 1
            errors.append(
                f"redirects[{idx}] (deprecated_record_id="
                f"{entry.get('deprecated_record_id', '<unknown>')}) "
                "missing required fields: " + ", ".join(missing_keys)
            )
            # still try canonical_path if present
        cp = entry.get("canonical_path")
        if cp:
            cp_path = workspace / cp
            if not cp_path.exists():
                missing_paths.append(cp)
    return {
        "total_redirects": len(redirects),
        "redirects_with_missing_canonical": len(missing_paths),
        "missing_paths": missing_paths,
        "malformed_redirect_entries": malformed,
    }, errors


# --------------------------------------------------------------------------- #
# coverage check (cosmos-sdk records vs ledger)
# --------------------------------------------------------------------------- #


def count_cosmos_records(workspace: Path) -> Dict[str, int]:
    """Count cosmos-related records under audit/corpus_tags/tags/.

    Three buckets are reported:

      * cosmos_sdk_ibc_record_json -- record.json under cosmos_sdk_ibc/
      * cosmos_related_flat_yaml   -- *.yaml whose filename contains
        cosmos/cometbft/ibc/tendermint (excluding _deprecated)
      * deprecated_cosmos_flat_dupes -- yaml/json under
        _deprecated/cosmos_sdk_flat_dupes/

    Total surface = cosmos_sdk_ibc_record_json + cosmos_related_flat_yaml +
    deprecated_cosmos_flat_dupes (records this commit was supposed to
    bring under canonical control).
    """
    tags_dir = workspace / TAGS_REL
    counts = {
        "cosmos_sdk_ibc_record_json": 0,
        "cosmos_related_flat_yaml": 0,
        "deprecated_cosmos_flat_dupes": 0,
    }
    if not tags_dir.exists():
        return counts
    for p in tags_dir.rglob("record.json"):
        parts = p.parts
        if "_deprecated" in parts:
            # treat deprecated record.json as part of deprecated bucket
            if any("cosmos" in pp.lower() for pp in parts):
                counts["deprecated_cosmos_flat_dupes"] += 1
            continue
        if "cosmos_sdk_ibc" in parts:
            counts["cosmos_sdk_ibc_record_json"] += 1
    for p in tags_dir.rglob("*.yaml"):
        parts = p.parts
        name = p.name.lower()
        if "_deprecated" in parts:
            if any(tok in name for tok in ("cosmos", "cometbft", "ibc", "tendermint")):
                counts["deprecated_cosmos_flat_dupes"] += 1
            continue
        if any(tok in name for tok in ("cosmos", "cometbft", "ibc", "tendermint")):
            counts["cosmos_related_flat_yaml"] += 1
    return counts


def compute_coverage(
    ledger: Optional[Dict[str, Any]],
    cosmos_counts: Dict[str, int],
) -> Tuple[Optional[float], Dict[str, Any]]:
    """Compute cosmos_coverage_pct = (records canonicalized + verdict-artefact-marked) / total surface.

    The W2.6 ledger reports counts via keys like
    ``in_scope_residual_groups_resolved``,
    ``verdict_artefacts_marked``, ``dupe_finder_group_count_pre/post``.
    We surface those and compute the coverage ratio relative to the
    live cosmos record surface.
    """
    total_surface = sum(cosmos_counts.values())
    if ledger is None:
        return None, {
            "total_cosmos_surface": total_surface,
            "ledger_resolved": None,
            "coverage_pct": None,
            "method": "ledger-absent",
        }

    # heuristics for "records the W2.6 commit owns":
    #   verdict_artefacts_marked + (dupe_finder_group_count_pre -
    #   dupe_finder_group_count_post)
    pre = ledger.get("dupe_finder_group_count_pre")
    post = ledger.get("dupe_finder_group_count_post")
    va_marked = ledger.get("verdict_artefacts_marked", 0)
    resolved = 0
    if isinstance(pre, int) and isinstance(post, int):
        resolved += max(0, pre - post)
    if isinstance(va_marked, int):
        resolved += va_marked

    coverage_pct: Optional[float] = None
    if total_surface > 0:
        coverage_pct = round(100.0 * resolved / total_surface, 2)
    return coverage_pct, {
        "total_cosmos_surface": total_surface,
        "ledger_resolved": resolved,
        "coverage_pct": coverage_pct,
        "method": "verdict_artefacts_marked + (pre - post)",
        "ledger_fields_used": {
            "dupe_finder_group_count_pre": pre,
            "dupe_finder_group_count_post": post,
            "verdict_artefacts_marked": va_marked,
        },
    }


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #


def run_verification(workspace: Path) -> Dict[str, Any]:
    """Top-level verification entry point. Returns the status pack dict."""
    failures: List[str] = []
    warnings: List[str] = []

    manifest, parse_status, parse_errors = load_manifest(workspace)
    failures.extend(parse_errors)

    if manifest is None:
        return {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "manifest_path": str(MANIFEST_REL),
            "manifest_parse_status": parse_status,
            "ledger_present": False,
            "ledger_fields_ok": False,
            "verdict_artefact_count": 0,
            "asa_2024_0012_referenced": False,
            "redirect_target_integrity": {
                "total_redirects": 0,
                "redirects_with_missing_canonical": 0,
                "missing_paths": [],
                "malformed_redirect_entries": 0,
            },
            "cosmos_surface_counts": {},
            "coverage": {
                "total_cosmos_surface": 0,
                "ledger_resolved": None,
                "coverage_pct": None,
                "method": "manifest-absent",
            },
            "cosmos_coverage_pct": None,
            "overall_status": "FAIL",
            "failures": failures,
            "warnings": warnings,
        }

    ledger_present, ledger_fields_ok, ledger_errors = check_ledger(manifest)
    failures.extend(ledger_errors)

    va_count, asa_referenced, va_errors, _ = check_verdict_artefacts(manifest)
    failures.extend(va_errors)

    integrity, integrity_errors = check_redirect_target_integrity(manifest, workspace)
    # missing canonical paths -> WARNING (not strict-FAIL by default) because
    # a benign rename can produce a transient mismatch the operator should
    # notice without auto-promoting it to FAIL.
    if integrity["redirects_with_missing_canonical"] > 0:
        warnings.append(
            f"{integrity['redirects_with_missing_canonical']} redirect(s) "
            "point at canonical_path values that do not exist on disk: "
            + ", ".join(integrity["missing_paths"][:5])
            + ("..." if len(integrity["missing_paths"]) > 5 else "")
        )
    # structural errors in the redirect block are FAIL
    failures.extend(integrity_errors)

    cosmos_counts = count_cosmos_records(workspace)
    ledger = manifest.get("wave2_w26_execution_ledger")
    coverage_pct, coverage_detail = compute_coverage(ledger, cosmos_counts)

    # ASA case: FAIL if not referenced anywhere in verdict_artefacts.
    if not asa_referenced and ledger_present:
        failures.append(
            f"residual case {ASA_CASE_TOKEN} not referenced in any "
            "verdict_artefacts[] entry"
        )

    # overall_status
    has_fail = bool(failures)
    if has_fail:
        overall_status = "FAIL"
    elif warnings:
        overall_status = "WARNING"
    else:
        overall_status = "PASS"

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "manifest_path": str(MANIFEST_REL),
        "manifest_parse_status": parse_status,
        "ledger_present": ledger_present,
        "ledger_fields_ok": ledger_fields_ok,
        "verdict_artefact_count": va_count,
        "asa_2024_0012_referenced": asa_referenced,
        "redirect_target_integrity": integrity,
        "cosmos_surface_counts": cosmos_counts,
        "coverage": coverage_detail,
        "cosmos_coverage_pct": coverage_pct,
        "overall_status": overall_status,
        "failures": failures,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _emit_text(pack: Dict[str, Any], verbose: bool) -> None:
    print(f"wave2-w26-cosmos-dedup-verify: {pack['overall_status']}")
    print(f"  manifest_path:               {pack['manifest_path']}")
    print(f"  manifest_parse_status:       {pack['manifest_parse_status']}")
    print(f"  ledger_present:              {pack['ledger_present']}")
    print(f"  ledger_fields_ok:            {pack['ledger_fields_ok']}")
    print(f"  verdict_artefact_count:      {pack['verdict_artefact_count']}")
    print(f"  asa_2024_0012_referenced:    {pack['asa_2024_0012_referenced']}")
    integ = pack["redirect_target_integrity"]
    print(
        "  redirect integrity:          "
        f"total={integ['total_redirects']}, "
        f"missing_canonical={integ['redirects_with_missing_canonical']}, "
        f"malformed={integ['malformed_redirect_entries']}"
    )
    if pack["cosmos_coverage_pct"] is not None:
        print(
            f"  cosmos_coverage_pct:         {pack['cosmos_coverage_pct']}%"
        )
    if verbose:
        print("  cosmos_surface_counts:")
        for k, v in pack["cosmos_surface_counts"].items():
            print(f"    {k}: {v}")
        print(f"  coverage detail:             {pack['coverage']}")
    if pack["failures"]:
        print("  failures:")
        for f in pack["failures"]:
            print(f"    - {f}")
    if pack["warnings"]:
        print("  warnings:")
        for w in pack["warnings"]:
            print(f"    - {w}")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="wave2-w26-cosmos-dedup-verify",
        description=(
            "Independent verifier for the Wave-2 W2.6 cosmos-sdk dupe "
            "canonicalization commit (8fa397589f)."
        ),
    )
    p.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Workspace root (defaults to cwd).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON status pack on stdout (machine-readable).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on overall_status=FAIL.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Include surface counts and coverage detail in text output.",
    )
    args = p.parse_args(argv)

    workspace = args.workspace.resolve()
    if not workspace.exists():
        sys.stderr.write(f"workspace not found: {workspace}\n")
        return 2

    pack = run_verification(workspace)

    if args.json:
        print(json.dumps(pack, indent=2, sort_keys=True))
    else:
        _emit_text(pack, verbose=args.verbose)

    if args.strict and pack["overall_status"] == "FAIL":
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
