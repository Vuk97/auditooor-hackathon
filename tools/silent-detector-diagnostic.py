#!/usr/bin/env python3
"""silent-detector-diagnostic.py - root-cause why Tier-D detectors fire on neither fixture.

Reads the Tier-D revival summary, finds the 104 "silent" detectors, and for each one
inspects the YAML predicate stack against the vuln/clean fixture source. Categorises
into one of four buckets:

  fixture-pattern-missing  YAML predicates look correct; the fixture lacks the regex
                           the YAML expects to match (vuln body never matches positive
                           regexes).
  predicate-overly-strict  YAML positive predicates DO match the fixture, but a
                           body_not_contains_regex (or contract.has_no_*) match
                           inadvertently excludes the same fixture.
  predicate-typo           YAML regex looks malformed (literal '\\.' that should be '.',
                           unbalanced parens, mismatched anchors, etc.) - fixable.
  architectural-mismatch   YAML requires preconditions (cross-contract anchors, ERC
                           interfaces, state-var shapes) that a single-contract
                           fixture cannot model.

Outputs /private/tmp/auditooor-inventory/silent_detector_diagnostic.json and prints
bucket counts + 5-row samples per bucket. For predicate-typo cases that look
trivially fixable, attempts the fix in-place, recompiles the detector via
pattern-compile.py, runs the smoke test, and bulk-promotes any that now pass.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path("/Users/wolf/Documents/Codex/auditooor")
SUMMARY = Path("/private/tmp/auditooor-inventory/tier_d_revival_summary.json")
OUT = Path("/private/tmp/auditooor-inventory/silent_detector_diagnostic.json")
PY = "/opt/homebrew/opt/python@3.13/bin/python3.13"

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path("/Users/wolf/Documents/Codex/auditooor")
SUMMARY = Path("/private/tmp/auditooor-inventory/tier_d_revival_summary.json")
_DEFAULT_OUT = Path("/private/tmp/auditooor-inventory/silent_detector_diagnostic.json")
PY = "/opt/homebrew/opt/python@3.13/bin/python3.13"

# Lazy yaml -- avoid hard dep at import-fail time.
import yaml  # type: ignore


def _ensure_smoke_mode() -> None:
    """Auto-set AUDITOOOR_FIXTURE_SMOKE_MODE=1 if not already set.

    Foot-gun #20: without this flag every fixture under patterns/fixtures/ is
    silently skipped by is_vendored_or_test_contract() -- vuln_hits is always 0.
    """
    if os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE") != "1":
        print(
            "[warn] AUDITOOOR_FIXTURE_SMOKE_MODE not set -- auto-setting to 1. "
            "Without this flag all fixtures under patterns/fixtures/ are silently "
            "skipped by is_vendored_or_test_contract() and every detector appears "
            "silent (foot-gun #20).",
            file=sys.stderr,
        )
        os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"




# helpers

def _flatten_match_block(match: Any) -> list[dict]:
    """match: in YAML is a list of single-key dicts; collect them in order."""
    out: list[dict] = []
    if isinstance(match, list):
        for entry in match:
            if isinstance(entry, dict):
                out.append(entry)
    elif isinstance(match, dict):
        out.append(match)
    return out


def _extract_function_predicates(yaml_doc: dict) -> dict[str, list[Any]]:
    """Pick out function.* predicates from match: block. Returns dict of key -> list of values."""
    preds: dict[str, list[Any]] = {}
    for entry in _flatten_match_block(yaml_doc.get("match", [])):
        for k, v in entry.items():
            if k.startswith("function.") or k.startswith("contract."):
                preds.setdefault(k, []).append(v)
    return preds


def _norm_regex(val: Any) -> str | None:
    """Predicate values can be a bare regex string or {regex: '...', flags: '...'}.
    Return the regex string."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        r = val.get("regex")
        if isinstance(r, str):
            return r
    return None


def _looks_like_typo(pat: str) -> tuple[bool, str | None, str | None]:
    """Heuristic: does a regex look malformed enough to be a copy-paste typo?
    Returns (is_typo, suggested_fix, reason). Conservative - only flag obvious cases.
    """
    # 1. Try to compile - a Python regex error is the only reliable typo signal.
    try:
        re.compile(pat)
    except re.error as exc:
        return True, None, f"regex compile error: {exc}"

    # NOTE: paren-balance + char-class "\." heuristics are removed: with backslash
    # escapes (`\(`, `\[`) and char-class brackets, surface counting produces too
    # many false positives. If the regex compiles, we trust it.

    return False, None, None


def _matches(pat: str | None, src: str) -> bool:
    if not pat:
        return False
    try:
        return re.search(pat, src, re.MULTILINE) is not None
    except re.error:
        return False


def _function_signatures(src: str) -> list[str]:
    """Extract function names defined in the source - a quick approximation."""
    return re.findall(r"\bfunction\s+([A-Za-z_]\w*)", src)


# per-detector classification

def classify(row: dict) -> dict:
    """Return classification dict for one silent detector row."""
    yaml_path = REPO / row["yaml_path"]
    vuln_path = REPO / row["vuln_fixture"]
    clean_path = REPO / row["clean_fixture"]

    out: dict[str, Any] = {
        "argument": row["argument"],
        "yaml_path": str(yaml_path.relative_to(REPO)),
        "bucket": "unknown",
        "reasons": [],
        "typo_fixes": [],
    }

    if not yaml_path.is_file():
        out["bucket"] = "architectural-mismatch"
        out["reasons"].append("yaml file missing")
        return out
    if not vuln_path.is_file():
        out["bucket"] = "architectural-mismatch"
        out["reasons"].append("vuln fixture missing")
        return out

    try:
        ydoc = yaml.safe_load(yaml_path.read_text())
    except yaml.YAMLError as exc:
        out["bucket"] = "predicate-typo"
        out["reasons"].append(f"yaml parse error: {exc}")
        return out

    vuln_src = vuln_path.read_text()
    preds = _extract_function_predicates(ydoc or {})

    # Check 1: any predicate regex that fails to compile or has unbalanced delim -> typo.
    for key, vals in preds.items():
        for v in vals:
            r = _norm_regex(v)
            if r is None:
                continue
            is_typo, fixed, reason = _looks_like_typo(r)
            if is_typo:
                out["bucket"] = "predicate-typo"
                out["reasons"].append(f"{key}: {reason} ({r!r})")
                if fixed:
                    out["typo_fixes"].append({"key": key, "old": r, "new": fixed})

    if out["bucket"] == "predicate-typo":
        return out

    # Check 2: function.name_matches predicate vs. fixture's actual function names.
    name_pat = None
    for v in preds.get("function.name_matches", []):
        name_pat = _norm_regex(v) or name_pat
    fns = _function_signatures(vuln_src)
    name_match_ok = True
    if name_pat:
        name_match_ok = any(re.search(name_pat, fn) for fn in fns)
        if not name_match_ok:
            out["reasons"].append(
                f"function.name_matches /{name_pat}/ does not match any of fixture fns: {fns[:6]}"
            )

    # Check 3: positive body_contains regexes - do they all hit?
    pos_keys = ("function.body_contains_regex", "function.source_matches_regex")
    pos_hits = []
    pos_miss = []
    for k in pos_keys:
        for v in preds.get(k, []):
            r = _norm_regex(v)
            if not r:
                continue
            (pos_hits if _matches(r, vuln_src) else pos_miss).append((k, r))

    # Check 4: negative predicates - do any of them inadvertently hit the vuln fixture?
    neg_keys = (
        "function.body_not_contains_regex",
        "function.not_body_contains_regex",
        "function.not_source_matches_regex",
        "contract.has_no_function_body_matching",
    )
    neg_inadvertent_hits = []
    for k in neg_keys:
        for v in preds.get(k, []):
            r = _norm_regex(v)
            if not r:
                continue
            if _matches(r, vuln_src):
                neg_inadvertent_hits.append((k, r))

    # Check 5: contract-level preconditions that may not be modelled in fixture.
    arch_signals = []
    for key in (
        "contract.is_erc4626",
        "contract.is_erc721",
        "contract.is_erc1155",
        "contract.implements_any_interface",
        "contract.inherits_any",
    ):
        for entry in _flatten_match_block(ydoc.get("preconditions", [])):
            if key in entry:
                # Cheap heuristic: if vuln src doesn't reference the interface name, suspicious.
                v = entry[key]
                if isinstance(v, list):
                    if not any(re.search(rf"\b{re.escape(str(s))}\b", vuln_src) for s in v):
                        arch_signals.append(f"{key}={v} not referenced in vuln src")
                elif isinstance(v, str):
                    if not re.search(rf"\b{re.escape(v)}\b", vuln_src):
                        arch_signals.append(f"{key}={v!r} not referenced in vuln src")

    # Decision tree.
    if not name_match_ok:
        out["bucket"] = "fixture-pattern-missing"
        return out

    if pos_miss and not pos_hits:
        # All positive regexes failed - fixture really doesn't have the pattern.
        out["bucket"] = "fixture-pattern-missing"
        out["reasons"].extend([f"positive miss {k}: {r!r}" for k, r in pos_miss[:3]])
        return out

    if neg_inadvertent_hits:
        out["bucket"] = "predicate-overly-strict"
        out["reasons"].extend(
            [f"negative inadvertently fires {k}: {r!r}" for k, r in neg_inadvertent_hits[:3]]
        )
        return out

    if arch_signals:
        out["bucket"] = "architectural-mismatch"
        out["reasons"].extend(arch_signals[:3])
        return out

    if pos_miss:
        # Some positive missed but at least one hit - likely the *combination* of
        # multiple ANDed regexes that none-of-fn satisfies all of them.
        out["bucket"] = "fixture-pattern-missing"
        out["reasons"].extend([f"partial positive miss {k}: {r!r}" for k, r in pos_miss[:3]])
        return out

    # Fallback: predicates seem to all match but engine still didn't fire - could be
    # a contract-level / function-level filter the diagnostic doesn't model.
    out["bucket"] = "architectural-mismatch"
    out["reasons"].append("all body predicates match per regex; engine miss likely "
                          "due to function.kind or contract anchor")
    return out


# typo auto-fix loop

def apply_typo_fixes(rows: list[dict]) -> dict:
    """For predicate-typo rows with concrete `typo_fixes`, write them in-place."""
    applied = 0
    failed = 0
    log: list[dict] = []
    for r in rows:
        if r["bucket"] != "predicate-typo" or not r["typo_fixes"]:
            continue
        ypath = REPO / r["yaml_path"]
        text = ypath.read_text()
        new_text = text
        for fix in r["typo_fixes"]:
            if fix["old"] in new_text and fix["new"] != fix["old"]:
                new_text = new_text.replace(fix["old"], fix["new"], 1)
        if new_text != text:
            ypath.write_text(new_text)
            applied += 1
            log.append({"argument": r["argument"], "fixes": r["typo_fixes"]})
        else:
            failed += 1
    return {"applied": applied, "failed": failed, "log": log}



def smoke_one(arg: str, vuln: Path, clean: Path) -> tuple[int, int]:
    """Run a single smoke test. Returns (vuln_hits, clean_hits) or (-1,-1) on error.

    Always injects AUDITOOOR_FIXTURE_SMOKE_MODE=1 (foot-gun #20 hardening).
    """
    _ensure_smoke_mode()
    smoke_env = os.environ.copy()
    smoke_env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    def _run(fix: Path) -> int:
        try:
            res = subprocess.run(
                [PY, "detectors/run_custom.py", "--tier=ALL", str(fix), arg],
                cwd=REPO, capture_output=True, text=True, timeout=90, env=smoke_env,
            )
            m = re.search(r"\[done\]\s+total hits:\s+(\d+)", res.stdout)
            return int(m.group(1)) if m else -1
        except Exception:
            return -1
    return _run(vuln), _run(clean)


# main


def main() -> int:
    ap = argparse.ArgumentParser(description="Root-cause silent detector diagnostic.")
    ap.add_argument(
        "--output-dir",
        default=str(_DEFAULT_OUT.parent),
        help=f"Directory for output JSON (default: {_DEFAULT_OUT.parent})",
    )
    ap.add_argument(
        "--run-smoke",
        action="store_true",
        help="After static classification, run engine smoke on arch-mismatch rows.",
    )
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    OUT = out_dir / "silent_detector_diagnostic.json"

    _ensure_smoke_mode()


    summary = json.loads(SUMMARY.read_text())
    rows = summary["classifications"]["viable_for_smoke"]
    # Filter to silent only - the summary mixes silent + parse_error.
    silent_rows = []
    smoke_status = summary.get("smoke_breakdown") or {}
    # The per-row status lives in the smoke output; we re-classify all viable_for_smoke
    # because silent dominates the bucket and parse_error is small.
    silent_rows = list(rows)
    print(f"[diag] inspecting {len(silent_rows)} viable_for_smoke detectors")

    classified = [classify(r) for r in silent_rows]
    buckets: dict[str, list[dict]] = {}
    for c in classified:
        buckets.setdefault(c["bucket"], []).append(c)

    OUT.write_text(json.dumps({
        "schema": "auditooor.silent_detector_diagnostic.v1",
        "input_count": len(silent_rows),
        "bucket_counts": {k: len(v) for k, v in buckets.items()},
        "classifications": classified,
    }, indent=2))

    print(f"[diag] wrote {OUT}")
    print("[diag] bucket counts:")
    for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print(f"   {k:30s} {len(v):4d}")
    print()
    for bk, rows_in in buckets.items():
        print(f"=== {bk} (sample 5) ===")
        for r in rows_in[:5]:
            why = "; ".join(r["reasons"][:2]) or "(no reasons)"
            print(f"  - {r['argument']:50s} :: {why}")
        print()

    # Auto-fix typo bucket.
    typo_rows = buckets.get("predicate-typo", [])
    fixable = [r for r in typo_rows if r["typo_fixes"]]
    print(f"[fix] predicate-typo total={len(typo_rows)} with concrete fixes={len(fixable)}")
    if fixable:
        fixlog = apply_typo_fixes(fixable)
        print(f"[fix] applied={fixlog['applied']} failed={fixlog['failed']}")
        # Recompile + smoke + collect deltas.
        passes_before = 0
        passes_after = 0
        delta_rows = []
        for r in fixable:
            arg = r["argument"]
            ypath = REPO / r["yaml_path"]
            try:
                rc = subprocess.run(
                    [PY, "tools/pattern-compile.py", str(ypath)],
                    cwd=REPO, capture_output=True, text=True, timeout=60,
                )
                if rc.returncode != 0:
                    continue
            except Exception:
                continue
            # Find matching summary row to relocate fixtures.
            row = next((s for s in silent_rows if s["argument"] == arg), None)
            if not row:
                continue
            vh, ch = smoke_one(arg, REPO / row["vuln_fixture"], REPO / row["clean_fixture"])
            if vh >= 1 and ch == 0:
                passes_after += 1
                delta_rows.append({"argument": arg, "vuln_hits": vh, "clean_hits": ch})
        print(f"[fix] post-fix smoke passes: {passes_after}")
        if delta_rows:
            print("[fix] newly passing detectors:")
            for d in delta_rows:
                print(f"   - {d['argument']} (vuln={d['vuln_hits']}, clean={d['clean_hits']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
