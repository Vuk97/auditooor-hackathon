#!/usr/bin/env python3
"""
CCIA for Rust/Soroban — Advisory-only attack-angle surveyor.

Iter10 T1 — NEW separate tool (NOT an extension of `tools/ccia.py`). The
Solidity CCIA is AST-style regex driven and Solidity-parser shaped. The
Rust/Soroban language surface is different enough that mixing the two risks
status-vocabulary drift (FM-001); this tool stays separate.

Scope and discipline:
  - Heuristic regex scan of `.rs` files under `<workspace>/src/`.
  - Emits a JSON list of attack-angle candidates at confidence
    `low` or `medium`. Never `high` — heuristics do not merit it. Real
    semantic analysis would be a prerequisite for a `high` claim.
  - Advisory-only: does NOT write to `reference/outcomes.jsonl`, does NOT
    edit operator workspace state, does NOT invoke any packager or
    evidence-matrix code.
  - Confidence strings `low`, `medium` are tool-internal only; they are
    NOT part of the playbook §5 status vocabulary table. They annotate
    candidate surfaces for human triage, not submission-gating artifacts.
  - Fail-closed: a workspace with no `.rs` files returns
    `{"angles": [], "note": "no Rust source"}` with exit 0, so the loop
    never forces a synthesized finding.

Attack angles surfaced (heuristic — may FP, may FN):
  - A-AUTH       — functions named `admin`/`owner`/privileged that lack a
                   `require_auth(...)` call in body; or `require_auth`
                   usage patterns themselves (flag for surface mapping).
  - A-ORACLE     — references to price/oracle/feed/Reflector surfaces,
                   or fn names like `price_of`, `get_rate`.
  - A-ROUNDING   — integer division `/` (incl. `checked_div`,
                   `integer_div`) inside function bodies; rounding-mode
                   not mechanically verifiable from text alone.
  - A-REENT      — cross-contract `invoke_contract` or `.invoke()` /
                   `.call()` preceding a storage write in the same
                   function body (text-order heuristic).
  - A-ARITHMETIC — function bodies doing `+`, `-`, `*` on numeric types
                   without `checked_add`/`checked_sub`/`checked_mul`.

CLI:
  tools/ccia-rust.py --workspace <path> [--out <path>]
                     [--confidence-floor low|medium]
                     [--max-per-angle <int>]
                     [--top-n <int>]

Tuning flags (iter12 T3):
  --confidence-floor   Drop findings below this tier. `low` keeps all
                       (default, backward compatible); `medium` drops lows.
                       Confidence ceiling remains `medium` by construction
                       (heuristics do not merit `high`).
  --max-per-angle N    After the confidence-floor filter, cap the number of
                       findings per angle class at N. Findings within an
                       angle class are ranked deterministically
                       (medium > low, then file path, then line) and the
                       highest N are kept.
  --top-n N            After the max-per-angle cap, keep only the top N
                       findings total (same deterministic ranking). Default:
                       no limit. Useful on fresh codebases without priors
                       where raw counts (iter11 T1 found 1163 on k2) are
                       noise.

Filter order (fixed, deterministic): confidence-floor → max-per-angle → top-n.
Tuning narrows output only; it does NOT introduce or promote findings.

Exit codes:
  0 — scan completed (including the "no Rust source" fail-closed path).
  2 — invalid CLI arguments.

Output JSON schema:
  {
    "workspace": "<abs path>",
    "lang": "rust",
    "total_files_scanned": N,
    "angles": [
      {
        "file":       "<path relative to workspace>",
        "line":       <int, 1-indexed>,
        "angle":      "A-AUTH" | "A-ORACLE" | "A-ROUNDING" |
                      "A-REENT" | "A-ARITHMETIC",
        "confidence": "low" | "medium",
        "reason":     "<short human-readable rationale>",
        "snippet":    "<the matched source line, trimmed>"
      },
      ...
    ],
    "note": "<optional — only set in fail-closed no-source case>"
  }

Stdlib-only. No network. No subprocess. No third-party Rust parser.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ANGLE_AUTH = "A-AUTH"
ANGLE_ORACLE = "A-ORACLE"
ANGLE_ROUNDING = "A-ROUNDING"
ANGLE_REENT = "A-REENT"
ANGLE_ARITHMETIC = "A-ARITHMETIC"

ALLOWED_ANGLES = {
    ANGLE_AUTH, ANGLE_ORACLE, ANGLE_ROUNDING, ANGLE_REENT, ANGLE_ARITHMETIC,
}
ALLOWED_CONFIDENCE = ("low", "medium")  # high intentionally excluded


# ----------------------------- utilities ------------------------------------

SKIP_DIR_PARTS = {"target", "node_modules", ".git", "build", "out"}


def find_rs_files(src_root: Path) -> List[Path]:
    """Recurse under src_root; collect .rs files, skipping build artifacts."""
    files: List[Path] = []
    if not src_root.exists() or not src_root.is_dir():
        return files
    for p in src_root.rglob("*.rs"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR_PARTS for part in p.parts):
            continue
        files.append(p)
    return sorted(files)


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _snippet(line: str, cap: int = 200) -> str:
    """Trim leading/trailing whitespace; cap to `cap` chars."""
    s = line.strip()
    if len(s) > cap:
        s = s[: cap - 1] + "…"
    return s


# ----------------------------- function extraction --------------------------

_FN_DEF_RE = re.compile(
    r"^\s*(?:pub\s+(?:\([^)]*\)\s+)?)?(?:async\s+)?(?:unsafe\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
)


def extract_functions(source: str) -> List[Dict[str, Any]]:
    """Return a list of {name, start_line, end_line, body_lines} dicts.

    Brace-counting scan; tolerant of missing/mismatched braces (returns
    whatever was matched so far). Body excludes the signature line's
    opening brace search; the `lines` slice is inclusive [start, end].
    """
    functions: List[Dict[str, Any]] = []
    lines = source.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _FN_DEF_RE.match(line)
        if not m:
            i += 1
            continue
        name = m.group("name")
        start_line = i  # 0-indexed
        # Find opening brace — could be on this or a later line.
        j = i
        found_open = False
        while j < n:
            if "{" in lines[j]:
                found_open = True
                break
            # If we hit a `;`, it's probably a trait fn decl without body.
            if ";" in lines[j]:
                break
            j += 1
        if not found_open:
            i = j + 1
            continue
        # Brace-count from the first `{`.
        depth = 0
        body_start = j
        k = j
        end_line = j
        started = False
        while k < n:
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        end_line = k
                        break
            if started and depth == 0:
                break
            k += 1
        else:
            end_line = n - 1
        functions.append({
            "name": name,
            "start_line": start_line,      # 0-indexed
            "body_start_line": body_start,  # 0-indexed
            "end_line": end_line,          # 0-indexed inclusive
            "lines": lines[start_line:end_line + 1],
        })
        i = end_line + 1
    return functions


# ----------------------------- angle detectors ------------------------------

# A-AUTH
_AUTH_FN_NAME_RE = re.compile(
    r"(?i)\b(admin|owner|privileged|restricted|upgrade|migrate|"
    r"pause|unpause|set_|sweep|withdraw_fees|mint_unbacked|take_over|"
    r"emergency)"
)
_REQUIRE_AUTH_RE = re.compile(r"\brequire_auth\s*\(")


def detect_auth(
    workspace: Path,
    rel: str,
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for fn in functions:
        name = fn["name"]
        body_text = "\n".join(fn["lines"])
        has_auth = bool(_REQUIRE_AUTH_RE.search(body_text))
        priv = bool(_AUTH_FN_NAME_RE.search(name))
        if priv and not has_auth:
            # Privileged-sounding name with NO require_auth — medium.
            angles.append({
                "file": rel,
                "line": fn["start_line"] + 1,
                "angle": ANGLE_AUTH,
                "confidence": "medium",
                "reason": (
                    f"fn `{name}` name suggests privileged action but body "
                    "contains no `require_auth(...)` call"
                ),
                "snippet": _snippet(fn["lines"][0]),
            })
        elif has_auth:
            # Flag require_auth sites too — low confidence surface map.
            for offset, line in enumerate(fn["lines"]):
                if _REQUIRE_AUTH_RE.search(line):
                    angles.append({
                        "file": rel,
                        "line": fn["start_line"] + 1 + offset,
                        "angle": ANGLE_AUTH,
                        "confidence": "low",
                        "reason": (
                            f"`require_auth` usage in fn `{name}` — "
                            "check whether correct principal is being authed"
                        ),
                        "snippet": _snippet(line),
                    })
                    break  # one per fn
    return angles


# A-ORACLE
_ORACLE_TOKENS_RE = re.compile(
    r"(?i)\b(oracle|reflector|price_oracle|lastprice|price_feed|"
    r"chainlink|pyth|fallback)"
)
_ORACLE_FN_NAME_RE = re.compile(
    r"(?i)^(price_of|get_rate|get_price|fetch_price|lastprice|asset_price)"
)


def detect_oracle(
    workspace: Path,
    rel: str,
    source_lines: List[str],
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    # Fn-name-based medium confidence
    for fn in functions:
        if _ORACLE_FN_NAME_RE.match(fn["name"]):
            angles.append({
                "file": rel,
                "line": fn["start_line"] + 1,
                "angle": ANGLE_ORACLE,
                "confidence": "medium",
                "reason": (
                    f"fn `{fn['name']}` is a price/rate accessor — "
                    "check staleness, decimals, fallback cascade"
                ),
                "snippet": _snippet(fn["lines"][0]),
            })
    # Token-based low confidence (file-level)
    for idx, line in enumerate(source_lines):
        if _ORACLE_TOKENS_RE.search(line) and "//" not in line.split("oracle")[0][-3:]:
            angles.append({
                "file": rel,
                "line": idx + 1,
                "angle": ANGLE_ORACLE,
                "confidence": "low",
                "reason": "oracle/price/feed token referenced",
                "snippet": _snippet(line),
            })
            break  # one per file at low
    return angles


# A-ROUNDING
# Match integer division operator `/` that is NOT `//` comment, NOT `/*`,
# NOT part of a path string.
_INT_DIV_RE = re.compile(r"(?<![/\*'\"])(?<!\w)(?:\w+\s*)?/(?!/|\*)")
_CHECKED_DIV_RE = re.compile(r"\bchecked_div\s*\(")
_INTEGER_DIV_RE = re.compile(r"\binteger_div\s*\(|\bdiv_floor\s*\(|\bdiv_ceil\s*\(")


def detect_rounding(
    workspace: Path,
    rel: str,
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for fn in functions:
        for offset, line in enumerate(fn["lines"]):
            stripped = line.strip()
            # skip comment-only lines
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if _CHECKED_DIV_RE.search(line) or _INTEGER_DIV_RE.search(line):
                angles.append({
                    "file": rel,
                    "line": fn["start_line"] + 1 + offset,
                    "angle": ANGLE_ROUNDING,
                    "confidence": "medium",
                    "reason": (
                        f"fn `{fn['name']}` uses division helper — "
                        "verify rounding mode (floor/ceil/nearest) vs invariant"
                    ),
                    "snippet": _snippet(line),
                })
                break
            # plain `/`
            # Ignore impl-style `/` cases by checking for space-delimited operands
            # Use a simpler check: look for `<expr> / <expr>;` or `= <expr> / <expr>`
            if re.search(r"[A-Za-z0-9_\)\]]\s*/\s*[A-Za-z0-9_\(]", line):
                # filter out `//` and doc comments already; filter out `impl Foo /` — unlikely
                # Avoid `<path>/<path>` by requiring no `::` right next door
                if "::" in line and line.count("/") == line.count("://"):
                    continue
                angles.append({
                    "file": rel,
                    "line": fn["start_line"] + 1 + offset,
                    "angle": ANGLE_ROUNDING,
                    "confidence": "low",
                    "reason": (
                        "integer `/` division in function body; rounding "
                        "mode not documented in-line"
                    ),
                    "snippet": _snippet(line),
                })
                break  # one per fn
    return angles


# A-REENT
_INVOKE_RE = re.compile(r"\b(?:invoke_contract|\.invoke\s*\(|\.call\s*\()")
_STORAGE_WRITE_RE = re.compile(
    r"\bstorage::(?:set|write|put|update)\w*\s*\(|"
    r"\.set\s*\(|"
    r"\benv\.storage\b"
)


def detect_reent(
    workspace: Path,
    rel: str,
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for fn in functions:
        # find first invoke line; then look for storage write after it in body
        invoke_line: Optional[int] = None
        for offset, line in enumerate(fn["lines"]):
            if _INVOKE_RE.search(line):
                invoke_line = offset
                break
        if invoke_line is None:
            continue
        # after invoke, look for storage write
        for offset in range(invoke_line + 1, len(fn["lines"])):
            line = fn["lines"][offset]
            if _STORAGE_WRITE_RE.search(line):
                angles.append({
                    "file": rel,
                    "line": fn["start_line"] + 1 + invoke_line,
                    "angle": ANGLE_REENT,
                    "confidence": "medium",
                    "reason": (
                        f"fn `{fn['name']}` performs cross-contract call "
                        "before a subsequent storage write (CEI violation "
                        "heuristic)"
                    ),
                    "snippet": _snippet(fn["lines"][invoke_line]),
                })
                break
    return angles


# A-ARITHMETIC
_CHECKED_ARITH_RE = re.compile(r"\bchecked_(?:add|sub|mul)\s*\(")
_RAW_ARITH_RE = re.compile(
    r"[A-Za-z0-9_\)\]]\s*[\+\-\*]\s*[A-Za-z0-9_\(]"
)
_NUMERIC_NAME_HINT_RE = re.compile(
    r"(?i)\b(amount|balance|shares|fee|premium|interest|"
    r"principal|debt|collateral|liquidity|reserve|rate|supply|borrow)"
)


def detect_arithmetic(
    workspace: Path,
    rel: str,
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for fn in functions:
        body_text = "\n".join(fn["lines"])
        if not _NUMERIC_NAME_HINT_RE.search(fn["name"] + " " + body_text):
            continue
        has_checked = bool(_CHECKED_ARITH_RE.search(body_text))
        if has_checked:
            continue
        # find a plausible unchecked arith line
        for offset, line in enumerate(fn["lines"]):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            # Skip attribute / type-parameter style lines
            if stripped.startswith("#[") or stripped.startswith("use "):
                continue
            if _RAW_ARITH_RE.search(line) and not _CHECKED_ARITH_RE.search(line):
                # Avoid trait-bound `+` style: `T: Foo + Bar`
                if ":" in line.split("+")[0][-40:] and "Bar" in line:
                    continue
                angles.append({
                    "file": rel,
                    "line": fn["start_line"] + 1 + offset,
                    "angle": ANGLE_ARITHMETIC,
                    "confidence": "low",
                    "reason": (
                        f"fn `{fn['name']}` does numeric arithmetic on "
                        "amount-shaped values without checked_* helpers "
                        "visible in body"
                    ),
                    "snippet": _snippet(line),
                })
                break
    return angles


# ----------------------------- driver ---------------------------------------

def scan_workspace(workspace: Path) -> Dict[str, Any]:
    """Produce the full JSON-shaped report. Fail-closed on empty source."""
    workspace = workspace.resolve()
    src_root = workspace / "src"
    if not src_root.exists():
        src_root = workspace  # allow --workspace pointing directly at src tree
    rs_files = find_rs_files(src_root)
    if not rs_files:
        return {
            "workspace": str(workspace),
            "lang": "rust",
            "total_files_scanned": 0,
            "angles": [],
            "note": "no Rust source",
        }
    all_angles: List[Dict[str, Any]] = []
    for path in rs_files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = _rel(workspace, path)
        source_lines = source.splitlines()
        functions = extract_functions(source)
        all_angles.extend(detect_auth(workspace, rel, functions))
        all_angles.extend(detect_oracle(workspace, rel, source_lines, functions))
        all_angles.extend(detect_rounding(workspace, rel, functions))
        all_angles.extend(detect_reent(workspace, rel, functions))
        all_angles.extend(detect_arithmetic(workspace, rel, functions))
    # Hard guard: no `high` confidence may leak.
    for a in all_angles:
        if a.get("confidence") not in ALLOWED_CONFIDENCE:
            # Force-demote rather than silently keep a bad value
            a["confidence"] = "low"
    return {
        "workspace": str(workspace),
        "lang": "rust",
        "total_files_scanned": len(rs_files),
        "angles": all_angles,
    }


def apply_confidence_floor(
    report: Dict[str, Any], floor: str,
) -> Dict[str, Any]:
    if floor not in ALLOWED_CONFIDENCE:
        return report
    if floor == "low":
        return report
    # floor == "medium" → drop low
    report = dict(report)
    report["angles"] = [
        a for a in report.get("angles", [])
        if a.get("confidence") == "medium"
    ]
    return report


# Confidence rank for deterministic sort: higher = better.
_CONFIDENCE_RANK = {"medium": 2, "low": 1}


def _rank_key(a: Dict[str, Any]) -> Tuple[int, str, int]:
    """Sort key: (-confidence_rank, file, line).

    Negated rank so that `medium` (rank 2) sorts BEFORE `low` (rank 1) in
    ascending order. File path and line break ties deterministically, so
    `--top-n` yields reproducible output across runs and platforms.
    """
    conf = a.get("confidence", "low")
    rank = _CONFIDENCE_RANK.get(conf, 0)
    return (-rank, str(a.get("file", "")), int(a.get("line", 0)))


def _sort_findings(angles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(angles, key=_rank_key)


def apply_max_per_angle(
    report: Dict[str, Any], cap: Optional[int],
) -> Dict[str, Any]:
    """Cap the number of findings per angle class at `cap`.

    Findings within each angle class are ranked via `_rank_key` (medium >
    low, then file, then line); the top `cap` per class are kept.
    """
    if cap is None:
        return report
    if cap < 0:
        return report
    report = dict(report)
    per_angle_counts: Dict[str, int] = {}
    kept: List[Dict[str, Any]] = []
    for a in _sort_findings(report.get("angles", [])):
        angle = a.get("angle", "")
        count = per_angle_counts.get(angle, 0)
        if count >= cap:
            continue
        per_angle_counts[angle] = count + 1
        kept.append(a)
    report["angles"] = kept
    return report


def apply_top_n(
    report: Dict[str, Any], top_n: Optional[int],
) -> Dict[str, Any]:
    """Keep only the top N findings (by deterministic rank) overall."""
    if top_n is None:
        return report
    if top_n < 0:
        return report
    report = dict(report)
    ranked = _sort_findings(report.get("angles", []))
    report["angles"] = ranked[:top_n]
    return report


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="ccia-rust",
        description=(
            "Rust/Soroban CCIA adapter — advisory-only attack-angle "
            "heuristic scanner. Outputs JSON to stdout or --out."
        ),
    )
    p.add_argument(
        "--workspace",
        required=True,
        help="Path to the workspace directory (contains `src/` with .rs files).",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Write JSON report to this path; default stdout.",
    )
    p.add_argument(
        "--confidence-floor",
        choices=list(ALLOWED_CONFIDENCE),
        default="low",
        help="Drop findings below this floor (low|medium). Default: low.",
    )
    p.add_argument(
        "--max-per-angle",
        type=int,
        default=None,
        help=(
            "Cap findings per angle class (A-AUTH, A-ORACLE, A-ROUNDING, "
            "A-REENT, A-ARITHMETIC). Applied after --confidence-floor. "
            "Default: no cap."
        ),
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=None,
        help=(
            "After --confidence-floor and --max-per-angle, keep only the "
            "top N findings total (ranked medium>low, then file, then "
            "line). Default: no limit."
        ),
    )
    args = p.parse_args(argv)

    workspace = Path(args.workspace).expanduser()
    report = scan_workspace(workspace)
    # Filter order (fixed, deterministic):
    #   confidence-floor → max-per-angle → top-n
    report = apply_confidence_floor(report, args.confidence_floor)
    report = apply_max_per_angle(report, args.max_per_angle)
    report = apply_top_n(report, args.top_n)
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized + "\n", encoding="utf-8")
    else:
        sys.stdout.write(serialized + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
