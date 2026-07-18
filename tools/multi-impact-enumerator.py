#!/usr/bin/env python3
"""Multi-Impact Enumerator - fix for the `impact-imagination` audit gap.

THE GAP THIS FIXES
==================
A flagged code pattern (e.g. external-call-before-state-finalization on a
function) gets investigated under exactly ONE impact hypothesis, that hypothesis
comes back benign, and the surface is closed - while the REAL impact, a
different class entirely, never gets a test. The canonical anchor is a
callback-before-pull ordering that was tested only as `reentrancy` (benign) and
the actually-exploitable `allowance-griefing` class was never enumerated.

This tool takes a flagged pattern on a function (or a candidate/finding record,
or a raw `file:line`) and enumerates ALL plausible impact classes for that
pattern - reentrancy, allowance-griefing, callback-trick, fee-manipulation,
DoS, accounting-skew, oracle-trust, and more - each with a concrete one-line
attack hypothesis and a concrete test-to-run. The output is a checklist a
worker (or a downstream gate) can drive to a verdict so no single benign result
silently closes a multi-impact surface.

GENERICITY (hard requirement)
=============================
- Operates on ANY auditooor workspace via `--workspace <path>`. There are NO
  hardcoded workspace paths, function names, finding ids, or contract names in
  this tool body. (The morpho-midnight specifics live ONLY in the unittest.)
- Language-aware: the pattern->impact taxonomy and the source-side cues are
  organised per target language family (solidity, rust, go, move, cairo) and
  every table is extensible via env hooks (AUDITOOOR_MIE_* below) so a new
  target does not require editing this file.
- Degrades gracefully: a workspace missing engage_report / exploit_queue still
  works (you can pass a bare `file:line` or a `--pattern`/`--function` pair);
  an unknown pattern emits the language-default impact set with an honest note.

INPUT (any one of)
==================
  --pattern <name> --function <file:line-or-name>   explicit
  --candidate <id>                                  resolve from workspace artifacts
  --file-line <path:line>                           bare source location (pattern inferred)
  --finding-file <path.md>                           parse a draft/candidate markdown

OUTPUT
======
  jsonl rows: {pattern, function, impact_class, attack_hypothesis, test_to_run}
  (or a single JSON object with --json carrying the rows + metadata)

ENV HOOKS (all newline-separated; appended to built-in tables)
==============================================================
  AUDITOOOR_MIE_PATTERN_IMPACTS   "pattern=>impact1,impact2,..." rows
  AUDITOOOR_MIE_IMPACT_TAXONOMY   "impact_class\t<one-line definition>" rows
  AUDITOOOR_MIE_LANG_PATTERNS     "lang\tregex" rows (source cue -> language)
  AUDITOOOR_MIE_FUNCTION_CALL_RE  extra regexes that mark an external/inter-contract call

Schema: auditooor.multi_impact_enumerator.v1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA_VERSION = "auditooor.multi_impact_enumerator.v1"
TOOL = "multi-impact-enumerator"

# ---------------------------------------------------------------------------
# Impact-class taxonomy (seeded from the auditooor corpus attack-class space).
# Each entry: impact_class -> short definition used to build the hypothesis.
# Extensible via AUDITOOOR_MIE_IMPACT_TAXONOMY.
# ---------------------------------------------------------------------------
_IMPACT_TAXONOMY: dict[str, str] = {
    "reentrancy": "attacker re-enters the contract mid-call before state is finalized",
    "allowance-griefing": "a third party consumes/redirects a victim's approval set for the call (exact-allowance gap)",
    "callback-trick": "the external callback is attacker-controlled and used to alter inputs/recipients before the pull",
    "fee-manipulation": "fee/rebate accounting is read or written across the external call and can be skewed",
    "dos": "the external call can be forced to revert / run out of gas, blocking the whole operation",
    "accounting-skew": "balances/shares/debt update out of order with the transfer, leaving the ledger inconsistent",
    "oracle-trust": "a price/state read straddles the external call and can be moved within the same tx",
    "front-running": "the action's profitability depends on ordering an adversary can influence in the mempool",
    "donation-inflation": "direct token donation between the call and the state read inflates a ratio/share price",
    "first-depositor": "an empty/initial state lets the first actor seize a disproportionate share",
    "rounding-loss": "directional rounding across the boundary leaks value (dust) per call",
    "auth-bypass": "the external boundary lets an unauthorized caller reach a privileged effect",
    "stuck-funds": "funds can be left unrecoverable because the post-call path can be blocked",
    "double-spend": "the same balance/credit is usable twice across the un-finalized window",
}

# ---------------------------------------------------------------------------
# Pattern -> candidate impact classes. The KEY anti-pattern: a pattern that is
# usually filed as a single class (e.g. external-call-before-state-finalization
# -> "reentrancy") actually spans MANY classes. We enumerate them all.
# Pattern keys are matched as normalized substrings against the flagged pattern.
# Extensible via AUDITOOOR_MIE_PATTERN_IMPACTS.
# ---------------------------------------------------------------------------
_PATTERN_IMPACTS: dict[str, list[str]] = {
    # the anchor family: anything "call before state/pull/finalize"
    "external-call-before-state": [
        "reentrancy", "allowance-griefing", "callback-trick",
        "accounting-skew", "fee-manipulation", "oracle-trust", "dos",
    ],
    "callback-before-pull": [
        "allowance-griefing", "callback-trick", "reentrancy",
        "accounting-skew", "fee-manipulation", "dos",
    ],
    "cei-violation": [
        "reentrancy", "allowance-griefing", "callback-trick",
        "accounting-skew", "dos",
    ],
    "reentrancy": [
        "reentrancy", "allowance-griefing", "callback-trick",
        "accounting-skew", "double-spend",
    ],
    "callback": [
        "callback-trick", "allowance-griefing", "reentrancy", "dos",
        "fee-manipulation",
    ],
    "unchecked-external-call": [
        "dos", "callback-trick", "accounting-skew", "stuck-funds",
    ],
    "zero-amount-transfer-revert": ["dos", "stuck-funds"],
    "transfer-before-update": [
        "reentrancy", "accounting-skew", "double-spend", "allowance-griefing",
    ],
    # economic / accounting families
    "dust": ["accounting-skew", "rounding-loss", "stuck-funds", "dos"],
    "rounding": ["rounding-loss", "accounting-skew", "donation-inflation"],
    "share-price": ["donation-inflation", "first-depositor", "rounding-loss", "oracle-trust"],
    "first-deposit": ["first-depositor", "donation-inflation", "rounding-loss"],
    "fee": ["fee-manipulation", "accounting-skew", "rounding-loss"],
    "oracle": ["oracle-trust", "front-running", "accounting-skew"],
    "price": ["oracle-trust", "donation-inflation", "front-running"],
    # auth / access
    "access-control": ["auth-bypass", "stuck-funds", "front-running"],
    "missing-guard": ["auth-bypass", "accounting-skew", "double-spend", "dos"],
    "signature": ["auth-bypass", "front-running", "double-spend"],
    "nonce": ["double-spend", "auth-bypass", "front-running"],
}

# Per-language source cue regexes: detect language from the source extension
# AND give the source-side hint of an external/inter-contract call so the
# hypothesis can be made concrete. Extensible via AUDITOOOR_MIE_LANG_PATTERNS /
# AUDITOOOR_MIE_FUNCTION_CALL_RE.
_LANG_BY_EXT: dict[str, str] = {
    ".sol": "solidity", ".vy": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".cairo": "cairo",
}

_EXTERNAL_CALL_RE: dict[str, list[str]] = {
    "solidity": [
        r"\.call\b", r"\.transfer\(", r"\.transferFrom\(",
        r"safeTransfer", r"\.on[A-Z]\w*\(", r"Callback\(", r"\.delegatecall\(",
    ],
    "rust": [r"::transfer\(", r"\.call\(", r"invoke\(", r"cross_program_invocation", r"\.cpi"],
    "go": [r"\.Call\(", r"keeper\.\w+Transfer", r"\.Send\("],
    "move": [r"::transfer", r"public\s+fun\s+\w*callback"],
    "cairo": [r"\.call\(", r"library_call", r"send_message_to_l1"],
}


def _load_env_pattern_impacts() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    raw = os.environ.get("AUDITOOOR_MIE_PATTERN_IMPACTS", "")
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=>" not in line:
            continue
        key, vals = line.split("=>", 1)
        impacts = [v.strip() for v in vals.split(",") if v.strip()]
        if key.strip() and impacts:
            out[_norm(key)] = impacts
    return out


def _load_env_taxonomy() -> dict[str, str]:
    out: dict[str, str] = {}
    raw = os.environ.get("AUDITOOOR_MIE_IMPACT_TAXONOMY", "")
    for line in raw.splitlines():
        if "\t" not in line:
            continue
        k, v = line.split("\t", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _load_env_lang_patterns() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    raw = os.environ.get("AUDITOOOR_MIE_LANG_PATTERNS", "")
    for line in raw.splitlines():
        if "\t" not in line:
            continue
        lang, rx = line.split("\t", 1)
        if lang.strip() and rx.strip():
            out.append((lang.strip(), rx.strip()))
    return out


def _load_env_call_res() -> list[str]:
    raw = os.environ.get("AUDITOOOR_MIE_FUNCTION_CALL_RE", "")
    return [l.strip() for l in raw.splitlines() if l.strip()]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


def _norm_file(s: str) -> str:
    """Normalize a file path for scope-manifest comparison."""
    return str(s or "").strip().lstrip("./").replace("\\", "/")


def _load_inscope_file_set(ws: Path):
    """Return the authoritative in-scope file set from ``.auditooor/inscope_units.jsonl``
    (each line is JSON with a ``file`` key, a ws-relative posix path), or ``None`` when
    the manifest is absent or empty (then no filtering - legacy behavior preserved).

    Disable with env AUDITOOOR_FCC_NO_SCOPE_FILTER (any non-empty value).
    """
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = _norm_file(row.get("file") or "")
        if f:
            files.add(f)
    return files or None


def _lang_for_path(path: str) -> str:
    # strip a trailing :line[:col] before taking the suffix so "x/lib.rs:42"
    # resolves to .rs, not ".rs:42".
    bare = re.sub(r":\d+(?::\d+)?$", "", path or "")
    ext = Path(bare).suffix.lower()
    return _LANG_BY_EXT.get(ext, "solidity")


def _impacts_for_pattern(pattern: str) -> tuple[list[str], bool]:
    """Return (impact_classes, matched). Substring-match the normalized pattern
    against the (built-in + env) pattern table; longest key wins for specificity.
    """
    table = dict(_PATTERN_IMPACTS)
    table.update(_load_env_pattern_impacts())
    npat = _norm(pattern)
    best_key = None
    for key in table:
        if key in npat or npat in key:
            if best_key is None or len(key) > len(best_key):
                best_key = key
    if best_key is not None:
        return table[best_key], True
    return [], False


def _default_impacts_for_lang(lang: str) -> list[str]:
    # honest language-default when the pattern is unknown: the broadest
    # external-boundary impact set, language-agnostic core.
    base = ["reentrancy", "callback-trick", "accounting-skew", "dos", "auth-bypass"]
    if lang == "solidity":
        base = ["reentrancy", "allowance-griefing", "callback-trick",
                "accounting-skew", "fee-manipulation", "dos"]
    return base


def _source_call_hint(workspace: Path, file_line: str, lang: str) -> str | None:
    """Read the cited source line(s) and return the first external-call cue, to
    make the attack hypothesis concrete. Best-effort; returns None if unreadable.
    """
    m = re.match(r"(.+?):(\d+)", file_line or "")
    if not m:
        return None
    rel = m.group(1)
    line = int(m.group(2))
    candidates = [workspace / rel, Path(rel)]
    # also try common src roots
    for root in ("src", "src/src", "contracts", "protocol", "crates"):
        candidates.append(workspace / root / rel)
    try:
        import importlib.util as _ilu
        _p = Path(__file__).resolve().parent / "lib" / "source_root_resolver.py"
        _s = _ilu.spec_from_file_location("auditooor_source_root_resolver", _p)
        _m = _ilu.module_from_spec(_s); _s.loader.exec_module(_m)
        for _r in _m.resolve_src_roots(workspace):
            candidates.append(_r / rel)
    except Exception:
        pass
    src = next((p for p in candidates if p.is_file()), None)
    if src is None:
        return None
    try:
        text = src.read_text(errors="replace").splitlines()
    except OSError:
        return None
    lo = max(0, line - 4)
    hi = min(len(text), line + 8)
    window = "\n".join(text[lo:hi])
    res = list(_EXTERNAL_CALL_RE.get(lang, [])) + _load_env_call_res()
    for rx in res:
        mm = re.search(rx, window)
        if mm:
            return mm.group(0)
    return None


def _build_taxonomy() -> dict[str, str]:
    tax = dict(_IMPACT_TAXONOMY)
    tax.update(_load_env_taxonomy())
    return tax


def _hypothesis(impact: str, pattern: str, function: str, call_hint: str | None,
                taxonomy: dict[str, str]) -> str:
    defn = taxonomy.get(impact, "impact path unverified - enumerate manually")
    where = f" at `{function}`" if function else ""
    via = f" (call cue: `{call_hint}`)" if call_hint else ""
    return f"Under `{pattern}`{where}: {defn}{via}."


def _test_to_run(impact: str, lang: str) -> str:
    common = {
        "reentrancy": "deploy a malicious receiver/callback that re-enters the function; assert state corruption or double effect",
        "allowance-griefing": "set victim approval; have a third party invoke the callback path to consume/redirect the victim's allowance; assert victim loss with attacker-only allowance never used",
        "callback-trick": "supply an attacker-controlled callback that mutates recipient/amount/index before the pull; assert the post-call effect diverges from caller intent",
        "fee-manipulation": "drive the call so the fee/rebate is read on a stale value or skipped; assert fee accrued != expected",
        "dos": "make the external call (or a zero-amount transfer) revert / exhaust gas; assert the whole operation reverts for an unrelated party",
        "accounting-skew": "interleave the transfer and the ledger update; assert sum(balances)/shares/debt invariant breaks",
        "oracle-trust": "move the price/state read inside the same tx (flash) across the call; assert mispricing realized",
        "front-running": "reorder the tx vs a competing one; assert the adversary captures the value",
        "donation-inflation": "donate tokens between the call and the ratio read; assert share price inflates and a later depositor is shorted",
        "first-depositor": "be the first actor on an empty market/vault; assert disproportionate share seized",
        "rounding-loss": "repeat the op N times to accumulate directional rounding dust; assert net leak",
        "auth-bypass": "reach the privileged effect via the external boundary from an unauthorized caller; assert effect lands",
        "stuck-funds": "block the post-call recovery path; assert funds become unrecoverable in-protocol",
        "double-spend": "use the same credit/balance twice inside the un-finalized window; assert total > entitlement",
    }
    desc = common.get(impact, "construct a PoC for this impact class and assert the broken invariant")
    suite = {
        "solidity": "forge test", "rust": "cargo test / proptest harness",
        "go": "go test", "move": "move test", "cairo": "scarb test / cairo-test",
    }.get(lang, "the project test runner")
    return f"{suite}: {desc}"


def enumerate_impacts(pattern: str, function: str, workspace: Path | None,
                      file_line: str | None) -> tuple[list[dict], dict]:
    lang = _lang_for_path(function or file_line or "")
    impacts, matched = _impacts_for_pattern(pattern)
    note = ""
    if not matched:
        impacts = _default_impacts_for_lang(lang)
        note = (f"pattern `{pattern}` not in taxonomy; emitted language-default "
                f"impact set for {lang}. Add a row via AUDITOOOR_MIE_PATTERN_IMPACTS.")
    taxonomy = _build_taxonomy()
    call_hint = None
    if workspace is not None and file_line:
        call_hint = _source_call_hint(workspace, file_line, lang)
    rows: list[dict] = []
    seen = set()
    for impact in impacts:
        if impact in seen:
            continue
        seen.add(impact)
        rows.append({
            "pattern": pattern,
            "function": function or file_line or "",
            "impact_class": impact,
            "attack_hypothesis": _hypothesis(impact, pattern, function or file_line or "",
                                             call_hint, taxonomy),
            "test_to_run": _test_to_run(impact, lang),
        })
    meta = {
        "language": lang,
        "pattern_matched": matched,
        "call_hint": call_hint,
        "note": note,
        "impact_count": len(rows),
    }
    return rows, meta


# ---------------------------------------------------------------------------
# Input resolvers (workspace artifacts). All best-effort; degrade to empty.
# ---------------------------------------------------------------------------
def _resolve_candidate(workspace: Path, cand_id: str) -> tuple[str, str] | None:
    """Find (pattern, function/file:line) for a candidate id in workspace
    artifacts (exploit_queue.json / reports/*.md / engage_report.md)."""
    eq = workspace / ".auditooor" / "exploit_queue.json"
    if eq.is_file():
        try:
            data = json.loads(eq.read_text())
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            rows = []
            for key in ("rows", "candidates", "queue", "surfaces"):
                v = data.get(key)
                if isinstance(v, list):
                    rows.extend(v)
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rid = str(r.get("id") or r.get("candidate_id") or r.get("eq_id") or "")
                if rid and (rid == cand_id or _norm(rid) == _norm(cand_id)):
                    pat = str(r.get("pattern") or r.get("detector") or r.get("class") or cand_id)
                    fn = str(r.get("function") or r.get("file_line") or r.get("location") or "")
                    return pat, fn
    # fall back: grep reports + engage_report for the id and a file:line nearby
    for src in list((workspace / "reports").glob("*.md")) + [workspace / "engage_report.md"]:
        if not src.is_file():
            continue
        try:
            txt = src.read_text(errors="replace")
        except OSError:
            continue
        if cand_id.lower() in txt.lower():
            mfl = re.search(r"([\w./-]+\.\w+:\d+)", txt)
            mpat = re.search(r"`([a-z][a-z0-9-]{4,})`", txt)
            return (mpat.group(1) if mpat else cand_id), (mfl.group(1) if mfl else "")
    return None


def _parse_finding_file(path: Path) -> tuple[str, str]:
    txt = path.read_text(errors="replace")
    mfl = re.search(r"([\w./-]+\.\w+:\d+(?:-\d+)?)", txt)
    # pattern: first backticked dash-token, else title slug
    mpat = re.search(r"`([a-z][a-z0-9-]{4,})`", txt)
    pat = mpat.group(1) if mpat else _norm(path.stem)
    fn = mfl.group(1) if mfl else ""
    return pat, fn


def run(args) -> tuple[int, dict]:
    workspace = args.workspace.resolve() if args.workspace else None
    pattern = args.pattern or ""
    function = args.function or ""
    file_line = args.file_line or ""

    if args.candidate:
        if workspace is None:
            return 2, {"schema_version": SCHEMA_VERSION, "tool": TOOL,
                       "error": "--candidate requires --workspace"}
        res = _resolve_candidate(workspace, args.candidate)
        if res is None:
            return 0, {"schema_version": SCHEMA_VERSION, "tool": TOOL,
                       "rows": [], "meta": {"note": f"candidate {args.candidate} not found in workspace artifacts"}}
        pattern, function = res
        if not file_line and ":" in function:
            file_line = function
    elif args.finding_file:
        pattern, function = _parse_finding_file(args.finding_file)
        if not file_line and ":" in function:
            file_line = function
    elif file_line and not function:
        function = file_line
        if not pattern:
            # infer a coarse pattern from the path/context: leave generic
            pattern = "external-call-before-state"

    if not pattern and not function and not file_line:
        return 2, {"schema_version": SCHEMA_VERSION, "tool": TOOL,
                   "error": "provide one of --pattern/--function, --file-line, --candidate, --finding-file"}
    if not function:
        function = file_line

    # Scope filter: when an authoritative inscope_units.jsonl manifest exists,
    # drop any request whose file_line references an out-of-scope file.  This
    # mirrors the _load_inscope_file_set / filter pattern in
    # function-coverage-completeness.py (commit 5dd42eca4a).  Rules:
    #   - Manifest absent or empty -> None -> no filtering (legacy behavior).
    #   - AUDITOOOR_FCC_NO_SCOPE_FILTER set -> skip filtering.
    #   - Path normalization: lstrip("./") + replace("\\","/") on both sides.
    scope_filter_info: dict = {"applied": False, "source": None,
                               "in_scope_files": None, "out_of_scope_dropped": 0}
    if workspace is not None:
        _inscope = _load_inscope_file_set(workspace)
        if _inscope is not None:
            scope_filter_info["applied"] = True
            scope_filter_info["source"] = ".auditooor/inscope_units.jsonl"
            scope_filter_info["in_scope_files"] = len(_inscope)
            # Extract the file portion from file_line (strip trailing :line).
            ref = re.sub(r":\d+(?::\d+)?$", "", file_line or function or "")
            ref_norm = _norm_file(ref)
            if ref_norm and ref_norm not in _inscope:
                scope_filter_info["out_of_scope_dropped"] = 1
                note = (f"file `{ref_norm}` not in inscope_units.jsonl "
                        f"({len(_inscope)} in-scope files); 0 impacts emitted")
                print(f"# scope-filter: {note}", file=sys.stderr)
                return 0, {
                    "schema_version": SCHEMA_VERSION,
                    "tool": TOOL,
                    "workspace": str(workspace),
                    "input": {"pattern": pattern, "function": function,
                              "file_line": file_line or None,
                              "candidate": getattr(args, "candidate", None),
                              "finding_file": (str(args.finding_file)
                                               if getattr(args, "finding_file", None)
                                               else None)},
                    "meta": {"language": _lang_for_path(function or file_line or ""),
                             "pattern_matched": False, "call_hint": None,
                             "note": note, "impact_count": 0},
                    "scope_filter": scope_filter_info,
                    "rows": [],
                }

    rows, meta = enumerate_impacts(pattern, function, workspace, file_line or function)
    return 0, {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "workspace": str(workspace) if workspace else None,
        "input": {"pattern": pattern, "function": function, "file_line": file_line or None,
                  "candidate": args.candidate, "finding_file": str(args.finding_file) if args.finding_file else None},
        "meta": meta,
        "scope_filter": scope_filter_info,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workspace", type=Path, default=None,
                        help="auditooor workspace root (for source cues / candidate resolution)")
    parser.add_argument("--pattern", default=None, help="flagged pattern/detector name")
    parser.add_argument("--function", default=None, help="function name or file:line")
    parser.add_argument("--file-line", default=None, help="bare source location path:line")
    parser.add_argument("--candidate", default=None, help="candidate/finding id to resolve from workspace artifacts")
    parser.add_argument("--finding-file", type=Path, default=None, help="markdown draft/candidate to parse")
    parser.add_argument("--json", action="store_true", help="emit one JSON object instead of jsonl rows")
    args = parser.parse_args(argv)

    rc, payload = run(args)
    if args.json or "error" in payload:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for row in payload.get("rows", []):
            print(json.dumps(row, sort_keys=True))
        meta = payload.get("meta", {})
        if meta.get("note"):
            print(f"# note: {meta['note']}", file=sys.stderr)
        print(f"# {TOOL}: {meta.get('impact_count', 0)} impact classes "
              f"(lang={meta.get('language')}, pattern_matched={meta.get('pattern_matched')})",
              file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
