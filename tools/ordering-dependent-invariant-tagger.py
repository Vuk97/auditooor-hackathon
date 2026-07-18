#!/usr/bin/env python3
"""
ordering-dependent-invariant-tagger.py -- E9 ordering-dependent-invariant screen.

Schema: auditooor.ordering_dependent_invariant.v1

GENERAL ENFORCEMENT CLASS (not a bug shape). North-star (w8mv5mpcw) instantiated:

  Delegated-and-trusted safety property:
    "A stateful accounting field is kept FRESH by a dedicated refresher, and every
     consumer runs that refresher BEFORE it reads the field."
  Private invariant (temporal / ordering):
    "The refresher call DOMINATES (precedes in program order) every dependent read
     of the accumulator it maintains, inside every state-changing entry point."
  Attack on the invariant:
    "Reorder: read the accumulator while it is STALE -- either the refresher is
     never called on this path, or a dependent read is emitted before the refresher
     runs -- so the consumer computes on drifted state (wrong shares / price / debt
     / reward)."

This is the reusable ORDERING-DEPENDENT INVARIANT axis of the invariant library
(temporal class). It is impact-agnostic: it does not know or care whether the drift
causes theft, DoS or mis-accounting; it only tags the ordering obligation and asks
fuzz to decide. It is language-agnostic: the refresh->read domination relation is
the same in Solidity, Rust and Go.

HOW IT WORKS (lightweight, no compiler, offline):
  Pass 1 (refresher + accumulator discovery, per file):
    * A REFRESHER is a function whose name carries a refresh verb
      (accrue/update/sync/refresh/checkpoint/settle/poke/harvest/touch/revalidate/
       recompute/reprice). These are the "delegated-and-trusted" freshness owners.
    * An ACCUMULATOR is a struct-MEMBER field written with a compound assignment
      (`.field += x` / `-=` / `*=` / `/=`) INSIDE a refresher. Compound assignment
      is the tell that the value DRIFTS with time/state, so a stale read is wrong.
      (Plain-assignment bookkeeping flags such as `lastUpdate = block.timestamp`
      are deliberately EXCLUDED -- reading them in an existence guard is not a
      value-drift hazard, which is why guarded code like Morpho.supplyCollateral
      stays silent.)

  Pass 2 (ordering-domination check, per state-changing function):
    For each non-refresher, non-view function that performs a state mutation or a
    value-movement sink, walk its body top-to-bottom. If a DEPENDENT READ of an
    accumulator member (`.field` appearing where it is not that field's own write
    target) occurs and NO refresher call has appeared earlier in the body, emit an
    advisory row: the ordering obligation is unproven on this path.

ADVISORY-FIRST (hard rule): every row is verdict="needs-fuzz". The tool NEVER
auto-credits and NEVER fails closed -- process exit is 0 whenever analysis
completes, regardless of how many ordering obligations were tagged. A tag means
"a coverage-guided fuzz campaign must prove refresher-domination on this path or
find the stale-read reorder", not "bug".

SCOPE / KNOWN LIMITS (honest): member-access accumulators only (a top-level state
var `totalSupply += x` with no receiver is not tracked -- these protocols keep the
drifting accounting on struct members, and requiring a receiver keeps FP ~0).
Refresher calls are matched by in-body call syntax `name(`; a refresher applied
only via a modifier is not counted (conservative -> may over-tag, never silently
under-credits an impact).

USAGE:
  ordering-dependent-invariant-tagger.py <path>...        # walk files/dirs
  ordering-dependent-invariant-tagger.py <path> --json out.json
  ordering-dependent-invariant-tagger.py <path> --quiet   # rows to stderr only

Exit code is 0 on success (advisory). Non-zero only on a usage/IO error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

SCHEMA = "auditooor.ordering_dependent_invariant.v1"
TOOL = "ordering-dependent-invariant-tagger"

# Refresh verbs -> a function carrying one of these is a "delegated freshness owner".
REFRESH_VERBS = (
    "accrue", "update", "sync", "refresh", "checkpoint", "settle",
    "poke", "harvest", "touch", "revalidate", "recompute", "reprice",
)
# Match the verb as a camelCase or snake_case token inside the function name.
_VERB_ALT = "|".join(REFRESH_VERBS)
REFRESHER_NAME_RE = re.compile(
    r"(?:^|_|\b)(?:%s)" % _VERB_ALT, re.IGNORECASE
)

# Value-movement / state-mutation sinks that make a stale read *matter*.
SINK_RE = re.compile(
    r"\b(?:safeTransfer(?:From)?|transfer(?:From)?|send|call|mint|burn|"
    r"withdraw|redeem|deposit|repay|borrow|liquidate|payable)\b"
)

# Language function-header patterns (name capture in group 'name').
FUNC_HEADER_RES = {
    "sol": re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\("),
    "rust": re.compile(r"\bfn\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\("),
    "go": re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("),
}
VIEW_RE = re.compile(r"\b(?:view|pure)\b")

# Compound-assignment to a struct member: `<recv>.field [ +-*/ ]= ...`
MEMBER_COMPOUND_ASSIGN_RE = re.compile(
    r"(?:\.|->)\s*(?P<field>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*[-+*/]="
)
# Plain assignment to a struct member (used to know a line is a *write* of a field).
MEMBER_PLAIN_ASSIGN_RE = re.compile(
    r"(?:\.|->)\s*(?P<field>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)"
)
LANG_BY_EXT = {".sol": "sol", ".rs": "rust", ".go": "go"}


@dataclass
class Func:
    name: str
    lang: str
    start: int          # 1-indexed line of header
    body_start: int     # line where '{' opens
    end: int            # 1-indexed line of matching close brace
    header: str
    lines: list          # list[(lineno, text)] of body lines (inclusive of braces)


@dataclass
class Row:
    schema: str
    tool: str
    file: str
    function: str
    line: int
    subject_field: str
    refresher_candidates: list
    verdict: str
    advisory: bool
    private_invariant: str
    note: str


# --------------------------------------------------------------------------- #
# Function extraction (brace-balanced, works for sol/rust/go bodies)
# --------------------------------------------------------------------------- #
def _strip_line_comment(text: str) -> str:
    # remove // comments (keep string content risk low for this heuristic tool)
    idx = text.find("//")
    return text[:idx] if idx != -1 else text


def extract_functions(source: str, lang: str) -> list:
    header_re = FUNC_HEADER_RES[lang]
    lines = source.splitlines()
    funcs: list = []
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        m = header_re.search(_strip_line_comment(raw))
        if not m:
            i += 1
            continue
        # find the opening brace for this function (could be same or later line)
        depth = 0
        opened = False
        body_lines = []
        header_text = raw
        j = i
        body_start = None
        while j < n:
            code = _strip_line_comment(lines[j])
            for ch in code:
                if ch == "{":
                    depth += 1
                    if not opened:
                        opened = True
                        body_start = j + 1
                elif ch == "}":
                    depth -= 1
            if opened:
                body_lines.append((j + 1, lines[j]))
            if opened and depth == 0:
                break
            # accumulate header text until brace opens (multi-line signatures)
            if not opened:
                header_text += " " + lines[j] if j != i else ""
            j += 1
        if opened and body_start is not None:
            funcs.append(
                Func(
                    name=m.group("name"),
                    lang=lang,
                    start=i + 1,
                    body_start=body_start,
                    end=j + 1,
                    header=header_text,
                    lines=body_lines,
                )
            )
            i = j + 1
        else:
            i += 1
    return funcs


def is_refresher(name: str) -> bool:
    return REFRESHER_NAME_RE.search(name) is not None


def accumulators_of(funcs: list) -> dict:
    """field -> set(refresher function names that compound-assign it)."""
    acc: dict = {}
    for f in funcs:
        if not is_refresher(f.name):
            continue
        for _, text in f.lines:
            code = _strip_line_comment(text)
            for m in MEMBER_COMPOUND_ASSIGN_RE.finditer(code):
                fld = m.group("field")
                acc.setdefault(fld, set()).add(f.name)
    return acc


def refresher_names(funcs: list) -> set:
    return {f.name for f in funcs if is_refresher(f.name)}


def _line_has_refresher_call(code: str, r_names: set) -> bool:
    for rn in r_names:
        # call syntax `name(` (allow leading '.' / '_' receiver forms)
        if re.search(r"(?<![A-Za-z0-9_])%s\s*\(" % re.escape(rn), code):
            return True
    # also accept an inline refresh-verb call token even if the callee wasn't
    # itself parsed as a function in this file (cross-module refresher).
    if re.search(r"(?<![A-Za-z0-9_])[A-Za-z_]\w*\s*\(", code):
        for verb in REFRESH_VERBS:
            if re.search(r"(?<![A-Za-z0-9_])[A-Za-z_]*%s[A-Za-z_]*\s*\(" % verb, code, re.IGNORECASE):
                return True
    return False


def _field_read_on_line(code: str, fld: str) -> bool:
    # a member read `.fld` that is NOT the LHS write-target of the same line
    if not re.search(r"(?:\.|->)\s*%s\b" % re.escape(fld), code):
        return False
    return True


def _line_writes_field(code: str, fld: str) -> bool:
    for m in MEMBER_COMPOUND_ASSIGN_RE.finditer(code):
        if m.group("field") == fld:
            return True
    for m in MEMBER_PLAIN_ASSIGN_RE.finditer(code):
        if m.group("field") == fld:
            return True
    return False


def _is_plain_overwrite_no_self_read(code: str, fld: str) -> bool:
    """True iff `code` PLAIN-assigns (`=`, not compound) `.fld` and the RHS does
    NOT reference `.fld` -- i.e. a pure overwrite `.<fld> = <expr w/o .<fld>>`.

    A pure overwrite is NOT a stale read: the field's value is discarded, so the
    ordering-domination obligation (refresh-before-read) does not apply to it.
    Compound assigns (`+= -= *= /=`) are real read-modify-write and are NEVER a
    pure overwrite; a self-referential plain assign (`.fld = .fld + x`) reads the
    stale value and is NOT a pure overwrite either. Both keep firing.
    """
    # must be a PLAIN assign to fld ...
    if not any(m.group("field") == fld for m in MEMBER_PLAIN_ASSIGN_RE.finditer(code)):
        return False
    # ... and NOT a compound assign to fld (compound is a genuine read-modify-write)
    if any(m.group("field") == fld for m in MEMBER_COMPOUND_ASSIGN_RE.finditer(code)):
        return False
    # `.fld` read-pattern occurrences: exactly one == just the LHS write target;
    # more than one (or an RHS reference) means the field is read, keep firing.
    reads = re.findall(r"(?:\.|->)\s*%s\b" % re.escape(fld), code)
    return len(reads) <= 1


def analyze_source(source: str, lang: str, file_label: str = "<mem>") -> list:
    """Return list[Row] of ordering obligations tagged (advisory)."""
    funcs = extract_functions(source, lang)
    acc = accumulators_of(funcs)
    if not acc:
        return []
    r_names = refresher_names(funcs)
    rows: list = []
    for f in funcs:
        if is_refresher(f.name):
            continue
        if lang == "sol" and VIEW_RE.search(f.header):
            continue
        # require the function to actually mutate state / move value, else a stale
        # read cannot matter (drops pure getters -> keeps FP ~0).
        body_text = "\n".join(t for _, t in f.lines)
        mutates = bool(
            MEMBER_COMPOUND_ASSIGN_RE.search(body_text)
            or MEMBER_PLAIN_ASSIGN_RE.search(body_text)
            or SINK_RE.search(body_text)
        )
        if not mutates:
            continue

        seen_refresher = False
        reported_fields: set = set()
        for lineno, text in f.lines:
            code = _strip_line_comment(text)
            if _line_has_refresher_call(code, r_names):
                seen_refresher = True
                continue
            if seen_refresher:
                continue
            for fld in acc:
                if fld in reported_fields:
                    continue
                if _is_plain_overwrite_no_self_read(code, fld):
                    # a pure overwrite `.fld = <expr not referencing .fld>` discards
                    # the field's value -- it is NOT a stale read, so it carries no
                    # refresh-before-read obligation. (Compound `+= -= *= /=` and a
                    # self-referential `.fld = .fld + x` still fall through and fire.)
                    continue
                if _field_read_on_line(code, fld):
                    r_cands = sorted(acc[fld])
                    rows.append(
                        Row(
                            schema=SCHEMA,
                            tool=TOOL,
                            file=file_label,
                            function=f.name,
                            line=lineno,
                            subject_field=fld,
                            refresher_candidates=r_cands,
                            verdict="needs-fuzz",
                            advisory=True,
                            private_invariant=(
                                "refresher(%s) must dominate reads of accumulator "
                                "'%s' in program order" % ("|".join(r_cands), fld)
                            ),
                            note=(
                                "dependent read of drifting accumulator '%s' at "
                                "line %d is NOT preceded by a refresher call in "
                                "state-changing function '%s'; fuzz must prove "
                                "refresher-domination or find the stale-read reorder"
                                % (fld, lineno, f.name)
                            ),
                        )
                    )
                    reported_fields.add(fld)
    return rows


def analyze_file(path: Path) -> list:
    lang = LANG_BY_EXT.get(path.suffix.lower())
    if lang is None:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return analyze_source(text, lang, file_label=str(path))


_NOISE_DIR_RE = re.compile(
    r"(?:^|/)(?:node_modules|lib|out|\.git|test|tests|mock|mocks|"
    r"chimera_harnesses|broadcast|cache|\.auditooor)(?:/|$)",
    re.IGNORECASE,
)


def iter_targets(paths: list, skip_noise: bool = False):
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            for ext in LANG_BY_EXT:
                for f in pp.rglob("*%s" % ext):
                    if skip_noise and _NOISE_DIR_RE.search(str(f)):
                        continue
                    yield f
        elif pp.is_file():
            yield pp


# Standard sidecar basename (audit-deep / hunt-review / exploit-queue consumers).
SIDECAR_BASENAME = "ordering_dependent_invariant_hypotheses.jsonl"


def run_workspace(ws: str) -> int:
    """Convention entry point for audit-deep Step wiring.

    Scans the workspace source tree (noise dirs skipped), writes one advisory row
    per line to <ws>/.auditooor/ordering_dependent_invariant_hypotheses.jsonl.
    Advisory-first: always returns 0 on success.
    """
    wsp = Path(ws)
    rows: list = []
    for f in iter_targets([ws], skip_noise=True):
        rows.extend(analyze_file(f))
    out_dir = wsp / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    sidecar = out_dir / SIDECAR_BASENAME
    with sidecar.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(asdict(r)) + "\n")
    print(
        "[%s] workspace advisory: %d ordering obligation(s) -> %s "
        "(verdict=needs-fuzz; no auto-credit)" % (TOOL, len(rows), sidecar),
        file=sys.stderr,
    )
    return 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="E9 ordering-dependent-invariant tagger (advisory)")
    ap.add_argument("paths", nargs="*", help="files or directories to screen")
    ap.add_argument("--workspace", default=None,
                    help="audit-deep entry point: scan <ws> tree, write standard sidecar")
    ap.add_argument("--json", dest="json_out", default=None, help="write rows as JSON here")
    ap.add_argument("--quiet", action="store_true", help="rows to stderr, keep stdout for summary")
    args = ap.parse_args(argv)

    if args.workspace:
        return run_workspace(args.workspace)

    if not args.paths:
        ap.error("provide one or more paths, or --workspace <ws>")

    all_rows: list = []
    for f in iter_targets(args.paths):
        all_rows.extend(analyze_file(f))

    out = sys.stderr if args.quiet else sys.stdout
    for r in all_rows:
        print(json.dumps(asdict(r)), file=out)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([asdict(r) for r in all_rows], indent=2), encoding="utf-8"
        )

    print(
        "[%s] advisory: %d ordering-dependent-invariant obligation(s) tagged "
        "(verdict=needs-fuzz; no auto-credit)" % (TOOL, len(all_rows)),
        file=sys.stderr,
    )
    # ADVISORY-FIRST: never fail closed.
    return 0


if __name__ == "__main__":
    sys.exit(main())
