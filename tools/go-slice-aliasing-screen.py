#!/usr/bin/env python3
"""go-slice-aliasing-screen.py - G10 slice-aliasing / missing-defensive-copy screen.

GENERAL INVARIANT / TRUST-ENFORCEMENT class (NOT a bug shape). Go slices are
(ptr, len, cap) fat pointers: passing or returning a slice shares the backing
array. A trust boundary between INTERNALLY-OWNED state and an EXTERNAL caller
must break that aliasing with a defensive copy, or the caller gets a live
handle onto internal memory.

--- North-star method (w8mv5mpcw), applied ---
DELEGATED-TRUSTED ENFORCEMENT: "the backing array of an internal slice field
`T.field` is exclusively owned by T; external callers observe/supply VALUES,
never an alias, so T's state can only change through T's own guarded writers."
PRIVATE INVARIANT that must hold at each boundary function:
  - a GETTER that returns `T.field` must return a COPY (append/copy/Clone),
  - a STORE that assigns a caller-supplied slice PARAM into `T.field` must
    copy it first,
  so no reference to T's backing array crosses the trust boundary.
ATTACK on the invariant: an attacker-drivable caller RETAINS the returned (or
supplied) slice header - a recycled handle / stale ref - and mutates it later;
the write lands directly in T's internal state, past every guarded writer, with
NO upstream visibility (a getter looks read-only; a setter looks like a store).
Reachable whenever the boundary function is externally callable.

--- WHAT THE SCREEN FIRES ON (both directions of the same invariant) ---
Per Go method with receiver `(recv *T)`, when `field` is a SLICE field of T:
  * aliasing-on-read : a `return recv.field` whose returned expression is the
    BARE field (not wrapped in append/copy/slices.Clone/bytes.Clone/...), i.e.
    no defensive copy on the read boundary.
  * aliasing-on-write: an assignment `recv.field = p` whose RHS is a BARE
    slice-typed PARAMETER `p` of the method (not a locally-copied value), i.e.
    no defensive copy on the write boundary.

CORE PREDICATE (load-bearing, mutation-checkable): `is_slice_type(t)` deciding
whether the field/param is a slice AND the "returned/assigned expression is the
bare handle" bareness test. Neutralise either and the screen stops firing.

--- DISCIPLINE ---
ADVISORY-FIRST, FAIL-OPEN. Every row carries verdict='needs-fuzz',
advisory=True, auto_credit=False. A defensively-copied boundary is SILENT (the
bare-handle test fails to match a wrapped expression). Any parse degradation
yields FEWER rows, never a false one - it never flips a verdict or credits a
finding. OFF by default: no-op unless env AUDITOOOR_GO_SLICE_ALIASING=1 or
--force. Never fail-closes a gate.

Emits (only when enabled):
  <ws>/.auditooor/go_slice_aliasing.jsonl            (one row per boundary)
  <ws>/.auditooor/go_slice_aliasing.accounting.json  ({status,rows,files,...})
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ENV = "AUDITOOOR_GO_SLICE_ALIASING"
DETECTOR = "go.slice_aliasing.missing_defensive_copy"

# Dirs never worth scanning (vendored / generated / test toolchain).
_SKIP_DIR = {
    "vendor", "node_modules", "testdata", ".git", "third_party",
    "mocks", "mock",
}
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", "_string.go", "_gen.go", ".gen.go")


# --------------------------------------------------------------------------
# CORE PREDICATE 1: slice-typedness.  Mutation-verify + non-vacuity target:
# neutralising this (always-False) makes every planted positive stop firing.
# --------------------------------------------------------------------------
def is_slice_type(type_str: str) -> bool:
    """True iff a Go type expression denotes a slice (shares a backing array).

    Slices alias; arrays ([N]T) and maps/strings do not in the copy-on-read
    sense we screen. `[]byte`, `[][]byte`, `[]*Foo`, `[]pkg.Bar` -> True;
    `[32]byte`, `map[...]`, `string`, `*T` -> False.
    """
    t = type_str.strip()
    # Strip a leading pointer (a *[]byte field is still slice-aliasing on deref,
    # but we conservatively only treat a bare/leading `[]` as a slice).
    if t.startswith("[]"):
        return True
    return False


# --------------------------------------------------------------------------
# CORE PREDICATE 2: defensive-copy wrappers.  A returned/assigned expression
# that invokes one of these is SILENT (guarded).  Kept as a named module
# constant so a test can neutralise it and prove it is load-bearing.
# --------------------------------------------------------------------------
COPY_WRAPPERS: Tuple[str, ...] = (
    "append(",
    "copy(",
    "slices.Clone(",
    "bytes.Clone(",
    "maps.Clone(",
    "CopyBytes(",       # go-ethereum common.CopyBytes
    "Clone(",           # generic *.Clone(...)
    ".Bytes(",          # returns an owned copy by convention
    "make(",
)

_STRUCT_RE = re.compile(r"\btype\s+(\w+)\s+struct\s*\{")
# A struct field line: `name  []Type` or grouped `a, b []Type` (we capture the
# type; each preceding comma-name shares it).
_FIELD_RE = re.compile(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+([\[\]\w\.\*\{\}<> ]+?)(?:\s+`[^`]*`)?\s*$")
# Method header: func (recv *T) Name(params) rets {
_METHOD_RE = re.compile(
    r"\bfunc\s*\(\s*(\w+)\s+\*?\s*(\w+)\s*\)\s*(\w+)\s*\(([^)]*)\)"
)
# A slice-typed parameter inside a param list: `name []type`.
_PARAM_SLICE_RE = re.compile(r"\b([A-Za-z_]\w*)\s+(\[\][\w\.\*\[\]]+)")


def _iter_go_files(root: Path) -> List[Path]:
    out: List[Path] = []
    if root.is_file():
        return [root] if root.suffix == ".go" else []
    for p in root.rglob("*.go"):
        parts = set(p.parts)
        if parts & _SKIP_DIR:
            continue
        if p.name.endswith(_SKIP_SUFFIX):
            continue
        out.append(p)
    return out


def _struct_slice_fields(text: str) -> Dict[str, Set[str]]:
    """Map struct type name -> set of its SLICE-typed field names.

    Brace-depth scan from each `type T struct {` to its matching `}`.
    """
    fields: Dict[str, Set[str]] = {}
    for m in _STRUCT_RE.finditer(text):
        tname = m.group(1)
        i = m.end()  # just past the opening '{'
        depth = 1
        body_start = i
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        body = text[body_start : i - 1]
        acc: Set[str] = fields.setdefault(tname, set())
        for line in body.splitlines():
            ln = line.strip()
            if not ln or ln.startswith("//"):
                continue
            fm = _FIELD_RE.match(line)
            if not fm:
                continue
            names_raw, ftype = fm.group(1), fm.group(2).strip()
            if not is_slice_type(ftype):
                continue
            for nm in re.split(r"\s*,\s*", names_raw.strip()):
                if nm:
                    acc.add(nm)
    return fields


def _method_body(text: str, open_brace_idx: int) -> Tuple[str, int]:
    """Return (body_text, end_index) for the brace block starting at
    open_brace_idx (index of the '{')."""
    depth = 0
    i = open_brace_idx
    start = open_brace_idx + 1
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i], i
        i += 1
    return text[start:], len(text)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _expr_is_copy_guarded(expr: str) -> bool:
    """True if the (returned or assigned) expression invokes a defensive-copy
    wrapper - i.e. it is NOT a bare handle."""
    for w in COPY_WRAPPERS:
        if w in expr:
            return True
    return False


def _slice_params(param_str: str) -> Set[str]:
    return {m.group(1) for m in _PARAM_SLICE_RE.finditer(param_str)}


def param_defensively_recopied(body: str, param: str) -> bool:
    """CORE PREDICATE (write-path guard, load-bearing): True iff `param` is
    re-copied to a fresh backing array somewhere in the body before being
    stored (`p = append(...)` / `copy(dst, p)` / `p = slices.Clone(p)`), so the
    subsequent `recv.field = p` no longer aliases the caller's array.
    Neutralise this (always-False) and a copy-then-store STOPS being silent.
    """
    p = re.escape(param)
    if re.search(rf"\b{p}\s*=\s*append\(", body):
        return True
    if re.search(rf"\b{p}\s*=\s*(?:slices|bytes)\.Clone\(", body):
        return True
    if re.search(rf"copy\(\s*\w+\s*,\s*{p}\b", body):
        return True
    return False


def scan_go_source(text: str, path: str) -> List[Dict[str, Any]]:
    """Pure screen over one Go source's text. Returns advisory rows."""
    rows: List[Dict[str, Any]] = []
    slice_fields = _struct_slice_fields(text)
    if not slice_fields:
        return rows

    for mm in _METHOD_RE.finditer(text):
        recv, rtype, fn, params = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        rfields = slice_fields.get(rtype)
        if not rfields:
            continue
        # locate the method's opening brace (after the return-type list).
        brace = text.find("{", mm.end())
        if brace == -1:
            continue
        body, _end = _method_body(text, brace)
        pslices = _slice_params(params)

        # ---- aliasing-on-read: return recv.field (bare) ----
        for rm in re.finditer(rf"\breturn\s+(.+?)(?:\n|$)", body):
            ret_expr = rm.group(1).strip()
            if _expr_is_copy_guarded(ret_expr):
                continue
            # first comma-separated returned value
            first = ret_expr.split(",")[0].strip()
            fm = re.fullmatch(rf"{re.escape(recv)}\.(\w+)", first)
            if not fm:
                continue
            field = fm.group(1)
            if field not in rfields:
                continue
            off = brace + 1 + rm.start()
            rows.append(_row("aliasing-on-read", path, _line_of(text, off),
                             rtype, field, fn, first))

        # ---- aliasing-on-write: recv.field = <bare slice param> ----
        for am in re.finditer(
            rf"(?<![=!<>+\-*/%&|^])\b{re.escape(recv)}\.(\w+)\s*=\s*([^=\n][^\n]*)",
            body,
        ):
            field, rhs = am.group(1), am.group(2).strip()
            if field not in rfields:
                continue
            rhs_first = rhs.split("//")[0].strip().rstrip(";")
            if not re.fullmatch(r"\w+", rhs_first):
                continue  # RHS must be a BARE identifier (not a copy expr)
            if rhs_first not in pslices:
                continue  # ...and that identifier must be a slice-typed param
            # A defensive re-copy of the param anywhere in the body guards it.
            if param_defensively_recopied(body, rhs_first):
                continue
            off = brace + 1 + am.start()
            rows.append(_row("aliasing-on-write", path, _line_of(text, off),
                             rtype, field, fn, f"{recv}.{field} = {rhs_first}"))
    return rows


def _row(kind, path, line, rtype, field, fn, evidence) -> Dict[str, Any]:
    inv = (f"internal slice field {rtype}.{field} is exclusively owned; the "
           f"{'read' if kind == 'aliasing-on-read' else 'write'} boundary must "
           f"break aliasing with a defensive copy")
    hq = (f"Can an external caller retain the {'returned' if kind=='aliasing-on-read' else 'supplied'} "
          f"slice header of {rtype}.{field} and mutate its backing array later to "
          f"corrupt internal state, bypassing every guarded writer?")
    return {
        "detector": DETECTOR,
        "kind": kind,
        "file": path,
        "line": line,
        "receiver_type": rtype,
        "field": field,
        "fn": fn,
        "invariant": inv,
        "evidence": evidence,
        "hacker_question": hq,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def emit_slice_aliasing(
    ws: Path,
    scan_root: Optional[Path] = None,
    max_rows: int = 2000,
    force: bool = False,
) -> Dict[str, Any]:
    """Screen a workspace (or a scan_root) and write the advisory sidecars.

    OFF by default (fail-open): unless force or env, status='off-by-default',
    0 rows, no sidecar mutation beyond an accounting stub.
    """
    acct: Dict[str, Any] = {
        "detector": DETECTOR,
        "status": "ok",
        "rows": 0,
        "files_scanned": 0,
        "advisory": True,
    }
    enabled = force or os.environ.get(ENV, "") not in ("", "0", "false", "False")
    if not enabled:
        acct["status"] = "off-by-default"
        return acct

    root = Path(scan_root) if scan_root else Path(ws)
    rows: List[Dict[str, Any]] = []
    files = _iter_go_files(root)
    scanned = 0
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue  # fail-open: a bad read never manufactures a row
        scanned += 1
        try:
            rows.extend(scan_go_source(text, str(f)))
        except Exception:
            continue  # fail-open on a parse hiccup
        if len(rows) >= max_rows:
            rows = rows[:max_rows]
            break

    acct["rows"] = len(rows)
    acct["files_scanned"] = scanned

    out_dir = Path(ws) / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    jl = out_dir / "go_slice_aliasing.jsonl"
    jl.write_text("".join(json.dumps(r) + "\n" for r in rows))
    (out_dir / "go_slice_aliasing.accounting.json").write_text(
        json.dumps(acct, indent=2)
    )
    return acct


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="G10 Go slice-aliasing advisory screen")
    ap.add_argument("--ws", required=True, help="workspace root (sidecar dest)")
    ap.add_argument("--scan-root", default=None, help="alt dir/file to scan")
    ap.add_argument("--max-rows", type=int, default=2000)
    ap.add_argument("--force", action="store_true", help="enable regardless of env")
    ap.add_argument("--json", action="store_true", help="print accounting json")
    args = ap.parse_args(argv)
    acct = emit_slice_aliasing(
        Path(args.ws),
        Path(args.scan_root) if args.scan_root else None,
        args.max_rows,
        args.force,
    )
    if args.json:
        print(json.dumps(acct, indent=2))
    else:
        print(f"[{DETECTOR}] status={acct['status']} rows={acct['rows']} "
              f"files={acct['files_scanned']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
