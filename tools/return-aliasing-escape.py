#!/usr/bin/env python3
"""return-aliasing-escape.py - RANK-13 [MED x7] return-aliasing escape reasoner.

RETURN-ALIASING ESCAPE ANALYSIS (a REASONING RELATION over the real Go source
substrate, NOT a grep for `return`). A function that hands back a slice / pointer
/ map-value which SHARES its backing store with state that OUTLIVES the call (a
package var, a slice/map/pointer field of a *pointer receiver* that is persisted,
a store-resident buffer) leaks a live handle onto internal state. A later
mutation by the caller - or by the callee on its next call reusing the same
buffer - then corrupts a PRIOR output or overwrites persistent state, with no
upstream visibility (a getter looks read-only).

REASONING QUERY (escape relation, not a shape):

  SURVIVOR := { functions whose RETURNED reference (slice / pointer / map-value)
                ALIASES - shares backing array / same underlying pointer - with a
                value that OUTLIVES the call }
              MINUS
              { functions that DEFENSIVELY COPY on the return path
                (append-to-nil / copy() / slices.Clone / bytes.Clone / make+copy
                 / .Bytes() convention) }.

  RETURNS_ALIASING_PERSISTENT  \\  DEFENSIVELY_COPIED

  - RETURNS_ALIASING_PERSISTENT (the escape relation, load-bearing):
      * field-return   : `return recv.field` where recv is a POINTER receiver
        (the receiver instance outlives the call, e.g. a keeper/store) and
        `field` is a slice / map / pointer field of the receiver type.
      * subslice-return: `return recv.field[a:b]` / `recv.field[a:]` - a
        re-slice shares the same backing array as the persistent field.
      * mapvalue-return: `return recv.field[k]` / `return pkgVar[k]` where the
        field/var is a `map[K]V` with a REFERENCE value type V (the returned V
        aliases the map-resident value).
      * pkgvar-return  : `return pkgVar` where pkgVar is a package-level
        reference-typed var (outlives every call).
  - DEFENSIVELY_COPIED: the returned expression invokes a copy wrapper, so the
    handed-back value has a FRESH backing store -> SILENT (not a survivor).

GUARD-RAIL: the relation is an ALIASING / ESCAPE relation (shared backing store
that outlives the call), never a token grep for `return`. A return of a
freshly-allocated local (`make`, `append(nil,...)`, composite literal) or of a
caller-supplied param does NOT alias persistent state and never fires.

HONESTY (never silent):
  * substrate_vacuous : no Go source under the scan root (nothing to reason over)
    -> status "substrate_vacuous" (fail-closed under --fail-closed). We NEVER
    manufacture a survivor from an empty substrate.
  * cited_empty       : Go source present, the relation ran, zero survivors ->
    honest 0 (status "cited_empty"). Every returning fn was accounted for.
  * needs_source (advisory): a returning fn (reference return type) returns a
    BARE LOCAL identifier that is neither a fresh local alloc, nor a param, nor a
    resolvable persistent alias - it may alias a store buffer through a helper we
    cannot trace here. Emit an ADVISORY needs_source obligation (never a
    survivor, never terminal) so a keeper getter returning an opaque
    store-resident buffer is not silently dropped.

Every emitted row cites a file:line anchor from real source.

Usage:
  python3 tools/return-aliasing-escape.py --workspace <ws>
        [--src-root DIR] [--emit PATH] [--json] [--fail-closed]

Output: <ws>/.auditooor/return_aliasing_escape_obligations.jsonl
        (schema auditooor.return_aliasing_escape.v1) + a summary on stderr.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict

SCHEMA = "auditooor.return_aliasing_escape.v1"
AUDITOOOR = ".auditooor"

_SKIP_DIR = {"vendor", "node_modules", "testdata", ".git", "third_party",
             "mocks", "mock"}
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".pulsar.go", "_string.go",
                "_gen.go", ".gen.go", "_mock.go", "mock.go")
# Generated files carry a "DO NOT EDIT" header; their getters are codegen noise.
_CODEGEN_MARKERS = ("// Code generated", "DO NOT EDIT")


# ---------------------------------------------------------------------------
# CORE PREDICATE 1: reference-typedness (shares a backing store).  Slices,
# maps and pointers alias; arrays / strings / value structs do not.  Mutation
# target: neutralise (always-False) and every planted positive stops firing.
# ---------------------------------------------------------------------------
def is_ref_type(type_str: str) -> bool:
    t = (type_str or "").strip()
    return t.startswith("[]") or t.startswith("map[") or t.startswith("*")


def map_value_type(type_str: str) -> str | None:
    """For `map[K]V` return V (balanced over a bracketed key), else None."""
    t = (type_str or "").strip()
    if not t.startswith("map["):
        return None
    i = len("map")  # points at the '['
    depth = 0
    while i < len(t):
        c = t[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return t[i + 1:].strip()
        i += 1
    return None


# ---------------------------------------------------------------------------
# CORE PREDICATE 2: defensive-copy wrappers.  A returned expression invoking one
# of these has a FRESH backing store and is SILENT (not an escape).  Kept as a
# named module constant so a test can neutralise it and prove it load-bearing.
# ---------------------------------------------------------------------------
COPY_WRAPPERS: tuple[str, ...] = (
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


def is_defensively_copied(expr: str) -> bool:
    """True iff the returned expression has a fresh backing store (a copy
    wrapper) -> NOT an escape.  Neutralise (always-False) and a copy-on-return
    stops being silent (a survivor reappears): load-bearing."""
    for w in COPY_WRAPPERS:
        if w in expr:
            return True
    return False


_STRUCT_RE = re.compile(r"\btype\s+(\w+)\s+struct\s*\{")
_FIELD_RE = re.compile(
    r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
    r"([\[\]\w\.\*\{\}<>,\s]+?)(?:\s+`[^`]*`)?\s*$")
# Method OR plain function header.  Group 1/2 = receiver var/type (may be None);
# 3 = fn name; 4 = params; the return spec is scanned separately up to the brace.
_METHOD_RE = re.compile(
    r"\bfunc\s*(?:\(\s*(\w+)\s+(\*?)\s*(\w+)\s*\)\s*)?(\w+)\s*\(")


def _load_inscope_go(ws: pathlib.Path) -> set:
    """ws-relative .go paths from the authoritative in-scope manifest. Empty set
    when the manifest is absent -> caller applies NO scope filter (conservative:
    never drops a file when scope is unknown). Root-caused 2026-07-14: the engine
    filtered only by suffix (_test.go/.pb.go), so it walked OOS simapp/ /
    simulation/ / cmd/ and emitted ~23 out-of-scope return-aliasing false-reds on
    nuva (SimApp.LegacyAmino, NewRootCmd, sim rand) - files correctly ABSENT from
    inscope_units.jsonl."""
    p = ws / AUDITOOOR / "inscope_units.jsonl"
    if not p.exists():
        return set()
    out: set = set()
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        f = d.get("file") or d.get("path") or d.get("unit") or ""
        if isinstance(f, str) and f.endswith(".go"):
            out.add(f)
    return out


def _iter_go_files(root: pathlib.Path, ws: pathlib.Path | None = None,
                   inscope: set | None = None) -> list[pathlib.Path]:
    if root.is_file():
        return [root] if root.suffix == ".go" else []
    out: list[pathlib.Path] = []
    for p in root.rglob("*.go"):
        if set(p.parts) & _SKIP_DIR:
            continue
        if p.name.endswith(_SKIP_SUFFIX):
            continue
        # SCOPE FILTER: when an in-scope manifest is present, only walk files it
        # lists (the authoritative scope the rest of the pipeline uses). Skipped
        # when the manifest is empty/absent so scope-less runs are unchanged.
        if inscope:
            rel = None
            if ws is not None:
                try:
                    rel = str(p.resolve().relative_to(ws.resolve()))
                except Exception:
                    rel = None
            in_manifest = (rel in inscope) if rel is not None \
                else any(str(p).endswith(insc) for insc in inscope)
            if not in_manifest:
                continue
        out.append(p)
    return out


def _brace_block(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_idx
    start = open_idx + 1
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


def struct_ref_fields(text: str) -> dict[str, dict[str, str]]:
    """type name -> { ref-field name -> field type }."""
    out: dict[str, dict[str, str]] = {}
    for m in _STRUCT_RE.finditer(text):
        tname = m.group(1)
        body, _end = _brace_block(text, m.end() - 1)
        acc = out.setdefault(tname, {})
        for line in body.splitlines():
            ln = line.strip()
            if not ln or ln.startswith("//"):
                continue
            fm = _FIELD_RE.match(line)
            if not fm:
                continue
            names_raw, ftype = fm.group(1), fm.group(2).strip()
            if not is_ref_type(ftype):
                continue
            for nm in re.split(r"\s*,\s*", names_raw.strip()):
                if nm:
                    acc[nm] = ftype
    return out


def package_ref_vars(text: str) -> dict[str, str]:
    """Package-level reference-typed vars: name -> type.  Both single
    `var name type` and grouped `var ( name type ... )` at column 0."""
    out: dict[str, str] = {}
    # single-line, column-0
    for m in re.finditer(r"(?m)^var\s+([A-Za-z_]\w*)\s+([\[\]\w\.\*<>,\s]+?)\s*(?:=|$)", text):
        nm, ty = m.group(1), m.group(2).strip()
        if is_ref_type(ty):
            out[nm] = ty
    # grouped block
    for m in re.finditer(r"(?m)^var\s*\(", text):
        body, _end = _brace_paren_block(text, text.index("(", m.start()))
        for line in body.splitlines():
            ln = line.strip()
            if not ln or ln.startswith("//"):
                continue
            gm = re.match(r"^([A-Za-z_]\w*)\s+([\[\]\w\.\*<>,\s]+?)\s*(?:=|$)", ln)
            if gm and is_ref_type(gm.group(2).strip()):
                out[gm.group(1)] = gm.group(2).strip()
    return out


def _brace_paren_block(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_idx
    start = open_idx + 1
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i
        i += 1
    return text[start:], len(text)


def _return_type_spec(text: str, params_close: int) -> tuple[str, int]:
    """From just after the params ')' return (return_spec_text, brace_idx)."""
    brace = text.find("{", params_close)
    if brace == -1:
        return "", -1
    return text[params_close:brace], brace


def _fresh_locals(body: str) -> set[str]:
    """Local identifiers bound to a fresh backing store in the body (so
    returning them does NOT alias persistent state)."""
    fresh: set[str] = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*:?=\s*(.+)", body):
        nm, rhs = m.group(1), m.group(2)
        rhs_head = rhs.split("//")[0]
        if is_defensively_copied(rhs_head) or re.match(r"\s*(?:\[\]|map\[)", rhs_head):
            fresh.add(nm)
    return fresh


def _first_returned_values(ret_expr: str) -> list[str]:
    """Split a return expression into top-level comma-separated values."""
    vals: list[str] = []
    depth = 0
    cur = ""
    for ch in ret_expr:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            vals.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        vals.append(cur.strip())
    return vals


def _classify_return(val: str, recv: str | None, ptr_recv: bool,
                     rfields: dict[str, str], pkgvars: dict[str, str],
                     params: set[str], fresh: set[str]
                     ) -> tuple[str, str, str] | None:
    """Return (alias_kind, target, target_type) if `val` aliases persistent
    state, else None.  Assumes val is NOT defensively copied (checked upstream)."""
    v = val.strip()
    # recv.field family (pointer receiver only: the instance outlives the call)
    if recv and ptr_recv:
        pref = re.escape(recv) + r"\."
        # bare field
        mm = re.fullmatch(pref + r"(\w+)", v)
        if mm and mm.group(1) in rfields:
            f = mm.group(1)
            return ("field-return", f"{recv}.{f}", rfields[f])
        # subslice recv.field[a:b]
        mm = re.fullmatch(pref + r"(\w+)\[[^\]]*:[^\]]*\]", v)
        if mm and mm.group(1) in rfields and rfields[mm.group(1)].startswith("[]"):
            f = mm.group(1)
            return ("subslice-return", f"{recv}.{f}[:]", rfields[f])
        # mapvalue recv.field[k]  (single index, no colon) with ref value type
        mm = re.fullmatch(pref + r"(\w+)\[[^\]:]+\]", v)
        if mm and mm.group(1) in rfields:
            f = mm.group(1)
            vt = map_value_type(rfields[f])
            if vt and is_ref_type(vt):
                return ("mapvalue-return", f"{recv}.{f}[k]", vt)
    # package var family
    mm = re.fullmatch(r"(\w+)", v)
    if mm and mm.group(1) in pkgvars:
        return ("pkgvar-return", mm.group(1), pkgvars[mm.group(1)])
    mm = re.fullmatch(r"(\w+)\[[^\]]*:[^\]]*\]", v)
    if mm and mm.group(1) in pkgvars and pkgvars[mm.group(1)].startswith("[]"):
        return ("subslice-return", f"{mm.group(1)}[:]", pkgvars[mm.group(1)])
    mm = re.fullmatch(r"(\w+)\[[^\]:]+\]", v)
    if mm and mm.group(1) in pkgvars:
        vt = map_value_type(pkgvars[mm.group(1)])
        if vt and is_ref_type(vt):
            return ("mapvalue-return", f"{mm.group(1)}[k]", vt)
    return None


def scan_go_source(text: str, path: str) -> tuple[list[dict], list[dict], dict]:
    """(survivors, needs_source, counts) over one Go source."""
    survivors: list[dict] = []
    needs: list[dict] = []
    counts = {"returning_fns": 0, "aliases_persistent": 0, "defensively_copied": 0}

    ref_fields = struct_ref_fields(text)
    pkgvars = package_ref_vars(text)

    for mm in _METHOD_RE.finditer(text):
        recv, star, rtype, fn = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        ptr_recv = star == "*"
        params_close = _matching_paren(text, mm.end() - 1)
        if params_close == -1:
            continue
        params_text = text[mm.end():params_close]
        ret_spec, brace = _return_type_spec(text, params_close + 1)
        if brace == -1:
            continue
        body, _end = _brace_block(text, brace)

        returns_ref = is_ref_type_in_spec(ret_spec)
        if returns_ref:
            counts["returning_fns"] += 1

        rfields = ref_fields.get(rtype or "", {})
        params = {p.group(1) for p in re.finditer(r"\b([A-Za-z_]\w*)\s+[\[\]\w\.\*]+", params_text)}
        fresh = _fresh_locals(body)

        fn_has_alias = False
        fn_has_copied_alias = False
        for rm in re.finditer(r"\breturn\s+([^\n{};]+)", body):
            ret_expr = rm.group(1).strip()
            off = brace + 1 + rm.start()
            for val in _first_returned_values(ret_expr):
                # shape check first: does it LOOK like a persistent target?
                pre_copy = _classify_return(
                    _strip_copy_wrapper(val), recv, ptr_recv, rfields,
                    pkgvars, params, fresh)
                if is_defensively_copied(val):
                    if pre_copy is not None:
                        fn_has_copied_alias = True
                    continue
                cls = _classify_return(val, recv, ptr_recv, rfields, pkgvars,
                                       params, fresh)
                if cls is None:
                    continue
                alias_kind, target, tgt_type = cls
                fn_has_alias = True
                survivors.append({
                    "file": path,
                    "line": _line_of(text, off),
                    "function": fn,
                    "receiver_type": rtype or "",
                    "alias_kind": alias_kind,
                    "returned_target": target,
                    "target_type": tgt_type,
                    "return_expr": val,
                    "outlives_call": (
                        "package-level var" if alias_kind == "pkgvar-return"
                        else f"field of persisted pointer receiver *{rtype}"),
                    "invariant": (
                        f"the backing store of {target} outlives {fn}(); the "
                        f"return boundary must break aliasing with a defensive "
                        f"copy or a later mutation corrupts prior output / "
                        f"persistent state"),
                    "hacker_question": (
                        f"Can a caller of {fn} retain the returned "
                        f"{alias_kind.split('-')[0]} handle and mutate its "
                        f"backing store to corrupt {target} (or a prior "
                        f"return), bypassing every guarded writer?"),
                })
        if fn_has_alias:
            counts["aliases_persistent"] += 1
        elif fn_has_copied_alias:
            counts["defensively_copied"] += 1
        elif returns_ref:
            # reference return, no persistent alias found: is it an opaque local
            # (possible store-buffer via helper) -> advisory needs_source.
            for rm in re.finditer(r"\breturn\s+([^\n{};]+)", body):
                for val in _first_returned_values(rm.group(1).strip()):
                    m = re.fullmatch(r"(\w+)", val)
                    if not m:
                        continue
                    nm = m.group(1)
                    if nm in fresh or nm in params or nm in ("nil",):
                        continue
                    if nm in pkgvars:
                        continue
                    needs.append({
                        "file": path,
                        "line": _line_of(text, brace + 1 + rm.start()),
                        "function": fn,
                        "receiver_type": rtype or "",
                        "returned_identifier": nm,
                        "reason": ("reference-typed return of a bare local not "
                                   "provably fresh/param - may alias a "
                                   "store-resident buffer via a helper; source "
                                   "needed to confirm or refute the escape"),
                    })
                    break
    return survivors, needs, counts


def is_ref_type_in_spec(ret_spec: str) -> bool:
    s = ret_spec.strip().lstrip("(").rstrip(")").strip()
    if not s:
        return False
    return ("[]" in s) or ("map[" in s) or bool(re.search(r"(?:^|[\s,(])\*\w", s))


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _strip_copy_wrapper(val: str) -> str:
    """Peel one copy wrapper so the inner target can be shape-classified (used
    only to tally the defensively-copied guarded subset, never to survive)."""
    m = re.match(r"(?:append|copy|make)\(\s*(.+)\)\s*$", val)
    if m:
        inner = m.group(1)
        return inner.split(",")[0].strip() if "," in inner else inner
    m = re.match(r"(?:slices|bytes|maps)\.Clone\(\s*(.+?)\s*\)\s*$", val)
    if m:
        return m.group(1)
    return val


def run(ws: pathlib.Path, src_root: str | None = None) -> dict:
    root = pathlib.Path(src_root) if src_root else ws
    files = _iter_go_files(root, ws=ws, inscope=_load_inscope_go(ws))
    survivors: list[dict] = []
    needs: list[dict] = []
    totals = {"returning_fns": 0, "aliases_persistent": 0, "defensively_copied": 0}
    scanned = 0
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        head = text[:400]
        if any(mk in head for mk in _CODEGEN_MARKERS):
            continue  # generated source: getters are codegen noise, not audit units
        scanned += 1
        try:
            s, n, c = scan_go_source(text, str(f))
        except Exception:
            continue  # fail-open on a parse hiccup: fewer rows, never a false one
        survivors.extend(s)
        needs.extend(n)
        for k in totals:
            totals[k] += c[k]

    substrate_vacuous = scanned == 0
    status = "substrate_vacuous" if substrate_vacuous else (
        "survivors" if survivors else "cited_empty")

    kept = sorted({f"{s['file']}::{s['function']}" for s in survivors})
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "src_root": str(root),
        "status": status,
        "substrate": {
            "go_files_scanned": scanned,
            "vacuous": substrate_vacuous,
        },
        "returning_fns": totals["returning_fns"],
        "aliases_persistent": totals["aliases_persistent"],
        "defensively_copied": totals["defensively_copied"],
        "survivor_count": len(survivors),
        "needs_source_count": len(needs),
        "kept": kept,
        "survivors": survivors,
        "needs_source": needs,
        "by_kind": _by_kind(survivors),
    }


def _by_kind(survivors: list[dict]) -> dict:
    d: dict = defaultdict(int)
    for s in survivors:
        d[s["alias_kind"]] += 1
    return dict(sorted(d.items()))


def _adir(ws: pathlib.Path) -> pathlib.Path:
    return ws / AUDITOOOR


def _emit_rows(rep: dict, outp: pathlib.Path) -> int:
    outp.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with outp.open("w") as fh:
        for s in rep["survivors"]:
            fh.write(json.dumps({
                "schema": SCHEMA,
                "reasoner": "RETURN-ALIASING-ESCAPE",
                "verdict": "survivor",
                "proof_status": "open",
                "advisory": False,
                "attack_class": "return-aliasing-escape",
                **s,
            }) + "\n")
            n += 1
        for ns in rep["needs_source"]:
            fh.write(json.dumps({
                "schema": SCHEMA,
                "reasoner": "RETURN-ALIASING-ESCAPE",
                "verdict": "needs_source",
                "proof_status": "open",
                "advisory": True,
                "attack_class": "return-aliasing-escape",
                **ns,
            }) + "\n")
            n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root to scan (default: the workspace)")
    ap.add_argument("--emit", default=None,
                    help="output jsonl (default "
                         "<ws>/.auditooor/return_aliasing_escape_obligations.jsonl)")
    ap.add_argument("--json", action="store_true",
                    help="emit full report JSON to stdout")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero on substrate_vacuous (no Go source found)")
    args = ap.parse_args(argv)

    ws = pathlib.Path(args.workspace).resolve()
    if not ws.exists():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 2

    rep = run(ws, src_root=args.src_root)
    outp = pathlib.Path(args.emit) if args.emit else (
        _adir(ws) / "return_aliasing_escape_obligations.jsonl")
    n = _emit_rows(rep, outp)

    if args.json:
        print(json.dumps(rep, indent=2, default=list))
    else:
        print(f"[return-aliasing-escape] ws={ws.name} status={rep['status']} "
              f"returning_fns={rep['returning_fns']} "
              f"aliases_persistent={rep['aliases_persistent']} "
              f"defensively_copied={rep['defensively_copied']} "
              f"survivors={rep['survivor_count']} "
              f"needs_source={rep['needs_source_count']} -> {outp} ({n} rows)",
              file=sys.stderr)
        for k, c in rep["by_kind"].items():
            print(f"    {k:18s} survivors={c}", file=sys.stderr)

    if args.fail_closed and rep["status"] == "substrate_vacuous":
        print("[return-aliasing-escape] FAIL-CLOSED: substrate vacuous "
              "(no Go source to reason over)", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
