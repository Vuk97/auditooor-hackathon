#!/usr/bin/env python3
"""arch-invariant-suspension-window.py  (R2) - invariant-SUSPENSION-window screen.

WHAT THIS TOOL DOES  (north-star: "a TRUSTED ENFORCEMENT is bypassable / its
private invariant is unsound")
=============================================================================
A whole-system SAFETY property that several storage cells jointly encode (a
conservation / coupled / coherence set S = {A, B, ...} that must move together)
is momentarily SUSPENDED - temporarily FALSE - during the window between the
first member's write and the last member's write. If control YIELDS the trust
boundary inside that window (an external call, a transfer, an ERC receiver hook,
a delegatecall, a low-level call), a reachable observer can re-enter or read the
half-updated set and consume the FALSE invariant.

  delegated-and-trusted invariant : "S is always internally consistent"
  private invariant it rests on    : "no reachable reader observes S while a
                                      writer has started but not settled it"
  the attack                       : drive a yield inside the write window; a
                                      view or sibling external entrypoint reads
                                      one member updated, its partner stale.

This is the INVARIANT plane of read-only / cross-function reentrancy. It is
deliberately MODIFIER-AGNOSTIC and VIEW-INCLUSIVE: it does not ask "is there a
nonReentrant modifier" (a shape); it asks "which coupled INVARIANT is suspended
at this yield and who can read it". A nonReentrant modifier on the WRITER does
not stop an unguarded VIEW from observing the suspended set - that is the exact
read-only-reentrancy blind spot both callback-shape and nonReentrant-presence
detectors miss.

WHAT IT IS NOT (dedup)
======================
  - Requires a COUPLED set (>=2 distinct storage cells written in one fn). A
    single-cell reentrancy is A7 / callback-reentrancy-composition's turf and is
    intentionally NOT flagged here.
  - It JOINs the yield against the coupled-write set; callback-reentrancy-
    composition matches callback SHAPES without that JOIN.
  - It fires ONLY when a member is written AFTER the yield (partial update). Pure
    checks-effects-interactions (all writes settled before the yield) is GREEN.

GENERAL, not a bug SHAPE: the emitted property is impact-agnostic
("no reachable observer sees a suspended coupled invariant"), independent of
whether the payoff is theft, DoS, or oracle drift.

ADVISORY-FIRST
==============
Every row carries verdict="needs-fuzz", advisory=True, auto_credit=False. This
tool NEVER flips a gate and NEVER fail-closes by default. It only sets
accounting["blocking"]=True (and main() returns rc=1) when BOTH
AUDITOOOR_YIELD_WINDOW_ENFORCE and AUDITOOOR_L37_STRICT are set AND >=1 open
(un-analyzed reader) row exists. Hang it on the wsitb-enforcement-plane /
completeness-matrix enforcement-point axis, not a silo.

Usage:
  python3 tools/arch-invariant-suspension-window.py --workspace <ws> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

OUT_REL = os.path.join(".auditooor", "invariant_suspension_window_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "invariant_suspension_window_accounting.json")

# ---------------------------------------------------------------------------
# Source-file selection (self-contained; skips test/mock/lib/script paths).
# ---------------------------------------------------------------------------
_SKIP_PARTS = frozenset({
    "test", "tests", "mock", "mocks", "dev", "script", "scripts",
    "lib", "libs", "out", "cache", "node_modules", "chimera_harnesses",
    "prior_audits", "audits", "ARCHIVED_FOR_SCAN",
})
_SKIP_SUFFIXES = (".t.sol", ".s.sol", ".spec.sol")


def _is_scope_file(p: pathlib.Path) -> bool:
    if any(part in _SKIP_PARTS for part in p.parts):
        return False
    if p.name.endswith(_SKIP_SUFFIXES):
        return False
    return True


def _inscope_files(ws: pathlib.Path, max_files: int = 4000):
    """Prefer .auditooor/inscope_units.jsonl file set; else glob **/*.sol."""
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    picked: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    if inscope.is_file():
        for line in inscope.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rel = rec.get("file") or rec.get("path")
            if not rel or not str(rel).endswith(".sol"):
                continue
            fp = (ws / rel).resolve()
            if fp in seen or not fp.is_file():
                continue
            seen.add(fp)
            picked.append(fp)
    if picked:
        return picked[:max_files]
    for p in sorted(ws.glob("**/*.sol")):
        if len(picked) >= max_files:
            break
        if not _is_scope_file(p):
            continue
        picked.append(p)
    return picked


# ---------------------------------------------------------------------------
# Lightweight Solidity lexing (comment/string-safe, brace-matched spans).
# ---------------------------------------------------------------------------
def strip_comments_strings(src: str) -> str:
    """Replace comment + string-literal bytes with spaces, preserving offsets."""
    out = list(src)
    i, n = 0, len(src)
    state = None  # None | 'line' | 'block' | 'dq' | 'sq'
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "line"; out[i] = out[i + 1] = " "; i += 2; continue
            if c == "/" and nxt == "*":
                state = "block"; out[i] = out[i + 1] = " "; i += 2; continue
            if c == '"':
                state = "dq"; out[i] = " "; i += 1; continue
            if c == "'":
                state = "sq"; out[i] = " "; i += 1; continue
            i += 1; continue
        if state == "line":
            if c == "\n":
                state = None
            else:
                out[i] = " "
            i += 1; continue
        if state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "; state = None; i += 2; continue
            if c != "\n":
                out[i] = " "
            i += 1; continue
        if state == "dq":
            out[i] = " "
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2; continue
            if c == '"':
                state = None
            i += 1; continue
        if state == "sq":
            out[i] = " "
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2; continue
            if c == "'":
                state = None
            i += 1; continue
    return "".join(out)


def _match_brace(src: str, open_idx: int) -> int:
    """Given index of a '{', return index just after the matching '}' (or len)."""
    depth = 0
    i, n = open_idx, len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


_CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)")


def find_contracts(clean: str):
    """Yield (name, body_inner, body_start_offset) for each `contract` def.
    body_inner excludes the outer braces; offsets are into `clean`."""
    out = []
    for m in _CONTRACT_RE.finditer(clean):
        brace = clean.find("{", m.end())
        if brace < 0:
            continue
        end = _match_brace(clean, brace)
        out.append((m.group(1), clean[brace + 1:end - 1], brace + 1))
    return out


# function / modifier / constructor headers inside a contract body
_FN_HDR_RE = re.compile(
    r"\b(function\s+([A-Za-z_]\w*)|constructor|fallback|receive|modifier\s+([A-Za-z_]\w*))\b"
    r"([^;{}]*)",  # signature tail up to the body-open or a ';'
)

_REENTRANCY_GUARD_TOKENS = (
    "nonreentrant", "noreentrancy", "reentrancyguard", "nonreentrantview",
    "readnonreentrant", "globalnonreentrant", "nonreentrantread",
)


def parse_functions(body: str, base_off: int):
    """Return list of function dicts within a contract body.
    Each: name, kind, header, is_view, has_guard, visibility, body_text,
          body_off (offset into the ORIGINAL clean string via base_off)."""
    fns = []
    for m in _FN_HDR_RE.finditer(body):
        # find whether this header terminates in a body '{' before the next ';'
        tail_start = m.end()
        brace = body.find("{", m.start())
        semi = body.find(";", m.start())
        if brace < 0:
            continue
        if 0 <= semi < brace:
            continue  # abstract / interface fn declaration (no body)
        header = body[m.start():brace]
        end = _match_brace(body, brace)
        b_text = body[brace + 1:end - 1]
        hlow = header.lower()
        name = m.group(2) or m.group(3) or (
            "constructor" if "constructor" in hlow else
            "fallback" if "fallback" in hlow else
            "receive" if "receive" in hlow else "?")
        kind = "modifier" if hlow.strip().startswith("modifier") else "function"
        is_view = bool(re.search(r"\b(view|pure)\b", header))
        has_guard = any(tok in re.sub(r"\s+", "", hlow) for tok in _REENTRANCY_GUARD_TOKENS)
        if "external" in hlow:
            vis = "external"
        elif "public" in hlow:
            vis = "public"
        elif "internal" in hlow:
            vis = "internal"
        elif "private" in hlow:
            vis = "private"
        else:
            vis = "public"  # solidity default for fns is public (pre-0.5 view)
        fns.append({
            "name": name, "kind": kind, "header": header,
            "is_view": is_view, "has_guard": has_guard, "visibility": vis,
            "body_text": b_text, "body_off": base_off + brace + 1,
        })
    return fns


def extract_state_vars(body: str, fns) -> set:
    """State-variable names declared at contract scope (function/modifier bodies
    masked out, plus struct/enum bodies, so only member-area decls remain)."""
    masked = list(body)
    # mask function + modifier bodies (relative offsets: body_off - base handled by caller)
    # here fns carry absolute body_off; we mask via search of the body_text.
    for fn in fns:
        bt = fn["body_text"]
        # blank out the first occurrence of this body text within `body`
        idx = body.find(bt)
        if idx >= 0:
            for k in range(idx, idx + len(bt)):
                masked[k] = " "
    m2 = "".join(masked)
    # mask struct / enum bodies too
    for kw in ("struct", "enum"):
        for mm in re.finditer(r"\b" + kw + r"\s+[A-Za-z_]\w*\s*", m2):
            br = m2.find("{", mm.end() - 1)
            if br < 0:
                continue
            en = _match_brace(m2, br)
            m2 = m2[:br] + (" " * (en - br)) + m2[en:]
    # drop non-declaration member lines
    names: set = set()
    decl_re = re.compile(
        r"(?:mapping\s*\([^;{}]*\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\[[^\]]*\])?)"
        r"\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+|"
        r"override(?:\s*\([^)]*\))?\s+|transient\s+)*"
        r"([A-Za-z_]\w*)\s*(?:=|;)")
    _KW = {"using", "event", "error", "import", "pragma", "return", "returns",
           "modifier", "function", "if", "for", "while", "emit", "require",
           "revert", "assembly", "unchecked", "contract", "interface",
           "library", "constructor", "is", "abstract"}
    for line in m2.splitlines():
        s = line.strip()
        if not s or s.startswith(("//", "/*", "*")):
            continue
        first = s.split(None, 1)[0].rstrip("(") if s.split() else ""
        if first in _KW:
            continue
        mm = decl_re.match(s)
        if mm:
            nm = mm.group(1)
            if nm not in _KW:
                names.add(nm)
    return names


# ---------------------------------------------------------------------------
# Write / read / yield detection inside a function body.
# ---------------------------------------------------------------------------
# Curated, general yield points: control leaving the trust boundary. NOT a bug
# shape - these are the enumerated yield-point classes from the R2 spec.
_YIELD_PATTERNS = (
    r"\.call\s*[({]",
    r"\.delegatecall\s*\(",
    r"\.transfer\s*\(",
    r"\.send\s*\(",
    r"\.sendValue\s*\(",
    r"\.functionCall\s*\(",
    r"\.functionCallWithValue\s*\(",
    r"\.safeTransfer\s*\(",
    r"\.safeTransferFrom\s*\(",
    r"\.safeMint\s*\(",
    r"\.transferFrom\s*\(",
    r"\.onERC721Received\b",
    r"\.onERC1155Received\b",
    r"\.onERC1155BatchReceived\b",
    r"\.tokensReceived\b",
    r"\.tokensToSend\b",
    r"\.onFlashLoan\b",
    r"\.onTokenTransfer\b",
    r"\.mint\s*\(",  # ERC-777/1155-style receiver hooks on mint
)
YIELD_RE = re.compile("|".join(_YIELD_PATTERNS))


def find_yields(body: str):
    """CORE PREDICATE: ordered offsets where control yields the trust boundary.
    Exposed as a module function so a non-vacuity test can neutralize it."""
    return [m.start() for m in YIELD_RE.finditer(body)]


def _write_offsets(body: str, var: str):
    """All offsets where `var` is WRITTEN (assignment / compound / element /
    field / delete / push / pop). Excludes ==, !=, <=, >= comparisons."""
    v = re.escape(var)
    offs = []
    # scalar / element / field assignment (not a comparator)
    asg = re.compile(
        r"\b" + v + r"\b\s*(?:\[[^\]]*\]|\.[A-Za-z_]\w*)*\s*"
        r"(?<![=!<>])([-+*/%&|^]?=)(?!=)")
    for m in asg.finditer(body):
        offs.append(m.start())
    for pat in (r"\bdelete\s+" + v + r"\b",
                r"\b" + v + r"\b\s*(?:\[[^\]]*\])?\.push\s*\(",
                r"\b" + v + r"\b\s*(?:\[[^\]]*\])?\.pop\s*\("):
        for m in re.finditer(pat, body):
            offs.append(m.start())
    return sorted(set(offs))


def _reads_var(body: str, var: str) -> bool:
    """True if `var` appears as a value read (any bare occurrence). Cheap: a
    write also reads the identifier, but readers are OTHER functions, so a bare
    occurrence there is a genuine read."""
    return re.search(r"\b" + re.escape(var) + r"\b", body) is not None


# ---------------------------------------------------------------------------
# Core analysis.
# ---------------------------------------------------------------------------
def analyze_contract(cname: str, body: str, base_off: int, rel_file: str):
    fns = parse_functions(body, base_off)
    statevars = extract_state_vars(body, fns)
    if len(statevars) < 2:
        return []
    # per-function write map + yields (skip modifiers as writers)
    writers = []
    readers = []
    for fn in fns:
        if fn["kind"] == "modifier":
            continue
        bt = fn["body_text"]
        wmap = {}
        for v in statevars:
            offs = _write_offsets(bt, v)
            if offs:
                wmap[v] = offs
        yields = find_yields(bt)
        fn["_writes"] = wmap
        fn["_yields"] = yields
        # a reader is re-entered / observed DURING the yield, so it must be
        # directly externally reachable (public/external).
        rvars = {v for v in statevars if _reads_var(bt, v)}
        fn["_reads"] = rvars
        if fn["visibility"] in ("public", "external"):
            readers.append(fn)
        # a writer only needs to sit on SOME external path: an internal helper
        # (e.g. `exit`/`_withdraw` reached from a public wrapper) still opens a
        # suspension window. Constructors cannot be re-entered post-deploy.
        if fn["name"] != "constructor" and wmap and yields:
            writers.append(fn)

    findings = []
    for W in writers:
        wmap = W["_writes"]
        if len(wmap) < 2:
            continue  # need a COUPLED set (>=2 members) - dedup vs single-var reentrancy
        for y in W["_yields"]:
            updated = {v: offs for v, offs in wmap.items() if min(offs) < y}
            pending = {v: offs for v, offs in wmap.items() if min(offs) > y}
            # invariant SUSPENDED iff >=1 member already updated AND a DIFFERENT
            # member is still pending at this yield.
            distinct = set(updated) | set(pending)
            if not updated or not pending or len(distinct) < 2:
                continue
            suspended_set = sorted(distinct)
            observable = set(updated) | set(pending)
            # enumerate readers that can observe the suspended set at the yield
            open_readers = []
            for R in readers:
                if R is W:
                    # the writer re-entering itself is A7's single-fn turf; the
                    # cross-observer plane is other entrypoints.
                    continue
                seen = R["_reads"] & observable
                if not seen:
                    continue
                # shared reentrancy lock spanning the whole write => reader
                # cannot execute inside the window => GREEN.
                if W["has_guard"] and R["has_guard"]:
                    continue
                open_readers.append({
                    "fn": R["name"],
                    "kind": "view" if R["is_view"] else "mutating",
                    "visibility": R["visibility"],
                    "reads": sorted(seen),
                    "reader_guarded": R["has_guard"],
                })
            if not open_readers:
                continue
            promotable = any(
                r["kind"] == "view" or r["visibility"] in ("public", "external")
                for r in open_readers)
            findings.append({
                "flag_kind": "invariant-suspension-window",
                "attack_class": "arch-invariant-suspension-window",
                "file": rel_file,
                "contract": cname,
                "writer_fn": W["name"],
                "writer_guarded": W["has_guard"],
                "suspended_invariant_set": suspended_set,
                "members_updated_at_yield": sorted(updated),
                "members_pending_at_yield": sorted(pending),
                "yield_offset": y,
                "readers": open_readers,
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "promotable": promotable,
                "dedup_note": ("R2 coupled-invariant suspended at a yield + a "
                               "reachable observer; NOT single-var reentrancy "
                               "(A7) and NOT a nonReentrant-presence check"),
                "private_invariant": ("no reachable observer sees the coupled "
                                      "set while a writer has started but not "
                                      "settled it"),
            })
    return findings


def analyze(ws: pathlib.Path):
    acc = {
        "tool": "arch-invariant-suspension-window",
        "workspace": str(ws),
        "status": "ok",
        "files_scanned": 0,
        "contracts_scanned": 0,
        "yield_points_seen": 0,
        "suspension_windows": 0,
        "hypotheses": 0,
        "open_rows": 0,
        "blocking": False,
    }
    findings = []
    files = _inscope_files(ws)
    for fp in files:
        try:
            raw = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        acc["files_scanned"] += 1
        clean = strip_comments_strings(raw)
        try:
            rel = str(fp.relative_to(ws))
        except Exception:
            rel = str(fp)
        for (cname, cbody, coff) in find_contracts(clean):
            acc["contracts_scanned"] += 1
            acc["yield_points_seen"] += len(find_yields(cbody))
            try:
                fnd = analyze_contract(cname, cbody, coff, rel)
            except Exception as exc:  # fail-open per contract
                acc.setdefault("errors", []).append(f"{rel}::{cname}: {str(exc)[:100]}")
                continue
            findings.extend(fnd)
    acc["suspension_windows"] = len({
        (f["file"], f["contract"], f["writer_fn"], f["yield_offset"]) for f in findings})
    acc["hypotheses"] = len(findings)
    acc["open_rows"] = len(findings)  # every emitted row = an un-analyzed reader

    strict = os.environ.get("AUDITOOOR_L37_STRICT") in ("1", "true", "True")
    enforce = os.environ.get("AUDITOOOR_YIELD_WINDOW_ENFORCE") in ("1", "true", "True")
    if strict and enforce and acc["open_rows"] > 0:
        acc["blocking"] = True
        acc["verdict"] = "fail-invariant-suspension-open"
    else:
        acc["verdict"] = "pass-invariant-suspension-window"
    return findings, acc


def _emit(ws: pathlib.Path, findings, acc, out=None):
    out_path = pathlib.Path(out) if out else (ws / OUT_REL)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for h in findings:
            f.write(json.dumps(h) + "\n")
    acc_path = ws / ACC_REL
    acc_path.parent.mkdir(parents=True, exist_ok=True)
    with open(acc_path, "w") as f:
        json.dump(acc, f, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 1
    findings, acc = analyze(ws)
    _emit(ws, findings, acc, args.out)
    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": findings}))
    else:
        print(f"[ok] R2 invariant-suspension-window: status={acc['status']} "
              f"verdict={acc['verdict']}")
        print(f"     files/contracts:      {acc['files_scanned']}/{acc['contracts_scanned']}")
        print(f"     yield points seen:    {acc['yield_points_seen']}")
        print(f"     suspension windows:   {acc['suspension_windows']}")
        print(f"     hypotheses (needs-fuzz): {acc['hypotheses']}")
        if acc["blocking"]:
            print("     BLOCKING (enforce+strict): open suspension-window rows")
    return 1 if acc.get("blocking") else 0


if __name__ == "__main__":
    sys.exit(main())
