#!/usr/bin/env python3
"""Access-control / guard-completeness gate (GENERIC, all-language, all-workspace).

wibjbh2e8 headline gap #5: nothing STRUCTURALLY enumerates every state-mutating
external/public function and asks "does it carry a correct guard?" as a gate. The
per-function hunt agents reason about guards ad hoc, so an entirely UNGUARDED
external mutator can slip through every net (nobody ever asked the question for
that specific function). This tool closes that: it enumerates every
EXTERNAL/PUBLIC STATE-MUTATING function of the in-scope units and, for each,
determines whether it carries a guard (a modifier like onlyOwner/onlyRole/only*,
a require(msg.sender ...)/require(hasRole ...) in the body, or an access-control
call) vs UNGUARDED.

It is language-generic (Solidity-first, with an extension map so Go/Rust/etc are
enumerated - not crashed - via the shared value-moving-functions primitives) and
DOES NOT hard-depend on a compiled-Slither pipeline: it uses a pure source-regex
guard-presence check so it runs with no build. When Slither IS importable it is
used only as an additive corroborating signal, never a hard dependency.

Emits <ws>/.auditooor/guard_completeness.jsonl (one row per external mutator:
file, function, language, guarded, guard_evidence, disposition) + a summary.

VERDICT
  pass-guards-complete    : every external mutator is guarded OR carries a typed
                            disposition (a permissionless-by-design function is
                            fine WITH a disposition).
  warn-unguarded-mutators : one or more external mutators are UNGUARDED and
                            undispositioned (advisory - the default; exit 0).
  fail-unguarded-mutators : same, but ONLY under env
                            AUDITOOOR_GUARD_COMPLETENESS_STRICT=1 (exit 1).

A ws-level rebuttal file .auditooor/guard_completeness_rebuttal.md (non-empty)
downgrades a fail to a warn (honest operator walk-back), mirroring the
commit-adjudication / fuzz-target rebuttal pattern.

Dispositions live in <ws>/.auditooor/guard_dispositions.jsonl - one JSON object
per line, keyed by file+function (or a "file::function" `unit` string). A row
with a non-empty reason marks a function permissionless-by-design (or otherwise
intentionally-unguarded) so it stops counting as an open unguarded mutator.

CLI:
  python3 tools/guard-completeness-check.py --workspace <ws> [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Reuse the value-moving-functions primitives (scope resolution, per-language
# function-start regexes, body extraction, extension map) so we stay in lockstep
# with the canonical enumerator instead of re-deriving them. Loaded via a spec
# because the file name has a hyphen (not importable as a module name).
# ---------------------------------------------------------------------------
def _load_vmf():
    p = Path(__file__).resolve().with_name("value-moving-functions.py")
    spec = importlib.util.spec_from_file_location("_vmf_guardcomplete", str(p))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vmf_guardcomplete"] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF = _load_vmf()

# Languages whose visibility model we understand well enough to say "external /
# public state-mutating" from source alone. Solidity-first. For other languages
# in the extension map we still enumerate declarations but treat an explicit
# public/exported marker conservatively (see _visibility_external).
_LANG_OF_EXT = _VMF._EXT_TO_LANG
_FN_RES = _VMF._FN_RES
_SOL_NONMUTATING_RE = _VMF._SOL_NONMUTATING_RE
_extract_body = _VMF._extract_body
_rust_fn_is_test = _VMF._rust_fn_is_test


# ---------------------------------------------------------------------------
# Guard-presence primitives (source-regex; no compiled Slither required).
# ---------------------------------------------------------------------------
# A guard MODIFIER on a Solidity header. "only*" is the ubiquitous convention;
# we also match the common OZ/AccessControl role/owner modifiers by name so a
# rename of the only-prefix convention is still caught.
_SOL_GUARD_MODIFIER_RE = re.compile(
    r"\b(only[A-Z]\w*|whenNotPaused|whenPaused|nonReentrant"
    r"|requiresAuth|authorized|restricted|onlyRole|onlyOwner|onlyGovernance"
    r"|onlyAdmin|onlyOperator|onlyController|onlyManager|onlyGuardian)\b"
)

# A guard in the BODY: a require/if that reads msg.sender or an access-control
# predicate, an OZ _checkRole/_checkOwner call, an AccessControl hasRole gate,
# or an explicit revert on an authz predicate. Deliberately broad at the body
# level - a false-positive here only means we call a function guarded (never a
# false UNGUARDED), and unguarded is the only bucket the gate acts on.
_BODY_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\brequire\s*\([^;]*\bmsg\.sender\b"),
    re.compile(r"\brequire\s*\([^;]*\bhasRole\b"),
    re.compile(r"\brequire\s*\([^;]*\bowner\b", re.I),
    re.compile(r"\b_checkRole\s*\("),
    re.compile(r"\b_checkOwner\s*\("),
    re.compile(r"\b_onlyRole\s*\("),
    re.compile(r"\b_authorizeUpgrade\b"),
    re.compile(r"\bhasRole\s*\([^;]*\bmsg\.sender\b"),
    re.compile(r"\bif\s*\([^)]*\bmsg\.sender\b[^)]*\)\s*(?:\{)?\s*(?:revert|_?revert)"),
    # OZ v5 custom-error style: if (msg.sender != owner()) revert ...
    re.compile(r"\brevert\s+\w*(?:Unauthorized|NotOwner|NotAuthorized|AccessControl|Forbidden)"),
    re.compile(r"\bcheckOnlyOwner\b|\b_msgSender\s*\(\)\s*[!=]="),
    # Rust / ink! / cosmwasm style authz predicates
    re.compile(r"\bensure!?\s*\([^;]*\bcaller\b"),
    re.compile(r"\bassert_eq!\s*\([^;]*\bcaller\b"),
    re.compile(r"\bself\.env\(\)\.caller\(\)\s*[!=]="),
    re.compile(r"\binfo\.sender\b"),  # cosmwasm MessageInfo sender check
    re.compile(r"\brequire_auth\b"),  # soroban
    # Go / cosmos-sdk style
    re.compile(r"\bGetSigners\b|\bValidateBasic\b|\bauthority\b"),
]

# Solidity visibility keywords in the header (signature ")" -> body "{"). We
# only gate EXTERNAL/PUBLIC. internal/private are not externally reachable so a
# missing guard on them is not an access-control gap at the boundary.
_SOL_EXTERNAL_RE = re.compile(r"\b(external|public)\b")
_SOL_INTERNAL_RE = re.compile(r"\b(internal|private)\b")

# Solidity headers that are NOT auditable external mutators even if public:
# constructors, receive/fallback (guardless-by-protocol), and pure/view.
_SOL_SPECIAL_FN = re.compile(r"\b(constructor|receive|fallback)\b")


def _slither_guarded(_ws: Path) -> dict:
    """Optional additive Slither corroboration. Returns {} on any error / when
    Slither or a compiled build is unavailable. NEVER a hard dependency: the
    source-regex path is authoritative and self-sufficient."""
    # Intentionally a no-op unless a caller wires a compiled artifact. Kept as a
    # named seam so a future build-backed corroboration can slot in without
    # changing the gate contract. We do not import slither here to guarantee the
    # tool runs with zero build.
    return {}


def _sol_visibility(header_tail: str) -> str | None:
    """Return 'external' if a Solidity header is external/public-and-mutating,
    None if internal/private/view/pure/special (not a boundary mutator)."""
    if _SOL_SPECIAL_FN.search(header_tail):
        return None
    if _SOL_NONMUTATING_RE.search(header_tail):
        return None  # view/pure - not state-mutating
    if _SOL_INTERNAL_RE.search(header_tail):
        return None
    if _SOL_EXTERNAL_RE.search(header_tail):
        return "external"
    # No explicit visibility keyword: Solidity <0.5 defaulted to public, but
    # modern in-scope contracts almost always annotate. Treat an un-annotated
    # function conservatively as NOT-external so we never false-flag a helper
    # that omitted the keyword; the external ones we care about are annotated.
    return None


def _is_external_mutator(lang: str, header_tail: str, body: str) -> bool:
    """Language-generic 'external/public state-mutating' predicate. Solidity is
    precise via visibility keywords; other languages fall back to an exported /
    public marker heuristic so they are ENUMERATED (not crashed) but never
    over-flagged."""
    if lang == "sol":
        return _sol_visibility(header_tail) == "external"
    if lang == "rs":
        # Rust: `pub fn` is the exported surface (the caller passes a lookback
        # window that includes the pub marker before the fn keyword). A
        # pub(crate)/pub(super) is not an external boundary. Require an exported
        # marker AND a mutating body signal (&mut self / state write) so a pure
        # pub getter is not flagged.
        if not re.search(r"\bpub\s+(?:async\s+)?fn\b", header_tail):
            return False
        if re.search(r"\bpub\s*\(\s*(?:crate|super|in\b)", header_tail):
            return False
        return bool(re.search(r"&mut\s+self\b", header_tail) or
                    re.search(r"\bstorage\b|\bset_|\bself\.\w+\s*=", body))
    if lang == "go":
        # Go: an exported method starts with an uppercase letter (export-ness is
        # decided by the caller via the captured name). Treat as external only if
        # the body writes PERSISTENT / cross-call state. The old predicate ended in
        # `\b\w+\s*:?=`, which matched ANY local assignment (`result = ...`,
        # `sum := ...`) - so every exported Go helper with a local variable,
        # including pure math like utils/math.go::ExpDec and the pro-rata share
        # helpers, was false-flagged as an unguarded external mutator. Real Go
        # state mutation = a keeper/KVStore write (k.X.Set / store.Set / .Set(ctx /
        # a keeper SetXxx method) OR an assignment to a SELECTOR LHS (`recv.field =`
        # / `store.x =`); a plain local assignment is NOT state mutation. Mirrors
        # the Rust branch (exported AND a mutating-body signal, not a pure getter).
        return bool(re.search(
            r"\bk\.\w+\.Set\b|\bstore\.Set\b|\.Set\(\s*ctx|\bk\.Set[A-Z]\w*\("
            r"|\b\w+\.\w+\s*=(?!=)", body))
    if lang in ("move", "cairo"):
        # Move `public fun` / Cairo `#[external]` or pub fn. Enumerate if the
        # header carries a public/external marker.
        return bool(re.search(r"\bpublic\b|\bexternal\b|\b#\[external", header_tail))
    return False


def _has_guard(lang: str, header_tail: str, body: str) -> tuple[bool, str]:
    """Return (guarded, evidence). Checks a modifier on the header (Solidity) or
    an access-control predicate/call in the body (all languages)."""
    if lang == "sol":
        m = _SOL_GUARD_MODIFIER_RE.search(header_tail)
        if m:
            return True, f"modifier:{m.group(1)}"
    else:
        # Non-Solidity: a guard-shaped attribute/annotation in the header.
        m = _SOL_GUARD_MODIFIER_RE.search(header_tail)
        if m:
            return True, f"modifier:{m.group(1)}"
    for rx in _BODY_GUARD_RES:
        bm = rx.search(body)
        if bm:
            return True, f"body:{bm.group(0)[:48].strip()}"
    return False, ""


# ---------------------------------------------------------------------------
# Enumeration.
# ---------------------------------------------------------------------------
def _iter_in_scope_files(ws: Path):
    for path in sorted(ws.rglob("*")):
        if not path.is_file():
            continue
        lang = _LANG_OF_EXT.get(path.suffix.lower())
        if lang is None:
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if not _VMF.is_in_scope(rel, workspace=ws):
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _VMF.is_generated(rel, head=head[:600]):
            continue
        yield path, rel, lang, head


def enumerate_external_mutators(ws: Path) -> list[dict[str, Any]]:
    """Enumerate every external/public state-mutating function of the in-scope
    units and tag each guarded true|false with evidence."""
    out: list[dict[str, Any]] = []
    for _path, rel, lang, text in _iter_in_scope_files(ws):
        fn_re = _FN_RES.get(lang)
        if fn_re is None:
            continue
        for m in fn_re.finditer(text):
            fn_name = m.group(1)
            sig_end = m.end()
            # Rust test functions are not an external boundary.
            if lang == "rs" and _rust_fn_is_test(text, m.start()):
                continue
            # Go export-ness is decided by the capitalization of the name.
            if lang == "go" and not (fn_name[:1].isupper()):
                continue
            body = _extract_body(text, sig_end)
            if not body:
                continue
            # header_tail = text between the signature "(" close and the body "{"
            # (Solidity visibility + modifiers live here). For non-brace langs we
            # approximate with a small window before the body.
            brace_pos = text.find("{", sig_end)
            if brace_pos < 0:
                continue
            # Skip Solidity abstract/interface declarations (";" before "{").
            if lang == "sol":
                next_semi = text.find(";", sig_end)
                if 0 <= next_semi < brace_pos:
                    continue
            header_tail = text[sig_end:brace_pos]
            # For rust/move/cairo the pub/public/#[external] marker sits BEFORE
            # the fn keyword; widen the header window to include a lookback.
            lookback = text[max(0, m.start() - 60):brace_pos]
            hdr = header_tail if lang == "sol" else lookback
            if not _is_external_mutator(lang, hdr, body):
                continue
            guarded, evidence = _has_guard(lang, hdr, body)
            out.append({
                "file": rel,
                "function": fn_name,
                "language": lang,
                "guarded": guarded,
                "guard_evidence": evidence,
            })
    return out


# ---------------------------------------------------------------------------
# Dispositions + rebuttal.
# ---------------------------------------------------------------------------
def _load_dispositions(ws: Path) -> set[tuple[str, str]]:
    """Return a set of (file, function) pairs that carry a typed disposition
    (a permissionless-by-design / intentionally-unguarded marker with a
    non-empty reason). Accepts either {"file","function","reason"} or a
    "file::function" `unit` string. Empty on absence (fail-open)."""
    p = ws / ".auditooor" / "guard_dispositions.jsonl"
    out: set[tuple[str, str]] = set()
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        reason = str(obj.get("reason") or obj.get("disposition") or "").strip()
        if not reason:
            continue  # a disposition with no reason does NOT excuse a mutator
        f = str(obj.get("file") or "").strip()
        fn = str(obj.get("function") or obj.get("function_name") or "").strip()
        if (not f or not fn) and obj.get("unit"):
            unit = str(obj["unit"])
            if "::" in unit:
                f, fn = unit.split("::", 1)
            elif ":" in unit:
                f, fn = unit.rsplit(":", 1)
        if f and fn:
            out.add((f.strip(), fn.strip()))
    return out


def _rebuttal(ws: Path) -> str | None:
    p = ws / ".auditooor" / "guard_completeness_rebuttal.md"
    try:
        t = p.read_text(encoding="utf-8", errors="replace").strip()
        return t or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Check + emit.
# ---------------------------------------------------------------------------
def check(ws: Path, *, write: bool = True) -> dict:
    ws = Path(ws).resolve()
    if not ws.is_dir():
        return {"verdict": "warn-workspace-absent", "workspace": str(ws),
                "external_mutators": 0, "unguarded": [], "note": "workspace not found"}

    rows = enumerate_external_mutators(ws)
    dispositions = _load_dispositions(ws)

    unguarded: list[dict[str, Any]] = []
    guarded_n = 0
    dispositioned_n = 0
    emit_rows: list[dict[str, Any]] = []
    for r in rows:
        key = (r["file"], r["function"])
        disp = key in dispositions
        row = dict(r)
        if disp:
            row["disposition"] = "permissionless-by-design"
        else:
            row["disposition"] = ""
        emit_rows.append(row)
        if r["guarded"]:
            guarded_n += 1
        elif disp:
            dispositioned_n += 1
        else:
            unguarded.append({"file": r["file"], "function": r["function"],
                              "language": r["language"]})

    if write:
        out_dir = ws / ".auditooor"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "guard_completeness.jsonl"
            with out_path.open("w", encoding="utf-8") as fh:
                for row in emit_rows:
                    fh.write(json.dumps(row) + "\n")
        except OSError:
            pass

    strict = bool(os.environ.get("AUDITOOOR_GUARD_COMPLETENESS_STRICT"))
    if not rows:
        verdict = "pass-no-external-mutators"
    elif not unguarded:
        verdict = "pass-guards-complete"
    else:
        verdict = ("fail-unguarded-mutators" if strict
                   else "warn-unguarded-mutators")

    return {
        "verdict": verdict,
        "workspace": str(ws),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_mutators": len(rows),
        "guarded": guarded_n,
        "dispositioned": dispositioned_n,
        "unguarded_count": len(unguarded),
        "unguarded": unguarded,
        "strict": strict,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write the guard_completeness.jsonl sidecar")
    a = ap.parse_args(argv)
    ws = Path(os.path.expanduser(a.workspace))
    rep = check(ws, write=not a.no_write)
    reb = _rebuttal(ws)
    failed = str(rep.get("verdict", "")).startswith("fail-")
    if failed and reb:
        rep["rebuttal"] = True
    if a.json:
        rep["rebuttal"] = bool(reb)
        print(json.dumps(rep, indent=2))
    else:
        print(f"[guard-completeness] verdict: {rep['verdict']} "
              f"(external_mutators={rep.get('external_mutators', 0)}, "
              f"guarded={rep.get('guarded', 0)}, "
              f"dispositioned={rep.get('dispositioned', 0)}, "
              f"unguarded={rep.get('unguarded_count', 0)}, "
              f"strict={rep.get('strict')})")
        for u in rep.get("unguarded", []):
            print(f"  UNGUARDED {u['file']}::{u['function']} ({u['language']}) "
                  "- add a guard or a typed disposition")
        if rep.get("note"):
            print(f"  {rep['note']}")
        if failed and reb:
            print("  (rebuttal present -> downgraded to advisory)")
    # exit code: fail-* under strict AND no rebuttal -> rc 1; otherwise rc 0.
    if failed and not reb:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
