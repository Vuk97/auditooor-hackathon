#!/usr/bin/env python3
"""js-oscript-value-moving-surface.py - a GENERAL JS/Oscript value-moving-surface
enforcement screen (C1).

WHAT THIS IS (and is NOT)
=========================
This is a GENERAL trust-enforcement invariant screen for JavaScript / Obyte
Oscript workspaces - the JS/Oscript analog of value-moving-functions.py
(Solidity per-function value-movers) and go_entrypoint_surface.py (Go external
entry surface). It is NOT a specific bug-shape or impact-specific detector: it
carries no per-target literal and no "known-exploit" template. It enumerates a
GENERIC value-moving surface and applies ONE reusable private invariant to it.

THE NORTH-STAR METHOD (applied inside this capability)
------------------------------------------------------
"A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."

  1. Delegated-trusted invariant
       A value-moving JS/Oscript unit (one that emits an outbound payment /
       issues an asset / credits a ledger balance) is TRUSTED by the rest of
       the system to authorize/validate the move before performing it. No
       upstream caller re-checks: the mover owns the check.
  2. Private invariant (stated, per unit)
       "Every value-move site in the unit body is DOMINATED by at least one
        validation / authorization enforcement earlier in the same body."
  3. Attack the invariant
       Find a value-moving unit whose FIRST value-move site is preceded by NO
       guard token - the enforcement is absent (or, on a mutated build, was
       weakened), so an attacker-shaped input reaches the move unchecked.
       This is the JS/Oscript instance of the must-move-together /
       trusted-enforcer failure the method enumerates.

TWO OUTPUTS (both advisory-first)
=================================
  A. SURFACE CENSUS (denominator integrity): the set of value-moving units, and
     the set of files EXEMPTED as genuinely non-value-moving infrastructure
     (config / CLI / pure-util / pure-infra). The exemption reuses the SINGLE
     SOURCE OF TRUTH classifier ``js_oscript_unit_value_moving_verdict`` in
     value-moving-functions.py (imported, never re-implemented) so this tool
     narrows the hunt/coverage denominator EXACTLY the way that module does -
     fail-OPEN: a unit is dropped only when POSITIVELY matched as non-value-
     moving AND its source shows no value signal.
  B. ENFORCEMENT SCREEN (the north-star application): per value-moving unit,
     whether its first value-move is guard-dominated. An un-dominated move is
     reported as an ADVISORY lead with ``verdict="needs-fuzz"``.

ADVISORY-FIRST, ALWAYS
======================
  * Every finding is ``verdict="needs-fuzz"`` - a lead to fuzz/verify, never an
    auto-credited confirmed bug.
  * The process ALWAYS exits rc=0. This screen NEVER fails a gate closed; it is
    a report generator. (An operator wires it as an advisory signal later.)
  * SILENT-by-default on uncertainty: if a unit body cannot be extracted, or a
    guard token is present anywhere before the move, NOTHING is reported. Over-
    firing is worse than under-firing for an advisory lead-gen, so the screen
    biases hard toward silence (no guess-firing).

CLI
===
  python3 tools/js-oscript-value-moving-surface.py <workspace> [--out <path>]
                                                    [--print-exempt]

Output JSON: <ws>/.auditooor/js_oscript_value_moving_surface.json
Returns rc=0 always (advisory).
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
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Reuse #1: OOS filter (single source of truth). Skip test / vendored / gen.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos, is_in_scope  # type: ignore
except Exception:  # pragma: no cover - bare-script fallback
    _LIB = Path(__file__).resolve().parent / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos, is_in_scope  # type: ignore
    except Exception:  # pragma: no cover
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            return any(
                m in n for m in (
                    "/test/", "/tests/", "_test.", ".spec.", "/node_modules/",
                    "/vendor/", "/dist/", "/build/", "/out/",
                )
            )

        def is_in_scope(rel: str, *, workspace=None) -> bool:  # type: ignore[misc]
            return not is_oos(rel)


# ---------------------------------------------------------------------------
# Reuse #2: the value-moving-functions.py FILE-LEVEL exemption classifier.
# It is the single source of truth for "is this JS/Oscript FILE genuinely
# non-value-moving infra (config/CLI/pure-util/pure-infra)". We IMPORT it (the
# filename has hyphens, so via importlib) and NEVER re-implement its curated
# category lists / value-signal veto. Falls back to a permissive value-moving
# verdict if the sister tool is unavailable (fail-open: never drop a unit).
# ---------------------------------------------------------------------------
def _load_vmf_verdict() -> Callable[[str, Optional[str]], "tuple[str, str]"]:
    tool = Path(__file__).resolve().parent / "value-moving-functions.py"
    try:
        spec = importlib.util.spec_from_file_location("value_moving_functions", tool)
        if spec is None or spec.loader is None:
            raise ImportError("no spec")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        fn = getattr(mod, "js_oscript_unit_value_moving_verdict", None)
        if callable(fn):
            return fn  # type: ignore[return-value]
    except Exception:
        pass

    def _fallback(unit_rel: str, text: Optional[str] = None) -> "tuple[str, str]":
        base = str(unit_rel or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        _, ext = os.path.splitext(base)
        if ext in (".oscript", ".aa"):
            return ("value-moving", "oscript-fail-open")
        if ext != ".js":
            return ("not-applicable", "non-js-oscript")
        return ("value-moving", "js-default-fail-open-nofallbackclassifier")

    return _fallback


_vmf_file_verdict = _load_vmf_verdict()


# ===========================================================================
# GENERIC value-move SINK vocabulary (part 1 of the private invariant).
# A "value-move site" is an outbound custody move (payment / asset issue /
# module bank send) or a ledger-balance credit write. Deliberately restricted
# to HIGH-SIGNAL money verbs so the advisory screen does not over-fire on the
# many non-value ``.send(`` (ws/http/event) call-sites JS code is full of.
# ===========================================================================
_JS_SINK_RE = re.compile(
    # Obyte / generic outbound-payment composition + send verbs
    r"\bcompose(?:AndSave)?(?:Minimal)?(?:Divisible|Indivisible)?(?:Asset)?PaymentJoint\s*\("
    r"|\bcomposeJoint\s*\("
    r"|\bpayToAddress\s*\("
    r"|\bsend(?:Multi)?Payment(?:FromWallet)?\s*\("
    r"|\bsendAllBytes\s*\("
    r"|\bsendAssetPayment\s*\("
    r"|\bissue(?:Divisible|Indivisible)?Asset\s*\("
    # Cosmos/bank-shaped custody moves reachable from JS bridge glue
    r"|\bsendCoins?\s*\("
    r"|\bbank(?:Keeper)?\.Send\w*\s*\("
    # Ledger-balance credit MUTATION: balances[key] += / -= (a compound
    # assignment is an actual balance move; a plain ``balances[k] = row.balance``
    # is almost always an in-memory map BUILT from a DB read - NOT a value-move -
    # so it is deliberately excluded to keep this advisory screen high-signal),
    # plus explicit add/credit/increment*Balance( mutator calls.
    r"|\b\w*[Bb]alances?\s*\[[^\]]*\]\s*(?<![=!<>])[-+]=(?!=)"
    r"|\b(?:add|credit|increase|increment)[A-Za-z_]*[Bb]alance\w*\s*\(",
    re.IGNORECASE,
)

# Oscript (declarative AA) value-move sites: a payment/asset message body.
_OSCRIPT_SINK_RE = re.compile(
    r"app\s*:\s*['\"]payment['\"]"
    r"|app\s*:\s*['\"]asset['\"]"
    r"|\boutputs\s*:",
    re.IGNORECASE,
)

# ===========================================================================
# GENERIC guard / trusted-enforcement vocabulary (part 2 of the invariant).
# A guard is a validation OR an authorization enforcement construct. Presence
# of ANY guard token before the first value-move site satisfies the private
# invariant (the move is "dominated" by an enforcement). This is intentionally
# broad on the SILENCE side: any plausible check keeps the screen quiet.
# ===========================================================================
_JS_GUARD_RE = re.compile(
    # Validation library / predicate calls
    r"\bValidationUtils\b"
    r"|\bis[A-Z]\w*\s*\("            # isValidAddress / isNonemptyArray / ...
    r"|\bvalidate\w*\s*\("
    r"|\bassert\w*\s*\("
    # Reject-paths that only exist to enforce a precondition
    r"|\bthrow\s+(?:new\s+)?[A-Za-z_]\w*(?:Error)?\b"
    r"|\breturn\s+(?:cb|callback|handle[A-Za-z_]*|onError|onDone)\s*\("
    # Error-callback return-guards: ``return <expr>.ifError(`` /
    # ``return <expr>.ifNotEnoughFunds(`` - the Obyte idiom for bailing out of a
    # value-mover on a failed precondition (callbacks.ifError / .ifNotEnoughFunds).
    r"|\breturn\s+[^;\n]*\.(?:ifError|ifNotEnoughFunds)\s*\("
    r"|\bbounce\s*\("
    # Bare conditional / ternary gating: an ``if (`` or a ternary ``? :`` before
    # the move is a precondition branch (Obyte movers gate almost entirely on
    # bare ``if`` + early ``return ...ifError()`` rather than assert/require).
    r"|\bif\s*\("
    r"|(?<!\?)\?(?![.?=])"
    # Authorization enforcement
    r"|\bmsg\.sender\b"
    r"|\brequire\s*\(\s*[^'\"]"       # require(cond ...  (NOT require('module'))
    r"|\bonly[A-Z]\w*\b|\bhasPermission\b|\bhasRole\b"
    r"|\bcheckSig\w*|\bverif\w*(?:Sig|Signature|Auth)\w*"
    r"|\bauthoriz\w*|\bisAuthor\w*|\bisOwner\b|\bisAdmin\b",
    re.IGNORECASE,
)

# Oscript guards: bounce/require-shaped rejection + conditional gating.
_OSCRIPT_GUARD_RE = re.compile(
    r"\bbounce\s*\("
    r"|require\s*:"
    r"|\bif\s*:"
    r"|\bif\s*\("
    r"|\bnonempty\s*\("
    r"|is_valid\w*\s*\(",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Language dispatch for sink/guard vocabularies.
# ---------------------------------------------------------------------------
def _vocab(lang: str) -> "tuple[re.Pattern, re.Pattern]":
    if lang == "oscript":
        return (_OSCRIPT_SINK_RE, _OSCRIPT_GUARD_RE)
    return (_JS_SINK_RE, _JS_GUARD_RE)


# ---------------------------------------------------------------------------
# CORE PREDICATE - the whole capability reduces to this one function.
# Returns the sink evidence snippet iff the body contains a value-move site
# that is NOT dominated by any guard token before it; else None.
#
# It is factored out (and _first_guard_offset with it) precisely so a test can
# NEUTRALIZE the predicate (force guard-dominance to always hold) and prove the
# planted positive stops firing - the non-vacuity lever.
# ---------------------------------------------------------------------------
def _first_sink(body: str, sink_re: re.Pattern) -> Optional["tuple[int, str]"]:
    m = sink_re.search(body)
    if m is None:
        return None
    snippet = body[max(0, m.start() - 4): m.end() + 24]
    return (m.start(), snippet.strip().replace("\n", " ")[:80])


def _first_guard_offset(body: str, guard_re: re.Pattern, before: int) -> Optional[int]:
    """Offset of the earliest guard token strictly before ``before``, or None."""
    for gm in guard_re.finditer(body):
        if gm.start() >= before:
            break
        return gm.start()
    return None


def unguarded_value_move(body: str, lang: str) -> Optional[str]:
    """CORE PREDICATE. If ``body`` performs a value-move that no guard dominates,
    return the sink evidence snippet; otherwise return None (guarded, or no
    value-move at all)."""
    sink_re, guard_re = _vocab(lang)
    sink = _first_sink(body, sink_re)
    if sink is None:
        return None  # not value-moving
    sink_off, evidence = sink
    if _first_guard_offset(body, guard_re, sink_off) is not None:
        return None  # dominated by a guard -> invariant holds -> silent
    return evidence


# ---------------------------------------------------------------------------
# Delegation / recursion resolution (FILE-LEVEL false-positive suppression).
#
# A value-mover whose sole sink is a CALL to another value-mover defined in the
# SAME file is a wrapper, not the trust boundary: the enforcement obligation
# belongs to the callee (or, for a same-named recursive self-call, to the
# guarded base of the same function). Firing on the wrapper double-reports the
# callee's move at a site that owns no enforcement. This is a SUPPRESSION-ONLY
# layer applied on top of the core predicate (which is unchanged) - it can only
# make the screen quieter, never louder, and never touches a unit whose sink is
# a leaf value primitive (a real payment call to a non-in-file function, or a
# ``balances[k] += `` credit) - those keep firing when unguarded.
# ---------------------------------------------------------------------------
_CALLEE_TAIL_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\(\s*$")


def _sink_callee(body: str, sink_re: re.Pattern) -> Optional[str]:
    """Identifier invoked at the first value-move sink when the sink is a call
    (e.g. ``composeJoint`` for ``composer.composeJoint(``, ``sendMultiPayment``
    for ``sendMultiPayment(``). Returns None for non-call sinks such as a
    ``balances[k] += `` compound-credit write."""
    m = sink_re.search(body)
    if m is None:
        return None
    cm = _CALLEE_TAIL_RE.search(body[: m.end()])
    return cm.group(1) if cm else None


def _resolve_delegating_safe(vm_units: "list[dict[str, Any]]") -> set:
    """Given the value-moving units of ONE file (each dict carries
    ``name``/``evidence``/``callee``), return the set of unit names whose finding
    should be SUPPRESSED because the unit merely delegates (transitively) into a
    guarded in-file value-mover, or recurses into itself.

    Base safe set = guarded units (``evidence is None``). Then, by fixpoint, any
    still-firing unit whose sink-callee is (a) itself (recursion) or (b) an
    already-safe in-file unit is folded in as a delegating wrapper."""
    names = {u["name"] for u in vm_units}
    safe = {u["name"] for u in vm_units if u["evidence"] is None}
    changed = True
    while changed:
        changed = False
        for u in vm_units:
            name = u["name"]
            if name in safe or u["evidence"] is None:
                continue
            callee = u["callee"]
            if callee is None:
                continue  # leaf value primitive -> never a delegation
            if callee == name or (callee in names and callee in safe):
                safe.add(name)
                changed = True
    return safe


# ---------------------------------------------------------------------------
# JS unit splitter: named function declarations + assigned/method function
# expressions + arrow-with-block. Best-effort brace-matched body extraction.
# ---------------------------------------------------------------------------
_JS_FN_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("           # function NAME(
    r"|([A-Za-z_$][\w$]*)\s*[:=]\s*function\s*\("     # NAME = function( / NAME: function(
    r"|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?\([^()]*\)\s*=>\s*\{",  # NAME = (..)=>{
)


def _extract_brace_body(text: str, from_idx: int) -> "tuple[str, int]":
    """Extract the ``{...}`` block at/after ``from_idx``. Returns (body, end_idx).
    Naive brace matcher (does not strip string/comment braces) - adequate for a
    conservative advisory screen; the guard vocabulary is robust to noise."""
    i = text.find("{", from_idx)
    if i < 0:
        return ("", from_idx)
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return (text[i + 1: j], j)
    return (text[i + 1:], len(text))


def js_units(text: str) -> "list[tuple[str, str]]":
    """Return [(function_name, body), ...] for a JS module. Anonymous / arrow
    callbacks without a bindable name are captured only when assigned to an
    identifier (NAME = function / NAME: function / NAME = (..)=>{)."""
    units: "list[tuple[str, str]]" = []
    for m in _JS_FN_RE.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3) or "<anon>"
        body, _ = _extract_brace_body(text, m.end() - 1)
        if body:
            units.append((name, body))
    return units


# ---------------------------------------------------------------------------
# Per-file screen.
# ---------------------------------------------------------------------------
def screen_file(rel: str, text: str) -> "tuple[list[dict[str, Any]], list[dict[str, Any]], Optional[dict[str, Any]]]":
    """Screen one JS/Oscript file.

    Returns (surface_units, findings, exempt_record):
      * surface_units : one record per value-moving unit (census).
      * findings      : advisory needs-fuzz leads (un-dominated value-move).
      * exempt_record : {"file","category"} if the whole FILE is exempted as
                        non-value-moving infra, else None.
    """
    base = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    _, ext = os.path.splitext(base)
    ext = ext.lower()
    if ext in (".oscript", ".aa"):
        lang = "oscript"
    elif ext == ".js":
        lang = "js"
    else:
        return ([], [], None)

    # FILE-LEVEL exemption (denominator narrowing) via the SSOT classifier.
    verdict, reason = _vmf_file_verdict(rel, text)
    if verdict == "non-value-moving":
        return ([], [], {"file": rel, "category": reason})

    surface: "list[dict[str, Any]]" = []
    findings: "list[dict[str, Any]]" = []

    if lang == "oscript":
        # One declarative unit per AA file.
        units = [("<aa>", text)]
    else:
        units = js_units(text)

    sink_re, _ = _vocab(lang)
    # Pass 1: enumerate the value-moving units + core-predicate verdict + the
    # sink callee (for delegation resolution).
    vm_units: "list[dict[str, Any]]" = []
    for name, body in units:
        if _first_sink(body, sink_re) is None:
            continue  # not value-moving
        surface.append({"file": rel, "unit": name, "language": lang})
        vm_units.append({
            "name": name,
            "evidence": unguarded_value_move(body, lang),
            "callee": _sink_callee(body, sink_re),
        })

    # Pass 2: fold delegating wrappers / recursive self-calls into the "safe"
    # set (their enforcement lives in the in-file callee, not here) so the
    # advisory does not double-report a guarded inner mover at a wrapper site.
    safe = _resolve_delegating_safe(vm_units)

    for u in vm_units:
        evidence = u["evidence"]
        if evidence is None:
            continue  # guarded -> invariant holds -> silent
        if u["name"] in safe:
            continue  # delegates into a guarded in-file mover / recursion
        findings.append({
            "file": rel,
            "unit": u["name"],
            "language": lang,
            "verdict": "needs-fuzz",
            "private_invariant": (
                "every value-move site is dominated by a validation/"
                "authorization guard earlier in the unit body"
            ),
            "violation": "value-move reached with no guard token before it",
            "sink_evidence": evidence,
        })
    return (surface, findings, None)


# ---------------------------------------------------------------------------
# Workspace walker.
# ---------------------------------------------------------------------------
_WALK_SKIP = {
    ".git", "node_modules", "vendor", "third_party", "testdata", "dist",
    "build", "out", ".auditooor", "prior_audits", "reference", "docs",
    "poc-tests", "agent_outputs", "coverage", "fuzz_runs",
}


def enumerate_surface(workspace: "str | Path") -> "dict[str, Any]":
    ws = Path(workspace).resolve()
    surface: "list[dict[str, Any]]" = []
    findings: "list[dict[str, Any]]" = []
    exempt: "list[dict[str, Any]]" = []

    for path in sorted(ws.rglob("*")):
        if any(part in _WALK_SKIP for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".js", ".oscript", ".aa"):
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if is_oos(rel) or not is_in_scope(rel, workspace=ws):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        s, f, ex = screen_file(rel, text)
        surface.extend(s)
        findings.extend(f)
        if ex is not None:
            exempt.append(ex)

    return {
        "tool": "js-oscript-value-moving-surface",
        "workspace": str(ws),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "needs-fuzz" if findings else "no-findings",
        "advisory": True,
        "surface_count": len(surface),
        "exempt_file_count": len(exempt),
        "fire_count": len(findings),
        "surface": surface,
        "findings": findings,
        "exempt_files": exempt,
    }


def run(workspace: "str | Path", out_path: "str | Path | None" = None) -> Path:
    ws = Path(workspace).resolve()
    report = enumerate_surface(ws)
    out = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "js_oscript_value_moving_surface.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Advisory JSONL sidecar for the hunt corpus (folded by auto-coverage-closer's
    # NETNEW_ADVISORY list): one needs-fuzz / no-auto-credit row per finding.
    _sidecar = ws / ".auditooor" / "js_oscript_value_moving_surface_hypotheses.jsonl"
    _sidecar.parent.mkdir(parents=True, exist_ok=True)
    with open(_sidecar, "w", encoding="utf-8") as _sf:
        for _f in report.get("findings", []):
            _row = _f if isinstance(_f, dict) else {"finding": _f}
            _sf.write(json.dumps({
                **_row, "capability": "C1",
                "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
            }) + "\n")
    return out


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def _main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="JS/Oscript value-moving-surface enforcement screen (advisory)."
    )
    ap.add_argument("workspace", help="Workspace root path")
    ap.add_argument("--out", default=None, help="Override output path")
    ap.add_argument("--print-exempt", action="store_true",
                    help="Also print the exempted (non-value-moving) files")
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 0  # advisory: never fail the caller closed

    out = run(ws, args.out)
    report = json.loads(out.read_text(encoding="utf-8"))
    print(
        f"js-oscript-value-moving-surface [{report['verdict']}] "
        f"surface={report['surface_count']} exempt={report['exempt_file_count']} "
        f"fire={report['fire_count']} -> {out}"
    )
    for fnd in report["findings"]:
        print(f"  needs-fuzz  {fnd['file']}::{fnd['unit']}  "
              f"[{fnd['language']}]  {fnd['sink_evidence']}")
    if args.print_exempt:
        for ex in report["exempt_files"]:
            print(f"  exempt      {ex['file']}  ({ex['category']})")
    return 0  # ALWAYS rc=0 - advisory-first, never fail-close.


if __name__ == "__main__":
    sys.exit(_main())
