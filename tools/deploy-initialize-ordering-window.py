#!/usr/bin/env python3
"""deploy-initialize-ordering-window.py  (A14) - deploy->initialize ordering-window screen.

WHAT THIS TOOL DOES (north-star method, w8mv5mpcw)
==================================================
"A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."

DELEGATED-AND-TRUSTED SAFETY PROPERTY (enumerated):
  Proxy / upgradeable / greenfield contracts delegate their trust-anchor setup
  (owner, admin, roles, sibling-dependency addresses) to an ``initialize()``
  step that runs SEPARATELY from bytecode deployment. Every consumer of the
  contract implicitly TRUSTS that, by the time the contract is reachable, that
  step has already run - once, by the intended deployer, and after every sibling
  it depends on was itself initialized.

PRIVATE INVARIANT (stated):
  (I1) No externally-callable path may ESTABLISH a trust anchor (ownership /
       roles / auth) unless an enforcement makes that path single-shot AND/OR
       deployer-authenticated - otherwise the deploy->init WINDOW is front-run.
  (I2) An initializer that WIRES a sibling dependency address must VALIDATE it
       (non-zero) - otherwise an out-of-order deploy (the sibling proxy not yet
       initialized / mis-passed) leaves a TRUSTED dependency zero / mis-set.

ATTACK ON THE INVARIANT:
  (A1) Attacker watches the mempool, front-runs the deployer's ``initialize``
       call, and becomes owner / grants themselves a role (greenfield init gap).
  (A2) Sibling proxies are brought live out of dependency order, so a live
       contract reads a dependency that is still address(0) / a placeholder.

THE TWO ADVISORY FLAGS
======================
  (A14-a) init-window-front-runnable   - an external/public initializer SETS a
          trust anchor but carries NO init-guard enforcement (no ``initializer``
          / ``reinitializer`` modifier, no ``_disableInitializers()`` lock, no
          access guard, no manual once-guard). Bypasses I1.
  (A14-b) cross-init-dependency-unvalidated - an initializer WIRES a sibling
          dependency ADDRESS from a parameter into state WITHOUT a non-zero
          validation. Bypasses I2 - the cross-proxy deploy-order arm.

DEDUP (per backlog A14): A8 (migration re-establishment) fires POST-migration on
value-move + reinit; A10 / storage-layout is slot-collision. NEITHER covers the
TEMPORAL deploy->init timing gap across sibling proxies. A14 owns exactly that
window and is complementary, not overlapping.

GENERAL, NOT A SHAPE: this is a reusable trust-enforcement invariant screen
(init-anchor authority + deploy-order dependency), never an impact-specific bug
detector. Every emitted row is verdict="needs-fuzz": NO-AUTO-CREDIT, advisory-
first, never flips a gate, never fail-closes. Hang it on the completeness-matrix
INITIALIZATION / AUTHORIZATION axis, not a silo.

FAIL-OPEN: on a source tree with no Solidity / no initializers, emit an empty
hypotheses file + an accounting record and exit 0.

Usage:
  python3 tools/deploy-initialize-ordering-window.py --workspace <ws> [--json]
  python3 tools/deploy-initialize-ordering-window.py --file <one.sol> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass

OUT_REL = os.path.join(".auditooor", "deploy_initialize_ordering_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "deploy_initialize_ordering_accounting.json")

# Advisory-first env gate. When UNSET, evaluate() returns None (OFF). Never wire
# under the L37 umbrella until validated across the fleet (single-ws / incomplete
# kill -> a dedicated env, mirroring the B1 enforcement-point precedent).
ENV_FLAG = "AUDITOOOR_A14_INIT_ORDERING"

# ---------------------------------------------------------------------------
# LOAD-BEARING PREDICATES (module-level so tests can neutralise them to prove
# non-vacuity: neutralising any of these silences the planted positive).
# ---------------------------------------------------------------------------

# (P1) Is this function an initializer BY NAME? `init` exact, or initialize*/
# reinitialize* (incl. versioned initializeV2). Deliberately NOT `initiate*`.
_INIT_NAME_RE = re.compile(r"^(?:re)?initiali[sz]e\w*$|^init$", re.I)

# (P1') Is this an initializer BY MODIFIER? OZ initializer / reinitializer(n).
_INIT_MODIFIER_RE = re.compile(r"\b(?:initializer\b|reinitializer\s*\()")

# (P2) Does the body ESTABLISH a trust anchor (ownership / roles / auth / an
# *_init parent-initializer that does so)? This is the half that makes the gap
# a SECURITY window rather than a benign config setter.
_TRUST_ANCHOR_RE = re.compile(
    r"(?:\b\w*_init\s*\("           # __Ownable_init(, AccessControlled_init(, ...
    r"|_transferOwnership\s*\(|transferOwnership\s*\("
    r"|_grantRole\s*\(|grantRole\s*\(|_setupRole\s*\(|_setRoleAdmin\s*\("
    r"|_setOwner\s*\(|__Ownable|__AccessControl"
    r"|\b_?owner\s*=|\b_?admin\s*=|\bgovernance\s*=|\bgovernor\s*=)",
    re.I,
)

# (G1) Init-guard: the OZ init-once / lock enforcement, on the fn attrs.
#      (initializer / reinitializer already matched by _INIT_MODIFIER_RE.)
# (G2) Access guard: an onlyX modifier or a msg.sender / role check.
_ACCESS_GUARD_RE = re.compile(
    r"(?:\bonly[A-Z]\w*|\bmsg\.sender\b|_checkOwner\b|_checkRole\b|hasRole\s*\()")
# (G3) Manual once-guard inside the body.
_ONCE_GUARD_RE = re.compile(
    r"(?:_initialized\b|_initializing\b|\binitialized\b|require\s*\(\s*!"
    r"|revert\s+Already|AlreadyInitialized)", re.I)
# (G4) Constructor lock present anywhere in the file.
_DISABLE_INIT_RE = re.compile(r"_disableInitializers\s*\(")
# (G5) The `Versioned` init-once family (a widely-used upgradeable base: a
#      contract-version writer that reverts on a second init). File-level, like
#      G4 - covers the public initializer that DELEGATES the version guard to an
#      internal `_initialize`. General pattern, not a per-project shape.
_VERSIONED_INIT_RE = re.compile(
    r"_initializeContractVersionTo\s*\(|_updateContractVersion\s*\("
    r"|initializeContractVersion\s*\(|_setContractVersion\s*\(|\b_petrify\s*\(")

# Flag-B helpers.
_ADDR_PARAM_RE = re.compile(r"\baddress\b(?:\s+(?:calldata|memory|payable))?\s+(\w+)")
_ZERO_CHECK_TOKEN_RE = re.compile(r"address\s*\(\s*0\s*\)|ZeroAddress|address\(0x0\)",
                                  re.I)

# Directory names we never treat as in-scope production source.
_SKIP_DIRS = {"node_modules", "lib", "out", "artifacts", "cache", ".git",
              "test", "tests", "mock", "mocks", "script", "scripts"}


@dataclass
class Fn:
    name: str
    params: str
    attrs: str
    body: str
    line: int


def _strip_comments(text: str) -> str:
    # Blank out comments but PRESERVE newlines so reported line numbers still map
    # to the original source.
    def _blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.S)
    text = re.sub(r"//[^\n]*", _blank, text)
    return text


def _match_delim(text: str, open_pos: int, oc: str, cc: str) -> int:
    depth = 0
    i, n = open_pos, len(text)
    while i < n:
        c = text[i]
        if c == oc:
            depth += 1
        elif c == cc:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def iter_functions(text: str):
    """Yield Fn for every `function NAME(...)` (bodies brace-matched; interface /
    abstract declarations yield an empty body). Comments stripped first."""
    clean = _strip_comments(text)
    for m in re.finditer(r"\bfunction\s+(\w+)\s*\(", clean):
        name = m.group(1)
        popen = m.end() - 1
        pclose = _match_delim(clean, popen, "(", ")")
        if pclose < 0:
            continue
        params = clean[popen + 1:pclose]
        rest = pclose + 1
        brace = clean.find("{", rest)
        semi = clean.find(";", rest)
        line = clean.count("\n", 0, m.start()) + 1
        if semi != -1 and (brace == -1 or semi < brace):
            yield Fn(name, params, clean[rest:semi], "", line)
            continue
        if brace == -1:
            continue
        attrs = clean[rest:brace]
        bclose = _match_delim(clean, brace, "{", "}")
        if bclose < 0:
            continue
        yield Fn(name, params, attrs, clean[brace + 1:bclose], line)


# ---------------------------------------------------------------------------
# Core predicate helpers
# ---------------------------------------------------------------------------

def is_initializer(fn: Fn) -> bool:
    return bool(_INIT_NAME_RE.match(fn.name) or _INIT_MODIFIER_RE.search(fn.attrs))


def is_external(fn: Fn) -> bool:
    return bool(re.search(r"\b(?:external|public)\b", fn.attrs))


def sets_trust_anchor(fn: Fn) -> bool:
    return bool(_TRUST_ANCHOR_RE.search(fn.body))


def init_guard_reasons(fn: Fn, file_text: str):
    """Return the set of enforcement mechanisms that make the deploy->init window
    NOT front-runnable. Empty set => I1 is bypassable => flag A fires."""
    reasons = set()
    if _INIT_MODIFIER_RE.search(fn.attrs):
        reasons.add("initializer-modifier")
    if _DISABLE_INIT_RE.search(file_text):
        reasons.add("constructor-_disableInitializers")
    if _VERSIONED_INIT_RE.search(fn.body) or _VERSIONED_INIT_RE.search(file_text):
        reasons.add("versioned-init-once")
    if _ACCESS_GUARD_RE.search(fn.attrs) or _ACCESS_GUARD_RE.search(fn.body):
        reasons.add("access-guard")
    if _ONCE_GUARD_RE.search(fn.body):
        reasons.add("manual-once-guard")
    return reasons


def unvalidated_dependency_params(fn: Fn):
    """Flag B: address params WIRED into state without a non-zero validation.

    Requires: an address param, a `<statevar> = <param>` (or `<param>` stored to
    an assigned identifier), and NO address(0) validation anywhere in the body.
    Returns the list of such param names."""
    params = _ADDR_PARAM_RE.findall(fn.params)
    if not params:
        return []
    if _ZERO_CHECK_TOKEN_RE.search(fn.body):
        return []  # some non-zero validation exists; conservatively silent
    stored = []
    for p in params:
        # `x = p;`  or  `something = p ;` (the param flows into state/assignment)
        if re.search(r"=\s*" + re.escape(p) + r"\s*;", fn.body):
            stored.append(p)
    return stored


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------

def screen_source(rel_path: str, text: str):
    """Return advisory hypotheses for one Solidity source string."""
    hyps = []
    for fn in iter_functions(text):
        if not fn.body:
            continue  # interface / abstract declaration
        if not is_initializer(fn):
            continue
        if not is_external(fn):
            continue  # internal *_init helper is not the front-runnable entry
        anchor = sets_trust_anchor(fn)

        # ---- Flag A: init-window front-run gap (I1) ----------------------
        if anchor:
            guards = init_guard_reasons(fn, text)
            if not guards:
                hyps.append({
                    "flag_kind": "init-window-front-runnable",
                    "file": rel_path,
                    "line": fn.line,
                    "function": fn.name,
                    "trust_anchor": True,
                    "init_guards_found": [],
                    "invariant": "I1: no external path may establish a trust "
                                 "anchor without a single-shot / deployer-auth "
                                 "enforcement",
                    "attack": "front-run the deployer initialize() tx in the "
                              "deploy->init window and seize ownership/roles",
                    "verdict": "needs-fuzz",
                    "attack_class": "deploy-init-ordering-window",
                    "dedup_note": "A14 temporal deploy->init gap; NOT A8 "
                                  "post-migration nor A10 slot-collision",
                })

        # ---- Flag B: cross-init dependency wired unvalidated (I2) ---------
        deps = unvalidated_dependency_params(fn)
        if deps:
            hyps.append({
                "flag_kind": "cross-init-dependency-unvalidated",
                "file": rel_path,
                "line": fn.line,
                "function": fn.name,
                "dependency_params": deps,
                "invariant": "I2: an initializer wiring a sibling dependency "
                             "address must validate it non-zero",
                "attack": "bring sibling proxies live out of dependency order so "
                          "a live contract trusts a zero/placeholder dependency",
                "verdict": "needs-fuzz",
                "attack_class": "deploy-init-ordering-window",
                "dedup_note": "A14 cross-proxy deploy-order arm; NOT A8/A10",
            })
    return hyps


def _iter_sol_files(ws: pathlib.Path, max_files: int = 4000):
    n = 0
    for p in sorted(ws.rglob("*.sol")):
        parts = {seg.lower() for seg in p.relative_to(ws).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        yield p
        n += 1
        if n >= max_files:
            return


def analyze(ws: pathlib.Path):
    acc = {
        "tool": "deploy-initialize-ordering-window",
        "workspace": str(ws),
        "status": "ok",
        "sol_files_scanned": 0,
        "initializers_seen": 0,
        "front_run_flags": 0,
        "dependency_flags": 0,
        "hypotheses": 0,
    }
    hyps = []
    seen_init = 0
    files = 0
    for p in _iter_sol_files(ws):
        files += 1
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for fn in iter_functions(text):
            if fn.body and is_initializer(fn) and is_external(fn):
                seen_init += 1
        try:
            rel = str(p.relative_to(ws))
        except Exception:
            rel = str(p)
        hyps.extend(screen_source(rel, text))
    acc["sol_files_scanned"] = files
    acc["initializers_seen"] = seen_init
    acc["front_run_flags"] = sum(
        1 for h in hyps if h["flag_kind"] == "init-window-front-runnable")
    acc["dependency_flags"] = sum(
        1 for h in hyps if h["flag_kind"] == "cross-init-dependency-unvalidated")
    acc["hypotheses"] = len(hyps)
    if files == 0:
        acc["status"] = "no-solidity"
    return hyps, acc


def evaluate(ws: pathlib.Path):
    """Advisory-first entry: OFF (returns None under the key) unless the env flag
    is set. When enabled, emits the needs-fuzz jsonl + accounting and returns a
    summary. Never flips a gate."""
    if os.environ.get(ENV_FLAG) not in ("1", "true", "TRUE", "yes"):
        return {"init_ordering_window": None}
    hyps, acc = analyze(ws)
    _emit(ws, hyps, acc)
    return {"init_ordering_window": {
        "enabled": True,
        "verdict": "needs-fuzz",
        "count": len(hyps),
        "front_run_flags": acc["front_run_flags"],
        "dependency_flags": acc["dependency_flags"],
        "accounting": acc,
    }}


def _emit(ws: pathlib.Path, hyps, acc, out=None):
    out_path = pathlib.Path(out) if out else (ws / OUT_REL)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for h in hyps:
            f.write(json.dumps(h) + "\n")
    acc_path = ws / ACC_REL
    acc_path.parent.mkdir(parents=True, exist_ok=True)
    with open(acc_path, "w") as f:
        json.dump(acc, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace")
    g.add_argument("--file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.file:
        p = pathlib.Path(args.file)
        if not p.is_file():
            print(f"[err] file not found: {p}", file=sys.stderr)
            sys.exit(1)
        text = p.read_text(encoding="utf-8", errors="replace")
        hyps = screen_source(str(p), text)
        acc = {
            "tool": "deploy-initialize-ordering-window",
            "file": str(p),
            "status": "ok",
            "front_run_flags": sum(
                1 for h in hyps if h["flag_kind"] == "init-window-front-runnable"),
            "dependency_flags": sum(
                1 for h in hyps
                if h["flag_kind"] == "cross-init-dependency-unvalidated"),
            "hypotheses": len(hyps),
        }
        if args.json:
            print(json.dumps({"accounting": acc, "hypotheses": hyps}))
        else:
            print(f"[ok] A14 single-file: front-run={acc['front_run_flags']} "
                  f"dep={acc['dependency_flags']} (needs-fuzz)")
        return

    ws = pathlib.Path(args.workspace)
    if not ws.is_dir():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        sys.exit(1)
    hyps, acc = analyze(ws)
    _emit(ws, hyps, acc, args.out)
    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": hyps}))
    else:
        print(f"[ok] A14 deploy-initialize-ordering-window: status={acc['status']}")
        print(f"     sol files scanned:     {acc['sol_files_scanned']}")
        print(f"     initializers seen:     {acc['initializers_seen']}")
        print(f"     front-run flags:       {acc['front_run_flags']}")
        print(f"     dependency flags:      {acc['dependency_flags']}")
        print(f"     hypotheses (needs-fuzz): {acc['hypotheses']}")


if __name__ == "__main__":
    main()
