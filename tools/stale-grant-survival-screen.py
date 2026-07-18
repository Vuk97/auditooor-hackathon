#!/usr/bin/env python3
"""stale-grant-survival-screen.py  (A15) - residual-grant-across-lifecycle screen.

WHAT THIS TOOL DOES  (GENERAL ENFORCEMENT / INVARIANT, not a bug shape)
======================================================================
North-star method (w8mv5mpcw): "A TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound." A15 enumerates ONE delegated-and-trusted safety
property and attacks its private invariant:

  DELEGATED-TRUSTED PROPERTY: when a contract issues a standing external
  authority to a *module reference it stores* - an ERC20 allowance
  (`approve`/`forceApprove`/`increaseAllowance`), an ERC721/1155 operator grant
  (`setApprovalForAll(op,true)`), or an access-control role
  (`grantRole`/`_grantRole`/`_setupRole`) - later code TRUSTS that only the
  currently-scoped module holds that authority.

  PRIVATE INVARIANT (must hold): every grant scoped to a REPLACEABLE grantee
  reference is REVOKED at the point that reference is replaced (module swap /
  implementation upgrade / operator rotation). Formally:
      forall grantee-var G granted a standing authority:
        reassign(G)  =>  revoke(old G) dominates the reassignment.

  ATTACK THE INVARIANT: find a stored grantee G that (1) receives a standing
  authority and (2) is REASSIGNED in a post-construction setter, but (3) that
  setter does NOT revoke the OLD grantee before/at the swap. The residual grant
  then OUTLIVES the code that scoped it: the old module (or whoever controls
  its address) keeps a live allowance/operator-approval/role under the NEW
  code's changed trust assumptions (type-erased silent-fail boundary - the swap
  site has no visibility that the stale grant survived).

This is a GENERAL lifecycle invariant ("a grant scoped to a replaceable module
must die with that module"), NOT an impact-specific detector. The payoff can be
theft, unauthorized operator action, or privilege retention - A15 is agnostic;
it screens the invariant, not the exploit.

DEDUP (per backlog A15, TIER-W3 line 140)
=========================================
  - A3 authority-blast-radius scopes a LIVE authority's blast radius; it never
    models a grant OUTLIVING its scoping code.
  - A8 upgrade/migration re-establishment checks a steady-state invariant is
    RE-SET after migration; it never tracks a RESIDUAL grant left behind.
  - access-control-coverage (A2) owns guard-ABSENCE on a sink, not grant residue.
  A15 owns exactly the residue: granted -> reference replaced -> old grant not
  revoked. No overlap.

ADVISORY-FIRST (hard rule 3)
============================
Every emitted row carries verdict="needs-fuzz". This tool NEVER flips a gate,
resolves a unit, or fails closed. On a degraded/empty target it emits an empty
sidecar + an accounting record and exits 0. Hang the rows on the completeness
matrix AUTHORIZATION / LIFECYCLE axis - they are hypotheses, not verdicts.

Usage:
  python3 tools/stale-grant-survival-screen.py --workspace <ws> [--json]
  python3 tools/stale-grant-survival-screen.py --path <file-or-dir> ... [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

OUT_REL = os.path.join(".auditooor", "stale_grant_survival_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "stale_grant_survival_accounting.json")

AUDITS_ROOT = os.environ.get("AUDITOOOR_AUDITS_ROOT", "/Users/wolf/audits")

# Files we never analyse: tests, mocks, vendored libs, build output, scripts,
# and prior-audit markdown corpora (which quote vulnerable code verbatim).
# NOTE: the fleet corpus itself lives under `/Users/wolf/audits/`, so we must
# NOT skip on a bare `/audits/` (that would drop every fleet file). We skip only
# report subdirs (`.../<pkg>/audits/`, always AFTER a `/src/` segment) and the
# `/prior_audits/` corpus.
_SKIP_RE = re.compile(
    r"(?:/lib/|/node_modules/|/out/|/cache/|/forge-std/|/openzeppelin|"
    r"/prior_audits/|/src/.+/audits/|/test/|/tests/|/mock|/script/|"
    r"\.t\.sol$|\.s\.sol$)",
    re.IGNORECASE,
)

# ---- comment stripping (so we never match commented-out / doc code) --------
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def _strip_comments(src: str) -> str:
    src = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), src)
    src = _LINE_COMMENT.sub("", src)
    return src


# ---- state-variable (module reference) enumeration -------------------------
# A module reference is a storage var of address / interface / contract type.
# We deliberately EXCLUDE value types (uint*, int*, bool, bytes*, string,
# mapping, enum) - a grant is only ever scoped to an address-like reference.
_VALUE_TYPE = re.compile(
    r"^(?:u?int\d*|bool|bytes\d*|string|mapping|enum|struct)\b")
_STATEVAR_RE = re.compile(
    r"^[ \t]*"
    r"(?P<type>address|I[A-Z]\w*|[A-Z]\w*)[ \t]+"
    r"(?P<mods>(?:public|private|internal|external|immutable|constant|"
    r"override|virtual|\s)*?)"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*(?:=|;)",
    re.MULTILINE,
)


def _contract_level_only(src: str) -> str:
    """Blank out everything nested inside struct{} bodies and function bodies,
    keeping ONLY contract-body (brace-depth-1) text so that struct fields and
    function-local declarations are NEVER enumerated as storage module vars.

    Depth 0 = file scope (pragma/imports/`contract X is Y`). The contract's `{`
    opens depth 1 (state vars live here). A `struct {`/`function () {` opens
    depth 2+ (struct fields, function locals) - those we mask. Newlines are
    preserved so line structure (and thus `^`-anchored matches) is unchanged."""
    out = []
    depth = 0
    for c in src:
        if c == "{":
            depth += 1
            out.append(" ")
        elif c == "}":
            depth -= 1
            out.append(" ")
        elif depth <= 1:
            out.append(c)
        else:
            out.append("\n" if c == "\n" else " ")
    return "".join(out)


def enumerate_module_vars(src: str) -> dict:
    """name -> {"immutable": bool, "constant": bool}. Address-like CONTRACT-LEVEL
    storage only: identifiers declared inside struct{} bodies or function bodies
    are excluded (they are not standing storage references that a swap can
    strand)."""
    out = {}
    src = _contract_level_only(src)
    for m in _STATEVAR_RE.finditer(src):
        typ = m.group("type")
        if _VALUE_TYPE.match(typ):
            continue
        name = m.group("name")
        # skip obvious non-storage keywords that could slip through
        if name in {"memory", "storage", "calldata", "returns", "public",
                    "private", "internal", "external"}:
            continue
        mods = m.group("mods") or ""
        out[name] = {
            "immutable": "immutable" in mods,
            "constant": "constant" in mods,
        }
    return out


# ---- balanced-paren argument extraction ------------------------------------
def _read_call_args(src: str, open_paren_idx: int):
    """Given index of '(', return (arg_list, index_after_close) or (None,-1)."""
    depth = 0
    i = open_paren_idx
    n = len(src)
    start = open_paren_idx + 1
    while i < n:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                inner = src[start:i]
                return _split_top_commas(inner), i + 1
        i += 1
    return None, -1


def _split_top_commas(s: str):
    args, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


_WRAP_RE = re.compile(r"^(?:address|payable|I[A-Z]\w*|[A-Z]\w*)\s*\(\s*(.*?)\s*\)$")


def _unwrap_ident(expr: str) -> str:
    """Strip address(...)/IFoo(...)/payable(...) wrappers to the inner token."""
    expr = expr.strip()
    for _ in range(4):
        m = _WRAP_RE.match(expr)
        if not m:
            break
        expr = m.group(1).strip()
    return expr


def _is_zero(expr: str) -> bool:
    return _unwrap_ident(expr).strip().rstrip(";").strip() in {"0", "0x0", "uint256(0)"}


def _is_true(expr: str) -> bool:
    return _unwrap_ident(expr).strip().rstrip(";").strip().lower() == "true"


def _is_false(expr: str) -> bool:
    return _unwrap_ident(expr).strip().rstrip(";").strip().lower() == "false"


# ---- function-body extraction (name, body, is_ctor/is_init) ----------------
_FN_HEAD_RE = re.compile(
    r"\b(?P<kind>function\s+(?P<name>[A-Za-z_]\w*)|constructor)\b(?P<sig>[^;{]*)\{")


def _fn_local_names(sig: str) -> set:
    """Param + named-return identifiers declared in a function signature.
    These are locals, never storage; an assignment to one cannot strand a
    stored grant, so the swap-detector must ignore them."""
    names = set()
    i, n = 0, len(sig)
    while i < n:
        if sig[i] == "(":
            args, after = _read_call_args(sig, i)
            if args:
                for part in args:
                    toks = re.findall(r"[A-Za-z_]\w*", part)
                    # a declaration is `Type [loc] name` -> >=2 tokens; a bare
                    # modifier arg (e.g. onlyRole(ROLE)) is 1 token -> skip.
                    if len(toks) >= 2:
                        names.add(toks[-1])
            i = after if after > i else i + 1
        else:
            i += 1
    return names


def enumerate_functions(src: str):
    """List of dicts {name, is_ctor, is_init, is_view, locals, body, body_start}."""
    fns = []
    for m in _FN_HEAD_RE.finditer(src):
        brace = src.index("{", m.start())
        depth, i, n = 0, brace, len(src)
        while i < n:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[brace + 1:i]
        name = m.group("name") or "constructor"
        sig = m.group("sig") or ""
        is_ctor = m.group("kind").startswith("constructor")
        # init / first-setup functions are NOT swaps (they establish, not replace)
        is_init = (
            bool(re.match(r"(?:__)?_?initiali[sz]e", name or "")) or
            name in {"init", "__init", "setUp"} or
            bool(re.match(r"(?:_setup|setup|_init)", name or ""))
        )
        # a view/pure function cannot write storage, so it can never strand a
        # storage grant - any `=` inside it targets a local/return.
        is_view = bool(re.search(r"\b(?:view|pure)\b", sig))
        fns.append({"name": name, "is_ctor": is_ctor, "is_init": is_init,
                    "is_view": is_view, "locals": _fn_local_names(sig),
                    "body": body, "body_start": brace + 1})
    return fns


# ---- grant / revoke recognition over a body --------------------------------
_ALLOWANCE_GRANT = ("approve", "forceApprove", "safeApprove", "increaseAllowance")
_CALL_SITE_RE = re.compile(
    r"\.(?P<fn>approve|forceApprove|safeApprove|increaseAllowance|"
    r"setApprovalForAll|grantRole|_grantRole|_setupRole|"
    r"revokeRole|_revokeRole|renounceRole|decreaseAllowance)\s*\(")
# Bare (non-`.`) internal AC helpers: _grantRole(role, acct) etc.
_BARE_CALL_RE = re.compile(
    r"(?<![.\w])(?P<fn>_grantRole|_setupRole|_revokeRole)\s*\(")


def _module_grantee(args, module_vars):
    """Return the arg (unwrapped ident) that names a stored module var, else None."""
    for a in args:
        ident = _unwrap_ident(a)
        # tolerate a leading token like `address(X)` already unwrapped
        head = re.match(r"^[A-Za-z_]\w*", ident)
        if head and head.group(0) in module_vars:
            return head.group(0)
    return None


def _scan_grants_revokes(body: str, module_vars: dict):
    """Return (grants, revokes) as lists of (grantee_var, kind, pos)."""
    grants, revokes = [], []
    for rx in (_CALL_SITE_RE, _BARE_CALL_RE):
        for m in rx.finditer(body):
            fn = m.group("fn")
            open_idx = body.index("(", m.end() - 1)
            args, _ = _read_call_args(body, open_idx)
            if not args:
                continue
            grantee = _module_grantee(args, module_vars)
            if grantee is None:
                continue
            pos = m.start()
            if fn in _ALLOWANCE_GRANT:
                last = args[-1]
                if fn == "approve" or fn == "forceApprove" or fn == "safeApprove":
                    (revokes if _is_zero(last) else grants).append(
                        (grantee, "allowance", pos))
                else:  # increaseAllowance -> always a grant
                    grants.append((grantee, "allowance", pos))
            elif fn == "decreaseAllowance":
                revokes.append((grantee, "allowance", pos))
            elif fn == "setApprovalForAll":
                last = args[-1]
                if _is_true(last):
                    grants.append((grantee, "operator", pos))
                elif _is_false(last):
                    revokes.append((grantee, "operator", pos))
            elif fn in ("grantRole", "_grantRole", "_setupRole"):
                grants.append((grantee, "role", pos))
            elif fn in ("revokeRole", "_revokeRole", "renounceRole"):
                revokes.append((grantee, "role", pos))
    return grants, revokes


# ---- reassignment (swap) recognition over a body ---------------------------
def _reassignments(body: str, var: str):
    """Positions where `var` is assigned (real =, not ==/<=/>=/!=/=> or decl)."""
    positions = []
    for m in re.finditer(r"(?<![\w.])" + re.escape(var) + r"\s*=(?![=>])", body):
        # exclude comparison / arrow already handled by lookahead;
        # exclude a local declaration `Type var =` right before the name
        pre = body[max(0, m.start() - 40):m.start()]
        if re.search(r"[A-Za-z_]\w*\s+$", pre) and not re.search(r"[;{}\)]\s*$", pre):
            # a type token precedes -> local declaration, skip
            # (state-var reassignment has a statement boundary before the name)
            continue
        positions.append(m.start())
    return positions


# ---- THE CORE PREDICATE (load-bearing; monkeypatched in the non-vacuity test)
def swap_revokes_old_grant(body: str, grantee: str, reassign_pos: int,
                           module_vars: dict) -> bool:
    """True iff the OLD grant to `grantee` is revoked within this swap scope.

    The private-invariant enforcer: a swap is SAFE only if the old grantee's
    standing authority is torn down in the same function (revoke dominates, or
    at least co-occurs in, the reassignment scope). Neutralising this predicate
    (forcing True) collapses A15 to nothing - the non-vacuity anchor.
    """
    _, revokes = _scan_grants_revokes(body, module_vars)
    return any(g == grantee for (g, _k, _p) in revokes)


def analyze_source(src_raw: str, rel_path: str):
    src = _strip_comments(src_raw)
    module_vars = enumerate_module_vars(src)
    if not module_vars:
        return []
    fns = enumerate_functions(src)

    # 1) which module vars ever receive a STANDING grant (anywhere)?
    granted = {}  # var -> (kind, fn_name)
    for fn in fns:
        grants, _ = _scan_grants_revokes(fn["body"], module_vars)
        for (g, kind, _pos) in grants:
            granted.setdefault(g, (kind, fn["name"]))

    if not granted:
        return []

    # 2) which granted vars get REASSIGNED (swapped) in a post-init setter,
    #    with NO revoke of the old grantee in that swap scope?
    violators = []
    for fn in fns:
        if fn["is_ctor"] or fn["is_init"]:
            continue  # first-init/setup is not a swap
        if fn.get("is_view"):
            continue  # a view/pure fn cannot write storage -> cannot strand a grant
        for var, (kind, grant_fn) in granted.items():
            if module_vars.get(var, {}).get("constant"):
                continue
            if var in fn.get("locals", ()):
                continue  # assignment target is a param/named-return, not storage
            positions = _reassignments(fn["body"], var)
            if not positions:
                continue
            for pos in positions:
                if swap_revokes_old_grant(fn["body"], var, pos, module_vars):
                    continue  # guarded swap -> invariant holds -> silent
                violators.append({
                    "tool": "stale-grant-survival-screen",
                    "capability": "A15",
                    "file": rel_path,
                    "grantee_var": var,
                    "grant_kind": kind,
                    "granted_in": grant_fn,
                    "swapped_in": fn["name"],
                    "verdict": "needs-fuzz",
                    "invariant": "grant scoped to a replaceable module must be "
                                 "revoked at replacement",
                    "reason": (
                        f"module reference `{var}` receives a standing {kind} "
                        f"grant in `{grant_fn}` and is reassigned in "
                        f"`{fn['name']}` without revoking the OLD grantee in the "
                        f"same scope; residual {kind} authority outlives the "
                        f"code that scoped it (stale-grant survival)."),
                })
                break  # one violator per (var, swap-fn) is enough
    return violators


# ---- IO / driver -----------------------------------------------------------
def _iter_sol_files(paths):
    for p in paths:
        p = pathlib.Path(p)
        if p.is_file() and p.suffix == ".sol":
            if not _SKIP_RE.search(str(p)):
                yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*.sol")):
                if not _SKIP_RE.search(str(f)):
                    yield f


def run(paths, root=None):
    hyps = []
    files_scanned = 0
    for f in _iter_sol_files(paths):
        files_scanned += 1
        try:
            src = f.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(f)
        if root:
            try:
                rel = str(f.relative_to(root))
            except ValueError:
                pass
        hyps.extend(analyze_source(src, rel))
    acc = {
        "tool": "stale-grant-survival-screen",
        "capability": "A15",
        "status": "ok",
        "files_scanned": files_scanned,
        "hypotheses": len(hyps),
        "advisory_first": True,
        "auto_credit": False,
    }
    return hyps, acc


def _emit(ws: pathlib.Path, hyps, acc, out=None):
    out_path = pathlib.Path(out) if out else (ws / OUT_REL)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        for h in hyps:
            fh.write(json.dumps(h) + "\n")
    acc_path = ws / ACC_REL
    acc_path.parent.mkdir(parents=True, exist_ok=True)
    with open(acc_path, "w") as fh:
        json.dump(acc, fh, indent=2)


def main():
    ap = argparse.ArgumentParser(description="A15 stale-grant survival screen")
    ap.add_argument("--workspace", help="workspace name under AUDITOOOR_AUDITS_ROOT")
    ap.add_argument("--path", nargs="*", default=[],
                    help="explicit .sol files or dirs to scan")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ws_dir = None
    scan_paths = list(args.path)
    if args.workspace:
        ws_dir = pathlib.Path(args.workspace)
        if not ws_dir.is_absolute():
            ws_dir = pathlib.Path(AUDITS_ROOT) / args.workspace
        if not ws_dir.is_dir():
            print(f"[err] workspace not found: {ws_dir}", file=sys.stderr)
            sys.exit(1)
        scan_paths.append(str(ws_dir))
    if not scan_paths:
        print("[err] provide --workspace or --path", file=sys.stderr)
        sys.exit(2)

    hyps, acc = run(scan_paths, root=ws_dir)

    if ws_dir is not None:
        _emit(ws_dir, hyps, acc, args.out)
    elif args.out:
        _emit(pathlib.Path("."), hyps, acc, args.out)

    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": hyps}, indent=2))
    else:
        print(f"[ok] A15 stale-grant-survival: status={acc['status']}")
        print(f"     files scanned:           {acc['files_scanned']}")
        print(f"     hypotheses (needs-fuzz): {acc['hypotheses']}")
        for h in hyps:
            print(f"       - {h['file']}: {h['grantee_var']} "
                  f"({h['grant_kind']}) swapped in {h['swapped_in']}")


if __name__ == "__main__":
    main()
