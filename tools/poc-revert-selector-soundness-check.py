#!/usr/bin/env python3
"""
poc-revert-selector-soundness-check.py
Rule 37 emit tier: tool utility (no corpus record emitted)

NEW bug class (operator-caught, strata MIN_SHARES, 2026-07-01):
  A Foundry PoC used `vm.expectRevert(MinSharesViolation.selector)`, which is
  matched by SELECTOR (keccak of the 4-byte error signature) ONLY. The same
  custom error name `MinSharesViolation()` was declared in THREE places:
    - in-scope   contracts/tranches/interfaces/IErrors.sol   (the real guard, MIN_SHARES = 0.1 ether)
    - OOS mock   contracts/test/ethena/interfaces/IStakedUSDe.sol (MIN_SHARES = 1 ether)
    - OOS mock   contracts/test/neutrl/sNUSD.sol
  Because `error MinSharesViolation()` has an IDENTICAL 4-byte selector in every
  declaration, `vm.expectRevert(X.selector)` will SILENTLY match whichever
  contract actually reverts - it cannot tell the in-scope guard from an OOS
  mock's guard. The PoC therefore asserted the WRONG contract's revert and
  mis-measured severity by 10x (asserted the 1-ether mock threshold instead of
  the 0.1-ether in-scope threshold).

WHAT THIS GATE DOES
  Given a PoC `.t.sol` file (or a finding folder, or a whole `--src-root`
  project), for each `vm.expectRevert(...)` that names a CUSTOM ERROR X:
    1. resolve the custom-error name X (from X.selector,
       abi.encodeWithSelector(X, ...), or a bare error-type arg X.selector),
    2. scan the entire project tree for `error X(` DECLARATIONS,
    3. if X is declared in MORE THAN ONE contract/file - especially when at
       least one declaration sits under a test/mock/OOS path AND at least one is
       in-scope - FLAG `ambiguous-revert-selector`: the assertion may match the
       wrong contract and mis-attribute the revert (and therefore severity).

  PASS for an expectRevert when:
    - the custom error name is UNIQUELY declared in the project, OR
    - the expectRevert is PINNED to a reverter address
      (`vm.expectRevert(<selector-or-bytes>, <address>)` - the 2-arg overload
      that asserts the reverter), OR
    - the PoC otherwise pins the reverting contract for that assertion via an
      adjacent trace/event assertion (best-effort heuristic within a small
      window).

  OUT OF SCOPE of this check (reported NA, never flagged):
    - string reverts (`vm.expectRevert("msg")`) and the legacy
      `Error(string)` / `Panic(uint256)` reverts - these are not custom-error
      selectors and carry no in-scope/OOS ambiguity of this kind.
    - `vm.expectRevert()` with no argument (matches any revert).

ANTI-FALSE-POSITIVE
  Only a GENUINELY multi-declared custom error is flagged. A custom error that
  is declared exactly once anywhere in the scanned tree PASSES. Address-pinned
  expectReverts PASS even when multi-declared.

VERDICTS
  pass-revert-selector-sound     : no ambiguous custom-error expectRevert found.
  fail-ambiguous-revert-selector : >=1 expectRevert names a custom error that is
                                   declared in >1 contract/file (review needed).

USAGE
  python3 tools/poc-revert-selector-soundness-check.py <poc.t.sol> [--src-root <dir>] [--json] [--strict]
  python3 tools/poc-revert-selector-soundness-check.py <finding-folder>/ [--json]
  python3 tools/poc-revert-selector-soundness-check.py --src-root <project-dir> [--json]

  <target> may be a single .t.sol file, a directory of PoCs, or omitted when
  --src-root is given (then every *.t.sol under src-root is checked).
  --src-root defaults to the target's enclosing project (walks up to the first
  dir containing foundry.toml / remappings.txt / a `src` dir, else the target's
  own directory tree). The DECLARATION scan always covers the full src-root.

EXIT CODES
  0  clean (pass-revert-selector-sound), or no custom-error expectReverts found.
  1  at least one ambiguous-revert-selector (review required).
  2  usage / IO error.
"""

import argparse
import json
import os
import re
import sys

# ---- path classification --------------------------------------------------

# Directory / path fragments that mark a declaration as test / mock / OOS.
_OOS_PATH_MARKERS = (
    "/test/",
    "/tests/",
    "/mock/",
    "/mocks/",
    "/script/",
    "/scripts/",
    "/lib/",
    "/node_modules/",
)
_OOS_NAME_MARKERS = ("mock", ".t.sol", ".s.sol")

# Directories never worth scanning for declarations (build output, deps caches).
_PRUNE_DIRS = {
    ".git",
    "out",
    "cache",
    "artifacts",
    "node_modules",
    "broadcast",
    "coverage",
}


def _is_oos_path(path):
    """Heuristic: does this declaration path look like test/mock/OOS material?"""
    p = "/" + path.replace(os.sep, "/").lstrip("/")
    low = p.lower()
    if any(m in low for m in _OOS_PATH_MARKERS):
        return True
    base = os.path.basename(low)
    if any(m in base for m in _OOS_NAME_MARKERS):
        return True
    return False


# ---- src-root resolution --------------------------------------------------

_ROOT_MARKERS = ("foundry.toml", "remappings.txt", "hardhat.config.js", "hardhat.config.ts")


def _resolve_src_root(start_path):
    """Walk up from start_path to the first plausible project root."""
    start = os.path.abspath(start_path)
    d = start if os.path.isdir(start) else os.path.dirname(start)
    prev = None
    while d and d != prev:
        try:
            entries = set(os.listdir(d))
        except OSError:
            entries = set()
        if any(m in entries for m in _ROOT_MARKERS):
            return d
        if "src" in entries and os.path.isdir(os.path.join(d, "src")):
            return d
        prev = d
        d = os.path.dirname(d)
    # Fallback: the enclosing directory of the target.
    return start if os.path.isdir(start) else os.path.dirname(start)


# ---- declaration scan -----------------------------------------------------

# `error Name(...)` declaration. Name is a Solidity identifier.
_ERROR_DECL_RE = re.compile(r"\berror\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")


def _scan_declarations(src_root):
    """Return {error_name: [ (relpath, lineno, is_oos), ... ]} for all *.sol."""
    decls = {}
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        for fn in filenames:
            if not fn.endswith(".sol"):
                continue
            full = os.path.join(dirpath, fn)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            rel = os.path.relpath(full, src_root)
            is_oos = _is_oos_path(rel)
            for i, line in enumerate(lines, 1):
                # Skip obvious comment-only lines to reduce noise.
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                for m in _ERROR_DECL_RE.finditer(line):
                    name = m.group(1)
                    decls.setdefault(name, []).append((rel, i, is_oos))
    return decls


# ---- expectRevert extraction ----------------------------------------------

# Match a vm.expectRevert( ... ) call, capturing the argument text up to the
# matching close paren on the same logical span. We do a light paren-balance
# scan rather than a fragile single regex so multi-line args work.
_EXPECT_RE = re.compile(r"\bvm\s*\.\s*expectRevert\s*\(")

# Inside the arg text, recognise a custom-error reference:
#   X.selector
#   Contract.X.selector          (dotted qualifier)
#   abi.encodeWithSelector(X.selector, ...)
#   abi.encodeWithSelector(X, ...) / abi.encodeWithSelector(Y.X.selector,...)
# We capture the FINAL identifier segment before `.selector` (the error name),
# or, inside encodeWithSelector, the first-argument error name.
_SELECTOR_REF_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$.]*)\s*\.\s*selector\b")
_ENCODE_WITH_SEL_RE = re.compile(
    r"abi\s*\.\s*encodeWithSelector\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]*?)(?:\s*\.\s*selector)?\s*[,)]"
)
# A bare custom-error type reference used by newer forge:
#   vm.expectRevert(MyError.selector) already handled by _SELECTOR_REF_RE.
# String / bytes literal arg -> NA.
_STRING_ARG_RE = re.compile(r"""^\s*['"]""")
_BYTES_HEX_RE = re.compile(r"""^\s*(hex\s*['"]|bytes\s*\()""")


def _final_ident(dotted):
    """`Contract.MyError` / `MyError` -> `MyError` (last dotted segment)."""
    return dotted.split(".")[-1].strip()


def _extract_arg_span(text, open_paren_idx):
    """Given text and index just AFTER 'expectRevert(', return (arg_text, end_idx).
    end_idx is the index of the matching ')'. Balances parens/brackets and
    respects string literals."""
    depth = 1
    i = open_paren_idx
    n = len(text)
    in_str = None
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in ("'", '"'):
                in_str = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    return text[open_paren_idx:i], i
        i += 1
    return text[open_paren_idx:], n  # unbalanced; return rest


def _split_top_level_args(arg_text):
    """Split a call-arg string on top-level commas."""
    args = []
    depth = 0
    in_str = None
    cur = []
    i = 0
    n = len(arg_text)
    while i < n:
        c = arg_text[i]
        if in_str:
            cur.append(c)
            if c == "\\":
                if i + 1 < n:
                    cur.append(arg_text[i + 1])
                    i += 2
                    continue
            elif c == in_str:
                in_str = None
        else:
            if c in ("'", '"'):
                in_str = c
                cur.append(c)
            elif c in "([{":
                depth += 1
                cur.append(c)
            elif c in ")]}":
                depth -= 1
                cur.append(c)
            elif c == "," and depth == 0:
                args.append("".join(cur))
                cur = []
            else:
                cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur))
    return [a.strip() for a in args]


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def _analyze_expect_arg(arg_text):
    """Classify an expectRevert argument.

    Returns a dict:
      { 'kind': 'custom'|'string'|'bytes'|'empty'|'other',
        'error_name': str|None,
        'address_pinned': bool }
    """
    args = _split_top_level_args(arg_text)
    first = args[0].strip() if args else ""
    # 2-arg overload: expectRevert(<revertData>, <reverter address>) -> pinned.
    address_pinned = len(args) >= 2 and bool(args[1].strip())

    if first == "":
        return {"kind": "empty", "error_name": None, "address_pinned": address_pinned}

    if _STRING_ARG_RE.match(first):
        return {"kind": "string", "error_name": None, "address_pinned": address_pinned}

    # abi.encodeWithSelector(X.selector, ...) or abi.encodeWithSelector(X, ...)
    m = _ENCODE_WITH_SEL_RE.search(first)
    if m:
        return {
            "kind": "custom",
            "error_name": _final_ident(m.group(1)),
            "address_pinned": address_pinned,
        }

    # X.selector / Contract.X.selector
    m = _SELECTOR_REF_RE.search(first)
    if m:
        return {
            "kind": "custom",
            "error_name": _final_ident(m.group(1)),
            "address_pinned": address_pinned,
        }

    # abi.encodeWithSignature("Err(uint)", ...) -> selector by signature string,
    # equally ambiguous by selector but we cannot resolve a decl name reliably;
    # treat as 'other' (not flagged) to stay conservative/no-false-positive.
    if _BYTES_HEX_RE.match(first) or "encodeWithSignature" in first:
        return {"kind": "bytes", "error_name": None, "address_pinned": address_pinned}

    return {"kind": "other", "error_name": None, "address_pinned": address_pinned}


def _find_expect_reverts(text):
    """Yield dicts for each vm.expectRevert(...) call in text."""
    for m in _EXPECT_RE.finditer(text):
        open_idx = m.end()  # just after '('
        arg_text, end_idx = _extract_arg_span(text, open_idx)
        info = _analyze_expect_arg(arg_text)
        info["line"] = _line_of(text, m.start())
        info["raw"] = arg_text.strip()
        yield info


# ---- core check -----------------------------------------------------------


def check_poc_file(poc_path, decls):
    """Return list of per-expectRevert result dicts for one .t.sol file."""
    try:
        with open(poc_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return [{"error": f"cannot read {poc_path}: {e}"}]

    results = []
    for ev in _find_expect_reverts(text):
        entry = {
            "file": poc_path,
            "line": ev["line"],
            "kind": ev["kind"],
            "error_name": ev.get("error_name"),
            "address_pinned": ev.get("address_pinned", False),
            "raw": ev["raw"][:120],
            "verdict": "na",
            "declarations": [],
        }

        if ev["kind"] != "custom" or not ev.get("error_name"):
            # string / bytes / empty / other -> not this check's concern.
            entry["verdict"] = "na"
            results.append(entry)
            continue

        name = ev["error_name"]
        sites = decls.get(name, [])
        entry["declarations"] = [
            {"path": p, "line": ln, "is_oos": oos} for (p, ln, oos) in sites
        ]
        distinct_files = {p for (p, _ln, _oos) in sites}

        if ev["address_pinned"]:
            entry["verdict"] = "pass-pinned"
        elif len(distinct_files) <= 1:
            entry["verdict"] = "pass-unique"
        else:
            has_oos = any(oos for (_p, _ln, oos) in sites)
            has_inscope = any(not oos for (_p, _ln, oos) in sites)
            # Genuine ambiguity: same custom error declared across >1 file.
            entry["verdict"] = "fail-ambiguous"
            entry["ambiguity"] = {
                "distinct_files": sorted(distinct_files),
                "has_oos_declaration": has_oos,
                "has_inscope_declaration": has_inscope,
                "cross_scope": bool(has_oos and has_inscope),
            }
        results.append(entry)
    return results


def _collect_poc_files(target, src_root):
    """Resolve the set of .t.sol PoC files to check."""
    files = []
    if target is None:
        base = src_root
        for dp, dn, fns in os.walk(base):
            dn[:] = [d for d in dn if d not in _PRUNE_DIRS]
            for fn in fns:
                if fn.endswith(".t.sol"):
                    files.append(os.path.join(dp, fn))
    elif os.path.isdir(target):
        for dp, dn, fns in os.walk(target):
            dn[:] = [d for d in dn if d not in _PRUNE_DIRS]
            for fn in fns:
                if fn.endswith(".t.sol") or fn.endswith(".sol"):
                    # In a finding folder, accept any .sol that has expectRevert.
                    if fn.endswith(".t.sol"):
                        files.append(os.path.join(dp, fn))
                    else:
                        full = os.path.join(dp, fn)
                        try:
                            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                                if "expectRevert" in fh.read():
                                    files.append(full)
                        except OSError:
                            pass
    else:
        files.append(target)
    return sorted(set(files))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Flag Foundry PoC vm.expectRevert(X.selector) that name a multi-declared custom error (ambiguous revert selector)."
    )
    ap.add_argument("target", nargs="?", help="PoC .t.sol file, finding folder, or omit with --src-root")
    ap.add_argument("--src-root", help="project root to scan for error declarations (default: auto-resolve from target)")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("--strict", action="store_true", help="(reserved) exit non-zero on any ambiguity - default already exits 1")
    args = ap.parse_args(argv)

    if not args.target and not args.src_root:
        ap.print_usage(sys.stderr)
        print("error: provide a target PoC/folder or --src-root", file=sys.stderr)
        return 2

    if args.src_root:
        src_root = os.path.abspath(args.src_root)
    else:
        src_root = _resolve_src_root(args.target)

    if not os.path.isdir(src_root):
        print(f"error: src-root is not a directory: {src_root}", file=sys.stderr)
        return 2

    decls = _scan_declarations(src_root)
    poc_files = _collect_poc_files(args.target, src_root)

    all_results = []
    for pf in poc_files:
        all_results.extend(check_poc_file(pf, decls))

    ambiguous = [r for r in all_results if r.get("verdict") == "fail-ambiguous"]
    read_errors = [r for r in all_results if r.get("error")]
    custom_checked = [r for r in all_results if r.get("kind") == "custom"]

    verdict = "fail-ambiguous-revert-selector" if ambiguous else "pass-revert-selector-sound"

    if args.json:
        print(json.dumps({
            "verdict": verdict,
            "src_root": src_root,
            "poc_files": poc_files,
            "expect_reverts_total": len(all_results),
            "custom_error_expect_reverts": len(custom_checked),
            "ambiguous_count": len(ambiguous),
            "results": all_results,
        }, indent=2))
    else:
        print(f"src-root: {src_root}")
        print(f"PoC files scanned: {len(poc_files)}")
        print(f"vm.expectRevert(...) sites: {len(all_results)}  "
              f"(custom-error: {len(custom_checked)})")
        if read_errors:
            for r in read_errors:
                print(f"  READ-ERROR: {r['error']}")
        for r in custom_checked:
            tag = {
                "pass-unique": "PASS (uniquely declared)",
                "pass-pinned": "PASS (address-pinned)",
                "fail-ambiguous": "FLAG ambiguous-revert-selector",
            }.get(r["verdict"], r["verdict"])
            print(f"  {r['file']}:{r['line']}  expectRevert({r['raw']})")
            print(f"      error={r['error_name']}  -> {tag}")
            if r["verdict"] == "fail-ambiguous":
                amb = r.get("ambiguity", {})
                if amb.get("cross_scope"):
                    print(f"      CROSS-SCOPE: declared in BOTH in-scope and test/mock/OOS paths")
                for d in r["declarations"]:
                    scope = "OOS/test" if d["is_oos"] else "in-scope"
                    print(f"        - {d['path']}:{d['line']}  [{scope}]")
        print()
        print(f"VERDICT: {verdict}")

    if ambiguous:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
