#!/usr/bin/env python3
"""selector-dispatch-collision-screen.py - GEN-EL2, the ABI SELECTOR / DISPATCH
COLLISION SOUNDNESS screen (enforcement-layer = compiler-dispatch).
Solidity-primary (Diamond/facet map, proxy fallback clash, assembly switch,
bytes4->address router). Vyper (raw_call method-id forward) + Move (dispatch /
entry-function table) secondary/synthetic.

GENERAL LOGIC (impact-agnostic trust-boundary class, never a numeric-hash SHAPE).
The Solidity compiler rejects two functions with the SAME 4-byte selector WITHIN
one contract - but NOT across a dispatch BOUNDARY where selectors are routed
MANUALLY. When a selector->function/target dispatch STRUCTURE exists:

  * an EIP-2535 Diamond facet selector map (selectorToFacet[sel] = facet), OR
  * a transparent/UUPS proxy fallback() that delegatecalls the impl for ANY
    selector while ALSO exposing admin fns at the proxy level (the admin and
    impl selector SPACES overlap), OR
  * a manual assembly `switch shr(224, calldataload(0))` dispatch table, OR
  * a router that maps bytes4 -> address,

then TWO different signatures that hash to the SAME 4-byte selector (or a plain
re-registration of an already-mapped selector) can route a benign or attacker
crafted call into a PRIVILEGED function, or SHADOW a privileged fn with a benign
one (last-wins). The bug is the UNGUARDED DISPATCH STRUCTURE.

SAFE forms (bias to SILENCE when present):
  (a) an add-collision reject before registration - a var read from the selector
      map compared `== address(0)` in a require/revert
      (`require(oldFacetAddress == address(0), "add: exists")`), OR a direct
      `require(map[sel] == address(0))`;
  (b) admin/impl selector-space SEPARATION - a proxy fallback gated by an
      `ifAdmin` / `onlyAdmin`-style router so admin and impl spaces are disjoint;
  (c) a duplicate-case rejection in the assembly switch (revert-on-default that
      does NOT route to a privileged target).

FP-CONTROL (load-bearing): brute-forcing keccak4 collisions across arbitrary fns
is near-zero-probability NOISE - this screen NEVER emits a numeric-hash
coincidence. It flags the STRUCTURE that would silently ACCEPT a colliding /
duplicate selector: a selector->target map WRITE that can overwrite with no
collision-reject; an admin+impl selector space not separated; an assembly switch
whose default routes to a privileged path. Remove/replace/delete contexts and
guarded adds are suppressed.

DEDUP / distinctness (per dispatch brief):
  * vault_function_signature_shape keys on fn NAME / ARG-shape, not the 4-byte
    selector-hash + dispatch ROUTING - a different index.
  * override-dropped-guard-dispatch (W1) checks a guard DROPPED on an override,
    not a selector COLLISION in a dispatch map.
  * tools/journal-collision-scanner.py checks abi.encodePacked ambiguity, not
    4-byte selector dispatch.
  GEN-EL2 = the selector-dispatch-map-WITHOUT-collision-rejection JOIN; if a
  site reduces to one of the above it is dropped as overlap.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; the tool exits 0 by default. The opt-in env
AUDITOOOR_SELECTOR_DISPATCH_COLLISION_STRICT (or --strict) raises the exit code
when a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, mock, sim
and vendored code via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     selector_dispatch_collision_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.vy/.move file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.selector_dispatch_collision_hypotheses.v1"
_SIDE_NAME = "selector_dispatch_collision_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_SELECTOR_DISPATCH_COLLISION_STRICT"
_CAPABILITY = "GEN_EL2"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "testdata",
              "mocks", "mock"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata|poc)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


# ============================================================================
# comment / string masking (Solidity + Vyper + Move share C-ish comments; Vyper
# uses '#' line comments and Move uses '//'  '/* */').
# ============================================================================
def _mask_comments(text: str, lang: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
    hash_line = lang == "vyper"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif hash_line and c == "#":
            in_line = True
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


def _stable_id(rel, kind, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{kind}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".vy"):
        return "vyper"
    if low.endswith(".move"):
        return "move"
    return "solidity"


# ============================================================================
# function-body slicing (brace languages: Solidity / Move). We use it to bound
# guard-context per function; the map-guard suppressor is FILE-scoped.
# ============================================================================
_FN_DECL_RE = re.compile(
    r"^\s*(?:function\s+([A-Za-z_]\w*)"      # Solidity/Move function foo
    r"|(fallback)\s*\("                       # Solidity fallback()
    r"|(receive)\s*\()")                      # Solidity receive()


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3)


def _iter_functions(text: str):
    """Yield (name, start_off, body_text) for brace-delimited functions."""
    lines = text.split("\n")
    line_off = []
    acc = 0
    for ln in lines:
        line_off.append(acc)
        acc += len(ln) + 1
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        j = i
        while j < n:
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        body = "\n".join(lines[i:j + 1])
        yield name, line_off[i], body
        i = max(j + 1, i + 1)


# ============================================================================
# SOLIDITY: selector-keyed dispatch maps
# ============================================================================
# mapping(bytes4 => X)  (top-level or struct field). Capture the map NAME.
_MAP_DECL_RE = re.compile(
    r"\bmapping\s*\(\s*bytes4\s*=>\s*[^;]*?\)\s*(?:public\s+|internal\s+|"
    r"private\s+|external\s+)?([A-Za-z_]\w*)")
# well-known EIP-2535 field names even when the mapping is inside a struct value
_KNOWN_SELECTOR_MAP = re.compile(
    r"\b(selectorToFacet\w*|facetAddressAndSelectorPosition|selectorTo\w*|"
    r"selectorsToFacets?|facets?BySelector|handlerOf|methodToImpl\w*)\b")

# a WRITE to a selector map: <chain>.<map>[<key>] ... =   (not ==, not delete)
# We anchor on the map name then a '[' ... ']' then a following '='.
def _map_write_sites(body: str, map_names):
    """Yield (map_name, key_text, off) for  <...><map>[<key>]... = <rhs>."""
    for mn in map_names:
        for m in re.finditer(
                rf"\b{re.escape(mn)}\s*\[\s*([^\]]+?)\s*\]", body):
            # look ahead for an assignment `=` that is not `==`, `!=`, `<=`, `>=`
            tail = body[m.end():m.end() + 60]
            am = re.match(r"\s*(?:\.\s*\w+\s*)*=(?!=)", tail)
            if am:
                yield mn, m.group(1).strip(), m.start()


# collision-reject guard (safe form a), FILE-scoped:
#  1) a var read from a selector map, then `require(<var> == address(0)`
#  2) a direct  require(<map>[sel]... == address(0)
_VAR_FROM_MAP_RE = None  # built per file with the map-name alternation


def _has_add_collision_guard(text: str, map_names) -> bool:
    if not map_names:
        return False
    alt = "|".join(re.escape(m) for m in map_names)
    # direct: require(...<map>[..]... == address(0)  (or `!= address(0)) revert`)
    if re.search(
            rf"require\s*\([^;]*?(?:{alt})\s*\[[^;]*?==\s*address\s*\(\s*0",
            text):
        return True
    # indirect: a var assigned from a selector-map read, then required ==address(0)
    for vm in re.finditer(
            rf"\b([A-Za-z_]\w*)\s*=\s*[^;]*?(?:{alt})\s*\[[^;]*?\]"
            rf"(?:\s*\.\s*\w+)*\s*;", text):
        var = vm.group(1)
        if re.search(
                rf"require\s*\(\s*{re.escape(var)}\s*==\s*address\s*\(\s*0",
                text):
            return True
        if re.search(
                rf"if\s*\(\s*{re.escape(var)}\s*!=\s*address\s*\(\s*0\s*\)\s*\)"
                rf"[^;{{]*\brevert\b", text):
            return True
    return False


# a write whose enclosing function is a legitimate overwrite (replace/remove) or
# a delete is NOT an add-collision - suppress.
_OVERWRITE_CTX = re.compile(
    r"(?i)(replace|remove|delet|uninstall|deregister|unregister|reset|"
    r"clear|swap|prune)")


def _enclosing_fn_name(text: str, off: int) -> str:
    best = "<file>"
    for name, start, body in _iter_functions(text):
        if start <= off <= start + len(body):
            best = name
    return best


def _classify_map_kind(map_name: str) -> str:
    if re.search(r"(?i)facet|diamond", map_name):
        return "diamond-facet-map"
    return "router-map"


# ============================================================================
# SOLIDITY: proxy fallback / admin-impl clash
# ============================================================================
_FALLBACK_DELEGATE_RE = re.compile(
    r"\bfallback\s*\(\s*\)[^{]*\{", re.S)
_DELEGATECALL_RE = re.compile(r"\bdelegatecall\s*\(")
_IFADMIN_RE = re.compile(
    r"(?i)\b(ifAdmin|onlyAdmin|onlyProxyAdmin|_fallback|ERC1967|"
    r"onlyOwner)\b|_delegate\s*\(")
# an admin-ish external/public fn declared in the proxy contract that clashes
_ADMIN_FN_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:external|public)\b"
    r"(?![^{;]*\bview\b)(?![^{;]*\bpure\b)")


def _scan_proxy_clash(text: str, rel: str, rows):
    fbm = _FALLBACK_DELEGATE_RE.search(text)
    if not fbm:
        return
    # fallback must actually delegatecall (proxy), else it's an ordinary receiver
    fb_body_end = text.find("}", fbm.end())
    window = text[fbm.start():fb_body_end if fb_body_end > 0 else fbm.end() + 400]
    delegates = bool(_DELEGATECALL_RE.search(window)) or \
        bool(re.search(r"_delegate\s*\(", window))
    if not delegates:
        return
    # transparent-proxy separation present? (ifAdmin router / OZ pattern)
    if _IFADMIN_RE.search(text):
        return
    # admin fns declared alongside the fallback that share the impl selector space
    admin_fns = [(m.group(1), m.start()) for m in _ADMIN_FN_RE.finditer(text)
                 if m.group(1) not in ("fallback", "receive")]
    if not admin_fns:
        return  # a minimal proxy with only fallback - no clash surface
    name, off = admin_fns[0]
    line = _line_of_offset(text, off)
    rows.append(_mk_row(
        rel, name, line, "solidity", "proxy-fallback-clash",
        "no-admin-impl-separation", _excerpt(text, off),
        subject=name,
        extra=("a proxy fallback() delegatecalls the impl for ANY selector "
               "while this contract ALSO exposes admin/public fn `%s` at the "
               "proxy level with NO ifAdmin-style admin/impl selector-space "
               "separation - an impl fn whose 4-byte selector equals an admin "
               "selector is shadowed / made unreachable (transparent-proxy "
               "selector clash)." % name)))


# ============================================================================
# SOLIDITY / generic: assembly selector switch
# ============================================================================
_ASM_SWITCH_SEL_RE = re.compile(
    r"switch\s+([A-Za-z_]\w*|shr\s*\(\s*224[^)]*\)|and\s*\([^)]*\)|"
    r"calldataload\s*\(\s*0\s*\))", re.I)
_SEL_DERIVE_RE = re.compile(
    r"(?i)shr\s*\(\s*224|calldataload\s*\(\s*0\s*\)|and\s*\([^)]*0xffffffff")


def _balanced_body(text: str, open_idx: int) -> str:
    """Return the substring inside the { } starting at text[open_idx] == '{',
    brace-balanced (handles nested blocks)."""
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


def _scan_assembly_switch(text: str, rel: str, rows):
    for asm in re.finditer(r"\bassembly\s*(?:\(\s*\"[^\"]*\"\s*\))?\s*\{", text):
        # bound the assembly block
        depth = 0
        i = asm.end() - 1
        n = len(text)
        while i < n:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        block = text[asm.start():i + 1]
        sw = _ASM_SWITCH_SEL_RE.search(block)
        if not sw:
            continue
        # confirm the switch subject is a 4-byte selector (directly or via a
        # var derived from calldata shr-224)
        subj = sw.group(1)
        selectorish = bool(_SEL_DERIVE_RE.search(sw.group(0))) or \
            bool(re.search(
                rf"\b{re.escape(subj)}\s*:=[^\n]*(?:shr\s*\(\s*224|"
                rf"calldataload\s*\(\s*0)", block))
        if not selectorish:
            continue
        # SAFE: a `default { revert(...) }` that does NOT route to a call/
        # delegatecall (a duplicate/unknown-selector rejection). Extract the
        # default body brace-balanced (it may nest `if ... { revert }`).
        dm = re.search(r"default\s*\{", block)
        default_privileged = False
        if dm:
            dbody = _balanced_body(block, dm.end() - 1)
            if re.search(r"\b(delegatecall|call|callcode|staticcall)\s*\(",
                         dbody):
                default_privileged = True
        else:
            # no default at all + a selector switch that also delegatecalls =>
            # unhandled selectors fall through with no duplicate/unknown reject
            default_privileged = bool(re.search(
                r"\b(delegatecall|callcode)\s*\(", block)) and \
                not re.search(r"default\s*\{", block)
        if not default_privileged:
            continue
        off = asm.start()
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, "<assembly>", line, _lang_of(rel), "assembly-switch",
            "no-duplicate-case-check", _excerpt(text, off), subject="switch",
            extra=("a manual assembly `switch` dispatches on the 4-byte "
                   "selector and its default branch routes to a privileged "
                   "delegate/call with NO duplicate/unknown-selector rejection "
                   "- a colliding or unknown selector is silently routed into "
                   "the privileged path.")))


# ============================================================================
# VYPER (secondary): a HashMap[bytes4, address] router written with no dedup, or
# a raw_call selector forward keyed on a mutable route map.
# ============================================================================
_VY_MAP_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*:\s*(?:public\s*\(\s*)?HashMap\s*\[\s*bytes4\s*,")


def _scan_vyper(text: str, rel: str, rows):
    map_names = set(_VY_MAP_DECL_RE.findall(text))
    if not map_names:
        return
    guarded = any(
        re.search(rf"assert\s+self\.{re.escape(mn)}\s*\[[^\n]*==\s*empty\s*\(",
                  text) or
        re.search(rf"assert\s+self\.{re.escape(mn)}\s*\[[^\n]*==\s*ZERO_ADDRESS",
                  text)
        for mn in map_names)
    if guarded:
        return
    for mn in map_names:
        wm = re.search(rf"self\.{re.escape(mn)}\s*\[[^\]]+\]\s*=(?!=)", text)
        if not wm:
            continue
        off = wm.start()
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, "<vyper>", line, "vyper", "router-map",
            "no-add-collision-require", _excerpt(text, off), subject=mn,
            extra=("a Vyper bytes4->address route map `%s` is written with NO "
                   "empty()/ZERO_ADDRESS collision-reject assert before the "
                   "assignment - a re-registered selector last-wins and can "
                   "shadow a privileged route." % mn)))
        break


# ============================================================================
# MOVE (secondary/synthetic): a dispatch/entry table add with no exists check.
# ============================================================================
def _scan_move(text: str, rel: str, rows):
    # table::add / smart_table::add on a <selector>-keyed dispatch table without a
    # preceding contains/exists assertion.
    for m in re.finditer(
            r"\b(?:table|smart_table|simple_map)::add\s*\(\s*&?mut\s+"
            r"([A-Za-z_][\w.]*(?:dispatch|handler|route|selector|entry)"
            r"[\w.]*)",
            text, re.I):
        tbl = m.group(1)
        if re.search(
                rf"(?:contains|exists)\s*\(\s*&?{re.escape(tbl)}", text):
            continue
        off = m.start()
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, "<move>", line, "move", "router-map",
            "no-add-collision-require", _excerpt(text, off), subject=tbl,
            extra=("a Move dispatch/entry table add on `%s` with NO "
                   "contains/exists check - a duplicate dispatch key silently "
                   "overwrites the routed target (last-wins)." % tbl)))


# ============================================================================
# row builder
# ============================================================================
def _mk_row(rel, fn, line, lang, dispatch_kind, missing_guard, excerpt,
            subject, extra=""):
    why = (
        f"selector-dispatch collision soundness: a {dispatch_kind} routes "
        f"selectors WITHOUT a collision-rejection guard ({missing_guard}). "
        f"{extra} The compiler only rejects same-selector fns WITHIN one "
        f"contract, never across this manual dispatch boundary - so a duplicate "
        f"/ colliding 4-byte selector routes a benign or attacker-crafted call "
        f"into a privileged target (or shadows a privileged fn last-wins). This "
        f"is the UNGUARDED DISPATCH STRUCTURE, not a numeric-hash coincidence.")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, dispatch_kind, subject, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "dispatch_kind": dispatch_kind,
        "missing_guard": missing_guard,
        "subject": subject,
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# per-file scan
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    lang = _lang_of(rel)
    text = _mask_comments(raw, lang)
    rows = []
    if lang == "solidity":
        _scan_solidity(text, rel, rows)
    elif lang == "vyper":
        _scan_vyper(text, rel, rows)
    elif lang == "move":
        _scan_move(text, rel, rows)
        _scan_assembly_switch(text, rel, rows)  # move inline-bytecode is rare
    return rows


def _scan_solidity(text: str, rel: str, rows):
    # --- selector-keyed dispatch maps (diamond-facet / router) --------------
    map_names = set(_MAP_DECL_RE.findall(text))
    map_names |= set(_KNOWN_SELECTOR_MAP.findall(text))
    map_names = {m for m in map_names if m}
    if map_names:
        guarded = _has_add_collision_guard(text, map_names)
        if not guarded:
            seen = set()
            for mn, key, off in _map_write_sites(text, map_names):
                fn = _enclosing_fn_name(text, off)
                if _OVERWRITE_CTX.search(fn):
                    continue
                # a `delete map[..]` is a removal, never an add-collision
                pre = text[max(0, off - 12):off]
                if re.search(r"delete\s*$", pre):
                    continue
                kind = _classify_map_kind(mn)
                dkey = (mn, fn, kind)
                if dkey in seen:
                    continue
                seen.add(dkey)
                line = _line_of_offset(text, off)
                rows.append(_mk_row(
                    rel, fn, line, "solidity", kind,
                    "no-add-collision-require", _excerpt(text, off),
                    subject=mn,
                    extra=("the selector->target map `%s` is written in "
                           "add/register context `%s` with NO "
                           "`require(map[sel] == address(0))` collision reject "
                           "- re-registering an existing (or colliding) "
                           "selector last-wins and shadows the prior target."
                           % (mn, fn))))
    # --- proxy fallback / admin-impl clash ----------------------------------
    _scan_proxy_clash(text, rel, rows)
    # --- assembly selector switch -------------------------------------------
    _scan_assembly_switch(text, rel, rows)


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".vy")
                    or low.endswith(".move")):
                continue
            if low.endswith(".t.sol") or low.endswith(".s.sol"):
                continue
            if _TEST_HINT.search(f) or low.startswith("mock") \
                    or low.startswith("test"):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4096]
                if _CODEGEN_SENTINEL.search(head):
                    continue
            except OSError:
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "dispatch_sites": len(rows),
        "fired": len(fired),
        "by_dispatch_kind": _count(rows, "dispatch_kind"),
        "by_missing_guard": _count(rows, "missing_guard"),
        "by_lang": _count(rows, "lang"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL2 ABI selector/dispatch collision soundness screen "
                    "(Solidity + Vyper + Move, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root, workspace=ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
