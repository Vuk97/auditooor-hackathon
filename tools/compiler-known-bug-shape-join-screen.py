#!/usr/bin/env python3
"""compiler-known-bug-shape-join-screen.py - GEN-EL1, the compiler-known-bug
SHAPE-JOIN reachability screen (enforcement-layer = compiler / codegen).

GENERAL LOGIC (impact-agnostic, NORTH-STAR; the compiler is a TRUSTED
enforcement - source semantics preserved in bytecode). A known solc/vyper
compiler bug is only a REAL finding when BOTH halves hold:
  (a) the workspace's pinned/declared compiler version falls in the bug's
      AFFECTED RANGE [introduced, fixed), AND
  (b) the bug's SOURCE-TRIGGER SHAPE is actually present in the source.
Version-affected WITHOUT the trigger shape is NOT a finding (the deployed
bytecode never exercises the miscompiled path); the shape present on a
NON-affected pin is NOT a finding (a fixed compiler emits correct bytecode).
Only the JOIN(version-affected, source-shape-present) is flagged.

WHY THIS IS DISTINCT FROM E2 (tools/compiler-feature-screen.py - dedup):
  E2 screens the (file, pinned_version, FEATURE-SUBSYSTEM) axis: it FLAGs when a
  file merely USES a feature (transient storage / udvt / abi codec) on an
  in-window pin. It does NOT check the per-bug SOURCE-SHAPE trigger, so it
  over-warns on version + coarse-feature alone (a lone `transient` var at 0.8.28
  FLAGs even though the specific miscompile needs the same-type clear shape).
  GEN-EL1 closes exactly that gap: it consumes the SAME curated bug windows /
  uids E2 already carries (KNOWN_BAD_WINDOWS in compiler-feature-screen), but
  additionally requires the concrete per-bug SOURCE SHAPE. So GEN-EL1 fires a
  STRICT SUBSET of E2's version-in-window population - the members that also
  carry the miscompile trigger. No overlap in verdict semantics: E2 = "feature
  used on a bad pin (advisory queue fuel)"; GEN-EL1 = "the specific miscompile
  trigger is present on a bad pin".

Encoded predicates (small, HIGH-CONFIDENCE, source-detectable; each requires
BOTH the affected-range AND its own trigger shape):
  * EL1-TSTORE-SAMETYPE  (solc SOL-2026-1 transient-storage clearing-helper
      collision; window [0.8.28, 0.8.34)):
      a `transient` state var of type T AND a NON-transient (persistent) state
      var of the SAME type T, both WRITTEN in one function body. The EIP-1153
      same-type clear/write shape the miscompiled clearing helper needs.
  * EL1-UDVT-SUB256  (solc SOL-2021-4 user-defined-value-types bug;
      window [0.8.8, 0.8.9)):
      a `type X is <underlying>` whose underlying is a SUB-256-bit type
      (uintN/intN with N<256, bool, address, bytesN with N<32) AND a
      `.wrap(` / `.unwrap(` on it - the dirty-higher-order-bits shape.
  * EL1-ABI-HEAD-OVERFLOW  (solc SOL-2022-6 abi re-encoding head overflow with
      static-array cleanup; window [0.5.8, 0.8.16)):
      a FIXED-SIZE array declaration `T[<N>]` AND an `abi.encode(` in the file -
      the static-array re-encoding head-overflow shape.
  * EL1-NESTED-CALLDATA-ARRAY  (solc SOL-2022-2 nested calldata array abi
      re-encoding size validation; window [0.5.8, 0.8.14)):
      a nested dynamic calldata array param `T[][] calldata` OR a single dynamic
      `T[] calldata` param combined with an `abi.encode(` re-encode in the file.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; the tool exits 0 by default. The opt-in env
AUDITOOOR_COMPILER_SHAPE_JOIN_STRICT (or --strict) raises the exit code when a
fired row exists.

Excludes machine-generated + test + vendored code via lib.synthetic_target_
exclusion; silent on other trees.

Usage:
  --workspace <ws>   scan <ws> (src/ preferred) -> .auditooor/
                     compiler_shape_join_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.compiler_shape_join_hypotheses.v1"
_SIDE_NAME = "compiler_shape_join_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_COMPILER_SHAPE_JOIN_STRICT"
_CAPABILITY = "GEN_EL1"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


# --- reuse E2 version + comment-strip helpers (never re-inline) -------------
def _load_e2():
    tool = TOOLS_DIR / "compiler-feature-screen.py"
    spec = importlib.util.spec_from_file_location("_e2_feature_screen", tool)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


try:
    _E2 = _load_e2()
    parse_ver = _E2.parse_ver
    pinned_solc = _E2.pinned_solc
    _strip_comments_and_strings = _E2._strip_comments_and_strings
except Exception:  # pragma: no cover - degrade with local fallbacks
    def parse_ver(v):  # type: ignore
        if not v:
            return None
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v.strip())
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None

    def pinned_solc(text):  # type: ignore
        for line in text.splitlines():
            m = re.search(r"pragma\s+solidity\s+([^;]+);", line)
            if m:
                sv = re.search(r"(\d+\.\d+\.\d+)", m.group(1))
                if sv:
                    return sv.group(1)
        return None

    def _strip_comments_and_strings(text):  # type: ignore
        return text


# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "simapp",
              "node", "testdata", "audits", "mocks", "mock", "fixtures",
              "flattened", "artifacts"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|examples|fixtures|simulation|"
    r"simapp|testdata|flattened)(/|$)")


# ============================================================================
# known-bug windows (REUSE the E2 curated uids/ranges - dedup, not rebuild)
# ============================================================================
# Each predicate carries its bug_id / uid (SAME as E2 KNOWN_BAD_WINDOWS where a
# 1:1 window exists) + affected [introduced, fixed) + a source-shape detector.
KNOWN_BUG_SHAPES = [
    {
        "bug_id": "SOL-2026-1",
        "uid": ("solc-compiler:sol-2026-1:"
                "transientstorageclearinghelpercollision:24a202785af6"),
        "shape_name": "transient+persistent same-type write in one function",
        "introduced": "0.8.28",
        "fixed": "0.8.34",
        "detector": "_shape_tstore_sametype",
        "why_shape": (
            "EIP-1153 transient storage clearing-helper collision: the "
            "miscompile only triggers when a transient state var and a "
            "persistent state var of the SAME type are cleared/written in one "
            "function - a lone transient var (E2's version+feature signal) does "
            "NOT exercise the miscompiled clearing helper."),
    },
    {
        "bug_id": "SOL-2021-4",
        "uid": "solc-compiler:sol-2021-4:userdefinedvaluetypesbug:4276fff67f9e",
        "shape_name": "UDVT over a sub-256-bit underlying type with wrap/unwrap",
        "introduced": "0.8.8",
        "fixed": "0.8.9",
        "detector": "_shape_udvt_sub256",
        "why_shape": (
            "UserDefinedValueTypesBug: the dirty-higher-order-bits miscompile "
            "only arises for a UDVT whose underlying type is narrower than 256 "
            "bits AND that is wrap()/unwrap()'d - a UDVT over uint256 (or one "
            "never wrapped) is not affected."),
    },
    {
        "bug_id": "SOL-2022-6",
        "uid": ("solc-compiler:sol-2022-6:"
                "abireencodingheadoverflowwithstaticarraycleanup:c96cde7b1de0"),
        "shape_name": "fixed-size array + abi.encode re-encode",
        "introduced": "0.5.8",
        "fixed": "0.8.16",
        "detector": "_shape_abi_head_overflow",
        "why_shape": (
            "ABIReencodingHeadOverflowWithStaticArrayCleanup: the head-overflow "
            "miscompile needs a FIXED-SIZE (static) array that is abi-encoded / "
            "re-encoded - a file that only uses abi.encode on scalars/dynamic "
            "arrays does not hit the static-array cleanup head overflow."),
    },
    {
        "bug_id": "SOL-2022-2",
        "uid": ("solc-compiler:sol-2022-2:"
                "nestedcalldataarrayabireencodingsizevalidation:68bf16017565"),
        "shape_name": "nested calldata dynamic array re-encoded",
        "introduced": "0.5.8",
        "fixed": "0.8.14",
        "detector": "_shape_nested_calldata_array",
        "why_shape": (
            "NestedCalldataArrayABIReencodingSizeValidation: the size-validation "
            "miscompile needs a nested dynamic calldata array (T[][] calldata) "
            "or a dynamic calldata array re-encoded via abi.encode - a plain "
            "value/memory param never reaches the faulty calldata size path."),
    },
]

# per-detector cheap file-level pre-gate (skip full parse when the coarse token
# is absent - the shape can never be present).
_SUB256_UNDERLYING = re.compile(
    r"^(?:uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|"
    r"152|160|168|176|184|192|200|208|216|224|232|240|248)?"
    r"|int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|"
    r"160|168|176|184|192|200|208|216|224|232|240|248)?"
    r"|bool|address|bytes(?:[1-9]|1[0-9]|2[0-9]|3[01]))$")


# ============================================================================
# lite state-var + function extraction (post comment/string strip)
# ============================================================================
def _brace_depth_lines(text):
    """Yield (line_idx, line, entry_depth) - the brace depth BEFORE the line."""
    depth = 0
    for idx, line in enumerate(text.split("\n")):
        yield idx, line, depth
        depth += line.count("{") - line.count("}")


# a contract-level state-var decl line: `<type> [visibility] [transient]
# [constant/immutable] <name> [= ...];`. We only need type + transient + name.
_STATE_VAR_RE = re.compile(
    r"^\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])*)"        # 1: type (w/ optional [..])
    r"((?:\s+(?:public|private|internal|external|constant|immutable|"
    r"transient|override))*)"                        # 2: modifiers blob
    r"\s+([A-Za-z_]\w*)\s*(?:=|;)")                 # 3: name
_TYPE_KEYWORDS_SKIP = {
    "function", "modifier", "constructor", "receive", "fallback", "event",
    "error", "struct", "enum", "mapping", "using", "import", "pragma",
    "contract", "interface", "library", "return", "returns", "if", "for",
    "while", "emit", "require", "assert", "revert", "else", "do", "try",
    "catch", "unchecked", "assembly", "new", "delete", "type",
}


def _state_vars(text):
    """Return list of dicts {name, type, transient, line} for depth==1 decls."""
    out = []
    for idx, line, depth in _brace_depth_lines(text):
        if depth != 1:
            continue
        m = _STATE_VAR_RE.match(line)
        if not m:
            continue
        typ = m.group(1).strip()
        base_type = re.split(r"\s*\[", typ, maxsplit=1)[0].strip()
        if base_type in _TYPE_KEYWORDS_SKIP:
            continue
        mods = m.group(2) or ""
        name = m.group(3)
        if name in _TYPE_KEYWORDS_SKIP:
            continue
        out.append({
            "name": name,
            "type": typ,
            "transient": bool(re.search(r"\btransient\b", mods)),
            "line": idx + 1,
        })
    return out


_FN_DECL_RE = re.compile(
    r"^\s*(?:function\s+([A-Za-z_]\w*)|(constructor|receive|fallback)\b)")


def _functions(text):
    """Yield (name, decl_line_idx, body_text) for each brace-matched function."""
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1) or m.group(2) or "<special>"
        depth = 0
        started = False
        body = []
        j = i
        while j < n:
            line = lines[j]
            depth += line.count("{") - line.count("}")
            body.append(line)
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        joined = "\n".join(body)
        brace = joined.find("{")
        yield name, i, (joined[brace + 1:] if brace >= 0 else joined)
        i = max(j, i + 1)


def _writes_var(body, var):
    """True if `var` is assigned in `body` (=, +=, -=, etc; not ==)."""
    return bool(re.search(
        r"\b" + re.escape(var) + r"\s*(?:=(?!=)|\+=|-=|\*=|/=|\|=|&=|\^=)",
        body))


# ============================================================================
# per-bug source-shape detectors
# ============================================================================
def _shape_tstore_sametype(text, rel):
    """EL1-TSTORE-SAMETYPE: transient var + persistent var of SAME type, both
    written in one function. Returns list of (line, function, excerpt)."""
    svs = _state_vars(text)
    transient = [v for v in svs if v["transient"]]
    persistent = [v for v in svs if not v["transient"]]
    if not transient or not persistent:
        return []
    # group by base type (ignore visibility/array suffix differences via full type)
    tt = {}
    for v in transient:
        tt.setdefault(v["type"], []).append(v)
    pp = {}
    for v in persistent:
        pp.setdefault(v["type"], []).append(v)
    common = set(tt) & set(pp)
    if not common:
        return []
    hits = []
    for name, decl_idx, body in _functions(text):
        for typ in common:
            tvar = next((v for v in tt[typ] if _writes_var(body, v["name"])),
                        None)
            pvar = next((v for v in pp[typ] if _writes_var(body, v["name"])),
                        None)
            if tvar and pvar:
                exc = (f"fn {name}: writes transient `{tvar['name']}` and "
                       f"persistent `{pvar['name']}` (both {typ})")
                hits.append((decl_idx + 1, name, exc[:180]))
                break
    return hits


def _shape_udvt_sub256(text, rel):
    """EL1-UDVT-SUB256: `type X is <sub256>` + a wrap/unwrap on it."""
    hits = []
    for m in re.finditer(r"\btype\s+([A-Za-z_]\w*)\s+is\s+([A-Za-z_]\w*\d*)",
                         text):
        udvt, underlying = m.group(1), m.group(2)
        if not _SUB256_UNDERLYING.match(underlying):
            continue
        # a wrap/unwrap keyed to this UDVT (X.wrap( / X.unwrap( / .wrap( )
        if re.search(r"\b" + re.escape(udvt) + r"\s*\.\s*(?:un)?wrap\s*\(",
                     text) or re.search(r"\.\s*(?:un)?wrap\s*\(", text):
            line = text.count("\n", 0, m.start()) + 1
            exc = (f"UDVT `{udvt}` over sub-256 `{underlying}` with wrap/unwrap")
            hits.append((line, "<file>", exc[:180]))
    return hits


# a fixed-size array TYPE position: `T[<N>]` immediately followed by a data
# location / visibility keyword or a variable-name identifier (the declaration
# context). This EXCLUDES an index ACCESS like `ret[0] = ...` (after `]` comes
# `=`, not a keyword/identifier), which is not a static-array type and was a
# measured FP on lido/deposit_contract.sol (`ret[0]` byte-swap indexing).
_FIXED_ARRAY_RE = re.compile(
    r"\b[A-Za-z_]\w*\s*\[\s*\d+\s*\]\s+"
    r"(?:memory|storage|calldata|public|private|internal|constant|immutable"
    r"|[A-Za-z_]\w*\s*[;,=)])")


def _shape_abi_head_overflow(text, rel):
    """EL1-ABI-HEAD-OVERFLOW: fixed-size array decl + abi.encode in file."""
    fa = _FIXED_ARRAY_RE.search(text)
    if not fa:
        return []
    ae = re.search(r"\babi\.encode(?:Packed|WithSelector|WithSignature)?\s*\(",
                   text)
    if not ae:
        return []
    line = text.count("\n", 0, fa.start()) + 1
    exc = (f"fixed-size array `{fa.group(0).strip()}` + "
           f"`{ae.group(0).strip()}` re-encode in file")
    return [(line, "<file>", exc[:180])]


def _shape_nested_calldata_array(text, rel):
    """EL1-NESTED-CALLDATA-ARRAY: nested calldata dyn array param, OR a single
    dynamic calldata array param combined with an abi.encode re-encode."""
    # nested dynamic calldata array `T[][] calldata`
    nested = re.search(
        r"\b[A-Za-z_]\w*\s*\[\s*\]\s*\[\s*\]\s+calldata\b", text)
    if nested:
        line = text.count("\n", 0, nested.start()) + 1
        return [(line, "<file>",
                 f"nested calldata array `{nested.group(0).strip()}`"[:180])]
    single = re.search(r"\b[A-Za-z_]\w*\s*\[\s*\]\s+calldata\b", text)
    if single and re.search(r"\babi\.encode(?:Packed)?\s*\(", text):
        line = text.count("\n", 0, single.start()) + 1
        return [(line, "<file>",
                 (f"dynamic calldata array `{single.group(0).strip()}` + "
                  f"abi.encode re-encode")[:180])]
    return []


_DETECTORS = {
    "_shape_tstore_sametype": _shape_tstore_sametype,
    "_shape_udvt_sub256": _shape_udvt_sub256,
    "_shape_abi_head_overflow": _shape_abi_head_overflow,
    "_shape_nested_calldata_array": _shape_nested_calldata_array,
}


# ============================================================================
# row + scan
# ============================================================================
def _stable_id(rel, bug_id, fn, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{bug_id}|{fn}|{line}".encode())
    return h.hexdigest()[:16]


def _in_range(pv, introduced, fixed):
    iv, fv = parse_ver(introduced), parse_ver(fixed)
    if pv is None or iv is None or fv is None:
        return False
    return iv <= pv < fv


def scan_file(path, rel, file_text=None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    if not (rel.lower().endswith(".sol")):
        return []
    version = pinned_solc(raw)
    pv = parse_ver(version) if version else None
    text = _strip_comments_and_strings(raw)
    rows = []
    for bug in KNOWN_BUG_SHAPES:
        # (a) version half - MUST be in the affected range (load-bearing).
        if not _in_range(pv, bug["introduced"], bug["fixed"]):
            continue
        # (b) shape half - MUST find the concrete source trigger.
        det = _DETECTORS[bug["detector"]]
        for line, fn, excerpt in det(text, rel):
            rng = f"[{bug['introduced']}, {bug['fixed']})"
            rows.append({
                "schema": HYP_SCHEMA,
                "capability": _CAPABILITY,
                "id": _stable_id(rel, bug["bug_id"], fn, line),
                "file": rel,
                "line": line,
                "function": fn,
                "bug_id": bug["bug_id"],
                "matched_advisory_uid": bug["uid"],
                "affected_range": rng,
                "pinned_version": version,
                "source_shape": bug["shape_name"],
                "why_version_and_shape_both_present": (
                    f"pinned {version} in affected range {rng} AND source shape "
                    f"present: {excerpt}"),
                "excerpt": excerpt,
                "why_severity_anchored": bug["why_shape"],
                "fires": True,
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
            })
    return rows


def _iter_source_files(root, workspace=None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".sol"):
                continue
            if low.endswith(".t.sol") or ".t.sol" in low:
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            yield p


def scan_tree(root, workspace=None):
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


def _emit_sidecar(ws, rows):
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
        "candidates": len(rows),
        "fired": len(fired),
        "by_bug_id": _count(rows, "bug_id"),
        "by_pinned_version": _count(rows, "pinned_version"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-EL1 compiler-known-bug shape-JOIN reachability screen "
                    "(Solidity; advisory; JOIN of version-affected x source-"
                    "shape-present)")
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
        return 1 if (strict and rows) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and rows) else 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", "/Users/wolf/auditooor-worktrees"):
            cand = Path(base) / args.workspace
            if cand.exists():
                ws = cand
                break
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
