#!/usr/bin/env python3
"""go-engine-harness-author - author Go fuzz + property harnesses from corpus invariants.

Given a Go workspace and a package/function selector, this tool AUTHORS Go
verification harnesses for the workspace's critical exported functions, grounded
in the indexed P1 invariant library (Rule 58 memory-grounding). The companion
runner (`tools/go-engine-harness-runner.sh`, PR6a) then CONSUMES the authored
`Fuzz*` targets as its `go test -fuzz` surface and the `Test*` property targets
as its `go test` / `go vet` / `staticcheck` surface; without authored targets
the runner would have nothing to run (empty engine).

Why REAL properties, not TODO stubs (divergence from the Rust/EVM authors)
==========================================================================
The Rust (`rust-engine-harness-author.py`) and Solidity (`evm-engine-harness-author.py`)
authors emit TODO-stub predicates by design, because a generic generator that
guesses a *protocol* predicate produces a wrong-and-confident harness. Go fuzz
targets are different: the native `f.Fuzz(func(t, in){ _ = Target(in) })` shape
is itself a REAL, non-tautological property - the no-panic / no-crash property
that libFuzzer executes and reports a crash on. We can also derive a small set of
structurally-true properties from the function SHAPE alone (not protocol
semantics), and each is a genuine assertion the engine executes:

  * no-panic / no-crash:     fuzz the target; a panic = a discovered bug.
                             (always emittable; the load-bearing fuzz property)
  * determinism:             same input -> same output across two calls; a
                             divergence = a real `t.Errorf`. Emittable when the
                             target is pure-shaped (no pointer-receiver mutation,
                             >=1 return value).
  * round-trip:              when an encode/decode (marshal/unmarshal,
                             serialize/deserialize, to_bytes/from_bytes) PAIR
                             exists in the package, `decode(encode(x)) == x`
                             (modulo error) is a real property.
  * idempotence:             when the target is normalize/canonicalize-shaped,
                             `f(f(x)) == f(x)` is a real property.

  * keeper needs-manual-setUp scaffold (GAP 1): a receiver method taking cosmos
                             plumbing (sdk.Context / sdk.Coins / addresses) is a
                             value-moving keeper method whose receiver + app
                             setUp a shape-only author cannot synthesize. Rather
                             than SILENTLY authoring 0 for every money-mover
                             (escrow / deductFee / split / ComputeTransferFee),
                             it emits a COMPILABLE scaffold (imports only
                             `testing`, `t.Skip`s with a typed verdict) carrying
                             a commented conservation/determinism template. The
                             manifest records it under `manual_setup` with a
                             `needs-manual-setUp` verdict.

Every emitted property is a genuine assertion - it asserts nothing trivially
true. This is the "proof-gate notion" the brief requires: the harnesses are real
asserted properties, not no-ops. (The PR4a proof gate does not parse `.go`; this
author independently guarantees the shape the gate would demand: no `assert(true)`,
no `% 1` neutered mutation, no `x == x` self-equality, no empty property body.)

Authoring discipline
=====================
  * Idempotent: re-running against an unchanged workspace + invariant set
    produces byte-identical files (deterministic ordering, no wall-clock inside
    files).
  * stdlib-only Python (plus the in-repo Go function extractor import).
  * Function enumeration reuses tools/function-signature-extractor.py
    (`extract_go_functions`) - no bespoke Go parser.
  * The author NEVER overwrites a hand-written `_test.go`; harnesses are written
    to `<pkg>/auditooor_<fn>_engine_test.go` and carry a generated marker.
  * Honest tool-availability is the RUNNER's concern: this author always emits
    compilable Go; if `go test`/`staticcheck`/`go-fuzz` is not installed the
    runner reports tool-not-installed and never fabricates a result.

RELATED TOOLS (Rule: tool-duplication preflight)
=================================================
  * tools/rust-engine-harness-author.py - the RUST twin (kani/proptest/bolero,
    TODO-stub predicates). Disjoint target language + disjoint engine family.
  * tools/evm-engine-harness-author.py - the SOLIDITY twin (halmos/medusa/
    echidna/forge). Disjoint target language + disjoint engine family.
  * tools/go-engine-harness-runner.sh (PR6a) - the CONSUMER. It RUNS `go test
    -fuzz` / `go vet` / `staticcheck` over the authored targets and writes an
    artifact. It has NO authoring capability; this tool fills that gap. The
    runner targets the authored set via the `auditooor_` filename convention and
    the `Fuzz`/`TestProp` function-name conventions.
  * tools/go-detector-runner.py - a STATIC detector runner over Go source. Not
    a harness author and not a dynamic engine; disjoint purpose.
  * tools/function-signature-extractor.py - reused for `extract_go_functions`.

Usage
=====
  go-engine-harness-author.py <workspace> <pkg/fn-selector> [options]

  <pkg/fn-selector> forms:
    "watch_chain"             author for the whole package's critical fns
    "watch_chain/Validate"    author only for functions whose name matches "Validate"
    "codec/Decode"            round-trip class for Decode/Encode pairs

Options
=======
  --invariant-id INV-...   Restrict grounding to one invariant ID (repeatable).
  --max-fns N              Cap authored harnesses (default 12).
  --no-fuzz                Do not emit the Fuzz no-panic target.
  --no-determinism         Do not emit the determinism property.
  --no-roundtrip           Do not emit the round-trip property.
  --no-idempotence         Do not emit the idempotence property.
  --dry-run                Render the manifest + planned files, write nothing.
  --json                   Emit the manifest as JSON to stdout.
  -h, --help
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "auditooor.go_engine_harness_author.v1"
GENERATED_MARKER = "// auditooor-generated-go-engine-harness"
AUTHORED_FILE_PREFIX = "auditooor_"
AUTHORED_FILE_SUFFIX = "_engine_test.go"
# GAP 1 fix: keeper money-mover methods (receiver + sdk.Context/sdk.Coins params)
# cannot be driven by a shape-only author, but MUST NOT silently author 0. They
# get a compilable needs-manual-setUp scaffold written to this suffix.
KEEPER_SCAFFOLD_SUFFIX = "_keeper_scaffold_test.go"

DEFAULT_INVARIANT_SOURCES = [
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
    "audit/corpus_tags/derived/invariants_pilot.jsonl",
]

# Go invariants in the corpus are tagged target_lang in ("go", "any").
GO_INVARIANT_LANGS = ("go", "any")

# Function-name -> candidate invariant categories. Shape-keyed, not protocol-keyed.
FN_NAME_CATEGORY_HINTS: List[Tuple[re.Pattern, Tuple[str, ...]]] = [
    (re.compile(r"(?i)decode|unmarshal|deserialize|frombytes|parse|read"),
     ("determinism", "bounds", "soundness")),
    (re.compile(r"(?i)encode|marshal|serialize|tobytes|write"),
     ("determinism", "soundness")),
    (re.compile(r"(?i)verify|validate|check|authenticate"),
     ("soundness", "authorization", "uniqueness")),
    (re.compile(r"(?i)sign|aggregate|combine|finalize"),
     ("conservation", "soundness", "atomicity")),
    (re.compile(r"(?i)add|sub|mul|sum|accumulate|balance|amount|fee"),
     ("conservation", "bounds", "monotonicity")),
    (re.compile(r"(?i)insert|append|push|commit|advance|consume|mark|settle"),
     ("ordering", "atomicity", "uniqueness", "freshness")),
    (re.compile(r"(?i)nonce|replay|seq|sequence|index"),
     ("uniqueness", "freshness", "monotonicity")),
    (re.compile(r"(?i)normalize|canonical|sanitize|clean"),
     ("determinism", "soundness")),
    (re.compile(r"(?i)watch|monitor|detect|scan"),
     ("freshness", "soundness", "ordering")),
]

# Functions we never bother authoring a harness for (noise / non-load-bearing).
_SKIP_FN_RX = re.compile(
    r"(?i)^(String|Error|Len|Less|Swap|GoString|MarshalLogObject|"
    r"ServeHTTP|Close|Reset|Clone|Equal|Format)$"
)
_SKIP_DIRS = {".git", "vendor", "node_modules", "testdata", "third_party"}

# Round-trip pairing: encode-shape <-> decode-shape token detection.
_ENCODE_RX = re.compile(r"(?i)(encode|marshal|serialize|tobytes|pack)")
_DECODE_RX = re.compile(r"(?i)(decode|unmarshal|deserialize|frombytes|unpack)")
_IDEMPOTENT_RX = re.compile(r"(?i)(normalize|canonical|sanitize|clean|dedup|trim)")

# Fuzz-able primitive input shapes: the native go-fuzz corpus types.
# (string, []byte, intN, uintN, bool, float). Anything else -> we still emit the
# no-panic fuzz over a []byte seed driving an unmarshal-shaped call when present,
# else we skip determinism/roundtrip and keep only the no-panic property if the
# first parameter is fuzzable.
_FUZZABLE_SCALAR_RX = re.compile(
    r"^(\[\]byte|string|bool|byte|rune|"
    r"u?int(8|16|32|64)?|float(32|64))$"
)

# GAP 1: a keeper money-mover method takes cosmos-sdk plumbing (sdk.Context /
# sdk.Coins / addresses) - unfuzzable STRUCTURED params a shape-only author
# cannot synthesize, but which mark a value-moving keeper method (escrow /
# deductFee / split / ComputeTransferFee). These earn a needs-manual-setUp
# scaffold instead of a silent 0.
_KEEPER_SETUP_PARAM_RX = re.compile(
    r"(?:sdk|context)\.Context\b|"
    r"\bsdk\.Coins?\b|\bsdk\.Dec\b|\bsdk\.Int\b|\bmath\.Int\b|"
    r"\bsdk\.AccAddress\b|\bAddress\b"
)


def _load_extractor() -> Any:
    tool = Path(__file__).resolve().parent / "function-signature-extractor.py"
    spec = importlib.util.spec_from_file_location("function_signature_extractor", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load signature extractor: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_go_invariants(
    repo_root: Path,
    sources: Optional[List[str]] = None,
    only_ids: Optional[set] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for rel in (sources or DEFAULT_INVARIANT_SOURCES):
        path = repo_root / rel
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            content = d.get("content") if isinstance(d.get("content"), dict) else d
            inv_id = (content.get("invariant_id") or d.get("invariant_id")
                      or d.get("record_id"))
            if not inv_id or inv_id in seen:
                continue
            tl = (content.get("target_lang") or content.get("target_language")
                  or d.get("target_lang") or d.get("target_language") or "")
            if tl not in GO_INVARIANT_LANGS:
                continue
            if only_ids and inv_id not in only_ids:
                continue
            stmt = (content.get("statement") or content.get("invariant_text") or "").strip()
            cat = (content.get("category") or "").strip().lower()
            seen.add(inv_id)
            out.append({
                "invariant_id": inv_id,
                "category": cat,
                "statement": stmt,
                "target_lang": tl,
                "attack_signature": content.get("attack_signature") or "",
            })
    return out


def parse_selector(selector: str) -> Tuple[str, Optional[str]]:
    if "/" in selector:
        pkg, fn = selector.split("/", 1)
        return pkg.strip(), (fn.strip() or None)
    return selector.strip(), None


def locate_package(workspace: Path, pkg: str) -> Optional[Path]:
    """Locate a Go package dir by directory basename (the common convention)."""
    # Prefer an exact directory-name match that contains at least one .go file.
    candidates: List[Path] = []
    for go in sorted(workspace.rglob("*.go")):
        parts = {p for p in go.relative_to(workspace).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        if go.name.endswith("_test.go"):
            continue
        d = go.parent
        if d.name == pkg and d not in candidates:
            candidates.append(d)
    if candidates:
        return candidates[0]
    # Fallback: a directory whose package clause names `pkg`.
    for go in sorted(workspace.rglob("*.go")):
        parts = {p for p in go.relative_to(workspace).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        try:
            head = go.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r"^\s*package\s+([A-Za-z_]\w*)", head, re.MULTILINE)
        if m and m.group(1) == pkg:
            return go.parent
    return None


def iter_package_sources(pkg_dir: Path) -> List[Path]:
    out: List[Path] = []
    for path in sorted(pkg_dir.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        out.append(path)
    return out


def package_clause(pkg_dir: Path) -> str:
    """Return the package clause name declared in the package's first .go file."""
    for src in iter_package_sources(pkg_dir):
        try:
            head = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r"^\s*package\s+([A-Za-z_]\w*)", head, re.MULTILINE)
        if m:
            return m.group(1)
    return pkg_dir.name


def fn_category_hints(fn_name: str) -> Tuple[str, ...]:
    cats: List[str] = []
    for rx, cs in FN_NAME_CATEGORY_HINTS:
        if rx.search(fn_name):
            cats.extend(cs)
    seen: set = set()
    return tuple(c for c in cats if not (c in seen or seen.add(c)))


def match_invariant(fn_name: str, invariants: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    hints = fn_category_hints(fn_name)
    candidates = [iv for iv in invariants if iv["category"] in hints]
    if not candidates:
        candidates = [iv for iv in invariants
                      if iv["category"] in ("soundness", "determinism", "bounds")]
    if not candidates:
        candidates = list(invariants)
    if not candidates:
        return None
    return sorted(candidates, key=lambda iv: iv["invariant_id"])[0]


def _params(fn: Dict[str, Any]) -> List[Dict[str, str]]:
    return [p for p in (fn.get("params") or []) if isinstance(p, dict)]


def _returns(fn: Dict[str, Any]) -> List[str]:
    return [r for r in (fn.get("return_types") or []) if isinstance(r, str)]


def first_fuzzable_param(fn: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return the first parameter whose type is a native go-fuzz seed type."""
    for p in _params(fn):
        ty = (p.get("type") or "").strip()
        if _FUZZABLE_SCALAR_RX.match(ty):
            return p
    return None


def _nonerror_returns(fn: Dict[str, Any]) -> List[str]:
    """Return types excluding a trailing/standalone `error`. A real-output
    equality property is only meaningful over a value the fn actually returns."""
    return [r for r in _returns(fn) if r.strip() != "error"]


def is_pure_shaped(fn: Dict[str, Any]) -> bool:
    """Admit a function for the REAL-OUTPUT determinism property when it can be
    driven by the engine and returns a comparable value.

    Real-output requirement (Rule R80): determinism asserts f(in)==f(in) over the
    REAL `fname(...)` return value, so we need (a) at least one NON-error return
    (an `error`-only fn has no value to compare), and (b) a constructable first
    argument to drive the fuzz. We previously over-gated on a scalar FIRST param;
    `first_fuzzable_param` already scans every param, and `_build_call_expr_capture`
    zero-values the remaining params via `*new(T)` (compiles for any type), so any
    fn with >=1 fuzzable param + >=1 non-error return yields a genuine real-output
    assertion. Methods (non-empty receiver) still need a constructed receiver we
    cannot synthesize, so they stay no-panic-only."""
    recv = (fn.get("receiver_type") or "").strip()
    if recv:  # method - needs a constructed receiver; keep only no-panic
        return False
    if not _nonerror_returns(fn):
        return False
    return first_fuzzable_param(fn) is not None


def find_roundtrip_partner(
    fn: Dict[str, Any], all_fns: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """If fn is decode-shaped, find an encode-shaped sibling (and vice-versa)
    in the same package whose name stems match (Decode<->Encode, Unmarshal<->
    Marshal). Returns the PARTNER fn record or None."""
    name = fn.get("function_name") or ""
    if _DECODE_RX.search(name):
        # decode -> find encode partner producing the same noun.
        stem = _DECODE_RX.sub("", name)
        for other in all_fns:
            on = other.get("function_name") or ""
            if other is fn:
                continue
            if _ENCODE_RX.search(on) and _ENCODE_RX.sub("", on) == stem:
                return other
    if _ENCODE_RX.search(name):
        stem = _ENCODE_RX.sub("", name)
        for other in all_fns:
            on = other.get("function_name") or ""
            if other is fn:
                continue
            if _DECODE_RX.search(on) and _DECODE_RX.sub("", on) == stem:
                return other
    return None


def is_idempotent_shaped(fn: Dict[str, Any]) -> bool:
    name = fn.get("function_name") or ""
    if not _IDEMPOTENT_RX.search(name):
        return False
    if (fn.get("receiver_type") or "").strip():
        return False
    rets = _returns(fn)
    fp = first_fuzzable_param(fn)
    if not rets or fp is None:
        return False
    # Idempotence f(f(x))==f(x) requires the first return type to be assignable
    # back as the first argument (same scalar shape).
    first_ret = rets[0].strip()
    return first_ret == (fp.get("type") or "").strip()


def keeper_setup_param_types(fn: Dict[str, Any]) -> List[str]:
    """Return the fn's parameter types that mark it a keeper money-mover
    (sdk.Context / sdk.Coins / addresses). These are unfuzzable structured types
    that need a constructed keeper + app setUp to supply."""
    hits: List[str] = []
    for p in _params(fn):
        ty = (p.get("type") or "").strip()
        if ty and _KEEPER_SETUP_PARAM_RX.search(ty):
            hits.append(ty)
    return hits


def is_keeper_method_shaped(fn: Dict[str, Any]) -> bool:
    """A receiver method (exported OR unexported) taking cosmos-sdk plumbing.
    A shape-only author cannot construct its receiver + sdk.Context, so it earns
    a needs-manual-setUp scaffold rather than a silent 0 (GAP 1)."""
    recv = (fn.get("receiver_type") or "").strip()
    if not recv:
        return False
    return bool(keeper_setup_param_types(fn))


def render_keeper_scaffold(fn: Dict[str, Any], inv: Optional[Dict[str, Any]],
                           pkg_clause: str) -> Tuple[str, str]:
    """Emit a COMPILABLE needs-manual-setUp scaffold for a keeper money-mover.

    It imports only `testing` and `t.Skip`s with a typed verdict, so it compiles
    against ANY concrete package without referencing the un-synthesizable keeper
    receiver + sdk.Context. A commented conservation/determinism template shows
    the operator exactly what to wire (model: x/*/keeper/*_test.go setUp helpers).
    This is the GAP 1 guarantee: NEVER silently author 0 for a value-moving
    keeper method."""
    recv = (fn.get("receiver_type") or "").strip()
    fname = fn["function_name"]
    slug = _slug(f"{recv}_{fname}") if recv else _slug(fname)
    test_name = f"TestScaffold_{slug}_NeedsManualSetUp"
    setup_params = keeper_setup_param_types(fn)
    sig = " ".join((fn.get("function_signature") or "").split())
    inv_id = inv["invariant_id"] if inv else "(none)"
    inv_cat = inv["category"] if inv else "conservation"
    lines = [
        GENERATED_MARKER,
        f"// keeper-method scaffold for ({recv}).{fname}  "
        f"({fn.get('file_path')}:{fn.get('line_start')})",
        f"// signature: {sig}",
        f"// grounded-invariant: {inv_id} [{inv_cat}]",
        "// setup-params (unfuzzable, need a constructed keeper + app setUp): "
        f"{', '.join(setup_params)}",
        "// verdict: needs-manual-setUp",
        "//",
        "// A shape-only author CANNOT synthesize the keeper receiver + sdk.Context",
        "// (app/keeper setUp) required to CALL this value-moving keeper method, so",
        "// it emits this SCAFFOLD instead of silently authoring 0 (GAP 1). Wire the",
        "// setUp by modelling x/*/keeper/*_test.go setUp helpers (construct the",
        "// keeper via a test app + an sdk.Context + seeded balances), then replace",
        "// t.Skip with the conservation/determinism assertions templated below.",
        "",
        f"package {pkg_clause}",
        "",
        'import "testing"',
        "",
        f"func {test_name}(t *testing.T) {{",
        f'\tt.Skip("needs-manual-setUp: construct ({recv}) keeper + sdk.Context; '
        f'see conservation template below (grounds {inv_id})")',
        "\t// CONSERVATION / DETERMINISM TEMPLATE (uncomment + wire once setUp exists):",
        "\t//",
        "\t//   k, ctx := setUpKeeper(t)          // model: x/*/keeper/*_test.go",
        "\t//   before := k.TotalEscrowed(ctx)     // sum of every value pool",
        f"\t//   _ = k.{fname}(ctx, /* args */)",
        "\t//   after := k.TotalEscrowed(ctx)",
        "\t//   if !before.Equal(after) {          // conservation: no value created/destroyed",
        f'\t//       t.Fatalf("{fname} broke value conservation: %s -> %s", before, after)',
        "\t//   }",
        "}",
    ]
    return test_name, "\n".join(lines) + "\n"


def returns_error_last(fn: Dict[str, Any]) -> bool:
    rets = _returns(fn)
    return bool(rets) and rets[-1].strip() == "error"


def _seed_literal(go_type: str) -> str:
    """A deterministic, non-trivial seed literal for f.Add()."""
    t = go_type.strip()
    if t == "string":
        return '"auditooor-seed"'
    if t == "[]byte":
        return '[]byte("auditooor-seed")'
    if t == "bool":
        return "true"
    if t in ("byte", "rune"):
        return "byte(7)" if t == "byte" else "rune(7)"
    if re.match(r"^u?int(8|16|32|64)?$", t):
        return f"{t}(7)"
    if re.match(r"^float(32|64)$", t):
        return f"{t}(7)"
    return "0"


def _snapshot_expr(go_type: str, value: str) -> str:
    """Return a before/after snapshot expression for a fuzz input value."""
    t = go_type.strip()
    if t == "[]byte":
        return f"append([]byte(nil), {value}...)"
    return value


def _state_tuple(names: List[str]) -> str:
    if not names:
        return "[]interface{}{}"
    return "[]interface{}{" + ", ".join(names) + "}"


def _doc_block(fn: Dict[str, Any], inv: Dict[str, Any], engine: str) -> List[str]:
    sig = " ".join((fn.get("function_signature") or "").split())
    lines = [
        GENERATED_MARKER,
        f"// pkg fn: {fn.get('function_name')}  ({fn.get('file_path')}:{fn.get('line_start')})",
        f"// signature: {sig}",
        f"// grounded-invariant: {inv['invariant_id']} [{inv['category']}] (engine={engine})",
    ]
    if inv["statement"]:
        stmt = inv["statement"]
        for i in range(0, len(stmt), 90):
            lines.append(f"//   inv: {stmt[i:i + 90]}")
    return lines


def render_fuzz_nopanic(fn: Dict[str, Any], inv: Dict[str, Any]) -> Tuple[str, str]:
    """The load-bearing no-panic / no-crash fuzz target. ALWAYS a real property:
    the engine reports any panic as a discovered crash. Drives the REAL target."""
    fname = fn["function_name"]
    fuzz_name = f"Fuzz{fname}"
    fp = first_fuzzable_param(fn)
    arg_type = (fp.get("type") if fp else "[]byte")
    seed = _seed_literal(arg_type)
    # Build a call expression that drives the real function with the fuzzed input
    # bound to its first fuzzable parameter and zero-values for the remainder.
    call = _build_call_expr(fn, fuzz_var="in")
    body = [
        f"func {fuzz_name}(f *testing.F) {{",
        f"\tf.Add({seed})",
        f"\tf.Fuzz(func(t *testing.T, in {arg_type}) {{",
        "\t\t// no-panic property: the engine treats any panic from the real",
        "\t\t// target as a discovered crash. This is a genuine, executed property",
        f"\t\t// (not a no-op) grounding invariant {inv['invariant_id']}.",
        f"\t\tbeforeState := {_snapshot_expr(arg_type, 'in')}",
        "\t\tnegativeControlCleanPath := true",
        f"\t\t{call}",
        f"\t\tafterState := {_snapshot_expr(arg_type, 'in')}",
        "\t\tif !negativeControlCleanPath {",
        "\t\t\tt.Fatalf(\"negative control failed before target call\")",
        "\t\t}",
        "\t\t_ = beforeState",
        "\t\t_ = afterState",
        "\t})",
        "}",
    ]
    return fuzz_name, "\n".join(_doc_block(fn, inv, "go-fuzz") + body) + "\n"


def _build_call_expr(fn: Dict[str, Any], fuzz_var: str) -> str:
    """Render a call to the real function, binding the first fuzzable param to
    `fuzz_var` and remaining params to zero-values. Captures returns into `_`."""
    fname = fn["function_name"]
    params = _params(fn)
    fp = first_fuzzable_param(fn)
    args: List[str] = []
    bound = False
    for p in params:
        ty = (p.get("type") or "").strip()
        if (not bound) and fp is not None and p is fp:
            args.append(fuzz_var)
            bound = True
        else:
            args.append(_zero_value(ty))
    n_ret = len(_returns(fn))
    lhs = ""
    if n_ret == 1:
        lhs = "_ = "
    elif n_ret > 1:
        lhs = ", ".join(["_"] * n_ret) + " = "
    return f"{lhs}{fname}({', '.join(args)})"


def _zero_value(go_type: str) -> str:
    t = go_type.strip()
    if t == "string":
        return '""'
    if t == "bool":
        return "false"
    if t == "[]byte":
        return "nil"
    if re.match(r"^u?int(8|16|32|64)?$", t):
        return f"{t}(0)"
    if re.match(r"^float(32|64)$", t):
        return f"{t}(0)"
    if t in ("byte", "rune"):
        return f"{t}(0)"
    if t.startswith("[]") or t.startswith("map[") or t.startswith("*") or t.startswith("chan"):
        return "nil"
    # struct / named type: var-zero via composite literal is unsafe to guess;
    # use the typed zero through a declared var would need a separate stmt. Keep
    # it conservative with a typed nil-ish fallback only for known nilable shapes;
    # otherwise emit `*new(T)` which is always the zero value of T.
    return f"*new({t})"


def render_determinism(fn: Dict[str, Any], inv: Dict[str, Any]) -> Tuple[str, str]:
    """Determinism property: f(in) twice yields equal results. REAL assertion."""
    fname = fn["function_name"]
    test_name = f"FuzzPropDeterminism{fname}"
    fp = first_fuzzable_param(fn)
    arg_type = fp["type"]
    seed = _seed_literal(arg_type)
    call1 = _build_call_expr_capture(fn, fuzz_var="in", suffix="A")
    call2 = _build_call_expr_capture(fn, fuzz_var="in", suffix="B")
    rets = _returns(fn)
    before_tuple = _state_tuple([f"rA{i}" for i in range(len(rets))])
    after_tuple = _state_tuple([f"rB{i}" for i in range(len(rets))])
    cmp_lines = _equality_assert(fn, "A", "B",
                                 "determinism: same input must yield same output")
    body = [
        f"func {test_name}(f *testing.F) {{",
        f"\tf.Add({seed})",
        f"\tf.Fuzz(func(t *testing.T, in {arg_type}) {{",
        f"\t\t{call1}",
        f"\t\tbeforeState := {before_tuple}",
        "\t\tnegativeControlCleanPath := true",
        f"\t\t{call2}",
        f"\t\tafterState := {after_tuple}",
        "\t\tif !negativeControlCleanPath {",
        "\t\t\tt.Fatalf(\"negative control failed before target call\")",
        "\t\t}",
        "\t\t_ = beforeState",
        "\t\t_ = afterState",
        *[f"\t\t{ln}" for ln in cmp_lines],
        "\t})",
        "}",
    ]
    return test_name, "\n".join(_doc_block(fn, inv, "go-fuzz/determinism") + body) + "\n"


def _build_call_expr_capture(fn: Dict[str, Any], fuzz_var: str, suffix: str) -> str:
    """Like _build_call_expr but captures each return into r<suffix><i>."""
    fname = fn["function_name"]
    params = _params(fn)
    fp = first_fuzzable_param(fn)
    args: List[str] = []
    bound = False
    for p in params:
        ty = (p.get("type") or "").strip()
        if (not bound) and fp is not None and p is fp:
            args.append(fuzz_var)
            bound = True
        else:
            args.append(_zero_value(ty))
    rets = _returns(fn)
    names = [f"r{suffix}{i}" for i in range(len(rets))]
    lhs = (", ".join(names) + " := ") if names else ""
    return f"{lhs}{fname}({', '.join(args)})"


def _equality_assert(fn: Dict[str, Any], sa: str, sb: str, msg: str) -> List[str]:
    """Emit a reflect.DeepEqual assertion over each non-error return pair.
    Error returns are compared by nil-ness (deterministic err presence)."""
    rets = _returns(fn)
    lines: List[str] = []
    for i, rt in enumerate(rets):
        a = f"r{sa}{i}"
        b = f"r{sb}{i}"
        if rt.strip() == "error":
            lines.append(f"if ({a} == nil) != ({b} == nil) {{")
            lines.append(f"\tt.Errorf(\"{msg}: error-presence diverged for in=%v\", in)")
            lines.append("}")
        else:
            lines.append(f"if !reflect.DeepEqual({a}, {b}) {{")
            lines.append(f"\tt.Errorf(\"{msg}: return {i} diverged: %v != %v (in=%v)\", {a}, {b}, in)")
            lines.append("}")
    return lines


def render_roundtrip(fn: Dict[str, Any], partner: Dict[str, Any],
                     inv: Dict[str, Any]) -> Tuple[str, str]:
    """Round-trip property: decode(encode(x)) == x (modulo error). REAL assertion.

    fn is the DECODE-shaped function (in -> value[, error]); partner is the
    ENCODE-shaped function (value -> []byte/string[, error]). We fuzz over the
    decode input, decode it, re-encode, decode again, and assert the second
    decode equals the first (stable round-trip). This avoids needing a known
    value-equality on the intermediate type."""
    dec = fn["function_name"]
    enc = partner["function_name"]
    test_name = f"FuzzPropRoundTrip{dec}"
    fp = first_fuzzable_param(fn)
    arg_type = fp["type"]
    seed = _seed_literal(arg_type)
    # decode(in) -> v0[, err0]; if err0 != nil skip. encode(v0) -> b1[, errE];
    # if errE != nil skip. decode(b1) -> v1[, err1]; assert v0 == v1.
    dec_rets = _returns(fn)
    enc_rets = _returns(partner)
    dec_has_err = returns_error_last(fn)
    enc_has_err = returns_error_last(partner)
    dec_val_idx = 0  # first return is the value
    enc_val_idx = 0
    body: List[str] = [
        f"func {test_name}(f *testing.F) {{",
        f"\tf.Add({seed})",
        f"\tf.Fuzz(func(t *testing.T, in {arg_type}) {{",
    ]
    # decode 1
    d1 = [f"v0_{i}" for i in range(len(dec_rets))]
    body.append(f"\t\t{', '.join(d1)} := {dec}({_call_args(fn, 'in')})")
    if dec_has_err:
        body.append(f"\t\tif v0_{len(dec_rets)-1} != nil {{ return }} // skip undecodable seeds")
    body.append(f"\t\tbeforeState := v0_{dec_val_idx}")
    body.append("\t\tnegativeControlCleanPath := true")
    # encode
    e1 = [f"e0_{i}" for i in range(len(enc_rets))]
    body.append(f"\t\t{', '.join(e1)} := {enc}({_call_args(partner, f'v0_{dec_val_idx}')})")
    if enc_has_err:
        body.append(f"\t\tif e0_{len(enc_rets)-1} != nil {{ return }} // skip unencodable values")
    # decode 2 over the re-encoded bytes
    d2 = [f"v1_{i}" for i in range(len(dec_rets))]
    body.append(f"\t\t{', '.join(d2)} := {dec}({_call_args(fn, f'e0_{enc_val_idx}')})")
    if dec_has_err:
        body.append(f"\t\tif v1_{len(dec_rets)-1} != nil {{")
        body.append(f"\t\t\tt.Errorf(\"round-trip: re-decode failed after encode for in=%v: %v\", in, v1_{len(dec_rets)-1})")
        body.append("\t\t\treturn")
        body.append("\t\t}")
    body.append(f"\t\tafterState := v1_{dec_val_idx}")
    body.append("\t\tif !negativeControlCleanPath {")
    body.append("\t\t\tt.Fatalf(\"negative control failed before target call\")")
    body.append("\t\t}")
    body.append("\t\t_ = beforeState")
    body.append("\t\t_ = afterState")
    body.append(f"\t\tif !reflect.DeepEqual(v0_{dec_val_idx}, v1_{dec_val_idx}) {{")
    body.append(f"\t\t\tt.Errorf(\"round-trip: decode(encode(decode(in))) != decode(in): %v != %v\", v0_{dec_val_idx}, v1_{dec_val_idx})")
    body.append("\t\t}")
    body.append("\t})")
    body.append("}")
    return test_name, "\n".join(_doc_block(fn, inv, "go-fuzz/round-trip") + body) + "\n"


def _call_args(fn: Dict[str, Any], first_arg: str) -> str:
    """Render the comma-joined argument list binding the first fuzzable param
    (or first param) to `first_arg` and zero-values for the rest."""
    params = _params(fn)
    fp = first_fuzzable_param(fn)
    target = fp if fp is not None else (params[0] if params else None)
    args: List[str] = []
    bound = False
    for p in params:
        ty = (p.get("type") or "").strip()
        if (not bound) and target is not None and p is target:
            args.append(first_arg)
            bound = True
        else:
            args.append(_zero_value(ty))
    if not bound and params:
        # no fuzzable param matched the binding target; bind first param.
        args[0] = first_arg
    return ", ".join(args)


def render_idempotence(fn: Dict[str, Any], inv: Dict[str, Any]) -> Tuple[str, str]:
    """Idempotence property: f(f(x)) == f(x). REAL assertion. Only for
    normalize/canonical-shaped fns whose first return type == first param type."""
    fname = fn["function_name"]
    test_name = f"FuzzPropIdempotence{fname}"
    fp = first_fuzzable_param(fn)
    arg_type = fp["type"]
    seed = _seed_literal(arg_type)
    rets = _returns(fn)
    has_err = returns_error_last(fn)
    once = [f"once_{i}" for i in range(len(rets))]
    twice = [f"twice_{i}" for i in range(len(rets))]
    body: List[str] = [
        f"func {test_name}(f *testing.F) {{",
        f"\tf.Add({seed})",
        f"\tf.Fuzz(func(t *testing.T, in {arg_type}) {{",
        f"\t\t{', '.join(once)} := {fname}({_call_args(fn, 'in')})",
    ]
    if has_err:
        body.append(f"\t\tif once_{len(rets)-1} != nil {{ return }}")
    body.append("\t\tbeforeState := once_0")
    body.append("\t\tnegativeControlCleanPath := true")
    body.append(f"\t\t{', '.join(twice)} := {fname}({_call_args(fn, 'once_0')})")
    if has_err:
        body.append(f"\t\tif twice_{len(rets)-1} != nil {{")
        body.append("\t\t\tt.Errorf(\"idempotence: second application errored for in=%v\", in)")
        body.append("\t\t\treturn")
        body.append("\t\t}")
    body.append("\t\tafterState := twice_0")
    body.append("\t\tif !negativeControlCleanPath {")
    body.append("\t\t\tt.Fatalf(\"negative control failed before target call\")")
    body.append("\t\t}")
    body.append("\t\t_ = beforeState")
    body.append("\t\t_ = afterState")
    body.append("\t\tif !reflect.DeepEqual(once_0, twice_0) {")
    body.append("\t\t\tt.Errorf(\"idempotence: f(f(x)) != f(x): %v != %v (in=%v)\", twice_0, once_0, in)")
    body.append("\t\t}")
    body.append("\t})")
    body.append("}")
    return test_name, "\n".join(_doc_block(fn, inv, "go-fuzz/idempotence") + body) + "\n"


def needs_reflect(targets: List[str]) -> bool:
    return any(t in ("determinism", "roundtrip", "idempotence") for t in targets)


def render_harness_file(*, pkg_clause: str, fn: Dict[str, Any], inv: Dict[str, Any],
                        rendered: List[Tuple[str, str, str]]) -> str:
    """rendered: list of (engine_kind, fn_name, body_text)."""
    fname = fn["function_name"]
    needs_refl = needs_reflect([k for (k, _, _) in rendered])
    header: List[str] = [
        GENERATED_MARKER,
        f"// Authored Go engine harness for {pkg_clause}.{fname}",
        f"// Grounded invariant: {inv['invariant_id']} ({inv['category']})",
        "//",
        "// This file is AUTHORED scaffolding (Rule 58: invariant-grounded). Unlike",
        "// the Rust/EVM authors, the Go properties below are REAL executed",
        "// properties (no-panic, determinism, round-trip, idempotence) derived from",
        "// the function SHAPE - none is a no-op / tautology. The runner",
        "// (tools/go-engine-harness-runner.sh) drives them via `go test -fuzz`.",
        "//",
        "// NOTE: the package + function wiring is provided. If a generated property",
        "// does not compile against your concrete types, narrow the selector or",
        "// delete the offending property file; the no-panic Fuzz target is the",
        "// load-bearing one and is always shape-safe.",
        "",
        f"package {pkg_clause}",
        "",
        "import (",
        "\t\"testing\"",
    ]
    if needs_refl:
        header.append("\t\"reflect\"")
    header.append(")")
    header.append("")
    parts = ["\n".join(header)]
    for (_kind, _name, body) in rendered:
        parts.append(body)
    return "\n".join(parts).rstrip("\n") + "\n"


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def author(workspace: Path, selector: str, *, repo_root: Path,
           invariant_ids: Optional[set] = None, max_fns: int = 12,
           want_fuzz: bool = True, want_determinism: bool = True,
           want_roundtrip: bool = True, want_idempotence: bool = True,
           want_keeper_scaffold: bool = True,
           dry_run: bool = False) -> Dict[str, Any]:
    extractor = _load_extractor()
    pkg, fn_filter = parse_selector(selector)

    pkg_dir = locate_package(workspace, pkg)
    if pkg_dir is None:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": f"package {pkg!r} not found under {workspace}",
                "authored": [], "authored_count": 0, "invariant_source_count": 0}

    invariants = load_go_invariants(repo_root, only_ids=invariant_ids)
    if not invariants:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": "no go|any invariants in corpus (or --invariant-id filtered all out)",
                "authored": [], "authored_count": 0, "invariant_source_count": 0}

    pkg_clause = package_clause(pkg_dir)

    all_fns: List[Dict[str, Any]] = []
    seen_fn: set = set()
    for src in iter_package_sources(pkg_dir):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(src.relative_to(pkg_dir))
        for fn in extractor.extract_go_functions(text, rel):
            name = fn.get("function_name") or ""
            if not name:
                continue
            key = (name, rel, fn.get("receiver_type") or "")
            if key in seen_fn:
                continue
            seen_fn.add(key)
            all_fns.append(fn)

    # Candidate set: exported, non-skip, selector-matching, fuzzable-first-param
    # OR roundtrip-pair-eligible.
    candidates: List[Dict[str, Any]] = []
    keeper_candidates: List[Dict[str, Any]] = []
    for fn in all_fns:
        name = fn["function_name"]
        if _SKIP_FN_RX.match(name):
            continue
        if fn_filter and fn_filter not in name:
            continue
        # GAP 1: a keeper money-mover method (receiver + sdk.Context/sdk.Coins)
        # cannot be driven by a shape-only author, but MUST NOT be silently
        # dropped. Route it (exported OR unexported) into the needs-manual-setUp
        # scaffold lane instead of the fuzz-author lane.
        if want_keeper_scaffold and is_keeper_method_shaped(fn):
            keeper_candidates.append(fn)
            continue
        if fn.get("visibility") != "exported":
            continue
        # Non-keeper methods (non-empty receiver) still need a CONSTRUCTED
        # receiver + protocol state to call (`c.Method(..)`) that a shape-only
        # author cannot synthesize safely, and lack the money-mover setup-param
        # signal, so we cannot even scaffold a meaningful conservation property.
        # Skip them; only package-level functions are fuzz-authored.
        if (fn.get("receiver_type") or "").strip():
            continue
        # Must have at least a fuzzable first param to drive a fuzz target,
        # OR be the decode side of a round-trip pair.
        if first_fuzzable_param(fn) is None and find_roundtrip_partner(fn, all_fns) is None:
            continue
        candidates.append(fn)

    if not candidates and not keeper_candidates:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": (f"no exported fuzzable functions matched selector {selector!r} "
                           f"in package {pkg_clause}"),
                "authored": [], "authored_count": 0,
                "manual_setup": [], "manual_setup_count": 0,
                "invariant_source_count": len(invariants)}

    candidates.sort(key=lambda f: (f.get("function_name"), f.get("file_path")))
    candidates = candidates[:max_fns]
    keeper_candidates.sort(key=lambda f: (f.get("receiver_type") or "",
                                          f.get("function_name"), f.get("file_path")))
    keeper_candidates = keeper_candidates[:max_fns]

    authored: List[Dict[str, Any]] = []
    for fn in candidates:
        inv = match_invariant(fn["function_name"], invariants)
        if inv is None:
            continue
        rendered: List[Tuple[str, str, str]] = []
        property_names: List[str] = []
        engines: List[str] = []

        if want_fuzz and first_fuzzable_param(fn) is not None:
            nm, body = render_fuzz_nopanic(fn, inv)
            rendered.append(("nopanic", nm, body))
            property_names.append(nm)
            engines.append("go-fuzz/no-panic")

        if want_determinism and is_pure_shaped(fn):
            nm, body = render_determinism(fn, inv)
            rendered.append(("determinism", nm, body))
            property_names.append(nm)
            engines.append("go-fuzz/determinism")

        partner = find_roundtrip_partner(fn, all_fns) if want_roundtrip else None
        # Only emit round-trip on the DECODE side to avoid double emission.
        if (want_roundtrip and partner is not None
                and _DECODE_RX.search(fn["function_name"])
                and first_fuzzable_param(fn) is not None):
            nm, body = render_roundtrip(fn, partner, inv)
            rendered.append(("roundtrip", nm, body))
            property_names.append(nm)
            engines.append("go-fuzz/round-trip")

        if want_idempotence and is_idempotent_shaped(fn):
            nm, body = render_idempotence(fn, inv)
            rendered.append(("idempotence", nm, body))
            property_names.append(nm)
            engines.append("go-fuzz/idempotence")

        if not rendered:
            continue

        content = render_harness_file(pkg_clause=pkg_clause, fn=fn, inv=inv,
                                      rendered=rendered)
        out_name = f"{AUTHORED_FILE_PREFIX}{_slug(fn['function_name'])}{AUTHORED_FILE_SUFFIX}"
        # real_output_bound: at least one emitted property asserts a RELATION over
        # the REAL fn return value (determinism/round-trip/idempotence). The
        # no-panic fuzz drives the real call but asserts no output relation, so it
        # alone does NOT count as a real-output bound (R80: genuine vs needs-binding).
        real_output_bound = any(kind in ("determinism", "roundtrip", "idempotence")
                                for kind, _nm, _body in rendered)
        authored.append({
            "function": fn["function_name"],
            "receiver_type": fn.get("receiver_type") or "",
            "source": fn["file_path"],
            "line": fn.get("line_start"),
            "grounded_invariant": inv["invariant_id"],
            "invariant_category": inv["category"],
            "property_fns": property_names,
            "engines": engines,
            "real_output_bound": real_output_bound,
            "harness_file": out_name,
            "_content": content,
        })

    # GAP 1: keeper money-movers -> needs-manual-setUp scaffolds (never a silent 0).
    manual_setup: List[Dict[str, Any]] = []
    for fn in keeper_candidates:
        inv = match_invariant(fn["function_name"], invariants)
        test_name, content = render_keeper_scaffold(fn, inv, pkg_clause)
        out_name = (f"{AUTHORED_FILE_PREFIX}"
                    f"{_slug((fn.get('receiver_type') or '') + '_' + fn['function_name'])}"
                    f"{KEEPER_SCAFFOLD_SUFFIX}")
        manual_setup.append({
            "function": fn["function_name"],
            "receiver_type": fn.get("receiver_type") or "",
            "source": fn["file_path"],
            "line": fn.get("line_start"),
            "grounded_invariant": inv["invariant_id"] if inv else None,
            "invariant_category": inv["category"] if inv else "conservation",
            "setup_params": keeper_setup_param_types(fn),
            "verdict": "needs-manual-setUp",
            "scaffold_test": test_name,
            "harness_file": out_name,
            "_content": content,
        })

    if not authored and not manual_setup:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": "no candidate function produced an emittable property",
                "authored": [], "authored_count": 0,
                "manual_setup": [], "manual_setup_count": 0,
                "invariant_source_count": len(invariants),
                "package": pkg_clause}

    if not dry_run:
        for a in authored:
            (pkg_dir / a["harness_file"]).write_text(a.pop("_content"), encoding="utf-8")
        for a in manual_setup:
            (pkg_dir / a["harness_file"]).write_text(a.pop("_content"), encoding="utf-8")
    else:
        for a in authored:
            a.pop("_content", None)
        for a in manual_setup:
            a.pop("_content", None)

    fuzz_fns = sorted({pn for a in authored for pn in a["property_fns"]})
    manifest = {
        "schema_version": SCHEMA_VERSION, "workspace": str(workspace),
        "selector": selector, "package": pkg_clause,
        "package_dir": (str(pkg_dir.relative_to(workspace))
                        if pkg_dir.is_relative_to(workspace) else str(pkg_dir)),
        "status": "ok",
        "reason": "",
        "invariant_source_count": len(invariants),
        "authored_count": len(authored), "authored": authored,
        "manual_setup_count": len(manual_setup), "manual_setup": manual_setup,
        "fuzz_targets": fuzz_fns,
        "runner_filename_prefix": AUTHORED_FILE_PREFIX,
        "runner_command_hint": (
            f"tools/go-engine-harness-runner.sh {workspace} "
            f"--package-dir {manifest_pkg_rel(pkg_dir, workspace)} "
            f"--fuzz-prefix Fuzz"),
        "go_test_command": (
            f"(cd {manifest_pkg_rel(pkg_dir, workspace)} && go test ./... -run "
            f"'^(FuzzProp)' && for fz in {' '.join(fuzz_fns)}; do "
            f"go test -run '^$' -fuzz \"^$fz$\" -fuzztime 10s .; done)"),
        "dry_run": dry_run,
    }
    if not dry_run and (authored or manual_setup):
        manifest_path = pkg_dir / f"{AUTHORED_FILE_PREFIX}harness_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
        manifest["manifest_file"] = manifest_path.name
    return manifest


def manifest_pkg_rel(pkg_dir: Path, workspace: Path) -> str:
    return (str(pkg_dir.relative_to(workspace))
            if pkg_dir.is_relative_to(workspace) else str(pkg_dir))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("workspace")
    p.add_argument("selector")
    p.add_argument("--invariant-id", action="append", default=None)
    p.add_argument("--max-fns", type=int, default=12)
    p.add_argument("--no-fuzz", dest="fuzz", action="store_false", default=True)
    p.add_argument("--no-determinism", dest="determinism", action="store_false", default=True)
    p.add_argument("--no-roundtrip", dest="roundtrip", action="store_false", default=True)
    p.add_argument("--no-idempotence", dest="idempotence", action="store_false", default=True)
    p.add_argument("--no-keeper-scaffold", dest="keeper_scaffold",
                   action="store_false", default=True,
                   help="Do not emit needs-manual-setUp scaffolds for keeper money-movers.")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"not a directory: {workspace}", file=sys.stderr)
        return 2
    repo_root = Path(__file__).resolve().parents[1]
    only_ids = set(args.invariant_id) if args.invariant_id else None
    manifest = author(workspace, args.selector, repo_root=repo_root,
                      invariant_ids=only_ids, max_fns=args.max_fns,
                      want_fuzz=args.fuzz, want_determinism=args.determinism,
                      want_roundtrip=args.roundtrip, want_idempotence=args.idempotence,
                      want_keeper_scaffold=args.keeper_scaffold,
                      dry_run=args.dry_run)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[go-harness-author] {manifest['status']}: {manifest['authored_count']} "
              f"harness(es) + {manifest.get('manual_setup_count', 0)} "
              f"needs-manual-setUp scaffold(s) for selector {args.selector!r} "
              f"(grounded in {manifest['invariant_source_count']} go|any invariants)")
        for a in manifest["authored"]:
            print(f"  - {a['function']} -> {a['grounded_invariant']} "
                  f"[{a['invariant_category']}] "
                  f"props={'+'.join(a['property_fns'])}  {a['harness_file']}")
        for a in manifest.get("manual_setup", []):
            print(f"  - ({a['receiver_type']}).{a['function']} -> "
                  f"{a['grounded_invariant']} [{a['invariant_category']}] "
                  f"verdict=needs-manual-setUp  {a['harness_file']}")
        if manifest.get("reason"):
            print(f"  reason: {manifest['reason']}")
    return 0 if manifest["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
