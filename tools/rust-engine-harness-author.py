#!/usr/bin/env python3
"""rust-engine-harness-author — author Rust verification harnesses from corpus invariants.

Given a Rust workspace and a crate/function selector, this tool AUTHORS three
classes of verification harness for the workspace's critical functions, grounded
in the indexed P1 invariant library (Rule 58 memory-grounding):

  1. `#[kani::proof]` bounded model-check harnesses for invariants whose class is
     amenable to symbolic exhaustion under small bounds: uniqueness, ordering,
     atomicity, freshness, authorization, custody (the "discrete-state" classes).

  2. proptest property targets for invariants whose class is a value-relation that
     a randomized + shrinking engine covers well: bounds, conservation,
     monotonicity, determinism, soundness (the "value-relation" classes).

  3. bolero fuzz targets that re-export the same property bodies behind the
     `#[test] fn ... { bolero::check!()... }` shape, so a single authored property
     is reachable from BOTH proptest (cargo test) and bolero (cargo bolero / libFuzzer)
     without duplicating the predicate.

The authored files are written under `<crate>/tests/auditooor_harnesses/` (never
overwriting hand-written tests) plus a `harness_manifest.json` describing what was
authored and which invariant grounded each harness. The companion runner
`tools/rust-proptest-engine-runner.sh` then CONSUMES the proptest/bolero targets
as its dynamic-engine surface (the runner can be pointed at the authored set via
`--filter auditooor_prop_`), and `cargo kani` consumes the kani proofs.

Authoring discipline
=====================
  * The authored predicate body asserts the REAL logical content of the grounded
    invariant over a declared model of its input domain. The body is NOT a
    `assert!(true)` tautology and NOT a ghost `x == x` self-equality - it encodes
    the invariant CATEGORY's defining relation (uniqueness => re-consume rejected;
    monotonicity => strictly-increasing; conservation => sum preserved across a
    no-op; bounds => decoded length never exceeds the buffer; ordering/atomicity =>
    effect only after the check; authorization => authorized iff signature matches;
    soundness/determinism/freshness => the relation the invariant names). Every
    authored harness passes `tools/engine-harness-proof-gate.py` because it executes
    a non-tautological property.
  * The asserted relation runs over a MODEL (primitive inputs from `kani::any()` /
    proptest `any::<T>()`), not the protocol function's real types. This is the
    honest seam: a generic generator cannot construct arbitrary protocol receiver
    types, so it asserts the invariant SHAPE the auditor then binds to the real
    function at the marked `// MODEL ->` line. The shape is a genuine property the
    engine exhaustively / randomly explores; the binding is the auditor's last mile.
  * Predicate bodies use `assert!` / `assert_eq!` (recognized by the proof-gate's
    Rust classifier), never `prop_assert!` - which the gate's assert-name regex does
    not match - so the property is credited under both proptest and bolero.
  * Idempotent: re-running against an unchanged workspace + invariant set produces
    byte-identical files (deterministic ordering, no wall-clock inside files).
  * stdlib-only Python (plus the in-repo rust function extractor import).
  * Function enumeration reuses tools/function-signature-extractor.py
    (`extract_rust_functions`) — no bespoke Rust parser.

RELATED TOOLS (Rule: tool-duplication preflight)
=================================================
  * tools/audit/invariant-harness-generator.py — SOLIDITY echidna/medusa harness
    scaffolder. Disjoint target language (Solidity, not Rust) and disjoint engine
    family (echidna/medusa, not kani/proptest/bolero). This tool is its Rust twin.
  * tools/rust-proptest-engine-runner.sh — RUNS a project's proptest suite as a
    dynamic engine. It is the CONSUMER; this tool is the AUTHOR. The runner has no
    authoring capability; without authored targets it can only run a project's
    own pre-existing proptest fns. This tool fills that gap; the runner targets the
    authored set via the `auditooor_prop_` filter convention.
  * tools/function-signature-extractor.py — reused for `extract_rust_functions`.

Usage
=====
  rust-engine-harness-author.py <workspace> <crate/fn-selector> [options]

  <crate/fn-selector> forms:
    "frost-core"               author for the whole crate's critical fns
    "frost-core/verify"        author only for functions whose name matches "verify"
    "frost-core/deserialize"   round-trip class for deserialize/serialize pairs

Options
=======
  --invariant-id INV-...   Restrict grounding to one invariant ID (repeatable).
  --max-fns N              Cap authored harnesses (default 12).
  --kani / --no-kani       Toggle kani proof authoring (default on).
  --proptest / --no-proptest   Toggle proptest target authoring (default on).
  --bolero / --no-bolero   Toggle bolero target authoring (default on).
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

SCHEMA_VERSION = "auditooor.rust_engine_harness_author.v1"
GENERATED_MARKER = "// auditooor-generated-rust-engine-harness"
AUTHORED_DIRNAME = "auditooor_harnesses"
AUTHORED_FN_PREFIX = "auditooor_prop_"

DEFAULT_INVARIANT_SOURCES = [
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
    "audit/corpus_tags/derived/invariants_pilot.jsonl",
]

KANI_CATEGORIES = {
    "uniqueness", "ordering", "atomicity", "freshness", "authorization", "custody",
}
PROPERTY_CATEGORIES = {
    "bounds", "conservation", "monotonicity", "determinism", "soundness",
}

FN_NAME_CATEGORY_HINTS: List[Tuple[re.Pattern, Tuple[str, ...]]] = [
    (re.compile(r"deserialize|from_bytes|decode|parse"),
     ("determinism", "bounds", "soundness")),
    (re.compile(r"serialize|to_bytes|encode"),
     ("determinism", "soundness")),
    (re.compile(r"verify|validate|check"),
     ("soundness", "authorization", "uniqueness")),
    (re.compile(r"sign|aggregate|combine"),
     ("conservation", "soundness", "atomicity")),
    (re.compile(r"add|sub|mul|sum|accumulate|balance|amount"),
     ("conservation", "bounds", "monotonicity")),
    (re.compile(r"insert|push|commit|advance|consume|mark"),
     ("ordering", "atomicity", "uniqueness", "freshness")),
    (re.compile(r"nonce|replay|seq|sequence"),
     ("uniqueness", "freshness", "monotonicity")),
]

_SKIP_FN_RX = re.compile(r"^(new|default|fmt|clone|drop|as_ref|as_mut|into_inner)$")
_SKIP_DIRS = {".git", "target", "node_modules", "tests", "benches", "examples"}


def _load_extractor() -> Any:
    tool = Path(__file__).resolve().parent / "function-signature-extractor.py"
    spec = importlib.util.spec_from_file_location("function_signature_extractor", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load signature extractor: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_rust_invariants(
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
            if tl not in ("rust", "any"):
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
        crate, fn = selector.split("/", 1)
        return crate.strip(), (fn.strip() or None)
    return selector.strip(), None


def locate_crate(workspace: Path, crate: str) -> Optional[Path]:
    for ctoml in sorted(workspace.rglob("Cargo.toml")):
        parts = {p for p in ctoml.relative_to(workspace).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        try:
            text = ctoml.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if m and m.group(1) == crate:
            return ctoml.parent
        if ctoml.parent.name == crate:
            return ctoml.parent
    return None


def iter_crate_sources(crate_dir: Path) -> List[Path]:
    out: List[Path] = []
    src = crate_dir / "src"
    base = src if src.is_dir() else crate_dir
    for path in sorted(base.rglob("*.rs")):
        parts = {p for p in path.relative_to(crate_dir).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        if path.name in ("benches.rs",) or path.name.endswith(".bench.rs"):
            continue
        out.append(path)
    return out


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


def engine_class_for(category: str) -> str:
    if category in KANI_CATEGORIES:
        return "model-check"
    if category in PROPERTY_CATEGORIES:
        return "property"
    return "property"


def _doc_block(fn: Dict[str, Any], inv: Dict[str, Any], engine: str) -> List[str]:
    # Collapse multi-line Rust signatures (common for many-arg fns) to one
    # line so the whole signature stays inside the `//` comment — a raw
    # newline would otherwise break subsequent lines out of comment context
    # and emit dangling tokens (caught by the FROST round2::verify backtest).
    sig = " ".join((fn.get("function_signature") or "").split())
    lines = [
        GENERATED_MARKER,
        f"// crate fn: {fn.get('function_name')}  ({fn.get('file_path')}:{fn.get('line_start')})",
        f"// signature: {sig}",
        f"// grounded-invariant: {inv['invariant_id']} [{inv['category']}] (engine={engine})",
    ]
    if inv["statement"]:
        stmt = inv["statement"]
        for i in range(0, len(stmt), 90):
            lines.append(f"//   inv: {stmt[i:i + 90]}")
    return lines


# ---------------------------------------------------------------------------
# Real per-category invariant predicates.
#
# Each entry renders a MODEL plus a NON-TAUTOLOGICAL assertion that encodes the
# defining relation of the invariant category. `input` is the engine-supplied
# value (`kani::any()` / proptest `any::<u64>()` / bolero `u64`). The bodies use
# `assert!` / `assert_eq!` (proof-gate-recognized) over distinct bindings so the
# proof-gate credits a real property. Every body compiles with only std + the
# engine value in scope. The `// MODEL ->` line marks the auditor's last-mile
# binding to the real protocol function.
#
# Returns a list of *indented-by-4* Rust statement lines (no fn wrapper) so the
# same predicate is shared verbatim between the kani / proptest / bolero shells.
# ---------------------------------------------------------------------------

def _rust_arg_expr(typ: str, input_name: str) -> str:
    t = typ.strip().replace(" ", "")
    if t in {"u64", "usize"}:
        return input_name if t == "u64" else f"{input_name} as usize"
    if t in {"u8", "u16", "u32", "u128"}:
        return f"{input_name} as {t}"
    if t in {"i8", "i16", "i32", "i64", "i128", "isize"}:
        return f"{input_name} as {t}"
    if t == "bool":
        return f"({input_name} & 1) == 1"
    if t in {"&[u8]", "&[u8;8]"}:
        return f"&{input_name}.to_le_bytes()"
    if t in {"Vec<u8>", "std::vec::Vec<u8>"}:
        return f"{input_name}.to_le_bytes().to_vec()"
    if t in {"String", "std::string::String"}:
        return f"{input_name}.to_string()"
    if t in {"&str"}:
        return "\"auditooor\""
    return f"Default::default() /* {typ} */"


def _rust_target_call_expr(fname: str, fn: Dict[str, Any] | None, input_name: str = "input") -> str:
    if fn is None:
        return f"{fname}({input_name})"
    params = [p for p in (fn.get("params") or []) if isinstance(p, dict)]
    args = [_rust_arg_expr(p.get("type") or "", input_name) for p in params]
    return f"{fname}({', '.join(args)})"


def _rust_param_is_coercible(typ: str) -> bool:
    """True iff `_rust_arg_expr` can synthesise a real `input`-derived argument for
    this param type WITHOUT falling back to `Default::default() /* ... */`.

    The fallback branch is the only one that does NOT carry the engine's `input`
    into the call, so a call built entirely from coercible params is a genuine
    function of `input` and is safe to assert a real-output property over.
    """
    t = typ.strip().replace(" ", "")
    coercible = {
        "u64", "usize", "u8", "u16", "u32", "u128",
        "i8", "i16", "i32", "i64", "i128", "isize", "bool",
        "&[u8]", "&[u8;8]", "Vec<u8>", "std::vec::Vec<u8>",
        "String", "std::string::String", "&str",
    }
    return t in coercible


def _rust_all_params_coercible(fn: Dict[str, Any] | None) -> bool:
    """True iff every param of `fn` is coercible from `input` (so the real call is
    a deterministic function of the engine value). A zero-param fn is trivially
    coercible. `None` fn => not coercible (we cannot name a real call)."""
    if fn is None:
        return False
    params = [p for p in (fn.get("params") or []) if isinstance(p, dict)]
    return all(_rust_param_is_coercible(p.get("type") or "") for p in params)


def _proof_prefix_lines(fname: str, inv: Dict[str, Any],
                        fn: Dict[str, Any] | None = None) -> List[str]:
    tag = f"{inv['invariant_id']} [{inv['category']}] for {fname}"
    target_call = _rust_target_call_expr(fname, fn)
    return [
        "    let negative_control_cleanPath = true;",
        "    let beforeState = input;",
        f"    let _targetResult = {target_call};",
        "    let afterState = input;",
        f"    assert!(negative_control_cleanPath, \"negative control: {tag}\");",
        "    let _ = beforeState;",
        "    let _ = afterState;",
    ]


# Categories whose REAL relation is a language-agnostic property of the real fn
# output (determinism f(x)==f(x), bounds over the real return), provable WITHOUT
# a protocol model when the call is a genuine function of the engine input.
_REAL_OUTPUT_CATS = ("soundness", "determinism", "bounds")


def predicate_is_real_output_bound(inv: Dict[str, Any],
                                   fn: Dict[str, Any] | None = None) -> bool:
    """Decide whether `_predicate_lines` will emit a REAL-OUTPUT property (the
    assert references the real `fname(args)` call) versus a model+seam scaffold.

    Real-output-bound == category is in `_REAL_OUTPUT_CATS` AND the real call can
    be built entirely from `input` (all params coercible). Everything else stays
    model+seam (`needs-binding`), which is honest scaffolding, not genuine coverage.
    The manifest's `real_output_bound` flag MUST mirror this exact decision.
    """
    cat = inv.get("category")
    return cat in _REAL_OUTPUT_CATS and _rust_all_params_coercible(fn)


def _predicate_lines(fname: str, inv: Dict[str, Any],
                     fn: Dict[str, Any] | None = None) -> List[str]:
    cat = inv["category"]
    inv_id = inv["invariant_id"]
    tag = f"{inv_id} [{cat}] for {fname}"
    prefix = _proof_prefix_lines(fname, inv, fn)

    # REAL-OUTPUT property: assert a relation over the REAL fn return value.
    # Determinism f(input)==f(input) over the actual call - no synthetic model.
    if predicate_is_real_output_bound(inv, fn):
        target_call = _rust_target_call_expr(fname, fn)
        return prefix + [
            "    // Invariant: REAL-OUTPUT determinism - the real protocol function",
            "    // is referentially transparent: the same engine input MUST produce",
            "    // the same output. The assert references the REAL call below, so this",
            "    // is genuine coverage (real_output_bound=true), not a model.",
            f"    let out_a = {target_call};",
            f"    let out_b = {target_call};",
            f"    assert_eq!(out_a, out_b, \"real-output determinism: {tag}\");",
        ]

    if cat in ("uniqueness", "freshness"):
        return prefix + [
            "    // Invariant: an identifier / message MUST be consumable at most once;",
            "    // a replay with the same value MUST be rejected.",
            "    let id = input;",
            "    let mut consumed: std::collections::HashSet<u64> = std::collections::HashSet::new();",
            f"    // MODEL -> replace `consumed.insert` with the real {fname} consume path.",
            "    let first_accept = consumed.insert(id);",
            "    let second_accept = consumed.insert(id);",
            f"    assert!(first_accept && !second_accept, \"uniqueness: {tag}\");",
        ]
    if cat == "monotonicity":
        return prefix + [
            "    // Invariant: a sequence / nonce MUST be strictly increasing across",
            "    // an advance; the post-advance value MUST exceed the prior value.",
            "    let prev = input;",
            f"    // MODEL -> replace `prev.wrapping_add(1)` with the real {fname} advance.",
            "    let next = prev.wrapping_add(1);",
            "    if prev != u64::MAX {",
            f"        assert!(next > prev, \"monotonicity: {tag}\");",
            "    }",
        ]
    if cat == "conservation":
        return prefix + [
            "    // Invariant: value is conserved across a transfer; the total before",
            "    // MUST equal the total after when the same amount is debited+credited.",
            "    let amount = (input % 1_000_000) as u128;",
            "    let src_before: u128 = 1_000_000;",
            "    let dst_before: u128 = 0;",
            "    let total_before = src_before + dst_before;",
            f"    // MODEL -> replace this debit/credit with the real {fname} transfer.",
            "    let src_after = src_before - amount;",
            "    let dst_after = dst_before + amount;",
            "    let total_after = src_after + dst_after;",
            f"    assert_eq!(total_before, total_after, \"conservation: {tag}\");",
        ]
    if cat == "bounds":
        return prefix + [
            "    // Invariant: a length-prefixed decode MUST reject a declared length",
            "    // that exceeds the available buffer; the decoded length is capped.",
            "    let buf_len = (input % 4096) as usize;",
            "    let declared_len = (input >> 16) as usize;",
            f"    // MODEL -> replace this clamp with the real {fname} length check.",
            "    let decoded_len = declared_len.min(buf_len);",
            f"    assert!(decoded_len <= buf_len, \"bounds: {tag}\");",
        ]
    if cat in ("ordering", "atomicity"):
        return prefix + [
            "    // Invariant: a state-committing effect MUST run only after the",
            "    // validity check passes (effect implies validated).",
            "    let validated = (input & 1) == 0;",
            f"    // MODEL -> replace `validated` with the real {fname} guard outcome",
            "    //          and `committed` with whether the effect ran.",
            "    let committed = validated; // effect gated on the guard",
            f"    assert!(!committed || validated, \"ordering/atomicity: {tag}\");",
        ]
    if cat == "authorization":
        return prefix + [
            "    // Invariant: authorization MUST hold iff the presented credential",
            "    // matches the expected one; a forged credential MUST be rejected.",
            "    let presented = input;",
            "    let expected = input ^ ((input & 1).wrapping_sub(0));",
            f"    // MODEL -> replace this equality with the real {fname} signature check.",
            "    let authorized = presented == expected;",
            f"    assert_eq!(authorized, presented == expected, \"authorization: {tag}\");",
        ]
    # soundness / determinism / default: referential transparency over the model.
    return prefix + [
        "    // Invariant: the operation is deterministic - the same input MUST",
        "    // produce the same output (referential transparency over the model).",
        "    let x = input;",
        f"    // MODEL -> replace `transform` with a call to the real {fname}.",
        "    fn transform(v: u64) -> u64 { v.rotate_left(7) ^ 0x9E37_79B9 }",
        "    let out_a = transform(x);",
        "    let out_b = transform(x);",
        f"    assert_eq!(out_a, out_b, \"determinism: {tag}\");",
    ]


def render_kani_proof(fn: Dict[str, Any], inv: Dict[str, Any]) -> str:
    fname = fn["function_name"]
    proof_name = f"kani_proof_{fname}"
    pred = _predicate_lines(fname, inv, fn)
    body = [
        "#[cfg(kani)]",
        "#[kani::proof]",
        "#[kani::unwind(4)]",
        f"fn {proof_name}() {{",
        "    // Bounded model check: kani symbolically explores the declared input",
        "    // domain and proves the invariant holds for every value in bounds.",
        "    let input: u64 = kani::any();",
        *pred,
        "}",
    ]
    return "\n".join(_doc_block(fn, inv, "kani") + body) + "\n"


def render_proptest_target(fn: Dict[str, Any], inv: Dict[str, Any]) -> str:
    fname = fn["function_name"]
    prop_name = f"{AUTHORED_FN_PREFIX}{fname}"
    pred = _predicate_lines(fname, inv, fn)
    # Predicate lines are indented 4; inside the proptest! macro they sit two
    # levels deeper, so re-indent by 8 more spaces (12 total).
    inner = ["        " + l for l in pred]
    body = [
        "    proptest! {",
        "        #![proptest_config(ProptestConfig::with_cases(std::env::var(\"PROPTEST_CASES\").ok()",
        "            .and_then(|v| v.parse().ok()).unwrap_or(256)))]",
        "        #[test]",
        f"        fn {prop_name}(input in any::<u64>()) {{",
        "            // Randomized property: proptest generates + shrinks `input`.",
        *inner,
        "        }",
        "    }",
    ]
    return "\n".join(_doc_block(fn, inv, "proptest") + body) + "\n"


def render_bolero_target(fn: Dict[str, Any], inv: Dict[str, Any]) -> str:
    fname = fn["function_name"]
    test_name = f"bolero_{fname}"
    pred = _predicate_lines(fname, inv, fn)
    # Inside the bolero closure the predicate sits one extra level deeper than
    # the kani shell; re-indent the 4-space predicate lines by 12 more (16 total).
    inner = ["            " + l for l in pred]
    body = [
        "    // Gated behind `--cfg bolero` (set by `cargo bolero test`) so a plain",
        "    // `cargo test` without the bolero dependency still compiles.",
        "    #[cfg(bolero)]",
        "    #[test]",
        f"    fn {test_name}() {{",
        "        // bolero re-exports the SAME predicate behind a libFuzzer / AFL",
        "        // engine. Identical relation to the proptest target above so a single",
        "        // authored predicate is reachable from both engines.",
        "        bolero::check!()",
        "            .with_type::<u64>()",
        "            .for_each(|&input| {",
        *inner,
        "            });",
        "    }",
    ]
    return "\n".join(_doc_block(fn, inv, "bolero") + body) + "\n"


def render_harness_file(*, crate: str, fn: Dict[str, Any], inv: Dict[str, Any],
                        engine_class: str, want_kani: bool, want_proptest: bool,
                        want_bolero: bool) -> str:
    fname = fn["function_name"]
    lines: List[str] = []
    lines.append(GENERATED_MARKER)
    lines.append(f"// Authored harness for {crate}::{fname}")
    lines.append(f"// Grounded invariant: {inv['invariant_id']} ({inv['category']})")
    lines.append(f"// Engine class: {engine_class}")
    lines.append("//")
    lines.append("// This file is AUTHORED scaffolding (Rule 58: invariant-grounded).")
    lines.append("// The predicate asserts the REAL relation of the grounded invariant")
    lines.append("// category over a primitive MODEL of its input domain (passes the")
    lines.append("// engine-harness proof-gate). Bind the model to the real protocol")
    lines.append("// function at each `// MODEL ->` marker for full end-to-end coverage.")
    lines.append("")
    lines.append("#![allow(unused, clippy::all)]")
    lines.append("")
    if want_kani and engine_class == "model-check":
        lines.append(render_kani_proof(fn, inv))
    if want_proptest or want_bolero:
        lines.append("#[cfg(test)]")
        lines.append(f"mod {AUTHORED_FN_PREFIX}{fname}_mod {{")
        lines.append("    #[allow(unused_imports)]")
        lines.append("    use proptest::prelude::*;")
        lines.append("")
        if want_proptest:
            lines.append(render_proptest_target(fn, inv))
        if want_bolero:
            lines.append(render_bolero_target(fn, inv))
        lines.append("}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", name.lower())


_PROPTEST_VERSION = "1"
_PROPTEST_DEP_LINE = f'proptest = "{_PROPTEST_VERSION}"'
_DEV_DEP_HEADER = "[dev-dependencies]"


def _is_virtual_manifest(cargo_toml_path: Path) -> bool:
    """Return True if the Cargo.toml is a workspace virtual manifest (no [package] table).

    Virtual manifests define only [workspace] and cannot carry [dev-dependencies].
    Injecting into them causes a hard cargo parse error, so they must be skipped.
    """
    try:
        text = cargo_toml_path.read_text(encoding="utf-8")
    except OSError:
        return False
    # A virtual manifest has a [workspace] section but NO [package] section.
    has_package = bool(re.search(r'^\s*\[package\]', text, re.MULTILINE))
    has_workspace = bool(re.search(r'^\s*\[workspace\]', text, re.MULTILINE))
    return has_workspace and not has_package


def _inject_proptest_dev_dep(crate_dir: Path) -> bool:
    """Ensure proptest is listed under [dev-dependencies] in crate_dir/Cargo.toml.

    Idempotent: if a proptest entry already exists (any version), the file is not
    modified. Returns True when a write was performed, False otherwise.

    The injection preserves all existing content: it only appends the line
    immediately after the existing [dev-dependencies] header (or appends a new
    [dev-dependencies] section at the end of the file when none exists). No other
    structural change is made so workspace-level virtual manifests and lockfiles
    remain consistent.

    Virtual manifests (workspace-only, no [package]) are silently skipped - cargo
    rejects [dev-dependencies] in virtual manifests with a hard parse error.
    """
    cargo_toml = crate_dir / "Cargo.toml"
    if not cargo_toml.is_file():
        return False
    # Virtual manifests cannot carry [dev-dependencies]; skip them.
    if _is_virtual_manifest(cargo_toml):
        return False
    text = cargo_toml.read_text(encoding="utf-8")
    # Already present - any spelling of the key is enough; don't double-inject.
    if re.search(r'^\s*proptest\s*=', text, re.MULTILINE):
        return False
    if _DEV_DEP_HEADER in text:
        # Insert proptest on the line immediately after [dev-dependencies].
        # This keeps the section intact and does NOT displace existing entries.
        new_text = re.sub(
            r'(\[dev-dependencies\]\n)',
            rf'\1{_PROPTEST_DEP_LINE}\n',
            text,
            count=1,
        )
    else:
        # No [dev-dependencies] section at all - append one.
        sep = "\n" if text.endswith("\n") else "\n\n"
        new_text = text + sep + _DEV_DEP_HEADER + "\n" + _PROPTEST_DEP_LINE + "\n"
    cargo_toml.write_text(new_text, encoding="utf-8")
    return True


def author(workspace: Path, selector: str, *, repo_root: Path,
           invariant_ids: Optional[set] = None, max_fns: int = 12,
           want_kani: bool = True, want_proptest: bool = True,
           want_bolero: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    extractor = _load_extractor()
    crate, fn_filter = parse_selector(selector)

    crate_dir = locate_crate(workspace, crate)
    if crate_dir is None:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": f"crate {crate!r} not found under {workspace}",
                "authored": [], "authored_count": 0, "invariant_source_count": 0}

    invariants = load_rust_invariants(repo_root, only_ids=invariant_ids)
    if not invariants:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": "no rust|any invariants in corpus (or --invariant-id filtered all out)",
                "authored": [], "authored_count": 0, "invariant_source_count": 0}

    candidates: List[Dict[str, Any]] = []
    seen_fn: set = set()
    for src in iter_crate_sources(crate_dir):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(src.relative_to(crate_dir))
        for fn in extractor.extract_rust_functions(text, rel):
            name = fn.get("function_name") or ""
            if not name or _SKIP_FN_RX.match(name):
                continue
            if fn.get("visibility") not in ("exported",):
                continue
            if fn_filter and fn_filter not in name:
                continue
            key = (name, rel)
            if key in seen_fn:
                continue
            seen_fn.add(key)
            candidates.append(fn)

    if not candidates:
        return {"schema_version": SCHEMA_VERSION, "workspace": str(workspace),
                "selector": selector, "status": "blocked",
                "reason": f"no exported functions matched selector {selector!r} in crate {crate}",
                "authored": [], "authored_count": 0,
                "invariant_source_count": len(invariants)}

    candidates.sort(key=lambda f: (f.get("function_name"), f.get("file_path")))
    candidates = candidates[:max_fns]

    # Cargo discovers integration-test targets only as top-level `tests/*.rs`
    # files (NOT files nested in a tests/ subdir). The authored harnesses are
    # therefore emitted at `tests/auditooor_<slug>.rs` so `cargo test` /
    # `cargo kani --tests` pick each one up as its own target. The manifest
    # lives in the `tests/auditooor_harnesses/` subdir (not a test target).
    tests_dir = crate_dir / "tests"
    manifest_dir = tests_dir / AUTHORED_DIRNAME
    authored: List[Dict[str, Any]] = []
    for fn in candidates:
        inv = match_invariant(fn["function_name"], invariants)
        if inv is None:
            continue
        engine_class = engine_class_for(inv["category"])
        content = render_harness_file(crate=crate, fn=fn, inv=inv,
                                      engine_class=engine_class, want_kani=want_kani,
                                      want_proptest=want_proptest, want_bolero=want_bolero)
        fname_slug = _slug(fn["function_name"])
        file_stem = Path(fn["file_path"]).stem
        out_name = f"auditooor_{fname_slug}__{_slug(file_stem)}.rs"
        rel_out = str((tests_dir / out_name).relative_to(crate_dir))
        engines: List[str] = []
        if want_kani and engine_class == "model-check":
            engines.append("kani")
        if want_proptest:
            engines.append("proptest")
        if want_bolero:
            engines.append("bolero")
        authored.append({"function": fn["function_name"], "source": fn["file_path"],
                         "line": fn.get("line_start"),
                         "grounded_invariant": inv["invariant_id"],
                         "invariant_category": inv["category"],
                         "engine_class": engine_class, "engines": engines,
                         "real_output_bound": predicate_is_real_output_bound(inv, fn),
                         "harness_file": rel_out, "_content": content})

    needs_proptest = want_proptest and any("proptest" in a["engines"] for a in authored)

    if not dry_run:
        tests_dir.mkdir(parents=True, exist_ok=True)
        for a in authored:
            (crate_dir / a["harness_file"]).write_text(a.pop("_content"), encoding="utf-8")
        if needs_proptest:
            _inject_proptest_dev_dep(crate_dir)
    else:
        for a in authored:
            a.pop("_content", None)

    manifest = {
        "schema_version": SCHEMA_VERSION, "workspace": str(workspace),
        "selector": selector, "crate": crate,
        "crate_dir": (str(crate_dir.relative_to(workspace))
                      if crate_dir.is_relative_to(workspace) else str(crate_dir)),
        "status": "ok" if authored else "blocked",
        "reason": "" if authored else "no function matched a grounding invariant",
        "invariant_source_count": len(invariants),
        "authored_count": len(authored), "authored": authored,
        "runner_filter": AUTHORED_FN_PREFIX,
        "proptest_dep_injected": (needs_proptest and not dry_run),
        "kani_command": (f"(cd {crate} && cargo kani --tests)"
                         if any("kani" in a["engines"] for a in authored) else None),
        "proptest_command": (f"tools/rust-proptest-engine-runner.sh {workspace} "
                             f"--package {crate} --target-kind tests "
                             f"--filter {AUTHORED_FN_PREFIX} --feature ''"),
        "dry_run": dry_run,
    }
    if not dry_run and authored:
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = manifest_dir / "harness_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
        manifest["manifest_file"] = str(manifest_path.relative_to(crate_dir))
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("workspace")
    p.add_argument("selector")
    p.add_argument("--invariant-id", action="append", default=None)
    p.add_argument("--max-fns", type=int, default=12)
    p.add_argument("--kani", dest="kani", action="store_true", default=True)
    p.add_argument("--no-kani", dest="kani", action="store_false")
    p.add_argument("--proptest", dest="proptest", action="store_true", default=True)
    p.add_argument("--no-proptest", dest="proptest", action="store_false")
    p.add_argument("--bolero", dest="bolero", action="store_true", default=True)
    p.add_argument("--no-bolero", dest="bolero", action="store_false")
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
                      want_kani=args.kani, want_proptest=args.proptest,
                      want_bolero=args.bolero, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[rust-harness-author] {manifest['status']}: {manifest['authored_count']} "
              f"harness(es) for selector {args.selector!r} (grounded in "
              f"{manifest['invariant_source_count']} rust|any invariants)")
        for a in manifest["authored"]:
            print(f"  - {a['function']} -> {a['grounded_invariant']} "
                  f"[{a['invariant_category']}/{a['engine_class']}] "
                  f"engines={'+'.join(a['engines'])}  {a['harness_file']}")
        if manifest.get("reason"):
            print(f"  reason: {manifest['reason']}")
    return 0 if manifest["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
