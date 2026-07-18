#!/usr/bin/env python3
"""
detector-lint.py — best-effort static linter for auditooor detectors.

Scans:
  - detectors/rust_wave1/*.py         (hand-written tree-sitter-rust detectors)
  - detectors/wave17/*.py             (DSL-compiled Slither detectors)
  - detectors/rust_wave1/test_fixtures/test_detectors.sh
  - detectors/_specs/drafts_*/*.yaml  (DSL YAML specs)
  - tools/parity-report.py            (BUG_CLASSES table)
  - reference/patterns.dsl/*.yaml     (corpus DSL — function.kind sanity)
  - detectors/_predicate_engine.py    (allowed values source-of-truth)

Emits one report section per check; prints count + top-5 examples per category.
Never crashes on unparseable input — unreadable files are counted and skipped.

Usage:
    python3 tools/detector-lint.py                # human-readable to stdout
    python3 tools/detector-lint.py --md > docs/archive/DETECTOR_LINT_REPORT.md
    python3 tools/detector-lint.py --fail-placeholder-fp-guards
    python3 tools/detector-lint.py --fail-high-tier-placeholder-fp-guards
    python3 tools/detector-lint.py --fail-high-tier-regex-only
    python3 tools/detector-lint.py --fail-unknown-function-kind
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
RUST_WAVE1 = ROOT / "detectors" / "rust_wave1"
WAVE17 = ROOT / "detectors" / "wave17"
WAVE18 = ROOT / "detectors" / "wave18"
FIXTURE_DIR = RUST_WAVE1 / "test_fixtures"
TEST_SCRIPT = FIXTURE_DIR / "test_detectors.sh"
SPEC_DIRS = list((ROOT / "detectors" / "_specs").glob("drafts_*"))
PARITY_REPORT = ROOT / "tools" / "parity-report.py"
PREDICATE_ENGINE = ROOT / "detectors" / "_predicate_engine.py"
PATTERNS_DSL_DIR = ROOT / "reference" / "patterns.dsl"

TOP_N = 5

_SEMANTIC_PREDICATE_KEYS = {
    "contract.has_external_call_to",
    "contract.has_mapping",
    "function.ast",
    "function.not_ast",
    "function.taints_param_to",
    "function.reaches_external",
    "function.has_param_mapping",
    "function.has_param_struct_named",
    "function.has_high_level_call_named",
    "function.has_low_level_call",
    "function.reads_msg_sender",
    "function.reads_tx_origin",
    "function.reads_block_timestamp",
    "function.reads_block_number",
    "function.emits_event_matching",
    "function.has_require_mentioning",
    "function.computes_keccak",
    "function.has_external_call_without_guard",
    "function.is_self_scoped_mapping_write",
}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _iter_detectors(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(
        p for p in folder.glob("*.py")
        if not p.name.startswith("_") and p.name != "__init__.py"
    )


# ─── Check 1: rust_wave1 detectors without a matching fixture pair ──────────
def check_missing_fixtures() -> list[str]:
    detectors = _iter_detectors(RUST_WAVE1)
    missing: list[str] = []
    if not FIXTURE_DIR.is_dir():
        return missing
    fixtures = {p.name for p in FIXTURE_DIR.glob("*.rs")}
    for det in detectors:
        stem = det.stem
        # DRAFT detectors are auto-generated stubs — not ready for regression testing
        if stem.startswith("DRAFT_"):
            continue
        pos = f"{stem}_positive.rs"
        neg = f"{stem}_negative.rs"
        if pos not in fixtures or neg not in fixtures:
            gap = []
            if pos not in fixtures:
                gap.append("positive")
            if neg not in fixtures:
                gap.append("negative")
            missing.append(f"{stem} (missing: {','.join(gap)})")
    return missing


# ─── Check 2: mismatch between test_detectors.sh and on-disk detectors ───────
_SH_ENTRY = re.compile(r"^\s+([a-zA-Z_][a-zA-Z_0-9]+)\s*$")
_SH_KEYWORDS = {
    "continue", "done", "else", "fi", "then", "esac", "do", "exit",
    "return", "break", "true", "false", "shift", "set",
}


def check_script_disk_mismatch() -> tuple[list[str], list[str]]:
    """Returns (in_script_not_on_disk, on_disk_not_in_script)."""
    script_entries: set[str] = set()
    in_array = False
    for line in _read(TEST_SCRIPT).splitlines():
        stripped = line.strip()
        if "DETECTORS=(" in line:
            in_array = True
            continue
        if in_array and stripped == ")":
            in_array = False
            continue
        if not in_array:
            continue
        if not stripped or stripped.startswith("#"):
            continue
        m = _SH_ENTRY.match(line)
        if m and m.group(1) not in _SH_KEYWORDS:
            script_entries.add(m.group(1))
    disk_entries = {
        p.stem for p in _iter_detectors(RUST_WAVE1)
        if not p.stem.startswith("DRAFT_")
    }
    missing_on_disk = sorted(script_entries - disk_entries)
    missing_in_script = sorted(disk_entries - script_entries)
    return missing_on_disk, missing_in_script


# ─── Check 3: module docstring <50 chars ────────────────────────────────────
def check_terse_docstrings() -> list[str]:
    terse: list[tuple[str, int]] = []
    for folder_name, folder in (("rust_wave1", RUST_WAVE1), ("wave17", WAVE17)):
        for det in _iter_detectors(folder):
            src = _read(det)
            if not src:
                continue
            try:
                mod = ast.parse(src)
                doc = ast.get_docstring(mod) or ""
            except SyntaxError:
                doc = ""  # best-effort
            if len(doc.strip()) < 50:
                terse.append((f"{folder_name}/{det.name}", len(doc.strip())))
    terse.sort(key=lambda t: t[1])
    return [f"{name} (doc len={n})" for name, n in terse]


# ─── Check 4: DSL YAML specs missing cross_refs or tags ─────────────────────
def check_yaml_missing_fields() -> list[str]:
    missing: list[str] = []
    for spec_dir in SPEC_DIRS:
        for yaml_path in spec_dir.rglob("*.yaml"):
            text = _read(yaml_path)
            if not text:
                continue
            has_cross = bool(re.search(r"^\s*cross_refs\s*:", text, re.M))
            has_tags = bool(re.search(r"^\s*tags\s*:", text, re.M))
            if not has_cross or not has_tags:
                gap = []
                if not has_cross:
                    gap.append("cross_refs")
                if not has_tags:
                    gap.append("tags")
                rel = yaml_path.relative_to(ROOT)
                missing.append(f"{rel} (missing: {','.join(gap)})")
    return missing


# ─── Check 4b: generated placeholder FP guards still present ───────────────
# These values are generator scaffolding, not evidence-bearing clean-codebase
# suppressors. They are useful as TODO markers, but Tier-S/A promotion should
# fail closed if a detector still depends on them after FP calibration.
_PLACEHOLDER_FP_GUARD_FIELDS: dict[str, tuple[str, ...]] = {
    "guarded_helper_name": ("_accrue", "_guard"),
    "guard_require_line": ("require(newVal <= 10000",),
    "guard_var_regex": (
        ".*(balance|amount|total|supply|reserve).*",
        ".*(admin|owner|balance|amount).*",
    ),
}
_YAML_SCALAR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*(?:#.*)?$")
_HIGH_TIER_RE = re.compile(r"^\s*tier\s*:\s*['\"]?([SA])['\"]?\s*(?:#.*)?$", re.I | re.M)


def _strip_yaml_scalar(raw: str) -> str:
    """Return a normalized one-line YAML scalar for lint heuristics."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value.strip()


def placeholder_fp_guard_usages(
    spec_dirs: Iterable[Path] | None = None,
    *,
    high_tier_only: bool = False,
) -> list[tuple[Path, int, str, str, str]]:
    """Yield placeholder FP-guard fields in generated detector specs.

    Returns tuples of `(path, lineno, field, value, reason)` so callers can
    either summarize by cohort or fail closed with precise line references.
    `high_tier_only` narrows the scan to Tier-S/A specs, which is the
    promotion-risk subset P1-4 needs CI to fail on before the full legacy
    generated backlog is cleaned up.
    """
    dirs = list(spec_dirs) if spec_dirs is not None else SPEC_DIRS
    hits: list[tuple[Path, int, str, str, str]] = []
    for spec_dir in dirs:
        if not spec_dir.is_dir():
            continue
        for yaml_path in sorted(spec_dir.rglob("*.yaml")):
            text = _read(yaml_path)
            if not text:
                continue
            if high_tier_only and not _HIGH_TIER_RE.search(text):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                m = _YAML_SCALAR_RE.match(line)
                if not m:
                    continue
                field, raw_value = m.group(1), m.group(2)
                needles = _PLACEHOLDER_FP_GUARD_FIELDS.get(field)
                if not needles:
                    continue
                value = _strip_yaml_scalar(raw_value)
                for needle in needles:
                    if needle in value:
                        reason = (
                            "generator placeholder — replace with an "
                            "evidence-backed guard or path-specific clean "
                            "corpus suppressor before Tier-S/A promotion"
                        )
                        hits.append((yaml_path, lineno, field, value, reason))
                        break
    return hits


def check_placeholder_fp_guards(
    spec_dirs: Iterable[Path] | None = None,
    *,
    high_tier_only: bool = False,
) -> list[str]:
    hits: list[str] = []
    for path, lineno, field, value, reason in placeholder_fp_guard_usages(
        spec_dirs,
        high_tier_only=high_tier_only,
    ):
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        hits.append(f"{rel}:{lineno}: {field}: {value!r} — {reason}")
    return hits


# ─── Check 4c: Tier-S/A DSL patterns still relying on regex-only shapes ─────
_TIER_RE = re.compile(r"^\s*tier\s*:\s*['\"]?([A-Za-z])['\"]?\s*(?:#.*)?$", re.M)
_STATUS_DOC_ONLY_RE = re.compile(
    r"^\s*status\s*:\s*['\"]?documentation-only['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)
_PREDICATE_KEY_RE = re.compile(r"^\s*-?\s*([A-Za-z][A-Za-z0-9_.]*)\s*:", re.M)
_REGEX_PREDICATE_RE = re.compile(
    r"^\s*-?\s*(?:contract|function)\.(?:not_)?(?:body_|source_)?"
    r"(?:contains_)?(?:matches_)?regex\s*:",
    re.M,
)


def high_tier_regex_only_usages(dsl_dir: Path = PATTERNS_DSL_DIR) -> list[tuple[Path, str, list[str]]]:
    """Return Tier-S/A DSL files with regex predicates but no semantic/AST predicate.

    This is an inventory guard for P1-1: it does not claim regex patterns are
    wrong, only that high-tier promotion should explain why no semantic/AST
    predicate is available.
    """
    hits: list[tuple[Path, str, list[str]]] = []
    if not dsl_dir.is_dir():
        return hits
    for yaml_path in sorted(dsl_dir.glob("*.yaml")):
        text = _read(yaml_path)
        if not text or _STATUS_DOC_ONLY_RE.search(text):
            continue
        tier_match = _TIER_RE.search(text)
        if not tier_match:
            continue
        tier = tier_match.group(1).upper()
        if tier not in {"S", "A"}:
            continue
        if not _REGEX_PREDICATE_RE.search(text):
            continue
        keys = sorted(set(_PREDICATE_KEY_RE.findall(text)))
        if any(key in _SEMANTIC_PREDICATE_KEYS for key in keys):
            continue
        hits.append((yaml_path, tier, keys))
    return hits


def check_high_tier_regex_only(dsl_dir: Path = PATTERNS_DSL_DIR) -> list[str]:
    hits: list[str] = []
    for path, tier, keys in high_tier_regex_only_usages(dsl_dir):
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        preview = ", ".join(keys[:6]) or "no predicate keys parsed"
        hits.append(
            f"{rel}: tier {tier} uses regex predicates without semantic/AST "
            f"predicate; parsed keys: {preview}"
        )
    return hits


# ─── Check 5: BUG_CLASS entries in parity-report.py with rust_only or sol_only
# Item-#6 burn-down: this check now honours the `deliberate: true` field +
# `rationale` text added to platform-only BUG_CLASSES entries. Deliberate
# rows do NOT count as gaps. Only true forward/reverse-port gaps (status
# `GAP_RUST` / `GAP_SOLIDITY` — `applies_to: both` with one side empty)
# and platform-only rows lacking a deliberate flag (i.e. suspect
# misclassifications) are surfaced.
#
# Implementation invokes `parity-report.py --json` so the canonical
# classification logic is reused (no double-source-of-truth regex).
def check_parity_gaps() -> list[str]:
    return _parity_gap_rows()["display"]


def _parity_gap_rows(parity_script: Path | None = None) -> dict:
    """Return {'display': [...], 'real_gaps': [...], 'suspect_platform_only': [...]}.

    `parity_script` override is used by `tools/tests/test_parity_report.py` to
    substitute a tiny fixture script while exercising the exclusion logic.
    """
    import json as _json
    import subprocess

    script = parity_script if parity_script is not None else PARITY_REPORT
    try:
        proc = subprocess.run(
            ["python3", str(script), "--json"],
            check=True, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.SubprocessError, OSError):
        return {"display": [], "real_gaps": [], "suspect_platform_only": []}
    try:
        report = _json.loads(proc.stdout)
    except _json.JSONDecodeError:
        return {"display": [], "real_gaps": [], "suspect_platform_only": []}

    real_gaps: list[str] = []
    suspect_platform_only: list[str] = []
    for r in report.get("rows", []):
        status = r.get("status", "")
        if status in ("GAP_RUST", "GAP_SOLIDITY"):
            real_gaps.append(f"{r['bug_class']} [{status}]")
        elif status.startswith("PLATFORM_ONLY") and not r.get("deliberate", False):
            suspect_platform_only.append(
                f"{r['bug_class']} [{r['applies_to']} — missing deliberate:true / rationale]"
            )
    display = real_gaps + suspect_platform_only
    return {
        "display": display,
        "real_gaps": real_gaps,
        "suspect_platform_only": suspect_platform_only,
    }


# ─── Check 6: regex literals using [\w] instead of \w ───────────────────────
_BAD_WCLASS = re.compile(r"\[\\w\]")


def check_bad_wclass() -> list[str]:
    hits: list[str] = []
    for folder_name, folder in (("rust_wave1", RUST_WAVE1), ("wave17", WAVE17)):
        for det in _iter_detectors(folder):
            src = _read(det)
            if not src:
                continue
            for lineno, line in enumerate(src.splitlines(), 1):
                if _BAD_WCLASS.search(line):
                    hits.append(f"{folder_name}/{det.name}:{lineno}: {line.strip()[:100]}")
    return hits


# ─── Check 7: function.kind values not recognized by _predicate_engine.py ──
# PR #121 follow-up (Codex batch review issue 4319734390): the engine only
# special-cases `external_or_public` and `any` for `function.kind`; everything
# else falls through to exact-equality on the raw visibility string. Composite
# values like `external_or_public_or_internal` therefore silently evaluate
# False and the detector emits zero hits — with no warning. This check
# enumerates the recognized values directly from the engine source so the
# allowed set stays in sync with the engine; any DSL file using something
# unrecognized is flagged HIGH.

# The function.kind handler is the only block in _predicate_engine.py that
# branches on string-literal values for this key. We extract those literals
# rather than hard-coding the set, so that if the engine is later extended
# to honor a new composite (Codex Part-3 call), the lint stays in sync
# automatically.
_FUNCTION_KIND_BLOCK = re.compile(
    r'if\s+key\s*==\s*"function\.kind"\s*:\s*(.*?)(?=\n\s*if\s+key\s*==|\Z)',
    re.DOTALL,
)
_FUNCTION_KIND_LITERAL = re.compile(r'val\s*==\s*"([^"]+)"')
_FUNCTION_KIND_FALLBACK_HINT = re.compile(r'return\s+vis\s*==\s*val')
# PR #140 Part 3: engine now also recognizes pure visibility composites
# joined by `_or_` (and the legacy pipe typo `internal|external_or_public`
# normalized via split-on-`|`). The lint mirrors the engine's recognition
# logic via `_VIS_TOKENS` + `_engine_recognizes_visibility_composite` below.
_FUNCTION_KIND_COMPOSITE_HINT = re.compile(
    r'_VIS_TOKENS\s*=\s*\{[^}]*"external"[^}]*"public"[^}]*"internal"[^}]*"private"[^}]*\}'
)
# Atomic visibilities are the values `vis = function.visibility` can take.
# Documented in _predicate_engine.py at `_function_kind` (lines 53-55).
_ATOMIC_VISIBILITY = {"external", "public", "internal", "private"}


def _engine_recognizes_visibility_composite(val: str) -> bool:
    """Mirror the engine's `_or_`/`|` composite dispatch (PR #140 Part 3).

    Returns True iff `val` is a pure visibility composite formed by joining
    2+ tokens from `_ATOMIC_VISIBILITY` with `_or_` separators (with optional
    `|` boundaries — only the legacy `internal|external_or_public` typo).
    """
    if not isinstance(val, str) or ("_or_" not in val and "|" not in val):
        return False
    tokens: list[str] = []
    for piece in val.split("|"):
        for tok in piece.split("_or_"):
            tok = tok.strip()
            if tok in _ATOMIC_VISIBILITY:
                tokens.append(tok)
            else:
                return False
    return len(tokens) >= 2


def recognized_function_kind_values(engine_source: str | None = None) -> set[str]:
    """Return the set of function.kind values the predicate engine recognizes.

    Parsed from detectors/_predicate_engine.py rather than hard-coded so that
    extending the engine (e.g. honoring `external_or_public_or_internal` by
    splitting on `_or_`) automatically widens the allowed set.

    The recognized set = composite literals special-cased inside the
    function.kind handler, plus the atomic visibility values that the
    fallback `return vis == val` branch can match. Note: the dynamic
    visibility-composite dispatch added in PR #140 Part 3 cannot be
    enumerated as a finite set (infinite composites of 4 tokens). Callers
    that need to validate a single value should use `is_recognized_function_kind_value`.
    """
    src = engine_source if engine_source is not None else _read(PREDICATE_ENGINE)
    if not src:
        return set()
    m = _FUNCTION_KIND_BLOCK.search(src)
    if not m:
        return set()
    block = m.group(1)
    composites = set(_FUNCTION_KIND_LITERAL.findall(block))
    recognized = set(composites)
    # If the handler ends with `return vis == val`, then atomic visibilities
    # are accepted via the fallback branch.
    if _FUNCTION_KIND_FALLBACK_HINT.search(block):
        recognized |= _ATOMIC_VISIBILITY
    return recognized


def is_recognized_function_kind_value(val: str, engine_source: str | None = None) -> bool:
    """Return True iff the engine will honor `val` for `function.kind:`.

    Combines:
      - the static set from `recognized_function_kind_values` (atomic
        visibilities + special-cased composites like `external_or_public`,
        `any`)
      - the PR #140 Part 3 dynamic dispatch for pure visibility composites
        joined with `_or_` (validated only when the engine source contains
        the matching `_VIS_TOKENS` block, so the lint stays in sync with
        the engine even if Part 3 is reverted).
    """
    if val in recognized_function_kind_values(engine_source=engine_source):
        return True
    src = engine_source if engine_source is not None else _read(PREDICATE_ENGINE)
    if src and _FUNCTION_KIND_COMPOSITE_HINT.search(src):
        return _engine_recognizes_visibility_composite(val)
    return False


_FUNCTION_KIND_USAGE = re.compile(r'^\s*-?\s*function\.kind\s*:\s*(.+?)\s*(#.*)?$')

# ─── Backend split (closes the I20-domain-marker FP class) ──────────────────
# A YAML pattern can declare `backend: <name>` at the root to mark the
# detector as targeting a non-Solidity engine. The Solidity-shaped lint
# checks (function.kind, regex-only Tier-S/A, placeholder FP guards) only
# apply when `backend` is "solidity" (the default — preserves all existing
# Solidity rows verbatim).
#
# Recognized backends:
#   - solidity            (default; Slither IR)
#   - rust                (rust_wave1 tree-sitter)
#   - cosmos              (Cosmos SDK Go handlers)
#   - anchor              (Solana Anchor instructions)
#   - reth                (reth/op-reth/base-reth Rust execution-engine)
#   - geth_runtime        (Geth/EVM Go runtime)
#   - circom              (Circom + Rust circuit code)
#   - vyper               (reserved)
#   - documentation_only  (no engine; pattern is a tracked observation)
#
# This is the schema-side fix referenced by the cross-cutting "split DSL by
# backend" suggestion in the 2026-04-29 Codex handover. Adding a new backend
# is a constant-list edit here + at the engine wiring point.
VALID_BACKENDS = {
    "solidity",
    "rust",
    "cosmos",
    "anchor",
    "reth",
    "geth_runtime",
    "circom",
    "vyper",
    "documentation_only",
}
NON_SOLIDITY_BACKENDS = VALID_BACKENDS - {"solidity"}

_BACKEND_RE = re.compile(r"^\s*backend\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:#.*)?$", re.M)


def yaml_backend(path: Path) -> str:
    """Return the declared `backend:` value for a DSL file, or 'solidity'.

    Only matches the root-level scalar form `backend: <name>`. The match is
    fail-closed: if the value isn't an identifier we recognize at the
    schema layer, we still return the raw token so the per-backend lint
    can flag it as unknown.
    """
    text = _read(path)
    if not text:
        return "solidity"
    m = _BACKEND_RE.search(text)
    if not m:
        return "solidity"
    return m.group(1).strip()


def _is_solidity_backend(path: Path) -> bool:
    return yaml_backend(path) == "solidity"


def function_kind_usages(dsl_dir: Path = PATTERNS_DSL_DIR) -> list[tuple[Path, int, str]]:
    """Yield (path, lineno, raw_value) for every function.kind: <value> in DSL."""
    out: list[tuple[Path, int, str]] = []
    if not dsl_dir.is_dir():
        return out
    for yaml_path in sorted(dsl_dir.glob("*.yaml")):
        text = _read(yaml_path)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            m = _FUNCTION_KIND_USAGE.match(line)
            if not m:
                continue
            raw = m.group(1).strip().strip('"').strip("'")
            if not raw:
                # `function.kind:` with no value — caller (eval_function_match)
                # will skip; treat as missing/None and pass.
                continue
            out.append((yaml_path, lineno, raw))
    return out


_STATE_MUTABILITY_TOKENS = {"view", "pure", "payable", "nonpayable"}


def _classify_unknown_function_kind(val: str) -> str:
    """Return a short hint explaining why `val` is unrecognized.

    Keeps the lint message specific enough that authors can act on it
    without re-reading the engine source.
    """
    pieces: list[str] = []
    for piece in (val or "").split("|"):
        pieces.extend(piece.split("_or_"))
    pieces = [p.strip() for p in pieces if p.strip()]
    # Detect state-mutability tokens, including ones glued onto a visibility
    # via underscore (e.g. `internal_view` inside `external_or_public_or_internal_view`).
    def _has_state_mutability(p: str) -> bool:
        if p in _STATE_MUTABILITY_TOKENS:
            return True
        for sm in _STATE_MUTABILITY_TOKENS:
            if p.endswith(f"_{sm}") or p.startswith(f"{sm}_"):
                return True
        return False
    if any(_has_state_mutability(p) for p in pieces):
        return ("mixes visibility + state-mutability — split into separate "
                "function.kind: + function.state_mutability: predicates, or "
                "add an explicit rationale and widen intentionally")
    if not pieces or any(p not in _ATOMIC_VISIBILITY for p in pieces):
        return ("unrecognized token(s) — non-Solidity / domain marker; move "
                "to an appropriate backend or rewrite/drop case-by-case")
    return "fewer than 2 visibility tokens — drop the composite syntax"


def _safe_relative_to_root(path: Path) -> Path | str:
    """Return path-relative-to-ROOT when possible, else the absolute path.

    Test fixtures live in tempdirs outside ROOT; relative_to would raise.
    """
    try:
        return path.relative_to(ROOT)
    except ValueError:
        return path


def check_function_kind_unknown(dsl_dir: Path | None = None) -> list[str]:
    """Flag any DSL file using a function.kind value the engine won't honor.

    Backend-aware (cross-cut from the 2026-04-29 Codex handover): rows that
    declare a non-Solidity `backend:` (cosmos, anchor, rust, geth_runtime,
    circom, etc.) intentionally use domain-specific function-kind tokens
    that the Solidity Slither-IR engine cannot evaluate. Those tokens are
    documentation/markers for a future per-backend engine, not silent
    no-ops in the Solidity engine: the Solidity engine never loads them
    because the contract.* preconditions don't match. So this check only
    flags rows where `backend: solidity` (the default).
    """
    recognized = recognized_function_kind_values()
    if not recognized:
        # Engine source unreadable — fail-loud rather than silently passing.
        return ["<predicate engine source unreadable — cannot validate "
                "function.kind values; check detectors/_predicate_engine.py>"]
    target_dir = dsl_dir if dsl_dir is not None else PATTERNS_DSL_DIR
    hits: list[str] = []
    for path, lineno, val in function_kind_usages(dsl_dir=target_dir):
        if is_recognized_function_kind_value(val):
            continue
        if not _is_solidity_backend(path):
            # Non-Solidity row — the function.kind value is a domain
            # marker for the row's declared backend, not a Solidity
            # visibility predicate. Skip.
            continue
        rel = _safe_relative_to_root(path)
        hint = _classify_unknown_function_kind(val)
        hits.append(f"{rel}:{lineno}: function.kind: {val!r} — {hint}")
    return hits


# ─── Check 8: inter-contract claim without callgraph evidence ───────────────
# Burn-down item #5: Slither has a callgraph but hand-written/wave17 Solidity
# detectors mostly operate per-contract — they iterate `self.contracts` and
# match a single function's syntactic shape. When a detector's docstring,
# HELP, WIKI_*, or class name claims inter-contract semantics ("cross-contract
# reentrancy", "factory deploys", "proxy implementation", "sibling contracts",
# "callgraph") but the source body never reads any Slither callgraph API
# (`high_level_calls`, `low_level_calls`, `cross_contract_calls`,
# `outgoing_internal_calls`, `internal_calls`, `all_*_calls_as_expressions`,
# `slither.contracts`, `compilation_unit.contracts`, etc.), the detector is
# almost certainly under-specified. It will either over-fire on per-contract
# shapes or miss legitimate cross-contract callers/callees.
#
# This check is heuristic — it cannot prove a detector needs the callgraph,
# only that the claim/evidence pair is asymmetric. CI fails closed only when
# `--fail-inter-contract-claim-without-callgraph` is passed; the default lint
# emits a HIGH-severity warning so the asymmetry is visible without breaking
# legacy generated detectors that legitimately ride per-contract pre/post
# conditions.

# Claim regexes — match the docstring/HELP/WIKI_* surface of a detector. The
# patterns are deliberately narrow: "cross-contract", "inter-contract",
# "callgraph", "factory deploys/creates", "proxy implementation/upgrade",
# "sibling contracts", "downstream callers/callees", "across deployments".
_INTER_CONTRACT_CLAIM_PATTERNS: tuple[tuple[str, str], ...] = (
    # "cross-contract" / "cross contract" / "inter-contract" — the most
    # explicit claim shape. We require either a hyphen/underscore boundary
    # or a leading word so we do not match "across contracts" inside a
    # docstring sentence accidentally.
    (r"cross[\-_]contract", "cross-contract phrase"),
    (r"inter[\-_]contract", "inter-contract phrase"),
    (r"call[\-_]?graph", "callgraph reference"),
    # "factory deploys" / "factory creates" — must be in the same short
    # span so we are matching the verb-phrase, not two unrelated words.
    (r"\bfactory\b[^.\n]{0,30}\b(?:deploy|deploys|deploying|creates?|spawn|clone|clones)\b",
     "factory.*deploy phrase"),
    # Proxy/implementation talk — narrowed to a verb-phrase span.
    (r"\bproxy\b[^.\n]{0,30}\b(?:implementation|upgrade|delegate|delegatecall)\b",
     "proxy.*implementation phrase"),
    (r"\bsibling\s+(?:contract|deployment)s?\b", "sibling-contract phrase"),
    (r"\bacross\s+(?:deployments|chains|contracts)\b", "across-deployments phrase"),
    # Call-direction claims — restrict to "caller(s)/callee(s)" near a
    # contract noun so generic "Upstream callers pass wei" prose does not
    # trigger. We only match plural caller forms that name a specific
    # contract relationship.
    (r"\bdownstream\s+(?:contract|helper|callee|callees)\b", "downstream-callee phrase"),
    (r"\b(?:cross|inter)[\s\-_]?function\s+reentr", "cross-function-reentrancy phrase"),
    (r"\breachab(?:le|ility)\s+from\s+(?:the\s+)?(?:caller|external|root|entrypoint)",
     "reachability-from phrase"),
    # "Read-only [reentrancy]" implies a separate observer contract.
    (r"\bread[\s\-]?only\s+reentr", "read-only-reentrancy phrase"),
)
_INTER_CONTRACT_CLAIM_REGEX = [
    (re.compile(pat, re.I), label) for pat, label in _INTER_CONTRACT_CLAIM_PATTERNS
]

# Evidence regexes — match Slither callgraph / multi-contract APIs in the
# detector source body. These are the surface that proves the detector did
# more than per-contract iteration. We deliberately do NOT count
# `self.contracts` alone as evidence: every detector iterates that list in
# the per-contract loop. Evidence requires reading edges between contracts
# or following call expressions across function boundaries.
_CALLGRAPH_EVIDENCE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\.high_level_calls\b", "high_level_calls"),
    (r"\.low_level_calls\b", "low_level_calls"),
    (r"\.cross_contract_calls\b", "cross_contract_calls"),
    (r"\.outgoing_internal_calls\b", "outgoing_internal_calls"),
    (r"\.internal_calls\b", "internal_calls"),
    (r"\.all_(?:high_level|low_level|internal|library)_calls(?:_as_expressions)?\b",
     "all_*_calls"),
    (r"\.solidity_calls\b", "solidity_calls"),
    (r"\.library_calls\b", "library_calls"),
    (r"\.calls_as_expressions\b", "calls_as_expressions"),
    (r"slither_predicates\.(?:has_high_level_call|reaches_external|taints_param_to)",
     "slither_predicates.callgraph helper"),
    (r"contract\.has_external_call_to\b", "predicate-engine inter-contract key"),
    (r"function\.reaches_external\b", "predicate-engine reaches_external key"),
    (r"function\.has_high_level_call_named\b", "predicate-engine has_high_level_call key"),
    (r"function\.taints_param_to\b", "predicate-engine taints_param_to key"),
    (r"compilation_unit\.contracts\b", "compilation_unit.contracts iteration"),
    (r"contracts_in_compilation_unit\b", "contracts_in_compilation_unit iteration"),
    (r"slither\.contracts_derived\b", "slither.contracts_derived iteration"),
)
_CALLGRAPH_EVIDENCE_REGEX = [
    (re.compile(pat), label) for pat, label in _CALLGRAPH_EVIDENCE_PATTERNS
]

# Claim surface inside a detector source: the module docstring, plus the
# HELP / WIKI_* class attributes. We extract these textually rather than
# importing the detector (which would pull in slither). Class-attribute
# strings are matched non-greedily up to the closing quote; multi-line
# triple-quoted strings are intentionally captured by allowing newlines
# inside the body.
_CLASS_ATTR_TEXT_RE = re.compile(
    r"^\s*(HELP|WIKI|WIKI_TITLE|WIKI_DESCRIPTION|WIKI_EXPLOIT_SCENARIO|"
    r"WIKI_RECOMMENDATION|ARGUMENT)\s*=\s*"
    r"(\"\"\"(?:.*?)\"\"\"|'''(?:.*?)'''|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')",
    re.M | re.DOTALL,
)


def _extract_claim_text(src: str) -> str:
    """Return the concatenated docstring + HELP/WIKI_* surface of a detector.

    The claim text is the human-readable surface a detector exposes about
    what bug class it covers. We treat the module docstring + the class
    attribute strings as the claim — that is what users read and what the
    DSL emits.
    """
    if not src:
        return ""
    parts: list[str] = []
    try:
        mod = ast.parse(src)
        doc = ast.get_docstring(mod) or ""
    except SyntaxError:
        doc = ""
    if doc:
        parts.append(doc)
    for m in _CLASS_ATTR_TEXT_RE.finditer(src):
        raw = m.group(2)
        # Strip the surrounding quotes (handle triple- and single-quoted
        # forms uniformly). The exact quote shape does not matter for
        # claim-phrase matching.
        if raw.startswith('"""') or raw.startswith("'''"):
            parts.append(raw[3:-3])
        else:
            parts.append(raw[1:-1])
    return "\n".join(parts)


def _extract_code_text(src: str) -> str:
    """Return the detector source with module docstring + class-attribute
    strings stripped, leaving only the executable code surface.

    The evidence scan must run on the code body, not the prose: a detector
    whose WIKI_DESCRIPTION says "we walk function.high_level_calls" but
    whose `_detect` body does no such walk should still be flagged. We
    drop the docstring and HELP/WIKI_* literal strings before scanning.
    """
    if not src:
        return ""
    stripped = src
    # Remove module docstring (first triple-quoted block at file start).
    try:
        mod = ast.parse(src)
        if (
            mod.body
            and isinstance(mod.body[0], ast.Expr)
            and isinstance(mod.body[0].value, ast.Constant)
            and isinstance(mod.body[0].value.value, str)
        ):
            doc_node = mod.body[0]
            # Replace docstring lines with blank lines so line numbers
            # stay stable (helps caller diagnostics).
            lines = stripped.splitlines(keepends=True)
            start = doc_node.lineno - 1
            end = (doc_node.end_lineno or doc_node.lineno) - 1
            for idx in range(start, min(end + 1, len(lines))):
                # Preserve trailing newline so line indexing stays stable.
                lines[idx] = "\n" if lines[idx].endswith("\n") else ""
            stripped = "".join(lines)
    except SyntaxError:
        pass
    # Remove HELP/WIKI_* class-attribute strings: replace each match with
    # a same-length space run so line numbers are not perturbed.
    def _blank(m: re.Match) -> str:
        return m.group(0)[: len(m.group(1)) + 1] + (" " * (len(m.group(0)) - len(m.group(1)) - 1))
    stripped = _CLASS_ATTR_TEXT_RE.sub(_blank, stripped)
    return stripped


def inter_contract_claim_signals(claim_text: str) -> list[str]:
    """Return the labels of inter-contract claim phrases found in `claim_text`."""
    if not claim_text:
        return []
    seen: list[str] = []
    for regex, label in _INTER_CONTRACT_CLAIM_REGEX:
        if regex.search(claim_text):
            seen.append(label)
    return seen


def callgraph_evidence_signals(code_text: str) -> list[str]:
    """Return the labels of Slither callgraph API references in `code_text`."""
    if not code_text:
        return []
    seen: list[str] = []
    for regex, label in _CALLGRAPH_EVIDENCE_REGEX:
        if regex.search(code_text):
            seen.append(label)
    return seen


def callgraph_relation_count(code_text: str) -> int:
    """Return the total count of Slither callgraph API references in `code_text`.

    Used by detector reporting to surface "this detector consults the
    callgraph N times" so reviewers can spot detectors that name-drop a
    callgraph helper once but never iterate the result.
    """
    if not code_text:
        return 0
    total = 0
    for regex, _label in _CALLGRAPH_EVIDENCE_REGEX:
        total += len(regex.findall(code_text))
    return total


def inter_contract_claim_without_callgraph(
    *,
    folders: Iterable[Path] | None = None,
) -> list[tuple[Path, list[str], int]]:
    """Yield (path, claim_labels, evidence_count) for each detector that
    claims inter-contract semantics but consults no callgraph API.

    `evidence_count` is always 0 for items in the returned list, but the
    return tuple shape mirrors `inter_contract_claim_with_callgraph` so
    downstream callers can use a single iteration shape.
    """
    dirs = list(folders) if folders is not None else [WAVE17, WAVE18]
    hits: list[tuple[Path, list[str], int]] = []
    for folder in dirs:
        for det in _iter_detectors(folder):
            src = _read(det)
            if not src:
                continue
            claim = _extract_claim_text(src)
            claim_labels = inter_contract_claim_signals(claim)
            if not claim_labels:
                continue
            code = _extract_code_text(src)
            evidence_labels = callgraph_evidence_signals(code)
            if evidence_labels:
                continue
            hits.append((det, claim_labels, 0))
    return hits


def inter_contract_claim_with_callgraph(
    *,
    folders: Iterable[Path] | None = None,
) -> list[tuple[Path, list[str], int]]:
    """Yield (path, claim_labels, callgraph_relation_count) for detectors
    that claim inter-contract semantics AND consult the callgraph.

    Surfacing the relation count gives reviewers a coarse measure of how
    much callgraph the detector actually uses (one reference vs many).
    """
    dirs = list(folders) if folders is not None else [WAVE17, WAVE18]
    hits: list[tuple[Path, list[str], int]] = []
    for folder in dirs:
        for det in _iter_detectors(folder):
            src = _read(det)
            if not src:
                continue
            claim = _extract_claim_text(src)
            claim_labels = inter_contract_claim_signals(claim)
            if not claim_labels:
                continue
            code = _extract_code_text(src)
            evidence_labels = callgraph_evidence_signals(code)
            if not evidence_labels:
                continue
            hits.append((det, claim_labels, callgraph_relation_count(code)))
    return hits


def check_inter_contract_claim_without_callgraph() -> list[str]:
    """Format the asymmetric-claim findings as one-line lint strings."""
    hits: list[str] = []
    for path, claim_labels, _evidence_count in inter_contract_claim_without_callgraph():
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        labels = ", ".join(claim_labels[:3]) or "claim phrase"
        hits.append(
            f"{rel}: claims inter-contract semantics ({labels}) but source "
            f"never consults Slither callgraph (high_level_calls, "
            f"cross_contract_calls, etc.)"
        )
    return hits


def check_invalid_backend(dsl_dir: Path | None = None) -> list[str]:
    """Flag any DSL file declaring a backend value not in VALID_BACKENDS.

    Adding this check protects the backend-split contract: typos like
    `backend: solidty` or `backend: cosmoss` would otherwise silently
    skip Solidity lint without any engine actually picking the row up.
    Returns one row per invalid declaration.
    """
    target_dir = dsl_dir if dsl_dir is not None else PATTERNS_DSL_DIR
    hits: list[str] = []
    if not target_dir.is_dir():
        return hits
    for yaml_path in sorted(target_dir.glob("*.yaml")):
        text = _read(yaml_path)
        if not text:
            continue
        m = _BACKEND_RE.search(text)
        if not m:
            continue
        val = m.group(1).strip()
        if val in VALID_BACKENDS:
            continue
        rel = _safe_relative_to_root(yaml_path)
        hits.append(
            f"{rel}: backend: {val!r} — not in VALID_BACKENDS "
            f"({sorted(VALID_BACKENDS)}); typo or unsupported backend"
        )
    return hits


def check_inter_contract_callgraph_users() -> list[str]:
    """Format the verified callgraph-using detectors with relation counts.

    Emitted at LOW severity as an inventory line so reviewers can see which
    detectors do consult the callgraph and how many references they have.
    """
    hits: list[str] = []
    for path, claim_labels, count in inter_contract_claim_with_callgraph():
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        labels = ", ".join(claim_labels[:2]) or "claim phrase"
        hits.append(f"{rel}: {labels}; callgraph_relation_count={count}")
    return hits


# ─── Report emitter ─────────────────────────────────────────────────────────
def emit(title: str, items: list[str], severity: str, out) -> None:
    out.write(f"\n## {title}  ({severity})\n")
    out.write(f"**Count:** {len(items)}\n\n")
    if not items:
        out.write("_No issues found._\n")
        return
    out.write("Top examples:\n")
    for ex in items[:TOP_N]:
        out.write(f"  - `{ex}`\n")
    if len(items) > TOP_N:
        out.write(f"\n…and {len(items) - TOP_N} more.\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--md", action="store_true", help="Markdown output (default: same)")
    parser.add_argument(
        "--fail-placeholder-fp-guards",
        action="store_true",
        help=(
            "Exit non-zero when generated DSL specs still contain placeholder "
            "FP guard fields. Use for calibration burn-down PRs, not broad CI "
            "until the existing cohort is resolved."
        ),
    )
    parser.add_argument(
        "--fail-high-tier-placeholder-fp-guards",
        action="store_true",
        help=(
            "Exit non-zero only when Tier-S/A DSL specs contain placeholder "
            "FP guard fields. This is suitable for CI promotion guards while "
            "the broad generated draft placeholder backlog is still advisory."
        ),
    )
    parser.add_argument(
        "--fail-high-tier-regex-only",
        action="store_true",
        help=(
            "Exit non-zero when Tier-S/A DSL patterns still rely on regex-only "
            "predicates. Use for semantic detector burn-down PRs, not broad CI "
            "until the existing cohort is resolved."
        ),
    )
    parser.add_argument(
        "--fail-unknown-function-kind",
        action="store_true",
        help=(
            "Exit non-zero when DSL specs use function.kind values the "
            "predicate engine will not honor. Use for P1-1 burn-down checks; "
            "default lint remains advisory until the legacy corpus is fixed "
            "or explicitly documented."
        ),
    )
    parser.add_argument(
        "--fail-inter-contract-claim-without-callgraph",
        action="store_true",
        help=(
            "Exit non-zero when wave17/wave18 detectors claim inter-contract "
            "semantics (cross-contract / inter-contract / callgraph / factory "
            "deploys / proxy implementation) but the detector source never "
            "consults a Slither callgraph API. Burn-down item #5; default "
            "lint remains advisory until the existing corpus is reviewed."
        ),
    )
    args = parser.parse_args(argv)

    missing_fx = check_missing_fixtures()
    missing_disk, missing_script = check_script_disk_mismatch()
    terse = check_terse_docstrings()
    yaml_missing = check_yaml_missing_fields()
    placeholder_fp_guards = check_placeholder_fp_guards()
    high_tier_placeholder_fp_guards = check_placeholder_fp_guards(high_tier_only=True)
    high_tier_regex_only = check_high_tier_regex_only()
    parity_gaps = check_parity_gaps()
    bad_w = check_bad_wclass()
    fk_unknown = check_function_kind_unknown()
    inter_contract_unsupported = check_inter_contract_claim_without_callgraph()
    inter_contract_supported = check_inter_contract_callgraph_users()
    invalid_backend = check_invalid_backend()

    out = sys.stdout
    out.write("# Detector Lint Report\n")
    out.write(
        "_Best-effort lint over `detectors/rust_wave1/`, `detectors/wave17/`, "
        "DSL YAML specs, and `tools/parity-report.py`._\n"
    )

    out.write("\n# HIGH severity\n")
    emit("1. rust_wave1 detectors without fixture pair", missing_fx, "HIGH", out)
    emit("2a. Entries in test_detectors.sh missing on disk", missing_disk, "HIGH", out)
    emit("2b. Detectors on disk but not in test_detectors.sh", missing_script, "HIGH", out)
    emit("7. DSL function.kind values not recognized by _predicate_engine.py "
         "(silent no-op — see PR #121 follow-up)", fk_unknown, "HIGH", out)
    emit("7b. DSL backend values not in VALID_BACKENDS (typo / unsupported)",
         invalid_backend, "HIGH", out)
    emit(
        "8. wave17/wave18 detectors with inter-contract claim but no "
        "Slither callgraph evidence (burn-down item #5)",
        inter_contract_unsupported,
        "HIGH",
        out,
    )

    out.write("\n# MEDIUM severity\n")
    emit("3. Detectors with docstring <50 chars", terse, "MEDIUM", out)
    emit("4b. DSL specs with placeholder FP guard fields", placeholder_fp_guards, "MEDIUM", out)
    emit(
        "4c. Tier-S/A DSL specs with placeholder FP guard fields",
        high_tier_placeholder_fp_guards,
        "MEDIUM",
        out,
    )
    emit("4d. Tier-S/A DSL specs with regex-only predicates", high_tier_regex_only, "MEDIUM", out)
    emit(
        "5. Parity BUG_CLASSES — true gaps (GAP_RUST / GAP_SOLIDITY) + suspect "
        "platform-only rows missing `deliberate:true`/`rationale` (item-#6 burn-down)",
        parity_gaps, "MEDIUM", out,
    )

    out.write("\n# LOW severity\n")
    emit("4. DSL YAML specs missing cross_refs or tags", yaml_missing, "LOW", out)
    emit("6. Regex literals using [\\w] instead of \\w", bad_w, "LOW", out)
    emit(
        "8b. wave17/wave18 detectors that DO consult the Slither callgraph "
        "(inventory + relation count)",
        inter_contract_supported,
        "LOW",
        out,
    )

    # Default non-zero exit remains limited to existing HIGH disk/script
    # mismatches. Placeholder guard cohorts fail only when the calibration
    # burn-down flag is explicitly requested.
    if missing_disk:
        return 1
    if args.fail_placeholder_fp_guards and placeholder_fp_guards:
        return 1
    if args.fail_high_tier_placeholder_fp_guards and high_tier_placeholder_fp_guards:
        return 1
    if args.fail_high_tier_regex_only and high_tier_regex_only:
        return 1
    if args.fail_unknown_function_kind and fk_unknown:
        return 1
    # Invalid backend values fail closed unconditionally — these are typos
    # (e.g. `backend: solidty`) that would silently disable Solidity lint
    # for the row. There is no opt-in here because no legitimate use case
    # requires a non-recognized backend identifier.
    if invalid_backend:
        return 1
    if (
        args.fail_inter_contract_claim_without_callgraph
        and inter_contract_unsupported
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
