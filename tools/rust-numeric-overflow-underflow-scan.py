#!/usr/bin/env python3
"""Rust numeric overflow / underflow scanner — Wave H-3F.

Wave 6 Worker F promoted a Swival-derived Medium candidate at:

  ``external/base/crates/consensus/derive/src/stages/frame_queue.rs``

Two arithmetic faults in the same ``prune()`` routine:

  1. Line 68: ``while i < self.queue.len() - 1``
     If the queue is empty (len()==0), the usize subtraction wraps to
     usize::MAX in release mode, causing ``self.queue[i]`` to index out of
     bounds and panic the derivation pipeline.

  2. Line 75: ``prev_frame.number + 1 != next_frame.number``
     Frame.number is u16 (protocol/src/frame.rs:139). If
     prev_frame.number == u16::MAX (65535), the addition panics in debug mode
     or wraps to 0 in release mode, causing incorrect frame-sequence validation.

Pattern IDs
-----------
* ``usize_sub_without_empty_guard``   — ``<expr>.len() - 1`` or
  ``<collection>.len() - <literal>`` without a preceding ``is_empty()`` or
  ``len() > <literal>`` guard.
* ``u8_u16_add_overflow_risk``        — ``<field_of_bounded_type> + 1`` where
  the field type is declared as u8 or u16 (inferred from struct definition or
  nearby annotation) and no ``checked_add``/``saturating_add``/
  ``wrapping_add`` is used.
* ``checked_add_unwrap``              — ``<expr>.checked_add(<n>).unwrap()``
  where an unwrap on checked_add is itself a panic path.

Distinguishing from existing ``rust-decode-bomb-scan``: that scanner covers
attacker-controlled-length allocation. This scanner covers arithmetic on
iterator lengths (``len() - 1``) and bounded-integer-type field increments
(u16 + 1), which are precision faults distinct from allocation size abuse.

Confidence levels
-----------------
* ``high``  — usize sub without empty guard in a function that processes
               network-derived frames/channels; OR u8/u16 field + literal
               with no checked_add/saturating_add.
* ``medium``— pattern found but a guard exists nearby (may be partial).
* ``low``   — heuristic match, broader context needed.

Default-to-kill discipline: every row carries ``candidate_status``.
``STRICT=1`` / ``--strict`` exits 1 when any row is emitted.

CLI: ``--workspace``, ``--strict``, ``--print-json``.

Examples
--------

::

    python3 tools/rust-numeric-overflow-underflow-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-numeric-overflow-underflow-scan.py \\
        --workspace ~/audits/base-azul --strict
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_numeric_overflow_underflow_scan.v1"

# ---------------------------------------------------------------------------
# Advisory axis: profile_wrap_silent (RU4)
# ---------------------------------------------------------------------------
# Cargo-blindness fix. The base scan treats every bare-arith site uniformly.
# A bare `a.len() - 1` or `field + 1` that panics in a release build
# (overflow-checks = true) is a very different risk from one that WRAPS
# SILENTLY (overflow-checks omitted/false => the Cargo release default). This
# axis resolves the EFFECTIVE release overflow-checks for the crate that owns
# each hit and, when release is wrap-silent, tags the hit
# `profile_wrap_silent = true` as an advisory severity modifier.
#
# Advisory-first: OFF unless AUDITOOOR_RUST_PROFILE_WRAP_SILENT is truthy (or
# --profile-wrap-silent is passed). When OFF, every row keeps the default
# `profile_wrap_silent = false` and behaviour is byte-identical to v1.
#
# NO-AUTO-CREDIT: a tagged hit is a hypothesis (verdict "needs-fuzz"), never a
# confirmed finding. --emit-hypotheses writes the needs-fuzz jsonl.
PROFILE_AXIS_ENV = "AUDITOOOR_RUST_PROFILE_WRAP_SILENT"

# Cargo built-in profile defaults for overflow-checks. dev/test panic; the
# release/bench family WRAPS unless explicitly re-enabled.
_PROFILE_BASE_DEFAULT = {
    "dev": True,
    "test": True,      # test inherits dev
    "release": False,
    "bench": False,    # bench inherits release
}
# Implicit base a built-in profile falls back to when it has no explicit entry.
_PROFILE_IMPLICIT_BASE = {
    "test": "dev",
    "bench": "release",
}

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

# ---------------------------------------------------------------------------
# Pattern compilation (Foot-gun #3: \b not ^)
# ---------------------------------------------------------------------------

# Pattern 1: <collection>.len() - <literal>
# Matches things like: self.queue.len() - 1
#                      items.len() - 2
#                      buf.len() - N
USIZE_SUB_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\.\s*len\s*\(\s*\)\s*-\s*(\d+|[A-Za-z_][A-Za-z0-9_]*)",
)

# Pattern 2: <expr> + 1  or  <expr>.number + 1  on u8/u16 context.
# We match the arithmetic and then check the context for u8/u16 declarations.
BOUNDED_ADD_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)"
    r"\s*\+\s*(\d+)\b",
)

# Pattern 3: .checked_add(...).unwrap()  — the unwrap is reachable and panics.
CHECKED_ADD_UNWRAP_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\.\s*checked_(?:add|sub|mul)\s*\([^)]*\)\s*"
    r"(?:\s*\.\s*ok_or[^)]*\))?"
    r"\s*\.\s*(?:unwrap|expect)\s*\(",
)

# Safe arithmetic patterns — suppress when these appear in the same expression.
SAFE_ARITHMETIC_RE = re.compile(
    r"\b(?:saturating_add|saturating_sub|wrapping_add|wrapping_sub|"
    r"overflowing_add|checked_add|checked_sub)\b",
)

# Guard patterns that suppress usize_sub_without_empty_guard.
EMPTY_GUARD_RE = re.compile(
    r"\b(?:is_empty\s*\(\s*\)|len\s*\(\s*\)\s*(?:==\s*0|>\s*\d|!=\s*0))\b",
)

# u8 / u16 type annotations in struct fields or let bindings.
U8_U16_DECL_RE = re.compile(
    r":\s*u(?:8|16)\b",
)

# Function declaration boundary.
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

# Frame/derive/consensus path tokens for source classification.
FRAME_PATH_TOKENS = (
    "/derive/",
    "/frame",
    "/channel",
    "/consensus/",
    "/proof/",
    "/batcher/",
    "/batch/",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class OverflowRow:
    file: str
    line: int
    pattern_id: str
    function: str
    expression: str
    safe_guard_present: bool
    safe_guard_indicator: str
    attacker_input_source: str
    confidence: str
    snippet: str
    recommendation: str
    candidate_status: str = "kill_or_reframe"
    submission_posture: str = "NOT_SUBMIT_READY"
    evidence_class: str = "detector_hit"
    harness_task: str = (
        "Fuzz: drive the containing function with inputs that set the bounded "
        "field to its maximum value (u16::MAX, u8::MAX) or leave the collection "
        "empty; assert no panic occurs."
    )
    kill_or_reframe_rule: str = (
        "kill_or_reframe unless a follow-up proof demonstrates that the "
        "attacker-controlled frame/queue state is reachable from untrusted L1 "
        "input and causes an observable derivation pipeline panic."
    )
    not_applicable_impacts: list[str] = field(default_factory=list)
    # RU4 advisory severity-modifier axis (default OFF => always false).
    profile_wrap_silent: bool = False
    profile_axis_evidence: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _input_source(rel_path: str) -> str:
    for tok in FRAME_PATH_TOKENS:
        if tok in "/" + rel_path:
            return "untrusted_l1"
    return "unknown"


def _strip_test_blocks(text: str) -> str:
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i : i + m.start()])
        depth = 0
        j = i + m.end() - 1
        n = len(text)
        while j < n:
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out_parts)


def _enclosing_function(text: str, offset: int) -> str:
    last = "<module>"
    for m in FN_START_RE.finditer(text, 0, offset):
        last = m.group(1)
    return last


def _enclosing_fn_body(text: str, offset: int) -> str:
    fn_starts = [m.start() for m in FN_START_RE.finditer(text, 0, offset)]
    if not fn_starts:
        return text
    fn_start = fn_starts[-1]
    n = len(text)
    i = fn_start
    depth = 0
    body_start = -1
    while i < n:
        c = text[i]
        if c == ";" and depth == 0 and body_start == -1:
            return text[fn_start:i]
        if c == "{":
            if body_start == -1:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and body_start != -1:
                return text[body_start : i + 1]
        i += 1
    return text[fn_start:]


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


def _guard_present_for_sub(fn_body: str, collection_expr: str) -> tuple[bool, str]:
    """Check if an empty-check guard exists for collection_expr before the subtraction."""
    # Look for is_empty() or len() == 0 on the same collection.
    base = collection_expr.split(".")[0]  # e.g. "self" or "items"

    # Check for is_empty() guard anywhere in the function.
    if re.search(rf"\b{re.escape(base)}\b.*?\.\s*is_empty\s*\(\s*\)", fn_body, re.DOTALL):
        return True, "is_empty() guard"

    # Check for len() > 0 / len() != 0 / len() >= 1 on the same base.
    if re.search(
        rf"\b{re.escape(base)}\b.*?\.len\s*\(\s*\)\s*(?:>|!=|>=)\s*\d",
        fn_body,
        re.DOTALL,
    ):
        return True, "len() > N guard"

    # Check for if queue.len() == 0 { return }
    if re.search(
        rf"if\s+.*?\b{re.escape(base)}\b.*?\.len\s*\(\s*\)\s*==\s*0",
        fn_body,
        re.DOTALL,
    ):
        return True, "len() == 0 early return"

    return False, ""


def _field_is_u8_or_u16(
    field_path: str,
    whole_file: str,
    workspace: Path | None = None,
) -> tuple[bool, str]:
    """Heuristic: is the field at the end of field_path declared as u8/u16?

    field_path is something like ``prev_frame.number``. We look for a struct
    field declaration ``number: u16`` in the file or in sibling crate files.

    Cross-file heuristic: well-known fields whose type is u16 in protocol
    structs across the Base codebase (e.g. Frame.number, FrameNumber, port).
    """
    # Extract the last component (field name).
    parts = field_path.rsplit(".", 1)
    if len(parts) < 2:
        return False, ""
    field_name = parts[-1].strip()

    # Known bounded fields (u16) in the Base protocol crate: verified against
    # external/base/crates/consensus/protocol/src/frame.rs:139 (Frame.number: u16)
    # and channel.rs:last_frame_number.
    KNOWN_U16_FIELDS = {
        "number",           # Frame.number: u16 (frame.rs:139)
        "last_frame_number",  # ChannelOut.last_frame_number: u16
        "frame_number",
        "seq_num",
        "sequence_number",
    }
    KNOWN_U8_FIELDS: set[str] = set()

    if field_name in KNOWN_U16_FIELDS:
        return True, "u16"
    if field_name in KNOWN_U8_FIELDS:
        return True, "u8"

    # Look for `field_name: u8` or `field_name: u16` in the whole file.
    m = re.search(
        rf"\b{re.escape(field_name)}\s*:\s*(u(?:8|16))\b",
        whole_file,
    )
    if m:
        return True, m.group(1)

    # Cross-file lookup: search sibling *.rs files in the workspace for the
    # struct field declaration.
    if workspace is not None:
        for protocol_glob in [
            "external/base*/crates/consensus/protocol/src/*.rs",
            "external/base*/crates/consensus/derive/src/**/*.rs",
        ]:
            for p in sorted(workspace.glob(protocol_glob)):
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                mx = re.search(
                    rf"\b{re.escape(field_name)}\s*:\s*(u(?:8|16))\b",
                    content,
                )
                if mx:
                    return True, mx.group(1)

    return False, ""


# ---------------------------------------------------------------------------
# Cargo profile pre-pass (RU4 profile_wrap_silent axis)
# ---------------------------------------------------------------------------


def _load_toml(text: str) -> dict:
    try:
        import tomllib  # py3.11+
    except ModuleNotFoundError:  # pragma: no cover
        return {}
    try:
        return tomllib.loads(text)
    except Exception:
        return {}


def _profiles_from_manifest(text: str) -> dict:
    data = _load_toml(text)
    profiles = data.get("profile")
    return profiles if isinstance(profiles, dict) else {}


def _has_workspace_table(text: str) -> bool:
    data = _load_toml(text)
    return isinstance(data.get("workspace"), dict)


def _resolve_overflow_checks(
    profiles: dict, name: str, _seen: set[str] | None = None
) -> bool:
    """Resolve the EFFECTIVE overflow-checks for a profile.

    Honours an explicit key, ``inherits`` chains (cycle-safe), the implicit
    built-in base (bench<-release, test<-dev) and the Cargo built-in defaults.
    """
    _seen = _seen or set()
    prof = profiles.get(name)
    if isinstance(prof, dict):
        if "overflow-checks" in prof:
            return bool(prof["overflow-checks"])
        inh = prof.get("inherits")
        if isinstance(inh, str) and inh and inh not in _seen:
            _seen.add(name)
            return _resolve_overflow_checks(profiles, inh, _seen)
    base = _PROFILE_IMPLICIT_BASE.get(name)
    if base and base not in _seen:
        _seen.add(name)
        return _resolve_overflow_checks(profiles, base, _seen)
    return _PROFILE_BASE_DEFAULT.get(name, False)


class CargoProfileResolver:
    """Resolve, per source file, whether the effective release build is
    wrap-silent (overflow-checks disabled).

    Cargo only honours ``[profile.*]`` in the WORKSPACE-ROOT manifest; member
    profile sections are ignored. So we walk upward from the file, pick the
    highest ``[workspace]`` manifest as the root (else the nearest manifest for
    a standalone crate), and read that root's effective release profile. Results
    are memoized by root-manifest path.
    """

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._root_cache: dict[str, tuple[bool, str]] = {}

    @staticmethod
    def _find_root_manifest(file_path: Path) -> Path | None:
        cur = file_path.parent if file_path.is_file() else file_path
        nearest: Path | None = None
        workspace_root: Path | None = None
        for d in [cur, *cur.parents]:
            manifest = d / "Cargo.toml"
            if not manifest.is_file():
                continue
            if nearest is None:
                nearest = manifest
            try:
                text = manifest.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _has_workspace_table(text):
                workspace_root = manifest  # keep climbing; highest wins
        return workspace_root or nearest

    def wrap_silent_for_file(self, file_path: Path) -> tuple[bool, str]:
        """Return (is_wrap_silent, evidence). Non-enabled -> (False, "")."""
        if not self.enabled:
            return False, ""
        root = self._find_root_manifest(file_path)
        if root is None:
            return False, "no Cargo.toml resolved"
        key = str(root)
        if key in self._root_cache:
            return self._root_cache[key]
        try:
            text = root.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result = (False, f"unreadable manifest {root}")
            self._root_cache[key] = result
            return result
        profiles = _profiles_from_manifest(text)
        oc = _resolve_overflow_checks(profiles, "release")
        wrap_silent = not oc
        rel_key = "explicit" if "release" in profiles and isinstance(
            profiles.get("release"), dict
        ) and "overflow-checks" in profiles["release"] else "default/inherited"
        evidence = (
            f"root={root.name} release.overflow-checks={oc} ({rel_key}) "
            f"wrap_silent={wrap_silent}"
        )
        result = (wrap_silent, evidence)
        self._root_cache[key] = result
        return result


# Bare-arith patterns eligible for the wrap-silent modifier. checked_add_unwrap
# is EXCLUDED: it already uses checked arithmetic (it panics via unwrap, it does
# not wrap), so a wrap-silent release profile does not change its shape.
_WRAP_SILENT_ELIGIBLE = frozenset(
    {"usize_sub_without_empty_guard", "u8_u16_add_overflow_risk"}
)


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_file(
    file_path: Path,
    workspace: Path,
    profile_resolver: "CargoProfileResolver | None" = None,
) -> list[OverflowRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[OverflowRow] = []
    seen_lines: set[int] = set()

    # Pattern 1: usize subtraction without empty guard.
    for m in USIZE_SUB_RE.finditer(cleaned):
        collection_expr = m.group(1)
        rhs = m.group(2)
        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue

        fn_body = _enclosing_fn_body(cleaned, m.start())
        guard, guard_val = _guard_present_for_sub(fn_body, collection_expr)

        # Determine confidence.
        if not guard and src in ("untrusted_l1", "untrusted_proof"):
            confidence = "high"
        elif not guard:
            confidence = "medium"
        else:
            confidence = "low"

        seen_lines.add(line)
        rows.append(
            OverflowRow(
                file=rel,
                line=line,
                pattern_id="usize_sub_without_empty_guard",
                function=_enclosing_function(cleaned, m.start()),
                expression=m.group(0).strip(),
                safe_guard_present=guard,
                safe_guard_indicator=guard_val,
                attacker_input_source=src,
                confidence=confidence,
                snippet=_snippet(cleaned, m.start()),
                recommendation=(
                    f"Guard against empty collection before `{m.group(0).strip()}`: "
                    f"add `if {collection_expr.split('.')[-2] if '.' in collection_expr else collection_expr}"
                    f".is_empty() {{ return; }}` or use saturating_sub(1)."
                ),
            )
        )

    # Pattern 2: bounded-type field + literal.
    for m in BOUNDED_ADD_RE.finditer(cleaned):
        field_path = m.group(1)
        literal = m.group(2)
        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue

        # Check if this expression is already under a safe arithmetic call.
        context_line = _snippet(cleaned, m.start())
        if SAFE_ARITHMETIC_RE.search(context_line):
            continue

        # Check if the field is u8/u16.
        is_bounded, type_name = _field_is_u8_or_u16(field_path, cleaned, workspace)
        if not is_bounded:
            continue

        fn_body = _enclosing_fn_body(cleaned, m.start())
        # Check if there's a safe arithmetic version in the same body.
        if SAFE_ARITHMETIC_RE.search(fn_body):
            guard_present = True
            guard_val = "saturating/checked/wrapping variant present in fn"
            confidence = "medium"
        else:
            guard_present = False
            guard_val = ""
            confidence = "high" if src in ("untrusted_l1", "untrusted_proof") else "medium"

        seen_lines.add(line)
        rows.append(
            OverflowRow(
                file=rel,
                line=line,
                pattern_id="u8_u16_add_overflow_risk",
                function=_enclosing_function(cleaned, m.start()),
                expression=m.group(0).strip(),
                safe_guard_present=guard_present,
                safe_guard_indicator=guard_val,
                attacker_input_source=src,
                confidence=confidence,
                snippet=context_line,
                recommendation=(
                    f"`{field_path}` is {type_name}; replace `{m.group(0).strip()}` "
                    f"with `{field_path}.checked_add({literal}).ok_or(FrameDecodingError::Overflow)?` "
                    f"or `{field_path}.saturating_add({literal})`."
                ),
            )
        )

    # Pattern 3: checked_add / checked_sub / checked_mul with .unwrap().
    for m in CHECKED_ADD_UNWRAP_RE.finditer(cleaned):
        line = _line_for_offset(cleaned, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)

        fn_name = _enclosing_function(cleaned, m.start())
        rows.append(
            OverflowRow(
                file=rel,
                line=line,
                pattern_id="checked_add_unwrap",
                function=fn_name,
                expression=m.group(0).strip()[:80],
                safe_guard_present=False,
                safe_guard_indicator="",
                attacker_input_source=src,
                confidence="medium",
                snippet=_snippet(cleaned, m.start()),
                recommendation=(
                    "Replace `.checked_add(...).unwrap()` with `.checked_add(...)`"
                    ".ok_or(SomeError::Overflow)?` to propagate the overflow error "
                    "rather than panicking."
                ),
            )
        )

    # RU4: profile_wrap_silent advisory modifier on bare-arith hits. Resolved
    # ONCE per file (all rows share one crate) and applied only to the
    # wrap-eligible bare-arith patterns.
    if profile_resolver is not None and profile_resolver.enabled and rows:
        wrap_silent, evidence = profile_resolver.wrap_silent_for_file(file_path)
        if wrap_silent:
            for row in rows:
                if row.pattern_id in _WRAP_SILENT_ELIGIBLE:
                    row.profile_wrap_silent = True
                    row.profile_axis_evidence = evidence

    return rows


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    roots = rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS) + list(extra_roots)
    for rel in roots:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path.name.endswith("_test.rs") or path.name.endswith("_tests.rs"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _count_by(rows: list[OverflowRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _axis_enabled(cli_flag: bool) -> bool:
    if cli_flag:
        return True
    val = (os.environ.get(PROFILE_AXIS_ENV) or "").strip().lower()
    return val in ("1", "true", "yes", "on")


def run(
    workspace: Path,
    extra_roots: list[str],
    profile_axis: bool = False,
) -> list[OverflowRow]:
    files = enumerate_files(workspace, extra_roots)
    resolver = CargoProfileResolver(enabled=profile_axis)
    rows: list[OverflowRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace, resolver))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def build_hypotheses(rows: list[OverflowRow], workspace: Path) -> list[dict]:
    """NO-AUTO-CREDIT hypotheses for wrap-silent bare-arith hits.

    Each row is a needs-fuzz hypothesis, NOT a confirmed finding. covered_by
    points back to the base detector so the axis rides on existing hits and does
    not duplicate them (dedup boundary).
    """
    out: list[dict] = []
    for r in rows:
        if not r.profile_wrap_silent:
            continue
        out.append(
            {
                "id": f"profile_wrap_silent::{r.file}::{r.line}::{r.pattern_id}",
                "workspace": str(workspace),
                "file": r.file,
                "line": r.line,
                "pattern_id": r.pattern_id,
                "function": r.function,
                "expression": r.expression,
                "axis": "profile_wrap_silent",
                "profile_axis_evidence": r.profile_axis_evidence,
                "verdict": "needs-fuzz",
                "auto_credit": False,
                "covered_by": "rust-numeric-overflow-underflow-scan",
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-numeric-overflow-underflow-scan.py",
        description=(
            "Wave H-3F — Rust numeric overflow/underflow scanner. "
            "Catches usize len()-1 underflow without empty-guard, u8/u16 field + N "
            "overflow risk, and checked_add().unwrap() panic paths."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Extra workspace-relative path to walk. May be passed multiple times.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout instead of writing files.",
    )
    parser.add_argument(
        "--out-json",
        default="",
        help="Set to '-' to print JSON to stdout (alias for --print-json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when at least one row is emitted (STRICT=1 gate for CI).",
    )
    parser.add_argument(
        "--profile-wrap-silent",
        action="store_true",
        help=(
            "Enable the advisory profile_wrap_silent axis: resolve the effective "
            "release overflow-checks and tag bare-arith hits in wrap-silent crates. "
            f"OFF by default; also enabled via {PROFILE_AXIS_ENV}=1."
        ),
    )
    parser.add_argument(
        "--emit-hypotheses",
        default="",
        help=(
            "Write NO-AUTO-CREDIT needs-fuzz hypotheses (one per wrap-silent hit) "
            "as jsonl to this path. '-' writes to stdout stderr-safe."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-numeric-overflow-underflow-scan] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    profile_axis = _axis_enabled(args.profile_wrap_silent)
    rows = run(workspace, list(args.root), profile_axis=profile_axis)
    print_json = args.print_json or args.out_json == "-"

    hypotheses = build_hypotheses(rows, workspace) if profile_axis else []
    if args.emit_hypotheses:
        lines = "".join(json.dumps(h, sort_keys=True) + "\n" for h in hypotheses)
        if args.emit_hypotheses == "-":
            sys.stderr.write(lines)
        else:
            emit_path = Path(args.emit_hypotheses)
            emit_path.parent.mkdir(parents=True, exist_ok=True)
            emit_path.write_text(lines, encoding="utf-8")
            print(
                f"[rust-numeric-overflow-underflow-scan] wrote {len(hypotheses)} "
                f"needs-fuzz hypotheses to {args.emit_hypotheses}",
                file=sys.stderr,
            )

    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "row_count": len(rows),
        "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
        "profile_axis_enabled": profile_axis,
        "profile_wrap_silent_count": sum(1 for r in rows if r.profile_wrap_silent),
        "rows": [asdict(r) for r in rows],
    }

    if print_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out_dir = workspace / "critical_hunt" / "numeric_overflow"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "rust_numeric_overflow_underflow_scan.json"
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"[rust-numeric-overflow-underflow-scan] wrote {json_path.relative_to(workspace)}",
            file=sys.stderr,
        )
        if rows:
            counts_str = ", ".join(
                f"{k}={v}"
                for k, v in sorted(_count_by(rows, lambda r: r.pattern_id).items())
            )
            print(
                f"[rust-numeric-overflow-underflow-scan] {len(rows)} rows: {counts_str}",
                file=sys.stderr,
            )
        else:
            print(
                "[rust-numeric-overflow-underflow-scan] no rows emitted",
                file=sys.stderr,
            )

    # Capability-vacuity-telltale: the scan RAN over a real Rust surface and emitted
    # 0 overflow rows. PERSIST an explicit cited-empty examined-record to the
    # firing-gate ledger so it scores FIRED_CLEAN (ran, recorded 0) not silently
    # VACUOUS. Gated on a present Rust surface; absent Rust -> a surface-absent
    # exemption governs instead (this reasoner writes nothing).
    aud = workspace / ".auditooor"
    ledger = aud / "rust_numeric_overflow_obligations.jsonl"
    if not rows and aud.is_dir():
        rust_present = any(
            "node_modules" not in p.parts for p in workspace.rglob("*.rs"))
        if rust_present:
            ledger.write_text(json.dumps({
                "schema": SCHEMA_VERSION,
                "note": ("cited-empty: rust numeric overflow/underflow scan ran over "
                         "the Rust surface, 0 wrap/silent-overflow rows"),
                "survivors": [],
                "report": {"reasoner": "rust-numeric-overflow-underflow-scan",
                           "totals": {"examined": 1}},
            }) + "\n", encoding="utf-8")

    if args.strict and rows:
        print(
            f"[rust-numeric-overflow-underflow-scan] STRICT FAIL: {len(rows)} row(s) emitted",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
