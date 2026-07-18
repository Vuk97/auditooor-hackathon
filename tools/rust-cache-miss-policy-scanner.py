#!/usr/bin/env python3
"""Rust cache-miss policy scanner (PR #546 Wave 2 Agent E, K7-3).

Walks Rust source files in a workspace's Rust source tree and flags
cache-miss / silent-success / deferred-validation patterns that have
historically caused critical "validator silently accepts a malformed
state" bugs. The Base Azul FN7 silent-pass at
``external/base/crates/execution/node/src/engine.rs:124-152`` is the
canonical example: ``state_by_block_hash`` returns ``Err`` (cache
miss) and the function returns ``Ok(())`` instead of bubbling the
error, so post-execution withdrawal-root verification is skipped on
non-canonical parents.

Detected patterns (regex + multi-line context, stdlib only):

  * ``match Err(_) => Ok(())`` — bare error swallow returning success.
  * ``unwrap_or_default`` outside init / test / clearly-safe code.
  * ``None => Ok`` — explicit ``None`` arm returning ``Ok``.
  * ``state_by_block_hash`` calls and the early-Ok arm following them.
  * ``let Some(x) = ... else { return Ok(...); }`` — early-Ok on a
    missing optional inside a validator-shaped function.
  * Deferred-validation comments: ``// TODO: validate later``,
    ``// FIXME: ... validate``, ``// skip if missing``.

Each match emits a row compatible with the schema used by
``tools/base-critical-candidate-matrix.py``: ``candidate_id``,
``scope_asset``, ``impact_mapping``, ``candidate_status``,
``production_path``, ``required_proof``, ``artifact_refs``,
``notes``. Every row is initialized with
``candidate_status='kill_or_reframe'`` (default-to-kill) until the
matrix tool maps the candidate's impact against the workspace
severity rubric.

Inputs:
  ``--workspace <path>``  Workspace root. Defaults to walking the
                          standard Base Azul Rust source paths
                          (``external/base/crates/`` plus any
                          ``external/<*>/crates/``). Custom paths
                          can be passed positionally.
  ``--out-dir <path>``    Output directory; defaults to
                          ``<ws>/critical_hunt/``.
  ``--json``              Emit JSON only (no Markdown side-car).
  ``--scope-asset <s>``   Override ``scope_asset`` field in rows.

Outputs (under ``<out-dir>``):
  ``rust_cache_miss_candidates.json``
  ``rust_cache_miss_candidates.md``

Stdlib-only. Idempotent. Offline-safe.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.rust_cache_miss_candidates.v1"

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
#
# All regexes use multi-line context where needed. We deliberately keep them
# simple — Rust has no Python-side AST library, so we rely on the surrounding
# function context (extracted by `_function_at`) plus exclusion heuristics
# to suppress test/init false positives.

# `match ... { Err(_) => Ok(()) ... }` or arm-style `Err(_) => Ok(())`.
RE_ERR_SWALLOW = re.compile(
    r"\bErr\s*\(\s*_\s*\)\s*=>\s*Ok\s*\(\s*\(\s*\)\s*\)",
)

# Bare `unwrap_or_default()` call.
RE_UNWRAP_OR_DEFAULT = re.compile(r"\.unwrap_or_default\s*\(\s*\)")

# `None => Ok(...)` arm.
RE_NONE_ARM_OK = re.compile(r"\bNone\s*=>\s*Ok\s*\(")

# `state_by_block_hash(` call site.
RE_STATE_BY_BLOCK_HASH = re.compile(r"\bstate_by_block_hash\s*\(")

# `let Some(x) = ... else { return Ok(...); }` — single-or-multi-line.
RE_LET_SOME_EARLY_OK = re.compile(
    r"\blet\s+Some\s*\([^)]*\)\s*=\s*[^;{]+?\s+else\s*\{\s*return\s+Ok\s*\(",
    re.DOTALL,
)

# `let Ok(...) = ... else { ... return Ok(...); }` — same shape but for
# a Result. This is the FN7 case at engine.rs:130-135.
RE_LET_OK_EARLY_OK = re.compile(
    r"\blet\s+Ok\s*\([^)]*\)\s*=\s*[^;{]+?\s+else\s*\{[^}]*?\breturn\s+Ok\s*\(",
    re.DOTALL,
)

# Deferred-validation comments.
RE_TODO_VALIDATE = re.compile(
    r"//\s*(?:TODO|FIXME|XXX)\b[^\n]*\b(?:validat|verify|check|later|skip)",
    re.IGNORECASE,
)
RE_SKIP_IF_MISSING = re.compile(
    r"//[^\n]*\bskip\b[^\n]*\bmissing\b",
    re.IGNORECASE,
)

# Top-level fn signature (very loose). We only use start positions to
# identify the parent fn for a hit.
RE_FN_DEF = re.compile(
    r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<\(]",
)


# Heuristics that mark a function/file as init / test / clearly safe.
INIT_FN_PREFIXES = (
    "new",
    "default",
    "init",
    "with_",
    "from_",
    "build",
    "builder",
    "configure",
    "setup",
)
TEST_DIR_TOKENS = ("/tests/", "/test_utils/", "/benches/", "/fuzz/")
TEST_FILE_TOKENS = ("_test.rs", "_tests.rs", "tests.rs", "test_utils.rs")
TEST_ATTR_TOKENS = (
    "#[test]",
    "#[tokio::test]",
    "#[cfg(test)]",
    "mod tests",
    "mod test",
)

# Patterns that, when the *line itself* names them, mark the
# `unwrap_or_default` call as clearly-safe (e.g., a HashMap with
# `unwrap_or_default()` to coerce a missing entry into an empty
# collection during display/build code).
SAFE_UNWRAP_OR_DEFAULT_LINE_TOKENS = (
    "to_string",
    "Default::default",
    ".clone()",
    ".len()",
    ".is_empty()",
    ".iter().collect",
)

# Validator-shaped fn-name tokens: hits inside one of these are upgraded
# from "advisory" to "high-risk" because a silent Ok in a validator is
# the FN7 shape.
VALIDATOR_FN_TOKENS = (
    "validate",
    "verify",
    "check",
    "ensure",
    "assert",
    "post_execution",
    "pre_validate",
    "consensus",
    "block_post_execution",
)


# ---------------------------------------------------------------------------
# Row dataclass
# ---------------------------------------------------------------------------


@dataclass
class CacheMissRow:
    candidate_id: str
    scope_asset: str
    impact_mapping: str
    candidate_status: str
    production_path: str
    required_proof: str
    artifact_refs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw_severity: str = ""
    has_execution_manifest: bool = False
    has_real_component_artifact: bool = False
    matches_listed_critical: bool = False
    pattern_type: str = ""
    function_context: str = ""
    risk_class: str = "advisory"
    file: str = ""
    line: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _function_at(source: str, offset: int) -> str:
    """Return the name of the nearest `fn` definition at or before `offset`.

    Loose heuristic: the last `fn NAME` start position <= offset wins.
    Returns ``""`` when no fn header is visible (e.g., file-level item).
    """
    last_name = ""
    for match in RE_FN_DEF.finditer(source, 0, offset + 1):
        if match.start() <= offset:
            last_name = match.group(1)
        else:
            break
    return last_name


def _is_test_file(path: Path) -> bool:
    p = str(path).replace("\\", "/")
    if any(token in p for token in TEST_DIR_TOKENS):
        return True
    name = path.name
    if any(name.endswith(token) or name == token for token in TEST_FILE_TOKENS):
        return True
    return False


def _function_is_test(source: str, fn_name: str) -> bool:
    """Return True when the function appears inside a `#[cfg(test)]` /
    `mod tests` / `#[test]` block, or has a test-only attribute right
    above it. Cheap heuristic: scan a 200-char window before each
    occurrence of the fn header."""
    if not fn_name:
        return False
    pat = re.compile(rf"\bfn\s+{re.escape(fn_name)}\b")
    for match in pat.finditer(source):
        start = max(0, match.start() - 200)
        window = source[start : match.start()]
        if any(tok in window for tok in TEST_ATTR_TOKENS):
            return True
    return False


def _function_is_init(fn_name: str) -> bool:
    if not fn_name:
        return False
    lowered = fn_name.lower()
    return any(lowered.startswith(prefix) for prefix in INIT_FN_PREFIXES)


def _function_is_validator(fn_name: str) -> bool:
    if not fn_name:
        return False
    lowered = fn_name.lower()
    return any(token in lowered for token in VALIDATOR_FN_TOKENS)


def _line_text(source: str, offset: int) -> str:
    line_start = source.rfind("\n", 0, offset) + 1
    line_end = source.find("\n", offset)
    if line_end < 0:
        line_end = len(source)
    return source[line_start:line_end]


def _line_is_clearly_safe_unwrap_or_default(line: str) -> bool:
    return any(token in line for token in SAFE_UNWRAP_OR_DEFAULT_LINE_TOKENS)


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------


def scan_file(path: Path, scope_asset: str = "") -> list[CacheMissRow]:
    if _is_test_file(path):
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rows: list[CacheMissRow] = []
    file_str = str(path)
    asset = scope_asset or _infer_scope_asset(path)

    # Quick file-level test bail: a file consisting entirely of
    # `#[cfg(test)]` items shouldn't fire. We require at least one
    # non-test fn somewhere in the source.
    if "#[cfg(test)]" in source and source.lstrip().startswith("#[cfg(test)]"):
        return []

    seen: set[tuple[str, int, str]] = set()

    def _emit(
        offset: int,
        pattern_type: str,
        risk: str,
        impact: str,
        proof: str,
        notes: Iterable[str] = (),
    ) -> None:
        line = _line_for_offset(source, offset)
        fn_name = _function_at(source, offset)

        # Suppress test-context hits.
        if _function_is_test(source, fn_name):
            return

        # Suppress init-context hits for unwrap_or_default and
        # `match Err(_) => Ok(())` only — the other patterns are
        # validator-shaped on their own.
        if pattern_type in {"unwrap_or_default", "err_arm_swallow"} and _function_is_init(fn_name):
            return

        key = (file_str, line, pattern_type)
        if key in seen:
            return
        seen.add(key)

        cid = f"rust-cache-miss::{path.name}:{line}::{pattern_type}"
        row_notes = ["default-to-kill: candidate not yet impact-mapped"]
        row_notes.extend(notes)
        if _function_is_validator(fn_name):
            row_notes.append(f"validator-shaped function `{fn_name}`")

        rows.append(
            CacheMissRow(
                candidate_id=cid,
                scope_asset=asset,
                impact_mapping=impact,
                candidate_status="kill_or_reframe",
                production_path=f"{file_str}:{line}",
                required_proof=proof,
                artifact_refs=[file_str],
                notes=row_notes,
                raw_severity="advisory",
                has_real_component_artifact=True,
                pattern_type=pattern_type,
                function_context=fn_name,
                risk_class=risk,
                file=file_str,
                line=line,
            )
        )

    # 1. Bare error-swallow `Err(_) => Ok(())`.
    for m in RE_ERR_SWALLOW.finditer(source):
        fn_name = _function_at(source, m.start())
        risk = "high" if _function_is_validator(fn_name) else "advisory"
        _emit(
            m.start(),
            "err_arm_swallow",
            risk,
            "validator returns Ok on swallowed error (cache miss policy)",
            "demonstrate a non-canonical / cache-missing input that reaches this arm in production",
        )

    # 2. `unwrap_or_default()`.
    for m in RE_UNWRAP_OR_DEFAULT.finditer(source):
        line_text = _line_text(source, m.start())
        if _line_is_clearly_safe_unwrap_or_default(line_text):
            continue
        fn_name = _function_at(source, m.start())
        risk = "high" if _function_is_validator(fn_name) else "advisory"
        _emit(
            m.start(),
            "unwrap_or_default",
            risk,
            "missing optional silently coerced to default in validator path",
            "show that a missing/default value lets a malformed input pass validation",
        )

    # 3. `None => Ok(...)` arm.
    for m in RE_NONE_ARM_OK.finditer(source):
        fn_name = _function_at(source, m.start())
        risk = "high" if _function_is_validator(fn_name) else "advisory"
        _emit(
            m.start(),
            "none_arm_ok",
            risk,
            "validator returns Ok when required optional is None",
            "construct an input where the optional is None and validation skips",
        )

    # 4. `state_by_block_hash` calls (separate row from 5/6 below — the
    # call itself is the cache lookup; the early-Ok pattern is the
    # silent-pass).
    for m in RE_STATE_BY_BLOCK_HASH.finditer(source):
        fn_name = _function_at(source, m.start())
        # Only emit when the surrounding fn is validator-shaped and the
        # function ALSO contains an early-Ok arm. Otherwise this is
        # noise (callers that propagate errors).
        if not _function_is_validator(fn_name):
            continue
        # Look ahead 400 chars for an `else { ... return Ok(...); }`
        # or `Err(_) => Ok(())` — confirms the silent-pass shape.
        window = source[m.start() : m.start() + 400]
        if not (
            "return Ok(" in window or RE_ERR_SWALLOW.search(window)
        ):
            continue
        _emit(
            m.start(),
            "state_by_block_hash_silent_pass",
            "high",
            "state_by_block_hash cache miss returns Ok in validator (FN7 shape)",
            "demonstrate a non-canonical parent_hash that bypasses post-execution checks",
            notes=[
                "matches FN7 silent-pass shape from base-azul engine.rs:124-152",
            ],
        )

    # 5. `let Some(x) = ... else { return Ok(...); }` — early Ok.
    for m in RE_LET_SOME_EARLY_OK.finditer(source):
        fn_name = _function_at(source, m.start())
        risk = "high" if _function_is_validator(fn_name) else "advisory"
        _emit(
            m.start(),
            "let_some_early_ok",
            risk,
            "validator skips work when an optional is None (early-Ok)",
            "demonstrate that the None branch is reachable for a malicious input",
        )

    # 6. `let Ok(x) = ... else { return Ok(...); }` — same shape but Result.
    for m in RE_LET_OK_EARLY_OK.finditer(source):
        fn_name = _function_at(source, m.start())
        risk = "high" if _function_is_validator(fn_name) else "advisory"
        _emit(
            m.start(),
            "let_ok_early_ok",
            risk,
            "validator skips work when a Result is Err (early-Ok)",
            "demonstrate that the Err branch is reachable for a malicious input",
            notes=[
                "matches FN7 silent-pass shape — Err arm returns Ok without running checks",
            ],
        )

    # 7. Deferred-validation comments.
    for m in RE_TODO_VALIDATE.finditer(source):
        _emit(
            m.start(),
            "deferred_validation_comment",
            "advisory",
            "developer flagged validation as TODO/FIXME",
            "confirm whether the deferred check is reachable in production",
        )
    for m in RE_SKIP_IF_MISSING.finditer(source):
        _emit(
            m.start(),
            "skip_if_missing_comment",
            "advisory",
            "comment admits the path is skipped when a value is missing",
            "confirm whether the skip path is reachable for an attacker-controlled input",
        )

    return rows


def _infer_scope_asset(path: Path) -> str:
    """Best-effort: take the first crate component under `external/`."""
    parts = path.parts
    if "external" in parts:
        idx = parts.index("external")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


# ---------------------------------------------------------------------------
# Workspace walk
# ---------------------------------------------------------------------------


def collect_rust_files(workspace: Path, extra_paths: list[Path]) -> list[Path]:
    """Return *.rs files under the standard Rust crate roots.

    Standard roots:
      ``<ws>/external/base/crates/``
      ``<ws>/external/<*>/crates/``  (any project under ``external/``)
    Plus any explicit paths the caller provided.
    """
    files: set[Path] = set()
    if workspace.is_dir():
        ext = workspace / "external"
        if ext.is_dir():
            for project in sorted(ext.iterdir()):
                crates = project / "crates"
                if crates.is_dir():
                    files.update(crates.rglob("*.rs"))
    for p in extra_paths:
        if p.is_file() and p.suffix == ".rs":
            files.add(p)
        elif p.is_dir():
            files.update(p.rglob("*.rs"))
    return sorted(files)


def scan_workspace(
    workspace: Path,
    extra_paths: list[Path],
    scope_asset: str = "",
) -> list[CacheMissRow]:
    files = collect_rust_files(workspace, extra_paths)
    rows: list[CacheMissRow] = []
    for path in files:
        rows.extend(scan_file(path, scope_asset=scope_asset))
    return rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_json(rows: list[CacheMissRow], workspace: Path) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "row_count": len(rows),
        "rows": [asdict(r) for r in rows],
    }


def render_markdown(rows: list[CacheMissRow], workspace: Path) -> str:
    lines = [
        "# Rust Cache-Miss Policy Candidates",
        "",
        f"Workspace: `{workspace}`",
        f"Row count: **{len(rows)}**",
        "",
        "All rows default to `kill_or_reframe` until impact-mapped via",
        "`tools/base-critical-candidate-matrix.py`.",
        "",
    ]
    if not rows:
        lines.append("_No cache-miss policy candidates flagged._")
        return "\n".join(lines) + "\n"

    by_pattern: dict[str, int] = {}
    for r in rows:
        by_pattern[r.pattern_type] = by_pattern.get(r.pattern_type, 0) + 1
    lines.append("## Summary by pattern")
    lines.append("")
    lines.append("| Pattern | Count |")
    lines.append("|---|---|")
    for pat, count in sorted(by_pattern.items()):
        lines.append(f"| `{pat}` | {count} |")
    lines.append("")

    lines.append("## Rows")
    lines.append("")
    lines.append("| candidate_id | risk | fn | path |")
    lines.append("|---|---|---|---|")
    for r in rows:
        cid = r.candidate_id
        fn = r.function_context or "(top-level)"
        lines.append(f"| `{cid}` | {r.risk_class} | `{fn}` | `{r.production_path}` |")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_outputs(rows: list[CacheMissRow], out_dir: Path, workspace: Path, json_only: bool) -> tuple[Path, Path | None]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "rust_cache_miss_candidates.json"
    json_path.write_text(json.dumps(render_json(rows, workspace), indent=2) + "\n")
    if json_only:
        return json_path, None
    md_path = out_dir / "rust_cache_miss_candidates.md"
    md_path.write_text(render_markdown(rows, workspace))
    return json_path, md_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Rust cache-miss / silent-success policy scanner (PR #546).",
    )
    p.add_argument("--workspace", type=Path, default=None, help="Workspace root (defaults to no walk).")
    p.add_argument("paths", nargs="*", type=Path, help="Extra files / directories to scan.")
    p.add_argument("--out-dir", type=Path, default=None, help="Output dir (defaults to <ws>/critical_hunt/).")
    p.add_argument("--scope-asset", type=str, default="", help="Override scope_asset on every row.")
    p.add_argument("--json", action="store_true", help="JSON only (no Markdown side-car).")
    p.add_argument("--stdout", action="store_true", help="Print JSON to stdout (and skip file output).")
    p.add_argument("--strict", action="store_true", help="Exit 1 when any high-risk row was emitted.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    workspace = args.workspace or Path.cwd()
    rows = scan_workspace(workspace, args.paths, scope_asset=args.scope_asset)

    if args.stdout:
        print(json.dumps(render_json(rows, workspace), indent=2))
    else:
        out_dir = args.out_dir or (workspace / "critical_hunt")
        json_path, md_path = write_outputs(rows, out_dir, workspace, args.json)
        print(f"[rust-cache-miss-scan] wrote {json_path}")
        if md_path:
            print(f"[rust-cache-miss-scan] wrote {md_path}")
        print(f"[rust-cache-miss-scan] {len(rows)} rows ({sum(1 for r in rows if r.risk_class == 'high')} high-risk)")

    if args.strict and any(r.risk_class == "high" for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
