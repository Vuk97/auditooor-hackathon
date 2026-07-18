#!/usr/bin/env python3
"""rust-constant-resolver.py — resolve pub const / pub static / lazy_static! values.

P0-2 burn-down (Wave C-2B): when a Rust candidate cites an implementation-pointer
constant (e.g. `pub const TOKEN_X: Address = ...`), the production-path dossier
previously only knew the constant *existed*; it had no value to reason about.
This tool builds a per-crate registry mapping each named constant to its literal
value (when extractable) or an expression/opaque annotation (when too complex).

Scope:
  - Stdlib-only (regex, no syn/tree-sitter/rustc).
  - Three constant shapes:
      1. ``pub const NAME: Type = EXPR;``
      2. ``pub static NAME: Type = EXPR;``
         ``pub static ref NAME: Type = EXPR;`` (lazy_static-like)
      3. ``lazy_static! { static ref NAME: Type = EXPR; }``
  - Resolution confidence:
      ``literal``    — EXPR is a plain literal (number, string, bool, hex,
                       Address/Bytes literal, or CONST_NAME array).
      ``expression`` — EXPR contains identifiers or arithmetic; value is
                       preserved verbatim for human review but not resolved.
      ``opaque``     — EXPR spans multiple lines, contains function calls, or
                       we cannot extract a clean value.

Output: ``<workspace>/.auditooor/rust_constant_registry.json``
Schema: ``auditooor.rust_constant_registry.v1``

Each row:
  {crate, file, line, kind, name, type, literal_value_or_expr,
   resolution_confidence}

CLI:
  tools/rust-constant-resolver.py --workspace <path> [--out <path>]
  tools/rust-constant-resolver.py --validate <path>

Exit codes:
  0  scan/validate succeeded
  2  invalid CLI arguments / missing workspace
  3  --validate failed schema integrity
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "auditooor.rust_constant_registry.v1"

SKIP_DIR_PARTS = {
    "target", "node_modules", ".git", "build", "out", ".auditooor", "scanners",
}

# ---------------------------------------------------------------------------
# Heuristic regexes
# ---------------------------------------------------------------------------

# HEURISTIC: pub const / pub static at module level. We require `pub` to avoid
# capturing private constants (which are internal and less relevant for
# cross-boundary pointer resolution). `pub(crate)` and `pub(super)` are
# excluded (they stay inside the crate). Const fn bodies are NOT captured
# (they look like `pub const fn name...` which has a `fn` token).
_PUB_CONST_RE = re.compile(
    r"^\s*pub\s+const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<type>[^=]+?)\s*=\s*(?P<expr>.+?)\s*;\s*$"
)
_PUB_STATIC_RE = re.compile(
    r"^\s*pub\s+static\s+(?:mut\s+|ref\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<type>[^=]+?)\s*=\s*(?P<expr>.+?)\s*;\s*$"
)

# HEURISTIC: lazy_static! block opener. We detect the macro call and then
# scan the block body (up to the matching `}`) for `static ref NAME: Type = EXPR;`
# lines. We do NOT try to handle nested macros inside a lazy_static! block.
_LAZY_STATIC_OPEN_RE = re.compile(r"\blazy_static!\s*\{")
_LAZY_STATIC_ENTRY_RE = re.compile(
    r"^\s*static\s+ref\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<type>[^=]+?)\s*=\s*(?P<expr>.+?)\s*;\s*$"
)

# HEURISTIC: also capture once_cell / std::sync::OnceLock static-ref patterns.
# Shape: `static NAME: OnceLock<Type> = OnceLock::new();`
# We capture these as opaque (the value is initialized at runtime).
_ONCE_CELL_RE = re.compile(
    r"^\s*(?:pub\s+)?static\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<type>(?:OnceLock|OnceCell|Lazy|SyncLazy)<[^>]+>)\s*=\s*(?P<expr>.+?)\s*;\s*$"
)

# HEURISTIC: literal detection. A value is `literal` when the EXPR (after
# stripping wrapping parens) matches one of:
#   - integer / float literal (optionally with _ separators)
#   - string literal "..." or b"..."
#   - boolean true / false
#   - hex literal 0x...
#   - address-like 0x[0-9a-f]{40}
#   - array of literals: [lit, lit, ...]
#   - type-constructors around a literal: Address::from_array([...]), u64::MAX, etc.
#     (captured as expression; not literal)
_LITERAL_INT_RE = re.compile(r"^-?(?:0x[0-9a-fA-F_]+|0b[01_]+|0o[0-7_]+|[0-9][0-9_]*)(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64)?$")
_LITERAL_FLOAT_RE = re.compile(r"^-?[0-9][0-9_]*\.[0-9_]+(?:f32|f64)?$")
_LITERAL_STR_RE = re.compile(r'^b?"[^"\\]*(?:\\.[^"\\]*)*"$')
_LITERAL_BOOL_RE = re.compile(r"^(?:true|false)$")
_LITERAL_ARRAY_RE = re.compile(r"^\[.*\]$", re.DOTALL)


def _resolution_confidence(expr: str) -> str:
    e = expr.strip()
    # Remove outer parens iteratively
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    if _LITERAL_INT_RE.match(e):
        return "literal"
    if _LITERAL_FLOAT_RE.match(e):
        return "literal"
    if _LITERAL_STR_RE.match(e):
        return "literal"
    if _LITERAL_BOOL_RE.match(e):
        return "literal"
    # Array literals (may contain complex exprs, but visually literal)
    if _LITERAL_ARRAY_RE.match(e):
        # Check that all inner elements are simple literals (best-effort)
        inner = e[1:-1].strip()
        if not inner:
            return "literal"
        parts = [p.strip() for p in inner.split(",")]
        if all(
            _LITERAL_INT_RE.match(p) or _LITERAL_STR_RE.match(p) or _LITERAL_BOOL_RE.match(p)
            for p in parts if p
        ):
            return "literal"
        return "expression"
    # Contains function calls, operators, identifiers
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", e):
        return "expression"
    if re.search(r"::", e):
        return "expression"
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*", e):
        return "expression"
    return "opaque"


def _strip_comment(line: str) -> str:
    if '"' in line:
        return line
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _skip_path(path: Path) -> bool:
    return any(part in SKIP_DIR_PARTS for part in path.parts)


# ---------------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------------

def _extract_file(
    workspace: Path,
    crate_name: str,
    path: Path,
    rows: List[Dict[str, Any]],
) -> None:
    rel = _rel(workspace, path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    lines = text.splitlines()

    # Skip `pub const fn` lines (const functions, not constants).
    # We do a single-line scan first, then handle multiline expressions.
    inside_lazy_static = False
    lazy_depth = 0

    for idx, raw_line in enumerate(lines):
        line = _strip_comment(raw_line)

        # Detect lazy_static! block entry/exit.
        if _LAZY_STATIC_OPEN_RE.search(line):
            inside_lazy_static = True
            lazy_depth = 1
            continue

        if inside_lazy_static:
            lazy_depth += line.count("{") - line.count("}")
            if lazy_depth <= 0:
                inside_lazy_static = False
                continue
            m = _LAZY_STATIC_ENTRY_RE.match(line)
            if m and not re.search(r"\bfn\b", line):
                expr = m.group("expr").strip()
                rows.append({
                    "crate": crate_name,
                    "file": rel,
                    "line": idx + 1,
                    "kind": "lazy_static",
                    "name": m.group("name"),
                    "type": m.group("type").strip(),
                    "literal_value_or_expr": expr,
                    "resolution_confidence": _resolution_confidence(expr),
                })
            continue

        # Skip const fn (has `fn` token after `const`).
        if re.match(r"^\s*pub\s+const\s+fn\b", line):
            continue
        # Skip `const fn` without pub.
        if re.match(r"^\s*const\s+fn\b", line):
            continue

        # OnceLock / OnceLock-family statics (opaque by design).
        m_once = _ONCE_CELL_RE.match(line)
        if m_once:
            rows.append({
                "crate": crate_name,
                "file": rel,
                "line": idx + 1,
                "kind": "static",
                "name": m_once.group("name"),
                "type": m_once.group("type").strip(),
                "literal_value_or_expr": m_once.group("expr").strip(),
                "resolution_confidence": "opaque",
            })
            continue

        # pub const NAME: Type = EXPR;
        m_const = _PUB_CONST_RE.match(line)
        if m_const:
            expr = m_const.group("expr").strip()
            # Multi-line const: if the line doesn't end with `;` (after
            # stripping comment), try to join the next few lines.
            if not raw_line.rstrip().endswith(";"):
                joined = raw_line.rstrip()
                for follow_idx in range(idx + 1, min(idx + 8, len(lines))):
                    joined += " " + lines[follow_idx].strip()
                    if joined.rstrip().endswith(";"):
                        break
                m2 = _PUB_CONST_RE.match(joined)
                if m2:
                    expr = m2.group("expr").strip()
                else:
                    expr = joined
                    rows.append({
                        "crate": crate_name,
                        "file": rel,
                        "line": idx + 1,
                        "kind": "const",
                        "name": m_const.group("name"),
                        "type": m_const.group("type").strip(),
                        "literal_value_or_expr": expr[:400],
                        "resolution_confidence": "opaque",
                    })
                    continue
            rows.append({
                "crate": crate_name,
                "file": rel,
                "line": idx + 1,
                "kind": "const",
                "name": m_const.group("name"),
                "type": m_const.group("type").strip(),
                "literal_value_or_expr": expr[:400],
                "resolution_confidence": _resolution_confidence(expr),
            })
            continue

        # pub static NAME: Type = EXPR;
        m_static = _PUB_STATIC_RE.match(line)
        if m_static:
            expr = m_static.group("expr").strip()
            rows.append({
                "crate": crate_name,
                "file": rel,
                "line": idx + 1,
                "kind": "static",
                "name": m_static.group("name"),
                "type": m_static.group("type").strip(),
                "literal_value_or_expr": expr[:400],
                "resolution_confidence": _resolution_confidence(expr),
            })


# ---------------------------------------------------------------------------
# Crate discovery (mirrors rust-source-graph.py)
# ---------------------------------------------------------------------------

_CARGO_PACKAGE_NAME_RE = re.compile(
    r'^\s*name\s*=\s*"([A-Za-z0-9_\-]+)"\s*$', re.MULTILINE
)


def _crate_name_from_cargo(root: Path, fallback: str) -> str:
    cargo = root / "Cargo.toml"
    if not cargo.is_file():
        return fallback
    try:
        text = cargo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback
    m = _CARGO_PACKAGE_NAME_RE.search(text)
    return m.group(1) if m else fallback


def discover_crates(workspace: Path) -> List[Tuple[str, Path]]:
    crates: List[Tuple[str, Path]] = []
    seen: set = set()

    def _add(name: str, root: Path) -> None:
        root = root.resolve()
        if root in seen:
            return
        if not (root / "src").is_dir():
            return
        seen.add(root)
        crates.append((_crate_name_from_cargo(root, name), root))

    if workspace.is_dir():
        for cargo in sorted(workspace.rglob("Cargo.toml")):
            if _skip_path(cargo):
                continue
            root = cargo.parent
            if (root / "src").is_dir():
                _add(root.name, root)

    if not crates and (workspace / "src").is_dir():
        _add(workspace.name or "crate", workspace)

    return crates


def _rs_files(root: Path) -> List[Path]:
    if not root.exists() or not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.rs") if p.is_file() and not _skip_path(p))


# ---------------------------------------------------------------------------
# Registry build
# ---------------------------------------------------------------------------

def build_registry(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.resolve()
    crates = discover_crates(workspace)
    rows: List[Dict[str, Any]] = []
    for crate_name, crate_root in crates:
        for rs_path in _rs_files(crate_root / "src"):
            _extract_file(workspace, crate_name, rs_path, rows)

    literal_count = sum(1 for r in rows if r["resolution_confidence"] == "literal")
    expression_count = sum(1 for r in rows if r["resolution_confidence"] == "expression")
    opaque_count = sum(1 for r in rows if r["resolution_confidence"] == "opaque")

    return {
        "_meta": {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "crate_count": len(crates),
            "total_constants": len(rows),
            "literal_count": literal_count,
            "expression_count": expression_count,
            "opaque_count": opaque_count,
        },
        "constants": rows,
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

REQUIRED_ROW_KEYS = {
    "crate", "file", "line", "kind", "name", "type",
    "literal_value_or_expr", "resolution_confidence",
}
VALID_KINDS = {"const", "static", "lazy_static"}
VALID_CONFIDENCES = {"literal", "expression", "opaque"}


def validate_registry(data: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(data, dict):
        return ["top-level: expected dict"]
    meta = data.get("_meta")
    if not isinstance(meta, dict):
        errors.append("_meta: missing or not a dict")
    else:
        if meta.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"_meta.schema_version: expected {SCHEMA_VERSION}, "
                f"got {meta.get('schema_version')!r}"
            )
        for k in ("crate_count", "total_constants", "literal_count", "expression_count", "opaque_count"):
            if not isinstance(meta.get(k), int):
                errors.append(f"_meta.{k}: expected int")
    constants = data.get("constants")
    if not isinstance(constants, list):
        errors.append("constants: expected list")
        return errors
    for i, row in enumerate(constants):
        if not isinstance(row, dict):
            errors.append(f"constants[{i}]: expected dict")
            continue
        missing = REQUIRED_ROW_KEYS - set(row.keys())
        if missing:
            errors.append(f"constants[{i}]: missing keys {sorted(missing)}")
            continue
        if row["kind"] not in VALID_KINDS:
            errors.append(f"constants[{i}]: invalid kind {row['kind']!r}")
        if row["resolution_confidence"] not in VALID_CONFIDENCES:
            errors.append(f"constants[{i}]: invalid resolution_confidence {row['resolution_confidence']!r}")
    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_out(workspace: Path) -> Path:
    return workspace / ".auditooor" / "rust_constant_registry.json"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rust-constant-resolver",
        description=(
            "Build a Rust constant/static/lazy_static registry with "
            "literal-value resolution. Stdlib-only; not a full Rust frontend."
        ),
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace", type=Path, help="Build registry for this workspace.")
    g.add_argument("--validate", type=Path, help="Re-read and assert schema integrity.")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--print-json", action="store_true")
    args = p.parse_args(argv)

    if args.validate is not None:
        path = args.validate.expanduser().resolve()
        if not path.is_file():
            print(f"[rust-constant-resolver] ERR not found: {path}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"[rust-constant-resolver] ERR cannot parse {path}: {exc}", file=sys.stderr)
            return 3
        errors = validate_registry(data)
        if errors:
            for e in errors:
                print(f"[rust-constant-resolver] schema-error {e}", file=sys.stderr)
            return 3
        print(f"[rust-constant-resolver] OK {path} schema={SCHEMA_VERSION}", file=sys.stderr)
        return 0

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-constant-resolver] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2

    registry = build_registry(workspace)
    out = args.out.expanduser().resolve() if args.out else _default_out(workspace)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        sys.stdout.write(json.dumps(registry, indent=2, sort_keys=True) + "\n")
    meta = registry["_meta"]
    print(
        f"[rust-constant-resolver] OK crates={meta['crate_count']} "
        f"constants={meta['total_constants']} "
        f"literal={meta['literal_count']} expression={meta['expression_count']} opaque={meta['opaque_count']} "
        f"json={out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
