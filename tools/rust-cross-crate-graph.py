#!/usr/bin/env python3
"""rust-cross-crate-graph.py — first slice of cross-crate Rust analysis.

Wave 2 capability uplift on top of PR #462. PR #462 shipped
`tools/rust-source-graph.py`, a per-crate syntactic inventory (entrypoints
/ trait impls / external calls / unsafe / value movement). It explicitly
deferred cross-crate analysis: every crate is scanned independently and
an `Env::invoke_contract` to another in-workspace crate becomes a generic
`external_call` with no resolved target.

This tool adds the FIRST cross-crate slice — an *import* graph + workspace
dependency extraction. Two layers:

  1. **Workspace dep graph** — parse every crate `Cargo.toml` under the
     workspace while pruning heavy/generated directories. Pull
     `[dependencies]` and `[workspace.dependencies]` tables and split each
     dep into `intra_workspace` (crate name resolves to another crate
     discovered in the same workspace) or `external` (everything else,
     including crates.io deps and git/path deps that point outside the
     workspace).

  2. **`use`-statement import graph** — walk every `*.rs` under each
     discovered crate and parse `use <path>::...;` statements with regex
     over Rust source. Map each `use` to the crate it imports from. Three
     buckets:

       * `intra_crate` — `use crate::...`, `use self::...`, `use super::...`.
         Folded; not emitted in the final graph.
       * `intra_workspace` — `use other_workspace_crate::...`. Emits a
         crate-to-crate edge.
       * `external` — `use anchor_lang::...`, `use std::...`, etc.

  Edge format: `{from_crate, from_file, to_crate, to_path}` where
  `to_path` is the full `use` path string post-cleaning.

Heuristic boundaries (documented inline; mirrored in
`docs/RUST_SOURCE_GRAPH.md`):

  - **Conditional `cfg(feature = "x")` deps NOT resolved.** The graph
    treats every dep declared in `[dependencies]` (and
    `[workspace.dependencies]`) as live. A feature-gated dep that is
    only pulled in under a specific cargo feature still appears as if
    it were always present.
  - **Macro-imported names NOT followed.** A macro that internally
    expands to `use foo::Bar;` will not be reflected.
  - **`use crate::module` (intra-crate) folded.** The dossier already
    sees the same files as the per-crate scan; intra-crate is noise.
  - **`pub use` re-exports counted as imports.** A re-export still pulls
    the source crate in.
  - **Glob imports (`use foo::*;`) recorded with `to_path == "foo::*"`.**
    Target crate is `foo`.
  - **`use ::foo::Bar;` rooted absolute paths supported.** Leading `::`
    stripped before crate-name resolution.
  - **Aliased imports (`use foo as bar`)** recorded with `to_path` =
    original path, alias not tracked.
  - **TOML parsing prefers `tomllib` (Python 3.11+).** A regex-based
    parser handles the only two table shapes we need (`[dependencies]`
    and `[workspace.dependencies]`) when `tomllib` is missing or the
    Cargo.toml has fancy syntax we cannot parse — failing closed to
    "no deps found" rather than crashing.

Output: `<workspace>/.auditooor/rust_cross_crate_graph.json`. Schema:

  {
    "_meta": {
      "schema_version": "auditooor.rust_cross_crate_graph.v1",
      "workspace": "<abs path>",
      "crate_count": <int>,
      "edge_count":  <int>
    },
    "crates": {
      "<crate_name>": {
        "path":           "<rel crate dir>",
        "deps_intra":     ["other_workspace_crate", ...],
        "deps_external":  ["anchor-lang", "serde", ...],
        "imports_in":     {
          "<rel rs file>": ["other_crate::module::Item", ...]
        }
      }
    },
    "edges": [
      {"from_crate", "from_file", "to_crate", "to_path"},
      ...
    ]
  }

CLI:
  tools/rust-cross-crate-graph.py --workspace <path> [--out <path>]
  tools/rust-cross-crate-graph.py --validate <path>

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
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Inline re-use of rust-source-graph helpers for trait dispatch.
# We import the module dynamically to avoid duplication if it is on sys.path,
# but fall back to None if the companion tool is unavailable (e.g. during
# validate-only runs).
# ---------------------------------------------------------------------------
import importlib.util as _ilu
import os as _os

def _load_source_graph_module() -> Any:
    """Load rust-source-graph as a module so we can reuse its extractors."""
    tool_dir = Path(__file__).resolve().parent
    candidate = tool_dir / "rust-source-graph.py"
    if not candidate.is_file():
        return None
    spec = _ilu.spec_from_file_location("rust_source_graph", candidate)
    if spec is None or spec.loader is None:
        return None
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod

_RSG = _load_source_graph_module()


SCHEMA_VERSION = "auditooor.rust_cross_crate_graph.v1"
SKIP_DIR_PARTS = {
    "target",
    "node_modules",
    ".git",
    "build",
    "out",
    ".auditooor",
    "scanners",
}


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# HEURISTIC: `use` statement parse. We deliberately handle the common
# forms and ignore exotic ones:
#   use foo::bar;
#   use foo::bar::Baz;
#   use foo::*;
#   use foo::{a, b::c};   <-- the brace group is captured but not split
#                              into separate paths; the head crate is the
#                              only thing we use to resolve target crate,
#                              which is enough.
#   pub use foo::bar;
#   use ::foo::bar;       <-- absolute path
#   use foo::bar as baz;  <-- alias not tracked
#
# Multi-line `use foo::{...}` brace groups that span lines are NOT
# supported; the head crate (`foo`) is still captured because the `use`
# keyword + first segment live on the first line. Acceptable false
# negative for the brace contents (we still get the edge).
_USE_RE = re.compile(
    r"^\s*(?:pub\s+)?use\s+(?P<path>::?[A-Za-z_][A-Za-z0-9_:]*"
    r"(?:\s*::\s*\*)?(?:\s*::\s*\{[^}]*\})?"
    r"|[A-Za-z_][A-Za-z0-9_:]*"
    r"(?:\s*::\s*\*)?(?:\s*::\s*\{[^}]*\})?)"
    r"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*;",
    re.MULTILINE,
)

# Fallback regex-mode TOML parser for when tomllib cannot parse a
# Cargo.toml (extremely rare in well-formed Cargo files; this is a
# safety net). We only need to extract the *names* on the LHS of the
# `[dependencies]` and `[workspace.dependencies]` tables.
_TOML_TABLE_HEADER_RE = re.compile(r"^\s*\[(?P<name>[A-Za-z0-9_\.\-]+)\]\s*$")
_TOML_KEY_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_\-]*)\s*=")
_TOML_PACKAGE_NAME_RE = re.compile(
    r'^\s*name\s*=\s*"([A-Za-z0-9_\-]+)"\s*$', re.MULTILINE
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skip_path(path: Path) -> bool:
    return any(part in SKIP_DIR_PARTS for part in path.parts)


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _normalize_crate_name(name: str) -> str:
    """Cargo-name normalization: hyphens and underscores are interchangeable
    in `use` paths (the crate `anchor-lang` is referenced as
    `anchor_lang::...` in source). We canonicalize to underscore for
    matching."""
    return name.strip().replace("-", "_")


# ---------------------------------------------------------------------------
# Cargo.toml parsing
# ---------------------------------------------------------------------------

def _parse_cargo_toml_with_tomllib(text: str) -> Dict[str, Any]:
    if tomllib is None:
        return {}
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}


def _parse_cargo_toml_regex(text: str) -> Dict[str, Any]:
    """Regex fallback. Returns a partial dict shaped like the tomllib
    output for the only two tables we care about: `[dependencies]` and
    `[workspace.dependencies]`. The values are empty dicts (we only
    need the keys).

    We also pull `[package].name` so we know the crate name even when
    tomllib is unavailable.
    """
    out: Dict[str, Any] = {}
    current: Optional[List[str]] = None
    for raw in text.splitlines():
        # strip line comments
        line = raw.split("#", 1)[0]
        m_hdr = _TOML_TABLE_HEADER_RE.match(line)
        if m_hdr:
            parts = m_hdr.group("name").split(".")
            current = parts
            # ensure nested dict exists
            d = out
            for p in parts:
                d = d.setdefault(p, {})
            continue
        if current is None:
            continue
        m_key = _TOML_KEY_RE.match(line)
        if not m_key:
            continue
        d = out
        for p in current:
            d = d.setdefault(p, {})
        d[m_key.group(1)] = {}  # value not needed
    # Stash the package.name if we found one; tomllib path stashes it
    # naturally so this just tries to keep parity.
    m_name = _TOML_PACKAGE_NAME_RE.search(text)
    if m_name:
        pkg = out.setdefault("package", {})
        pkg["name"] = m_name.group(1)
    return out


def _read_cargo_toml(path: Path) -> Dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    parsed = _parse_cargo_toml_with_tomllib(text) if tomllib is not None else {}
    if not parsed:
        parsed = _parse_cargo_toml_regex(text)
    return parsed


def _crate_name_from_cargo(parsed: Dict[str, Any], fallback: str) -> str:
    pkg = parsed.get("package")
    if isinstance(pkg, dict):
        name = pkg.get("name")
        if isinstance(name, str) and name:
            return name
    return fallback


def _deps_from_cargo(parsed: Dict[str, Any]) -> List[str]:
    """Collect dependency names from `[dependencies]` and
    `[workspace.dependencies]`. Feature-gated `[target.*]` deps are not
    resolved (heuristic boundary); they would need conditional cfg
    handling we deliberately skip."""
    out: List[str] = []
    deps = parsed.get("dependencies")
    if isinstance(deps, dict):
        out.extend(k for k in deps.keys() if isinstance(k, str))
    ws = parsed.get("workspace")
    if isinstance(ws, dict):
        wsdeps = ws.get("dependencies")
        if isinstance(wsdeps, dict):
            out.extend(k for k in wsdeps.keys() if isinstance(k, str))
    # de-dupe preserving order
    seen: Set[str] = set()
    uniq: List[str] = []
    for n in out:
        if n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


# ---------------------------------------------------------------------------
# Crate discovery
# ---------------------------------------------------------------------------

def discover_crates(workspace: Path) -> List[Tuple[str, Path]]:
    """Return ordered list of `(crate_name, crate_root_dir)` to scan.

    Priority (matches `rust-source-graph.py`):
      1. Any `Cargo.toml` under `<workspace>` whose parent has `src/`.
         This intentionally covers real engagement roots that nest code
         under `external/<project>/...`.
      2. Fallback: workspace itself is a single crate.

    crate_name comes from `Cargo.toml [package] name` when present;
    otherwise the dir basename.
    """
    crates: List[Tuple[str, Path]] = []
    seen: Set[Path] = set()

    def _add(default_name: str, root: Path) -> None:
        root = root.resolve()
        if root in seen:
            return
        cargo = root / "Cargo.toml"
        if not cargo.is_file():
            return
        # `src/` is not strictly required at the cross-crate layer (a
        # workspace virtual manifest may have only `[workspace]` and no
        # source), but to keep parity with the per-crate graph we still
        # require it. A virtual root with no `src/` is handled in the
        # workspace-level dep collection step below.
        if not (root / "src").is_dir():
            return
        parsed = _read_cargo_toml(cargo)
        name = _crate_name_from_cargo(parsed, default_name)
        seen.add(root)
        crates.append((name, root))

    # Real engagements often wrap source in `external/<project>/...`. Walk
    # Cargo roots from the engagement root instead of requiring operators to
    # point WS at the nested Rust checkout.
    if workspace.is_dir():
        for cargo in sorted(workspace.rglob("Cargo.toml")):
            if _skip_path(cargo):
                continue
            root = cargo.parent
            if (root / "src").is_dir():
                _add(root.name, root)

    # Fallback: workspace itself is a single crate.
    if not crates and (workspace / "src").is_dir() and (workspace / "Cargo.toml").is_file():
        _add(workspace.name or "crate", workspace)

    return crates


def _rs_files_in(root: Path) -> List[Path]:
    if not root.exists() or not root.is_dir():
        return []
    out: List[Path] = []
    for p in root.rglob("*.rs"):
        if not p.is_file():
            continue
        if _skip_path(p):
            continue
        out.append(p)
    return sorted(out)


# ---------------------------------------------------------------------------
# `use` parsing
# ---------------------------------------------------------------------------

def _head_crate_from_use_path(path: str) -> Optional[str]:
    """Pull the first identifier from a `use` path. Returns None for
    intra-crate (`crate::...`, `self::...`, `super::...`) and the
    underscore-normalized crate name otherwise."""
    p = path.strip()
    if p.startswith("::"):
        p = p[2:]
    # split on first `::` separator (whitespace-tolerant)
    head = re.split(r"\s*::\s*", p, maxsplit=1)[0]
    head = head.strip()
    if not head:
        return None
    if head in {"crate", "self", "super"}:
        return None
    # intra-module-segment shapes can show up if the regex catches a
    # nested `use` brace contents — drop anything that isn't a clean
    # ident.
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", head):
        return None
    return _normalize_crate_name(head)


def _clean_use_path(raw: str) -> str:
    """Collapse whitespace and trim an extracted `use` path to a stable
    string suitable for `to_path` in the output."""
    return re.sub(r"\s+", "", raw).strip(":")


def parse_use_paths(text: str) -> List[Tuple[str, Optional[str]]]:
    """Yield `(cleaned_path, head_crate_or_None)` for every `use` in
    `text`. `head_crate` is None for intra-crate uses (folded
    downstream)."""
    out: List[Tuple[str, Optional[str]]] = []
    for m in _USE_RE.finditer(text):
        raw = m.group("path")
        if raw is None:
            continue
        cleaned = _clean_use_path(raw)
        # The cleaned path may end in `::*` or `::{a,b}`; head crate
        # comes from before any `::` separator.
        head = _head_crate_from_use_path(cleaned)
        out.append((cleaned, head))
    return out


# ---------------------------------------------------------------------------
# Cross-crate trait dispatch resolution
# ---------------------------------------------------------------------------

def _build_cross_crate_dispatch(
    workspace: Path,
    discovered: List[Tuple[str, Path]],
) -> List[Dict[str, Any]]:
    """Build cross_crate_dispatch edges using rust-source-graph extractors.

    Algorithm (heuristic / source-shape only):
      1. For each crate, collect declared trait methods (trait_decl_crate).
      2. For each crate, collect `impl Trait for Struct` pairs (impl_crate).
      3. For each crate, scan `trait_impl_methods` whose `trait_decl_file` is
         empty (the bound view marks these as cross-crate). Pair them with
         trait declarations and impls found in OTHER crates by (trait_name, fn).
      4. Emit one `cross_crate_dispatch` edge per resolved triple.

    Edge shape:
      {site_file, site_line, trait_name, struct_name,
       trait_decl_crate, impl_crate, target_method}
    """
    if _RSG is None:
        return []

    # Per-crate data: trait declarations and trait impls.
    # trait_decls: {normalized_trait_name -> [{crate, file, line, fn}]}
    # trait_impls: {(normalized_trait_name, normalized_struct_name) -> [{crate, file, line}]}
    trait_decls: Dict[str, List[Dict[str, Any]]] = {}
    trait_impl_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    # impl_methods_by_crate: crate_name -> [bound trait_impl_method records]
    impl_methods_by_crate: Dict[str, List[Dict[str, Any]]] = {}

    for crate_name, crate_root in discovered:
        src = crate_root / "src"
        if not src.is_dir():
            continue
        rs_files = []
        for p in src.rglob("*.rs"):
            if p.is_file() and not any(part in SKIP_DIR_PARTS for part in p.parts):
                rs_files.append(p)

        crate_trait_methods: List[Dict[str, Any]] = []
        crate_impl_methods: List[Dict[str, Any]] = []
        crate_trait_impls_raw: List[Dict[str, Any]] = []

        for f in rs_files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            crate_trait_methods.extend(_RSG._collect_trait_methods(workspace, f, text))
            crate_impl_methods.extend(_RSG._collect_impl_methods(workspace, f, text))
            # Also collect raw trait impls (impl Trait for Struct).
            for m in _RSG._TRAIT_IMPL_RE.finditer(text):
                trait = m.group("trait").strip()
                struct = m.group("struct").strip()
                if "{" in trait or "{" in struct:
                    continue
                crate_trait_impls_raw.append({
                    "crate": crate_name,
                    "trait": _RSG._normalize_trait_name(trait),
                    "struct": _RSG._normalize_trait_name(struct),
                    "file": _rel(workspace, f),
                    "line": text.count("\n", 0, m.start()) + 1,
                })

        # Index trait declarations from this crate.
        for tm in crate_trait_methods:
            key = _normalize_crate_name(tm.get("trait", ""))
            trait_decls.setdefault(key, []).append({
                "crate": crate_name,
                "file": tm.get("file", ""),
                "line": tm.get("line", 0),
                "fn": tm.get("fn", ""),
                "trait": tm.get("trait", ""),
            })

        # Index trait impls from this crate.
        for ti in crate_trait_impls_raw:
            k = (_normalize_crate_name(ti["trait"]), _normalize_crate_name(ti["struct"]))
            trait_impl_map.setdefault(k, []).append(ti)

        # Bind impl methods and store under crate.
        bound = _RSG._bind_trait_impl_methods(crate_trait_methods, crate_impl_methods)
        impl_methods_by_crate[crate_name] = bound

    # Now resolve cross-crate dispatch edges.
    # For each crate C and each bound impl method M whose trait_decl_file == ""
    # (the binding was to an unresolved cross-crate decl), look up (trait, fn)
    # in trait_decls from other crates. If found, check that the struct matches
    # a trait_impl from yet another (or same) crate to produce the full triple.
    dispatch_edges: List[Dict[str, Any]] = []
    seen_edges: set = set()

    for site_crate, bound_methods in impl_methods_by_crate.items():
        for m in bound_methods:
            # Only process methods where the trait declaration was NOT resolved
            # within the same crate (trait_decl_file is empty = cross-crate).
            if m.get("trait_decl_file"):
                continue
            trait_name = m.get("trait", "")
            struct_name = m.get("struct", "")
            fn_name = m.get("fn", "")
            if not (trait_name and fn_name):
                continue

            norm_trait = _normalize_crate_name(trait_name)
            norm_struct = _normalize_crate_name(struct_name)

            # Find decl crates for this trait+fn (other than site_crate).
            decl_hits = [
                d for d in trait_decls.get(norm_trait, [])
                if d["fn"] == fn_name and d["crate"] != site_crate
            ]
            if not decl_hits:
                continue

            # Find impl crates for (trait, struct).
            impl_hits = trait_impl_map.get((norm_trait, norm_struct), [])

            for decl in decl_hits:
                if impl_hits:
                    for impl_rec in impl_hits:
                        edge_key = (
                            m.get("file", ""), int(m.get("line", 0)),
                            trait_name, struct_name,
                            decl["crate"], impl_rec["crate"], fn_name,
                        )
                        if edge_key in seen_edges:
                            continue
                        seen_edges.add(edge_key)
                        dispatch_edges.append({
                            "site_file": m.get("file", ""),
                            "site_line": m.get("line", 0),
                            "trait_name": trait_name,
                            "struct_name": struct_name,
                            "trait_decl_crate": decl["crate"],
                            "impl_crate": impl_rec["crate"],
                            "target_method": fn_name,
                            "confidence": "source-shape",
                        })
                else:
                    # No impl record found — emit with impl_crate == site_crate
                    # (the impl IS the site crate; the decl is elsewhere).
                    edge_key = (
                        m.get("file", ""), int(m.get("line", 0)),
                        trait_name, struct_name,
                        decl["crate"], site_crate, fn_name,
                    )
                    if edge_key in seen_edges:
                        continue
                    seen_edges.add(edge_key)
                    dispatch_edges.append({
                        "site_file": m.get("file", ""),
                        "site_line": m.get("line", 0),
                        "trait_name": trait_name,
                        "struct_name": struct_name,
                        "trait_decl_crate": decl["crate"],
                        "impl_crate": site_crate,
                        "target_method": fn_name,
                        "confidence": "source-shape",
                    })

    return dispatch_edges


# ---------------------------------------------------------------------------
# Concrete dispatch annotation (P0-2 Wave C-2B)
# ---------------------------------------------------------------------------

# HEURISTIC: local variable binding with explicit type annotation.
# Shapes:
#   let var: Type = ...;
#   let mut var: Type = ...;
#   let var: Arc<Type> = ...;
#   let var: Box<Type> = ...;
# We extract (var_name, inner_type) pairs so we can match against
# struct_name in a dispatch edge — if the struct appears as the concrete
# type at the binding site, we upgrade from source-shape to concrete.
_LET_BINDING_RE = re.compile(
    r"^\s*let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?:Arc|Box|Rc|RefCell|Mutex|RwLock|Pin)?\s*<?\s*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:[<>].*?)?\s*>?\s*="
)

# HEURISTIC: function argument type annotation in fn signature.
# Shape: fn foo(var: Type, ...) or fn foo(var: Arc<Type>, ...)
# Used to resolve trait-method dispatch in impl blocks.
_FN_ARG_RE = re.compile(
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?:Arc|Box|Rc|RefCell|Mutex|RwLock|Pin|&|&mut\s+)?\s*<?\s*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:]*)"
)


def _infer_local_types(text: str) -> Dict[str, str]:
    """Return {var_name -> inferred_struct_name} from let-bindings in text.

    Only explicit type annotations are captured. Inference is deliberately
    conservative: we take the LAST binding for a name (closest to any later
    call site in the same scope) and normalize the struct name to its tail
    (strip path qualifiers like ``foo::Bar`` -> ``Bar``).
    """
    bindings: Dict[str, str] = {}
    for m in _LET_BINDING_RE.finditer(text):
        var = m.group("var")
        typ = m.group("type").rsplit("::", 1)[-1].strip()
        if typ and not typ[0].islower():  # struct names start uppercase
            bindings[var] = typ
    return bindings


def _annotate_dispatch_confidence(
    workspace: Path,
    dispatch_edges: List[Dict[str, Any]],
    discovered: List[Tuple[str, Path]],
) -> List[Dict[str, Any]]:
    """Upgrade dispatch edge confidence from 'source-shape' to 'concrete'
    when the call-site file contains a let-binding whose inferred type
    matches the edge's struct_name.

    An edge is marked 'abstract' when the struct_name is a generic type
    parameter (all-lowercase or contains angle brackets after normalization)
    and no binding can be found.

    Confidence levels (lowest to highest):
      abstract  — struct_name looks like a generic type param (T, S, etc.)
      source-shape — struct found in impl map but no call-site evidence
      concrete  — call-site let-binding explicitly names the struct type

    This function never REMOVES edges; it only upgrades or downgrades the
    confidence field and adds an optional 'inferred_from' annotation.
    """
    if not dispatch_edges:
        return dispatch_edges

    # Build a fast lookup: rel_file -> file text (load only files referenced
    # by dispatch edges to avoid re-reading the entire workspace).
    edge_files: set = {e.get("site_file", "") for e in dispatch_edges if e.get("site_file")}
    file_texts: Dict[str, str] = {}
    for crate_name, crate_root in discovered:
        for rs_path in _rs_files_in(crate_root / "src"):
            rel = _rel(workspace, rs_path)
            if rel not in edge_files:
                continue
            try:
                file_texts[rel] = rs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

    # Per-file type bindings cache.
    type_cache: Dict[str, Dict[str, str]] = {}

    result: List[Dict[str, Any]] = []
    for edge in dispatch_edges:
        edge = dict(edge)  # copy to avoid mutating original
        struct_name = str(edge.get("struct_name", ""))
        site_file = str(edge.get("site_file", ""))

        # Determine if struct_name looks like a generic parameter.
        # Generic params are single-letter lowercase (t, s, u) or
        # multi-char with all-lowercase (trait). We treat struct_name
        # as generic when it matches ^[A-Z]?[a-z]+$ (a single plain
        # lowercase ident) and is <= 3 chars.
        is_generic_param = (
            bool(re.match(r"^[A-Z]$", struct_name))  # single uppercase T, S, V
            or bool(re.match(r"^[a-z]{1,3}$", struct_name))  # t, st, etc.
        )

        if is_generic_param:
            edge["confidence"] = "abstract"
            result.append(edge)
            continue

        # Try to upgrade to concrete by looking for let-bindings.
        if site_file and site_file in file_texts:
            if site_file not in type_cache:
                type_cache[site_file] = _infer_local_types(file_texts[site_file])
            bindings = type_cache[site_file]
            # Check if any binding resolves to the struct_name (normalized).
            norm_struct = struct_name.rsplit("::", 1)[-1]
            matched_var = next(
                (var for var, typ in bindings.items() if typ == norm_struct),
                None,
            )
            if matched_var:
                edge["confidence"] = "concrete"
                edge["inferred_from"] = f"let {matched_var}: {norm_struct}"
                result.append(edge)
                continue

        # No upgrade possible — keep as source-shape.
        result.append(edge)

    return result


# ---------------------------------------------------------------------------
# Graph build
# ---------------------------------------------------------------------------

def build_graph(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.resolve()
    discovered = discover_crates(workspace)

    # First pass: build the set of in-workspace crate names (normalized).
    workspace_crates: Dict[str, Tuple[str, Path]] = {}
    for name, root in discovered:
        workspace_crates[_normalize_crate_name(name)] = (name, root)

    crates_out: Dict[str, Dict[str, Any]] = {}
    edges_out: List[Dict[str, str]] = []

    for crate_name, crate_root in discovered:
        cargo = crate_root / "Cargo.toml"
        parsed = _read_cargo_toml(cargo)
        all_deps = _deps_from_cargo(parsed)
        deps_intra: List[str] = []
        deps_external: List[str] = []
        for dep in all_deps:
            norm = _normalize_crate_name(dep)
            if norm in workspace_crates and norm != _normalize_crate_name(crate_name):
                # Resolve back to the canonical (un-normalized) crate
                # name as discovered, so consumers see the same string
                # in `crates` keys and `deps_intra`.
                canonical, _ = workspace_crates[norm]
                deps_intra.append(canonical)
            else:
                deps_external.append(dep)
        # de-dupe preserving order
        deps_intra = list(dict.fromkeys(deps_intra))
        deps_external = list(dict.fromkeys(deps_external))

        imports_in: Dict[str, List[str]] = {}
        for rs_path in _rs_files_in(crate_root / "src"):
            try:
                text = rs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            file_imports: List[str] = []
            for cleaned, head in parse_use_paths(text):
                if head is None:
                    continue  # intra-crate folded
                file_imports.append(cleaned)
                if head in workspace_crates and head != _normalize_crate_name(crate_name):
                    target_canonical, _ = workspace_crates[head]
                    edges_out.append({
                        "from_crate": crate_name,
                        "from_file":  _rel(workspace, rs_path),
                        "to_crate":   target_canonical,
                        "to_path":    cleaned,
                    })
            if file_imports:
                imports_in[_rel(workspace, rs_path)] = file_imports

        crates_out[crate_name] = {
            "path":          _rel(workspace, crate_root),
            "deps_intra":    deps_intra,
            "deps_external": deps_external,
            "imports_in":    imports_in,
        }

    # Cross-crate trait dispatch resolution (P1-2).
    dispatch_edges = _build_cross_crate_dispatch(workspace, discovered)
    # P0-2 Wave C-2B: annotate dispatch edges with concrete/abstract/source-shape
    # confidence based on inferred let-binding types at call sites.
    dispatch_edges = _annotate_dispatch_confidence(workspace, dispatch_edges, discovered)

    concrete_count = sum(1 for e in dispatch_edges if e.get("confidence") == "concrete")
    abstract_count = sum(1 for e in dispatch_edges if e.get("confidence") == "abstract")

    return {
        "_meta": {
            "schema_version":               SCHEMA_VERSION,
            "workspace":                    str(workspace),
            "crate_count":                  len(crates_out),
            "edge_count":                   len(edges_out),
            "cross_crate_dispatch_count":   len(dispatch_edges),
            "dispatch_concrete_count":      concrete_count,
            "dispatch_abstract_count":      abstract_count,
        },
        "crates":               crates_out,
        "edges":                edges_out,
        "cross_crate_dispatch": dispatch_edges,
    }


# ---------------------------------------------------------------------------
# Validation mode (--validate)
# ---------------------------------------------------------------------------

REQUIRED_TOP_KEYS = {"_meta", "crates", "edges"}
REQUIRED_META_KEYS = {"schema_version", "workspace", "crate_count", "edge_count"}
REQUIRED_CRATE_KEYS = {"path", "deps_intra", "deps_external", "imports_in"}
REQUIRED_EDGE_KEYS = {"from_crate", "from_file", "to_crate", "to_path"}
REQUIRED_DISPATCH_KEYS = {
    "site_file", "site_line", "trait_name", "struct_name",
    "trait_decl_crate", "impl_crate", "target_method",
}


def validate_graph(graph: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(graph, dict):
        return ["top-level: expected dict"]
    missing_top = REQUIRED_TOP_KEYS - set(graph.keys())
    if missing_top:
        errors.append(f"top-level: missing keys {sorted(missing_top)}")
        return errors
    meta = graph["_meta"]
    if not isinstance(meta, dict):
        errors.append("_meta: expected dict")
    else:
        missing_meta = REQUIRED_META_KEYS - set(meta.keys())
        if missing_meta:
            errors.append(f"_meta: missing keys {sorted(missing_meta)}")
        if meta.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"_meta.schema_version: expected {SCHEMA_VERSION}, "
                f"got {meta.get('schema_version')!r}"
            )
        for k in ("crate_count", "edge_count"):
            if not isinstance(meta.get(k), int):
                errors.append(f"_meta.{k}: expected int")
    crates = graph["crates"]
    if not isinstance(crates, dict):
        errors.append("crates: expected dict")
    else:
        for name, body in crates.items():
            if not isinstance(body, dict):
                errors.append(f"crates.{name}: expected dict")
                continue
            missing = REQUIRED_CRATE_KEYS - set(body.keys())
            if missing:
                errors.append(f"crates.{name}: missing keys {sorted(missing)}")
                continue
            if not isinstance(body["path"], str):
                errors.append(f"crates.{name}.path: expected str")
            if not isinstance(body["deps_intra"], list):
                errors.append(f"crates.{name}.deps_intra: expected list")
            if not isinstance(body["deps_external"], list):
                errors.append(f"crates.{name}.deps_external: expected list")
            if not isinstance(body["imports_in"], dict):
                errors.append(f"crates.{name}.imports_in: expected dict")
    edges = graph["edges"]
    if not isinstance(edges, list):
        errors.append("edges: expected list")
    else:
        for i, edge in enumerate(edges):
            if not isinstance(edge, dict):
                errors.append(f"edges[{i}]: expected dict")
                continue
            missing = REQUIRED_EDGE_KEYS - set(edge.keys())
            if missing:
                errors.append(f"edges[{i}]: missing keys {sorted(missing)}")
    # cross_crate_dispatch is optional (absent in older JSON); validate if present.
    dispatch = graph.get("cross_crate_dispatch")
    if dispatch is not None:
        if not isinstance(dispatch, list):
            errors.append("cross_crate_dispatch: expected list")
        else:
            for i, edge in enumerate(dispatch):
                if not isinstance(edge, dict):
                    errors.append(f"cross_crate_dispatch[{i}]: expected dict")
                    continue
                missing = REQUIRED_DISPATCH_KEYS - set(edge.keys())
                if missing:
                    errors.append(f"cross_crate_dispatch[{i}]: missing keys {sorted(missing)}")
    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_out(workspace: Path) -> Path:
    return workspace / ".auditooor" / "rust_cross_crate_graph.json"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rust-cross-crate-graph",
        description=(
            "Build a syntactic Rust *cross-crate* graph (workspace dep "
            "graph + use-statement import edges). Stdlib-only; not a "
            "full Rust frontend."
        ),
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace", type=Path,
                   help="Build graph for this workspace.")
    g.add_argument("--validate", type=Path,
                   help="Re-read this graph JSON and assert schema integrity.")
    p.add_argument("--out", type=Path, default=None,
                   help="Path to write graph JSON (default: <workspace>/.auditooor/rust_cross_crate_graph.json).")
    p.add_argument("--print-json", action="store_true",
                   help="Also print the graph JSON to stdout (build mode).")
    args = p.parse_args(argv)

    if args.validate is not None:
        path = args.validate.expanduser().resolve()
        if not path.is_file():
            print(f"[rust-cross-crate-graph] ERR not found: {path}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"[rust-cross-crate-graph] ERR cannot parse {path}: {exc}", file=sys.stderr)
            return 3
        errors = validate_graph(data)
        if errors:
            for e in errors:
                print(f"[rust-cross-crate-graph] schema-error {e}", file=sys.stderr)
            return 3
        print(f"[rust-cross-crate-graph] OK {path} schema={SCHEMA_VERSION}", file=sys.stderr)
        return 0

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-cross-crate-graph] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2
    graph = build_graph(workspace)
    out = args.out.expanduser().resolve() if args.out else _default_out(workspace)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        sys.stdout.write(json.dumps(graph, indent=2, sort_keys=True) + "\n")
    print(
        f"[rust-cross-crate-graph] OK crates={graph['_meta']['crate_count']} "
        f"edges={graph['_meta']['edge_count']} json={out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
