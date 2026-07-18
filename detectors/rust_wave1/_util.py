"""
_util.py — shared helpers for rust_wave1 detectors.

All helpers operate on tree-sitter-rust nodes + raw source bytes.
"""

from __future__ import annotations

import pathlib
import re as _re_module


def text_of(node, source: bytes) -> str:
    """Return UTF-8 text of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def walk(node):
    """Depth-first iterator yielding all descendant nodes (and `node` itself)."""
    yield node
    for c in node.children:
        yield from walk(c)


def walk_no_nested_fn(node):
    """Iterator that skips entering nested function_item bodies (so callers
    can inspect a function's own body only)."""
    yield node
    if node.type in ("function_item", "closure_expression"):
        return
    for c in node.children:
        yield from walk_no_nested_fn(c)


def function_items(root):
    """Yield every `function_item` node in the tree."""
    for n in walk(root):
        if n.type == "function_item":
            yield n


def impl_items(root):
    for n in walk(root):
        if n.type == "impl_item":
            yield n


def attr_names_above(node, source: bytes) -> list[str]:
    """Return names of attribute_items immediately preceding `node`.
    tree-sitter-rust puts attributes as sibling nodes before the thing
    they annotate."""
    names = []
    parent = node.parent
    if parent is None:
        return names
    prev = node.prev_named_sibling
    while prev is not None and prev.type == "attribute_item":
        # Find inner `attribute` → identifier
        for c in prev.children:
            if c.type == "attribute":
                for cc in c.children:
                    if cc.type == "identifier":
                        names.append(text_of(cc, source))
                        break
                    # scoped path: scoped_identifier → take last identifier
                    if cc.type == "scoped_identifier":
                        ident_children = [x for x in cc.children
                                          if x.type == "identifier"]
                        if ident_children:
                            names.append(text_of(ident_children[-1], source))
                            break
                break
        prev = prev.prev_named_sibling
    return names


def is_pub(fn_node, source: bytes) -> bool:
    for c in fn_node.children:
        if c.type == "visibility_modifier":
            return "pub" in text_of(c, source)
    return False


def fn_name(fn_node, source: bytes) -> str:
    for c in fn_node.children:
        if c.type == "identifier":
            return text_of(c, source)
    return "?"


def fn_body(fn_node):
    for c in fn_node.children:
        if c.type == "block":
            return c
    return None


def impl_has_contractimpl(impl_node, source: bytes) -> bool:
    """True if an impl_item has a preceding #[contractimpl] attribute."""
    prev = impl_node.prev_named_sibling
    while prev is not None and prev.type == "attribute_item":
        for c in prev.children:
            if c.type == "attribute":
                for cc in c.children:
                    if cc.type == "identifier":
                        if text_of(cc, source) == "contractimpl":
                            return True
        prev = prev.prev_named_sibling
    return False


def functions_in_contractimpl(root, source: bytes):
    """Yield (fn_node, impl_node) for every function inside an #[contractimpl]
    impl block."""
    for impl in impl_items(root):
        if not impl_has_contractimpl(impl, source):
            continue
        for c in impl.children:
            if c.type != "declaration_list":
                continue
            for d in c.children:
                if d.type == "function_item":
                    yield d, impl


def in_test_cfg(fn_node, source: bytes) -> bool:
    """True if function has #[test] or #[cfg(test)] attribute."""
    for name in attr_names_above(fn_node, source):
        if name in ("test", "cfg", "tokio"):
            return True
    # Also check if an enclosing mod has #[cfg(test)] — quick check by
    # scanning up
    n = fn_node.parent
    while n is not None:
        if n.type == "mod_item":
            for name in attr_names_above(n, source):
                if name == "cfg":
                    # cfg(test) requires looking at token_tree; heuristic
                    # check source text
                    prev = n.prev_named_sibling
                    while prev is not None and prev.type == "attribute_item":
                        t = text_of(prev, source)
                        if "cfg(test)" in t or "test" in t and "cfg" in t:
                            return True
                        prev = prev.prev_named_sibling
        n = n.parent
    return False


def line_col(node):
    """1-based line, 0-based column."""
    return node.start_point[0] + 1, node.start_point[1]


def snippet_of(node, source: bytes, max_len: int = 160) -> str:
    t = text_of(node, source)
    t = " ".join(t.split())
    if len(t) > max_len:
        t = t[:max_len] + "..."
    return t


# --- R94 loop cycle 7: shared helpers hoisted from individual detectors ---

import re as _re

_LINE_COMMENT_RE = _re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = _re.compile(r"/\*.*?\*/", _re.DOTALL)


def body_text_nocomment(body_node, source: bytes) -> str:
    """Return the body's text with line- and block-comments stripped.

    Detectors that check for the ABSENCE of a guard (e.g. "no mint-equality
    assert") regularly false-negative on positive fixtures whose comments
    describe the bug using the same tokens as the real guard they look for.
    Strip comments before predicate scans. Hoisted in R94 cycle 7.
    """
    t = text_of(body_node, source)
    t = _LINE_COMMENT_RE.sub("", t)
    t = _BLOCK_COMMENT_RE.sub("", t)
    return t


def direct_method_name(call_node, source: bytes):
    """Return the DIRECT method name invoked by a call_expression, or None.

    Matches ONLY the method directly invoked by THIS call_expression —
    ignores nested descendant calls. Structure:
        call_expression
          field_expression           <-- [0]
            <receiver>
            `.`
            field_identifier         <-- the method name
          arguments                  <-- [1]

    Use this when a detector filters for "method name is X" — substring
    regex on call_text fires on outer chains like `x.transfer(…).expect(…)`
    because the inner call's text shows up inside the outer node's text.
    Hoisted in R94 cycle 7 from r94_unchecked_approve_return.py.
    """
    if len(call_node.children) == 0:
        return None
    head = call_node.children[0]
    if head.type != "field_expression":
        return None
    for c in head.children:
        if c.type == "field_identifier":
            return text_of(c, source).strip()
    return None


def source_nocomment(source: bytes) -> str:
    """Return the entire module source text with line- and block-comments
    stripped. Hoisted in R94 cycle 25 from 6 detectors that scanned the
    full source for module-level patterns.
    """
    t = source.decode("utf8", errors="replace")
    t = _LINE_COMMENT_RE.sub("", t)
    t = _BLOCK_COMMENT_RE.sub("", t)
    return t


# ---------------------------------------------------------------------------
# Shared regex primitives (Phase 3 megaplan, PR #84).
#
# Retrofitted 75 detectors as of PR #84 Phase 13.
#
# Use these instead of ad-hoc `\w*ident` / `\w+\s*\(` constructions. The
# "regex-widening treadmill" (agent-written regex failing on agent-written
# fixtures because `\w*` doesn't match `foo.bar`) is the #1 source of post-
# deployment fixture fixups. These primitives handle the common
# dotted-identifier / nested-call / assignment shapes out of the box.
#
# Import:
#     from _util import IDENT, CALL, ASSIGN, COMP, WSP, INT
#
# Example usage (new-style):
#     _RE = re.compile(fr"{IDENT}required_dvn_count\s*=\s*{IDENT}value")
#     _RE = re.compile(fr"balance_of\s*{CALL}\s*>=\s*{IDENT}amount")
#
# Example MIGRATION from old-style:
#     OLD: r"\w*config\.required_dvn_count\s*==\s*\w*2"   # FAILS on `self.config.required_dvn_count`
#     NEW: fr"{IDENT}required_dvn_count\s*==\s*{IDENT}2"  # matches dotted chains
# ---------------------------------------------------------------------------

# A (possibly empty) dotted-identifier PREFIX: matches `foo.bar.` before an
# anchor, or matches empty string. Use like `fr"{IDENT}releaseRate"` to match
# `grantor.releaseRate`, `self.cfg.releaseRate`, or bare `releaseRate`.
IDENT = r"[\w\.]*"

# A function-call shape: `f(a)`, `f(a, b.c)`, `f(g(h))`, `f(&x)`.
# Allows paren-inside-paren (one level deep + mixed tokens). Handles most
# real-world cases in tree-sitter-rust fixtures.
CALL = r"\([\w\s\(\),\.\:\[\]\&\*\-\+]*\)"

# Common assignment / insertion forms: `=`, `+=`, `-=`, `.insert(...`,
# `.push(...`, `.set(...`. Use AFTER an identifier pattern.
ASSIGN = r"(?:\s*(?:\+=|\-=|=|\.insert\s*\(|\.push\s*\(|\.set\s*\())"

# Comparison operators.
COMP = r"(?:==|!=|<=|>=|<|>)"

# Whitespace (single chunk, including newlines).
WSP = r"[\s]*"

# Decimal integer literal (with optional Rust underscore separators).
INT = r"\d+(?:_\d+)*"


# ---------------------------------------------------------------------------
# Track K-Rust step 1: per-function emit helpers
# ---------------------------------------------------------------------------

def _file_module_prefix(file_path: pathlib.Path) -> str:
    """Derive the crate-relative module prefix from a file path.

    Examples
    --------
    src/lib.rs          -> "crate"
    src/main.rs         -> "crate"
    src/foo/bar/baz.rs  -> "foo::bar::baz"
    src/foo/bar.rs      -> "foo::bar"
    tests/integration.rs -> "tests::integration"
    benches/bench_foo.rs -> "benches::bench_foo"
    examples/demo.rs    -> "examples::demo"
    build.rs            -> "build"
    """
    p = file_path
    parts = list(p.parts)

    # Normalise: work with the Path object's parts relative to the nearest
    # well-known root segment.
    try:
        src_idx = parts.index("src")
    except ValueError:
        src_idx = None

    stem = p.stem  # filename without extension

    if src_idx is not None:
        after_src = parts[src_idx + 1:]
        if not after_src:
            # The file IS src/ (shouldn't happen, but guard)
            return "crate"
        if len(after_src) == 1 and after_src[0] in ("lib.rs", "main.rs"):
            return "crate"
        # Strip .rs from the last component (already have stem from p.stem above)
        segments = after_src[:-1] + [stem]
        # Drop "lib" or "mod" terminal (mod.rs -> parent dir name is enough)
        if segments and segments[-1] == "lib":
            segments = segments[:-1]
        if segments and segments[-1] == "mod":
            segments = segments[:-1]
        if not segments:
            return "crate"
        return "::".join(segments)

    # No src/ in path — check for tests/ benches/ examples/
    for special in ("tests", "benches", "examples"):
        try:
            idx = parts.index(special)
            after = parts[idx + 1:]
            if not after:
                return f"{special}::{stem}"
            segs = [p2.replace(".rs", "") for p2 in after[:-1]] + [stem]
            return "::".join([special] + segs)
        except ValueError:
            pass

    # build.rs at top level
    if p.name == "build.rs":
        return "build"

    # Fallback: just use the stem
    return stem


def fn_module_path(fn_node, source: bytes, file_path: pathlib.Path) -> str:
    """Return the canonical Rust module path for ``fn_node``.

    The returned string is the *module* path (not including the function name
    itself), e.g. ``"frost_ed25519::dkg::round2"`` for a function in
    ``src/dkg/round2.rs``.

    Algorithm
    ---------
    1. Walk up from ``fn_node`` via the tree-sitter parent chain.
    2. For each ``mod_item`` ancestor, collect its ``identifier`` child.
    3. Reverse (innermost-last → outermost-first).
    4. Prepend the crate-relative file prefix derived from ``file_path``.
    5. Join with ``::`` and return.

    Note: cross-file ``mod foo;`` declarations are NOT traversed.  Only
    inline ``mod foo { ... }`` ancestors show up in the tree.  For
    cross-file resolution, the file path component is used as-is (which is
    the correct behaviour for most callers — they already have the right
    file open).
    """
    # Collect inline mod names by walking up the parent chain
    mod_names: list[str] = []
    parent = fn_node.parent
    while parent is not None:
        if parent.type == "mod_item":
            for c in parent.children:
                if c.type == "identifier":
                    mod_names.append(text_of(c, source))
                    break
        parent = parent.parent

    # mod_names is innermost-first; reverse to outermost-first
    mod_names.reverse()

    file_prefix = _file_module_prefix(file_path)

    if mod_names:
        if file_prefix == "crate":
            return "::".join(mod_names)
        return "::".join([file_prefix] + mod_names)
    return file_prefix


def fn_signature_normalized(fn_node, source: bytes) -> str:
    """Return the function signature stripped of body and normalized.

    Works for both ``function_item`` nodes (with a ``block`` body) and
    ``function_signature_item`` nodes (trait methods with no body, ending
    with ``;``).

    The signature text runs from the first child of the node up to (but not
    including) the opening ``{`` of the body, or includes the ``;`` for
    body-less trait methods.  Whitespace is collapsed to single spaces.
    """
    full_text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")

    # Find the block body child to cut before it.
    block_child = None
    semi_child = None
    for c in fn_node.children:
        if c.type == "block":
            block_child = c
            break
        if c.type == ";":
            semi_child = c
            break

    if block_child is not None:
        # Cut the text at the block start (relative to fn_node start)
        rel_start = block_child.start_byte - fn_node.start_byte
        sig_text = full_text[:rel_start]
    elif semi_child is not None:
        # Include the semicolon
        rel_end = semi_child.end_byte - fn_node.start_byte
        sig_text = full_text[:rel_end]
    else:
        # Fallback: use full text (shouldn't normally happen)
        sig_text = full_text

    # Normalize whitespace
    sig_text = " ".join(sig_text.split())
    return sig_text.strip()


def crate_name_from_path(file_path: pathlib.Path) -> str:
    """Return the crate name for a Rust source file by locating ``Cargo.toml``.

    Walks up the directory tree from ``file_path.parent`` looking for a
    ``Cargo.toml`` that contains a ``[package]`` section with a ``name``
    field.  Returns ``"unknown"`` if no such file is found.

    Uses ``tomllib`` (stdlib ≥ 3.11) with a regex fallback for older
    Pythons.
    """
    try:
        import tomllib as _tomllib  # Python 3.11+
    except ImportError:
        _tomllib = None  # type: ignore[assignment]

    directory = file_path.parent if file_path.is_file() else file_path
    # Ensure we have an absolute path to avoid infinite loops
    try:
        directory = directory.resolve()
    except OSError:
        pass

    while True:
        candidate = directory / "Cargo.toml"
        if candidate.exists():
            try:
                if _tomllib is not None:
                    with open(candidate, "rb") as fh:
                        data = _tomllib.load(fh)
                    pkg = data.get("package", {})
                    name = pkg.get("name")
                    if name:
                        return str(name)
                    # Workspace Cargo.toml without [package] — continue
                    # walking *down* isn't practical; just move up and try
                    # again (the caller's file is deeper, so nearest one wins).
                else:
                    # Regex fallback for Python < 3.11
                    text = candidate.read_text(encoding="utf-8", errors="replace")
                    m = _re_module.search(r'^\s*\[package\].*?^\s*name\s*=\s*"([^"]+)"',
                                         text, _re_module.DOTALL | _re_module.MULTILINE)
                    if m:
                        return m.group(1)
            except (OSError, Exception):
                pass

        parent = directory.parent
        if parent == directory:
            # Reached filesystem root
            break
        directory = parent

    return "unknown"
