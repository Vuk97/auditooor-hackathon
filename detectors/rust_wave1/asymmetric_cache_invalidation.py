"""
asymmetric_cache_invalidation.py

Net-new detector (2026-07-08), seeded by the Feb-2026 Aptos Move-VM "struct
hijack" bug (hexens.io/research/aptos-hijack-bug): a partial cache flush where
one code path invalidates the FULL set of caches (an aggregate `flush_all_caches()`)
while a sibling path enumerates individual member flushes and OMITS one member,
leaving a stale index->value mapping -> type confusion / capability theft.

Generic shape (the CLASS-2 gap that paired_function_state_write_asymmetry and
fork_batch_flush_race do NOT cover): within one file, one flush/invalidation
BLOCK touches a STRICT SUPERSET of the caches a sibling block touches, OR a
sibling block calls an aggregate `*_all` invalidation while an enumerated block
does not - so the enumerated path may silently drop a cache that must be
invalidated in lockstep.

Analysis is BLOCK-LEVEL (per brace-balanced region, direct calls only), because
the two divergent flush paths are typically two arms of one `if/else` inside a
single function (exactly the Aptos `check_ready()` shape) - a function-level
profile would conflate the arms and hide the bug.

Two signals:
  A (HIGH)  a sibling block flushes a strict SUPERSET -> names the omitted cache(s).
  B (MED)   an aggregate `*_all` flush exists in the file AND an enumerated block
            (>=2 members, no aggregate) coexists -> the enumerated path may omit a
            cache the aggregate covers (the exact Aptos Path-B shape). Advisory.

Interface: rust-detect.py calls run(tree, source, filepath); we ignore `tree` and
work on raw source (VM-runtime Rust often will not fully parse, and the signal is
textual anyway). Also exposes scan(root) for standalone/CLI use.

Anti-FP: a flagged block enumerates >=2 distinct cache receivers; a block that
also calls the aggregate is complete and suppressed; universe of individually
flushed caches must be >=2 (signal A) or an aggregate must exist (signal B).
"""

from __future__ import annotations

import re
from pathlib import Path

DETECTOR_ID = "asymmetric_cache_invalidation"
CLASS_TAG = "asymmetric-cache-invalidation-partial-flush"
LANGUAGE = "rust"  # mirrored to go via the go runner
SEVERITY = "MED"

# . <method> (   - each method call; the receiver is recovered by looking
# backward (method CHAINS like `env.ty_tag_cache().flush()` mean a single
# forward regex would let the outer `.flush` lose its receiver token).
_METHOD_RE = re.compile(r"\.\s*([a-z_][a-z0-9_]*)\s*\(")
# receiver = last identifier before the '.', optionally with a trailing `()`.
_RECV_TAIL_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\(\s*\))?\s*$")

_MEMBER_OPS = ("flush", "clear", "invalidate", "reset", "purge", "evict")
_AGG_SUFFIXES = ("_all", "_all_caches")
_AGG_NAMES = {
    "flush_all", "flush_all_caches", "clear_all", "invalidate_all",
    "reset_all", "purge_all", "evict_all", "flush_caches", "clear_caches",
}
_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive",
              "tests", "test", "test_fixtures", "__pycache__"}
_NESTED_BRACE_RE = re.compile(r"\{[^{}]*\}")


def _classify(method: str) -> str:
    """member | aggregate | none for a called method name."""
    if method in _AGG_NAMES or method.endswith(_AGG_SUFFIXES):
        return "aggregate"
    if method in _MEMBER_OPS:
        return "member"
    for op in _MEMBER_OPS:
        if method.startswith(op + "_"):   # flush_module, clear_cache, ...
            return "member"               # (_all handled by aggregate above)
    return "none"


def _blocks(src: str):
    """Yield (start_line, block_text) for every brace-balanced region."""
    stack = []
    spans = []
    for idx, ch in enumerate(src):
        if ch == "{":
            stack.append(idx)
        elif ch == "}" and stack:
            s = stack.pop()
            spans.append((s, idx))
    for s, e in spans:
        yield src[:s].count("\n") + 1, src[s:e + 1]


def _strip_nested(block_text: str) -> str:
    """Remove nested {...} so only DIRECT calls in this block's scope remain."""
    inner = block_text[1:-1] if block_text.startswith("{") else block_text
    prev = None
    while prev != inner:
        prev = inner
        inner = _NESTED_BRACE_RE.sub(" ", inner)
    return inner


def _profile(text: str):
    """(member_receivers:set, has_aggregate:bool) for direct calls in text."""
    members: set[str] = set()
    has_agg = False
    for m in _METHOD_RE.finditer(text):
        method = m.group(1)
        kind = _classify(method)
        if kind == "none":
            continue
        if kind == "aggregate":
            has_agg = True
            continue
        rm = _RECV_TAIL_RE.search(text[:m.start()])
        recv = rm.group(1) if rm else "?"
        members.add(recv)
    return members, has_agg


def _analyze_source(src: str, filepath: str):
    blocks = []  # (start_line, members, has_agg)
    for start_line, block_text in _blocks(src):
        members, has_agg = _profile(_strip_nested(block_text))
        if members or has_agg:
            blocks.append((start_line, members, has_agg))
    if not blocks:
        return []

    universe: set[str] = set()
    for _l, members, _a in blocks:
        universe |= members
    file_has_aggregate = any(a for _l, _m, a in blocks)
    if len(universe) < 2 and not file_has_aggregate:
        return []

    hits = []
    seen = set()
    for line, members, has_agg in blocks:
        if has_agg or len(members) < 2:
            continue

        # Signal A (HIGH): a sibling block flushes a strict superset.
        superset = None
        for _l2, om, _a2 in blocks:
            if members < om and (superset is None or len(om) > len(superset)):
                superset = om
        if superset is not None:
            omitted = superset - members
            key = (line, tuple(sorted(members)), "A")
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "severity": "high",
                "line": line,
                "col": 1,
                "snippet": f"flush block @L{line}",
                "message": (
                    f"{DETECTOR_ID}: flush block @L{line} flushes {sorted(members)} "
                    f"but a sibling block flushes the superset {sorted(superset)} - "
                    f"this path OMITS {sorted(omitted)}. Asymmetric cache "
                    f"invalidation: a recycled/stale entry in an omitted cache "
                    f"survives -> stale-mapping / type-confusion risk."),
            })
            continue

        # Signal B (MED): aggregate flush coexists (Aptos Path-B shape).
        if file_has_aggregate:
            key = (line, tuple(sorted(members)), "B")
            if key in seen:
                continue
            seen.add(key)
            residual = universe - members
            note = (f" (individually-flushed elsewhere but omitted here: "
                    f"{sorted(residual)})" if residual else "")
            hits.append({
                "severity": "med",
                "line": line,
                "col": 1,
                "snippet": f"flush block @L{line}",
                "message": (
                    f"{DETECTOR_ID}: block @L{line} enumerates {len(members)} "
                    f"individual cache flushes {sorted(members)} while a sibling "
                    f"path invalidates via an aggregate `*_all` flush - the "
                    f"enumerated path may OMIT a cache the aggregate covers{note}. "
                    f"Verify flush parity (Aptos-struct-hijack partial-flush shape)."),
            })
    return hits


def run(tree, source, filepath):
    """rust_wave1 detector interface (tree ignored; textual signal)."""
    if isinstance(source, (bytes, bytearray)):
        src = source.decode("utf-8", "ignore")
    else:
        src = str(source)
    return _analyze_source(src, str(filepath))


def _iter_files(root: Path):
    for ext in (".rs", ".go"):
        for p in root.rglob("*" + ext):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            yield p


def scan(root):
    """Standalone runner interface: list[(filepath, line, message)]."""
    root = Path(root)
    out = []
    for f in _iter_files(root):
        try:
            src = f.read_text(errors="ignore")
        except Exception:
            continue
        for h in _analyze_source(src, str(f)):
            out.append((str(f), h["line"], h["message"]))
    return out


if __name__ == "__main__":
    import sys
    for fp, ln, msg in scan(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(f"{fp}:{ln}:{msg}")
