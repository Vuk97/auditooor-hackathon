#!/usr/bin/env python3
"""Mechanically extract a compact 'probe packet' per guard - so the LLM probe
never re-reads source.

The expensive part of agent-based negative-space probing is each agent opening
and reading whole source files (~100K tokens/guard). This tool does the reading
ONCE per file in plain Python (grouped + cached), and emits a small packet per
guard containing exactly what the negative-space judgement needs:

  - the guard line/condition itself,
  - a bounded enclosing-function window (best-effort signature + body slice),
  - the invariant hint (from the worklist),

so the downstream probe LLM receives a ~0.5-1.5K-token snippet instead of
reading the file. Generation cost drops ~100x; the file read is free (Python).

Input:  <ws>/.auditooor/negative_space_worklist.jsonl  (guard_id, file_line, checks, invariant_hint)
Output: <ws>/.auditooor/guard_probe_packets.jsonl       (one compact packet per guard)

Usage:
  guard-context-extract.py --workspace <ws> [--source-root <dir>]
                           [--window N] [--limit N] [--out <path>] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Manifest-authoritative scope filter (single source of truth). Best-effort
# import: when unavailable the extractor falls back to no scope filtering (more
# coverage), never crashing on an odd sys.path.
try:
    from tools.lib.scope_exclusion import (  # type: ignore
        is_in_scope as _is_in_scope,
        rust_test_line_ranges as _shared_test_line_ranges,
    )
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    try:
        _LIB = Path(__file__).resolve().parent / "lib"
        if str(_LIB) not in sys.path:
            sys.path.insert(0, str(_LIB))
        from scope_exclusion import (  # type: ignore
            is_in_scope as _is_in_scope,
            rust_test_line_ranges as _shared_test_line_ranges,
        )
    except Exception:
        def _is_in_scope(rel: str, *, workspace=None) -> bool:  # type: ignore[misc]
            return True
        _shared_test_line_ranges = None  # type: ignore[assignment]

SCHEMA = "auditooor.guard_probe_packet.v1"

# Rust test-attribute: a guard inside a #[cfg(test)] / #[test] item is TEST code,
# not a production runtime guard, so it is OOS for a negative-space PRODUCTION
# guard probe. (Go/Solidity test files are excluded earlier by the path-level
# is_in_scope test-marker; this catches Rust INLINE test modules living in an
# otherwise in-scope .rs file - the dominant optimism op-reth pollution: ~80% of
# guard packets were flashblocks #[cfg(test)] assertions.)
_RUST_TEST_ATTR = re.compile(
    r"^\s*#\[\s*(cfg\(\s*test\s*\)|test|tokio::test|cfg\(\s*all\([^)]*\btest\b[^)]*\)\s*\))\s*\]"
)
_RUST_TESTABLE_ITEM = re.compile(r"^\s*(pub\s+|pub\(crate\)\s+)?(async\s+)?(mod|fn)\b")


def _test_line_ranges(lines: list[str]) -> set[int]:
    """Line indices (0-based) inside a Rust ``#[cfg(test)]`` / ``#[test]`` item.

    Thin delegate to the shared single-source helper
    ``scope_exclusion.rust_test_line_ranges`` so this probe-packet emitter and the
    worklist emitter (guard-negative-space-analyzer.py) cannot drift - if they
    disagree the cert enumerates guards the probe never receives and
    depth_certificate stays pinned at depth-pending. Falls back to the local brace
    matcher only if the shared lib is unavailable (odd sys.path)."""
    if _shared_test_line_ranges is not None:
        return _shared_test_line_ranges(lines)
    # pragma: no cover - shared lib always present in-repo; inline fallback only
    test_idx: set[int] = set()
    n = len(lines)
    i = 0
    while i < n:
        if not _RUST_TEST_ATTR.match(lines[i]):
            i += 1
            continue
        item = i + 1
        while item < n and item <= i + 4 and not _RUST_TESTABLE_ITEM.match(lines[item]):
            if lines[item].lstrip().startswith("#[") or not lines[item].strip():
                item += 1
                continue
            break
        if item >= n or item > i + 4 or not _RUST_TESTABLE_ITEM.match(lines[item]):
            i += 1
            continue
        depth = 0
        opened = False
        j = item
        while j < n:
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                break
            j += 1
        for k in range(i, min(j + 1, n)):
            test_idx.add(k)
        i = j + 1
    return test_idx
_DEFAULT_WINDOW = int(os.environ.get("AUDITOOOR_GUARD_CONTEXT_WINDOW", "40"))

# best-effort enclosing-function signature, per language family
_FN_SIG = re.compile(
    r"^\s*(pub\s+|pub\(crate\)\s+|async\s+|unsafe\s+|export\s+|internal\s+|external\s+|"
    r"public\s+|private\s+)*"
    r"(fn|func|function)\b",
    re.IGNORECASE,
)

# enclosing impl / trait / type block carries the type-parameter bounds that
# define the semantic invariant a mechanical guard is a proxy for (e.g.
# `impl<C: Constraint> From<Amount<C>> for jubjub::Fr`). The packet MUST carry
# this header so the probe can see whether the guarded value's range is set by
# a generic bound it cannot see from the guard line alone.
_IMPL_HDR = re.compile(
    r"^\s*(pub\s+|pub\(crate\)\s+)*"
    r"(impl\b|trait\b|struct\b|enum\b)",
    re.IGNORECASE,
)

# a guard line that checks a purely-MECHANICAL property. When such a guard is
# applied to a value whose semantic range is defined ELSEWHERE (generic type
# param, named constant not in window), `gap_found=false` is unsafe to trust:
# the mechanical property can be vacuously satisfied while the real invariant
# (range <= MAX_MONEY) is unguarded. This is the NS-628de923949e miss class.
_MECHANICAL_GUARD = re.compile(
    r"\b("
    r"checked_abs|checked_add|checked_sub|checked_mul|checked_div|checked_neg|"
    r"abs\(\)|unsigned_abs|wrapping_|saturating_|overflowing_|"
    r"\.len\(\)|is_empty|is_zero|!= 0|== 0|is_some|is_none|"
    r"SafeCast|safeCast|safe_cast|try_into|TryInto|as u\d+|as i\d+|"
    r"require\(|assert\(|ensure\("
    r")",
    re.IGNORECASE,
)

# a generic type parameter on the enclosing impl/fn -> the guarded value's
# range may be set by a `<C: Bound>` the packet would otherwise miss.
_GENERIC_PARAM = re.compile(r"(impl|fn|func|struct|trait|enum)\s*<\s*[A-Z]\w*", re.IGNORECASE)

# --- HB packet-miss fix (NS-9f940d402058 / NS-b8ef09c25261 / NS-e986be6f56eb) ---
# A guard inside a parser/decoder/proof-router is structurally a WINDOWING trap:
# the visible guard line is correct, but the exploitable behavior lives in the
# CALLER's consumption of the guard's output (dispatch loop / switch desync) or
# in the DOWNSTREAM SINK that consumes returned bytes/root (Bytes.substr,
# abi.decode, child verify()) - often across files (Codec.sol -> Types.sol,
# ConsensusRouter.sol -> EcdsaBeefy.sol). A single-guard packet cannot surface
# these, so packet=no-gap must be treated as PROVISIONAL on such guards.
#
# Detect the windowing-trap guard class by enclosing-function name + file name.
_PARSER_FN_NAME = re.compile(
    r"\b(decode\w*|read\w*|parse\w*|deserialize\w*|fromBytes|from_bytes|"
    r"unpack\w*|scale\w*|verify|dispatch\w*|handle\w*|route\w*)\b",
    re.IGNORECASE,
)
_PARSER_FILE = re.compile(
    r"(codec|scale|decoder|parser|router|dispatch|handler|consensus|proof)",
    re.IGNORECASE,
)
# downstream sinks that silently propagate a zero/forged value or panic on a
# malformed slice; when a parser guard's output feeds one of these the gap is
# in the sink, not the guard line.
_SINK_CALL = re.compile(
    r"\b(Bytes\.substr|substr\(|abi\.decode|\.verify\(|stateCommitment|"
    r"toBytes32|decodeUint\w*|\.consensus\.data)\b",
)
# a child-callee invocation inside the guard's own function body whose body
# carries the real sink. Three shapes: (a) `X.verify(` / `IFoo(addr).verify(`
# (child-contract verifier - NS-e986be6f56eb), (b) bare-name calls like
# `decodeDigestItem(` / `stateCommitment(` (sibling/in-file consumer that
# substr's the returned bytes - NS-9f940d402058). Capture the *called* method
# name so we can resolve its body (in-file or cross-file) and pull its sink line.
_CALLEE_INVOKE = re.compile(
    r"(?:\.|\b)([A-Za-z_]\w*)\s*\(",
)
# method-call names that are too generic / control-flow to treat as a callee sink
_CALLEE_NOISE = {"require", "assert", "revert", "if", "for", "while", "return",
                 "abi", "uint8", "uint256", "bytes32", "bytes4", "address",
                 "decode", "encode", "encodePacked", "keccak256", "new",
                 "memory", "ByteSlice", "expect", "unwrap", "length"}
# a function-signature line that names the enclosing fn, used to find call sites
def _fn_name_from_sig(sig_line: str) -> str | None:
    m = re.search(r"\b(?:fn|func|function)\s+([A-Za-z_]\w*)", sig_line)
    return m.group(1) if m else None

# ALL_CAPS named constants referenced on/around the guard line whose *value*
# (the bound the guard is really a proxy for) is defined elsewhere in the file.
_NAMED_CONST = re.compile(r"\b([A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)*)\b")
# const / static / let-binding *definitions* so we can pull the bound into the packet
_CONST_DEF = re.compile(
    r"^\s*(pub\s+)?(const|static)\s+([A-Z][A-Z0-9_]+)\s*(:|=)", re.IGNORECASE,
)
# Rust/Python keywords that look ALL_CAPS-ish but are not semantic constants
_CONST_NOISE = {"TODO", "FIXME", "SAFETY", "NOTE", "XXX", "HACK", "PANIC", "ERROR",
                "WARN", "INFO", "DEBUG", "TRACE", "OK", "ERR", "NONE", "SOME",
                "TRUE", "FALSE", "SELF", "TYPE"}


def _file_of(file_line: str) -> tuple[str | None, int | None]:
    if not file_line:
        return None, None
    parts = file_line.split(":")
    path = parts[0].strip()
    line = None
    if len(parts) > 1:
        m = re.match(r"\d+", parts[1].strip())
        if m:
            line = int(m.group())
    return path, line


def _resolve_file(path_hint: str, source_root: Path) -> Path | None:
    if not path_hint:
        return None
    h = path_hint.lstrip("/")
    for cand in (source_root / h, source_root / "src" / h):
        if cand.is_file():
            return cand
    # short-prefix forms (e.g. 'zebra-consensus/...'): match by basename
    base = Path(h).name
    for cand in source_root.rglob(base):
        if cand.is_file():
            return cand
    return None


def _enclosing_fn_start(lines: list[str], idx: int) -> int:
    """Scan backward from idx for the nearest function signature line."""
    for i in range(idx, max(idx - 400, -1), -1):
        if _FN_SIG.match(lines[i]):
            return i
    return max(idx - _DEFAULT_WINDOW, 0)


def _enclosing_impl_header(lines: list[str], fn_start: int) -> tuple[str | None, int | None]:
    """Scan backward from the enclosing-fn start for the nearest impl/trait/type
    block header. Returns (header_text, header_line_index). The header carries the
    generic type-parameter bounds (`impl<C: Constraint>`) that define the semantic
    invariant a mechanical guard is a proxy for - the NS-628de923949e miss class."""
    for i in range(fn_start, max(fn_start - 400, -1), -1):
        if _IMPL_HDR.match(lines[i]):
            # the header may span multiple lines before `{`; grab until brace/where
            hdr = []
            j = i
            while j < len(lines) and j < i + 6:
                hdr.append(lines[j].rstrip())
                if "{" in lines[j] or lines[j].rstrip().endswith(";"):
                    break
                j += 1
            return "\n".join(hdr).strip(), i
    return None, None


def _const_defs_in_file(lines: list[str]) -> dict[str, str]:
    """Index every ALL_CAPS const/static definition in the file by name -> def line.
    Lets the packet carry the *value* of a bound (MAX_MONEY, COIN) the guard is a
    proxy for, even when the definition is far from the guard line."""
    out: dict[str, str] = {}
    for ln in lines:
        m = _CONST_DEF.match(ln)
        if m:
            name = m.group(3)
            out[name] = ln.strip()
    return out


def _referenced_consts(guard_line: str, context: str, const_index: dict[str, str]) -> list[str]:
    """Return definition lines for ALL_CAPS constants referenced near the guard
    whose definition is NOT already inside the packet's context window."""
    referenced = set(_NAMED_CONST.findall(guard_line)) | set(_NAMED_CONST.findall(context))
    referenced -= _CONST_NOISE
    out = []
    for name in sorted(referenced):
        defn = const_index.get(name)
        if defn and defn not in context:
            out.append(defn)
    return out


def _snippet(lines: list[str], center: int, before: int, after: int, cap: int) -> str:
    """A small, capped source snippet centered on line index `center`."""
    lo = max(center - before, 0)
    hi = min(len(lines), center + after + 1)
    s = "\n".join(l.rstrip() for l in lines[lo:hi])
    if len(s) > cap:
        s = s[:cap] + "\n... [truncated]"
    return s


def _caller_loop_context(lines: list[str], fn_name: str, fn_start: int, max_sites: int = 1,
                         cap: int = 700) -> str:
    """Find the IMMEDIATE caller's control-flow (dispatch loop / switch / for)
    that consumes `fn_name`'s output, and return a bounded snippet around the
    nearest enclosing loop/branch. This surfaces the offset-desync / fall-through
    class (NS-b8ef09c25261) the single-guard window structurally misses."""
    if not fn_name:
        return ""
    call_re = re.compile(r"\b" + re.escape(fn_name) + r"\s*\(")
    out = []
    for i, ln in enumerate(lines):
        if i >= fn_start - 2 and i <= fn_start + 2:
            continue  # skip the definition line itself
        if not call_re.search(ln):
            continue
        # only treat as a "caller" if it is OUTSIDE the callee body (above its sig
        # or well below it) - we want the consuming control-flow, not recursion.
        # walk back to the nearest loop/switch/branch header that frames the call.
        loop_hdr = i
        for j in range(i, max(i - 30, -1), -1):
            if re.search(r"\b(for|while|if|else if|switch)\b", lines[j]):
                loop_hdr = j
                break
        out.append(_snippet(lines, loop_hdr, 1, max(i - loop_hdr, 0) + 4, cap // max_sites))
        if len(out) >= max_sites:
            break
    return "\n--\n".join(out)


def _produced_field_terms(fn_body: str, fn_sig: str) -> set[str]:
    """Data-flow anchors a downstream sink would reference if it consumes THIS
    guard's output: the enclosing fn's return type, struct types it builds, and
    field accesses on those (e.g. `Header`, `Digest`, `consensus`, `consensus.data`).
    Used to RANK sibling sinks so we pick the one that actually consumes the
    guard's product (Types.sol substr of `consensus.data`) rather than the first
    arbitrary sink in the first sibling (the NS-9f940d402058 miss)."""
    terms: set[str] = set()
    # return-type name(s)
    m = re.search(r"returns\s*\(([^)]*)\)", fn_sig)
    if m:
        for tok in re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", m.group(1)):
            terms.add(tok)
    # struct/type constructors and `.field` accesses inside the body
    for tok in re.findall(r"\b([A-Z][A-Za-z0-9_]+)\s*\(", fn_body):
        terms.add(tok)
    for tok in re.findall(r"\.([a-z][A-Za-z0-9_]*)\b", fn_body):
        if len(tok) >= 4 and tok not in {"length", "offset", "data", "value", "push"}:
            terms.add(tok)
    # the produced bytes most often flow through `.consensus.data` / `.digests`
    for kw in ("consensus", "digests", "digest", "data"):
        if kw in fn_body:
            terms.add(kw)
    return {t for t in terms if len(t) >= 4}


def _sink_score(sink_text: str, fn_terms: set[str]) -> int:
    """Rank a candidate sink by how strongly it references the guard fn's product."""
    score = 0
    for t in fn_terms:
        if t and t in sink_text:
            score += 2
    # the high-value zero-propagation / panic sinks
    if "substr" in sink_text or "abi.decode" in sink_text:
        score += 1
    return score


def _downstream_sink_context(lines: list[str], src_path: Path, source_root: Path,
                             fn_terms: set[str] | None = None,
                             max_sites: int = 2, cap: int = 700) -> str:
    """When a parser guard's enclosing fn returns bytes/root, the gap is usually
    in the SINK that consumes it - Bytes.substr / abi.decode / child verify() -
    frequently in a SIBLING file (Codec.sol -> Types.sol, Router -> EcdsaBeefy).
    Pull a small snippet of the sibling-dir sink call-sites that most strongly
    reference THIS guard fn's product (ranked by `fn_terms`) so the cross-file
    zero-propagation gap (substr("") -> bytes32(0)) falls inside the window.
    Bounded: scan only same-directory siblings, rank, keep top `max_sites`."""
    fn_terms = fn_terms or set()
    sib_dir = src_path.parent
    try:
        siblings = sorted(p for p in sib_dir.iterdir()
                          if p.is_file() and p.suffix == src_path.suffix and p != src_path)
    except OSError:
        siblings = []
    candidates: list[tuple[int, str]] = []  # (score, snippet)
    for sib in siblings:
        try:
            sl = sib.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        # pick the single best-scoring sink per sibling (relevance, not first-hit)
        best: tuple[int, int] | None = None  # (score, line_idx)
        for i, ln in enumerate(sl):
            if not _SINK_CALL.search(ln):
                continue
            sc = _sink_score(ln, fn_terms)
            if best is None or sc > best[0]:
                best = (sc, i)
        if best is not None:
            sc, i = best
            snip = f"// sink in {sib.name}:{i + 1}\n" + _snippet(sl, i, 1, 1, cap // max_sites)
            candidates.append((sc, snip))
    # highest-relevance sinks first, then keep the budget
    candidates.sort(key=lambda x: x[0], reverse=True)
    return "\n--\n".join(s for _, s in candidates[:max_sites])


def _callee_body_context(lines: list[str], fn_start: int, fn_end_hint: int,
                         src_path: Path, max_sites: int = 1, cap: int = 600) -> str:
    """The guard's OWN function body may invoke a child callee whose body carries
    the real sink - a child-contract `verify()` whose `abi.decode(proof,...)`
    panics on the stripped 1-byte input (NS-e986be6f56eb), or a sibling consumer
    that substr's the returned bytes. Find such invocations in the guard fn body,
    resolve the callee's method body (in-file or cross-file in the same dir), and
    pull its SINK line so the downstream-decode/panic gap is inside the window.
    Bounded: at most `max_sites` callees, cap each snippet."""
    body = "\n".join(lines[fn_start:min(fn_end_hint, len(lines))])
    callees: list[str] = []
    for name in _CALLEE_INVOKE.findall(body):
        if name in _CALLEE_NOISE or len(name) < 4 or name in callees:
            continue
        # only chase callees that plausibly carry a decode/verify sink
        if re.search(r"(verify|decode|stateCommitment|parse|deserialize|read)", name, re.IGNORECASE):
            callees.append(name)
    out: list[str] = []
    # search the guard file itself + same-dir siblings for each callee's body
    search_files: list[Path] = [src_path]
    try:
        search_files += sorted(p for p in src_path.parent.iterdir()
                               if p.is_file() and p.suffix == src_path.suffix and p != src_path)
    except OSError:
        pass
    for name in callees:
        if len(out) >= max_sites:
            break
        def_re = re.compile(r"\b(?:fn|func|function)\s+" + re.escape(name) + r"\b")
        for sf in search_files:
            try:
                sl = (lines if sf == src_path
                      else sf.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                continue
            di = next((i for i, ln in enumerate(sl) if def_re.search(ln)), None)
            if di is None:
                continue
            # scan the callee body (bounded) for the first sink line
            for i in range(di, min(di + 60, len(sl))):
                if i > di and _SINK_CALL.search(sl[i]):
                    out.append(f"// callee {name}() sink in {sf.name}:{i + 1}\n" +
                               _snippet(sl, i, 1, 1, cap // max_sites))
                    break
            if out and len(out) >= max_sites:
                break
        if len(out) >= max_sites:
            break
    return "\n--\n".join(out)


def extract(workspace: Path, source_root: Path, window: int, limit: int | None, out_path: Path) -> dict:
    worklist = workspace / ".auditooor" / "negative_space_worklist.jsonl"
    if not worklist.is_file():
        return {"schema": SCHEMA, "error": f"no worklist at {worklist}", "packets": 0}

    guards = []
    for ln in worklist.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            guards.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    if limit:
        guards = guards[:limit]

    # group by file so each file is read + split ONCE
    file_cache: dict[str, list[str]] = {}
    test_range_cache: dict[str, set[int]] = {}
    packets = []
    unresolved = 0
    oos_skipped = 0
    test_skipped = 0
    for g in guards:
        gid = g.get("guard_id") or g.get("id")
        fl = str(g.get("file_line") or "")
        path_hint, line_no = _file_of(fl)
        f = _resolve_file(path_hint, source_root) if path_hint else None
        if not f or line_no is None:
            unresolved += 1
            continue
        # SCOPE FILTER (manifest-authoritative): a guard whose file is OOS
        # (vendored/test/generated, or not in the workspace's inscope manifest) is
        # not a production audit surface - do not spend probe budget on it. Uses
        # the workspace-relative path_hint from the worklist file_line.
        if path_hint and not _is_in_scope(str(path_hint), workspace=workspace):
            oos_skipped += 1
            continue
        key = str(f)
        if key not in file_cache:
            try:
                file_cache[key] = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                file_cache[key] = []
            test_range_cache[key] = _test_line_ranges(file_cache[key])
        lines = file_cache[key]
        if not lines:
            unresolved += 1
            continue
        # TEST FILTER: a guard inside a Rust #[cfg(test)]/#[test] item is a test
        # assertion, not a production guard - OOS for a negative-space probe. (The
        # dominant optimism pollution: ~80% of guard packets were op-reth
        # flashblocks #[cfg(test)] assertions burning probe budget on test oracles.)
        if (line_no - 1) in test_range_cache.get(key, ()):
            test_skipped += 1
            continue
        const_index = _const_defs_in_file(lines)
        idx = min(max(line_no - 1, 0), len(lines) - 1)
        guard_line = lines[idx].strip()
        fn_start = _enclosing_fn_start(lines, idx)
        lo = max(fn_start, idx - window)
        hi = min(len(lines), idx + window)
        context = "\n".join(lines[lo:hi])
        # cap the function body slice to keep packets compact
        if len(context) > 4000:
            context = context[:4000] + "\n... [truncated for packet compactness]"

        # --- NS-628de923949e fix: carry the invariant-defining context the
        #     guard line alone cannot show ---
        # (a) enclosing impl/trait header with generic type-param bounds
        impl_header, _ = _enclosing_impl_header(lines, fn_start)
        # (b) definitions of ALL_CAPS constants referenced near the guard whose
        #     value is the bound the mechanical guard is really a proxy for
        const_defs = _referenced_consts(guard_line, context, const_index)

        # (c) invariant-context-completeness heuristic: a mechanical guard
        #     (overflow/abs/len/non-zero/cast) on a value whose semantic range is
        #     defined elsewhere (generic type param, or named constant not in the
        #     window) is NOT safe to certify as no-gap from the packet alone.
        header_for_scan = impl_header or ""
        # also fold in the enclosing fn signature line for generic detection
        if 0 <= fn_start < len(lines):
            header_for_scan += "\n" + lines[fn_start]
        is_mechanical = bool(_MECHANICAL_GUARD.search(guard_line))
        has_generic = bool(_GENERIC_PARAM.search(header_for_scan))
        # constant referenced on the guard line but whose definition we could NOT
        # locate in-file -> the bound lives out of reach; treat as incomplete.
        gl_consts = (set(_NAMED_CONST.findall(guard_line)) - _CONST_NOISE)
        missing_const_bound = any(c not in const_index for c in gl_consts)
        invariant_context_incomplete = is_mechanical and (has_generic or missing_const_bound)
        # When a mechanical guard is flagged incomplete by a generic type param,
        # the bound it is really a proxy for is most often a monetary/range const
        # defined elsewhere in the file (MAX_MONEY, COIN, MAX_*, *_LIMIT). Surface
        # those defs so the probe (or escalated full-read) sees the candidate
        # invariant anchors without a second file read.
        if invariant_context_incomplete and has_generic and not const_defs:
            for name, defn in sorted(const_index.items()):
                if defn not in context and re.search(
                    r"(MAX|MIN|LIMIT|CAP|MONEY|COIN|SUPPLY|RANGE|BOUND|AMOUNT)", name, re.IGNORECASE
                ):
                    const_defs.append(defn)
        # --- HB windowing-trap fix: parser/decoder/proof-router guards ---
        # The visible guard line is correct, but the exploitable behavior lives
        # in the caller's consumption (dispatch desync) or a downstream sink
        # (Bytes.substr / abi.decode / child verify(), often cross-file). Detect
        # the class mechanically and carry the missing caller + sink context.
        fn_sig_line = lines[fn_start] if 0 <= fn_start < len(lines) else ""
        enclosing_fn_name = _fn_name_from_sig(fn_sig_line) or _fn_name_from_sig(guard_line)
        is_parser_router_class = bool(
            (_PARSER_FILE.search(str(f)) and _PARSER_FN_NAME.search(fn_sig_line or guard_line))
            or _SINK_CALL.search(context)
        )
        caller_loop_context = ""
        downstream_sink_context = ""
        callee_body_context = ""
        if is_parser_router_class:
            caller_loop_context = _caller_loop_context(lines, enclosing_fn_name or "", fn_start)
            # data-flow anchors so the sink ranker picks the consumer of THIS
            # guard fn's product (e.g. Types.sol substr of `consensus.data`),
            # not the first arbitrary sibling sink (NS-9f940d402058 miss).
            fn_terms = _produced_field_terms(context, fn_sig_line)
            downstream_sink_context = _downstream_sink_context(lines, f, source_root, fn_terms)
            # the guard fn's own body may call a child verify()/decode whose body
            # carries the panicking abi.decode (NS-e986be6f56eb) or the substr sink.
            callee_body_context = _callee_body_context(lines, fn_start, hi, f)
        windowing_incomplete = is_parser_router_class and bool(
            caller_loop_context or downstream_sink_context or callee_body_context
            or _SINK_CALL.search(context)
        )

        # fold the windowing trap into the provisional-no-gap signal so the probe
        # (and the depth gate) treat packet=no-gap as PROVISIONAL on these guards.
        invariant_context_incomplete = invariant_context_incomplete or windowing_incomplete

        escalation_reason = ""
        if invariant_context_incomplete:
            bits = []
            if has_generic:
                bits.append("guarded value's range is set by a generic type parameter "
                            "(see impl_header) the mechanical guard cannot bound")
            if missing_const_bound:
                bits.append(f"guard references named constant(s) {sorted(gl_consts)} whose "
                            "defining bound is not visible in this window")
            if windowing_incomplete:
                bits.append("guard sits inside a parser/decoder/proof-router; the exploitable "
                            "behavior is the CALLER's consumption (dispatch/offset desync) or a "
                            "DOWNSTREAM SINK (Bytes.substr / abi.decode / child verify(), possibly "
                            "cross-file) - see caller_loop_context / downstream_sink_context / "
                            "callee_body_context")
            lead = "MECHANICAL guard" if is_mechanical else "PARSER/ROUTER guard"
            escalation_reason = ("{} ({}) is a proxy for a wider invariant defined OUTSIDE the guard "
                                 "line: {}. Do NOT certify gap_found=false from this packet - escalate "
                                 "to a full read (caller control-flow + downstream sink) to confirm the "
                                 "wider invariant is enforced.").format(lead, guard_line[:80], "; ".join(bits))

        packets.append({
            "schema": SCHEMA,
            "guard_id": gid,
            "file_line": fl,
            "guard_line": guard_line,
            "checks": g.get("checks") or g.get("invariant_hint") or "",
            "invariant_hint": g.get("invariant_hint") or g.get("invariant") or "",
            "impl_header": impl_header or "",
            "referenced_const_defs": const_defs,
            "function_context": context,
            "context_line_span": [lo + 1, hi],
            "caller_loop_context": caller_loop_context,
            "downstream_sink_context": downstream_sink_context,
            "callee_body_context": callee_body_context,
            "windowing_incomplete": windowing_incomplete,
            "invariant_context_incomplete": invariant_context_incomplete,
            "escalation_reason": escalation_reason,
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for p in packets:
            fh.write(json.dumps(p) + "\n")

    # token estimate (rough: 4 chars/token) over EVERY context-bearing field
    def _packet_chars(p: dict) -> int:
        return (len(p["function_context"]) + len(p.get("impl_header", "")) +
                sum(len(c) for c in p.get("referenced_const_defs", [])) +
                len(p.get("caller_loop_context", "")) +
                len(p.get("downstream_sink_context", "")) +
                len(p.get("callee_body_context", "")) +
                len(p.get("escalation_reason", "")))
    approx_tokens = sum(_packet_chars(p) for p in packets) // 4
    incomplete = sum(1 for p in packets if p.get("invariant_context_incomplete"))
    windowing = sum(1 for p in packets if p.get("windowing_incomplete"))
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "guards_in_worklist": len(guards),
        "packets_written": len(packets),
        "unresolved": unresolved,
        "oos_skipped": oos_skipped,
        "test_skipped": test_skipped,
        "files_read": len(file_cache),
        "invariant_context_incomplete": incomplete,
        "windowing_incomplete": windowing,
        "out": str(out_path),
        "approx_packet_tokens_total": approx_tokens,
        "approx_tokens_per_packet": (approx_tokens // len(packets)) if packets else 0,
        "note": "feed each packet's guard_line+function_context+impl_header+referenced_const_defs+"
                "invariant_hint to a cheap probe model; no file read needed downstream. When "
                "invariant_context_incomplete=true, a packet 'gap_found=false' is PROVISIONAL - "
                "escalate to a full read per escalation_reason.",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--source-root", type=Path, default=None)
    ap.add_argument("--window", type=int, default=_DEFAULT_WINDOW)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    source_root = (args.source_root or ws).expanduser().resolve()
    out_path = args.out or (ws / ".auditooor" / "guard_probe_packets.jsonl")
    out = extract(ws, source_root, args.window, args.limit, out_path)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        if out.get("error"):
            print(f"[guard-context-extract] {out['error']}")
            return 2
        print(f"[guard-context-extract] {out['packets_written']} packets from {out['files_read']} files "
              f"(~{out['approx_tokens_per_packet']} tok/packet, {out['unresolved']} unresolved) -> {out['out']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
