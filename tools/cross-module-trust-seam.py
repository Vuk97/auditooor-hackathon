#!/usr/bin/env python3
"""cross-module-trust-seam.py - A2 cross-module trust-boundary seam detector.

North-star: module A TRUSTS that module B validated a state var V and does NOT
re-check V at A's sink; find an entry to A's sink reaching it via a path that
BYPASSES B's guard.

A SEAM FIRES for a state var V when ALL hold:
  (a) V has >=1 GUARDED producer:
        slither_predicates.has_guard_in_closure(writer) == True
  (b) the reader sink S does NOT re-check V:
        dataflow.DataFlowEngine._guards_for_vars(reader, {V}) is empty
        AND slither_predicates.has_guard_in_closure(reader) == False
  (c) slither_predicates.unguarded_paths_to_sink(S, scope) returns
        >=1 UNGUARDED entrypoint (a bypass path to A's sink).

Substrate reuse (build-from, do NOT re-derive):
  - slither_predicates.has_guard_in_closure  -> GUARDED-PRODUCER test
  - slither_predicates.unguarded_paths_to_sink -> BYPASS-PATH enumerator
  - dataflow-slice.DataFlowEngine.storage_mediated_paths / _contract_statevar_sites
      -> writer@A(V) -> reader@B(V) storage-mediated pairs
  - dataflow-slice.DataFlowEngine._guards_for_vars -> consumer re-check test

Emits:
  .auditooor/cross_module_trust_seams.jsonl  (one row per trust edge:
      guarded-producer file:line, unguarded-consumer-sink file:line,
      bypass-entrypoint)
  .auditooor/cross_module_trust_seams.accounting.json  ({rows, disposed,
      un_disposed, ...})

ADVISORY-first, FAIL-OPEN (0 rows) on ANY DEGRADED / missing substrate (R80):
a DEGRADED predicate never produces a flag - it leaves the candidate
UN-DISPOSED, never a false seam. NO auto-finding, never a flip of `unguarded`.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE = Path(__file__).resolve().parent
DISPOSITIONS_REL = Path(".auditooor") / "cross_module_trust_seams_dispositions.jsonl"
_TERMINAL_DISPOSITION_TYPES = {
    "clean", "covered", "duplicate", "known-issue", "not-applicable",
    "not_applicable", "oos", "out-of-scope", "refuted", "resolved",
}


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _HERE / filename)
    if not (spec and spec.loader):
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


_SCOPE = _load("_cmts_scope", "scope_authority.py")


def _target_has_inscope_source(ws: Path, target: Path) -> bool:
    """Drop compile targets containing no authoritative in-scope source."""
    if _SCOPE is None:
        return True
    try:
        manifest = _SCOPE.load_inscope(ws)
        if not manifest.present:
            return True
        root = target.resolve()
        for rel in manifest.relpaths:
            path = (ws / rel).resolve()
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False
    except Exception:
        # Scope setup/gating owns missing or malformed manifests. Do not make
        # this advisory producer silently discard a target on a reader error.
        return True


def _site_of(dfs, fn, var: str):
    """Best-effort (file, line) of the node in `fn` touching `var`; fall back
    to the function declaration site."""
    try:
        for n in getattr(fn, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if var and var in expr:
                return dfs._file_of(n), dfs._first_line(n)
    except Exception:
        pass
    return dfs._file_of(fn), dfs._first_line(fn)


def _fn_id(fn) -> str:
    return getattr(fn, "canonical_name", getattr(fn, "name", "?")) or "?"


def _stable_id(namespace: str, *parts: Any) -> str:
    body = "|".join([namespace, *(str(part or "") for part in parts)])
    return "cmts-" + hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:20]


def _evidence_backed_disposition(row: dict) -> bool:
    """A typed terminal close must carry explicit evidence, not prose alone."""
    dtype = str(row.get("disposition_type") or "").strip().lower()
    reason = str(row.get("reason") or "").strip()
    if dtype not in _TERMINAL_DISPOSITION_TYPES or not reason:
        return False
    def has_value(value) -> bool:
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple)):
            return any(has_value(item) for item in value)
        if isinstance(value, dict):
            return any(has_value(item) for item in value.values())
        return False

    for key in ("evidence", "evidence_ref", "evidence_refs", "source_ref", "source_refs"):
        value = row.get(key)
        if has_value(value):
            return True
    return False


def _load_dispositions(ws: Path) -> tuple[Dict[str, dict], set[str]]:
    """Return valid stable-ID closures and conflicting IDs separately."""
    valid: Dict[str, dict] = {}
    ambiguous: set[str] = set()
    path = ws / DISPOSITIONS_REL
    if not path.is_file():
        return valid, ambiguous
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return valid, ambiguous
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(row, dict) or not _evidence_backed_disposition(row):
            continue
        stable_id = str(row.get("stable_id") or "").strip()
        if not stable_id:
            continue
        if stable_id in valid and valid[stable_id] != row:
            ambiguous.add(stable_id)
            valid.pop(stable_id, None)
            continue
        if stable_id not in ambiguous:
            valid[stable_id] = row
    return valid, ambiguous


def _strict_finalize(ws: Path, rows: List[Dict[str, Any]],
                     acct: Dict[str, Any], strict: bool) -> Dict[str, Any]:
    """Attach strict accounting without changing advisory-mode semantics."""
    acct["strict"] = bool(strict)
    if not strict:
        return acct
    dispositions, ambiguous_dispositions = _load_dispositions(ws)
    open_ids: List[str] = []
    resolved = 0
    for row in rows:
        stable_id = str(row.get("stable_id") or "")
        if stable_id and stable_id in dispositions and stable_id not in ambiguous_dispositions:
            row["disposition"] = dispositions[stable_id].get("disposition_type")
            row["disposition_evidence_backed"] = True
            resolved += 1
        else:
            open_ids.append(stable_id or "<missing-stable-id>")
    blockers: List[str] = []
    if acct.get("degraded") or str(acct.get("status", "")).startswith("0-"):
        blockers.append("missing-or-degraded-substrate")
    if not acct.get("substrate_evidence"):
        blockers.append("missing-evidence-backed-accounting")
    if open_ids:
        blockers.append("unresolved-seams:" + ",".join(open_ids))
    if ambiguous_dispositions:
        blockers.append("ambiguous-dispositions:" + ",".join(sorted(ambiguous_dispositions)))
    if acct.get("truncated"):
        blockers.append("truncated-output")
    acct["strict_resolved_rows"] = resolved
    acct["strict_unresolved_rows"] = open_ids
    acct["strict_blockers"] = blockers
    acct["strict_verdict"] = "fail-cross-module-trust-seam" if blockers else (
        "pass-not-applicable" if not rows and not acct.get("substrate_present", True)
        else "pass-cross-module-trust-seam"
    )
    acct["strict_ok"] = not blockers
    acct["verdict"] = acct["strict_verdict"]
    return acct


def _pick_compile_target(dfs, ws: Path) -> List[Path]:
    """Ordered slither compile-target candidates for a (possibly multi-package)
    ws. Passing the bare ws DIR to slither fails on a multi-package tree
    (etherfi/morpho -> 0 rows). Prefer the nearest config root(s); reuse
    dataflow-slice._resolve_targets (harness/vendor dirs excluded, shallowest
    first). Fall back to src/**.sol package dirs, then the bare ws.
    """
    # ws itself is a config root -> use it directly.
    for cfg in ("foundry.toml", "hardhat.config.ts", "hardhat.config.js"):
        if (ws / cfg).is_file():
            return [ws]
    cands: List[Path] = []
    try:
        cands = list(dfs._resolve_targets(ws)) if hasattr(dfs, "_resolve_targets") else []
    except Exception:
        cands = []
    if cands:
        return [c for c in cands if _target_has_inscope_source(ws, c)] or cands
    # Fallback: package dirs under src/ that hold .sol (dedup, shallowest first).
    src = ws / "src"
    if src.is_dir():
        pkgs: set = set()
        for sol in src.rglob("*.sol"):
            parts = set(sol.parts)
            if parts & {"node_modules", "lib", "out", "cache", "test", "tests"}:
                continue
            pkgs.add(sol.parent)
        if pkgs:
            filtered = [p for p in pkgs if _target_has_inscope_source(ws, p)]
            return sorted(filtered or pkgs, key=lambda d: len(d.parts))
    return [ws]


def _all_functions(slither) -> List[Any]:
    out: List[Any] = []
    for cu in getattr(slither, "compilation_units", []) or []:
        for c in getattr(cu, "contracts", []) or []:
            if getattr(c, "is_interface", False):
                continue
            for f in getattr(c, "functions", []) or []:
                out.append(f)
    return out


def emit(ws: Path, target: Optional[Path], max_rows: int,
         strict: bool = False) -> Dict[str, Any]:
    acct: Dict[str, Any] = {
        "workspace": str(ws),
        "rows": 0,
        "disposed": 0,
        "un_disposed": 0,
        "candidates": 0,
        "guarded_producer_vars": 0,
        "status": "not-run",
        "degraded": False,
        "substrate_present": False,
        "substrate_evidence": False,
    }
    out_rows: List[Dict[str, Any]] = []

    def finish() -> Dict[str, Any]:
        _strict_finalize(ws, out_rows, acct, strict)
        return _write(ws, out_rows, acct)

    dfs = _load("_cmts_dfs", "dataflow-slice.py")
    sp = _load("_cmts_sp", "slither_predicates.py")
    if dfs is None or sp is None or not hasattr(sp, "has_guard_in_closure"):
        acct["status"] = "0-substrate-module-absent"
        acct["degraded"] = True
        return finish()

    DEGRADED = getattr(sp, "DEGRADED", object())
    # A bare ws DIR does not compile on a multi-package tree; pick a compilable
    # target (nearest config root, then src/**.sol pkg). Try each in order.
    candidates = [Path(target)] if target else _pick_compile_target(dfs, ws)
    slither, err, chosen = None, None, None
    for cand in candidates:
        slither, err = dfs.load_slither_offline(Path(cand))
        if slither is not None:
            chosen = cand
            break
    acct["compile_target"] = str(chosen) if chosen else ""
    acct["compile_candidates"] = [str(c) for c in candidates]
    if slither is None:
        acct["status"] = "0-slither-degraded"
        acct["degraded"] = True
        acct["note"] = (err or "slither-load-failed")[:160]
        return finish()

    try:
        engine = dfs.DataFlowEngine(slither)
    except Exception as e:
        acct["status"] = "0-engine-degraded"
        acct["degraded"] = True
        acct["note"] = f"{type(e).__name__}:{str(e)[:120]}"
        return finish()

    scope = _all_functions(slither)
    acct["substrate_present"] = True

    # writers[var]/readers[var] as Function objects (semantic-ssa track).
    writers: Dict[str, List[Any]] = {}
    readers: Dict[str, List[Any]] = {}
    try:
        statevar_sites = 0
        for var, f, c, kind in engine._contract_statevar_sites():
            statevar_sites += 1
            (writers if kind == "write" else readers).setdefault(var, []).append(f)
        acct["substrate_evidence"] = bool(acct.get("compile_target"))
        acct["accounting"] = {
            "functions_examined": len(scope),
            "statevar_sites_examined": statevar_sites,
            "candidate_vars": 0,
        }
    except Exception as e:
        acct["status"] = "0-statevar-sites-degraded"
        acct["degraded"] = True
        acct["note"] = f"{type(e).__name__}:{str(e)[:120]}"
        return finish()

    def _dedup(fns: List[Any]) -> List[Any]:
        seen = set()
        uniq = []
        for f in fns:
            k = id(f)
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        return uniq

    candidate_vars = sorted(set(writers) & set(readers))
    acct["candidates"] = len(candidate_vars)
    seen_edge = set()

    for var in candidate_vars:
        ws_writers = _dedup(writers.get(var, []))
        rs_readers = _dedup(readers.get(var, []))

        # (a) guarded producers of V.
        guarded_producers: List[Any] = []
        degraded_here = False
        for w in ws_writers:
            g = sp.has_guard_in_closure(w)
            if g is DEGRADED:
                degraded_here = True
                continue
            if bool(g):
                guarded_producers.append(w)
        if degraded_here and not guarded_producers:
            # cannot honestly decide (a) - leave un-disposed (fail-open).
            acct["un_disposed"] += 1
            continue
        if not guarded_producers:
            acct["disposed"] += 1  # terminal: no guarded producer for V.
            continue
        acct["guarded_producer_vars"] += 1

        # (b) reader sinks S that do NOT re-check V.
        fired_any = False
        var_degraded = False
        for s in rs_readers:
            if id(s) in {id(w) for w in ws_writers} and s in ws_writers:
                # producer == consumer is not a cross-fn seam; skip.
                pass
            # consumer must not itself re-check V.
            try:
                sguards = engine._guards_for_vars(s, {var})
            except Exception:
                var_degraded = True
                continue
            if sguards:
                continue  # consumer re-checks V -> BENIGN, no seam.
            gs = sp.has_guard_in_closure(s)
            if gs is DEGRADED:
                var_degraded = True
                continue
            if bool(gs):
                continue  # consumer's closure carries a guard -> re-checks.

            # (c) bypass path: an unguarded entrypoint reaching sink S.
            paths = sp.unguarded_paths_to_sink(s, scope)
            if paths is DEGRADED:
                var_degraded = True
                continue
            bypass = [p for p in paths if not p.get("guarded")]
            if not bypass:
                continue  # every reaching entry is guarded -> no bypass.

            # SEAM fires for (each guarded producer, this sink, each bypass ep).
            pfile, pline = None, None
            sfile, sline = _site_of(dfs, s, var)
            for prod in guarded_producers:
                pfile, pline = _site_of(dfs, prod, var)
                for ep in bypass:
                    ep_id = _fn_id(ep.get("entrypoint"))
                    edge_key = (var, _fn_id(prod), pline, _fn_id(s), sline, ep_id)
                    if edge_key in seen_edge:
                        continue
                    seen_edge.add(edge_key)
                    stable_id = _stable_id(
                        "a2", var, _fn_id(prod), pline, _fn_id(s), sline, ep_id
                    )
                    out_rows.append({
                        "seam_id": f"cmts-{len(out_rows):04d}",
                        "stable_id": stable_id,
                        "id": stable_id,
                        "state_var": var,
                        "guarded_producer": {
                            "fn": _fn_id(prod), "file": pfile, "line": pline,
                        },
                        "unguarded_consumer_sink": {
                            "fn": _fn_id(s), "file": sfile, "line": sline,
                        },
                        "bypass_entrypoint": {
                            "fn": ep.get("name"),
                            "contract": ep.get("contract"),
                            "guarded": False,
                        },
                        "trust_edge": (
                            f"{_fn_id(prod)} writes {var} (guarded) -> "
                            f"{_fn_id(s)} reads {var} (no re-check) <- "
                            f"bypass entry {ep.get('name')}"
                        ),
                        "confidence": "syntactic",
                        "advisory": True,
                    })
                    fired_any = True
                    if len(out_rows) >= max_rows:
                        break
                if len(out_rows) >= max_rows:
                    break
            if len(out_rows) >= max_rows:
                break

        if var_degraded and not fired_any:
            acct["un_disposed"] += 1
        else:
            acct["disposed"] += 1
        if len(out_rows) >= max_rows:
            acct["truncated"] = True
            break

    acct["rows"] = len(out_rows)
    acct["accounting"]["candidate_vars"] = len(candidate_vars)
    acct["status"] = "ok"
    return finish()


def _write(ws: Path, rows: List[Dict[str, Any]], acct: Dict[str, Any]) -> Dict[str, Any]:
    a = ws / ".auditooor"
    try:
        a.mkdir(parents=True, exist_ok=True)
        with (a / "cross_module_trust_seams.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        (a / "cross_module_trust_seams.accounting.json").write_text(
            json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return acct


# ============================================================================
# A5 encode/decode LAYOUT-trust seam (Rust serialize/deserialize JOIN).
#
# Reuses A2's DISPOSITION signal (a GUARDED producer trusted by an UNGUARDED
# consumer) but replaces A2's storage-slot JOIN with a serialize/deserialize
# JOIN: an ``encode_*`` producer that enforces a FIXED byte layout (a *LEN*
# usize const materialised via ``with_capacity(const)``) paired with a
# ``decode_*`` consumer. The novel teeth = the codec JOIN; a storage-slot
# JOIN (A2) cannot express "the decoder omits the exact-length/is_empty guard
# the encoder layout implies". A2 rows are DEDUP'd (covered_by_a2), never
# re-derived.
#
# ADVISORY-first, OFF by default: no-op unless env AUDITOOOR_ENCODE_DECODE_SEAM
# is set (or force=True). Every row carries verdict='needs-fuzz' (NO-AUTO-
# CREDIT). FP-GUARD: derive-based (symmetric) Encodable/Decodable pairs are
# EXCLUDED (they never register a handwritten *LEN*-enforcing producer), and a
# decoder that carries ANY .len()-compare / .is_empty() / *LEN*-const compare
# is BENIGN. Emits <ws>/.auditooor/encode_decode_seams.jsonl.
# ============================================================================
import os
import re

_A5_ENV = "AUDITOOOR_ENCODE_DECODE_SEAM"
_A5_ON = {"1", "true", "on", "yes"}

# fn declaration head (name capture); permissive on modifiers.
_A5_FN_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)
_A5_ENC_RE = re.compile(r"^encode(?:_(\w+))?$")
_A5_DEC_RE = re.compile(r"^decode(?:_(\w+))?$")
# a *LEN* usize const reference in the encoder body -> enforced fixed layout.
_A5_LEN_TOKEN_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_?LEN[A-Z0-9_]*)\b")
_A5_WITH_CAP_RE = re.compile(r"\bwith_capacity\s*\(\s*(?:Self::)?([A-Za-z_][A-Za-z0-9_]*)")
# the exact-length / is_empty guard the layout implies.
_A5_LEN_GUARD_RE = re.compile(r"\.len\s*\(\s*\)\s*(?:==|!=|<=|>=|<|>)")
_A5_IS_EMPTY_RE = re.compile(r"\.is_empty\s*\(\s*\)")
# symmetric derived codecs -> safe, high FP -> excluded from the producer index.
_A5_DERIVE_RE = re.compile(
    r"#\[\s*derive\s*\([^)]*\b(?:Rlp(?:Encodable|Decodable)|Encode|Decode|"
    r"Serialize|Deserialize|Borsh(?:Serialize|Deserialize))\b[^)]*\)\s*\]"
)


def _a5_strip_tests(text: str) -> str:
    """Remove ``#[cfg(test)] mod .. { .. }`` blocks (brace-balanced)."""
    out: List[str] = []
    i = 0
    pat = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub\s+)?mod\s+\w+\s*\{")
    while True:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        depth, j, n = 0, m.end() - 1, len(text)
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
    return "".join(out)


def _a5_iter_fns(text: str):
    """Yield (name, decl_line, body_text) for every fn WITH a body."""
    n = len(text)
    for m in _A5_FN_RE.finditer(text):
        name = m.group(1)
        j = m.end()
        depth, body_start = 0, -1
        while j < n:
            c = text[j]
            if c == ";" and body_start == -1:
                break  # trait/extern decl, no body
            if c == "{":
                if body_start == -1:
                    body_start = j
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0 and body_start != -1:
                    line = text.count("\n", 0, m.start()) + 1
                    yield name, line, text[body_start:j + 1]
                    break
            j += 1


def _a5_enumerate(ws: Path, scan_root: Optional[Path]) -> List[Path]:
    roots: List[Path] = []
    if scan_root is not None:
        roots = [Path(scan_root)]
    else:
        try:
            sys.path.insert(0, str(_HERE))
            from lib.project_source_roots import rust_crate_scan_roots  # type: ignore
            rels = rust_crate_scan_roots(ws, ("external/base/crates", "crates"))
            roots = [ws / r for r in rels]
        except Exception:
            roots = [ws]
    files: List[Path] = []
    seen: set = set()
    for root in roots:
        root = Path(root)
        if root.is_file() and root.suffix == ".rs":
            if root not in seen:
                seen.add(root)
                files.append(root)
            continue
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.rs")):
            s = str(p)
            if "/target/" in s or "/tests/" in s:
                continue
            if p.name.endswith("_test.rs") or p.name.endswith("_tests.rs"):
                continue
            if p in seen:
                continue
            seen.add(p)
            files.append(p)
    return files


def _a5_load_a2_sinks(ws: Path) -> set:
    """DEDUP boundary: (file,line) of A2 consumer sinks - covered_by_a2, never
    re-derived here."""
    sinks: set = set()
    jl = ws / ".auditooor" / "cross_module_trust_seams.jsonl"
    if not jl.is_file():
        return sinks
    try:
        for ln in jl.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            row = json.loads(ln)
            s = row.get("unguarded_consumer_sink") or {}
            f, l = s.get("file"), s.get("line")
            if f is not None and l is not None:
                sinks.add((str(f), int(l)))
    except Exception:
        return set()
    return sinks


def emit_encode_decode_seams(
    ws: Path,
    scan_root: Optional[Path] = None,
    max_rows: int = 2000,
    force: bool = False,
    strict: bool = False,
) -> Dict[str, Any]:
    """A5 codec layout-trust seams. OFF unless env/force. Fail-open, advisory."""
    acct: Dict[str, Any] = {
        "workspace": str(ws),
        "detector": "A5-encode-decode-seam",
        "rows": 0,
        "files_scanned": 0,
        "producer_types": 0,
        "decoder_consumers": 0,
        "covered_by_a2": 0,
        "status": "not-run",
        "advisory": True,
        "strict": bool(strict),
        "substrate_present": False,
        "substrate_evidence": False,
    }
    rows: List[Dict[str, Any]] = []

    def finish() -> Dict[str, Any]:
        _strict_finalize(ws, rows, acct, strict)
        return _write_ed(ws, rows, acct)

    on = strict or force or os.environ.get(_A5_ENV, "").strip().lower() in _A5_ON
    if not on:
        acct["status"] = "off-by-default"
        return finish()

    files = _a5_enumerate(ws, scan_root)
    acct["files_scanned"] = len(files)
    acct["substrate_present"] = bool(files)
    acct["substrate_evidence"] = bool(
        ws.is_dir() and (scan_root is None or Path(scan_root).exists())
    )

    # PASS 1: producer index. enc_stems maps a codec stem -> {len_consts},
    # ONLY for handwritten encoders that enforce a fixed *LEN* layout.
    enc_stems: Dict[str, set] = {}
    for fp in files:
        try:
            text = _a5_strip_tests(fp.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for name, _line, body in _a5_iter_fns(text):
            em = _A5_ENC_RE.match(name)
            if not em:
                continue
            stem = em.group(1) or ""
            cap = _A5_WITH_CAP_RE.search(body)
            cap_const = cap.group(1) if cap else ""
            len_tokens = set(_A5_LEN_TOKEN_RE.findall(body))
            # layout-enforcing = with_capacity(<const>) AND a *LEN* const in body.
            if cap and (cap_const in len_tokens or len_tokens):
                if cap_const and cap_const[:1].isupper():
                    len_tokens.add(cap_const)
                enc_stems.setdefault(stem, set()).update(len_tokens)
    acct["producer_types"] = len(enc_stems)

    a2_sinks = _a5_load_a2_sinks(ws)
    seen_edge: set = set()

    # PASS 2: decoder consumers joined to a layout-enforcing encoder.
    for fp in files:
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = _a5_strip_tests(raw)
        # per-file derive guard: types whose codec is derive-generated are
        # symmetric-safe; a decoder immediately under such a derive is skipped.
        for name, line, body in _a5_iter_fns(text):
            dm = _A5_DEC_RE.match(name)
            if not dm:
                continue
            acct["decoder_consumers"] += 1
            stem = dm.group(1) or ""
            join_mode = None
            join_stem = None
            len_consts: set = set()
            # (i) DIRECT: this fn IS decode_<stem> for a layout-enforcing stem.
            if stem in enc_stems:
                join_mode, join_stem = "direct", stem
                len_consts = enc_stems[stem]
            else:
                # (ii) WRAPPER: fn body delegates to ::decode_<S> for a
                # layout-enforcing stem S (cross-module trust of the callee).
                for s in enc_stems:
                    callee = "decode_" + s if s else "decode"
                    if re.search(r"::" + re.escape(callee) + r"\s*\(", body):
                        join_mode, join_stem = "wrapper", s
                        len_consts = enc_stems[s]
                        break
            if not join_mode:
                continue
            # BENIGN if the consumer re-checks the layout it trusts: an exact
            # .len() compare, .is_empty(), or a *LEN*-const comparison.
            has_len_guard = bool(_A5_LEN_GUARD_RE.search(body))
            has_empty = bool(_A5_IS_EMPTY_RE.search(body))
            has_const_cmp = any(
                re.search(re.escape(lc) + r"\s*(?:==|!=|<=|>=|<|>)", body)
                or re.search(r"(?:==|!=|<=|>=|<|>)\s*(?:Self::)?" + re.escape(lc), body)
                for lc in len_consts
            )
            if has_len_guard or has_empty or has_const_cmp:
                continue  # decoder re-validates the layout -> no seam.

            try:
                rel = str(fp.relative_to(ws))
            except ValueError:
                rel = str(fp)
            key = (rel, line, name)
            if key in seen_edge:
                continue
            seen_edge.add(key)
            covered = (rel, line) in a2_sinks or (str(fp), line) in a2_sinks
            if covered:
                acct["covered_by_a2"] += 1
            stable_id = _stable_id("a5", rel, line, name)
            rows.append({
                "seam_id": f"eds-{len(rows):04d}",
                "stable_id": stable_id,
                "id": stable_id,
                "codec_stem": join_stem,
                "join": join_mode,
                "decoder_consumer": {"fn": name, "file": rel, "line": line},
                "encoder_layout": {
                    "stem": join_stem,
                    "len_consts": sorted(len_consts),
                },
                "missing_guard": "exact-length/is_empty",
                "trust_edge": (
                    f"encode_{join_stem} enforces layout(len_consts="
                    f"{sorted(len_consts)}) -> decoder {name} omits the "
                    f"exact-length/is_empty guard ({join_mode} join)"
                ),
                "verdict": "needs-fuzz",
                "covered_by_a2": covered,
                "confidence": "syntactic",
                "advisory": True,
            })
            if len(rows) >= max_rows:
                acct["truncated"] = True
                break
        if len(rows) >= max_rows:
            break

    acct["rows"] = len(rows)
    acct["dedup_distinct"] = acct["covered_by_a2"] == 0
    acct["status"] = "ok"
    return finish()


def _write_ed(ws: Path, rows: List[Dict[str, Any]], acct: Dict[str, Any]) -> Dict[str, Any]:
    a = ws / ".auditooor"
    try:
        a.mkdir(parents=True, exist_ok=True)
        with (a / "encode_decode_seams.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        (a / "encode_decode_seams.accounting.json").write_text(
            json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return acct


# ============================================================================
# A17 freshness TOCTOU trust seam (validate-freshness-here / consume-stale-there).
#
# Reuses A2's storage-mediated writer[V] -> reader[V] JOIN (the SAME slither
# substrate: _contract_statevar_sites) but swaps A2's DEFAULT caller-identity
# guard for a FRESHNESS guard predicate + a freshness-typing filter on the flowed
# var. The novel teeth = a value that is validated FRESH at T1 (a staleness /
# updatedAt / deadline compare against block.timestamp) but consumed as an
# authoritative CURRENT value at T2 with NO freshness re-check - a distinct
# population from A2 (a producer whose ONLY guard is a staleness require, with no
# access-control guard, is invisible to A2's caller-identity predicate).
#
# SEMANTIC DIFFERENCE vs A2: A2 = MISSING re-check of a validated INVARIANT
# (value-integrity); A17 = TIME-decayed freshness of a value fresh-at-T1 but
# stale-at-T2. Overlap (a var both AC- and freshness-guarded) is DEDUP'd via
# covered_by_a2 (the consumer sink file:line vs cross_module_trust_seams.jsonl).
#
# ADVISORY-first, OFF by default: no-op unless env AUDITOOOR_FRESHNESS_TOCTOU_SEAM
# (or force=True; the audit-complete auto-run passes force=True). Every row carries
# verdict='needs-fuzz' (NO-AUTO-CREDIT). FAIL-OPEN on ANY degraded substrate
# (a degraded predicate never flags -> un_disposed, never a false seam).
#
# FP-GUARDs (fleet-safe; a green ws stays green):
#   (ii) the PRODUCER guard must be a genuine TIME/oracle COMPARE (block.timestamp
#        / now / Chainlink updatedAt|answeredInRound on one side of a require), not
#        a soft lexicon read.
#   (v) REPLAY-UNIQUENESS / ACCESS-CONTROL EXCLUSION: the flowed var V must name a
#        genuine TIME/ROUND-DECAYED quantity (updatedAt/roundId/answeredInRound/
#        heartbeat/deadline/timestamp/...). A replay-nonce / usedSignatures /
#        authorizationState uniqueness mapping - or an owner/role/whitelist access
#        gate - is NEVER a freshness producer, even when its writer reads
#        block.timestamp for an UNRELATED deadline (NUVA EIP3009 authorizationState
#        FP: the writer's block.timestamp compare is a validAfter/validBefore
#        window check, but the written var is a replay bool with no recency to
#        decay - consuming it later is by design, not a stale-read).
#   (vii) STALE-BY-DESIGN: BENIGN when the consumer body carries an elapsed-time
#        term (`block.timestamp - V` accrual / `V + PERIOD (cmp) block.timestamp`
#        cooldown) - accrual / TWAP / cooldown consume V as an age ON PURPOSE.
# Emits <ws>/.auditooor/freshness_toctou_seams.jsonl (+ .accounting.json).
# ============================================================================
_A17_ENV = "AUDITOOOR_FRESHNESS_TOCTOU_SEAM"
_A17_ON = {"1", "true", "on", "yes"}

# Broad freshness-reference lexicon: names V as freshness-typed AND recognises a
# consumer's freshness re-check (block.timestamp/now/<any freshness token>).
_A17_FRESHNESS_LEXICON = re.compile(
    r"(?:updatedAt|updated_at|answeredInRound|answeredinround|roundId|round_id|"
    r"startedAt|started_at|lastUpdated?|last_updated?|lastAccrual|last_accrual|"
    r"timestamp|deadline|expir(?:y|ation|es|ed|e)|staleness|staleAfter|maxAge|"
    r"maxStale|heartbeat|sequence|nonce)",
    re.IGNORECASE,
)
# Genuine TIME/oracle reference for the PRODUCER guard (mitigation ii): a real
# block.timestamp/now or Chainlink updatedAt/answeredInRound COMPARE - the soft
# lexicon tokens (deadline/nonce/sequence) are deliberately excluded here so a
# producer must carry a real time/oracle compare, never a mere lexicon read.
_A17_TIME_REF = re.compile(
    r"(?:block\.timestamp|(?<![A-Za-z0-9_])now(?![A-Za-z0-9_])|updatedAt|updated_at|"
    r"answeredInRound|answeredinround|roundId|round_id|startedAt|started_at)",
    re.IGNORECASE,
)
# STRICT time/round-DECAYED quantity names for the PRODUCER var-typing (mitigation
# v): the freshness lexicon MINUS the replay-uniqueness tokens (nonce/sequence) -
# the flowed var V must NAME a real time/round-decayed value (a value with recency
# that can go stale), never a replay ordinal.
_A17_DECAY_LEXICON = re.compile(
    r"(?:updatedAt|updated_at|answeredInRound|answeredinround|roundId|round_id|"
    r"startedAt|started_at|lastUpdated?|last_updated?|lastAccrual|last_accrual|"
    r"timestamp|deadline|expir(?:y|ation|es|ed|e)|staleness|staleAfter|maxAge|"
    r"maxStale|heartbeat)",
    re.IGNORECASE,
)
# Replay-uniqueness / access-control var-name patterns (mitigation v): a mapping
# that records "this signature/nonce/hash was USED / this account is AUTHORIZED"
# is a uniqueness or access guard, NOT a time/round-decayed value. Such a var must
# NEVER be typed as a freshness quantity even when its writer reads block.timestamp
# for an unrelated deadline check (NUVA EIP3009 authorizationState FP).
_A17_REPLAY_UNIQUENESS_AC = re.compile(
    r"(?:authorizationstate|usedsignature|usednonce|usedhash|usedauth|usedmessage|"
    r"used_|_used|isused|hasused|seen|consumed|spent|redeemed|processed|executed|"
    r"replay|invalidated|revoked|cancell?ed|(?<![A-Za-z0-9_])nonce|sequence|"  # uniqueness
    r"owner|admin|(?<![A-Za-z0-9_])role|whitelist|blacklist|allowlist|denylist|"  # access-control
    r"authorized|permission|approved|operator|guardian)",
    re.IGNORECASE,
)


def _a17_node_is_conditionish(node: Any) -> bool:
    """True iff `node` is a guard/condition context: an IF node, a require/assert
    call, or a slither Condition IR (mirrors dataflow-slice _guards_for_vars)."""
    t = str(getattr(node, "type", "") or "").upper()
    if "IF" in t:
        return True
    expr = str(getattr(node, "expression", "") or "")
    if "require(" in expr or "assert(" in expr:
        return True
    for ir in getattr(node, "irs", []) or []:
        cls = type(ir).__name__
        if cls == "Condition":
            return True
        if cls == "SolidityCall":
            fnobj = getattr(ir, "function", None)
            nm = str(getattr(fnobj, "name", "") or fnobj or "")
            if "require" in nm or "assert" in nm:
                return True
    return False


def _a17_node_reads_time(node: Any) -> bool:
    """True iff `node` reads block.timestamp/now (SolidityVariable) OR its
    expression carries a genuine time/oracle reference."""
    for v in getattr(node, "solidity_variables_read", []) or []:
        if str(getattr(v, "name", "") or "") in ("block.timestamp", "now"):
            return True
    return bool(_A17_TIME_REF.search(str(getattr(node, "expression", "") or "")))


def _a17_is_freshness_guard(node: Any) -> bool:
    """BROAD freshness guard: a require/if reading ANY freshness reference (a real
    time/oracle compare OR a soft freshness-lexicon token). Used for the CONSUMER
    re-check and the BYPASS test (a consumer that re-checks freshness ANY way is
    BENIGN - a precision-conscious over-suppression, not a false fire)."""
    if not _a17_node_is_conditionish(node):
        return False
    if _a17_node_reads_time(node):
        return True
    return bool(_A17_FRESHNESS_LEXICON.search(str(getattr(node, "expression", "") or "")))


def _a17_producer_freshness_pred(node: Any) -> bool:
    """STRICT producer freshness guard (mitigation ii): a require/if carrying a
    GENUINE block.timestamp/now or Chainlink updatedAt/answeredInRound compare -
    NOT a soft lexicon read - so a producer must prove a real time/oracle gate."""
    return _a17_node_is_conditionish(node) and _a17_node_reads_time(node)


def _a17_expr_is_freshness(expr: str) -> bool:
    """A consumer guard EXPR that re-validates freshness: block.timestamp/now OR
    any freshness-lexicon token (verbatim recon step-6 re-check test)."""
    if not expr:
        return False
    return bool(_A17_TIME_REF.search(expr) or _A17_FRESHNESS_LEXICON.search(expr))


def _a17_freshness_typed_name(var: str) -> bool:
    """V NAMES a genuine time/round-DECAYED quantity (mitigation v): the STRICT
    decay lexicon, NOT the broad freshness lexicon - a replay ordinal (nonce/
    sequence) is deliberately NOT decay-typed here."""
    return bool(var) and bool(_A17_DECAY_LEXICON.search(var))


def _a17_var_is_replay_or_ac(var: str) -> bool:
    """V is a replay-uniqueness (usedSignatures / authorizationState / nonce) or
    access-control (owner / role / whitelist) var - a uniqueness/authorization
    guard, NOT a decayed value. Such a var is NEVER a freshness quantity."""
    return bool(var) and bool(_A17_REPLAY_UNIQUENESS_AC.search(var))


def _a17_writer_freshness_sourced(sp, w: Any, var: str) -> bool:
    """Step-5 freshness typing on V (mitigation v): V must be a genuine time/round-
    DECAYED quantity. A replay-uniqueness / access-control mapping is NEVER a
    freshness quantity even when the writer reads block.timestamp for an UNRELATED
    deadline check (NUVA EIP3009 authorizationState FP: the writer's block.timestamp
    compare is a validAfter/validBefore window guard, but the written var is a replay
    bool). V is freshness-typed iff V is decay-NAMED, OR (V is NOT replay/AC AND the
    writer is oracle/timestamp-sourced)."""
    if _a17_var_is_replay_or_ac(var):
        return False  # replay-nonce / usedSignatures / owner-role: not a freshness var.
    if _a17_freshness_typed_name(var):
        return True
    for pred in ("reads_block_timestamp", "has_latest_round_data"):
        fn = getattr(sp, pred, None)
        if fn is None:
            continue
        try:
            if bool(fn(w)):
                return True
        except Exception:
            pass
    return False


def _a17_has_age_term(fn: Any, var: str) -> bool:
    """Step-7 STALE-BY-DESIGN FP-guard: BENIGN when the consumer body carries an
    elapsed-time term over V - `block.timestamp - V` / `V - block.timestamp`
    (accrual/TWAP) or `V + PERIOD (cmp) block.timestamp` (cooldown/expiry). The
    consumer accounts for staleness ON PURPOSE, so V is not an authoritative
    CURRENT value."""
    if not var:
        return False
    for n in getattr(fn, "nodes", []) or []:
        e = str(getattr(n, "expression", "") or "")
        if not e or var not in e:
            continue
        ce = e.replace(" ", "")
        for ts in ("block.timestamp", "now"):
            if f"{ts}-{var}" in ce or f"{var}-{ts}" in ce:
                return True
            # V used additively (a period) alongside a timestamp -> cooldown/expiry.
            if ts in ce and (f"{var}+" in ce or f"+{var}" in ce):
                return True
    return False


def emit_freshness_toctou_seams(
    ws: Path,
    target: Optional[Path] = None,
    max_rows: int = 2000,
    force: bool = False,
    strict: bool = False,
) -> Dict[str, Any]:
    """A17 freshness TOCTOU seams. OFF unless env/force. Fail-open, advisory."""
    acct: Dict[str, Any] = {
        "workspace": str(ws),
        "detector": "A17-freshness-toctou",
        "rows": 0,
        "disposed": 0,
        "un_disposed": 0,
        "candidates": 0,
        "freshness_producer_vars": 0,
        "covered_by_a2": 0,
        "status": "not-run",
        "degraded": False,
        "advisory": True,
        "strict": bool(strict),
        "substrate_present": False,
        "substrate_evidence": False,
    }
    out_rows: List[Dict[str, Any]] = []

    def finish() -> Dict[str, Any]:
        _strict_finalize(ws, out_rows, acct, strict)
        return _write_ft(ws, out_rows, acct)

    on = strict or force or os.environ.get(_A17_ENV, "").strip().lower() in _A17_ON
    if not on:
        acct["status"] = "off-by-default"
        return finish()

    dfs = _load("_cmts_dfs", "dataflow-slice.py")
    sp = _load("_cmts_sp", "slither_predicates.py")
    if dfs is None or sp is None or not hasattr(sp, "has_guard_in_closure"):
        acct["status"] = "0-substrate-module-absent"
        acct["degraded"] = True
        return finish()

    DEGRADED = getattr(sp, "DEGRADED", object())
    candidates = [Path(target)] if target else _pick_compile_target(dfs, ws)
    slither, err, chosen = None, None, None
    for cand in candidates:
        slither, err = dfs.load_slither_offline(Path(cand))
        if slither is not None:
            chosen = cand
            break
    acct["compile_target"] = str(chosen) if chosen else ""
    if slither is None:
        acct["status"] = "0-slither-degraded"
        acct["degraded"] = True
        acct["note"] = (err or "slither-load-failed")[:160]
        return finish()

    try:
        engine = dfs.DataFlowEngine(slither)
    except Exception as e:
        acct["status"] = "0-engine-degraded"
        acct["degraded"] = True
        acct["note"] = f"{type(e).__name__}:{str(e)[:120]}"
        return finish()

    scope = _all_functions(slither)
    writers: Dict[str, List[Any]] = {}
    readers: Dict[str, List[Any]] = {}
    try:
        statevar_sites = 0
        for var, f, c, kind in engine._contract_statevar_sites():
            statevar_sites += 1
            (writers if kind == "write" else readers).setdefault(var, []).append(f)
        acct["substrate_evidence"] = bool(acct.get("compile_target"))
        acct["accounting"] = {
            "functions_examined": len(scope),
            "statevar_sites_examined": statevar_sites,
            "candidate_vars": 0,
        }
    except Exception as e:
        acct["status"] = "0-statevar-sites-degraded"
        acct["degraded"] = True
        acct["note"] = f"{type(e).__name__}:{str(e)[:120]}"
        return finish()

    def _dedup(fns: List[Any]) -> List[Any]:
        seen, uniq = set(), []
        for f in fns:
            if id(f) in seen:
                continue
            seen.add(id(f))
            uniq.append(f)
        return uniq

    a2_sinks = _a5_load_a2_sinks(ws)
    acct["substrate_present"] = True
    candidate_vars = sorted(set(writers) & set(readers))
    acct["candidates"] = len(candidate_vars)
    seen_edge: set = set()

    for var in candidate_vars:
        ws_writers = _dedup(writers.get(var, []))
        rs_readers = _dedup(readers.get(var, []))

        # (4)+(5) FRESHNESS-VALIDATOR producers of V: a STRICT time/oracle guard
        # AND V is freshness-typed (lexicon) or oracle/timestamp-sourced.
        freshness_producers: List[Any] = []
        degraded_here = False
        for w in ws_writers:
            g = sp.has_guard_in_closure(w, guard_pred=_a17_producer_freshness_pred)
            if g is DEGRADED:
                degraded_here = True
                continue
            if bool(g) and _a17_writer_freshness_sourced(sp, w, var):
                freshness_producers.append(w)
        if degraded_here and not freshness_producers:
            acct["un_disposed"] += 1
            continue
        if not freshness_producers:
            acct["disposed"] += 1  # terminal: no freshness validator for V.
            continue
        acct["freshness_producer_vars"] += 1

        writer_ids = {id(w) for w in ws_writers}
        fired_any = False
        var_degraded = False
        for s in rs_readers:
            if id(s) in writer_ids:
                continue  # producer == consumer is not a cross-fn seam.

            # (6) CONSUMER does NOT re-validate freshness of V.
            try:
                sguards = engine._guards_for_vars(s, {var})
            except Exception:
                var_degraded = True
                continue
            if any(_a17_expr_is_freshness(g.get("expr", "")) for g in (sguards or [])):
                continue  # a direct freshness re-check -> BENIGN.
            hg = sp.has_guard_in_closure(s, guard_pred=_a17_is_freshness_guard)
            if hg is DEGRADED:
                var_degraded = True
                continue
            if bool(hg):
                continue  # closure carries a freshness re-check -> BENIGN.

            # (7) STALE-BY-DESIGN FP-guard: an elapsed-time term -> accrual/TWAP.
            if _a17_has_age_term(s, var):
                continue

            # (8) BYPASS: an unguarded (no freshness re-check) entrypoint -> S.
            paths = sp.unguarded_paths_to_sink(s, scope, guard_pred=_a17_is_freshness_guard)
            if paths is DEGRADED:
                var_degraded = True
                continue
            bypass = [p for p in paths if not p.get("guarded")]
            if not bypass:
                continue

            sfile, sline = _site_of(dfs, s, var)
            covered = (sfile, sline) in a2_sinks if sfile is not None and sline is not None else False
            for prod in freshness_producers:
                pfile, pline = _site_of(dfs, prod, var)
                for ep in bypass:
                    ep_id = _fn_id(ep.get("entrypoint"))
                    edge_key = (var, _fn_id(prod), pline, _fn_id(s), sline, ep_id)
                    if edge_key in seen_edge:
                        continue
                    seen_edge.add(edge_key)
                    if covered:
                        acct["covered_by_a2"] += 1
                    stable_id = _stable_id(
                        "a17", var, _fn_id(prod), pline, _fn_id(s), sline, ep_id
                    )
                    out_rows.append({
                        "seam_id": f"ftx-{len(out_rows):04d}",
                        "stable_id": stable_id,
                        "id": stable_id,
                        "freshness_quantity": var,
                        "validator": {"fn": _fn_id(prod), "file": pfile, "line": pline},
                        # KEEP this exact key: the enforcement-plane reader
                        # (_consolidate_a2) folds on `unguarded_consumer_sink`.
                        "unguarded_consumer_sink": {
                            "fn": _fn_id(s), "file": sfile, "line": sline,
                        },
                        "bypass_entrypoint": {
                            "fn": ep.get("name"),
                            "contract": ep.get("contract"),
                            "guarded": False,
                        },
                        "trust_edge": (
                            f"{_fn_id(prod)} validates freshness of {var} "
                            f"(time/oracle compare) -> {_fn_id(s)} consumes {var} as "
                            f"CURRENT (no freshness re-check, no age term) <- bypass "
                            f"entry {ep.get('name')}"
                        ),
                        "covered_by_a2": covered,
                        "confidence": "syntactic",
                        "verdict": "needs-fuzz",
                        "advisory": True,
                    })
                    fired_any = True
                    if len(out_rows) >= max_rows:
                        break
                if len(out_rows) >= max_rows:
                    break
            if len(out_rows) >= max_rows:
                break

        if var_degraded and not fired_any:
            acct["un_disposed"] += 1
        else:
            acct["disposed"] += 1
        if len(out_rows) >= max_rows:
            acct["truncated"] = True
            break

    acct["rows"] = len(out_rows)
    acct["dedup_distinct"] = acct["covered_by_a2"] == 0
    acct["status"] = "ok"
    acct["accounting"]["candidate_vars"] = len(candidate_vars)
    return finish()


def _write_ft(ws: Path, rows: List[Dict[str, Any]], acct: Dict[str, Any]) -> Dict[str, Any]:
    a = ws / ".auditooor"
    try:
        a.mkdir(parents=True, exist_ok=True)
        with (a / "freshness_toctou_seams.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        (a / "freshness_toctou_seams.accounting.json").write_text(
            json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return acct


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="A2 cross-module trust-boundary seam detector")
    ap.add_argument("--ws", required=True, help="workspace root (artifacts land in <ws>/.auditooor)")
    ap.add_argument("--target", default=None, help="slither compile target (file or dir); default=ws")
    ap.add_argument("--max-rows", type=int, default=2000, help="cap emitted rows")
    ap.add_argument("--mode", choices=["storage-slot", "encode-decode", "freshness"],
                    default="storage-slot",
                    help="storage-slot=A2 (default); encode-decode=A5 codec-layout seam; "
                         "freshness=A17 freshness-TOCTOU seam")
    ap.add_argument("--scan-root", default=None, help="A5: restrict the Rust scan to this dir/file")
    ap.add_argument("--force", action="store_true", help="A5/A17: run even when env is unset")
    ap.add_argument("--strict", action="store_true",
                    help="fail on missing/degraded substrate or unresolved seams")
    ap.add_argument("--print", action="store_true", help="print accounting json to stdout")
    args = ap.parse_args(argv)
    if args.mode == "encode-decode":
        acct = emit_encode_decode_seams(
            Path(args.ws),
            Path(args.scan_root) if args.scan_root else None,
            args.max_rows,
            force=args.force,
            strict=args.strict,
        )
    elif args.mode == "freshness":
        acct = emit_freshness_toctou_seams(
            Path(args.ws),
            Path(args.target) if args.target else None,
            args.max_rows,
            force=args.force,
            strict=args.strict,
        )
    else:
        acct = emit(Path(args.ws), Path(args.target) if args.target else None,
                    args.max_rows, strict=args.strict)
    if args.print:
        print(json.dumps(acct, ensure_ascii=False, indent=2))
    return 1 if args.strict and acct.get("strict_blockers") else 0


if __name__ == "__main__":
    raise SystemExit(main())
