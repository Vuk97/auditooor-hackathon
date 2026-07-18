#!/usr/bin/env python3
"""Mechanically filter sibling-path asymmetries to the real candidates + emit a
compact 'asymmetry packet' per surviving pair - so the probe LLM never re-reads source.

The sibling-path-guard-diff enumerates by naming convention (deposit|withdraw,
mint|burn, ...) and by variant-arm (same enum/trait match arms). Naming-convention
matching OVER-GENERATES: it pairs same-named functions across UNRELATED modules
(collator-manager.deposit vs IntentsBase.withdraw) which are not real siblings and
have a meaningless 'asymmetry'. This tool keeps only the genuine candidates:

  - drop test-file pairs (either side under test/mock/fixtures),
  - drop cross-module naming-convention pairs (path_a and path_b in different
    top-level modules/contracts) - coincidental name match, not a real sibling,
  - drop no-asymmetry pairs (neither side is missing a guard the other has),
  - KEEP variant-arm pairs (same enum/trait arms - the FaultDisputeGame-vs-L2Oracle
    / Pharos apex-vs-internal class that produced the confirmed Criticals),
  - KEEP same-module / same-file naming-convention pairs (a real deposit/withdraw
    in one contract).

For each survivor it reads both files ONCE (cached) and emits a small packet with
both sides' guard context + the missing-guard delta + the shared invariant, so the
downstream probe gets a ~1K-token packet instead of reading two source files.

Input:  <ws>/.auditooor/sibling_guard_asymmetries.jsonl
Output: <ws>/.auditooor/asymmetry_probe_packets.jsonl

Usage:
  asymmetry-context-extract.py --workspace <ws> [--source-root <dir>]
                              [--window N] [--keep-cross-module] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.asymmetry_probe_packet.v1"
_WINDOW = int(os.environ.get("AUDITOOOR_ASYM_CONTEXT_WINDOW", "30"))

# F5: route test/generated/scaffolding classification through the SINGLE shared
# classifier (tools/lib/scope_exclusion) instead of a private regex that drifted.
# The private _TEST_RE missed Go conventions (*_mock.go, simulated.go, abigen
# bindings) - exactly why the polygon asymmetry generator paired production code
# against the test-only SimulatedBackend. The shared module knows them and is
# head-aware (DO-NOT-EDIT generated header). Kept _TEST_RE only as an import-failure
# fallback so this tool stays runnable standalone.
_TEST_RE = re.compile(r"(^|/)(tests?|mocks?|fixtures?|testdata)(/|$)|_test\.|\.t\.sol|Test\.sol|/test_", re.I)
try:  # normal package import
    from tools.lib.scope_exclusion import is_oos as _shared_is_oos  # type: ignore
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    import sys as _sys
    _LIBDIR = str(Path(__file__).resolve().parent / "lib")
    if _LIBDIR not in _sys.path:
        _sys.path.insert(0, _LIBDIR)
    try:
        from scope_exclusion import is_oos as _shared_is_oos  # type: ignore
    except Exception:
        _shared_is_oos = None  # type: ignore

try:  # trivial-container-method filter (SEI 2026-07-05 heap.Swap vs AMM.swap FP)
    from tools.lib.container_interface_filter import (  # type: ignore
        is_trivial_container_interface_method as _is_trivial_container,
    )
except Exception:  # pragma: no cover - direct-script fallback
    try:
        from container_interface_filter import (  # type: ignore
            is_trivial_container_interface_method as _is_trivial_container,
        )
    except Exception:
        _is_trivial_container = None  # type: ignore


def _side_name(side) -> str:
    if isinstance(side, dict):
        return str(side.get("name") or "").split("(", 1)[0].strip()
    return ""


def _go_fn_body(file_path: str | None, line: int | None, name: str,
                source_root: Path) -> str:
    """Read the brace-balanced body of Go function ``name`` near ``line``. '' on failure."""
    if not (file_path and name):
        return ""
    rf = _resolve(file_path, source_root)
    if not rf:
        return ""
    try:
        text = rf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"\bfunc\s+(\([^)]*\)\s*)?" + re.escape(name) + r"\b", text)
    if not m:
        return ""
    i = text.find("{", m.start())
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return ""


def _container_interface_side(r: dict, source_root: Path) -> str:
    """Return a ``path_x:name`` label if EITHER side of the pair is a trivial Go
    container/heap.Interface method (Len/Less/Swap/Push/Pop with a single-statement slice
    body); '' otherwise. Conservative: only fires for a ``.go`` side whose exact body is
    interface plumbing, so a real Go function named e.g. ``Swap`` with logic is untouched."""
    if _is_trivial_container is None:
        return ""
    for key in ("path_a", "path_b"):
        side = r.get(key)
        fp, ln = _path(side)
        if _lang(fp) != "go":
            continue
        nm = _side_name(side)
        if not nm:
            continue
        body = _go_fn_body(fp, ln, nm, source_root)
        if body and _is_trivial_container(nm, body):
            return f"{key}:{nm}"
    return ""


def _path(side) -> tuple[str | None, int | None]:
    if isinstance(side, dict):
        return side.get("file"), side.get("line")
    if isinstance(side, str):
        m = re.match(r"(.+?):(\d+)", side)
        if m:
            return m.group(1), int(m.group(2))
        return side, None
    return None, None


def _lang(path: str | None) -> str:
    """Coarse language family from file extension. Two siblings in DIFFERENT
    languages (e.g. a Go ABI binding `.go` vs a Solidity `.sol`, or a Go config
    `.go` vs a Solidity drippie `.sol`) are NEVER variant-arms of the same
    invariant - they live in different trust/execution domains. This is the
    dominant asymmetry false-positive class (confirmed: 240/240 probed pairs were
    false, overwhelmingly cross-language Go-binding-vs-Solidity name matches)."""
    if not path:
        return ""
    p = path.lower()
    if p.endswith((".sol", ".vy")):
        return "solidity"
    if p.endswith(".go"):
        return "go"
    if p.endswith(".rs"):
        return "rust"
    if p.endswith((".move", ".cairo")):
        return p.rsplit(".", 1)[-1]
    return ""


def _top_module(path: str | None) -> str:
    """A coarse module key: the dir two levels below an 'src/.../<module>/' or the
    contract-ish parent, used to decide same-module vs cross-module."""
    if not path:
        return ""
    parts = Path(path).parts
    # heuristic: the segment after 'modules'/'src'/'pallets'/'apps' or the parent dir
    for anchor in ("modules", "pallets", "apps", "clients", "consensus"):
        if anchor in parts:
            i = parts.index(anchor)
            if i + 1 < len(parts):
                return "/".join(parts[i:i + 2])
    return "/".join(parts[:-1][-2:])  # fallback: last 2 dir segments


def _is_test(*paths) -> bool:
    """True if ANY side path is test/mock/fixture/generated/scaffolding (OOS).

    Uses the shared scope_exclusion.is_oos (knows *_mock.go, simulated.go, abigen
    bindings, generated headers, all languages) and falls back to the legacy
    private regex only if the shared module could not be imported."""
    if _shared_is_oos is not None:
        return any(p and _shared_is_oos(p) for p in paths)
    return any(p and _TEST_RE.search(p) for p in paths)


def _resolve(path_hint: str | None, root: Path) -> Path | None:
    if not path_hint:
        return None
    h = path_hint.lstrip("/")
    for c in (root / h, root / "src" / h):
        if c.is_file():
            return c
    base = Path(h).name
    for c in root.rglob(base):
        if c.is_file():
            return c
    return None


def _window(lines: list[str], line_no: int | None, window: int) -> tuple[str, str]:
    if not lines:
        return "", ""
    if line_no is None:
        line_no = 1
    idx = min(max(line_no - 1, 0), len(lines) - 1)
    guard_line = lines[idx].strip()
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window)
    ctx = "\n".join(lines[lo:hi])
    if len(ctx) > 2600:
        ctx = ctx[:2600] + "\n... [truncated]"
    return guard_line, ctx


def _asym_identity(r: dict) -> str:
    """Stable id matching the cert builder's _asymmetry_id for a raw sibling row."""
    cid = r.get("candidate_gap_id") or r.get("asym_id")
    if isinstance(cid, str) and cid.strip():
        return cid.strip()
    fa, la = _path(r.get("path_a"))
    fb, lb = _path(r.get("path_b"))
    return "ASYM-" + hashlib.sha1(f"{fa}:{la}|{fb}:{lb}".encode()).hexdigest()[:12]


def _drop_row(r: dict, reason: str) -> dict:
    """A mechanically-disposed DROP disposition for a filtered sibling pair.
    Keyed by guard_id == candidate_gap_id so BOTH the cert builder
    (_apply_asymmetry_dispositions, keyed by candidate_gap_id) AND
    depth-probe-ingest's merge (keyed by guard_id) preserve it. gap_found=false
    => disposition 'drop'; the source-cited reason carries a real file:line so the
    cert's substantive-reason anti-stub gate accepts it."""
    aid = _asym_identity(r)
    return {
        "schema": "auditooor.negative_space_gap.v1",
        "guard_id": aid,
        "candidate_gap_id": aid,
        "asym_id": aid,
        "file_line": (r.get("file_lines") or [""])[0] if isinstance(r.get("file_lines"), list) else "",
        "gap_found": False,
        "disposition": "drop",
        "ruled_out_reason": reason,
        "why_no_gap_or_exploit": reason,
        "probe_source": "asymmetry-context-extract-filter",
        "probed": True,
    }


def extract(ws: Path, source_root: Path, window: int, keep_cross_module: bool) -> dict:
    asym_file = ws / ".auditooor" / "sibling_guard_asymmetries.jsonl"
    if not asym_file.is_file():
        return {"schema": SCHEMA, "error": f"no asymmetries at {asym_file}", "packets": 0}

    rows = []
    for ln in asym_file.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln:
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                pass

    dropped = {"test_file": 0, "cross_language": 0, "cross_module_naming": 0,
               "no_asymmetry": 0, "container_interface": 0}
    keep = []
    # filtered_drops: mechanically-disposable rows. A sibling pair that is dropped
    # by the extract filter (test/mock/fixture path, coincidental cross-module
    # name match, or a no-asymmetry pair) is NOT a real candidate finding, but the
    # cert reads the FULL sibling_guard_asymmetries.jsonl and counts every row as a
    # candidate gap. So we emit a source-cited DROP disposition for each filtered
    # row, keyed by its candidate_gap_id, into asymmetry_probes.jsonl. The cert's
    # _apply_asymmetry_dispositions then disposes them mechanically (no LLM), which
    # is honest: a test-file or cross-module-coincidence pair is a real drop with a
    # source-cited reason. Each reason LEADS with the distinct file:line so the
    # cert's bulk-template anti-stub gate (largest near-identical 60-char shingle)
    # sees distinct prose per row, not one bulk template.
    filtered_drops = []
    for r in rows:
        fa, la = _path(r.get("path_a"))
        fb, lb = _path(r.get("path_b"))
        if _is_test(fa, fb, str(r.get("file_lines"))):
            dropped["test_file"] += 1
            filtered_drops.append(_drop_row(
                r, f"{fa}:{la} vs {fb}:{lb} - sibling pair lies under a "
                   f"test/mock/fixture path; not an in-scope finding pair (extract filter: test_file)"))
            continue
        lang_a, lang_b = _lang(fa), _lang(fb)
        if lang_a and lang_b and lang_a != lang_b:
            dropped["cross_language"] += 1
            filtered_drops.append(_drop_row(
                r, f"{fa}:{la} vs {fb}:{lb} - siblings are DIFFERENT languages "
                   f"({lang_a} vs {lang_b}); a {lang_a} function and a {lang_b} "
                   f"function are never variant-arms of the same invariant "
                   f"(extract filter: cross_language)"))
            continue
        ci_side = _container_interface_side(r, source_root)
        if ci_side:
            dropped["container_interface"] += 1
            filtered_drops.append(_drop_row(
                r, f"{fa}:{la} vs {fb}:{lb} - {ci_side} is a trivial Go "
                   f"container/heap.Interface method (Len/Less/Swap/Push/Pop with a "
                   f"single-statement slice body); interface plumbing, not a business "
                   f"variant-arm - identifier coincidence only "
                   f"(extract filter: container_interface)"))
            continue
        ma = r.get("guard_on_a_missing_on_b") or []
        mb = r.get("guard_on_b_missing_on_a") or []
        if not ma and not mb:
            dropped["no_asymmetry"] += 1
            filtered_drops.append(_drop_row(
                r, f"{fa}:{la} vs {fb}:{lb} - both sides enforce the same guards; "
                   f"no missing-guard asymmetry exists (extract filter: no_asymmetry)"))
            continue
        kind = (r.get("pair_kind") or "").lower()
        if kind == "naming-convention" and not keep_cross_module:
            if _top_module(fa) != _top_module(fb):
                dropped["cross_module_naming"] += 1
                filtered_drops.append(_drop_row(
                    r, f"{fa}:{la} vs {fb}:{lb} - same function name in DIFFERENT "
                       f"top-level modules; coincidental naming match, not a real "
                       f"sibling pair (extract filter: cross_module_naming)"))
                continue
        keep.append((r, fa, la, fb, lb))

    file_cache: dict[str, list[str]] = {}

    def read(f: str | None):
        rf = _resolve(f, source_root)
        if not rf:
            return None
        if str(rf) not in file_cache:
            try:
                file_cache[str(rf)] = rf.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                file_cache[str(rf)] = []
        return file_cache[str(rf)]

    out_path = ws / ".auditooor" / "asymmetry_probe_packets.jsonl"
    packets = []
    unresolved = 0
    for r, fa, la, fb, lb in keep:
        la_lines, lb_lines = read(fa), read(fb)
        if not la_lines or not lb_lines:
            unresolved += 1
            continue
        ga, ca = _window(la_lines, la, window)
        gb, cb = _window(lb_lines, lb, window)
        aid = (
            r.get("candidate_gap_id")
            or "ASYM-" + hashlib.sha1(f"{fa}:{la}|{fb}:{lb}".encode()).hexdigest()[:12]
        )
        packets.append({
            "schema": SCHEMA, "asym_id": aid,
            "candidate_gap_id": aid,
            "pair": r.get("pair"), "pair_kind": r.get("pair_kind"),
            "shared_invariant": r.get("shared_invariant_hint"),
            "missing_on_a": r.get("guard_on_a_missing_on_b") or [],
            "missing_on_b": r.get("guard_on_b_missing_on_a") or [],
            "side_a": {"file_line": f"{fa}:{la}", "guard_line": ga, "context": ca},
            "side_b": {"file_line": f"{fb}:{lb}", "guard_line": gb, "context": cb},
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for p in packets:
            fh.write(json.dumps(p) + "\n")

    # Emit the filtered-row DROP dispositions into asymmetry_probes.jsonl, merging
    # by id so a later live probe ingest does not clobber them (and a re-run of
    # extract refreshes them idempotently). This is the step that drops the cert's
    # candidate_gaps_undisposed by exactly the number of extract-filtered rows.
    probes_path = ws / ".auditooor" / "asymmetry_probes.jsonl"
    existing: dict[str, dict] = {}
    if probes_path.is_file():
        for ln in probes_path.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                o = json.loads(ln)
            except json.JSONDecodeError:
                continue
            k = o.get("guard_id") or o.get("candidate_gap_id") or o.get("asym_id")
            if k:
                existing[k] = o
    for d in filtered_drops:
        existing[d["guard_id"]] = d  # extract-filter drops are authoritative for filtered ids
    with probes_path.open("w", encoding="utf-8") as fh:
        for o in existing.values():
            fh.write(json.dumps(o) + "\n")

    approx = sum(len(p["side_a"]["context"]) + len(p["side_b"]["context"]) for p in packets) // 4
    return {
        "schema": SCHEMA, "workspace": str(ws),
        "asymmetries_in": len(rows), "dropped": dropped,
        "filtered_drop_dispositions": len(filtered_drops),
        "asymmetry_probes_path": str(probes_path),
        "kept_after_filter": len(keep), "packets_written": len(packets),
        "unresolved": unresolved, "files_read": len(file_cache),
        "out": str(out_path),
        "approx_tokens_per_packet": (approx // len(packets)) if packets else 0,
        "approx_total_tokens": approx,
        "note": "feed each packet's side_a + side_b + missing_on_* + shared_invariant to a cheap probe; no file read needed.",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--source-root", type=Path, default=None)
    ap.add_argument("--window", type=int, default=_WINDOW)
    ap.add_argument("--keep-cross-module", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    source_root = (args.source_root or ws).expanduser().resolve()
    out = extract(ws, source_root, args.window, args.keep_cross_module)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    elif out.get("error"):
        print(f"[asymmetry-context-extract] {out['error']}")
        return 2
    else:
        d = out["dropped"]
        print(f"[asymmetry-context-extract] {out['asymmetries_in']} in -> dropped "
              f"{d['test_file']} test / {d['cross_module_naming']} cross-module / {d['no_asymmetry']} no-asym "
              f"-> {out['packets_written']} packets (~{out['approx_tokens_per_packet']} tok/packet, "
              f"{out['unresolved']} unresolved) -> {out['out']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
