#!/usr/bin/env python3
"""scope-oos-dispatch-guard.py - BLOCK dispatching out-of-scope units to hunters.

THE ENFORCEMENT. Driven off SCOPE.md (via tools/lib/scope_oos_globs.py), generic
across languages/chains. Given a hunt agent_batch / worklist .md (or a JSON/JSONL
list of units), it extracts each unit's file path, asks is_oos(), and FAILS CLOSED
(rc=1) if ANY unit is out of scope - unless explicitly allowed.

MOTIVATION (2026-07-05): SCOPE.md documented OOS carve-outs (Autobahn consensus
OUT, non-executor giga/ OUT except giga/executor, evmone OUT, StateSync OUT) but
the dispatch path had no scope gate, so OOS units were hunted wave after wave.

Usage:
  scope-oos-dispatch-guard.py --workspace <ws> --batch <file> [--batch <file> ...]
  scope-oos-dispatch-guard.py --workspace <ws> --units-file <units.jsonl>
  scope-oos-dispatch-guard.py --workspace <ws> --batch <file> --allow-oos

rc=1 when >=1 OOS unit found (blocked), UNLESS --allow-oos OR the override marker
<ws>/.auditooor/scope_oos_dispatch_override exists (then rc=0 + WARN). rc=0 when
no OOS unit. FAIL-OPEN: an empty/absent SCOPE.md OOS section -> no exclusions.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the shared OOS-glob library (package + direct-script fallbacks).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_oos_globs import load_oos_spec, is_oos  # type: ignore
except Exception:  # noqa: BLE001
    _HERE = Path(__file__).resolve().parent
    for cand in (_HERE / "lib", _HERE):
        if str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
    try:
        from scope_oos_globs import load_oos_spec, is_oos  # type: ignore
    except Exception as _e:  # pragma: no cover - hard failure -> fail-open
        load_oos_spec = None  # type: ignore
        is_oos = None  # type: ignore


OVERRIDE_MARKER = ".auditooor/scope_oos_dispatch_override"

_SKIP_WALK_DIRS = {
    ".git", "node_modules", "target", "build", "out", "dist", ".auditooor",
    "__pycache__", ".venv", "venv",
}
_SOURCE_EXTS = {
    ".sol", ".rs", ".go", ".vy", ".move", ".cairo", ".circom", ".nr", ".sw",
    ".fe", ".yul",
}

# A markdown/worklist unit line. We accept many shapes:
#   src/x/keeper/msg_server.go :: Foo
#   src/x/keeper/msg_server.go::Foo
#   - `src/foo.sol` :: transfer
#   msg_server.go::Foo              (bare basename -> resolve against tree)
#   {"file": "...", "function": "..."} (JSON)
_PATHY_TOKEN_RE = re.compile(
    r"[`'\"]?([A-Za-z0-9_./\\-]+\.(?:sol|rs|go|vy|move|cairo|circom|nr|sw|fe|yul))"
    r"[`'\"]?"
)


def _build_basename_index(ws: Path) -> dict:
    """Map basename -> list of POSIX relpaths for bare-name resolution."""
    idx: dict[str, list[str]] = {}
    if not ws.is_dir():
        return idx
    for root, dirs, files in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in _SKIP_WALK_DIRS
                   and not d.startswith(".")]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SOURCE_EXTS:
                continue
            full = Path(root) / fn
            try:
                rel = full.relative_to(ws).as_posix()
            except ValueError:
                continue
            idx.setdefault(fn, []).append(rel)
    return idx


def _resolve_bare(basename: str, idx: dict) -> str | None:
    hits = idx.get(basename)
    if not hits:
        return None

    def _rank(p: str) -> tuple:
        low = p.lower().split("/")
        penalty = 1 if any(s in low for s in ("test", "tests", "mock", "mocks",
                                              "legacy", "example", "examples"))\
            else 0
        return (penalty, p.count("/"), p)
    return sorted(hits, key=_rank)[0]


def _norm_rel(p: str) -> str:
    return str(p or "").strip().lstrip("./").replace("\\", "/").strip("/")


def _extract_paths_from_text(text: str, idx: dict) -> list[str]:
    """Extract candidate file relpaths (resolved) from a batch/worklist body."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _PATHY_TOKEN_RE.finditer(text):
        raw = _norm_rel(m.group(1))
        if not raw:
            continue
        # If it has a directory component, keep as-is; else resolve bare name.
        if "/" in raw:
            rel = raw
        else:
            rel = _resolve_bare(raw, idx) or raw
        if rel not in seen:
            seen.add(rel)
            out.append(rel)
    return out


def _extract_paths_from_json(obj, idx: dict) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _add(p: str):
        raw = _norm_rel(p)
        if not raw:
            return
        rel = raw if "/" in raw else (_resolve_bare(raw, idx) or raw)
        if rel not in seen:
            seen.add(rel)
            out.append(rel)

    def _walk(o):
        if isinstance(o, dict):
            for k in ("file", "path", "relpath", "source_file", "unit_path"):
                v = o.get(k)
                if isinstance(v, str):
                    _add(v)
            # unit token "file::fn" or "file::fn::file:line"
            u = o.get("unit")
            if isinstance(u, str) and "::" in u:
                _add(u.split("::", 1)[0])
            for v in o.values():
                if isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(o, list):
            for it in o:
                if isinstance(it, str) and ("::" in it or "/" in it
                                            or it.endswith(tuple(_SOURCE_EXTS))):
                    _add(it.split("::", 1)[0])
                else:
                    _walk(it)

    _walk(obj)
    return out


def _units_from_file(fpath: Path, idx: dict) -> list[str]:
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return []
    stripped = text.strip()
    # Try JSON / JSONL first.
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return _extract_paths_from_json(json.loads(stripped), idx)
        except Exception:  # noqa: BLE001
            pass
    # JSONL
    if fpath.suffix.lower() == ".jsonl" or "\n{" in stripped:
        acc: list[str] = []
        seen: set[str] = set()
        for line in stripped.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                for p in _extract_paths_from_json(json.loads(line), idx):
                    if p not in seen:
                        seen.add(p)
                        acc.append(p)
            except Exception:  # noqa: BLE001
                continue
        if acc:
            return acc
    # Fallback: markdown/plain-text path extraction.
    return _extract_paths_from_text(text, idx)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--batch", action="append", default=[],
                    help="hunt batch / worklist .md (repeatable)")
    ap.add_argument("--units-file", action="append", default=[],
                    help="JSON/JSONL list of units (repeatable)")
    ap.add_argument("--allow-oos", action="store_true",
                    help="warn instead of blocking (rc=0)")
    ap.add_argument("--json", action="store_true",
                    help="emit a JSON summary to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"[scope-oos-dispatch-guard] workspace not a dir: {ws} "
              f"(fail-open, pass)", file=sys.stderr)
        print("pass-no-oos-in-batch")
        return 0

    if load_oos_spec is None or is_oos is None:
        print("[scope-oos-dispatch-guard] scope_oos_globs unavailable "
              "(fail-open, pass)", file=sys.stderr)
        print("pass-no-oos-in-batch")
        return 0

    spec = load_oos_spec(str(ws))
    if not spec.get("exclude_globs"):
        print("[scope-oos-dispatch-guard] no OOS section in SCOPE.md "
              "(fail-open, pass)", file=sys.stderr)
        print("pass-no-oos-in-batch")
        return 0

    idx = _build_basename_index(ws)
    all_units: list[str] = []
    seen: set[str] = set()
    for f in list(args.batch) + list(args.units_file):
        fp = Path(f)
        if not fp.is_absolute():
            fp = (ws / f) if (ws / f).exists() else fp
        if not fp.exists():
            print(f"[scope-oos-dispatch-guard] batch/units file not found: {f} "
                  f"(fail-open, skip)", file=sys.stderr)
            continue
        for u in _units_from_file(fp, idx):
            if u not in seen:
                seen.add(u)
                all_units.append(u)

    oos_hits = []
    for rel in all_units:
        blocked, reason = is_oos(rel, spec, str(ws))
        if blocked:
            oos_hits.append((rel, reason))

    override_present = (ws / OVERRIDE_MARKER).exists()

    summary = {
        "workspace": str(ws),
        "units_total": len(all_units),
        "oos_count": len(oos_hits),
        "exclude_globs": spec.get("exclude_globs"),
        "include_exceptions": spec.get("include_exceptions"),
        "oos_units": [{"path": p, "reason": r} for p, r in oos_hits],
        "skipped_tokens": spec.get("skipped"),
    }

    for rel, reason in oos_hits:
        print(f"[scope-oos-dispatch-guard] OUT-OF-SCOPE unit blocked: {rel}",
              file=sys.stderr)
        print(f"    reason (SCOPE.md): {reason}", file=sys.stderr)

    if not oos_hits:
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"pass-no-oos-in-batch ({len(all_units)} units, 0 OOS)")
        return 0

    # >=1 OOS unit found.
    blocked_line = (f"SCOPE-OOS-DISPATCH-GUARD: {len(all_units)} units, "
                    f"{len(oos_hits)} OOS (blocked)")
    if args.allow_oos or override_present:
        why = "--allow-oos" if args.allow_oos else f"override marker {OVERRIDE_MARKER}"
        print(f"[scope-oos-dispatch-guard] WARN: {len(oos_hits)} OOS unit(s) "
              f"present but allowed via {why}", file=sys.stderr)
        summary["allowed_via"] = why
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(blocked_line + f" - ALLOWED via {why}")
        return 0

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(blocked_line)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
