#!/usr/bin/env python3
"""differential-test-runner — compare two source trees (e.g. an upstream
library pin vs an audit-target's vendored fork) and surface behavioral
divergences function-by-function.

Why this exists
---------------
Upstream-fork-divergence is a documented high-yield bug class for app-chain
and cross-client audits (anchor: dYdX cantina-018 cometbft fork-lag — the
pinned fork lacked v0.38.22 silently-shipped blocksync hardening). The
existing fork tooling answers *which dependency* diverged:
  - tools/cargo-fork-ancestry-check.py / tools/gomod-fork-ancestry-check.py
    (which git-pinned dep is ahead/behind crates.io / proxy.golang.org)
  - tools/fork-divergence-template.py (Markdown filing skeleton)
This tool answers the next question: *which functions* diverged and *is the
divergence security-relevant*. It does NOT re-implement a parser — it imports
tools/function-signature-extractor.py for per-function records (name,
signature, guards_detected, calls_made, body line span).

Divergence classification (per function present in BOTH trees, or only one):
  - "added"               — function exists only in tree B (the fork)
  - "removed"             — function exists only in tree A (upstream)
  - "identical"           — same signature, same guard set, same calls
  - "cosmetic"            — signature/guards/calls identical; only line span
                            or whitespace-level body differs (refactor)
  - "behavior-changing"   — calls_made set differs OR signature differs
  - "security-relevant"   — guards_detected differs. A guard present upstream
                            but missing in the fork (or vice-versa) is the
                            highest-value class: a check that was added/removed
                            and did not propagate. This is the finding signal.

The "upstream guard dropped in fork" direction is flagged with the strongest
verdict because it is the classic missing-guard finding (Rule 30 / L30
missing-guard-callsite discipline applies downstream).

CLI
---
    python3 tools/audit/differential-test-runner.py \
        --upstream <path/to/upstream-tree> \
        --fork <path/to/fork-tree> \
        --language {go,solidity} \
        [--out report.json] [--strict] [--audit-pin SHA]

Output: an `auditooor.differential_report.v1` JSON artifact (stdout or --out).

Exit codes:
    0 = analysis succeeded, no security-relevant divergence
    1 = error (bad path, extractor import failure)
    2 = security-relevant divergence found (only with --strict)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.differential_report.v1"

_TOOLS_DIR = Path(__file__).resolve().parent.parent  # .../tools


# ---------------------------------------------------------------------------
# Reuse the existing extractor (do NOT write a new parser).
# ---------------------------------------------------------------------------
def _load_extractor():
    """Import tools/function-signature-extractor.py as a module.

    The filename has hyphens so it is not importable by name; load by path.
    """
    ext_path = _TOOLS_DIR / "function-signature-extractor.py"
    if not ext_path.is_file():
        raise RuntimeError(f"extractor not found: {ext_path}")
    spec = importlib.util.spec_from_file_location("_fn_sig_extractor", ext_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load extractor spec: {ext_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _extract_tree(extractor, root: Path, language: str) -> Dict[str, Dict[str, Any]]:
    """Return {function_key: record} for every function in `root`.

    function_key = "<receiver_type>.<function_name>" so overloaded / same-name
    functions on different receivers do not collide. Falls back to
    "<file_path>::<function_name>" when a same key would otherwise clash.
    """
    if language == "solidity":
        file_iter = extractor.iter_sol_files(root)
        do_extract = extractor.extract_solidity_functions
    else:
        file_iter = extractor.iter_go_files(root)
        do_extract = extractor.extract_go_functions

    out: Dict[str, Dict[str, Any]] = {}
    for fp in file_iter:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = str(fp)
        for rec in do_extract(text, rel):
            recv = rec.get("receiver_type") or ""
            name = rec.get("function_name") or "?"
            key = f"{recv}.{name}" if recv else name
            if key in out:
                # disambiguate by file path on collision
                key = f"{rel}::{recv}.{name}" if recv else f"{rel}::{name}"
            out[key] = rec
    return out


# ---------------------------------------------------------------------------
# Divergence classification
# ---------------------------------------------------------------------------
def _norm_sig(rec: Dict[str, Any]) -> str:
    """Whitespace-normalised signature for cosmetic-vs-behavior discrimination."""
    sig = rec.get("function_signature") or ""
    return " ".join(sig.split())


def _classify(up: Dict[str, Any], fk: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Classify the divergence between an upstream record and a fork record.

    Returns (verdict, detail).
    """
    up_guards = set(up.get("guards_detected") or [])
    fk_guards = set(fk.get("guards_detected") or [])
    up_calls = set(up.get("calls_made") or [])
    fk_calls = set(fk.get("calls_made") or [])
    up_sig = _norm_sig(up)
    fk_sig = _norm_sig(fk)

    guards_only_upstream = sorted(up_guards - fk_guards)
    guards_only_fork = sorted(fk_guards - up_guards)
    calls_only_upstream = sorted(up_calls - fk_calls)
    calls_only_fork = sorted(fk_calls - up_calls)
    sig_changed = up_sig != fk_sig

    detail: Dict[str, Any] = {
        "guards_dropped_in_fork": guards_only_upstream,
        "guards_added_in_fork": guards_only_fork,
        "calls_only_upstream": calls_only_upstream,
        "calls_only_fork": calls_only_fork,
        "signature_changed": sig_changed,
        "upstream_signature": up_sig,
        "fork_signature": fk_sig,
    }

    # Highest-value class: a guard present upstream but missing in the fork.
    # Direction matters — dropped-in-fork is the classic missing-guard finding.
    if guards_only_upstream:
        return "security-relevant", detail
    # A guard the fork added but upstream lacks is also security-relevant
    # (fork-specific divergence; may be a fork bug or a fork hardening).
    if guards_only_fork:
        return "security-relevant", detail
    # No guard delta. Behaviour-changing if calls or signature differ.
    if sig_changed or calls_only_upstream or calls_only_fork:
        return "behavior-changing", detail
    # Same signature, same guards, same calls. Body may still differ in
    # whitespace / line span — that is cosmetic / a pure refactor.
    up_span = up.get("line_end", 0) - up.get("line_start", 0)
    fk_span = fk.get("line_end", 0) - fk.get("line_start", 0)
    if up_span != fk_span:
        return "cosmetic", detail
    return "identical", detail


def _rank(verdict: str) -> int:
    return {
        "security-relevant": 0,
        "behavior-changing": 1,
        "added": 2,
        "removed": 2,
        "cosmetic": 3,
        "identical": 4,
    }.get(verdict, 5)


def build_report(
    extractor,
    upstream: Path,
    fork: Path,
    language: str,
    audit_pin: Optional[str],
) -> Dict[str, Any]:
    up_funcs = _extract_tree(extractor, upstream, language)
    fk_funcs = _extract_tree(extractor, fork, language)

    all_keys = sorted(set(up_funcs) | set(fk_funcs))
    divergences: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {
        "identical": 0, "cosmetic": 0, "behavior-changing": 0,
        "security-relevant": 0, "added": 0, "removed": 0,
    }

    for key in all_keys:
        up = up_funcs.get(key)
        fk = fk_funcs.get(key)
        if up and not fk:
            verdict, detail = "removed", {
                "note": "function present upstream, absent in fork",
            }
            loc = {"upstream": f"{up['file_path']}:{up['line_start']}"}
        elif fk and not up:
            verdict, detail = "added", {
                "note": "function present in fork, absent upstream",
            }
            loc = {"fork": f"{fk['file_path']}:{fk['line_start']}"}
        else:
            verdict, detail = _classify(up, fk)  # type: ignore[arg-type]
            loc = {
                "upstream": f"{up['file_path']}:{up['line_start']}",  # type: ignore[index]
                "fork": f"{fk['file_path']}:{fk['line_start']}",  # type: ignore[index]
            }
        counts[verdict] = counts.get(verdict, 0) + 1
        # identical functions are not interesting noise; keep them out of the
        # divergence list but count them.
        if verdict == "identical":
            continue
        divergences.append({
            "function_key": key,
            "verdict": verdict,
            "location": loc,
            "detail": detail,
        })

    # security-relevant first, then behavior-changing, then the rest.
    divergences.sort(key=lambda d: (_rank(d["verdict"]), d["function_key"]))

    sec = [d for d in divergences if d["verdict"] == "security-relevant"]
    return {
        "schema": SCHEMA,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "language": language,
        "audit_pin": audit_pin,
        "inputs": {
            "upstream_tree": str(upstream),
            "fork_tree": str(fork),
        },
        "summary": {
            "upstream_functions": len(up_funcs),
            "fork_functions": len(fk_funcs),
            "counts": counts,
            "security_relevant_count": len(sec),
            "top_finding_keys": [d["function_key"] for d in sec[:10]],
        },
        "divergences": divergences,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--upstream", required=True, help="Path to upstream/reference source tree")
    p.add_argument("--fork", required=True, help="Path to fork/audit-target source tree")
    p.add_argument("--language", default="go", choices=["go", "solidity"])
    p.add_argument("--out", help="Output JSON path. Default: stdout.")
    p.add_argument("--audit-pin", help="Optional audit-pin SHA for the fork tree.")
    p.add_argument("--strict", action="store_true",
                   help="Exit 2 when any security-relevant divergence is found.")
    args = p.parse_args(argv)

    up = Path(args.upstream).resolve()
    fk = Path(args.fork).resolve()
    if not up.is_dir():
        print(f"not a directory: {up}", file=sys.stderr)
        return 1
    if not fk.is_dir():
        print(f"not a directory: {fk}", file=sys.stderr)
        return 1

    try:
        extractor = _load_extractor()
    except Exception as exc:  # pragma: no cover - import guard
        print(f"failed to load function-signature-extractor: {exc}", file=sys.stderr)
        return 1

    report = build_report(extractor, up, fk, args.language, args.audit_pin)

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    s = report["summary"]
    print(
        f"differential: upstream={s['upstream_functions']}fn "
        f"fork={s['fork_functions']}fn "
        f"security-relevant={s['security_relevant_count']} "
        f"behavior-changing={s['counts'].get('behavior-changing', 0)} "
        f"cosmetic={s['counts'].get('cosmetic', 0)} "
        f"added={s['counts'].get('added', 0)} removed={s['counts'].get('removed', 0)}",
        file=sys.stderr,
    )
    if args.strict and s["security_relevant_count"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
