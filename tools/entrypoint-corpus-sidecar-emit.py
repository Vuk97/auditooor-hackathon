#!/usr/bin/env python3
"""entrypoint-corpus-sidecar-emit.py - make the entrypoint-corpus-bridge closes
DURABLE across an exploit_queue REBUILD by persisting them as terminal-negative
hunt sidecars that ``tools/exploit-queue-terminal-join.py`` re-applies every run.

Why this exists (the durability gap it closes)
----------------------------------------------
``tools/entrypoint-corpus-bridge.py`` proves that N corpus-INV
``blocked_missing_truth`` exploit-queue rows are safely closeable (their pinned
function is PROVABLY a non-entry-point per the AUTHORITATIVE
``go_entrypoint_surface`` classifier AND the packet carries a
``missing:permissionless_trigger`` / ``missing:attacker_actor`` marker). But the
bridge's own ``--write`` mutates ``exploit_queue.json`` directly, and
``make prove-top-leads`` REBUILDS the queue (``exploit-queue-source-mine`` ->
``source-mined-impact-contracts UPDATE_QUEUE=1``) and then re-applies terminal-join
from the persistent hunt sidecars. A direct queue write is therefore WIPED on the
next rebuild and the fully-adjudicated lead reappears as non-terminal (the classic
serving-join false-red: adjudication done, gate blind).

This tool emits ONE terminal-negative hunt sidecar PER bridge-approved close, keyed
by the row's STABLE ``lead_id`` (deterministic ``F-CORPUS-INV-<template>-<fn>`` ids
that survive the source-mine rebuild). ``exploit-queue-terminal-join`` reads those
sidecars via ``_build_refuted_leadid_index`` and re-writes
``proof_status=closed_negative`` onto exactly those rows on EVERY rebuild -> the
close is DURABLE.

FAITHFULNESS / SAFETY (this must NEVER close more than the bridge approved)
--------------------------------------------------------------------------
  * The close set is taken VERBATIM from ``entrypoint-corpus-bridge.build_plan``
    (decision == "close"): the same authoritative non-entry-point classifier, the
    same marker requirement, the same already-terminal guard. This tool adds NO new
    close logic - it only PERSISTS the bridge's verdicts in the durable shape.
  * Sidecars are LEAD-ID keyed and DELIBERATELY fn-index-inert: they carry NO
    top-level ``function`` / ``fn`` / ``function_anchor`` key, so
    ``exploit-queue-terminal-join._sidecar_refuted_fn`` returns None for them and
    the (fn, contract-stem) + fn-name-only fallback joins NEVER fire off these
    sidecars. Only the exact-lead_id join fires -> the durable close set equals the
    bridge close set EXACTLY (no marker-less / entry-point-name collateral closes).
  * An ENTRY-POINT row is never in the bridge close set, so never gets a sidecar.

Default is DRY-RUN; sidecars are written only under ``--write``.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Optional

_TOOLS = Path(__file__).resolve().parent
_SIDECAR_SUBDIR = ("hunt_findings_sidecars",)
_SCHEMA = "auditooor.entrypoint_corpus_terminal_negative.v1"
_FNAME_SANITIZE = re.compile(r"[^A-Za-z0-9._-]+")


def _load_bridge():
    spec = importlib.util.spec_from_file_location(
        "entrypoint_corpus_bridge", str(_TOOLS / "entrypoint-corpus-bridge.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["entrypoint_corpus_bridge"] = mod
    spec.loader.exec_module(mod)
    return mod


def _decl_file_line(ws: Path, contract: Optional[str], fn: str) -> str:
    """Return ``<contract>:L<lineno>`` for the first ``func ... fn(`` declaration
    (R76-passing cite). Falls back to ``<contract>:L1`` if the line cannot be
    pinpointed but the file exists; returns "" only when there is no usable path."""
    if not contract:
        return ""
    fpath = ws / contract
    if not fpath.is_file():
        return f"{contract}:L1"
    pat = re.compile(r"func\b.*\b" + re.escape(fn) + r"\s*\(")
    try:
        for i, line in enumerate(fpath.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                return f"{contract}:L{i}"
    except OSError:
        pass
    return f"{contract}:L1"


def _sidecar_filename(lead_id: str) -> str:
    return "entrypoint_corpus__" + _FNAME_SANITIZE.sub("_", str(lead_id)) + ".json"


def build_sidecars(ws: Path, marker: str = "") -> list[dict]:
    """Build (but do not write) one terminal-negative sidecar per bridge close."""
    B = _load_bridge()
    plan = B.build_plan(ws)
    closes = [d for d in plan.get("decisions", []) if d.get("decision") == "close"]
    out: list[dict] = []
    for d in closes:
        lead_id = d.get("lead_id")
        fn = d.get("function") or ""
        contract = d.get("source_ref") or d.get("contract")
        file_line = _decl_file_line(ws, contract, fn) or f"{contract}:L1"
        out.append(
            {
                "schema": _SCHEMA,
                "producer": "entrypoint-corpus-sidecar-emit.py",
                # --- lead-id join key (the ONLY join key these sidecars activate) ---
                "lead_id": lead_id,
                "candidate_id": lead_id,
                # --- refuted-verdict signal read by _sidecar_refuted_leadid ---
                "verdict": "refuted",
                "applies_to_target": "no",
                "file_line": file_line,
                "notes": d.get("reason"),
                # --- record-only metadata (NOT top-level function/fn/function_anchor,
                #     so the (fn, contract-stem) fn-index join stays inert) ---
                "entrypoint_corpus": {
                    "function": fn,
                    "entry_point": False,
                    "classifier": "go_entrypoint_surface.is_go_entry_point",
                    "source_ref": contract,
                    "rationale": d.get("reason"),
                },
                "joined_at_marker": marker or "unset",
            }
        )
    return out


def emit(ws: Path, marker: str = "", write: bool = False) -> dict:
    ws = ws.expanduser().resolve()
    sidecars = build_sidecars(ws, marker=marker)
    outdir = ws.joinpath(".auditooor", *_SIDECAR_SUBDIR)
    written = 0
    if write:
        outdir.mkdir(parents=True, exist_ok=True)
        for sc in sidecars:
            fpath = outdir / _sidecar_filename(sc["lead_id"])
            fpath.write_text(json.dumps(sc, indent=1), encoding="utf-8")
            written += 1
    return {
        "schema": "auditooor.entrypoint_corpus_sidecar_emit.v1",
        "workspace": str(ws),
        "sidecar_dir": str(outdir),
        "would_emit": len(sidecars),
        "written": written if write else 0,
        "applied": bool(write),
        "sample": sidecars[0] if sidecars else None,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--workspace", required=True, help="workspace path")
    ap.add_argument("--marker", default="", help="context_pack marker to stamp on sidecars")
    ap.add_argument("--write", action="store_true", help="write sidecars (default: dry-run)")
    ap.add_argument("--json", action="store_true", help="emit the result as JSON")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[entrypoint-corpus-sidecar-emit] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    res = emit(ws, marker=args.marker, write=args.write)
    if args.json:
        print(json.dumps(res, indent=1))
    else:
        print("=" * 72)
        print("entrypoint-corpus-sidecar-emit  " + ("(--write APPLIED)" if args.write else "(DRY-RUN)"))
        print("=" * 72)
        print(f"workspace   : {res['workspace']}")
        print(f"sidecar dir : {res['sidecar_dir']}")
        print(f"would-emit  : {res['would_emit']}  (one terminal-negative sidecar per bridge close)")
        print(f"written     : {res['written']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
