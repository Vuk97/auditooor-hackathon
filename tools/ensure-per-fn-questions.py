#!/usr/bin/env python3
"""ensure-per-fn-questions.py - materialize <ws>/.auditooor/per_fn_hacker_questions.jsonl.

The scoped per-function hacker-question hunt (README step-3) CONSUMES
``<ws>/.auditooor/per_fn_hacker_questions.jsonl``. Its producer chain
(invariant-auto-synth.py -> per-function-hacker-questions.py) was an ORPHAN: it was never
wired into the canonical audit-deep pipeline, and the standalone make targets default their
output to ``reports/``, NOT ``.auditooor/``. So every workspace finished audit-deep WITHOUT
the worklist, ``make hunt-scoped`` SILENTLY fell back to the blunt N=2007 generic-corpus
mode, and the readme-step-integrity ``scoped-hunt`` gate stayed SKIPPED forever (the
"keep missing stuff" failure mode - NUVA 2026-06-30).

This wrapper closes the gap GENERICALLY (any language / workspace):
  1. Idempotent: if the canonical file already has rows, do nothing (unless --force).
  2. Else run the producer chain and LAND the result at the canonical path:
       invariant-auto-synth.py  --workspace <ws> --output <tmp-inv>
       per-function-hacker-questions.py --invariants <tmp-inv> --workspace <ws>
           --output <ws>/.auditooor/per_fn_hacker_questions.jsonl
     ``--max-files`` is raised so large workspaces are not truncated (NUVA 512 .sol).
  3. LOUD on failure: if it genuinely cannot produce (no invariants / no in-scope units),
     write ``<ws>/.auditooor/per_fn_questions_generation_defect.json`` and exit non-zero so
     the loop SEES the defect instead of a silent corpus-mode degrade.

Exit codes: 0 = file present (pre-existing or freshly generated); 1 = could not generate
(defect marker written); 2 = bad args.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
CANON_REL = Path(".auditooor") / "per_fn_hacker_questions.jsonl"
RANKED_REL = Path(".auditooor") / "per_fn_hacker_questions.jsonl.ranked.jsonl"
DEFECT_REL = Path(".auditooor") / "per_fn_questions_generation_defect.json"
SCHEMA = "auditooor.ensure_per_fn_questions.v1"


def _count_rows(p: Path) -> int:
    if not p.is_file():
        return 0
    n = 0
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip():
                n += 1
    except OSError:
        return 0
    return n


def _run(cmd: list[str], log_prefix: str) -> tuple[int, str]:
    """Run a subprocess, streaming nothing; return (rc, tail_of_stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return 124, f"{log_prefix}: timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, f"{log_prefix}: {exc}"
    tail = "\n".join((proc.stderr or "").splitlines()[-4:])
    return proc.returncode, tail


def _write_defect(ws: Path, reason: str, stages: list[dict]) -> None:
    defect = ws / DEFECT_REL
    defect.parent.mkdir(parents=True, exist_ok=True)
    defect.write_text(json.dumps({
        "schema": SCHEMA,
        "verdict": "defect-cannot-generate-per-fn-questions",
        "reason": reason,
        "stages": stages,
        "remediation": (
            "Per-fn hunt worklist could not be auto-built. Check invariant-auto-synth "
            "(needs in-scope source) + per-function-hacker-questions on this workspace. "
            "Until fixed, hunt-scoped runs in blunt N=2007 corpus mode (NOT scoped)."
        ),
    }, indent=2), encoding="utf-8")


def _ensure_ranked(ws: Path, out: Path, *, force: bool) -> dict:
    """Produce the PRIORITY-RANKED worklist <out>.ranked.jsonl that hunt-scoped prefers,
    so the hunt dispatches value-moving / prime-core entrypoints FIRST and drops generated
    /OOS noise (e.g. *.pb.go protobuf stubs). Orphaned producer (per-fn-question-ranker.py)
    was never wired in, so the hunt ran in arbitrary GENERATION order, burying the crown
    jewels (NUVA 2026-06-30: DepositorFactory factories ran before DedicatedVaultRouter
    $4.6M core). Non-fatal: on any failure the hunt falls back to the unranked base."""
    ranked = ws / RANKED_REL
    if _count_rows(ranked) > 0 and not force:
        return {"stage": "rank", "verdict": "exists", "rows": _count_rows(ranked)}
    base_rows = _count_rows(out)
    # --top-n high enough that ranking ORDERS the full set; the ranker's internal
    # surface-score filter (OOS/upstream/generated -> negative) decides the final set.
    rc, err = _run([
        sys.executable, str(TOOLS / "per-fn-question-ranker.py"),
        "--questions", str(out), "--workspace", str(ws),
        "--output", str(ranked), "--top-n", str(max(base_rows, 1)), "--json",
    ], "per-fn-question-ranker")
    return {"stage": "rank", "rc": rc, "rows": _count_rows(ranked), "stderr_tail": err}


def ensure(ws: Path, *, force: bool, max_files: int) -> tuple[int, dict]:
    out = ws / CANON_REL
    pre = _count_rows(out)
    if pre > 0 and not force:
        # Base exists; still make sure the priority-ranked worklist is materialized.
        rank = _ensure_ranked(ws, out, force=force)
        return 0, {"verdict": "exists", "rows": pre, "path": str(out),
                   "ranked_rows": rank.get("rows"), "rank": rank}

    out.parent.mkdir(parents=True, exist_ok=True)
    stages: list[dict] = []

    # Stage 1: synthesize invariants from the workspace's in-scope source.
    inv = Path(tempfile.gettempdir()) / f"per_fn_inv_{ws.name}.jsonl"
    rc1, err1 = _run([
        sys.executable, str(TOOLS / "invariant-auto-synth.py"),
        "--workspace", str(ws), "--output", str(inv),
        "--max-files", str(max_files), "--json",
    ], "invariant-auto-synth")
    inv_rows = _count_rows(inv)
    stages.append({"stage": "invariant-auto-synth", "rc": rc1, "rows": inv_rows, "stderr_tail": err1})
    if inv_rows == 0:
        _write_defect(ws, "invariant-auto-synth produced 0 invariants (no in-scope source?)", stages)
        return 1, {"verdict": "defect", "stages": stages}

    # Stage 2: emit per-function hacker questions, LANDED at the canonical path.
    rc2, err2 = _run([
        sys.executable, str(TOOLS / "per-function-hacker-questions.py"),
        "--invariants", str(inv), "--workspace", str(ws),
        "--output", str(out), "--json",
    ], "per-function-hacker-questions")
    post = _count_rows(out)
    stages.append({"stage": "per-function-hacker-questions", "rc": rc2, "rows": post, "stderr_tail": err2})
    if post == 0:
        _write_defect(ws, "per-function-hacker-questions produced 0 questions", stages)
        return 1, {"verdict": "defect", "stages": stages}

    # Stage 3: priority-rank so the hunt dispatches the crown jewels first.
    rank = _ensure_ranked(ws, out, force=True)
    stages.append(rank)
    return 0, {"verdict": "generated", "rows": post, "path": str(out),
               "invariants": inv_rows, "ranked_rows": rank.get("rows"), "stages": stages}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--force", action="store_true", help="regenerate even if the file exists")
    ap.add_argument("--max-files", type=int, default=1000,
                    help="invariant-synth file cap (raised so large ws are not truncated)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(json.dumps({"schema": SCHEMA, "verdict": "error",
                          "error": f"workspace not found: {ws}"}))
        return 2

    rc, payload = ensure(ws, force=args.force, max_files=args.max_files)
    payload["schema"] = SCHEMA
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        v = payload.get("verdict")
        if v in ("exists", "generated"):
            sys.stderr.write(f"[ensure-per-fn-questions] {v}: {payload.get('rows')} rows -> {payload.get('path')}\n")
        else:
            sys.stderr.write(f"[ensure-per-fn-questions] DEFECT: could not generate per-fn worklist "
                             f"(defect marker written); hunt-scoped will run BLUNT corpus mode\n")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
