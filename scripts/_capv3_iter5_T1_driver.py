#!/usr/bin/env python3
"""capv3-iter5-T1 driver — re-run adversarial-copilot.py --live against the
18 polymarket DROPPED drafts, this time with `SWARM_REAL_DISPATCH=1` so
`swarm-orchestrator.py --dispatch` shells out to `tools/llm-dispatch.py`.

Per-draft JSON artefacts land at:
  agent_outputs/capv3_iter5_T1_live_<slug>.json

If `ANTHROPIC_API_KEY` is unset, each record is flagged as
`cannot-run: no-api-key`. Plumbing ships either way. Does NOT modify
`tools/adversarial-copilot.py`.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
COPILOT_PATH = ROOT / "tools" / "adversarial-copilot.py"
SWARM_PATH = ROOT / "tools" / "swarm-orchestrator.py"

DRAFTS = [
    "R83-A.notes.md",
    "R83-B.notes.md",
    "R83-C.notes.md",
    "R83-D.notes.md",
    "R83-E.notes.md",
    "R84-F.notes.md",
    "R84-G.notes.md",
    "R84-H.notes.md",
    "R85-A.notes.md",
    "R85-B.notes.md",
    "R85-C.notes.md",
    "R87-H1-authorize-upgrade-onlyProxy.notes.md",
    "R87-H2-reinitializer-drift.notes.md",
    "R87-H3-storage-collision.notes.md",
    "R87-H4-vault-drift-on-upgrade.notes.md",
    "R87-H5-init-frontrun.notes.md",
    "R87-Y-negrisk-operator-state-machine.notes.md",
    "R87-Z-vault.notes.md",
]

ITER_V3_3_PRIOR_VERDICT = "skipped"  # from iter-v3-3 T2 results (printer stdout)


def _load_copilot():
    spec = importlib.util.spec_from_file_location("adversarial_copilot", COPILOT_PATH)
    assert spec and spec.loader, "adversarial-copilot.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _live_on_draft(copilot, draft: Path, workspace: Path) -> Dict:
    record: Dict = {
        "draft_path": str(draft),
        "iter_v3_3_printer_verdict": ITER_V3_3_PRIOR_VERDICT,
        "iter_v3_5_live_verdict": None,
        "dispatch_mode": None,
        "verdicts_extracted": [],
        "counter_brief_body": None,
        "raw_dispatcher_response": None,
        "dispatch_error": None,
        "cannot_run_reason": None,
        "swarm_real_dispatch_env": os.environ.get("SWARM_REAL_DISPATCH"),
        "anthropic_api_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "elapsed_seconds": None,
    }
    t0 = time.time()

    try:
        text = draft.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        record["iter_v3_5_live_verdict"] = copilot.STATUS_ERROR
        record["dispatch_error"] = f"cannot read {draft}: {e}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    if copilot.is_malformed(text):
        record["iter_v3_5_live_verdict"] = copilot.STATUS_SKIPPED
        record["dispatch_error"] = f"malformed agent output: {draft}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    verdicts = copilot.extract_not_a_bug_verdicts(text)
    record["verdicts_extracted"] = list(verdicts)
    if not verdicts:
        record["iter_v3_5_live_verdict"] = copilot.STATUS_SKIPPED
        record["dispatch_error"] = f"no NOT-A-BUG verdicts in {draft}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    brief = copilot.build_counter_brief(draft, verdicts)
    record["counter_brief_body"] = brief

    try:
        response, mode = copilot.dispatch_counter_brief(
            workspace,
            brief,
            live=True,
            swarm_tool=SWARM_PATH,
        )
        record["raw_dispatcher_response"] = response
        record["dispatch_mode"] = mode
    except Exception as e:
        record["iter_v3_5_live_verdict"] = copilot.STATUS_ERROR
        record["dispatch_mode"] = "error"
        record["dispatch_error"] = f"dispatch failed: {e}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        # If the failure was caused by missing key, reflect it explicitly.
        if not os.environ.get("ANTHROPIC_API_KEY"):
            record["cannot_run_reason"] = "cannot-run: no-api-key"
        return record

    # Honest cannot-run accounting: in SWARM_REAL_DISPATCH=1 mode, an empty
    # response with stderr cannot-run:no-api-key is the plumbing-ships signal.
    if not response.strip() and not os.environ.get("ANTHROPIC_API_KEY"):
        record["cannot_run_reason"] = "cannot-run: no-api-key"

    status = copilot.classify_response(response)
    record["iter_v3_5_live_verdict"] = status
    record["elapsed_seconds"] = round(time.time() - t0, 3)
    return record


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Minimal arg parsing: workspace + staging + out via env only.
    workspace = Path(os.environ.get(
        "CAPV3_T1_WORKSPACE", str((ROOT.parent / "polymarket").resolve())
    )).resolve()
    staging = Path(os.environ.get(
        "CAPV3_T1_STAGING", str((workspace / "submissions" / "staging").resolve())
    )).resolve()
    out_dir = Path(os.environ.get(
        "CAPV3_T1_OUT_DIR", str((ROOT / "agent_outputs").resolve())
    )).resolve()

    copilot = _load_copilot()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Enforce SWARM_REAL_DISPATCH=1 for this driver.
    os.environ["SWARM_REAL_DISPATCH"] = "1"

    summary: List[Dict] = []
    counts = {s: 0 for s in copilot.ALLOWED_STATUSES}
    cannot_run_count = 0
    for name in DRAFTS:
        draft = staging / name
        if not draft.is_file():
            print(f"[driver] MISSING: {draft}", file=sys.stderr)
            rec = {
                "draft_path": str(draft),
                "iter_v3_3_printer_verdict": ITER_V3_3_PRIOR_VERDICT,
                "iter_v3_5_live_verdict": copilot.STATUS_ERROR,
                "dispatch_mode": "error",
                "dispatch_error": "draft file missing on disk",
                "cannot_run_reason": None,
                "anthropic_api_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "swarm_real_dispatch_env": os.environ.get("SWARM_REAL_DISPATCH"),
            }
            # If the staging directory doesn't exist at all, that's a
            # plumbing gap. Plug it as cannot-run so honest-zero shows.
            if not staging.is_dir() and not os.environ.get("ANTHROPIC_API_KEY"):
                rec["cannot_run_reason"] = "cannot-run: no-api-key"
        else:
            rec = _live_on_draft(copilot, draft, workspace)
        slug = copilot.slug_from_path(Path(name))
        out_path = out_dir / f"capv3_iter5_T1_live_{slug}.json"
        out_path.write_text(
            json.dumps(rec, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        v = rec["iter_v3_5_live_verdict"]
        print(
            f"[driver] {v:>7s}  {slug}  "
            f"({rec.get('elapsed_seconds','?')}s)  "
            f"cannot_run={rec.get('cannot_run_reason') or '-'}"
        )
        if v in counts:
            counts[v] += 1
        if rec.get("cannot_run_reason"):
            cannot_run_count += 1
        summary.append({
            "slug": slug,
            "path": str(draft),
            "verdict": v,
            "mode": rec.get("dispatch_mode"),
            "out": str(out_path),
            "cannot_run": rec.get("cannot_run_reason"),
        })

    summary_line = ", ".join(
        f"{k}={counts.get(k, 0)}" for k in sorted(copilot.ALLOWED_STATUSES)
    )
    print(f"[driver] summary: {summary_line}  cannot_run={cannot_run_count}")

    (out_dir / "capv3_iter5_T1_run_summary.json").write_text(
        json.dumps(
            {
                "counts": counts,
                "cannot_run": cannot_run_count,
                "drafts": summary,
                "anthropic_api_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "swarm_real_dispatch_env": os.environ.get("SWARM_REAL_DISPATCH"),
            },
            indent=2, ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
