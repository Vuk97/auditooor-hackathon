#!/usr/bin/env python3
"""capv3-iter3-T2 driver — run adversarial-copilot.py --live against each of
the 18 polymarket DROPPED drafts that parsed in iter-v3-2 T1.

Per draft, capture:
  - path
  - iter-v3-2 dry-run verdict (break / hold / skipped)   [from caller-provided map]
  - verdicts extracted by adversarial-copilot
  - counter-brief body the copilot built
  - raw dispatcher response (stdout of swarm-orchestrator --dispatch)
  - dispatch_mode ("live" | "dry-run" | "error")
  - classify_response() verdict (break / hold / skipped / error)
  - error_reason if any

Writes one JSON per draft at:
  agent_outputs/capv3_iter3_T2_live_<slug>.json

No SHIPPING. No writes to <ws>/submissions/*. Read-only over the draft corpus.
The polymarket workspace is only opened to read the swarm/manifest.json via
swarm-orchestrator.py --dispatch; no files are written there.

This driver does NOT modify adversarial-copilot.py. It imports the module and
calls its public helpers directly so we can capture dispatcher output per
draft.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
COPILOT_PATH = ROOT / "tools" / "adversarial-copilot.py"
SWARM_PATH = ROOT / "tools" / "swarm-orchestrator.py"

# Workspace + staging directory are parameterized so this driver can be run
# against any audit workspace. Resolution order (first match wins):
#   1. CLI flag (--workspace / --staging)
#   2. Env var (CAPV3_T2_WORKSPACE / CAPV3_T2_STAGING)
#   3. Fallback: ROOT.parent / "polymarket" (i.e. a sibling checkout)
def _default_workspace() -> Path:
    env = os.environ.get("CAPV3_T2_WORKSPACE")
    if env:
        return Path(env).resolve()
    return (ROOT.parent / "polymarket").resolve()


def _default_staging(ws: Path) -> Path:
    env = os.environ.get("CAPV3_T2_STAGING")
    if env:
        return Path(env).resolve()
    return (ws / "submissions" / "staging").resolve()

# The 18 drafts that parsed in iter-v3-2 T1 (i.e. 21 DROPPED minus the 3
# genuine no-verdict ones: R77-07.DROPPED.md, R77-NEW-feebips, feemodule_draft).
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

# iter-v3-2 T1 verdicts (from capv3_iter2_T1_adversarial_rerun.log) — every
# parseable draft classified `break` in dry-run (the input-echo artefact).
ITER_V3_2_DRY_RUN_VERDICT = "break"


def _load_copilot():
    spec = importlib.util.spec_from_file_location("adversarial_copilot", COPILOT_PATH)
    assert spec and spec.loader, "adversarial-copilot.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _live_on_draft(copilot, draft: Path, workspace: Path) -> Dict:
    """Run the copilot pipeline on one draft with --live semantics, but
    instrument each stage so we can persist a structured JSON record."""
    record: Dict = {
        "draft_path": str(draft),
        "iter_v3_2_dry_run_verdict": ITER_V3_2_DRY_RUN_VERDICT,
        "iter_v3_3_live_verdict": None,
        "dispatch_mode": None,
        "verdicts_extracted": [],
        "counter_brief_body": None,
        "raw_dispatcher_response": None,
        "dispatch_error": None,
        "elapsed_seconds": None,
    }
    t0 = time.time()

    try:
        text = draft.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        record["iter_v3_3_live_verdict"] = copilot.STATUS_ERROR
        record["dispatch_error"] = f"cannot read {draft}: {e}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    if copilot.is_malformed(text):
        record["iter_v3_3_live_verdict"] = copilot.STATUS_SKIPPED
        record["dispatch_error"] = f"malformed agent output: {draft}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    verdicts = copilot.extract_not_a_bug_verdicts(text)
    record["verdicts_extracted"] = list(verdicts)
    if not verdicts:
        record["iter_v3_3_live_verdict"] = copilot.STATUS_SKIPPED
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
        record["iter_v3_3_live_verdict"] = copilot.STATUS_ERROR
        record["dispatch_mode"] = "error"
        record["dispatch_error"] = f"dispatch failed: {e}"
        record["elapsed_seconds"] = round(time.time() - t0, 3)
        return record

    status = copilot.classify_response(response)
    record["iter_v3_3_live_verdict"] = status
    record["elapsed_seconds"] = round(time.time() - t0, 3)
    return record


def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="capv3-iter3-T2 adversarial --live driver over DROPPED drafts.",
    )
    p.add_argument(
        "--workspace",
        type=Path,
        default=_default_workspace(),
        help="Audit workspace root (contains submissions/staging and swarm/manifest.json). "
             "Default: $CAPV3_T2_WORKSPACE, else <repo>/../polymarket.",
    )
    p.add_argument(
        "--staging",
        type=Path,
        default=None,
        help="Drafts directory. Default: $CAPV3_T2_STAGING, else <workspace>/submissions/staging.",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "agent_outputs",
        help="Directory for per-draft JSON + run summary. Default: <repo>/agent_outputs.",
    )
    return p.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    workspace = args.workspace.resolve()
    staging = (args.staging or _default_staging(workspace)).resolve()
    out_dir = args.out_dir.resolve()

    copilot = _load_copilot()
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: List[Dict] = []
    counts = {s: 0 for s in copilot.ALLOWED_STATUSES}
    for name in DRAFTS:
        draft = staging / name
        if not draft.is_file():
            print(f"[driver] MISSING: {draft}", file=sys.stderr)
            rec = {
                "draft_path": str(draft),
                "iter_v3_2_dry_run_verdict": ITER_V3_2_DRY_RUN_VERDICT,
                "iter_v3_3_live_verdict": copilot.STATUS_ERROR,
                "dispatch_mode": "error",
                "dispatch_error": "draft file missing on disk",
            }
        else:
            rec = _live_on_draft(copilot, draft, workspace)
        slug = copilot.slug_from_path(Path(name))
        out_path = out_dir / f"capv3_iter3_T2_live_{slug}.json"
        out_path.write_text(
            json.dumps(rec, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"[driver] {rec['iter_v3_3_live_verdict']:>7s}  "
            f"{slug}  ({rec.get('elapsed_seconds','?')}s)"
        )
        counts[rec["iter_v3_3_live_verdict"]] = counts.get(
            rec["iter_v3_3_live_verdict"], 0
        ) + 1
        summary.append({
            "slug": slug,
            "path": str(draft),
            "verdict": rec["iter_v3_3_live_verdict"],
            "mode": rec.get("dispatch_mode"),
            "out": str(out_path),
        })

    # Print a final summary line with the same keys adversarial-copilot uses.
    summary_line = ", ".join(
        f"{k}={counts.get(k, 0)}" for k in sorted(copilot.ALLOWED_STATUSES)
    )
    print(f"[driver] summary: {summary_line}")

    # Also drop a run-summary JSON for the report generator.
    (out_dir / "capv3_iter3_T2_run_summary.json").write_text(
        json.dumps({"counts": counts, "drafts": summary}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
