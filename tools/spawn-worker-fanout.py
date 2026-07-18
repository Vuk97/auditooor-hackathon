#!/usr/bin/env python3
"""spawn-worker-fanout.py - fan a worklist of INDEPENDENT units into N canonical
spawn-worker lanes, one enriched prompt per unit, for CONCURRENT Agent dispatch.

WHY (operator-caught 2026-07-03, SSV per-file floor): a canonical step often
yields a worklist of N INDEPENDENT read/adjudication units - non-economic
dispositions, undriven business-flow members, unscanned mechanism cells, per-fn
hunt units. The single-thread habit is to hand all N to ONE agent that grinds
them serially. The standing directive ([[feedback_parallel_canonical_readme_no_single_thread]])
is to fan them out into N CONCURRENT canonical lanes. Nothing made that the path
of least resistance - so this composes (does NOT fork) tools/spawn-worker.sh:
it calls spawn-worker once per worklist row and collects the N enriched prompt
paths, which the orchestrator then hands to N Agent-tool calls IN ONE MESSAGE
(the harness runs same-message tool_uses concurrently).

ANTI-CLOBBER (the load-bearing design): each lane is assigned a DISTINCT
per-unit output sidecar path (`{{OUTPUT_SIDECAR}}` in the template). Parallel
lanes therefore never race on one shared JSON (the failure mode that otherwise
forces serialization). Read/adjudication lanes need no build; spawn-worker
already auto-worktree-isolates harness/PoC lane-types (spawn-worker.sh:277-287),
so even build lanes fan out safely.

NOT a hunt-planner and NOT an enrichment engine - it OWNS neither. It reuses
spawn-worker.sh verbatim for registration + META-1 enrichment + isolation; this
tool only iterates a worklist and templates a per-unit prompt.

TEMPLATE placeholders substituted per row:
  {{UNIT_JSON}}       -> compact json.dumps(row)
  {{UNIT_INDEX}}      -> 0-based row index
  {{OUTPUT_SIDECAR}}  -> the distinct per-unit sidecar path this lane must write
  {{FIELD:<key>}}     -> str(row[<key>]) for a top-level row field (empty if absent)

USAGE
  python3 tools/spawn-worker-fanout.py \
      --worklist <ws>/.auditooor/completeness_enumeration_worklist.jsonl \
      --lane-type hunt --severity HIGH --workspace <ws> \
      --lane-prefix ssv-mech --prompt-template /tmp/mech_cell.md.tmpl \
      [--filter-axis mechanism] [--max 16] [--sidecar-subdir agent_mechanism_verdicts] [--dry-run]

  -> prints one enriched-prompt path per line (hand each to a concurrent Agent call)
     + writes .auditooor/fanout_<prefix>_manifest.jsonl
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_SPAWN_WORKER = Path(__file__).resolve().parent / "spawn-worker.sh"
_ENRICHED_RE = "_enriched.md"


def _load_worklist(path: Path, filter_axis: str | None) -> list[dict]:
    rows: list[dict] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        if filter_axis and str(r.get("axis") or r.get("kind") or "") != filter_axis:
            continue
        rows.append(r)
    return rows


def _render(template: str, row: dict, index: int, out_sidecar: str) -> str:
    out = template.replace("{{UNIT_JSON}}", json.dumps(row, sort_keys=True))
    out = out.replace("{{UNIT_INDEX}}", str(index))
    out = out.replace("{{OUTPUT_SIDECAR}}", out_sidecar)
    # {{FIELD:key}} substitution
    while "{{FIELD:" in out:
        start = out.index("{{FIELD:")
        end = out.index("}}", start)
        key = out[start + len("{{FIELD:"):end]
        out = out[:start] + str(row.get(key, "")) + out[end + 2:]
    return out


def _extract_enriched_path(stdout: str) -> str | None:
    """Return a CLEAN enriched-prompt path from spawn-worker output.

    spawn-worker emits the path in two shapes: a bare stdout line
    (`/tmp/spawn_worker_<lane>_<pid>_enriched.md`) and a prefixed stderr line
    (`[spawn-worker] durable_brief=/<ws>/.auditooor/dispatch_briefs/<lane>_enriched.md`).
    Prefer a bare absolute path token ending in `_enriched.md`; strip any
    `key=path` wrapper so the returned string is a real, Agent-usable file path
    (returning the whole `[spawn-worker] durable_brief=...` line would hand a
    malformed path to the Agent call - the smoke-test bug this closes)."""
    bare: str | None = None
    prefixed: str | None = None
    for line in reversed(stdout.splitlines()):
        for tok in line.strip().split():
            if not tok.endswith(_ENRICHED_RE):
                continue
            # strip a leading `key=` wrapper (durable_brief=/path -> /path)
            path = tok.rsplit("=", 1)[-1] if "=" in tok else tok
            if not path.startswith("/"):
                continue
            if "durable_brief" in line or "dispatch_briefs" in path:
                prefixed = prefixed or path
            else:
                bare = bare or path
    return bare or prefixed


def main() -> int:
    ap = argparse.ArgumentParser(description="Fan a worklist into N concurrent spawn-worker lanes.")
    ap.add_argument("--worklist", required=True, help="JSONL worklist; one independent unit per row")
    ap.add_argument("--lane-type", required=True)
    ap.add_argument("--severity", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--lane-prefix", required=True, help="lane-id prefix; each lane is <prefix>-<i>")
    ap.add_argument("--prompt-template", required=True, help="template file with {{...}} placeholders")
    ap.add_argument("--filter-axis", default=None, help="keep only rows whose axis/kind == this")
    ap.add_argument("--sidecar-subdir", default=None,
                    help="subdir under <ws>/.auditooor for per-unit output sidecars "
                         "(default: fanout_<prefix>)")
    ap.add_argument("--max", type=int, default=16,
                    help="cap lanes (default 16, the harness concurrency ceiling); "
                         "excess rows are reported, not silently dropped")
    ap.add_argument("--tmp-dir", default="/tmp", help="where to write per-unit prompt files")
    ap.add_argument("--dry-run", action="store_true",
                    help="render per-unit prompts + manifest but do NOT call spawn-worker")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    tmpl_path = Path(args.prompt_template).expanduser()
    if not tmpl_path.is_file():
        print(f"[fanout] ERROR: template not found: {tmpl_path}", file=sys.stderr)
        return 2
    template = tmpl_path.read_text(encoding="utf-8", errors="replace")

    rows = _load_worklist(Path(args.worklist).expanduser(), args.filter_axis)
    if not rows:
        print(f"[fanout] worklist empty (or no rows match axis={args.filter_axis}); nothing to fan out",
              file=sys.stderr)
        return 0

    subdir = args.sidecar_subdir or f"fanout_{args.lane_prefix}"
    sidecar_dir = ws / ".auditooor" / subdir
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(args.tmp_dir).expanduser()

    dispatched = rows[: args.max]
    overflow = rows[args.max:]
    manifest: list[dict] = []
    enriched_paths: list[str] = []

    for i, row in enumerate(dispatched):
        lane_id = f"{args.lane_prefix}-{i}"
        out_sidecar = str(sidecar_dir / f"{args.lane_prefix}_{i}.json")
        prompt = _render(template, row, i, out_sidecar)
        prompt_file = tmp_dir / f"fanout_{args.lane_prefix}_{i}.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        rec = {
            "index": i, "lane_id": lane_id, "unit": row,
            "prompt_file": str(prompt_file), "output_sidecar": out_sidecar,
            "enriched_prompt": None,
        }
        if not args.dry_run:
            proc = subprocess.run(
                [str(_SPAWN_WORKER), "--lane-id", lane_id, "--lane-type", args.lane_type,
                 "--severity", args.severity, "--workspace", str(ws),
                 "--prompt-file", str(prompt_file)],
                capture_output=True, text=True)
            enriched = _extract_enriched_path(proc.stdout + "\n" + proc.stderr)
            rec["enriched_prompt"] = enriched
            rec["spawn_worker_rc"] = proc.returncode
            if enriched:
                enriched_paths.append(enriched)
            else:
                print(f"[fanout] WARN lane {lane_id}: no enriched path parsed (rc={proc.returncode})",
                      file=sys.stderr)
        manifest.append(rec)

    manifest_path = ws / ".auditooor" / f"fanout_{args.lane_prefix}_manifest.jsonl"
    manifest_path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in manifest), encoding="utf-8")

    # Human summary to stderr; the enriched paths to stdout (one per line) so the
    # orchestrator can hand each to a concurrent Agent call in ONE message.
    print(f"[fanout] lane_prefix={args.lane_prefix} units={len(rows)} "
          f"dispatched={len(dispatched)} overflow={len(overflow)} "
          f"sidecar_dir={sidecar_dir} manifest={manifest_path}", file=sys.stderr)
    if overflow:
        print(f"[fanout] NOTE: {len(overflow)} unit(s) over --max={args.max} NOT dispatched this "
              f"round (re-run to drain; NOT silently covered)", file=sys.stderr)
    if args.dry_run:
        print("[fanout] --dry-run: per-unit prompts written; spawn-worker NOT invoked", file=sys.stderr)
        for r in manifest:
            print(r["prompt_file"])
    else:
        print(f"[fanout] hand these {len(enriched_paths)} enriched prompt(s) to "
              f"{len(enriched_paths)} CONCURRENT Agent call(s) in ONE message:", file=sys.stderr)
        for p in enriched_paths:
            print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
