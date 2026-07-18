#!/usr/bin/env python3
"""haiku-fanout-dispatcher.py - Haiku-via-Agent-tool batch dispatcher.

r36-rebuttal: lane bug-fix-and-haiku-2026-05-28 pathspec-registered

WHY THIS EXISTS:
  MIMO mining is blocked (KEY5 rate-limit). Operator uses Anthropic via the
  paid Claude Code sub — no `ANTHROPIC_API_KEY` set in shell. The
  `claude` headless CLI requires API-key auth in `--bare` mode and
  OAuth-tokens-via-keychain otherwise; neither works from arbitrary
  subprocess context.

  Pattern that DOES work: the orchestrator Claude session (you) calls the
  Agent tool with `model: "haiku"` to dispatch a subagent. Each subagent
  uses the operator's paid sub through OAuth seamlessly. See task #249
  ("CAP-83: enrich remaining 3913 Solodit MED records via Haiku Agent
  dispatches") + task #250 for the proven precedent.

  This tool BATCHES a mining task-list (mimo-harness-batch-gen.py output
  shape) into Agent-dispatch-ready prompt files. The orchestrator then
  invokes Agent(model=haiku) on each prompt file. Each subagent emits
  per-task sidecars in the same format as MIMO so the existing
  mimo-corpus-miner.py + brain-prime + downstream tooling consume them
  unchanged.

RELATED TOOLS (read these BEFORE building anything overlapping):
  - tools/llm-fanout-dispatcher.py: HTTP-API-based dispatcher
    (deepseek-flash / deepseek-pro / mimo). Requires API key. THIS tool
    is the Agent-tool-via-OAuth alternative for Haiku.
  - tools/mimo-harness-batch-gen.py: produces the input task-list this
    tool batches. Output schema unchanged.
  - tools/mimo-corpus-miner.py: consumes per-task sidecars this tool's
    Haiku subagents produce. Same sidecar shape as MIMO.

USAGE (operator drives):
  1. Generate task batch (same as MIMO flow):
     python3 tools/mimo-harness-batch-gen.py \\
       --workspace-name <ws> --workspace-path <path> \\
       --num-questions 100 --lane-id <id> \\
       --output /tmp/haiku_batch_<ws>.jsonl

  2. Plan Haiku dispatch (this tool):
     python3 tools/haiku-fanout-dispatcher.py plan \\
       --task-batch /tmp/haiku_batch_<ws>.jsonl \\
       --output-dir audit/corpus_tags/derived/haiku_harness_<ws> \\
       --batch-size 25

  3. Orchestrator consumes the plan: invokes Agent(model=haiku,
     prompt_file=plan/agent_batch_NNN.md) for each batch. Each agent
     processes ~25 questions and writes per-task sidecars to
     `--output-dir/<task_id>.json`.

  4. After all batches complete, run normal learning loop:
     python3 tools/mimo-corpus-miner.py --workspace <ws>

USAGE (single-batch verify mode):
  python3 tools/haiku-fanout-dispatcher.py emit-batch \\
    --task-batch /tmp/haiku_batch.jsonl \\
    --batch-index 0 --batch-size 25 > /tmp/agent_batch_0.md

Schema: auditooor.haiku_fanout_dispatcher.v1
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.haiku_fanout_dispatcher.v1"

# Relative path from this file to dispatch-agent-with-prebriefing.py.
_DISPATCH_PREBRIEFING_PY = Path(__file__).resolve().parent / "dispatch-agent-with-prebriefing.py"

# Marker emitted by dispatch-agent-with-prebriefing.py that confirms the
# guard/harness context block was successfully injected.
PREBRIEFING_BEGIN_MARKER = "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->"


def _fetch_prebriefing_block(workspace_path: str) -> str:
    """Call dispatch-agent-with-prebriefing.py --skeleton-only for one workspace.

    Returns the META-1 Section 15 block as a string, or an empty string on
    any failure (graceful degradation - the batch prompt is still usable, just
    without the enriched guard/harness context).

    r36-rebuttal: lane haiku-fanout-prebriefing-wiring registered.
    """
    if not _DISPATCH_PREBRIEFING_PY.is_file():
        return ""
    if not workspace_path:
        return ""
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(_DISPATCH_PREBRIEFING_PY),
                "--skeleton-only",
                "--workspace", workspace_path,
                "--lane-type", "hunt",
                "--severity", "HIGH",
                "--no-infer",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    block = result.stdout.strip()
    if not block:
        return ""
    return block + "\n\n"


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_tasks(p: Path) -> list[dict]:
    tasks = []
    with p.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                tasks.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return tasks


_MODEL_IDS = {"sonnet": "claude-sonnet-5", "haiku": "claude-haiku-4-5", "opus": "claude-opus-4-8"}


def _sidecar_slug(task: dict, task_id: str) -> str:
    """Stable, collision-free sidecar filename derived from the task's FUNCTION
    IDENTITY (file basename + fn), not the sequential task_id (which the batch
    builder restarts at 00000 each run, causing cross-wave overwrites). Falls back
    to the task_id when no anchor is available. Sanitized to a safe filename."""
    import re as _re
    import hashlib as _hashlib
    anchor = task.get("function_anchor")
    if isinstance(anchor, str):
        try:
            anchor = json.loads(anchor)
        except (ValueError, TypeError):
            anchor = None
    # (unit x FRAME) key: when a task carries an impact/frame, the sidecar must be
    # frame-DISTINCT so a freeze-frame hunt of a function does NOT overwrite its
    # theft-frame hunt (the strata MIN_SHARES near-miss: latest-wins clobbered the
    # other impact's verdict). ADDITIVE + backward-compatible: a task with no impact
    # field yields the exact legacy slug (no regression). The frame is appended LAST.
    _impact = ""
    if isinstance(anchor, dict):
        _impact = str(anchor.get("impact") or anchor.get("impact_frame") or "")
    _impact = _impact or str(task.get("impact") or task.get("impact_frame") or "")
    _impact = _re.sub(r"[^A-Za-z0-9_-]+", "-", _impact).strip("-_").lower()[:40]
    full = ""
    base = ""
    fn = ""
    line = 0
    if isinstance(anchor, dict):
        full = str(anchor.get("file") or "").replace("\\", "/")
        base = full.rsplit("/", 1)[-1] if full else ""
        fn = str(anchor.get("fn") or anchor.get("function") or "").split("(", 1)[0]
        try:
            line = int(anchor.get("start_line") or anchor.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
    base = _re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("._")
    fn = _re.sub(r"[^A-Za-z0-9_]", "_", fn).strip("_")
    parts = [p for p in ("hunt", base, fn) if p]
    slug = "__".join(parts)
    if not base and not fn:
        # no usable anchor - keep the task_id so the sidecar is still written, but
        # note these CAN collide across waves; anchored tasks (the norm) do not.
        return (_re.sub(r"[^A-Za-z0-9_.-]", "_", str(task_id)).strip("._") or "hunt_task")[:180]
    # Disambiguate same-basename-same-fn units that live in DIFFERENT directories
    # (e.g. several `lib.rs::new` across crates would all collapse to the same slug
    # and clobber one another WITHIN a wave). Append a short hash of the FULL file
    # path: same function (same path) -> same hash -> correct overwrite on re-hunt;
    # different path -> different hash -> distinct file.
    if full:
        h = _hashlib.sha1(full.encode("utf-8", "replace")).hexdigest()[:8]
        slug = f"{slug[:150]}__{h}"
    # Include the decl line LAST so OVERLOADED / multi-impl same-name functions in
    # the SAME file (e.g. participants()/threshold() on two structs, three `new`
    # impls in recent_blocks_tracker.rs) each get a distinct sidecar instead of
    # clobbering one another. The function-coverage denominator is per-instance, so
    # a file::name-only slug left every same-name sibling permanently untouched
    # (near-intents 2026-06-26: 16 such instances).
    if line > 0:
        slug = f"{slug}__L{line}"
    elif fn and fn != fn.lower():
        # Case-insensitive filesystems (macOS APFS, Windows NTFS default) collapse
        # two same-file functions that differ ONLY by case (Go's exported GetVault
        # vs unexported getVault) to the SAME physical sidecar file - the second
        # write silently overwrites the first, losing its coverage credit (NUVA
        # 2026-07-03: getVault clobbered by GetVault). When NO decl line is available
        # to disambiguate (the __L branch above already separates them when it is),
        # append a short hash of the EXACT-CASE fn so the two paths differ by more
        # than case. Lowercase-only fns cannot case-collide, so they are untouched
        # (slug stays byte-identical to the legacy scheme - no mass re-name).
        _cf = _hashlib.sha1(fn.encode("utf-8", "replace")).hexdigest()[:4]
        slug = f"{slug}__f{_cf}"
    # Frame suffix LAST: (file,fn,path,line) is the unit; impact is the frame. A task
    # with no impact leaves the slug byte-identical to the legacy scheme.
    if _impact:
        slug = f"{slug[:180]}__I-{_impact}"
    return slug[:210]


def build_agent_prompt(
    batch_tasks: list[dict],
    output_dir: Path,
    batch_idx: int,
    model: str = "sonnet",
    prebriefing_block: str = "",
) -> str:
    """Build a single Agent-tool prompt that processes N tasks -> N sidecars.

    When ``prebriefing_block`` is supplied (non-empty string containing the
    META-1 Section 15 block from dispatch-agent-with-prebriefing.py), it is
    prepended BEFORE the TASKS section so every subagent receives:
      - Section 15a/15b/15c/15d R-rule mandates + skeleton templates
      - Section 15r present-guard inventory (R57 defense-chain enumeration)
      - Section 15k per-function hunter brief (LIFT-28)
      - Section 15s full-audit pipeline results
      - Section 15l/15m/15n OOS / exploit-queue / lane-verdict-bus context
      - Rule 78/81/82 mandate blocks

    The block is produced by:
      python3 tools/dispatch-agent-with-prebriefing.py --skeleton-only
        --workspace <ws> --lane-type hunt --severity HIGH --no-infer

    r36-rebuttal: lane haiku-fanout-prebriefing-wiring registered.
    """
    _model_id = _MODEL_IDS.get(model, "claude-sonnet-4-5")
    task_lines = []
    for i, t in enumerate(batch_tasks):
        task_lines.append(f"### Task {i+1}: {t.get('task_id', '?')}\n")
        task_lines.append(f"**workspace**: {t.get('workspace', '?')}\n")
        task_lines.append(f"**source_question_id**: {t.get('source_question_id', '?')}\n")
        task_lines.append(f"**function_anchor**: {json.dumps(t.get('function_anchor', {}))}\n")
        task_lines.append(f"**prompt body** (read carefully):\n")
        task_lines.append("```\n")
        task_lines.append(t.get("prompt", "")[:8000])
        task_lines.append("\n```\n\n")
        # Sidecars MUST land in the workspace dir the hunt-coverage gate scans
        # (`<ws>/.auditooor/hunt_findings_sidecars/`), NOT the tmp prompt output
        # dir. Writing them under `output_dir` (a /tmp location) orphaned 80
        # genuine wave-A sidecars outside the gate's scan roots on near-intents
        # 2026-06-26 - they credited 0 units until hand-copied. Use the task's
        # own workspace_path so the gate reads them on the next run.
        #
        # FILENAME = function identity, NOT the sequential task_id. The batch
        # builder restarts task_id numbering at 00000 each run, so naming the
        # sidecar `inscope_hunt_00010.json` makes wave N+1 OVERWRITE wave N's
        # same-indexed (but different-function) sidecar - regressing already-hunted
        # units back to queued_not_scanned (near-intents 2026-06-26: an FC wave
        # clobbered 42 wave-B sidecars). A function-identity slug is stable across
        # waves (different fns -> different files) while a genuine re-hunt of the
        # SAME function correctly overwrites its own file (latest verdict wins).
        _task_id = t.get("task_id", f"unknown_{i}")
        _slug = _sidecar_slug(t, _task_id)
        _ws_path = str(t.get("workspace_path") or "").strip()
        if _ws_path:
            _sidecar_dest = f"{_ws_path}/.auditooor/hunt_findings_sidecars/{_slug}.json"
        else:
            _sidecar_dest = f"{output_dir}/{_slug}.json"
        task_lines.append(f"**write sidecar to**: `{_sidecar_dest}`\n\n")
        task_lines.append("---\n\n")

    prebriefing_section = prebriefing_block if prebriefing_block else ""
    return f"""<!-- r64-rebuttal: {model} batch dispatch via Agent tool; task prompts pre-built by haiku-fanout-dispatcher.py -->
<!-- hacker-mcp-rebuttal: batch mining lane; tasks pre-enriched in task-batch file -->

{prebriefing_section}You are a {model.capitalize()} subagent processing batch {batch_idx} ({len(batch_tasks)} tasks)
of an auditooor mining wave. For EACH task below, execute the prompt body
and write a per-task sidecar to the specified path.

EACH SIDECAR MUST be a JSON object with this exact shape (mirrors MIMO format):

```json
{{
  "task_id": "<from task definition>",
  "workspace": "<from task definition>",
  "workspace_path": "<from task definition>",
  "source_question_id": "<from task definition>",
  "function_anchor": "<from task definition>",
  "task_type": "workspace_hunt_harnessed",
  "provider": "{model}-via-agent",
  "model_id": "{_model_id}",
  "status": "ok",
  "started_at_utc": "<iso8601>",
  "ended_at_utc": "<iso8601>",
  "duration_s": <float>,
  "cost_usd": 0.0,
  "input_tokens": 0,
  "output_tokens": 0,
  "retries": 0,
  "error": null,
  "verification_tier": "tier-3-synthetic-taxonomy-anchored",
  "result": "<verbatim JSON STRING returned by your reasoning, see task prompt for required JSON keys>"
}}
```

CRITICAL RULES:
- The `result` field is a STRING containing JSON-encoded verdict (NOT a parsed object).
  This matches the MIMO sidecar shape so downstream miner tools work unchanged.
- The task id in the sidecar MUST exactly equal the task id in that task heading;
  do not derive, renumber, or omit it. The sidecar filename is not a substitute
  for the `task_id` field because downstream joins use the field.
- For each task's prompt, follow its STRICT JSON output requirements.
  The verdict requires keys: applies_to_target, confidence,
  candidate_finding, file_path_hint, severity_estimate, rubric_row_cited,
  dupe_check, falsification_attempt, novel_angle_score, chain_with, notes,
  AND (MANDATORY for coverage credit) file_line, code_excerpt.
- file_line + code_excerpt are REQUIRED on EVERY verdict, including a clean
  rule-out (applies_to_target='no'). file_line = the exact "<relative/path.sol>:<N>"
  you read and based the verdict on (the guard/require/branch that rules the attack
  out, or the value-moving line you confirmed safe). code_excerpt = the 1-3 real
  source lines you read at that file_line, VERBATIM. WHY: function-coverage-completeness
  credits an applies_to_target='no' rule-out as genuine per-function coverage ONLY when
  it carries a same-file file_line cite (bare prose stays hollow - R80), and the R76
  hallucination guard greps your code_excerpt against the real tree. A verdict with no
  file_line/code_excerpt is dropped to hollow (uncredited) even though you did the work -
  so omitting them silently wastes the hunt and leaves the function permanently hollow.
- DO NOT execute any tools other than Read (to verify cited file:line)
  and Bash (rg / grep for source verification).
- DO NOT modify any source files or create staging drafts.
- DO NOT commit anything.
- If a prompt asks for source verification, USE Read/Bash to grep the workspace.
  This is the R76 hallucination guard built into your behavior.
- Write each sidecar atomically. If the runtime has no Write tool (including the
  Codex CLI), use a short Python or shell writer that writes a temporary file in
  the same directory, validates it with `python3 -m json.tool`, and then uses
  `os.replace`/`mv` to publish it. Never use `apply_patch` to edit JSON content,
  never append to a sidecar, and never leave a partially written file. A failed
  JSON validation is a failed task, not a completed sidecar.
- Preserve the exact outer JSON shape above and JSON-encode `result` exactly once.

After all tasks done, return ONLY:
1. Count of sidecars written (should equal {len(batch_tasks)})
2. Count of `applies_to_target=yes` verdicts
3. Count of `applies_to_target=maybe` verdicts
4. Any task that FAILED to complete (with reason)

---

# TASKS ({len(batch_tasks)} total)

{''.join(task_lines)}

---

OUTPUT (when done): YES_COUNT=<n>, MAYBE_COUNT=<n>, NO_COUNT=<n>, FAILED=[<list>], SIDECARS_WRITTEN=<n>
"""


def plan(args):
    """Build a plan directory of Agent-ready prompts."""
    tasks = load_tasks(args.task_batch)
    if not tasks:
        print(f"[haiku-dispatcher] no tasks loaded from {args.task_batch}", file=sys.stderr)
        return 2
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    plan_dir = output_dir / "_haiku_plan"
    plan_dir.mkdir(parents=True, exist_ok=True)

    batch_size = args.batch_size
    n_batches = (len(tasks) + batch_size - 1) // batch_size

    # Pre-fetch prebriefing blocks per unique workspace_path so each batch
    # agent sees the full guard/harness context (Sections 15a-d/15k/15r/15s/
    # 15l/15m/15n + Rule 78/81/82 mandates). One subprocess call per unique
    # workspace; cached here to avoid N*batches calls.
    # r36-rebuttal: lane haiku-fanout-prebriefing-wiring registered.
    unique_workspaces: set[str] = set()
    for t in tasks:
        ws = str(t.get("workspace_path") or t.get("workspace") or "").strip()
        if ws:
            unique_workspaces.add(ws)
    prebriefing_blocks: dict[str, str] = {}
    for ws in unique_workspaces:
        block = _fetch_prebriefing_block(ws)
        if block:
            prebriefing_blocks[ws] = block
            print(
                f"[haiku-dispatcher] prebriefing fetched for workspace "
                f"{ws} ({len(block)} chars)",
                file=sys.stderr,
            )
        else:
            print(
                f"[haiku-dispatcher] WARN: prebriefing unavailable for "
                f"workspace {ws} (degraded gracefully - batch has no META-1 "
                f"block; run dispatch-agent-with-prebriefing.py manually to "
                f"diagnose)",
                file=sys.stderr,
            )

    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "task_batch_input": str(args.task_batch),
        "output_dir": str(output_dir),
        "plan_dir": str(plan_dir),
        "total_tasks": len(tasks),
        "batch_size": batch_size,
        "n_batches": n_batches,
        "batches": [],
    }

    for i in range(n_batches):
        batch = tasks[i * batch_size:(i + 1) * batch_size]
        # Determine the workspace for this batch (first task wins; batches are
        # workspace-homogeneous when produced by mimo-harness-batch-gen.py).
        batch_ws = ""
        for t in batch:
            ws = str(t.get("workspace_path") or t.get("workspace") or "").strip()
            if ws:
                batch_ws = ws
                break
        prebriefing = prebriefing_blocks.get(batch_ws, "")
        prompt = build_agent_prompt(batch, output_dir, i, args.model, prebriefing)
        prompt_path = plan_dir / f"agent_batch_{i:04d}.md"
        prompt_path.write_text(prompt)
        manifest["batches"].append({
            "batch_index": i,
            "prompt_path": str(prompt_path),
            "task_count": len(batch),
            "task_ids": [t.get("task_id") for t in batch],
            "prebriefing_status": "real" if prebriefing else "unavailable",
        })

    manifest_path = plan_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"[haiku-dispatcher] PLAN ready:")
    print(f"  total tasks: {len(tasks)}")
    print(f"  batch size:  {batch_size}")
    print(f"  n batches:   {n_batches}")
    print(f"  plan dir:    {plan_dir}")
    print(f"  manifest:    {manifest_path}")
    print()
    print(f"Next step: operator (or orchestrator Claude session) invokes Agent")
    print(f"tool with model='{args.model}' for each prompt in {plan_dir}/:")
    print(f"  Agent(subagent_type='general-purpose', model='{args.model}',")
    print(f"        prompt='Read {plan_dir}/agent_batch_0000.md and execute',")
    print(f"        run_in_background=True)")
    print()
    print(f"After all batches complete, run downstream learning loop:")
    print(f"  python3 tools/mimo-corpus-miner.py --workspace <ws>")
    if args.json:
        print()
        print(json.dumps(manifest, indent=2))
    return 0


def emit_batch(args):
    """Emit a single batch prompt to stdout (for shell pipelines / verification)."""
    tasks = load_tasks(args.task_batch)
    start = args.batch_index * args.batch_size
    end = start + args.batch_size
    batch = tasks[start:end]
    if not batch:
        print(f"[haiku-dispatcher] batch {args.batch_index} empty "
              f"(start={start}, end={end}, total={len(tasks)})", file=sys.stderr)
        return 2
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    # Fetch prebriefing block for the first task's workspace.
    batch_ws = ""
    for t in batch:
        ws = str(t.get("workspace_path") or t.get("workspace") or "").strip()
        if ws:
            batch_ws = ws
            break
    prebriefing = _fetch_prebriefing_block(batch_ws) if batch_ws else ""
    prompt = build_agent_prompt(batch, output_dir, args.batch_index, args.model, prebriefing)
    print(prompt)
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="Build Agent-ready batch prompts")
    p_plan.add_argument("--task-batch", required=True, type=Path)
    p_plan.add_argument("--output-dir", required=True)
    p_plan.add_argument("--batch-size", type=int, default=25,
                        help="Tasks per Agent dispatch (default 25)")
    p_plan.add_argument("--model", default="sonnet", choices=["sonnet","haiku","opus"],
                        help="Dispatch model (default sonnet; haiku is low-signal/hallucination-prone for per-fn hunts)")
    p_plan.add_argument("--json", action="store_true")

    p_emit = sub.add_parser("emit-batch", help="Emit single batch prompt to stdout")
    p_emit.add_argument("--task-batch", required=True, type=Path)
    p_emit.add_argument("--output-dir", required=True)
    p_emit.add_argument("--batch-index", type=int, default=0)
    p_emit.add_argument("--batch-size", type=int, default=25)
    p_emit.add_argument("--model", default="sonnet", choices=["sonnet","haiku","opus"])

    args = p.parse_args(argv)
    if args.cmd == "plan":
        return plan(args)
    elif args.cmd == "emit-batch":
        return emit_batch(args)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
