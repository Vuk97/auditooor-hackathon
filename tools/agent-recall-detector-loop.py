#!/usr/bin/env python3
"""agent-recall-detector-loop.py — 5-stage orchestrator for the agent-recall → detector pipeline.

Stage flow (per ROADMAP item #9, docs/MCP_HARNESS_REVIEW_2026-05-09_FINAL.md row 136):
  1. agent-recall-detector-queue.py   — build/refresh the advisory recall queue
  2. memory-next-loop-dispatcher.py   — consume the detector-recall queue, emit briefs
  3. Brief materialisation             — write detector-authoring briefs to agent_briefs/
  4. Fixture skeleton seeding          — optionally create empty fixture stubs
  5. detector-promote.py              — read-only wave-promotion check

Usage:
  python3 tools/agent-recall-detector-loop.py --workspace ~/audits/<project> --dry-run
  python3 tools/agent-recall-detector-loop.py --workspace ~/audits/<project>
  python3 tools/agent-recall-detector-loop.py --workspace ~/audits/<project> --stage 1-3

Exit codes:
  0 — all requested stages ran successfully (or dry-run completed)
  1 — no detector tasks found in queue (nothing to do)
  2 — input error / missing workspace
  3 — a stage failed and --fail-fast is set
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
QUEUE_TOOL = ROOT / "tools" / "agent-recall-detector-queue.py"
DISPATCHER_TOOL = ROOT / "tools" / "memory-next-loop-dispatcher.py"
PROMOTE_TOOL = ROOT / "tools" / "detector-promote.py"
BRIEF_TEMPLATE = ROOT / "agent_briefs" / "templates" / "detector-authoring-brief.template.md"
BRIEF_OUT_DIR = ROOT / "agent_briefs"

SCHEMA = "auditooor.agent_recall_detector_loop.v1"
FIXTURE_LANG_EXT = {"solidity": "sol", "rust": "rs", "go": "go", "ts": "ts", "python": "py"}
DEFAULT_LANG = "solidity"

MCP_CONTEXT_PACK_ID = "auditooor.vault_context_pack.v1:resume:5cbb004d7436a32c"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _slug(value: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out[:80] or "detector"


def _detector_tasks(tasks_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        task for task in tasks_payload.get("tasks", [])
        if isinstance(task, dict) and task.get("task_type") == "detector_task"
    ]


# ---------------------------------------------------------------------------
# Stage 1: build queue
# ---------------------------------------------------------------------------

def run_stage1_build_queue(workspace: Path, *, dry_run: bool, log) -> dict[str, Any]:
    """Run agent-recall-detector-queue.py and return the tasks payload."""
    log("[stage 1] building agent recall detector queue...")
    tasks_path = workspace / ".auditooor" / "agent_recall_detector_tasks.json"

    if dry_run:
        # In dry-run mode return existing tasks if present, otherwise empty
        existing = _read_json(tasks_path)
        if existing:
            log(f"[stage 1] dry-run: reusing existing tasks artifact at {tasks_path}")
            return existing
        log("[stage 1] dry-run: no existing tasks artifact; returning empty payload")
        return {"schema": "", "tasks": [], "task_count": 0, "queue_count": 0}

    result = subprocess.run(
        [sys.executable, str(QUEUE_TOOL), "--workspace", str(workspace)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log(f"[stage 1] WARN: queue tool exited {result.returncode}")
        log(result.stderr.strip() or result.stdout.strip())
    else:
        log(f"[stage 1] queue tool OK")

    return _read_json(tasks_path)


# ---------------------------------------------------------------------------
# Stage 2: dispatcher consume branch
# ---------------------------------------------------------------------------

def run_stage2_dispatcher(workspace: Path, tasks_payload: dict[str, Any], *, dry_run: bool, log) -> list[dict[str, Any]]:
    """Consume the detector-recall tasks and return the list of detector task rows."""
    log("[stage 2] consuming detector-recall tasks via dispatcher...")
    detector_tasks = _detector_tasks(tasks_payload)
    if not detector_tasks:
        log("[stage 2] no detector tasks found in queue; nothing to dispatch")
    else:
        log(f"[stage 2] found {len(detector_tasks)} detector task(s)")

    # Use the dispatcher's consume_detector_queue function if available;
    # otherwise fall back to direct task list processing.
    try:
        module = _load_module(DISPATCHER_TOOL, "memory_next_loop_dispatcher")
        if hasattr(module, "consume_detector_queue"):
            result = module.consume_detector_queue(workspace, tasks_payload, dry_run=dry_run)
            if isinstance(result, list):
                return result
    except Exception as exc:
        log(f"[stage 2] dispatcher module load warning: {exc} — proceeding with direct task list")

    return detector_tasks


# ---------------------------------------------------------------------------
# Stage 3: brief materialisation
# ---------------------------------------------------------------------------

def _render_brief(task: dict[str, Any], *, lang: str, context_pack_id: str) -> str:
    """Render a detector-authoring brief from the template."""
    template_text = BRIEF_TEMPLATE.read_text(encoding="utf-8") if BRIEF_TEMPLATE.is_file() else _default_template()
    ext = FIXTURE_LANG_EXT.get(lang, "sol")
    detector_slug = _slug(
        str(task.get("suggested_detector_slug") or task.get("source_id") or task.get("task_id") or "detector")
    )
    claims_list = task.get("claims_detected") or []
    claims_str = "\n".join(f"- `{c}`" for c in claims_list) if claims_list else "- _none recorded_"
    blockers_list = task.get("terminal_blockers") or []
    blockers_str = "\n".join(f"- `{b}`" for b in blockers_list) if blockers_list else "- _none_"

    return template_text.format(
        detector_slug=detector_slug,
        context_pack_id=context_pack_id,
        queue_id=str(task.get("queue_id") or ""),
        task_id=str(task.get("task_id") or ""),
        source=str(task.get("source") or ""),
        source_artifact=str(task.get("source_artifact") or ""),
        generated_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        claims_detected=claims_str,
        reason=str(task.get("reason") or ""),
        lang=lang,
        ext=ext,
        terminal_blockers=blockers_str,
        next_command=str(task.get("next_command") or "make agent-recall-detector-queue WS=<workspace>"),
    )


def _default_template() -> str:
    """Minimal fallback template if the file is missing."""
    return (
        "# Detector Authoring Brief — {detector_slug}\n\n"
        "<!-- MCP context_pack_id: {context_pack_id} -->\n\n"
        "Queue ID: `{queue_id}` | Task ID: `{task_id}` | Source: `{source}`\n\n"
        "## Claims\n\n{claims_detected}\n\n"
        "## Reason\n\n{reason}\n\n"
        "## Terminal blockers\n\n{terminal_blockers}\n\n"
        "## Next command\n\n```\n{next_command}\n```\n"
    )


def run_stage3_materialise_briefs(
    workspace: Path,
    detector_tasks: list[dict[str, Any]],
    *,
    dry_run: bool,
    lang: str,
    context_pack_id: str,
    log,
) -> list[Path]:
    """Write detector-authoring briefs to agent_briefs/."""
    log(f"[stage 3] materialising {len(detector_tasks)} detector-authoring brief(s)...")
    written: list[Path] = []

    for task in detector_tasks:
        detector_slug = _slug(
            str(task.get("suggested_detector_slug") or task.get("source_id") or task.get("task_id") or "detector")
        )
        brief_path = BRIEF_OUT_DIR / f"detector-{detector_slug}.md"
        content = _render_brief(task, lang=lang, context_pack_id=context_pack_id)

        if dry_run:
            log(f"[stage 3] dry-run: would write {brief_path.relative_to(ROOT)}")
        else:
            _write_text(brief_path, content)
            log(f"[stage 3] wrote {brief_path.relative_to(ROOT)}")
        written.append(brief_path)

    return written


# ---------------------------------------------------------------------------
# Stage 4: fixture skeleton seeding
# ---------------------------------------------------------------------------

def run_stage4_seed_fixtures(
    workspace: Path,
    detector_tasks: list[dict[str, Any]],
    *,
    dry_run: bool,
    lang: str,
    log,
) -> list[Path]:
    """Optionally seed empty fixture stubs under detectors/fixtures/<lang>/."""
    ext = FIXTURE_LANG_EXT.get(lang, "sol")
    fixtures_dir = ROOT / "detectors" / "fixtures" / lang
    seeded: list[Path] = []

    for task in detector_tasks:
        detector_slug = _slug(
            str(task.get("suggested_detector_slug") or task.get("source_id") or task.get("task_id") or "detector")
        )
        positive = fixtures_dir / f"{detector_slug.replace('-', '_')}_positive.{ext}"
        negative = fixtures_dir / f"{detector_slug.replace('-', '_')}_negative.{ext}"

        for fixture_path, kind in [(positive, "positive"), (negative, "negative")]:
            if fixture_path.exists():
                log(f"[stage 4] fixture already exists (skip): {fixture_path.relative_to(ROOT)}")
                continue
            stub = f"// Fixture stub: {kind} fixture for detector '{detector_slug}'\n// TODO: fill in a {kind} example\n"
            if lang == "rust":
                stub = f"// Fixture stub: {kind} fixture for detector '{detector_slug}'\n// TODO: fill in a {kind} Rust example\n"
            elif lang in ("go",):
                stub = f"// Fixture stub: {kind} fixture for detector '{detector_slug}'\n// TODO: fill in a {kind} Go example\n"

            if dry_run:
                log(f"[stage 4] dry-run: would seed {fixture_path.relative_to(ROOT)}")
            else:
                fixture_path.parent.mkdir(parents=True, exist_ok=True)
                fixture_path.write_text(stub, encoding="utf-8")
                log(f"[stage 4] seeded {fixture_path.relative_to(ROOT)}")
            seeded.append(fixture_path)

    return seeded


# ---------------------------------------------------------------------------
# Stage 5: detector-promote (read-only)
# ---------------------------------------------------------------------------

def run_stage5_promote_check(workspace: Path, *, dry_run: bool, log) -> int:
    """Run detector-promote.py (read-only) to surface wave-promotion candidates."""
    log("[stage 5] running detector-promote.py wave-promotion check...")
    cmd = [sys.executable, str(PROMOTE_TOOL)]
    if workspace:
        cmd.extend(["--workspace", str(workspace)])

    if dry_run:
        log(f"[stage 5] dry-run: would run: {' '.join(cmd)}")
        return 0

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout.strip():
        log(result.stdout.strip())
    if result.stderr.strip():
        log(f"[stage 5] stderr: {result.stderr.strip()}")
    log(f"[stage 5] detector-promote exited {result.returncode}")
    return result.returncode


# ---------------------------------------------------------------------------
# Manifest writer
# ---------------------------------------------------------------------------

def write_loop_manifest(
    workspace: Path,
    *,
    stages_run: list[int],
    detector_tasks: list[dict[str, Any]],
    briefs: list[Path],
    fixtures: list[Path],
    promote_rc: int,
    dry_run: bool,
    context_pack_id: str,
) -> Path:
    manifest_path = workspace / ".auditooor" / "agent_recall_detector_loop.json"
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "dry_run": dry_run,
        "context_pack_id": context_pack_id,
        "stages_run": stages_run,
        "detector_task_count": len(detector_tasks),
        "briefs_written": [str(p.relative_to(ROOT)) for p in briefs],
        "fixtures_seeded": [str(p.relative_to(ROOT)) for p in fixtures],
        "promote_exit_code": promote_rc,
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_stages(raw: str) -> set[int]:
    stages: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            stages.update(range(int(m.group(1)), int(m.group(2)) + 1))
        elif part.isdigit():
            stages.add(int(part))
    return stages or {1, 2, 3, 4, 5}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workspace", required=True, type=Path,
                        help="path to the audit workspace (e.g. ~/audits/<project>)")
    parser.add_argument("--dry-run", action="store_true",
                        help="render and log but do not write artifacts")
    parser.add_argument("--stage", default="1-5",
                        help="comma-separated stage numbers or range (default: 1-5)")
    parser.add_argument("--lang", default=DEFAULT_LANG,
                        choices=list(FIXTURE_LANG_EXT.keys()),
                        help="target language for fixture stubs (default: solidity)")
    parser.add_argument("--seed-fixtures", action="store_true",
                        help="seed empty fixture stubs (stage 4); default off in dry-run")
    parser.add_argument("--fail-fast", action="store_true",
                        help="exit with rc=3 if any stage fails")
    parser.add_argument("--context-pack-id", default=MCP_CONTEXT_PACK_ID,
                        help="MCP context_pack_id to embed in generated briefs")
    parser.add_argument("--json", action="store_true",
                        help="emit loop manifest JSON to stdout at end")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[error] workspace not found: {workspace}", file=sys.stderr)
        return 2

    stages = _parse_stages(args.stage)
    progress = sys.stderr if args.json else sys.stdout

    def log(*parts: object) -> None:
        print(*parts, file=progress)

    log(f"[agent-recall-detector-loop] workspace={workspace}")
    log(f"[agent-recall-detector-loop] stages={sorted(stages)} dry_run={args.dry_run}")

    tasks_payload: dict[str, Any] = {}
    detector_tasks: list[dict[str, Any]] = []
    briefs: list[Path] = []
    fixtures: list[Path] = []
    promote_rc = -1
    stages_run: list[int] = []

    # Stage 1
    if 1 in stages:
        tasks_payload = run_stage1_build_queue(workspace, dry_run=args.dry_run, log=log)
        stages_run.append(1)

    # Stage 2
    if 2 in stages:
        detector_tasks = run_stage2_dispatcher(workspace, tasks_payload, dry_run=args.dry_run, log=log)
        stages_run.append(2)

    if not detector_tasks and (3 in stages or 4 in stages):
        log("[agent-recall-detector-loop] no detector tasks — stages 3/4 are no-ops")

    # Stage 3
    if 3 in stages:
        briefs = run_stage3_materialise_briefs(
            workspace, detector_tasks,
            dry_run=args.dry_run,
            lang=args.lang,
            context_pack_id=args.context_pack_id,
            log=log,
        )
        stages_run.append(3)

    # Stage 4
    if 4 in stages and (args.seed_fixtures or not args.dry_run):
        fixtures = run_stage4_seed_fixtures(
            workspace, detector_tasks,
            dry_run=args.dry_run,
            lang=args.lang,
            log=log,
        )
        stages_run.append(4)
    elif 4 in stages:
        log("[stage 4] skipped (use --seed-fixtures to enable)")
        stages_run.append(4)

    # Stage 5
    if 5 in stages:
        promote_rc = run_stage5_promote_check(workspace, dry_run=args.dry_run, log=log)
        if promote_rc != 0 and args.fail_fast:
            log(f"[agent-recall-detector-loop] fail-fast: promote check exited {promote_rc}")
            return 3
        stages_run.append(5)

    # Write manifest
    manifest_path = write_loop_manifest(
        workspace,
        stages_run=stages_run,
        detector_tasks=detector_tasks,
        briefs=briefs,
        fixtures=fixtures,
        promote_rc=promote_rc,
        dry_run=args.dry_run,
        context_pack_id=args.context_pack_id,
    )
    log(f"[agent-recall-detector-loop] wrote manifest: {manifest_path.relative_to(workspace)}")

    if args.json:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        print(json.dumps(manifest, indent=2, sort_keys=True))

    if not detector_tasks and 2 in stages_run:
        return 1

    log("[agent-recall-detector-loop] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
