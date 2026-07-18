#!/usr/bin/env python3
"""Build Kimi/Minimax dispatch prompts from zkBugs farming briefs.

This is intentionally a queue builder, not an auto-promoter. It turns the
briefs created by ``tools/zkbugs-ingest.py`` into bounded provider prompts so
Kimi can extract reusable root-cause predicates and Minimax can kill broad or
toy-only ideas before Claude/Codex spend implementation time.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IN_DIR = ROOT / ".audit_logs" / "zkbugs_farming" / "briefs"
DEFAULT_OUT_DIR = ROOT / ".audit_logs" / "zkbugs_farming" / "provider_queue"


KIMI_TEMPLATE = """You are mining zkBugs for auditooor detector/replay ideas.

Task:
1. Extract the minimal reusable root-cause predicate from this one bug.
2. State the exact code/circuit shape that should be searched for elsewhere.
3. State what would make the idea too broad or toy-only.
4. Propose one vulnerable/clean fixture or replay direction.

Return JSON only:
{{
  "verdict": "CANDIDATE|ADVISORY_ONLY|REJECT",
  "root_cause_predicate": "...",
  "generalizable_code_shape": "...",
  "required_evidence_before_promotion": ["..."],
  "fixture_or_replay_plan": "...",
  "rejection_reason": ""
}}

Bug brief:
```markdown
{brief}
```
"""


MINIMAX_TEMPLATE = """You are the adversarial kill-pass for a zkBugs mining candidate.

Task:
1. Reject overbroad predicates.
2. Reject candidates that are duplicate corpus descriptions without a checkable detector/replay shape.
3. Reject toy-only ideas that do not generalize to real audit work.
4. If keeping, name the exact evidence Codex must require before promotion.

Return JSON only:
{{
  "verdict": "KEEP_FOR_CODEX|BLOCKER",
  "blocker": "...",
  "codex_required_evidence": ["..."],
  "notes": "..."
}}

Kimi extraction:
```text
{kimi_output}
```

Original bug brief:
```markdown
{brief}
```
"""


def _load_readiness_module():
    tool = ROOT / "tools" / "zkbugs-readiness.py"
    spec = importlib.util.spec_from_file_location("zkbugs_readiness_for_queue", tool)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[zkbugs-brief-queue] unable to load {tool}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_name(path: Path) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in path.stem)


def build_queue(in_dir: Path, out_dir: Path, limit: int) -> dict[str, object]:
    briefs = sorted(in_dir.glob("*.md"))
    if limit > 0:
        briefs = briefs[:limit]
    prompts_dir = out_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for index, brief_path in enumerate(briefs, start=1):
        brief = brief_path.read_text(encoding="utf-8")
        base = f"{index:03d}_{_safe_name(brief_path)}"
        kimi_prompt = prompts_dir / f"{base}.kimi.md"
        minimax_prompt = prompts_dir / f"{base}.minimax.template.md"
        kimi_prompt.write_text(KIMI_TEMPLATE.format(brief=brief), encoding="utf-8")
        minimax_prompt.write_text(
            MINIMAX_TEMPLATE.format(kimi_output="<PASTE_KIMI_JSON_HERE>", brief=brief),
            encoding="utf-8",
        )
        rows.append(
            {
                "index": index,
                "brief": str(brief_path),
                "kimi_prompt": str(kimi_prompt),
                "minimax_prompt_template": str(minimax_prompt),
                "kimi_command": [
                    "python3",
                    "tools/llm-dispatch.py",
                    "--provider",
                    "kimi",
                    "--prompt-file",
                    str(kimi_prompt),
                ],
                "minimax_command_template": [
                    "python3",
                    "tools/llm-dispatch.py",
                    "--provider",
                    "minimax",
                    "--prompt-file",
                    str(minimax_prompt),
                ],
                "promotion_gate": "Codex requires vulnerable/clean smoke-fire or replayable counterexample before detector/PoC promotion.",
            }
        )
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "brief_dir": str(in_dir),
        "out_dir": str(out_dir),
        "count": len(rows),
        "rows": rows,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "zkbugs_provider_queue.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "zkbugs_provider_queue.md").write_text(render_markdown(manifest), encoding="utf-8")
    readiness = _load_readiness_module()
    farming_dir = out_dir.parent
    resolved_root = readiness.resolve_zkbugs_root(farming_dir)
    readiness_payload = readiness.build_payload(resolved_root, farming_dir)
    readiness.write_reports(
        readiness_payload,
        farming_dir / "zkbugs_readiness.json",
        farming_dir / "zkbugs_readiness.md",
    )
    manifest["readiness"] = {
        "status": readiness_payload["status"],
        "report_json": str(farming_dir / "zkbugs_readiness.json"),
        "report_md": str(farming_dir / "zkbugs_readiness.md"),
        "blocker_count": len(readiness_payload["blockers"]),
    }
    (out_dir / "zkbugs_provider_queue.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "zkbugs_provider_queue.md").write_text(render_markdown(manifest), encoding="utf-8")
    return manifest


def render_markdown(manifest: dict[str, object]) -> str:
    rows = manifest.get("rows", [])
    assert isinstance(rows, list)
    lines = [
        "# zkBugs Provider Queue",
        "",
        "Use this queue to delegate repetitive zkBugs brief triage:",
        "",
        "1. Run Kimi on the `.kimi.md` prompt.",
        "2. Paste/save Kimi JSON into a concrete Minimax prompt from the template.",
        "3. Run Minimax kill-pass.",
        "4. Claude may draft detector/fixture/replay work only for rows Minimax keeps.",
        "5. Codex promotes only with smoke-fire or replayable counterexample.",
        "",
        f"- Readiness status: `{manifest.get('readiness', {}).get('status', 'unknown')}`",
        "",
        "| # | Brief | Kimi prompt | Minimax template |",
        "|---:|---|---|---|",
    ]
    for row in rows:
        assert isinstance(row, dict)
        lines.append(
            f"| {row['index']} | `{row['brief']}` | `{row['kimi_prompt']}` | `{row['minimax_prompt_template']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brief-dir", type=Path, default=DEFAULT_IN_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.brief_dir.is_dir():
        raise SystemExit(f"[zkbugs-brief-queue] missing brief dir: {args.brief_dir}")
    manifest = build_queue(args.brief_dir, args.out_dir, max(0, args.limit))
    if args.print_json:
        print(json.dumps({"count": manifest["count"], "out_dir": manifest["out_dir"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
