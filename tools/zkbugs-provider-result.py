#!/usr/bin/env python3
"""Record Kimi/Minimax zkBugs provider triage output as durable evidence."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


def _read_jsonish(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", raw, re.S | re.I)
    body = fence.group(1) if fence else raw
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        return {
            "parse_error": str(exc),
            "raw_excerpt": raw[:2000],
        }
    return payload if isinstance(payload, dict) else {"value": payload}


def _verdict(payload: dict[str, Any]) -> str:
    value = payload.get("verdict")
    return value if isinstance(value, str) else "UNKNOWN"


def _promotion_status(kimi: dict[str, Any], minimax: dict[str, Any]) -> str:
    if "parse_error" in kimi or "parse_error" in minimax:
        return "needs_human"
    if _verdict(minimax) == "KEEP_FOR_CODEX":
        return "candidate_needs_codex_evidence"
    if _verdict(minimax) == "BLOCKER":
        return "blocked_by_minimax"
    if _verdict(kimi) == "REJECT":
        return "rejected_by_kimi"
    return "needs_human"


def render_markdown(record: dict[str, Any]) -> str:
    lines = [
        "# zkBugs Provider Triage Result",
        "",
        f"- Brief: `{record['brief']}`",
        f"- Kimi output: `{record['kimi_output']}`",
        f"- Minimax output: `{record['minimax_output']}`",
        f"- Kimi verdict: `{record['kimi_verdict']}`",
        f"- Minimax verdict: `{record['minimax_verdict']}`",
        f"- Promotion status: `{record['promotion_status']}`",
        "",
        "## Minimax Blocker",
        "",
        str(record["minimax"].get("blocker", "")) or "No blocker field.",
        "",
        "## Codex Required Evidence",
        "",
    ]
    evidence = record["minimax"].get("codex_required_evidence", [])
    if isinstance(evidence, list) and evidence:
        for item in evidence:
            lines.append(f"- {item}")
    else:
        lines.append("- No explicit evidence list.")
    lines.extend([
        "",
        "## Guardrail",
        "",
        "Do not promote this row to detector/PoC work unless `promotion_status` is",
        "`candidate_needs_codex_evidence` and the required smoke-fire or replay",
        "evidence is actually produced.",
        "",
    ])
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brief", required=True, type=Path)
    parser.add_argument("--kimi-output", required=True, type=Path)
    parser.add_argument("--minimax-output", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    kimi = _read_jsonish(args.kimi_output)
    minimax = _read_jsonish(args.minimax_output)
    record = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "brief": str(args.brief),
        "kimi_output": str(args.kimi_output),
        "minimax_output": str(args.minimax_output),
        "kimi": kimi,
        "minimax": minimax,
        "kimi_verdict": _verdict(kimi),
        "minimax_verdict": _verdict(minimax),
        "promotion_status": _promotion_status(kimi, minimax),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(record), encoding="utf-8")
    if args.print_json:
        print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
