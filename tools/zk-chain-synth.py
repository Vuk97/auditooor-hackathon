#!/usr/bin/env python3
# <!-- r36-rebuttal: ZK-CHAIN-SYNTH lane; file declared in .auditooor/agent_pathspec.json -->
"""zk-chain-synth.py - ZK soundness exploit-chain synthesis.

The ZK analog of chain-synth-driver.py. Where chain-synth-driver synthesizes
generic multi-contract exploit chains from broken INV-* invariants, this tool
synthesizes whether a set of ZK *soundness* gaps compose into a single
forged-proof-acceptance chain.

Example composite chain:
  missing databus constraint (#15007)
    + partial masking gap (#18736)
    + challenge-generation gap (#16623)
  -> attacker forges a proof the verifier accepts
  -> false state root finalized

RELATED TOOLS:
  - tools/chain-synth-driver.py  : direct inspiration; this is the ZK analog.
        Gap filled: chain-synth-driver matches generic INV-* chain templates;
        this tool reads ZK soundness gaps (zk_candidates_*.jsonl /
        zk_hunt_queue.jsonl) and synthesizes a forged-proof-acceptance chain
        with the soundness invariant each hop breaks.
  - tools/zk-verify-persist.py    : produces the zk_candidates_*.jsonl that
        feeds this tool's gap inventory.
  - tools/zk-verifier-bugclass-checklist.py : produces zk_hunt_queue.jsonl.
  - tools/llm-dispatch.py         : the dispatch surface (provider mimo).

Pipeline
--------
  1. Read workspace ZK soundness gaps from zk_candidates_*.jsonl (most recent)
     and zk_hunt_queue.jsonl.
  2. Build an adversarial synthesis prompt enumerating the gaps and asking the
     model to order them into hops, naming the soundness invariant each hop
     breaks plus the composite impact.
  3. Dispatch via tools/llm-dispatch.py --provider mimo.
  4. Write a chain-synthesis report (mirroring chain-synth-driver's shape) to
     <ws>/.auditooor/zk_chain_synthesis_<date>.json.

CLI
---
python3 tools/zk-chain-synth.py --workspace <ws> [--now <iso>] [--dry-run] [--json]

Env
---
  MIMO_API_KEY, MIMO_BASE_URL, AUDITOOOR_LLM_NETWORK_CONSENT=1

Schema emitted: auditooor.zk_chain_synthesis_report.v1
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.zk_chain_synthesis_report.v1"
ZK_HUNT_QUEUE_FILE = ".auditooor/zk_hunt_queue.jsonl"
ZK_CANDIDATES_GLOB = "zk_candidates_*.jsonl"
LLM_DISPATCH = "tools/llm-dispatch.py"
DEFAULT_MAX_GAPS = 12
DISPATCH_MAX_TOKENS = "2000"


def utc_now(now: str | None = None) -> str:
    if now:
        return now
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def date_str(now: str | None = None) -> str:
    if now:
        # Accept a full ISO timestamp; take the date portion.
        return now.split("T", 1)[0]
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not path.is_file():
        return items
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def _gap_id(gap: dict[str, Any], idx: int) -> str:
    """Derive a stable per-gap id. Prefer an explicit finding number /
    candidate id; fall back to bug_class+fn; finally a positional id."""
    for key in ("finding_id", "finding", "candidate_id", "id", "zkbugs_id"):
        v = gap.get(key)
        if v not in (None, ""):
            return str(v)
    bc = gap.get("bug_class") or gap.get("attack_class") or "gap"
    fn = gap.get("fn") or gap.get("function") or ""
    base = f"{bc}-{fn}".strip("-") or "gap"
    return f"{base}-{idx}"


def collect_soundness_gaps(workspace: Path, max_gaps: int = DEFAULT_MAX_GAPS) -> list[dict[str, Any]]:
    """Gather ZK soundness gaps from the most recent zk_candidates_*.jsonl and
    the zk_hunt_queue.jsonl. De-dupe by derived gap id."""
    raw: list[dict[str, Any]] = []

    auditooor = workspace / ".auditooor"
    if auditooor.is_dir():
        cand_files = sorted(auditooor.glob(ZK_CANDIDATES_GLOB))
        if cand_files:
            raw.extend(_read_jsonl(cand_files[-1]))

    raw.extend(_read_jsonl(workspace / ZK_HUNT_QUEUE_FILE))

    gaps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, g in enumerate(raw):
        gid = _gap_id(g, idx)
        if gid in seen:
            continue
        seen.add(gid)
        gaps.append(
            {
                "gap_id": gid,
                "bug_class": g.get("bug_class") or g.get("attack_class") or "",
                "fn": g.get("fn") or g.get("function") or "",
                "file_line": g.get("file_line", ""),
                "code_excerpt": (g.get("code_excerpt") or "")[:400],
                "soundness_invariant": g.get("soundness_invariant")
                or g.get("invariant")
                or "",
                "note": (g.get("note") or g.get("description") or "")[:300],
            }
        )
        if len(gaps) >= max_gaps:
            break
    return gaps


def build_synthesis_prompt(workspace_handle: str, gaps: list[dict[str, Any]]) -> str:
    """Adversarial prompt: order the gaps into a forged-proof-acceptance chain,
    naming the soundness invariant each hop breaks and the composite impact."""
    lines: list[str] = []
    lines.append(
        "You are an adversarial ZK-circuit / verifier soundness analyst. Below is a "
        f"set of confirmed ZK soundness gaps found in workspace `{workspace_handle}`. "
        "Each gap is a place where a circuit constraint, masking step, or "
        "challenge-generation step is missing or partial."
    )
    lines.append("")
    lines.append("SOUNDNESS GAPS:")
    for g in gaps:
        lines.append(
            f"- [{g['gap_id']}] bug_class={g['bug_class']!r} fn={g['fn']!r} "
            f"file_line={g['file_line']!r}"
        )
        if g["soundness_invariant"]:
            lines.append(f"    soundness_invariant: {g['soundness_invariant']}")
        if g["note"]:
            lines.append(f"    note: {g['note']}")
        if g["code_excerpt"]:
            lines.append(f"    code_excerpt: {g['code_excerpt']!r}")
    lines.append("")
    lines.append(
        "TASK: Determine whether these gaps COMPOSE into a single end-to-end "
        "forged-proof-acceptance chain - i.e. an attacker exploits them in some "
        "order to produce a proof the verifier ACCEPTS for a statement that is "
        "FALSE, finalizing an invalid state root / nullifier / withdrawal. A real "
        "chain requires that the soundness break at each hop is preconditioned by "
        "the break at the prior hop (e.g. a missing databus constraint lets an "
        "unconstrained witness through, which a partial masking gap then hides, "
        "which a challenge-gen gap then fails to catch)."
    )
    lines.append("")
    lines.append(
        "Respond with STRICT JSON ONLY (no prose, no markdown fences) of shape:\n"
        "{\n"
        '  "composes": true|false,\n'
        '  "hops": [\n'
        '    {"gap_id": "<one of the ids above>",\n'
        '     "order": 1,\n'
        '     "soundness_invariant_broken": "<the exact soundness invariant this hop violates>",\n'
        '     "enables_next": "<what state/witness this hop produces for the next hop>"}\n'
        "  ],\n"
        '  "composite_impact": "<the final forged-proof-acceptance impact, e.g. false state root finalized>",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '  "missing_link": "<if composes=false, the gap that is missing to complete the chain>"\n'
        "}\n"
        "If the gaps do NOT compose into a single accepted-forged-proof chain, set "
        'composes=false and explain the missing_link. Do NOT fabricate gaps that '
        "are not in the list above."
    )
    return "\n".join(lines)


def dispatch_synthesis(
    repo_root: Path,
    prompt: str,
    dry_run: bool = False,
    mock_llm: bool = False,
) -> dict[str, Any]:
    """Send the synthesis prompt to the LLM via llm-dispatch.py --provider mimo.
    Returns a parsed narrative dict (or {"raw": ...} on non-JSON output)."""
    if dry_run:
        return {"dry_run": True, "prompt_len": len(prompt)}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="zk_chain_synth_"
    ) as f:
        f.write(prompt)
        prompt_file = Path(f.name)

    cmd = [
        sys.executable,
        str(repo_root / LLM_DISPATCH),
        "--prompt-file",
        str(prompt_file),
        "--provider",
        "mimo",
        "--max-tokens",
        DISPATCH_MAX_TOKENS,
        "--operator-live-network-consent",
        "--task-type",
        "zk-chain-synth",
    ]
    if mock_llm:
        cmd.append("--mock")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
    finally:
        prompt_file.unlink(missing_ok=True)

    if proc.returncode != 0:
        return {"error": proc.stderr[:300]}

    stdout = proc.stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"raw": stdout[:2000]}


def build_report(
    workspace: Path,
    gaps: list[dict[str, Any]],
    narrative: dict[str, Any],
    dry_run: bool,
    now: str | None,
    status: str | None = None,
) -> dict[str, Any]:
    if status is None:
        status = "dry-run" if dry_run else ("no-gaps" if not gaps else "complete")
    return {
        "schema": SCHEMA_ID,
        "generated_at": utc_now(now),
        "workspace": str(workspace),
        "soundness_gaps": gaps,
        "gap_count": len(gaps),
        "gap_ids": [g["gap_id"] for g in gaps],
        "chains_synthesized": 0 if not narrative or "dry_run" in narrative else 1,
        "dry_run": dry_run,
        "status": status,
        "narrative": narrative,
    }


def run(
    workspace: Path,
    dry_run: bool = False,
    now: str | None = None,
    max_gaps: int = DEFAULT_MAX_GAPS,
    mock_llm: bool = False,
    write: bool = True,
) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent

    gaps = collect_soundness_gaps(workspace, max_gaps=max_gaps)

    if not gaps:
        report = build_report(workspace, [], {}, dry_run, now, status="no-gaps")
        return report

    prompt = build_synthesis_prompt(workspace.name, gaps)
    narrative = dispatch_synthesis(repo_root, prompt, dry_run=dry_run, mock_llm=mock_llm)

    report = build_report(workspace, gaps, narrative, dry_run, now)

    if write and not dry_run:
        out_path = workspace / ".auditooor" / f"zk_chain_synthesis_{date_str(now)}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["report_path"] = str(out_path)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace", required=True, type=Path,
        help="Audit workspace root (e.g. /Users/wolf/audits/aztec).",
    )
    parser.add_argument(
        "--now", default=None,
        help="Override the timestamp (ISO 8601) for deterministic report names.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Collect gaps + build prompt but do not call the LLM or write a report.",
    )
    parser.add_argument(
        "--max-gaps", type=int, default=DEFAULT_MAX_GAPS,
        help=f"Max soundness gaps to feed the synthesizer (default {DEFAULT_MAX_GAPS}).",
    )
    parser.add_argument(
        "--mock-llm", action="store_true",
        help="Pass --mock to llm-dispatch (synthetic response, no network). Test hook.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report to stdout.")
    args = parser.parse_args(argv)

    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1

    report = run(
        workspace,
        dry_run=args.dry_run,
        now=args.now,
        max_gaps=args.max_gaps,
        mock_llm=args.mock_llm,
    )

    print(
        f"[zk-chain-synth] gaps={report['gap_count']} "
        f"status={report['status']} "
        f"chains_synthesized={report['chains_synthesized']}",
        file=sys.stderr,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        rp = report.get("report_path", "(not written)")
        print(
            f"gap_count={report['gap_count']} "
            f"chains_synthesized={report['chains_synthesized']} "
            f"report={rp}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
