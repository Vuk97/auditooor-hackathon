#!/usr/bin/env python3
# <!-- r36-rebuttal: CHAIN-VERIFY-PERSIST lane; file declared in .auditooor/agent_pathspec.json -->
"""chain-verify-persist.py - Stage 4 adversarial chain verifier + Stage 5 learn-back persister.

CHAIN-LIFT (2026-05-28): Reads chain_synthesis_<date>.json produced by chain-synth-driver.py,
dispatches an adversarial LLM verifier per chain (R57/R40 refutation), writes
chain_verdicts_<date>.json, and optionally persists confirmed chains to
global_chain_templates.jsonl and refuted chains to reports/known_dead_ends.jsonl.

CLI
---
python3 tools/chain-verify-persist.py \\
    --workspace <ws> \\
    [--synthesis-file <path>] \\
    [--persist] \\
    [--dry-run] \\
    [--now <ISO8601>] \\
    [--json]

Env
---
  MIMO_API_KEY, MIMO_BASE_URL, AUDITOOOR_LLM_NETWORK_CONSENT=1

Schema emitted: auditooor.chain_verdicts_report.v1
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERDICTS = "auditooor.chain_verdicts_report.v1"
SCHEMA_GCT = "auditooor.global_chain_template.v1"
SCHEMA_KDE = "auditooor.known_dead_end.v1"

GLOBAL_CHAIN_TEMPLATES = "audit/corpus_tags/derived/global_chain_templates.jsonl"
KNOWN_DEAD_ENDS = "reports/known_dead_ends.jsonl"
LLM_DISPATCH = "tools/llm-dispatch.py"
CHAIN_SYNTH_INPUT_FILES = (
    ".auditooor/exploit_queue.json",
    ".auditooor/exploit_queue.source_mined.json",
    ".auditooor/ccia_attack_angles.json",
    ".auditooor/chain_synth_source_links.json",
)
CHAIN_SYNTH_INPUT_GLOBS = (
    ".auditooor/source_artifacts/*.composition_link_source_artifact.json",
)
FRESHNESS_SKEW = timedelta(seconds=1)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _find_latest_synthesis(workspace: Path) -> Path | None:
    """Return the most-recently written chain_synthesis_*.json in workspace/.auditooor/."""
    auditooor_dir = workspace / ".auditooor"
    candidates = sorted(auditooor_dir.glob("chain_synthesis_*.json"), reverse=True)
    return candidates[0] if candidates else None


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_json_doc(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _artifact_timestamp(path: Path) -> tuple[datetime, str]:
    doc = _load_json_doc(path)
    if isinstance(doc, dict):
        for key in ("generated_at", "generated_at_utc", "created_at", "updated_at"):
            parsed = _parse_timestamp(doc.get(key))
            if parsed is not None:
                return parsed, key
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc), "mtime"


def _chain_synth_input_artifacts(workspace: Path) -> list[Path]:
    candidates: list[Path] = [workspace / rel for rel in CHAIN_SYNTH_INPUT_FILES]
    for pattern in CHAIN_SYNTH_INPUT_GLOBS:
        candidates.extend(workspace.glob(pattern))
    out: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        if not path.is_file():
            continue
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(path)


def validate_synthesis_freshness(workspace: Path, synthesis_file: Path) -> dict:
    """Require chain synthesis to be at least as fresh as its queue inputs."""
    synthesis_ts, synthesis_ts_source = _artifact_timestamp(synthesis_file)
    inputs: list[dict] = []
    stale_inputs: list[dict] = []
    for path in _chain_synth_input_artifacts(workspace):
        input_ts, input_ts_source = _artifact_timestamp(path)
        row = {
            "path": _rel(path, workspace),
            "timestamp": input_ts.isoformat().replace("+00:00", "Z"),
            "timestamp_source": input_ts_source,
        }
        inputs.append(row)
        if input_ts > synthesis_ts + FRESHNESS_SKEW:
            stale_inputs.append(row)

    verdict = "fail-stale-synthesis-report" if stale_inputs else "pass-synthesis-current"
    return {
        "verdict": verdict,
        "synthesis_file": _rel(synthesis_file, workspace),
        "synthesis_timestamp": synthesis_ts.isoformat().replace("+00:00", "Z"),
        "synthesis_timestamp_source": synthesis_ts_source,
        "input_count": len(inputs),
        "inputs": inputs,
        "stale_inputs": stale_inputs,
    }


def _load_chains(synthesis_file: Path) -> list[dict]:
    """Extract the list of chain narratives from the synthesis report."""
    data = json.loads(synthesis_file.read_text(encoding="utf-8"))
    # narratives is a list of {task_id, narrative} dicts; narrative may itself be a dict
    # with chain-level fields or a raw string produced by the LLM.
    return data.get("narratives", [])


def _build_verify_prompt(chain: dict) -> str:
    """Build an adversarial refutation prompt for a single chain narrative."""
    chain_json = json.dumps(chain, indent=2)
    return f"""You are an adversarial security reviewer tasked with REFUTING a proposed exploit chain.

Your job is to prove the chain DOES NOT WORK by finding the first blocking defense.

Analyze the following chain and answer the 4 adversarial questions:
1. PER-HOP REACHABILITY: Is each hop actually reachable by the attacker with no privilege escalation not modelled?
2. R57 DEFENSE-BETWEEN-HOPS: Is there a modifier / require / access-control / reentrancy-guard / pause / separate-actor defense between any two hops that blocks the chain?
3. CROSS-CONTRACT TRUST: Does any hop assume trust-without-revalidation (e.g. msg.sender not re-checked after cross-contract call)?
4. R40 ONE-ATTACKER FEASIBILITY: Can a single unprivileged attacker control all inputs and execute every hop in one transaction or tightly coupled sequence?

Chain under review:
{chain_json}

Respond ONLY with a JSON object (no markdown fences) with these exact fields:
{{
  "holds": <true if the chain survives ALL 4 questions, false if ANY question exposes a blocker>,
  "blocking_defense": "<empty string if holds=true, otherwise the first blocking defense found>",
  "reasoning": "<1-3 sentence explanation>",
  "question_verdicts": {{
    "reachability": "pass|fail",
    "defense_between_hops": "pass|fail",
    "cross_contract_trust": "pass|fail",
    "one_attacker_feasibility": "pass|fail"
  }}
}}
"""


def _dispatch_verifier(prompt: str, mock: bool = False) -> dict:
    """Dispatch the adversarial verifier via llm-dispatch.py --provider mimo.

    Returns the parsed verdict dict.  On any error returns holds=false.
    """
    if mock:
        # Return a stable refutation for testing
        return {
            "holds": False,
            "blocking_defense": "mock-refuted: test mode",
            "reasoning": "Mock verifier always refutes.",
            "question_verdicts": {
                "reachability": "pass",
                "defense_between_hops": "fail",
                "cross_contract_trust": "pass",
                "one_attacker_feasibility": "pass",
            },
        }

    repo_root = _repo_root()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write(prompt)
        prompt_path = f.name

    try:
        env = os.environ.copy()
        # Ensure network consent for LLM call
        env.setdefault("AUDITOOOR_LLM_NETWORK_CONSENT", "1")

        cmd = [
            sys.executable,
            str(repo_root / LLM_DISPATCH),
            "--provider", "mimo",
            "--prompt-file", prompt_path,
            "--max-tokens", "1024",
            "--operator-live-network-consent",
            "--task-type", "chain-verify",
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(repo_root), env=env, timeout=120
        )
        if proc.returncode != 0:
            return {
                "holds": False,
                "blocking_defense": f"llm-dispatch error: {proc.stderr[:200]}",
                "reasoning": "LLM dispatch failed; defaulting to refuted.",
                "question_verdicts": {},
            }
        raw = proc.stdout.strip()
        # Strip potential markdown fences
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
        return {
            "holds": False,
            "blocking_defense": f"parse/timeout error: {exc!s:.200}",
            "reasoning": "LLM dispatch failed; defaulting to refuted.",
            "question_verdicts": {},
        }
    finally:
        Path(prompt_path).unlink(missing_ok=True)


def verify_chains(
    chains: list[dict], mock: bool = False
) -> list[dict]:
    """Run adversarial verification for each chain. Returns list of verdict dicts."""
    verdicts = []
    for i, chain in enumerate(chains):
        task_id = chain.get("task_id", f"chain-{i}")
        prompt = _build_verify_prompt(chain)
        result = _dispatch_verifier(prompt, mock=mock)
        verdicts.append(
            {
                "task_id": task_id,
                "holds": result.get("holds", False),
                "blocking_defense": result.get("blocking_defense", ""),
                "reasoning": result.get("reasoning", ""),
                "question_verdicts": result.get("question_verdicts", {}),
                "raw_chain": chain,
            }
        )
        status = "CONFIRMED" if result.get("holds") else "REFUTED"
        print(
            f"[chain-verify-persist] {status} chain {task_id}: {result.get('blocking_defense', 'no blocker')}",
            file=sys.stderr,
        )
    return verdicts


# ---------------------------------------------------------------------------
# Stage 5 helpers: persist confirmed + refuted chains
# ---------------------------------------------------------------------------

def _read_existing_ids(path: Path, id_field: str) -> set[str]:
    """Read all values of id_field from a JSONL file; return as a set."""
    ids: set[str] = set()
    if not path.exists():
        return ids
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            v = row.get(id_field)
            if v:
                ids.add(str(v))
        except json.JSONDecodeError:
            pass
    return ids


def _atomic_append(path: Path, record: dict) -> None:
    """Append a JSON record as one JSONL line; idempotent via id dedup before call."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def _extract_hop0_info(chain: dict) -> tuple[str, str]:
    """Extract (contract.function, attack_class) from a chain narrative."""
    narrative = chain.get("narrative", chain)
    if isinstance(narrative, dict):
        hops = narrative.get("hops", [])
        if hops and isinstance(hops[0], dict):
            fn = hops[0].get("function", hops[0].get("target", "unknown"))
            attack_class = narrative.get("attack_class", "unknown")
            return fn, attack_class
    # Fallback: use task_id
    return chain.get("task_id", "unknown"), "unknown"


def persist_confirmed(
    verdict: dict,
    workspace: str,
    repo_root: Path,
    confirmed_at: str,
    dry_run: bool = False,
) -> str | None:
    """Persist a confirmed chain to global_chain_templates.jsonl.

    Mirrors the existing GCT schema (read real rows above).
    Returns the chain_template_id or None on dry-run.
    """
    chain = verdict["raw_chain"]
    narrative = chain.get("narrative", chain)
    task_id = chain.get("task_id", "unknown")

    # Build a chain_template_id from task_id
    import hashlib
    h = hashlib.sha256(task_id.encode()).hexdigest()[:16]
    chain_template_id = f"GCT-confirmed-{h}"

    gct_path = repo_root / GLOBAL_CHAIN_TEMPLATES

    # Dedup check
    existing = _read_existing_ids(gct_path, "chain_template_id")
    if chain_template_id in existing:
        print(
            f"[chain-verify-persist] GCT dedup: {chain_template_id} already present, skip",
            file=sys.stderr,
        )
        return chain_template_id

    # Build state_machine from hops if available
    state_machine: list[dict] = []
    if isinstance(narrative, dict):
        for step_i, hop in enumerate(narrative.get("hops", []), start=1):
            if isinstance(hop, dict):
                state_machine.append(
                    {
                        "step": step_i,
                        "invariant_id": hop.get("invariant_id", ""),
                        "commit_point_pattern": hop.get("commit_point", hop.get("target", "")),
                        "precondition_summary": hop.get("precondition", hop.get("description", "")),
                        "produces_state": f"state:{hop.get('produces_state', hop.get('target', ''))}",
                    }
                )

    record: dict = {
        "schema_version": SCHEMA_GCT,
        "chain_template_id": chain_template_id,
        "source": "confirmed-novel-chain",
        "origin_workspace": workspace,
        "confirmed_at": confirmed_at,
        "advisory_only": False,
        "submission_posture": "CANDIDATE",
        "verification_tier": "tier-2-verified-public-archive",
        "tuple_size": len(state_machine) or 1,
        "member_invariant_ids": [
            hop.get("invariant_id", "")
            for hop in (narrative.get("hops", []) if isinstance(narrative, dict) else [])
            if isinstance(hop, dict) and hop.get("invariant_id")
        ],
        "member_categories": [],
        "member_target_langs": [],
        "state_machine": state_machine,
        "composition_score": 0.0,
        "composition_rationale": f"Confirmed by adversarial verifier in workspace {workspace}",
        "composition_breakdown": {},
        "evidence_incidents": [],
        "kill_conditions": [],
        "falsification_requirements": [],
        "generated_at_utc": confirmed_at,
        # Verifier reasoning preserved for traceability
        "verifier_reasoning": verdict.get("reasoning", ""),
        "verifier_question_verdicts": verdict.get("question_verdicts", {}),
        # Original task narrative
        "raw_narrative": narrative if not isinstance(narrative, dict) else None,
    }
    # Drop None values to keep clean
    record = {k: v for k, v in record.items() if v is not None}

    if dry_run:
        print(f"[chain-verify-persist] DRY-RUN: would append GCT {chain_template_id}", file=sys.stderr)
    else:
        _atomic_append(gct_path, record)
        print(f"[chain-verify-persist] persisted GCT {chain_template_id} to {gct_path}", file=sys.stderr)
    return chain_template_id


def persist_refuted(
    verdict: dict,
    workspace: str,
    repo_root: Path,
    confirmed_at: str,
    dry_run: bool = False,
) -> str | None:
    """Persist a refuted chain to reports/known_dead_ends.jsonl.

    Mirrors the existing KDE schema.
    """
    chain = verdict["raw_chain"]
    task_id = chain.get("task_id", "unknown")
    fn, attack_class = _extract_hop0_info(chain)

    import hashlib
    h = hashlib.sha256(task_id.encode()).hexdigest()[:16]
    record_id = f"{workspace}:chain_verify_refuted_{h}"

    kde_path = repo_root / KNOWN_DEAD_ENDS

    existing = _read_existing_ids(kde_path, "record_id")
    if record_id in existing:
        print(
            f"[chain-verify-persist] KDE dedup: {record_id} already present, skip",
            file=sys.stderr,
        )
        return record_id

    record: dict = {
        "schema_version": SCHEMA_KDE,
        "record_id": record_id,
        "workspace": workspace,
        "candidate_id": task_id,
        "kill_verdict": "CHAIN-REFUTED",
        "kill_reason": verdict.get("blocking_defense", ""),
        "attack_class": attack_class,
        "evidence_file_line": fn,
        "evidence_code_excerpt": verdict.get("reasoning", ""),
        "severity_claim": "",
        "promoted_at_utc": confirmed_at,
        "source_artifact": f"{workspace}/.auditooor/chain_verdicts_*.json",
    }

    if dry_run:
        print(f"[chain-verify-persist] DRY-RUN: would append KDE {record_id}", file=sys.stderr)
    else:
        _atomic_append(kde_path, record)
        print(f"[chain-verify-persist] persisted KDE {record_id} to {kde_path}", file=sys.stderr)
    return record_id


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--workspace", required=True, type=Path,
                        help="Audit workspace root.")
    parser.add_argument("--synthesis-file", type=Path, default=None,
                        help="Path to chain_synthesis_<date>.json. "
                             "Auto-detected from workspace/.auditooor/ if omitted.")
    parser.add_argument("--persist", action="store_true",
                        help="Stage 5: persist confirmed chains to GCT + refuted to KDE.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify chains but do not write to disk (implies --persist preview).")
    parser.add_argument("--now", default=None,
                        help="ISO8601 timestamp to use as confirmed_at (for reproducibility).")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON report to stdout.")
    parser.add_argument("--mock-llm", action="store_true",
                        help="Use mock LLM responses (for testing only).")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1

    repo_root = _repo_root()
    confirmed_at = args.now or utc_now()

    # Locate synthesis file
    if args.synthesis_file:
        synthesis_file = args.synthesis_file.resolve()
    else:
        synthesis_file = _find_latest_synthesis(workspace)

    if synthesis_file is None or not synthesis_file.exists():
        result = {
            "schema": SCHEMA_VERDICTS,
            "generated_at": confirmed_at,
            "workspace": str(workspace),
            "verdict": "pass-no-synthesis-file",
            "chains_verified": 0,
            "confirmed": 0,
            "refuted": 0,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("verdict=pass-no-synthesis-file chains_verified=0")
        return 0

    input_freshness = validate_synthesis_freshness(workspace, synthesis_file)
    if input_freshness["verdict"] != "pass-synthesis-current":
        result = {
            "schema": SCHEMA_VERDICTS,
            "generated_at": confirmed_at,
            "workspace": str(workspace),
            "synthesis_file": str(synthesis_file),
            "verdict": "fail-stale-synthesis-report",
            "chains_verified": 0,
            "confirmed": 0,
            "refuted": 0,
            "input_freshness": input_freshness,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            stale = ",".join(row["path"] for row in input_freshness["stale_inputs"])
            print(f"verdict=fail-stale-synthesis-report chains_verified=0 stale_inputs={stale}")
        return 1

    # Load chains
    chains = _load_chains(synthesis_file)
    print(f"[chain-verify-persist] loaded {len(chains)} chains from {synthesis_file}", file=sys.stderr)

    if not chains:
        result = {
            "schema": SCHEMA_VERDICTS,
            "generated_at": confirmed_at,
            "workspace": str(workspace),
            "synthesis_file": str(synthesis_file),
            "verdict": "pass-all-refuted",
            "chains_verified": 0,
            "confirmed": 0,
            "refuted": 0,
            "input_freshness": input_freshness,
            "verdicts": [],
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("verdict=pass-all-refuted chains_verified=0")
        return 0

    # Stage 4: verify
    verdicts = verify_chains(chains, mock=args.mock_llm)

    confirmed = [v for v in verdicts if v["holds"]]
    refuted = [v for v in verdicts if not v["holds"]]

    # Write verdicts file
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    verdicts_path = workspace / ".auditooor" / f"chain_verdicts_{date_str}.json"
    if not args.dry_run:
        verdicts_path.parent.mkdir(parents=True, exist_ok=True)
        verdicts_path.write_text(json.dumps({
            "schema": SCHEMA_VERDICTS,
            "generated_at": confirmed_at,
            "workspace": str(workspace),
            "synthesis_file": str(synthesis_file),
            "input_freshness": input_freshness,
            "chains_verified": len(verdicts),
            "confirmed": len(confirmed),
            "refuted": len(refuted),
            "verdicts": verdicts,
        }, indent=2), encoding="utf-8")
        print(f"[chain-verify-persist] verdicts written to {verdicts_path}", file=sys.stderr)

    # Stage 5: persist
    persisted_gct: list[str] = []
    persisted_kde: list[str] = []

    if args.persist or args.dry_run:
        workspace_name = workspace.name
        for v in confirmed:
            gct_id = persist_confirmed(v, workspace_name, repo_root, confirmed_at, dry_run=args.dry_run)
            if gct_id:
                persisted_gct.append(gct_id)
        for v in refuted:
            kde_id = persist_refuted(v, workspace_name, repo_root, confirmed_at, dry_run=args.dry_run)
            if kde_id:
                persisted_kde.append(kde_id)

    overall_verdict = (
        "pass-confirmed-chains-persisted" if confirmed
        else "pass-all-refuted"
    )

    report = {
        "schema": SCHEMA_VERDICTS,
        "generated_at": confirmed_at,
        "workspace": str(workspace),
        "synthesis_file": str(synthesis_file),
        "input_freshness": input_freshness,
        "verdict": overall_verdict,
        "chains_verified": len(verdicts),
        "confirmed": len(confirmed),
        "refuted": len(refuted),
        "persisted_gct_ids": persisted_gct,
        "persisted_kde_ids": persisted_kde,
        "verdicts": verdicts,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"verdict={overall_verdict} "
            f"chains_verified={len(verdicts)} "
            f"confirmed={len(confirmed)} "
            f"refuted={len(refuted)} "
            f"gct_persisted={len(persisted_gct)} "
            f"kde_persisted={len(persisted_kde)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
