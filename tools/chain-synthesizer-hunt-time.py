#!/usr/bin/env python3
"""Chain synthesizer for hunt-time attack path discovery.

Combines CCIA per-function attack angles, vault_hackerman chain candidates,
and the workspace contract graph to synthesize compound attack chains.

Output: JSONL with {chain_id, steps:[{function,attack_class,file_path}],
        pre_conditions, post_conditions, impact_estimate}.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_ID = "auditooor.chain_synthesized.v1"
CCIA_FILE = "ccia_attack_angles.json"
CHAIN_CANDIDATES_FILE = "vault_hackerman_chain_candidates.json"
CONTRACT_GRAPH_FILE = "contract_graph.json"
DEFAULT_MAX_CHAINS = 10
DEFAULT_MAX_DEPTH = 4
IMPACT_LEVELS = ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def emit_record(record: dict, out_fh: Any) -> None:
    out_fh.write(json.dumps(record, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_ccia_angles(workspace: Path) -> list[dict]:
    """Load per-function attack angles from CCIA output."""
    data = load_json(workspace / CCIA_FILE)
    # TODO: normalize into [{function, attack_class, file_path, severity}]
    return data if isinstance(data, list) else []


def load_chain_candidates(workspace: Path) -> list[dict]:
    """Load seed chain candidates from vault_hackerman."""
    data = load_json(workspace / CHAIN_CANDIDATES_FILE)
    # TODO: normalize into [{id, steps:[fn_name,...], rationale}]
    return data if isinstance(data, list) else []


def load_contract_graph(workspace: Path) -> dict:
    """Load workspace contract graph (adjacency / call edges)."""
    data = load_json(workspace / CONTRACT_GRAPH_FILE)
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Synthesis engine (skeleton)
# ---------------------------------------------------------------------------

def synthesize_chains(
    ccia_angles: list[dict],
    chain_seeds: list[dict],
    graph: dict,
    max_chains: int,
    max_depth: int,
) -> list[dict]:
    """Produce compound attack chains by merging seeds with CCIA angles.

    TODO inner logic:
      1. For each seed, validate steps exist in graph.
      2. Enrich each step with attack_class from ccia_angles lookup.
      3. Expand chains up to max_depth using graph reachability.
      4. Score / rank by impact_estimate and deduplicate.
      5. Return top max_chains results.
    """
    chains: list[dict] = []
    # --- PLACEHOLDER: real synthesis goes here ---
    for seed in chain_seeds[:max_chains]:
        steps_raw = seed.get("steps", [])[:max_depth]
        steps = []
        for fn in steps_raw:
            match = next((a for a in ccia_angles if a.get("function") == fn), {})
            steps.append({
                "function": fn,
                "attack_class": match.get("attack_class", "unknown"),
                "file_path": match.get("file_path", "unknown"),
            })
        if not steps:
            continue
        chains.append({
            "chain_id": f"chain-{seed.get('id', len(chains)):04d}",
            "steps": steps,
            "pre_conditions": seed.get("pre_conditions", []),
            "post_conditions": seed.get("post_conditions", []),
            "impact_estimate": seed.get("impact_estimate", "medium"),
        })
    return chains


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Synthesize compound attack chains at hunt time.",
    )
    p.add_argument(
        "--workspace", required=True, type=Path,
        help="Path to the auditooor workspace directory.",
    )
    p.add_argument(
        "--max-chains", type=int, default=DEFAULT_MAX_CHAINS,
        help=f"Maximum chains to emit (default {DEFAULT_MAX_CHAINS}).",
    )
    p.add_argument(
        "--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
        help=f"Maximum steps per chain (default {DEFAULT_MAX_DEPTH}).",
    )
    p.add_argument(
        "--output", type=Path, default=None,
        help="Output JSONL file (default: stdout).",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    if not args.workspace.is_dir():
        print(f"error: workspace not found: {args.workspace}", file=sys.stderr)
        return 1

    ccia = load_ccia_angles(args.workspace)
    seeds = load_chain_candidates(args.workspace)
    graph = load_contract_graph(args.workspace)

    if not seeds:
        print("warning: no chain candidates loaded", file=sys.stderr)

    chains = synthesize_chains(ccia, seeds, graph, args.max_chains, args.max_depth)

    out_fh = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    meta = {
        "schema_id": SCHEMA_ID,
        "generated_at": utc_now(),
        "workspace": str(args.workspace.resolve()),
        "chain_count": len(chains),
        "max_depth": args.max_depth,
    }
    emit_record(meta, out_fh)
    for chain in chains:
        emit_record(chain, out_fh)

    if args.output:
        out_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
