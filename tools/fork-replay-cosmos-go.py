#!/usr/bin/env python3
"""fork-replay-cosmos-go.py — Cosmos/Go workspace fork-replay branch for audit-deep.

Detects whether the target workspace has a Cosmos/Go shape (presence of go.mod,
app/app.go, or cmd/*/main.go) and, when detected, emits a stub
``<workspace>/fork_replay/cosmos_go_<sha>.json`` packet that documents the
recommended forge fork-replay posture for this workspace type.

This is the symbolic equivalent of the Solidity fork-replay harness for Cosmos
SDK / Go-based chains.  The stub packet is consumed by audit-deep Step 5
reviewers and by any downstream fork-replay-assert gate.

Usage (key forms)::

  # Auto-detect + hermetic stub emit:
  python3 tools/fork-replay-cosmos-go.py --hermetic --workspace ~/audits/dydx --finding-id FN1

  # Dry-run (print plan, write nothing):
  python3 tools/fork-replay-cosmos-go.py --dry-run --workspace ~/audits/dydx --finding-id DEMO

  # Non-Cosmos workspace (exits 0, skips cleanly):
  python3 tools/fork-replay-cosmos-go.py --hermetic --workspace ~/audits/base-azul --finding-id FN2

Exit codes::
  0  success / dry-run printed / no Cosmos shape detected (always skips cleanly)
  2  usage error (missing required argument)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Schema constant
# ---------------------------------------------------------------------------
SCHEMA = "auditooor.fork_replay_cosmos_go.v1"

# Cosmos/Go shape indicators — at least one must exist under the workspace root
_COSMOS_SHAPE_CANDIDATES = [
    "go.mod",
    "app/app.go",
]

# Glob pattern for cmd/*/main.go (checked separately)
_CMD_MAIN_GLOB = "cmd/*/main.go"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_cosmos_go_shape(workspace: Path) -> list[str]:
    """Return the list of Cosmos/Go shape indicators found under *workspace*.

    Returns an empty list when the workspace has no recognised Cosmos/Go shape.
    """
    found: list[str] = []
    for rel in _COSMOS_SHAPE_CANDIDATES:
        if (workspace / rel).exists():
            found.append(rel)
    # Check cmd/*/main.go via glob
    for p in workspace.glob(_CMD_MAIN_GLOB):
        rel = str(p.relative_to(workspace))
        if rel not in found:
            found.append(rel)
    return found


def _sha_from_workspace(workspace: Path) -> str:
    """Derive a short deterministic hash from the workspace path string."""
    return hashlib.sha256(str(workspace).encode()).hexdigest()[:12]


def _output_path(workspace: Path, finding_id: str) -> Path:
    """Return the path for the output JSON packet."""
    sha = _sha_from_workspace(workspace)
    fname = f"cosmos_go_{sha}.json"
    if finding_id and finding_id != "NONE":
        fname = f"cosmos_go_{finding_id}_{sha}.json"
    return workspace / "fork_replay" / fname


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def run(workspace: Path, finding_id: str, hermetic: bool, dry_run: bool) -> int:
    """Main entry point.  Returns an exit code (0 = ok/skip, 2 = usage error)."""
    tag = "[fork-replay-cosmos-go]"

    shape = detect_cosmos_go_shape(workspace)

    if not shape:
        print(
            f"{tag} no Cosmos/Go shape detected under {workspace}; skipping",
            flush=True,
        )
        return 0

    print(f"{tag} detected Cosmos/Go shape: {shape}", flush=True)

    out_path = _output_path(workspace, finding_id)
    packet = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "finding_id": finding_id,
        "detected_shape": shape,
        "recommendation": (
            "forge fork-replay against fork-pinned upstream; "
            "use `make fork-replay WS=<workspace> FN=<finding-id> HERMETIC=1` "
            "as symbolic equivalent for Cosmos/Go audits"
        ),
        "status": "stub",
        "notes": (
            "Cosmos/Go workspaces do not have Solidity contracts for anvil fork-replay. "
            "The canonical symbolic equivalent is to replay the audited chain state "
            "against the fork-pinned upstream Go module tree via vanilla `go test`. "
            "See docs/COSMOS_BACKEND.md for the full posture."
        ),
    }

    if dry_run:
        print(f"{tag} DRY-RUN — would write packet to: {out_path}", flush=True)
        print(f"{tag} DRY-RUN packet preview:", flush=True)
        print(json.dumps(packet, indent=2), flush=True)
        return 0

    if not hermetic:
        # In non-hermetic mode we still emit the stub (it's always advisory).
        print(
            f"{tag} non-hermetic mode: emitting advisory stub (no live RPC involved)",
            flush=True,
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    print(f"{tag} wrote packet: {out_path}", flush=True)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fork-replay-cosmos-go.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workspace",
        default=".",
        help="Path to the audit workspace root (default: current directory).",
    )
    p.add_argument(
        "--finding-id",
        default="NONE",
        metavar="ID",
        help="Finding identifier used in the output filename (default: NONE).",
    )
    p.add_argument(
        "--hermetic",
        action="store_true",
        help="Run in hermetic mode (no live RPC; produce stub artifact for CI).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned action and exit without writing any files.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Reserved for future use.  Currently a no-op: non-Cosmos workspaces "
            "always exit 0 (skip) regardless of this flag."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()

    return run(
        workspace=workspace,
        finding_id=args.finding_id,
        hermetic=args.hermetic,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
