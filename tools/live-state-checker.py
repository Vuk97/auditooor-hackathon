#!/usr/bin/env python3
"""
live-state-checker.py — Verify findings against live on-chain state

Reads contract state from mainnet (or specified RPC) and checks if a
vulnerability condition is present. Critical for findings that depend on
live deployment state (e.g., missing roles, incorrect config).

Usage:
    live-state-checker.py --address <0x...> --network mainnet
    live-state-checker.py --address <0x...> --network polygon --rpc-url https://...
    live-state-checker.py --address <0x...> --call "isAdmin(address)(bool)" --args 0x1234... --expect true
    live-state-checker.py --address <0x...> --slot <storage-slot> --expect <value>
    live-state-checker.py --workspace ~/audits/polymarket --address <0x...> --network polygon --call "paused()(bool)" --expect false

Environment:
    Set MAINNET_RPC_URL / POLYGON_RPC_URL / ... or point --workspace at a
    workspace with .env files. Falls back to public RPCs only when no private
    endpoint is configured.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def log(message: str, *, json_mode: bool = False) -> None:
    """Route human logs to stderr when JSON mode is active."""
    print(message, file=sys.stderr if json_mode else sys.stdout)


def resolve_cast() -> str:
    """Resolve cast binary."""
    for candidate in ["cast", os.path.expanduser("~/.foundry/bin/cast")]:
        if os.path.isabs(candidate) and os.path.exists(candidate):
            return candidate
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    print("[live] cast not found. Install Foundry.")
    sys.exit(1)


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse a simple KEY=VALUE env file without mutating process env."""
    values: Dict[str, str] = {}
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key:
                values[key] = value
    except OSError:
        pass
    return values


def load_workspace_env(workspace: Path) -> Dict[str, str]:
    """Load likely workspace-local env files."""
    env: Dict[str, str] = {}
    candidates = [
        workspace / ".env",
        workspace / ".env.local",
        workspace / "env" / ".env",
        workspace / "env" / ".env.local",
    ]
    env_dir = workspace / "env"
    if env_dir.is_dir():
        candidates.extend(sorted(env_dir.glob("*.env")))
    for candidate in candidates:
        if candidate.is_file():
            env.update(parse_env_file(candidate))
    return env


def get_rpc_url(network: str, *, explicit: str = "", env: Dict[str, str] | None = None) -> Tuple[str, str]:
    """Get RPC URL for network, returning (url, source)."""
    if explicit:
        return explicit, "flag"

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    env_map = {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }
    env_key = env_map.get(network.lower(), f"{network.upper()}_RPC_URL")
    url = merged_env.get(env_key)
    if url:
        source = "workspace-env" if env and env_key in env else "env"
        return url, f"{source}:{env_key}"
    # Fallback public RPCs (rate-limited, for testing only)
    public = {
        "mainnet": "https://rpc.ankr.com/eth",
        "polygon": "https://polygon.drpc.org",
        "arbitrum": "https://rpc.ankr.com/arbitrum",
        "optimism": "https://rpc.ankr.com/optimism",
        "base": "https://rpc.ankr.com/base",
    }
    url = public.get(network.lower(), "")
    return (url, "public-fallback") if url else ("", "")


def run_cast(cast_bin: str, rpc: str, *args, block: str = "") -> Tuple[int, str]:
    """Run cast with RPC. RPC flag goes AFTER subcommand for cast 1.5.x."""
    cmd = [cast_bin]
    cmd.extend(args)
    if block:
        cmd.extend(["--block", block])
    if rpc:
        cmd.extend(["--rpc-url", rpc])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout.strip() if result.returncode == 0 else result.stderr.strip()


def resolve_block(cast_bin: str, rpc: str, block: str, *, dry_run: bool) -> Optional[str]:
    """Resolve a concrete block number for this proof when possible."""
    if block:
        return block
    if dry_run:
        return None
    rc, output = run_cast(cast_bin, rpc, "block-number")
    if rc != 0 or not output.strip():
        return None
    return output.strip()


def parse_call_args(raw: str | None) -> List[str]:
    """Parse CLI call args into cast-ready positional arguments."""
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def normalize_value(value: str) -> str:
    """Normalize values before comparison so replay artifacts show exact semantics."""
    return value.strip().lower()


def compare_values(actual: str, expected: str, comparator: str) -> tuple[bool, Dict[str, Any]]:
    """Compare actual vs expected and preserve the exact semantics used."""
    actual_norm = normalize_value(actual)
    expected_norm = normalize_value(expected)
    meta: Dict[str, Any] = {
        "actual_raw": actual,
        "expected_raw": expected,
        "actual_normalized": actual_norm,
        "expected_normalized": expected_norm,
        "comparator": comparator,
        "normalization": ["strip", "lower"],
    }
    if comparator == "exact":
        return actual_norm == expected_norm, meta
    if comparator == "contains":
        return expected_norm in actual_norm, meta
    if comparator == "gte":
        try:
            return int(actual.strip()) >= int(expected.strip()), meta
        except ValueError:
            meta["comparison_error"] = "non-integer value for gte"
            return False, meta
    meta["comparison_error"] = f"unknown comparator: {comparator}"
    return False, meta


def check_call(cast_bin: str, rpc: str, address: str, call_sig: str, call_args: List[str], expected: str,
               *, json_mode: bool = False, dry_run: bool = False, block: str = "") -> Dict[str, Any]:
    """Check if a view function returns expected value."""
    if dry_run:
        preview = " ".join([cast_bin, "call", address, call_sig, *call_args]).strip()
        if block:
            preview += f" --block {block}"
        log(f"[live] Dry-run call: {preview}", json_mode=json_mode)
        return {
            "match": False,
            "actual": None,
            "expected": expected,
            "comparator": "contains",
            "execution_mode": "dry_run",
            "command_preview": preview,
        }
    rc, output = run_cast(cast_bin, rpc, "call", address, call_sig, *call_args, block=block)
    if rc != 0:
        log(f"[live] Call failed: {output}", json_mode=json_mode)
        return {
            "match": False,
            "actual": None,
            "expected": expected,
            "comparator": "contains",
            "execution_mode": "executed",
            "error": output,
        }
    log(f"[live] Result: {output}", json_mode=json_mode)
    comparator = "exact" if normalize_value(output) == normalize_value(expected) else "contains"
    match, meta = compare_values(output, expected, comparator)
    return {
        "match": match,
        "actual": output,
        "expected": expected,
        "comparator": comparator,
        "execution_mode": "executed",
        **meta,
    }


def check_slot(cast_bin: str, rpc: str, address: str, slot: str, expected: str,
               *, json_mode: bool = False, block: str = "") -> Dict[str, Any]:
    """Check if a storage slot matches expected value."""
    rc, output = run_cast(cast_bin, rpc, "storage", address, slot, block=block)
    if rc != 0:
        log(f"[live] Storage read failed: {output}", json_mode=json_mode)
        return {
            "match": False,
            "actual": None,
            "expected": expected,
            "comparator": "contains",
            "execution_mode": "executed",
            "error": output,
        }
    log(f"[live] Slot {slot}: {output}", json_mode=json_mode)
    match, meta = compare_values(output, expected, "contains")
    return {
        "match": match,
        "actual": output,
        "expected": expected,
        "comparator": "contains",
        "execution_mode": "executed",
        **meta,
    }


def check_balance(cast_bin: str, rpc: str, address: str, expected_min: str,
                  *, json_mode: bool = False, block: str = "") -> Dict[str, Any]:
    """Check if contract balance meets minimum."""
    rc, output = run_cast(cast_bin, rpc, "balance", address, block=block)
    if rc != 0:
        log(f"[live] Balance check failed: {output}", json_mode=json_mode)
        return {
            "match": False,
            "actual": None,
            "expected": expected_min,
            "comparator": "gte",
            "execution_mode": "executed",
            "error": output,
        }
    log(f"[live] Balance: {output} wei", json_mode=json_mode)
    match, meta = compare_values(output, expected_min, "gte")
    return {
        "match": match,
        "actual": output,
        "expected": expected_min,
        "comparator": "gte",
        "execution_mode": "executed",
        **meta,
    }


def build_replay_command(
    *,
    script_name: str,
    address: str,
    workspace: str,
    network: str,
    rpc_url: str,
    block: str,
    call_sig: str = "",
    call_args: Optional[List[str]] = None,
    expect: str = "",
    slot: str = "",
    balance_min: str = "",
) -> str:
    """Build a replayable command line for this proof."""
    parts: List[str] = [shlex.quote(script_name)]
    parts.extend(["--address", shlex.quote(address)])
    if workspace:
        parts.extend(["--workspace", shlex.quote(workspace)])
    if network:
        parts.extend(["--network", shlex.quote(network)])
    if rpc_url:
        parts.extend(["--rpc-url", shlex.quote(rpc_url)])
    if block:
        parts.extend(["--block", shlex.quote(block)])
    if call_sig:
        parts.extend(["--call", shlex.quote(call_sig)])
    if call_args:
        parts.extend(["--args", shlex.quote(",".join(call_args))])
    if expect:
        parts.extend(["--expect", shlex.quote(expect)])
    if slot:
        parts.extend(["--slot", shlex.quote(slot)])
    if balance_min:
        parts.extend(["--balance-min", shlex.quote(balance_min)])
    parts.append("--json")
    return " ".join(parts)


def sanitize_proof_id(raw: str) -> str:
    """Make a proof id safe for deterministic workspace file paths."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw.strip())
    return cleaned.strip("-._")


def build_manual_proof_payload(
    *,
    workspace: str,
    proof_id: str,
    result: Dict[str, Any],
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Wrap a single manual proof in a dossier-like advisory envelope."""
    checks = result.get("checks") or []
    check = checks[0] if checks else {}
    status = "dry_run" if result.get("dry_run") else (
        "error" if check.get("error") else ("pass" if check.get("match") else "fail")
    )
    return {
        "workspace": str(Path(workspace).expanduser().resolve()),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "advisory_only": True,
        "canonical_dossier": "live_topology_checks.json",
        "summary": {
            "result_count": 1,
            "pass": 1 if status == "pass" else 0,
            "fail": 1 if status == "fail" else 0,
            "dry_run": 1 if status == "dry_run" else 0,
            "error": 1 if status == "error" else 0,
        },
        "results": [
            {
                "id": proof_id,
                "status": status,
                "title": metadata.get("title") or proof_id,
                "contract": metadata.get("contract_name") or result.get("address"),
                "address": result.get("address"),
                "network": result.get("network"),
                "block": result.get("block"),
                "expected": check.get("expected"),
                "actual": check.get("actual"),
                "comparator": check.get("comparator"),
                "execution_mode": check.get("execution_mode"),
                "command": check.get("command", []),
                "rpc_source": result.get("rpc_source"),
                "evidence_class": metadata.get("evidence_class") or "manual-proof",
                "related_angle_ids": metadata.get("related_angle_ids", []),
                "rationale": metadata.get("rationale"),
                "implication_if_match": metadata.get("implication_if_match"),
                "pair_id": metadata.get("pair_id"),
                "proof_pair_id": metadata.get("proof_pair_id"),
                "replay_command": result.get("replay_command"),
                "live_result": check,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Live on-chain state checker")
    parser.add_argument("--address", required=True, help="Contract address")
    parser.add_argument("--workspace", help="Workspace root to load .env RPC settings from")
    parser.add_argument("--network", default="mainnet", help="Network name")
    parser.add_argument("--rpc-url", help="Explicit RPC URL (overrides env and workspace .env)")
    parser.add_argument("--block", help="Pinned block number for reproducible proof")
    parser.add_argument("--call", help="Function call signature (e.g., 'isAdmin(address)(bool)')")
    parser.add_argument("--args", help="Call arguments (comma-separated, passed after the signature)")
    parser.add_argument("--expect", help="Expected result substring")
    parser.add_argument("--slot", help="Storage slot to read")
    parser.add_argument("--balance-min", help="Minimum balance in wei")
    parser.add_argument("--dry-run", action="store_true", help="Print the planned live check without hitting RPC")
    parser.add_argument("--out-json", help="Optional file path to persist JSON proof output")
    parser.add_argument("--save-workspace-proof",
                        help="Persist this one-off proof under <workspace>/manual_proofs/<id>.json (advisory only)")
    parser.add_argument("--contract-name", help="Semantic contract label to store with a saved workspace proof")
    parser.add_argument("--title", help="Human title to store with a saved workspace proof")
    parser.add_argument("--evidence-class", help="Evidence class to store with a saved workspace proof")
    parser.add_argument("--related-angle-id", action="append",
                        help="Repeatable angle id to store with a saved workspace proof")
    parser.add_argument("--pair-id", help="Proof-pair id to store with a saved workspace proof")
    parser.add_argument("--proof-pair-id", help="Explicit proof pair id to store with a saved workspace proof")
    parser.add_argument("--rationale", help="Rationale text to store with a saved workspace proof")
    parser.add_argument("--implication-if-match",
                        help="Implication text to store with a saved workspace proof")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    if args.save_workspace_proof and not args.workspace:
        print("[live] --workspace is required with --save-workspace-proof")
        sys.exit(1)
    if args.save_workspace_proof and not (args.call or args.slot or args.balance_min):
        print("[live] --save-workspace-proof requires --call, --slot, or --balance-min")
        sys.exit(1)
    safe_proof_id = sanitize_proof_id(args.save_workspace_proof or "")
    if args.save_workspace_proof and not safe_proof_id:
        print("[live] --save-workspace-proof must contain at least one alphanumeric character")
        sys.exit(1)

    cast_bin = resolve_cast()
    workspace_env: Dict[str, str] = {}
    if args.workspace:
        workspace_env = load_workspace_env(Path(args.workspace).expanduser().resolve())
    rpc, rpc_source = get_rpc_url(args.network, explicit=args.rpc_url or "", env=workspace_env)
    if not rpc and not args.dry_run:
        print(f"[live] No RPC URL for {args.network}. Set {args.network.upper()}_RPC_URL.")
        sys.exit(1)
    resolved_block = resolve_block(cast_bin, rpc, args.block or "", dry_run=args.dry_run)

    log(f"[live] Checking {args.address} on {args.network}", json_mode=args.json)
    if rpc:
        log(f"[live] RPC source: {rpc_source}", json_mode=args.json)
        log(f"[live] RPC: {rpc[:40]}...", json_mode=args.json)
    elif args.dry_run:
        log("[live] Dry-run mode: RPC not required", json_mode=args.json)

    result = {
        "address": args.address,
        "network": args.network,
        "rpc_source": rpc_source,
        "dry_run": args.dry_run,
        "block": resolved_block,
        "checks": [],
    }

    vulnerable = False

    if args.call:
        call_sig = args.call
        call_args = parse_call_args(args.args)
        rendered_call = " ".join([call_sig, *call_args]).strip()
        log(f"[live] Calling: {rendered_call}", json_mode=args.json)
        match = check_call(cast_bin, rpc, args.address, call_sig, call_args, args.expect or "",
                           json_mode=args.json, dry_run=args.dry_run, block=resolved_block or "")
        result["checks"].append({
            "type": "call",
            "sig": call_sig,
            "args": call_args,
            **match,
            "dry_run": args.dry_run,
            "block": resolved_block,
            "command": [cast_bin, "call", args.address, call_sig, *call_args],
        })
        result["replay_command"] = build_replay_command(
            script_name=sys.argv[0],
            address=args.address,
            workspace=args.workspace or "",
            network=args.network,
            rpc_url=args.rpc_url or "",
            block=resolved_block or "",
            call_sig=call_sig,
            call_args=call_args,
            expect=args.expect or "",
        )
        vulnerable = bool(match.get("match"))

    if args.slot:
        log(f"[live] Reading slot: {args.slot}", json_mode=args.json)
        match = check_slot(cast_bin, rpc, args.address, args.slot, args.expect or "",
                           json_mode=args.json, block=resolved_block or "")
        result["checks"].append({"type": "slot", "slot": args.slot, **match, "block": resolved_block})
        result["replay_command"] = build_replay_command(
            script_name=sys.argv[0],
            address=args.address,
            workspace=args.workspace or "",
            network=args.network,
            rpc_url=args.rpc_url or "",
            block=resolved_block or "",
            slot=args.slot,
            expect=args.expect or "",
        )
        vulnerable = bool(match.get("match"))

    if args.balance_min:
        log(f"[live] Checking balance >= {args.balance_min}", json_mode=args.json)
        match = check_balance(cast_bin, rpc, args.address, args.balance_min,
                              json_mode=args.json, block=resolved_block or "")
        result["checks"].append({"type": "balance", "min": args.balance_min, **match, "block": resolved_block})
        result["replay_command"] = build_replay_command(
            script_name=sys.argv[0],
            address=args.address,
            workspace=args.workspace or "",
            network=args.network,
            rpc_url=args.rpc_url or "",
            block=resolved_block or "",
            balance_min=args.balance_min,
        )
        vulnerable = bool(match.get("match"))

    result["vulnerable"] = vulnerable

    if args.save_workspace_proof:
        manual_metadata = {
            "contract_name": args.contract_name or "",
            "title": args.title or "",
            "evidence_class": args.evidence_class or "",
            "related_angle_ids": [item.strip() for item in (args.related_angle_id or []) if item.strip()],
            "pair_id": args.pair_id or "",
            "proof_pair_id": args.proof_pair_id or args.pair_id or "",
            "rationale": args.rationale or "",
            "implication_if_match": args.implication_if_match or "",
        }
        manual_payload = build_manual_proof_payload(
            workspace=args.workspace,
            proof_id=safe_proof_id,
            result=result,
            metadata=manual_metadata,
        )
        proof_path = (
            Path(args.workspace).expanduser().resolve() / "manual_proofs" / f"{safe_proof_id}.json"
        )
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        proof_path.write_text(json.dumps(manual_payload, indent=2) + "\n")
        result["workspace_proof_json"] = str(proof_path)
        result["workspace_proof_id"] = safe_proof_id
        result["workspace_proof_advisory_only"] = True

    if args.out_json:
        out_path = Path(args.out_json).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        result["out_json"] = str(out_path)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*50}")
        if args.save_workspace_proof:
            print(f"[live] Saved advisory workspace proof: {result['workspace_proof_json']}")
        if args.dry_run:
            print("📝 DRY RUN ONLY — no live RPC call executed")
            print("Use the printed call details to verify the topology check wiring.")
        elif vulnerable:
            print("✅ VULNERABLE STATE CONFIRMED ON-CHAIN")
            print("This is a STRONG finding — live deployment is actually broken.")
        else:
            print("❌ Vulnerable state NOT confirmed")
            print("The condition may not be present in current on-chain state.")
        print(f"{'='*50}")

    sys.exit(0 if vulnerable or args.dry_run else 1)


if __name__ == "__main__":
    main()
