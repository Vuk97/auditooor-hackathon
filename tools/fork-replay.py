#!/usr/bin/env python3
"""fork-replay.py — standardized fork-replay harness for Critical/High PoCs.

Wraps `anvil --fork-url <rpc> --fork-block-number N` with protocol-aware
state overrides, tx replay, and assertion evaluation. Captures all output
to `<workspace>/poc_execution/<finding_id>/replay_<sha>.{log,json}` and
updates `<finding_id>.execution_manifest.json`. When a live replay has a
pinned executed block and proof-grade PASS assertions, it also emits a
Check-22-compatible semantic bundle under `<workspace>/fork_replay/`.

M14-trap discipline: every stub is declared-scope only; gaps are honest.
No real RPC dependency required for --hermetic or --dry-run paths.

Usage (key forms):
  # Hermetic self-test (no external RPC, no anvil):
  python3 tools/fork-replay.py --hermetic --finding-id TEST \\
    --override-contract OptimismPortal=detectors/_fixtures/replay_harness/OptimismPortalStub.sol

  # Dry-run (print planned commands, no anvil):
  python3 tools/fork-replay.py --dry-run --network mainnet --block 21500000 \\
    --replay-tx 0xabc123 --finding-id DEMO

  # Live (requires anvil + RPC):
  python3 tools/fork-replay.py --workspace ~/audits/base-azul \\
    --recipe tools/fork-replay-recipe.yaml --protocol optimism \\
    --finding-id FN2 --replay-tx 0xabc123 \\
    --assert "attacker_gain > 0"

Exit codes:
  0  success / dry-run printed / hermetic artifact written
  1  assertion FAIL or recipe load error
  2  usage error
  3  anvil/cast dependency missing (live mode only)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------
MANIFEST_SCHEMA = "auditooor.fork_replay_manifest.v1"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fork-replay.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = p.add_argument_group("Mode (pick one)")
    m = mode.add_mutually_exclusive_group()
    m.add_argument("--hermetic", action="store_true",
                   help="Run in hermetic mode: no real anvil/RPC; produce a "
                        "synthetic replay artifact for CI validation.")
    m.add_argument("--dry-run", action="store_true",
                   help="Print planned commands without executing anvil.")

    p.add_argument("--workspace", metavar="DIR",
                   help="Audit workspace root. Replay artifacts go to "
                        "<workspace>/poc_execution/<finding-id>/. "
                        "Defaults to cwd.")
    p.add_argument("--finding-id", metavar="ID", required=True,
                   help="Finding identifier (e.g. FN2, TEST). Used as the "
                        "output directory name.")

    net = p.add_argument_group("Network / fork target")
    net.add_argument("--network", metavar="NAME",
                     help="Protocol network (mainnet|arbitrum|optimism|…). "
                          "Used to look up defaults from recipe YAML.")
    net.add_argument("--rpc", metavar="URL",
                     help="RPC URL override. Falls back to recipe / env var "
                          "ALCHEMY_<NETWORK>_RPC_URL.")
    net.add_argument("--block", metavar="N", type=int,
                     help="Fork block number. Falls back to recipe default.")
    net.add_argument("--protocol", metavar="NAME",
                     help="Protocol name (optimism|arbitrum|layerzero|…). "
                          "Selects recipe entry and default overrides.")
    net.add_argument("--recipe", metavar="FILE",
                     help="Path to fork-replay-recipe.yaml. "
                          "Defaults to tools/fork-replay-recipe.yaml next to "
                          "this script.")

    override = p.add_argument_group("State overrides")
    override.add_argument("--override-contract", metavar="NAME=PATH",
                          action="append", default=[],
                          help="Replace a deployed contract with a local stub "
                               "source. Format: ContractName=path/to/Stub.sol "
                               "May be repeated.")

    replay = p.add_argument_group("Replay and assertion")
    replay.add_argument("--replay-tx", metavar="TXHASH",
                        help="Transaction hash to replay via `cast run`.")
    replay.add_argument("--assert", metavar="EXPR", dest="assert_expr",
                        help="Assertion expression evaluated after replay "
                             "(uses cast call). Example: 'attacker_gain > 0'")

    p.add_argument("--verbose", action="store_true",
                   help="Print subprocess output to stderr.")
    return p


# ---------------------------------------------------------------------------
# Recipe loader
# ---------------------------------------------------------------------------

def _default_recipe_path() -> Path:
    return Path(__file__).parent / "fork-replay-recipe.yaml"


def load_recipe(recipe_path: Path | None, protocol: str | None) -> dict[str, Any]:
    """Load a YAML recipe file and return the matching protocol entry, or {}."""
    if recipe_path is None:
        recipe_path = _default_recipe_path()
    if not recipe_path.exists():
        return {}
    try:
        import yaml  # type: ignore
        with recipe_path.open() as f:
            recipes = yaml.safe_load(f) or []
    except Exception:
        # Fallback: minimal JSON-ish parse is not needed — return empty on error.
        return {}
    if not isinstance(recipes, list):
        return {}
    if protocol is None:
        return {}
    for entry in recipes:
        if isinstance(entry, dict) and entry.get("protocol") == protocol:
            return entry
    return {}


# ---------------------------------------------------------------------------
# Override map
# ---------------------------------------------------------------------------

def parse_overrides(override_args: list[str]) -> dict[str, str]:
    """Parse ['ContractName=path/to/Stub.sol', ...] into a dict."""
    result: dict[str, str] = {}
    for arg in override_args:
        if "=" not in arg:
            print(f"[fork-replay] WARN override '{arg}' has no '='; skipped", file=sys.stderr)
            continue
        name, _, path = arg.partition("=")
        result[name.strip()] = path.strip()
    return result


# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

def output_dir(workspace: Path, finding_id: str) -> Path:
    d = workspace / "poc_execution" / finding_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def replay_sha(finding_id: str, replay_tx: str | None, block: int | None) -> str:
    """Stable short sha for output file naming."""
    key = f"{finding_id}|{replay_tx or ''}|{block or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def semantic_bundle_dir(workspace: Path) -> Path:
    d = workspace / "fork_replay"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _positive_int(value: Any) -> int | None:
    try:
        iv = int(value)
    except (TypeError, ValueError):
        return None
    return iv if iv > 0 else None


def _is_proof_grade_assertion(assertion: Any) -> bool:
    if not isinstance(assertion, dict):
        return False
    if str(assertion.get("status") or "").upper() != "PASS":
        return False
    # `expr/status/notes` only is the current advisory path. Treat a replay
    # assertion as proof-grade only when it carries a stronger binding signal.
    for key in ("selector", "matched_row", "impact_bound", "observed"):
        if key in assertion:
            return True
    return False


def _semantic_bundle_ready(replay_json: dict[str, Any]) -> bool:
    if str(replay_json.get("mode") or "").lower() != "live":
        return False
    if str(replay_json.get("replay_result") or "").lower() != "executed":
        return False
    if _positive_int(replay_json.get("block")) is None:
        return False
    if _positive_int(replay_json.get("fork_block", replay_json.get("block"))) is None:
        return False
    assertions = replay_json.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        return False
    return all(_is_proof_grade_assertion(item) for item in assertions)


def emit_check22_semantic_bundle(
    workspace: Path,
    replay_json: dict[str, Any],
) -> dict[str, str] | None:
    """Write a Check-22-compatible semantic bundle when replay evidence is proof-grade."""
    if not _semantic_bundle_ready(replay_json):
        return None

    replay_tx = replay_json.get("replay_tx")
    if not isinstance(replay_tx, str) or not replay_tx:
        return None
    bundle_dir = semantic_bundle_dir(workspace)
    stem = replay_tx
    manifest_path = bundle_dir / f"{stem}_manifest.json"
    deltas_path = bundle_dir / f"{stem}_deltas.json"
    summary_path = bundle_dir / f"{stem}_replay.yaml"

    status = str(replay_json.get("replay_result") or "").lower()
    block = int(replay_json["block"])
    fork_block = int(replay_json.get("fork_block", block))
    assertions = replay_json["assertions"]

    manifest_payload: dict[str, Any] = {
        "tx": replay_tx,
        "status": status,
        "block": block,
        "fork_block": fork_block,
        "assertions": assertions,
    }
    for key in ("draft_claims", "network", "replay_sha"):
        if key in replay_json:
            manifest_payload[key] = replay_json[key]
    manifest_path.write_text(json.dumps(manifest_payload, indent=2))

    deltas_payload = {
        "tx": replay_tx,
        "status": status,
        "block": block,
        "fork_block": fork_block,
        "addresses": replay_json.get("deltas", {}),
    }
    deltas_path.write_text(json.dumps(deltas_payload, indent=2))
    summary_path.write_text(
        "\n".join(
            [
                f"tx: {replay_tx}",
                f"status: {status}",
                f"block: {block}",
                f"fork_block: {fork_block}",
            ]
        )
        + "\n"
    )
    return {
        "manifest": f"fork_replay/{manifest_path.name}",
        "deltas": f"fork_replay/{deltas_path.name}",
        "summary": f"fork_replay/{summary_path.name}",
    }


# ---------------------------------------------------------------------------
# Hermetic mode
# ---------------------------------------------------------------------------

def run_hermetic(args: argparse.Namespace) -> int:
    """Produce a synthetic replay artifact without calling anvil/cast.

    This validates the harness logic and manifest schema without external
    RPC dependency — suitable for CI.
    """
    workspace = Path(args.workspace or ".")
    finding_id = args.finding_id
    overrides = parse_overrides(args.override_contract)

    out_dir = output_dir(workspace, finding_id)
    sha = replay_sha(finding_id, args.replay_tx, args.block)
    log_path = out_dir / f"replay_{sha}.log"
    json_path = out_dir / f"replay_{sha}.json"
    manifest_path = out_dir / f"{finding_id}.execution_manifest.json"

    # Validate override stubs exist
    stub_results: list[dict[str, Any]] = []
    for name, stub_path in overrides.items():
        p = Path(stub_path)
        exists = p.exists()
        faithfulness_scope = _extract_faithfulness_scope(p) if exists else None
        stub_results.append({
            "contract": name,
            "stub_path": str(stub_path),
            "stub_exists": exists,
            "faithfulness_scope": faithfulness_scope,
        })
        if not exists:
            print(f"[fork-replay] WARN stub not found: {stub_path}", file=sys.stderr)

    now = int(time.time())
    log_content = (
        f"[fork-replay hermetic] finding_id={finding_id}\n"
        f"[fork-replay hermetic] mode=hermetic (no anvil / no RPC)\n"
        f"[fork-replay hermetic] timestamp={now}\n"
        f"[fork-replay hermetic] overrides={list(overrides.keys())}\n"
        f"[fork-replay hermetic] stubs_validated={len(stub_results)}\n"
        f"[fork-replay hermetic] OK\n"
    )
    log_path.write_text(log_content)

    replay_json: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "mode": "hermetic",
        "finding_id": finding_id,
        "timestamp_unix": now,
        "replay_sha": sha,
        "replay_tx": args.replay_tx,
        "network": args.network,
        "block": args.block,
        "overrides": overrides,
        "stub_results": stub_results,
        "anvil_command": None,
        "anvil_pid": None,
        "replay_result": "hermetic_ok",
        "assertions": [],
        "semantic_bundle": None,
        "log_path": str(log_path),
        "artifacts": [str(log_path), str(json_path)],
        "proof_boundary": (
            "hermetic mode — no real fork state; stubs validated for "
            "presence and faithfulness-scope comment only. Not proof. "
            "No Check-22 semantic bundle is emitted in hermetic mode."
        ),
    }
    json_path.write_text(json.dumps(replay_json, indent=2))

    # Update / create execution manifest
    _update_execution_manifest(manifest_path, replay_json, finding_id, sha)

    print(f"[fork-replay] hermetic OK — {json_path}")
    return 0


def _extract_faithfulness_scope(stub_path: Path) -> str | None:
    """Return the Production faithfulness scope: ... comment from a stub, if present."""
    if not stub_path.exists():
        return None
    try:
        text = stub_path.read_text(errors="replace")
    except OSError:
        return None
    m = re.search(r"Production faithfulness scope:\s*(.+)", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------

def run_dry_run(args: argparse.Namespace) -> int:
    """Print the commands that would be executed, without running anything."""
    workspace = Path(args.workspace or ".")
    finding_id = args.finding_id
    overrides = parse_overrides(args.override_contract)

    recipe_path = Path(args.recipe) if args.recipe else None
    recipe = load_recipe(recipe_path, args.protocol)

    network = args.network or recipe.get("network", "mainnet")
    block = args.block or recipe.get("default_block")
    rpc = args.rpc or recipe.get("rpc", f"${{ALCHEMY_{network.upper()}_RPC_URL}}")

    sha = replay_sha(finding_id, args.replay_tx, block)
    out_dir = output_dir(workspace, finding_id)

    print(f"[fork-replay dry-run] finding_id={finding_id}")
    print(f"[fork-replay dry-run] network={network}  block={block}")
    print(f"[fork-replay dry-run] rpc={rpc}")
    print()

    anvil_cmd = _build_anvil_command(rpc, block, overrides, recipe)
    print("# Step 1: Start forked anvil")
    print("  " + " ".join(anvil_cmd))
    print()

    if args.replay_tx:
        replay_cmd = _build_replay_command(args.replay_tx, rpc)
        print("# Step 2: Replay transaction")
        print("  " + " ".join(replay_cmd))
        print()

    if args.assert_expr:
        print("# Step 3: Evaluate assertion")
        print(f"  # --assert '{args.assert_expr}'")
        print(f"  # (evaluated via cast call after replay)")
        print()

    log_path = out_dir / f"replay_{sha}.log"
    json_path = out_dir / f"replay_{sha}.json"
    print(f"# Step 4: Write artifacts")
    print(f"  {log_path}")
    print(f"  {json_path}")

    return 0


# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------

def run_live(args: argparse.Namespace) -> int:
    """Execute a real fork-replay against a live anvil instance."""
    # Dependency check
    for tool in ("anvil", "cast"):
        if not shutil.which(tool):
            print(f"[fork-replay] ERROR: '{tool}' not found in PATH. "
                  f"Install foundry: https://getfoundry.sh/", file=sys.stderr)
            return 3

    workspace = Path(args.workspace or ".")
    finding_id = args.finding_id
    overrides = parse_overrides(args.override_contract)

    recipe_path = Path(args.recipe) if args.recipe else None
    recipe = load_recipe(recipe_path, args.protocol)

    network = args.network or recipe.get("network", "mainnet")
    block = args.block or recipe.get("default_block")
    rpc = _resolve_rpc(args.rpc, network, recipe)

    if not rpc:
        print("[fork-replay] ERROR: RPC URL required for live mode. "
              "Set --rpc, --recipe, or env var "
              f"ALCHEMY_{network.upper()}_RPC_URL", file=sys.stderr)
        return 2

    sha = replay_sha(finding_id, args.replay_tx, block)
    out_dir = output_dir(workspace, finding_id)
    log_path = out_dir / f"replay_{sha}.log"
    json_path = out_dir / f"replay_{sha}.json"
    manifest_path = out_dir / f"{finding_id}.execution_manifest.json"

    # Build stub results for manifest
    stub_results: list[dict[str, Any]] = []
    for name, stub_path_str in overrides.items():
        stub_path = Path(stub_path_str)
        exists = stub_path.exists()
        stub_results.append({
            "contract": name,
            "stub_path": stub_path_str,
            "stub_exists": exists,
            "faithfulness_scope": _extract_faithfulness_scope(stub_path) if exists else None,
        })

    now = int(time.time())
    log_lines: list[str] = [
        f"[fork-replay live] finding_id={finding_id}",
        f"[fork-replay live] network={network}  block={block}",
        f"[fork-replay live] rpc={rpc}",
        f"[fork-replay live] timestamp={now}",
    ]

    anvil_cmd = _build_anvil_command(rpc, block, overrides, recipe)
    log_lines.append(f"[fork-replay live] anvil_cmd={' '.join(anvil_cmd)}")

    # Start anvil
    anvil_proc = _start_anvil(anvil_cmd, args.verbose)
    if anvil_proc is None:
        log_lines.append("[fork-replay live] ERROR: failed to start anvil")
        log_path.write_text("\n".join(log_lines) + "\n")
        return 1

    replay_result = "started"
    assertions: list[dict[str, Any]] = []

    try:
        # Give anvil time to start
        time.sleep(2)

        # Replay tx
        if args.replay_tx:
            ok, stdout, stderr = _run_replay_tx(args.replay_tx, rpc, args.verbose)
            replay_result = "executed" if ok else "failed"
            log_lines.append(f"[fork-replay live] replay_tx={args.replay_tx} result={replay_result}")
            log_lines.append("[fork-replay live] --- replay stdout ---")
            log_lines.extend(stdout.splitlines()[:100])
            if stderr:
                log_lines.append("[fork-replay live] --- replay stderr ---")
                log_lines.extend(stderr.splitlines()[:50])
        else:
            replay_result = "no_tx"

        # Evaluate assertion
        if args.assert_expr:
            result = _eval_assertion(args.assert_expr, args.verbose)
            assertions.append(result)
            log_lines.append(f"[fork-replay live] assertion '{args.assert_expr}' => {result['status']}")

    finally:
        anvil_proc.terminate()
        try:
            anvil_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil_proc.kill()

    log_lines.append("[fork-replay live] anvil stopped")
    log_path.write_text("\n".join(log_lines) + "\n")

    # Determine overall status
    assertion_pass = all(a["status"] == "PASS" for a in assertions) if assertions else True
    overall = "PASS" if (replay_result in ("executed", "no_tx") and assertion_pass) else "FAIL"

    replay_json: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "mode": "live",
        "finding_id": finding_id,
        "timestamp_unix": now,
        "replay_sha": sha,
        "replay_tx": args.replay_tx,
        "network": network,
        "block": block,
        "fork_block": block,
        "rpc_redacted": _redact_rpc(rpc),
        "overrides": overrides,
        "stub_results": stub_results,
        "anvil_command": _redact_rpc(" ".join(anvil_cmd)),
        "replay_result": replay_result,
        "assertions": assertions,
        "overall": overall,
        "log_path": str(log_path),
        "artifacts": [str(log_path), str(json_path)],
        "proof_boundary": (
            "This replay log and JSON are execution evidence. "
            "Proof state requires matching assertion PASS + OOS clearance "
            "+ severity gate acceptance."
        ),
    }
    semantic_bundle = emit_check22_semantic_bundle(workspace, replay_json)
    replay_json["semantic_bundle"] = semantic_bundle
    if semantic_bundle:
        replay_json["artifacts"].extend(
            [
                str(workspace / semantic_bundle["manifest"]),
                str(workspace / semantic_bundle["deltas"]),
                str(workspace / semantic_bundle["summary"]),
            ]
        )
    json_path.write_text(json.dumps(replay_json, indent=2))
    _update_execution_manifest(manifest_path, replay_json, finding_id, sha)

    status_line = f"[fork-replay] {overall} — {json_path}"
    if assertions:
        for a in assertions:
            status_line += f"\n  assertion '{a['expr']}': {a['status']}"
    print(status_line)

    return 0 if overall == "PASS" else 1


# ---------------------------------------------------------------------------
# Helper: anvil command builder
# ---------------------------------------------------------------------------

def _build_anvil_command(
    rpc: str,
    block: int | None,
    overrides: dict[str, str],
    recipe: dict[str, Any],
) -> list[str]:
    cmd = ["anvil", "--fork-url", rpc]
    if block:
        cmd += ["--fork-block-number", str(block)]
    # Port default
    cmd += ["--port", "8545"]
    # Contract overrides require separate mechanism (cast deploy) — we record
    # the intent here but deployment happens after anvil starts.
    # The command is printed as planned; actual override deploy is separate.
    return cmd


def _build_replay_command(tx_hash: str, rpc: str) -> list[str]:
    return ["cast", "run", tx_hash, "--rpc-url", rpc]


# ---------------------------------------------------------------------------
# Helper: RPC resolver
# ---------------------------------------------------------------------------

def _resolve_rpc(cli_rpc: str | None, network: str, recipe: dict[str, Any]) -> str | None:
    if cli_rpc:
        return cli_rpc
    recipe_rpc = recipe.get("rpc")
    if recipe_rpc:
        # Expand env vars like ${ALCHEMY_MAINNET_RPC_URL}
        return os.path.expandvars(recipe_rpc)
    # Try env vars
    for suffix in (network.upper(), network.lower()):
        for pattern in (f"ALCHEMY_{suffix}_RPC_URL", f"RPC_{suffix}_URL", f"{suffix}_RPC_URL"):
            val = os.environ.get(pattern)
            if val:
                return val
    return None


def _redact_rpc(s: str) -> str:
    """Remove API keys from RPC URLs for safe logging."""
    return re.sub(r"(https?://[^/]+/)[A-Za-z0-9_-]{20,}", r"\1<redacted>", s)


# ---------------------------------------------------------------------------
# Helper: start/stop anvil
# ---------------------------------------------------------------------------

def _start_anvil(cmd: list[str], verbose: bool) -> subprocess.Popen | None:  # type: ignore[type-arg]
    try:
        out = subprocess.DEVNULL if not verbose else None
        proc = subprocess.Popen(cmd, stdout=out, stderr=out)
        return proc
    except Exception as e:
        print(f"[fork-replay] ERROR starting anvil: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Helper: replay tx
# ---------------------------------------------------------------------------

def _run_replay_tx(
    tx_hash: str, rpc: str, verbose: bool
) -> tuple[bool, str, str]:
    cmd = ["cast", "run", tx_hash, "--rpc-url", rpc]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


# ---------------------------------------------------------------------------
# Helper: assertion evaluator
# ---------------------------------------------------------------------------

def _eval_assertion(expr: str, verbose: bool) -> dict[str, Any]:
    """
    Evaluate a simple assertion expression.

    Current support:
    - '<label> > <N>'  / '<label> >= <N>' / '<label> == <N>'
    These are advisory; full cast-call binding is a future operator hook.
    """
    status = "INCONCLUSIVE"
    notes = "advisory evaluation only; full cast-call binding not wired"
    return {
        "expr": expr,
        "status": status,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Helper: execution manifest update
# ---------------------------------------------------------------------------

def _update_execution_manifest(
    manifest_path: Path,
    replay_json: dict[str, Any],
    finding_id: str,
    sha: str,
) -> None:
    """Upsert a replay entry into the finding's execution manifest."""
    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text())
        except Exception:
            existing = {}
    else:
        existing = {}

    replays = existing.get("fork_replays", [])
    replays = [r for r in replays if r.get("replay_sha") != sha]
    replays.append({
        "replay_sha": sha,
        "mode": replay_json.get("mode"),
        "replay_tx": replay_json.get("replay_tx"),
        "network": replay_json.get("network"),
        "block": replay_json.get("block"),
        "fork_block": replay_json.get("fork_block"),
        "replay_result": replay_json.get("replay_result"),
        "overall": replay_json.get("overall", "N/A"),
        "log_path": replay_json.get("log_path"),
        "json_path": str(manifest_path.parent / f"replay_{sha}.json"),
        "semantic_bundle": replay_json.get("semantic_bundle"),
        "timestamp_unix": replay_json.get("timestamp_unix"),
    })

    existing.update({
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "finding_id": finding_id,
        "updated_at_unix": int(time.time()),
        "fork_replays": replays,
        "latest_replay_sha": sha,
    })
    manifest_path.write_text(json.dumps(existing, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.hermetic:
        return run_hermetic(args)
    if args.dry_run:
        return run_dry_run(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
