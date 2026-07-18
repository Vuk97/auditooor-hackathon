#!/usr/bin/env python3
"""Fork-pinned PoC witness package checker and scaffolder.

For every ``proved`` High/Critical exploit-queue row, checks that a
``witness.json`` bundle exists (complete with all required fields) plus a
rerunnable command transcript.  Also scaffolds a template witness when
``--scaffold <row-id>`` is requested.

Schema id: auditooor.fork_pinned_witness.v1

Required witness fields
-----------------------
* pinned_state       - RPC endpoint + block number (EVM) OR local chain-state
                       snapshot path (Cosmos/Solana/non-EVM).
* replay_command     - One-command string to reproduce the exploit.
* attacker_setup     - Description of attacker preconditions / funded accounts.
* call_trace         - Transaction call trace or equivalent execution trace.
* state_diff         - Before/after state diff (storage slots, balances, etc.).
* balance_deltas     - Table of token/ETH balance changes.
* capital_accounting - Gas cost and attacker capital model.
* negative_control   - Control run proving the bug is NOT triggered when
                       preconditions are absent.

Non-EVM equivalent
------------------
Cosmos/Solana rows may carry ``non_evm_proof_manifest`` (a dict) in place of
``pinned_state`` EVM fields.  The manifest must itself contain ``chain_type``
(``cosmos`` or ``solana``), ``snapshot_path``, and ``replay_command``.  The
remaining fields (call_trace, state_diff, balance_deltas, capital_accounting,
negative_control, attacker_setup) are still required even on non-EVM rows.

Modes
-----
Check (default)
    Reports which proved High/Critical rows are missing a complete witness.
    Exits 0 when all rows are covered; exits 1 when ``--strict`` and any row
    is missing or incomplete.

Scaffold (--scaffold <row-id>)
    Emits a template witness.json to <ws>/witness_bundles/<row-id>/witness.json
    with every required field pre-populated with a ``TODO`` / ``PENDING``
    marker.  The file is explicitly tagged ``template_unfilled: true`` so it
    cannot be mistaken for real proof.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.fork_pinned_witness.v1"

REQUIRED_FIELDS: list[str] = [
    "pinned_state",
    "replay_command",
    "attacker_setup",
    "call_trace",
    "state_diff",
    "balance_deltas",
    "capital_accounting",
    "negative_control",
]

# Values that count as "unfilled" / placeholder
PLACEHOLDER_VALUES: set[str] = {
    "",
    "todo",
    "TODO",
    "pending",
    "PENDING",
    "null",
    "n/a",
    "N/A",
    "missing",
    "MISSING",
}

# proof_status values treated as "proved"
PROVED_STATUSES: frozenset[str] = frozenset({"proved", "proven"})

# Severity strings treated as High or Critical
HIGH_CRITICAL_SEVERITIES: frozenset[str] = frozenset({
    "high", "critical", "High", "Critical", "HIGH", "CRITICAL",
})

# Chain-type indicator strings that mark a row as non-EVM
NON_EVM_CHAIN_HINTS: tuple[str, ...] = (
    "cosmos",
    "solana",
    "substrate",
    "polkadot",
    "near",
    "sui",
    "aptos",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_exploit_queue(ws: Path) -> list[dict[str, Any]]:
    """Load exploit-queue rows from the workspace.  Tries the primary queue
    first; falls back to the source-mined variant.  Returns an empty list
    (never raises) when neither exists."""
    adir = ws / ".auditooor"
    for name in ("exploit_queue.json", "exploit_queue.source_mined.json"):
        raw = _read_json(adir / name)
        if raw is None:
            continue
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            for key in ("rows", "queue", "items"):
                if isinstance(raw.get(key), list):
                    return raw[key]
    return []


def _is_proved_high_critical(row: dict[str, Any]) -> bool:
    status = str(row.get("proof_status", "")).lower()
    severity = str(row.get("likely_severity", row.get("severity", ""))).lower()
    return status in PROVED_STATUSES and severity in {"high", "critical"}


def _row_id(row: dict[str, Any]) -> str:
    return str(row.get("lead_id", row.get("candidate_id", row.get("id", "UNKNOWN"))))


def _is_non_evm(row: dict[str, Any]) -> bool:
    """Return True if this row targets a non-EVM chain."""
    chain = str(row.get("chain_type", row.get("chain", ""))).lower()
    if any(hint in chain for hint in NON_EVM_CHAIN_HINTS):
        return True
    # Check attack_class / title / root_cause for hints
    haystack = " ".join([
        str(row.get("attack_class", "")),
        str(row.get("title", "")),
        str(row.get("root_cause_hypothesis", "")),
    ]).lower()
    return any(hint in haystack for hint in NON_EVM_CHAIN_HINTS)


def _witness_path(ws: Path, row_id: str) -> Path:
    return ws / "witness_bundles" / row_id / "witness.json"


def _transcript_path(ws: Path, row_id: str) -> Path:
    return ws / "witness_bundles" / row_id / "replay_transcript.txt"


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------

def _is_placeholder(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip() in PLACEHOLDER_VALUES:
        return True
    return False


def _validate_non_evm_manifest(manifest: Any) -> list[str]:
    """Return list of missing sub-fields in a non_evm_proof_manifest."""
    missing: list[str] = []
    if not isinstance(manifest, dict):
        return ["non_evm_proof_manifest must be a dict"]
    for sub in ("chain_type", "snapshot_path", "replay_command"):
        if _is_placeholder(manifest.get(sub)):
            missing.append(f"non_evm_proof_manifest.{sub}")
    return missing


def _check_witness(witness: Any, non_evm: bool) -> list[str]:
    """Return a list of missing or unfilled fields.  Empty list means pass."""
    if not isinstance(witness, dict):
        return ["witness.json is not a valid JSON object"]

    if witness.get("template_unfilled"):
        return ["witness is a scaffold template - not real proof (template_unfilled=true)"]

    missing: list[str] = []

    # pinned_state handling
    pinned = witness.get("pinned_state")
    if non_evm:
        # Accept non_evm_proof_manifest as the pinned-state equivalent
        manifest = witness.get("non_evm_proof_manifest")
        if manifest is not None:
            sub_missing = _validate_non_evm_manifest(manifest)
            missing.extend(sub_missing)
        elif _is_placeholder(pinned):
            # Neither a valid manifest nor a real pinned_state
            missing.append("pinned_state (or non_evm_proof_manifest for non-EVM rows)")
        else:
            # pinned_state provided for non-EVM is also acceptable
            if isinstance(pinned, dict):
                if _is_placeholder(pinned.get("block_number")) and _is_placeholder(pinned.get("snapshot_path")):
                    missing.append("pinned_state.block_number or pinned_state.snapshot_path")
    else:
        # EVM: require pinned_state with rpc_url + block_number
        if _is_placeholder(pinned):
            missing.append("pinned_state")
        elif isinstance(pinned, dict):
            if _is_placeholder(pinned.get("rpc_url")):
                missing.append("pinned_state.rpc_url")
            if _is_placeholder(pinned.get("block_number")):
                missing.append("pinned_state.block_number")
        # If pinned_state is a plain non-empty string, accept it

    # Remaining required fields (common to EVM and non-EVM)
    for field in REQUIRED_FIELDS:
        if field == "pinned_state":
            continue  # handled above
        val = witness.get(field)
        if _is_placeholder(val):
            missing.append(field)

    return missing


# ---------------------------------------------------------------------------
# Check mode
# ---------------------------------------------------------------------------

def build_check_payload(
    ws: Path,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Return a check-mode payload dict."""
    if not ws.exists():
        return {
            "schema": SCHEMA,
            "workspace": str(ws),
            "degraded": True,
            "degraded_reason": "workspace_missing",
            "rows": [],
            "summary": {"proved_high_critical": 0, "covered": 0, "missing_witness": 0},
            "all_covered": True,
            "strict_fail": False,
        }

    queue_rows = _load_exploit_queue(ws)
    proved_rows = [r for r in queue_rows if _is_proved_high_critical(r)]

    if not proved_rows:
        return {
            "schema": SCHEMA,
            "workspace": str(ws),
            "degraded": False,
            "rows": [],
            "no_proved_high_critical_rows": True,
            "summary": {"proved_high_critical": 0, "covered": 0, "missing_witness": 0},
            "all_covered": True,
            "strict_fail": False,
        }

    rows_out: list[dict[str, Any]] = []
    for row in proved_rows:
        rid = _row_id(row)
        non_evm = _is_non_evm(row)
        wp = _witness_path(ws, rid)
        tp = _transcript_path(ws, rid)

        # Check witness.json
        witness_raw = _read_json(wp)
        if witness_raw is None:
            verdict = "missing_artifact"
            missing_fields: list[str] = []
            note = f"witness.json not found at {wp}"
        else:
            missing_fields = _check_witness(witness_raw, non_evm)
            if missing_fields:
                verdict = "incomplete_witness"
                note = f"witness.json present but incomplete: {', '.join(missing_fields)}"
            else:
                verdict = "pass"
                note = "witness.json complete"

        # Check transcript
        has_transcript = tp.exists() and tp.stat().st_size > 0
        if verdict == "pass" and not has_transcript:
            verdict = "missing_transcript"
            note = f"witness.json complete but replay_transcript.txt not found at {tp}"

        rows_out.append({
            "row_id": rid,
            "severity": row.get("likely_severity", row.get("severity", "unknown")),
            "proof_status": row.get("proof_status", "unknown"),
            "non_evm": non_evm,
            "verdict": verdict,
            "missing_fields": missing_fields,
            "witness_path": str(wp),
            "transcript_path": str(tp),
            "note": note,
        })

    covered = sum(1 for r in rows_out if r["verdict"] == "pass")
    missing_count = len(rows_out) - covered
    all_covered = missing_count == 0
    strict_fail = strict and not all_covered

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "degraded": False,
        "rows": rows_out,
        "no_proved_high_critical_rows": False,
        "summary": {
            "proved_high_critical": len(proved_rows),
            "covered": covered,
            "missing_witness": missing_count,
        },
        "all_covered": all_covered,
        "strict_fail": strict_fail,
    }


# ---------------------------------------------------------------------------
# Scaffold mode
# ---------------------------------------------------------------------------

def _evm_witness_template(row_id: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "template_unfilled": True,
        "row_id": row_id,
        "chain_type": "evm",
        "pinned_state": {
            "rpc_url": "TODO: e.g. https://mainnet.infura.io/v3/YOUR_KEY",
            "block_number": "TODO: e.g. 19500000",
            "fork_flag": "TODO: e.g. --fork-url $RPC --fork-block-number 19500000",
        },
        "replay_command": "TODO: one-command replay, e.g. forge test --match-test testExploit --fork-url $RPC --fork-block-number 19500000 -vvv",
        "attacker_setup": "TODO: describe funded attacker address, initial balances, preconditions",
        "call_trace": "PENDING: paste forge/hardhat call trace here",
        "state_diff": {
            "before": "PENDING: storage slot / balance state before attack",
            "after": "PENDING: storage slot / balance state after attack",
        },
        "balance_deltas": "PENDING: table of token/ETH balance changes (attacker, victim, protocol)",
        "capital_accounting": {
            "gas_cost_gwei": "TODO",
            "attacker_capital_required": "TODO",
            "attacker_profit": "TODO",
        },
        "negative_control": "TODO: replay command/description that proves bug does NOT fire when preconditions absent",
        "_instructions": (
            "Fill every TODO/PENDING field. Remove template_unfilled key when complete. "
            "Run replay_command and paste output into replay_transcript.txt in same dir."
        ),
    }


def _non_evm_witness_template(row_id: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "template_unfilled": True,
        "row_id": row_id,
        "chain_type": "TODO: cosmos | solana | substrate | ...",
        "non_evm_proof_manifest": {
            "chain_type": "TODO: cosmos | solana | substrate | ...",
            "snapshot_path": "TODO: path to local chain-state snapshot or genesis + state-export",
            "replay_command": "TODO: one-command replay, e.g. go test ./poc/... -run TestExploit -v",
        },
        "pinned_state": {
            "description": "PENDING: describe pinned chain state (block height, git commit, node version)",
            "snapshot_path": "TODO",
            "block_number": "TODO",
        },
        "replay_command": "TODO: one-command replay string",
        "attacker_setup": "TODO: describe attacker account, stake, permissions, initial state",
        "call_trace": "PENDING: extrinsic / instruction trace or equivalent",
        "state_diff": {
            "before": "PENDING: key storage state before attack",
            "after": "PENDING: key storage state after attack",
        },
        "balance_deltas": "PENDING: token balance changes across attacker, victim, protocol",
        "capital_accounting": {
            "fee_cost": "TODO",
            "attacker_capital_required": "TODO",
            "attacker_profit": "TODO",
        },
        "negative_control": "TODO: command/description proving bug does NOT fire without preconditions",
        "_instructions": (
            "Fill every TODO/PENDING field. Remove template_unfilled key when complete. "
            "Run replay_command and paste output into replay_transcript.txt in same dir."
        ),
    }


def scaffold_witness(
    ws: Path,
    row_id: str,
    *,
    non_evm: bool = False,
    row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write a template witness.json to <ws>/witness_bundles/<row-id>/ and
    return the template dict."""
    if row is None:
        row = {}
    if not non_evm:
        template = _evm_witness_template(row_id, row)
    else:
        template = _non_evm_witness_template(row_id, row)

    wp = _witness_path(ws, row_id)
    _write_json(wp, template)

    # Also write a placeholder transcript
    tp = _transcript_path(ws, row_id)
    if not tp.exists():
        tp.parent.mkdir(parents=True, exist_ok=True)
        tp.write_text(
            "# Replay transcript - PENDING\n"
            "# Run the replay_command from witness.json and paste the full output here.\n",
            encoding="utf-8",
        )

    return template


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Fork-pinned PoC witness checker and scaffolder "
            "(auditooor.fork_pinned_witness.v1)"
        )
    )
    p.add_argument("--workspace", "--ws", required=True, metavar="WS",
                   help="Workspace root directory")
    p.add_argument("--scaffold", metavar="ROW_ID", default=None,
                   help="Emit a witness.json template for the given row-id")
    p.add_argument("--non-evm", action="store_true", default=False,
                   help="Force non-EVM template when scaffolding")
    p.add_argument("--strict", action="store_true", default=False,
                   help="Exit non-zero if any proved High/Critical row lacks a complete witness")
    p.add_argument("--json", action="store_true", default=False,
                   help="Print output as JSON")
    p.add_argument("--out", metavar="PATH", default=None,
                   help="Write JSON output to this path instead of stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()

    if args.scaffold:
        row_id = args.scaffold
        # Try to load the row for chain-type detection
        queue_rows = _load_exploit_queue(ws) if ws.exists() else []
        matched = [r for r in queue_rows if _row_id(r) == row_id]
        row = matched[0] if matched else {}
        non_evm = args.non_evm or _is_non_evm(row)
        template = scaffold_witness(ws, row_id, non_evm=non_evm, row=row)
        wp = _witness_path(ws, row_id)
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "mode": "scaffold",
            "row_id": row_id,
            "template_unfilled": True,
            "witness_path": str(wp),
            "message": (
                f"Template written to {wp}. "
                "Fill every TODO/PENDING field and remove template_unfilled "
                "before declaring the witness complete."
            ),
        }
        if args.json or args.out:
            out_str = json.dumps(payload, indent=2) + "\n"
            if args.out:
                Path(args.out).write_text(out_str, encoding="utf-8")
            else:
                print(out_str, end="")
        else:
            print(f"[fork-pinned-witness] scaffold written to {wp}")
            print("  Fill every TODO/PENDING field, then run replay_command")
            print("  and paste output into replay_transcript.txt in same dir.")
        return 0

    # Check mode
    payload = build_check_payload(ws, strict=args.strict)

    if args.json or args.out:
        out_str = json.dumps(payload, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(out_str, encoding="utf-8")
        else:
            print(out_str, end="")
    else:
        _print_human(payload)

    return 1 if payload.get("strict_fail") else 0


def _print_human(payload: dict[str, Any]) -> None:
    ws = payload.get("workspace", "?")
    print(f"[fork-pinned-witness] workspace: {ws}")

    if payload.get("degraded"):
        print(f"  DEGRADED: {payload.get('degraded_reason', 'unknown')}")
        return

    if payload.get("no_proved_high_critical_rows"):
        print("  no proved High/Critical rows - nothing to check")
        return

    summary = payload.get("summary", {})
    print(
        f"  proved High/Critical rows: {summary.get('proved_high_critical', 0)}"
        f"  covered: {summary.get('covered', 0)}"
        f"  missing: {summary.get('missing_witness', 0)}"
    )

    for row in payload.get("rows", []):
        verdict = row.get("verdict", "?")
        rid = row.get("row_id", "?")
        sev = row.get("severity", "?")
        mark = "PASS" if verdict == "pass" else "FAIL"
        print(f"  [{mark}] {rid} ({sev}): {verdict}")
        if verdict != "pass":
            print(f"         note: {row.get('note', '')}")
            mf = row.get("missing_fields", [])
            if mf:
                print(f"         missing fields: {', '.join(mf)}")

    if payload.get("all_covered"):
        print("  all proved High/Critical rows have complete witness bundles")
    else:
        print("  WARN: some proved High/Critical rows are missing witness bundles")
        if payload.get("strict_fail"):
            print("  STRICT: exiting non-zero")


if __name__ == "__main__":
    sys.exit(main())
