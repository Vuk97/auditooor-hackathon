#!/usr/bin/env python3
"""Check explicit live claim preconditions in a draft.

Drafts can declare live-state assumptions with HTML comments:

    <!-- claim-precondition: 0xabc... owner()(address) == 0xdef... -->
    <!-- claim-precondition: 0xabc... totalSupply()(uint256) <= 1000000 -->
    <!-- claim-precondition: network=polygon 0xabc... isAdmin(address)(bool) 0xdef... == false -->

Comparison operators: ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``. Numeric
operators apply to ``uint256`` / ``int256`` returns. Equality operators apply
to addresses, booleans, and bytes.

When an RPC URL is provided, the tool runs `cast call` and compares the
observed value with the expected value. For hermetic tests or already-captured
evidence, pass `--observed-json` with a mapping from the left-hand expression
to the observed value.

Wave 2 (Issue #345 follow-up) capability uplift:

  * Per-network RPC URL resolution — ``AUDITOOOR_LIVE_RPC_<NETWORK>`` or
    ``<NETWORK>_RPC_URL``. Recognised network annotation is the optional
    ``network=<name>`` token in the directive head.
  * Workspace-aware address symbol resolution — when ``--workspace`` is
    passed, ``${ContractName}`` tokens are resolved against
    ``deployment_topology.json`` (and ``live_topology_checks.json`` as a
    secondary source). The ``${...}`` form is used instead of angle-brackets
    so the symbol does not collide with the ``<`` / ``>`` comparison
    operators when both appear in a single directive.
  * Manifest output — ``--workspace`` (or ``--manifest-out``) writes
    ``<workspace>/.auditooor/claim_precondition_results.json`` with one
    entry per directive (status, observation, expected, network, etc.) so
    closeout/dashboards can surface contradictions without re-running cast.

Exit codes:
  0 = all declared preconditions passed, or no directives were present
  1 = at least one declared precondition contradicted observed state
  2 = directives exist but could not be verified (missing RPC/cast/etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DIRECTIVE_RE = re.compile(r"<!--\s*claim-precondition:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
# Order matters: longest operators first so `<=`/`>=` win over `<`/`>`.
EXPR_RE = re.compile(r"^(?P<left>.+?)\s*(?P<op><=|>=|==|!=|<|>)\s*(?P<expected>.+?)\s*$")
CAST_LEFT_RE = re.compile(
    r"^(?P<address>0x[a-fA-F0-9]{40})\s+(?P<signature>[A-Za-z_][A-Za-z0-9_]*\([^)]*\)(?:\([^)]*\))?)\s*(?P<args>.*)$"
)
NETWORK_TOKEN_RE = re.compile(r"^\s*network\s*=\s*(?P<network>[A-Za-z0-9_-]+)\s+", re.IGNORECASE)
ALL_OPS = {"==", "!=", "<", "<=", ">", ">="}
NUMERIC_OPS = {"<", "<=", ">", ">="}


@dataclass(frozen=True)
class ClaimPrecondition:
    raw: str
    left: str
    op: str
    expected: str
    network: str = ""


def _normalise(value: str) -> str:
    value = value.strip().strip("`").strip('"').strip("'")
    if value.lower() in {"true", "false"}:
        return value.lower()
    if re.fullmatch(r"0x0+", value, re.IGNORECASE):
        return "0x0"
    if re.fullmatch(r"0x[a-fA-F0-9]+", value):
        return value.lower().lstrip("0x").lstrip("0") or "0x0"
    if re.fullmatch(r"\d+", value):
        return str(int(value))
    return value.lower()


def parse_directives(text: str) -> list[ClaimPrecondition]:
    out: list[ClaimPrecondition] = []
    for match in DIRECTIVE_RE.finditer(text):
        raw = " ".join(match.group(1).split())
        body = raw
        network = ""
        net_match = NETWORK_TOKEN_RE.match(body)
        if net_match:
            network = net_match.group("network").lower()
            body = body[net_match.end():].strip()
        expr_match = EXPR_RE.match(body)
        if not expr_match:
            out.append(ClaimPrecondition(raw=raw, left=body or raw, op="?", expected="", network=network))
            continue
        out.append(
            ClaimPrecondition(
                raw=raw,
                left=expr_match.group("left").strip(),
                op=expr_match.group("op"),
                expected=expr_match.group("expected").strip(),
                network=network,
            )
        )
    return out


def _load_observed(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("--observed-json must be a JSON object")
    return {str(k).strip(): str(v).strip() for k, v in payload.items()}


def _network_rpc_url(network: str) -> str:
    """Resolve an RPC URL for a given network from the environment.

    Looked up in this order (first non-empty wins):

      1. ``AUDITOOOR_LIVE_RPC_<NETWORK>``  (preferred, audited-tool scoped)
      2. ``<NETWORK>_RPC_URL``             (matches `live-check-runner.py`)
    """
    if not network:
        return ""
    upper = network.upper().replace("-", "_")
    for key in (f"AUDITOOOR_LIVE_RPC_{upper}", f"{upper}_RPC_URL"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def _load_workspace_topology(workspace: Path | None) -> dict[str, str]:
    """Return a mapping of contract-name -> resolved address.

    Reads ``<workspace>/deployment_topology.json`` (canonical engage.py
    artifact) and folds in any `live_topology_checks.json` rows that already
    pin a `(contract, address)` pair. Both lookups are tolerant: missing or
    malformed files yield an empty mapping rather than raising.
    """
    if workspace is None:
        return {}
    out: dict[str, str] = {}
    topo = workspace / "deployment_topology.json"
    if topo.exists():
        try:
            payload = json.loads(topo.read_text())
            entries = payload.get("entries") if isinstance(payload, dict) else None
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    name = str(entry.get("contract") or "").strip()
                    addr = str(entry.get("resolved_address") or "").strip()
                    if name and addr:
                        out[name] = addr
        except (json.JSONDecodeError, OSError):
            pass
    rows = workspace / "live_topology_checks.json"
    if rows.exists():
        try:
            payload = json.loads(rows.read_text())
            entries = (
                payload.get("checks") if isinstance(payload, dict) else None
            ) or (payload if isinstance(payload, list) else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("contract") or entry.get("contract_name") or "").strip()
                addr = str(entry.get("address") or "").strip()
                if name and addr and name not in out:
                    out[name] = addr
        except (json.JSONDecodeError, OSError):
            pass
    return out


def _resolve_address_symbols(left: str, topology: dict[str, str]) -> str:
    """Substitute ``${ContractName}`` tokens in ``left`` with resolved addresses.

    Symbol form is ``${Name}`` (shell-style). The angle-bracket form ``<Name>``
    is intentionally NOT used because it collides with the ``<`` / ``>``
    comparison operators when written in a single directive line. Hex
    addresses pass through unchanged. Unknown symbols are left in place so the
    cast call surfaces a readable error rather than a silently wrong query.
    """
    if not topology:
        return left

    def _sub(match: "re.Match[str]") -> str:
        name = match.group(1).strip()
        if re.fullmatch(r"0x[a-fA-F0-9]{40}", name or ""):
            return name
        return topology.get(name, match.group(0))

    return re.sub(r"\$\{([^{}]+)\}", _sub, left)


def _coerce_int(value: str) -> int | None:
    """Parse a numeric value as an integer (decimal or 0x-hex), else None."""
    cleaned = value.strip().strip("`").strip('"').strip("'")
    if not cleaned:
        return None
    try:
        if re.fullmatch(r"-?\d+", cleaned):
            return int(cleaned)
        if re.fullmatch(r"0x[a-fA-F0-9]+", cleaned):
            return int(cleaned, 16)
    except ValueError:
        return None
    # cast often emits values like "1000000 [1e6]" — strip the trailing tag.
    head = cleaned.split()[0]
    try:
        if re.fullmatch(r"-?\d+", head):
            return int(head)
        if re.fullmatch(r"0x[a-fA-F0-9]+", head):
            return int(head, 16)
    except ValueError:
        return None
    return None


def _compare(observed: str, op: str, expected: str) -> bool | None:
    """Return True/False for op(observed, expected); None if comparison cannot
    be carried out (e.g. non-numeric values for numeric ops)."""
    if op in NUMERIC_OPS:
        lhs = _coerce_int(observed)
        rhs = _coerce_int(expected)
        if lhs is None or rhs is None:
            return None
        if op == "<":
            return lhs < rhs
        if op == "<=":
            return lhs <= rhs
        if op == ">":
            return lhs > rhs
        if op == ">=":
            return lhs >= rhs
        return None
    lhs = _normalise(observed)
    rhs = _normalise(expected)
    if op == "==":
        return lhs == rhs
    if op == "!=":
        return lhs != rhs
    return None


def _cast_call(left: str, rpc_url: str) -> tuple[bool, str]:
    match = CAST_LEFT_RE.match(left)
    if not match:
        return False, "unsupported directive syntax for live cast call"
    address = match.group("address")
    signature = match.group("signature")
    args = [item for item in match.group("args").split() if item]
    cast = shutil.which("cast")
    if not cast:
        return False, "cast not found on PATH"
    cmd = [cast, "call", address, signature, *args, "--rpc-url", rpc_url]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "cast call failed").strip().splitlines()[0]
        return False, msg
    return True, proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""


def evaluate(
    directives: Iterable[ClaimPrecondition],
    *,
    observed: dict[str, str],
    rpc_url: str | None,
    skip_live_verify: bool,
    topology: dict[str, str] | None = None,
    cast_runner=None,
) -> tuple[int, list[str], list[dict]]:
    """Evaluate parsed directives against observed/live state.

    Returns ``(rc, messages, manifest_entries)``. ``manifest_entries`` is a
    list of structured dicts suitable for serialising to
    ``claim_precondition_results.json``. ``cast_runner`` is an optional
    injection point for tests (signature: ``(left, rpc_url) -> (ok, value)``).
    """
    messages: list[str] = []
    entries: list[dict] = []
    topology = topology or {}
    runner = cast_runner or _cast_call
    unresolved = 0
    contradicted = 0

    for directive in directives:
        entry: dict = {
            "directive": directive.raw,
            "left": directive.left,
            "op": directive.op,
            "expected": directive.expected,
            "network": directive.network,
            "status": "unresolved",
            "observed": None,
            "rpc_used": None,
            "note": "",
        }

        if directive.op not in ALL_OPS:
            unresolved += 1
            entry["status"] = "cannot-run"
            entry["note"] = "unparseable directive"
            messages.append(f"warn\tunparseable directive: {directive.raw}")
            entries.append(entry)
            continue

        resolved_left = _resolve_address_symbols(directive.left, topology)
        if resolved_left != directive.left:
            entry["resolved_left"] = resolved_left

        observed_value = observed.get(directive.left)
        if observed_value is None and resolved_left != directive.left:
            observed_value = observed.get(resolved_left)

        if observed_value is None and skip_live_verify:
            unresolved += 1
            entry["status"] = "cannot-run"
            entry["note"] = "skip-live-verify and no observed value"
            messages.append(
                f"warn\t{directive.left}: skipped (skip-live-verify)"
            )
            entries.append(entry)
            continue

        if observed_value is None:
            # Pick an RPC URL: explicit caller > per-network env > none.
            target_rpc = rpc_url or _network_rpc_url(directive.network)
            entry["rpc_used"] = target_rpc or None
            if not target_rpc:
                unresolved += 1
                entry["status"] = "cannot-run"
                hint = "provide --rpc-url"
                if directive.network:
                    hint += f" or set AUDITOOOR_LIVE_RPC_{directive.network.upper()}"
                hint += " or --observed-json"
                entry["note"] = f"no observed value ({hint})"
                messages.append(f"warn\t{directive.left}: no observed value ({hint})")
                entries.append(entry)
                continue
            ok, observed_value = runner(resolved_left, target_rpc)
            if not ok:
                unresolved += 1
                entry["status"] = "cannot-run"
                entry["note"] = str(observed_value)
                messages.append(f"warn\t{directive.left}: {observed_value}")
                entries.append(entry)
                continue

        entry["observed"] = observed_value
        result = _compare(observed_value, directive.op, directive.expected)
        if result is None:
            unresolved += 1
            entry["status"] = "cannot-run"
            entry["note"] = (
                f"cannot compare observed {observed_value!r} {directive.op} "
                f"{directive.expected!r} (numeric op needs integer values)"
            )
            messages.append(f"warn\t{directive.raw}: {entry['note']}")
            entries.append(entry)
            continue

        if result:
            entry["status"] = "match"
            messages.append(f"pass\t{directive.raw} (observed {observed_value})")
        else:
            contradicted += 1
            entry["status"] = "contradicts"
            messages.append(
                f"fail\t{directive.raw} contradicted by observed {observed_value}"
            )
        entries.append(entry)

    if contradicted:
        return 1, messages, entries
    if unresolved:
        return 2, messages, entries
    return 0, messages, entries


def _write_manifest(
    *,
    workspace: Path | None,
    manifest_out: Path | None,
    draft: Path,
    entries: list[dict],
    overall_status: str,
) -> Path | None:
    if manifest_out is None and workspace is None:
        return None
    if manifest_out is None and workspace is not None:
        manifest_out = workspace / ".auditooor" / "claim_precondition_results.json"
    assert manifest_out is not None  # for type checkers
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.claim_precondition_results.v1",
        "draft": str(draft),
        "overall_status": overall_status,
        "entries": entries,
    }
    manifest_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest_out


def _overall_status(rc: int, entries: list[dict]) -> str:
    if rc == 1:
        return "contradicts"
    if rc == 2:
        return "cannot-run"
    if not entries:
        return "no-directives"
    return "match"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("draft", type=Path)
    parser.add_argument("--rpc-url", default=os.environ.get("AUDITOOOR_RPC_URL") or os.environ.get("RPC_URL"))
    parser.add_argument("--observed-json", type=Path)
    parser.add_argument("--skip-live-verify", action="store_true")
    parser.add_argument(
        "--workspace",
        type=Path,
        help=(
            "Workspace directory. When set, address symbols of the form "
            "<ContractName> are resolved against deployment_topology.json / "
            "live_topology_checks.json, and the result manifest is written "
            "to <workspace>/.auditooor/claim_precondition_results.json."
        ),
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        help="Override manifest output path (default: <workspace>/.auditooor/claim_precondition_results.json).",
    )
    args = parser.parse_args(argv)

    text = args.draft.read_text(errors="replace")
    directives = parse_directives(text)
    if not directives:
        print("pass\tno claim-precondition directives declared")
        _write_manifest(
            workspace=args.workspace,
            manifest_out=args.manifest_out,
            draft=args.draft,
            entries=[],
            overall_status="no-directives",
        )
        return 0
    observed = _load_observed(args.observed_json)
    topology = _load_workspace_topology(args.workspace)
    rc, messages, entries = evaluate(
        directives,
        observed=observed,
        rpc_url=args.rpc_url,
        skip_live_verify=args.skip_live_verify,
        topology=topology,
    )
    for message in messages:
        print(message)
    _write_manifest(
        workspace=args.workspace,
        manifest_out=args.manifest_out,
        draft=args.draft,
        entries=entries,
        overall_status=_overall_status(rc, entries),
    )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
