#!/usr/bin/env python3
"""Auto-discover cross-contract composition fixture candidates.

This is a thin orchestration layer over ``tools/gen-composition-fuzz.sh``.  It
turns a workspace into a small set of ranked contract pairs, writes the
contract-list files the legacy generator expects, and invokes that generator to
emit Foundry invariant harness scaffolds under ``<workspace>/composition_fuzz``.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "auditooor.composition_fixtures.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "tools" / "gen-composition-fuzz.sh"
EXCLUDED_DIRS = {
    ".git",
    "artifacts",
    "broadcast",
    "cache",
    "lib",
    "node_modules",
    "out",
    "poc-tests",
    "poc_execution",
    "test",
}
ROLE_KEYWORDS = {
    "router": ("router", "multicall", "batch", "bundle", "zap", "execute", "route"),
    "vault": ("vault", "deposit", "withdraw", "redeem", "mint", "share"),
    "adapter": ("adapter", "wrapper", "bridge", "connector", "module"),
    "oracle": ("oracle", "price", "feed", "twap", "vwap"),
    "token": ("token", "erc20", "erc1155", "transfer", "balanceof", "allowance"),
    "manager": ("manager", "registry", "controller", "admin", "keeper"),
}


@dataclass(frozen=True)
class ContractInfo:
    name: str
    rel_path: str
    functions: tuple[str, ...]
    roles: tuple[str, ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_") or "fixture"


def _solidity_files(workspace: Path) -> list[Path]:
    rows: list[Path] = []
    for root, dirs, files in workspace.walk():
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
        for name in sorted(files):
            if name.endswith(".sol"):
                rows.append(root / name)
    return sorted(rows, key=lambda p: p.relative_to(workspace).as_posix())


def _extract_contract_name(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in re.finditer(r"\b(abstract\s+)?(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)", text):
        if match.group(1) or match.group(2) in {"interface", "library"}:
            continue
        return match.group(3)
    return None


def _extract_functions(path: Path) -> tuple[str, ...]:
    text = " ".join(path.read_text(encoding="utf-8", errors="replace").split())
    names = re.findall(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s+(?:[^;{]*\s+)?(?:public|external)\b", text)
    return tuple(sorted(set(names)))


def _roles_for(name: str, rel_path: str, functions: tuple[str, ...]) -> tuple[str, ...]:
    haystack = " ".join([name, rel_path, *functions]).lower()
    roles = [role for role, keywords in ROLE_KEYWORDS.items() if any(k in haystack for k in keywords)]
    return tuple(roles or ["generic"])


def discover_contracts(workspace: Path) -> list[ContractInfo]:
    contracts: list[ContractInfo] = []
    for sol in _solidity_files(workspace):
        name = _extract_contract_name(sol)
        if not name:
            continue
        rel = sol.relative_to(workspace).as_posix()
        functions = _extract_functions(sol)
        contracts.append(ContractInfo(name=name, rel_path=rel, functions=functions, roles=_roles_for(name, rel, functions)))
    return contracts


def _pair_score(pair: tuple[ContractInfo, ContractInfo]) -> tuple[int, str]:
    left, right = pair
    roles = set(left.roles) | set(right.roles)
    role_bonus = 4 if set(left.roles).isdisjoint(right.roles) else 1
    flow_bonus = 0
    if {"router", "vault"} <= roles or {"router", "adapter"} <= roles:
        flow_bonus += 5
    if "oracle" in roles and ("vault" in roles or "manager" in roles):
        flow_bonus += 3
    if "token" in roles and ("vault" in roles or "router" in roles):
        flow_bonus += 2
    action_bonus = min(len(left.functions) + len(right.functions), 8)
    key = f"{left.name}_vs_{right.name}"
    return (role_bonus + flow_bonus + action_bonus, key)


def select_pairs(contracts: list[ContractInfo], max_pairs: int) -> list[tuple[ContractInfo, ContractInfo]]:
    pairs = list(itertools.combinations(contracts, 2))
    pairs.sort(key=lambda pair: (-_pair_score(pair)[0], _pair_score(pair)[1]))
    return pairs[:max_pairs]


def _write_contract_list(out_dir: Path, pair: tuple[ContractInfo, ContractInfo]) -> Path:
    path = out_dir / f"{_slug(pair[0].name)}_vs_{_slug(pair[1].name)}.contracts.txt"
    path.write_text("\n".join(f"{c.name}:{c.rel_path}" for c in pair) + "\n", encoding="utf-8")
    return path


def _expected_harness(workspace: Path, pair: tuple[ContractInfo, ContractInfo]) -> Path:
    return workspace / "composition_fuzz" / f"{pair[0].name}_vs_{pair[1].name}.t.sol"


def build_payload(workspace: Path, out_dir: Path, max_pairs: int, *, generate: bool) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    contracts = discover_contracts(workspace)
    eligible = [contract for contract in contracts if contract.functions]
    selected = select_pairs(eligible, max_pairs=max_pairs) if len(eligible) >= 2 else []
    rows: list[dict[str, object]] = []
    for pair in selected:
        list_path = _write_contract_list(out_dir, pair)
        harness = _expected_harness(workspace, pair)
        command = ["bash", str(GENERATOR), str(workspace), str(list_path)]
        status = "planned"
        rc: int | None = None
        stderr_tail = ""
        stdout_tail = ""
        if generate:
            proc = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=90)
            rc = proc.returncode
            status = "generated" if rc == 0 and harness.is_file() else "failed"
            stdout_tail = proc.stdout[-2000:]
            stderr_tail = proc.stderr[-2000:]
        rows.append(
            {
                "contracts": [c.name for c in pair],
                "roles": {c.name: list(c.roles) for c in pair},
                "functions": {c.name: list(c.functions) for c in pair},
                "score": _pair_score(pair)[0],
                "contract_list": str(list_path),
                "harness": str(harness),
                "status": status,
                "returncode": rc,
                "command": " ".join(command),
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
            }
        )
    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(workspace),
        "contracts_discovered": len(contracts),
        "contracts_eligible": len(eligible),
        "contracts": [
            {
                "name": c.name,
                "path": c.rel_path,
                "roles": list(c.roles),
                "functions": list(c.functions),
                "eligible_for_pairing": bool(c.functions),
            }
            for c in contracts
        ],
        "max_pairs": max_pairs,
        "pairs_generated": sum(1 for row in rows if row["status"] == "generated"),
        "pairs": rows,
        "generator": str(GENERATOR),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--out-dir", default=".auditooor/composition_fixtures")
    parser.add_argument("--max-pairs", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--plan-only", action="store_true", help="Write contract lists without invoking gen-composition-fuzz.sh")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[gen-composition-fixtures] workspace not found: {workspace}")
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = workspace / out_dir
    payload = build_payload(workspace, out_dir, max_pairs=max(args.max_pairs, 0), generate=not args.plan_only)
    manifest = out_dir / "manifest.json"
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[gen-composition-fixtures] wrote manifest: {manifest}")
        print(f"[gen-composition-fixtures] pairs_generated={payload['pairs_generated']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
