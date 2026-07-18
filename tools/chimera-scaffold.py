#!/usr/bin/env python3
"""Generate an advisory Chimera-compatible harness from one invariant row.

The output is intentionally scaffold-only. It gives operators the Recon /
Chimera file layout while preserving auditooor's proof discipline: generated
harnesses are not evidence until a real execution manifest proves impact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.chimera_harness.v1"
ADVISORY = "ADVISORY - scaffold only; not proof until execution is recorded."
SOL_IDENT = re.compile(r"[^A-Za-z0-9_]+")
ROW_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*[A-Za-z0-9]$")
PATH_HINT = re.compile(r"(?P<path>[\w./@-]+\.(?:sol|vy))(?:[:#][0-9]+)?")
CONTRACT_RE = re.compile(r"\b(abstract\s+contract|interface|library|contract)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT_RE = re.compile(r"//.*")


def _canonical_hash(data: Any) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"missing invariant ledger: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _explicit_false(value: Any) -> bool:
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "n"}
    if isinstance(value, (int, float)):
        return value == 0
    return False


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _first_text(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _text(row.get(key))
        if value:
            return value
    return ""


def _impact_contract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "records", "rows", "impact_contracts"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _load_impact_contracts(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        return []
    try:
        return _impact_contract_rows(json.loads(path.read_text()))
    except (OSError, ValueError):
        return []


def _match_key(row: dict[str, Any]) -> str:
    return _first_text(row, ("candidate_id", "stable_candidate_id", "id", "harness_task_id", "source_proof_id", "row_id", "invariant_id"))


def _matching_impact_contract(workspace: Path, row: dict[str, Any], row_id: str) -> dict[str, Any] | None:
    rows = _load_impact_contracts(workspace)
    explicit = _first_text(row, ("impact_contract_id",))
    if explicit:
        for candidate in rows:
            if _first_text(candidate, ("impact_contract_id",)) == explicit:
                return candidate
        return row

    keys = {_text(row_id), _match_key(row)}
    keys.discard("")
    for candidate in rows:
        if _match_key(candidate) in keys:
            return candidate
    return None


def _impact_contract_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "impact_contract_id": _first_text(row, ("impact_contract_id",)),
        "selected_impact": _first_text(row, ("selected_impact", "listed_impact_selected")),
        "severity": _first_text(row, ("severity", "raw_severity", "severity_implied")),
        "exact_impact_row": row.get("exact_impact_row"),
        "listed_impact_proven": row.get("listed_impact_proven"),
    }


def _require_locked_impact_contract(workspace: Path, row: dict[str, Any], row_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    matched = _matching_impact_contract(workspace, row, row_id)
    merged: dict[str, Any] = {}
    if matched:
        merged.update(matched)
    for key, value in row.items():
        if value not in (None, ""):
            merged[key] = value

    missing: list[str] = []
    if not _first_text(merged, ("impact_contract_id",)):
        missing.append("impact_contract_id")
    if not _first_text(merged, ("selected_impact", "listed_impact_selected")):
        missing.append("selected_impact")
    severity = _first_text(merged, ("severity", "raw_severity", "severity_implied"))
    if not severity or severity.lower() == "none":
        missing.append("severity")
    if _explicit_false(merged.get("exact_impact_row")):
        missing.append("exact_impact_row_not_false")
    if not _truthy(merged.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")

    if missing:
        return None, missing
    return _impact_contract_projection(merged), []


def _ledger_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        rows = data.get("rows") or data.get("invariants") or data.get("items")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    raise SystemExit("invariant ledger does not contain rows[]")


def _row_id(row: dict[str, Any]) -> str:
    for key in ("id", "row_id", "invariant_id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _find_row(rows: list[dict[str, Any]], row_id: str) -> dict[str, Any]:
    for row in rows:
        if _row_id(row) == row_id:
            return row
    raise SystemExit(f"row id not found in invariant ledger: {row_id}")


def _flatten_text(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_flatten_text(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(_flatten_text(item))
    return out


def _normalize_hint(workspace: Path, text: str) -> Path | None:
    match = PATH_HINT.search(text)
    if not match:
        return None
    raw_match = match.group("path")
    raw = raw_match.lstrip("./")
    candidates = []
    if raw_match.startswith("/"):
        candidates.append(Path(raw_match))
    candidates.append(workspace / raw)
    if "/external/" in raw:
        candidates.append(workspace / raw.split("/external/", 1)[1])
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.exists() and workspace.resolve() in resolved.parents:
            return resolved
    return None


def _discover_source_bindings(workspace: Path, row: dict[str, Any]) -> list[Path]:
    found: list[Path] = []
    for text in _flatten_text(row):
        hint = _normalize_hint(workspace, text)
        if hint and hint not in found:
            found.append(hint)

    if found:
        return found

    haystack = " ".join(_flatten_text(row)).lower()
    if not haystack:
        return []
    for source in sorted(workspace.rglob("*.sol")):
        if any(part in {".git", "node_modules", "out", "cache", "lib", "test"} for part in source.parts):
            continue
        stem = source.stem.lower()
        rel = str(source.relative_to(workspace)).lower()
        if stem in haystack or rel in haystack:
            found.append(source.resolve())
    return found


def _contract_kinds(source: Path) -> list[tuple[str, str]]:
    try:
        text = _strip_comments(source.read_text(errors="replace"))
    except OSError:
        return []
    return [(kind, name) for kind, name in CONTRACT_RE.findall(text)]


def _strip_comments(text: str) -> str:
    return LINE_COMMENT_RE.sub("", BLOCK_COMMENT_RE.sub("", text))


def _concrete_bindings(sources: list[Path]) -> list[dict[str, str]]:
    concrete: list[dict[str, str]] = []
    for source in sources:
        for kind, name in _contract_kinds(source):
            if kind in {"contract"}:
                concrete.append({"path": str(source), "contract": name})
    return concrete


def _contract_binding_summary(sources: list[Path]) -> list[dict[str, str | bool]]:
    summary: list[dict[str, str | bool]] = []
    for source in sources:
        for kind, name in _contract_kinds(source):
            summary.append({"path": str(source), "contract": name, "kind": kind, "is_concrete": kind == "contract"})
    return summary


def _functions_from_sources(sources: list[Path]) -> tuple[list[str], dict[str, list[str]]]:
    names: list[str] = []
    seen_at: dict[str, list[str]] = {}
    for source in sources:
        try:
            text = _strip_comments(source.read_text(errors="replace"))
        except OSError:
            continue
        for name in FUNCTION_RE.findall(text):
            seen_at.setdefault(name, []).append(str(source))
            if name not in names and not name.startswith("_"):
                names.append(name)
    collisions = {name: paths for name, paths in seen_at.items() if len(paths) > 1}
    return names, collisions


def _slug(value: str, fallback: str = "row") -> str:
    slug = SOL_IDENT.sub("_", value).strip("_")
    if not slug:
        slug = fallback
    if slug[0].isdigit():
        slug = f"row_{slug}"
    return slug[:80]


def _valid_row_id(value: str) -> bool:
    return bool(ROW_ID_RE.match(value)) and "--" not in value


def _comment(value: str) -> str:
    safe = value.replace("*/", "* /").replace("/*", "/ *").replace("\r", " ").replace("\n", " ")
    return safe.strip()[:256]


def _handler_functions(functions: list[str]) -> list[dict[str, str]]:
    if not functions:
        functions = ["wire_target_call"]
    handlers: list[dict[str, str]] = []
    used: set[str] = set()
    for fn in functions[:16]:
        handler = f"target_{_slug(fn, 'call')}"
        if handler in used:
            suffix = 2
            while f"{handler}_{suffix}" in used:
                suffix += 1
            handler = f"{handler}_{suffix}"
        used.add(handler)
        handlers.append({"handler": handler, "source_function": fn})
    return handlers


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _forge_std_resolution(workspace: Path, out: Path) -> dict[str, str]:
    root = workspace / "lib" / "forge-std"
    if not root.is_dir():
        return {"status": "not_found", "source_root": "", "remapping": ""}
    source_root = root / "src" if (root / "src").is_dir() else root
    rel = Path(os.path.relpath(source_root.resolve(), start=out.resolve())).as_posix()
    remapping = f"forge-std/={rel.rstrip('/')}/"
    return {
        "status": "remapping_written",
        "source_root": str(source_root.resolve()),
        "remapping": remapping,
    }


def _solidity_files(row_id: str, row: dict[str, Any], handlers: list[dict[str, str]]) -> dict[str, str]:
    slug = _slug(row_id)
    title = _comment(str(row.get("title") or row.get("invariant") or row_id))
    target_body = "\n".join(
        f"    function {item['handler']}() public {{\n"
        f"        // TODO: bind to source function `{_comment(item['source_function'])}`.\n"
        "        _chimeraRuns += 1;\n"
        "    }\n"
        for item in handlers
    )
    return {
        "test/recon/Setup.sol": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// {ADVISORY}
contract Setup {{
    address internal actor = address(0xBEEF);

    function setUp() public virtual {{
        // TODO: deploy or bind protocol contracts and seed actors/assets.
    }}
}}
""",
        "test/recon/TargetFunctions.sol": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Setup.sol";

/// {ADVISORY}
contract TargetFunctions is Setup {{
    uint256 internal _chimeraRuns;

{target_body}}}
""",
        "test/recon/Properties.sol": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./TargetFunctions.sol";

/// {ADVISORY}
contract Properties is TargetFunctions {{
    /// Invariant row: {_comment(row_id)}
    /// Claim: {title}
    function property_{slug}() public view returns (bool) {{
        // TODO: replace with the real postcondition from the invariant ledger row.
        return true;
    }}

    function invariant_{slug}() public view {{
        assert(property_{slug}());
    }}
}}
""",
        "test/recon/CryticTester.sol": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Properties.sol";

/// {ADVISORY}
contract CryticTester is Properties {{}}
""",
        "test/recon/CryticToFoundry.sol": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./CryticTester.sol";

/// {ADVISORY}
contract CryticToFoundry is Test, CryticTester {{
    function test_replay_scaffold_{slug}() public {{
        vm.skip(true);
    }}
}}
""",
    }


def _write_harness(out: Path, row_id: str, row: dict[str, Any], manifest: dict[str, Any]) -> None:
    commands = manifest["commands"]
    forge_std = manifest.get("forge_std_resolution") or {}
    remapping_section = ""
    if forge_std.get("remapping"):
        remapping_section = f"""
## Foundry Remapping

- `remappings.txt`: `{forge_std['remapping']}`
"""
    _write(out / "README.md", f"""# Chimera Harness Scaffold: {row_id}

{ADVISORY}

{remapping_section}

This directory was generated from an auditooor invariant-ledger row. It is a
portable Recon/Chimera-style starting point for Foundry, Medusa, Echidna, and
Halmos, but it does not prove a vulnerability until setup, handlers, and
assertions are wired and an execution manifest is recorded.

## Suggested Commands

- `{manifest['forge_build_display']}`
- `{manifest['foundry_invariant_display']}`
- `{manifest['medusa_display']}`
- `{manifest['echidna_display']}`

## Row Snapshot

```json
{json.dumps(row, indent=2, sort_keys=True)}
```
""")
    _write(out / "foundry.toml", """[profile.default]
src = "src"
test = "test"
libs = ["lib"]

[profile.invariants]
test = "test/recon"
""")
    if forge_std.get("remapping"):
        _write(out / "remappings.txt", f"{forge_std['remapping']}\n")
    _write(out / "echidna.yaml", """testMode: assertion
testLimit: 10000
contract: CryticTester
corpusDir: corpus/echidna
""")
    _write(out / "medusa.json", json.dumps({
        "testLimit": 10000,
        "targetContracts": ["CryticTester"],
        "corpusDirectory": "corpus/medusa",
    }, indent=2, sort_keys=True) + "\n")
    for rel, text in _solidity_files(row_id, row, manifest["handler_functions"]).items():
        _write(out / rel, text)
    _write(out / "auditooor_chimera_manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def _write_blocked_manifest(out: Path, row_id: str, row: dict[str, Any], manifest: dict[str, Any]) -> None:
    _write(out / "README.md", f"""# Chimera Harness Scaffold Blocked: {row_id}

{ADVISORY}

No harness Solidity files were generated. This row is blocked until it is
locked to a proved exact impact contract.

## Blocker

- Status: `{manifest['status']}`
- Missing preconditions: `{', '.join(manifest['missing_preconditions'])}`

## Row Snapshot

```json
{json.dumps(row, indent=2, sort_keys=True)}
```
""")
    _write(out / "auditooor_chimera_manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def build_manifest(workspace: Path, row_id: str, ledger: Any, row: dict[str, Any], out: Path) -> dict[str, Any]:
    sources = _discover_source_bindings(workspace, row)
    concrete = _concrete_bindings(sources)
    functions, collisions = _functions_from_sources(sources)
    handlers = _handler_functions(functions)
    commands = {
        "forge_build": ["forge", "build"],
        "foundry_invariant": ["forge", "test", "--match-contract", "CryticToFoundry", "-vv"],
        "medusa": ["medusa", "fuzz", "--config", "medusa.json"],
        "echidna": ["echidna", "test/recon/CryticTester.sol", "--config", "echidna.yaml"],
    }
    impact_contract, missing_impact = _require_locked_impact_contract(workspace, row, row_id)
    status = "scaffolded_unverified" if not missing_impact else "blocked_missing_impact_contract"
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "row_id": row_id,
        "ledger_hash": _canonical_hash(ledger),
        "ledger_provenance_hash": _canonical_hash(ledger),
        "ledger_hash_note": "Provenance hash only; not a signed integrity boundary.",
        "status": status,
        "evidence_class": "scaffolded_unverified",
        "out_dir": str(out),
        "source_bindings": [str(path) for path in sources],
        "contract_bindings": _contract_binding_summary(sources),
        "concrete_bindings": concrete,
        "handler_functions": handlers,
        "handler_collisions": collisions,
        "commands": commands,
        "commands_display_only": True,
        "forge_build_display": shlex.join(commands["forge_build"]),
        "foundry_invariant_display": shlex.join(commands["foundry_invariant"]),
        "medusa_display": shlex.join(commands["medusa"]),
        "echidna_display": shlex.join(commands["echidna"]),
        "forge_std_resolution": _forge_std_resolution(workspace, out),
        "advisory": ADVISORY,
        "impact_contract": impact_contract or {},
        "impact_contract_required": True,
        "impact_contract_id": (impact_contract or {}).get("impact_contract_id", ""),
        "selected_impact": (impact_contract or {}).get("selected_impact", ""),
        "severity": (impact_contract or {}).get("severity", "none") or "none",
        "submit_ready": False,
        "missing_preconditions": missing_impact,
        "blocker_reason": "blocked_missing_impact_contract" if missing_impact else "",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--row-id", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--require-source-binding", action="store_true")
    parser.add_argument("--require-concrete-binding", action="store_true")
    parser.add_argument("--strict-handlers", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    if not _valid_row_id(args.row_id):
        print("invalid row id: allowed characters are letters, numbers, underscore, and single hyphen separators", file=sys.stderr)
        return 2

    workspace = args.workspace.expanduser().resolve()
    ledger_path = workspace / ".auditooor" / "invariant_ledger.json"
    ledger = _read_json(ledger_path)
    row = _find_row(_ledger_rows(ledger), args.row_id)
    out = (args.out or workspace / "chimera_harnesses" / _slug(args.row_id)).expanduser().resolve()
    if out != workspace and workspace not in out.parents:
        print("out directory must be inside the workspace", file=sys.stderr)
        return 2
    manifest = build_manifest(workspace, args.row_id, ledger, row, out)

    if manifest["status"] == "blocked_missing_impact_contract":
        if not args.dry_run:
            _write_blocked_manifest(out, args.row_id, row, manifest)
        if args.print_json or args.dry_run:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"blocked_missing_impact_contract for row {args.row_id}", file=sys.stderr)
        return 2

    if args.require_source_binding and not manifest["source_bindings"]:
        print(f"no source binding found for row {args.row_id}", file=sys.stderr)
        return 2
    if args.require_concrete_binding and not manifest["concrete_bindings"]:
        print(f"no concrete contract binding found for row {args.row_id}", file=sys.stderr)
        return 2
    if args.strict_handlers:
        names = [item["handler"] for item in manifest["handler_functions"]]
        if len(names) != len(set(names)) or manifest["handler_collisions"]:
            print(f"handler collision for row {args.row_id}", file=sys.stderr)
            return 2

    if not args.dry_run:
        _write_harness(out, args.row_id, row, manifest)

    if args.print_json or args.dry_run:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
