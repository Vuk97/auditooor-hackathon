"""Offline-safe Foundry version inventory helpers.

The migration to Foundry v1.7.1 must be evidence-preserving. These helpers
only inspect local binaries with version commands; they never install, upgrade,
or reach the network.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    tomllib = None  # type: ignore[assignment]
from pathlib import Path
from typing import Any


PLANNED_TARGET_VERSION = "v1.7.1"
SCHEMA_VERSION = "auditooor.foundry_version_inventory.v1"

UPGRADE_RISKS = [
    "forge/anvil default hardfork changes to Osaka unless workspaces pin evm_version, hardfork, or network",
    "fuzz tests use a random seed when none is set, so proof runs need explicit seeds",
    "copyStorage and setArbitraryStorage are marked Unsafe and may break existing helpers",
    "unresolved imports now fail compilation instead of continuing",
    "per-network config can expose stale single-hardfork assumptions",
    "invariant check_interval > 1 can miss transient violations and should stay exploratory unless justified",
    "parallel fuzzing can change corpus timing/order, so manifests must record seed, profile, workers, and config",
]

VALIDATION_COMMANDS = [
    "python3 tools/foundry-version-report.py --workspace <ws> --print-json",
    "forge build",
    "forge test",
    "forge test --match-contract <Contract> --fuzz-seed <seed>",
    "FOUNDRY_PROFILE=invariants forge test --match-contract <InvariantContract> --fuzz-seed <seed>",
    "python3 tools/poc-execution-record.py --workspace <ws> --brief <brief.md> --run 'forge test ...'",
]

RECOMMENDED_PROFILES = {
    "profile.default": {
        "purpose": "normal PoC build/test profile",
        "required_for_proof": ["explicit evm_version or hardfork/network"],
    },
    "profile.invariants": {
        "purpose": "proof-quality invariant profile",
        "required_for_proof": ["explicit fuzz seed", "check_interval omitted or 1"],
    },
    "profile.invariants_fast": {
        "purpose": "exploratory throughput profile only",
        "required_for_proof": ["not final evidence unless interval safety is justified"],
    },
    "profile.fuzz_repro": {
        "purpose": "deterministic fuzz replay profile",
        "required_for_proof": ["explicit seed", "recorded Foundry version"],
    },
}


def _first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _clean_version_token(token: str) -> str:
    return token.strip().strip(",;()[]{}")


def normalize_foundry_version(version: str) -> str:
    match = re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b", version)
    return match.group(1) if match else ""


def _version_family(version: str) -> str:
    normalized = normalize_foundry_version(version)
    return f"v{normalized}" if normalized else ""


def _release_channel(version: str) -> str:
    lowered = version.lower()
    if "nightly" in lowered:
        return "nightly"
    if any(token in lowered for token in ("alpha", "beta", "rc")):
        return "pre-release"
    if "stable" in lowered:
        return "stable"
    if normalize_foundry_version(version):
        return "release"
    return "unknown"


def parse_foundry_version(raw: str, tool: str) -> tuple[str, str]:
    """Return ``(version, commit_sha)`` parsed from a Foundry version output."""
    version = ""
    commit_sha = ""
    patterns = [
        rf"\b{re.escape(tool)}\s+Version:\s*([^\s]+)",
        rf"\b{re.escape(tool)}\s+version[:\s]*([^\s]+)",
        rf"\b{re.escape(tool)}[:\s]+([^\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            version = _clean_version_token(match.group(1))
            break
    if not version:
        first = _first_nonempty_line(raw)
        generic = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+(?:[-+][^\s]+)?|v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][^\s]+)?)\b", first)
        if generic:
            version = _clean_version_token(generic.group(1))
    sha_match = re.search(r"\b(?:Commit SHA|commit)[:\s]+([0-9a-fA-F]{7,40})\b", raw)
    if sha_match:
        commit_sha = sha_match.group(1)
    return version or "version-unknown", commit_sha


def _normalized_semver(version: str) -> str:
    return normalize_foundry_version(version)


def current_matches_planned_target(tools: dict[str, dict[str, Any]], planned_target: str) -> bool | None:
    """Compare present Foundry tool versions with the planned target."""
    target = _normalized_semver(planned_target)
    comparable_versions = [
        _normalized_semver(str(meta.get("version", "")))
        for meta in tools.values()
        if meta.get("present")
    ]
    comparable_versions = [version for version in comparable_versions if version]
    if not target or not comparable_versions:
        return None
    return all(version == target for version in comparable_versions)


def _run_version(binary: str, args: list[str], timeout: float) -> tuple[int | None, str, str]:
    try:
        proc = subprocess.run(
            [binary, *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "", str(exc)


def collect_tool(tool: str, *, timeout: float = 5.0, env: dict[str, str] | None = None) -> dict[str, Any]:
    """Collect local version metadata for one Foundry binary."""
    search_path = None if env is None else env.get("PATH")
    path = shutil.which(tool, path=search_path)
    result: dict[str, Any] = {
        "tool": tool,
        "present": bool(path),
        "path": path or "",
        "version": "",
        "normalized_version": "",
        "version_family": "",
        "release_channel": "unknown",
        "commit_sha": "",
        "returncode": None,
        "raw_output": "",
        "error": "",
    }
    if not path:
        result["error"] = "not found on PATH"
        return result
    returncode, stdout, stderr = _run_version(path, ["--version"], timeout)
    raw = "\n".join(part.strip() for part in (stdout, stderr) if part.strip())
    version, commit_sha = parse_foundry_version(raw, tool)
    result.update(
        {
            "version": version,
            "normalized_version": normalize_foundry_version(version),
            "version_family": _version_family(version),
            "release_channel": _release_channel(version),
            "commit_sha": commit_sha,
            "returncode": returncode,
            "raw_output": raw[:4000],
            "error": "" if returncode == 0 else (stderr.strip() or stdout.strip() or "version command failed")[:500],
        }
    )
    return result


def collect_foundryup(*, timeout: float = 5.0, env: dict[str, str] | None = None) -> dict[str, Any]:
    search_path = None if env is None else env.get("PATH")
    path = shutil.which("foundryup", path=search_path)
    result: dict[str, Any] = {
        "tool": "foundryup",
        "present": bool(path),
        "path": path or "",
        "version": "",
        "normalized_version": "",
        "version_family": "",
        "release_channel": "unknown",
        "channel": "",
        "returncode": None,
        "raw_output": "",
        "error": "",
    }
    if not path:
        result["error"] = "not found on PATH"
        return result
    returncode, stdout, stderr = _run_version(path, ["--version"], timeout)
    raw = "\n".join(part.strip() for part in (stdout, stderr) if part.strip())
    version, _commit = parse_foundry_version(raw, "foundryup")
    result.update(
        {
            "version": version,
            "normalized_version": normalize_foundry_version(version),
            "version_family": _version_family(version),
            "release_channel": _release_channel(version),
            "channel": os.environ.get("FOUNDRYUP_CHANNEL", ""),
            "returncode": returncode,
            "raw_output": raw[:4000],
            "error": "" if returncode == 0 else (stderr.strip() or stdout.strip() or "version command failed")[:500],
        }
    )
    return result


def _is_ignored_foundry_path(path: Path) -> bool:
    ignored = {"lib", "vendor", "node_modules", ".git", "out", "cache"}
    return any(part in ignored for part in path.parts)


def find_foundry_tomls(workspace: Path) -> list[Path]:
    if not workspace.exists():
        return []
    found = []
    root = workspace / "foundry.toml"
    if root.is_file():
        found.append(root)
    for path in sorted(workspace.rglob("foundry.toml")):
        if path == root or _is_ignored_foundry_path(path.relative_to(workspace)):
            continue
        found.append(path)
    return found


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is not None:
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return _regex_toml_fallback(path)


def _regex_toml_fallback(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"profile": {"default": {}}}
    current: list[str] = ["profile", "default"]
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        section = re.match(r"\[([^\]]+)\]", line)
        if section:
            current = section.group(1).split(".")
            node = data
            for part in current:
                node = node.setdefault(part, {})
            continue
        match = re.match(r"([A-Za-z0-9_-]+)\s*=\s*(.+)", line)
        if not match:
            continue
        key, value = match.groups()
        value = value.strip().strip('"').strip("'")
        node = data
        for part in current:
            node = node.setdefault(part, {})
        if value.lower() in {"true", "false"}:
            node[key] = value.lower() == "true"
        elif value.isdigit():
            node[key] = int(value)
        else:
            node[key] = value
    return data


def _walk_dict(data: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_walk_dict(value, path))
    else:
        out.append((prefix, data))
    return out


def _has_key(data: dict[str, Any], key: str) -> bool:
    return any(path.endswith(f".{key}") or path == key for path, _value in _walk_dict(data))


def _values_for_key(data: dict[str, Any], key: str) -> list[tuple[str, Any]]:
    return [(path, value) for path, value in _walk_dict(data) if path.endswith(f".{key}") or path == key]


def scan_foundry_config(workspace: Path | None) -> dict[str, Any]:
    """Scan foundry.toml files for v1.7 migration readiness risks."""
    if workspace is None:
        return {
            "foundry_toml_count": 0,
            "configs": [],
            "warnings": [],
            "warning_counts": {},
            "recommended_profiles": RECOMMENDED_PROFILES,
        }
    configs: list[dict[str, Any]] = []
    warnings: list[dict[str, str]] = []
    for toml in find_foundry_tomls(workspace):
        data = _load_toml(toml)
        rel = str(toml.relative_to(workspace))
        evm_values = _values_for_key(data, "evm_version")
        hardfork_values = _values_for_key(data, "hardfork")
        network_values = _values_for_key(data, "network")
        seed_values = _values_for_key(data, "seed")
        check_interval_values = _values_for_key(data, "check_interval")
        profiles = data.get("profile") if isinstance(data.get("profile"), dict) else {}
        config = {
            "path": rel,
            "has_explicit_evm_version": bool(evm_values),
            "has_explicit_hardfork": bool(hardfork_values),
            "has_explicit_network": bool(network_values),
            "has_fuzz_seed": bool(seed_values),
            "has_invariant_profile": "invariants" in profiles,
            "has_fast_invariant_profile": "invariants_fast" in profiles,
            "has_fuzz_repro_profile": "fuzz_repro" in profiles,
            "evm_version_values": evm_values,
            "hardfork_values": hardfork_values,
            "network_values": network_values,
            "seed_values": seed_values,
            "check_interval_values": check_interval_values,
        }
        configs.append(config)
        if not (evm_values or hardfork_values):
            warnings.append({
                "path": rel,
                "code": "missing_explicit_hardfork",
                "message": "Pin evm_version or hardfork before v1.7.1 trial; Osaka defaults can change behavior.",
            })
        if not network_values:
            warnings.append({
                "path": rel,
                "code": "missing_network_key",
                "message": "Consider explicit network/per-network config for forked or live-proof workspaces.",
            })
        if not seed_values:
            warnings.append({
                "path": rel,
                "code": "missing_fuzz_seed",
                "message": "Final fuzz/invariant evidence should set an explicit seed.",
            })
        for path, value in check_interval_values:
            try:
                interval = int(value)
            except (TypeError, ValueError):
                interval = 0
            if interval > 1:
                warnings.append({
                    "path": rel,
                    "code": "check_interval_exploratory_only",
                    "message": f"{path}={value} can miss transient violations; do not use as final proof without justification.",
                })
        if not ("invariants" in profiles or "fuzz_repro" in profiles):
            warnings.append({
                "path": rel,
                "code": "missing_repro_profiles",
                "message": "Add proof-quality invariants/fuzz_repro profiles before relying on v1.7.1 campaign evidence.",
            })
    counts: dict[str, int] = {}
    for warning in warnings:
        counts[warning["code"]] = counts.get(warning["code"], 0) + 1
    return {
        "foundry_toml_count": len(configs),
        "configs": configs,
        "warnings": warnings,
        "warning_counts": counts,
        "recommended_profiles": RECOMMENDED_PROFILES,
    }


def readiness_accounting(inventory: dict[str, Any]) -> dict[str, Any]:
    current = inventory.get("current", {})
    config_scan = inventory.get("config_scan", {})
    workspace = str(inventory.get("workspace") or "<ws>")
    missing_tools = [
        name for name in ("forge", "cast", "anvil")
        if not current.get(name, {}).get("present")
    ]
    unparsed_versions = [
        name for name in ("forge", "cast", "anvil")
        if current.get(name, {}).get("present")
        and not current.get(name, {}).get("normalized_version")
    ]
    warnings = config_scan.get("warnings") or []
    blockers = []
    blocker_details = []
    if missing_tools:
        blockers.append("missing_foundry_tools")
        for tool in missing_tools:
            blocker_details.append(
                {
                    "id": f"foundry-tool-missing:{tool}",
                    "tool": tool,
                    "kind": "missing_foundry_tool",
                    "detail": f"`{tool}` is not available on PATH for this inventory run.",
                    "next_action": f"Expose the existing `{tool}` binary on PATH, then rerun `python3 tools/foundry-version-report.py --workspace {workspace} --print-json`.",
                }
            )
    if unparsed_versions:
        blockers.append("unparsed_foundry_versions")
        for tool in unparsed_versions:
            blocker_details.append(
                {
                    "id": f"foundry-version-unparsed:{tool}",
                    "tool": tool,
                    "kind": "unparsed_foundry_version",
                    "detail": f"`{tool} --version` ran, but the output did not normalize to a semver core.",
                    "next_action": f"Capture `{tool} --version` from the same PATH and rerun `python3 tools/foundry-version-report.py --workspace {workspace} --print-json`; if this is an isolated toolchain, repoint PATH to the directory that contains the real Foundry binaries.",
                }
            )
    if config_scan.get("foundry_toml_count", 0) == 0:
        blockers.append("no_foundry_toml_detected")
        blocker_details.append(
            {
                "id": "foundry-config-missing",
                "tool": "foundry.toml",
                "kind": "missing_foundry_config",
                "detail": "No `foundry.toml` was discovered under the workspace.",
                "next_action": f"Point the workflow at the Forge project root, then rerun `python3 tools/foundry-version-report.py --workspace {workspace} --print-json` before building a v1.7 trial plan.",
            }
        )
    return {
        "status": "ready_for_isolated_trial" if not blockers and not warnings else "needs_migration_review",
        "blockers": blockers,
        "blocker_details": blocker_details,
        "warning_count": len(warnings),
        "missing_tools": missing_tools,
        "unparsed_versions": unparsed_versions,
        "next_actions": [
            f"review {workspace}/.auditooor/foundry_version_inventory.md" if workspace != "<ws>" else "review <ws>/.auditooor/foundry_version_inventory.md",
            "pin hardfork/evm_version/network before comparing v1.5.x and v1.7.1 behavior",
            "set explicit fuzz seeds for final proof profiles",
            "run validation commands only in an operator-approved isolated v1.7.1 trial",
        ],
    }


def build_inventory(workspace: Path | None = None, *, timeout: float = 5.0, env: dict[str, str] | None = None) -> dict[str, Any]:
    tools = {name: collect_tool(name, timeout=timeout, env=env) for name in ("forge", "cast", "anvil")}
    present_versions = {
        name: meta.get("version", "")
        for name, meta in tools.items()
        if meta.get("present") and meta.get("version")
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace.expanduser().resolve()) if workspace else "",
        "planned_target": {
            "foundry_version": PLANNED_TARGET_VERSION,
            "status": "planned_not_executed",
            "upgrade_performed": False,
        },
        "current": {
            "forge": tools["forge"],
            "cast": tools["cast"],
            "anvil": tools["anvil"],
            "foundryup": collect_foundryup(timeout=timeout, env=env),
        },
        "current_matches_planned_target": current_matches_planned_target(tools, PLANNED_TARGET_VERSION),
        "current_version_summary": present_versions,
        "config_scan": scan_foundry_config(workspace.expanduser().resolve() if workspace else None),
        "upgrade_risks": UPGRADE_RISKS,
        "validation_commands": VALIDATION_COMMANDS,
        "proof_boundary": (
            "This inventory is planning/environment metadata only. It does not install Foundry, "
            "upgrade Foundry, run Forge tests, or prove exploit impact."
        ),
    }
    report["readiness_accounting"] = readiness_accounting(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    current = report.get("current", {})
    rows = []
    for name in ("forge", "cast", "anvil", "foundryup"):
        meta = current.get(name, {}) if isinstance(current, dict) else {}
        rows.append(
            "| {name} | {present} | {version} | {commit} | {path} |".format(
                name=name,
                present="yes" if meta.get("present") else "no",
                version=" / ".join(
                    part for part in (
                        meta.get("version") or "",
                        meta.get("version_family") or "",
                        meta.get("release_channel") or "",
                    )
                    if part
                ),
                commit=meta.get("commit_sha") or meta.get("channel") or "",
                path=meta.get("path") or "",
            )
        )
    risks = "\n".join(f"- {risk}" for risk in report.get("upgrade_risks", []))
    commands = "\n".join(f"- `{cmd}`" for cmd in report.get("validation_commands", []))
    config_scan = report.get("config_scan", {})
    readiness = report.get("readiness_accounting", {})
    current_match = report.get("current_matches_planned_target")
    current_match_text = "unknown" if current_match is None else ("yes" if current_match else "no")
    warnings = "\n".join(
        f"- `{w.get('code')}` in `{w.get('path')}`: {w.get('message')}"
        for w in config_scan.get("warnings", [])
    ) or "- none"
    blockers = "\n".join(
        f"- `{b.get('id')}`: {b.get('detail')} Next action: {b.get('next_action')}"
        for b in readiness.get("blocker_details", [])
    ) or "- none"
    next_actions = "\n".join(f"- {item}" for item in readiness.get("next_actions", [])) or "- none"
    return "\n".join(
        [
            "# Foundry Version Inventory",
            "",
            f"Workspace: `{report.get('workspace') or 'not specified'}`",
            "",
            f"Planned target: `{report.get('planned_target', {}).get('foundry_version', PLANNED_TARGET_VERSION)}`",
            "",
            "Status: planned_not_executed; no install or upgrade was performed.",
            "",
            f"Current matches planned target: `{current_match_text}`",
            "",
            "| Tool | Present | Version | Commit/Channel | Path |",
            "|---|---:|---|---|---|",
            *rows,
            "",
            "## Config Scan",
            "",
            f"- foundry.toml files: {config_scan.get('foundry_toml_count', 0)}",
            f"- readiness: `{readiness.get('status', 'unknown')}`",
            f"- blockers: `{', '.join(readiness.get('blockers', [])) or 'none'}`",
            "",
            "## Config Warnings",
            "",
            warnings,
            "",
            "## Workflow Blockers",
            "",
            blockers,
            "",
            "## Upgrade Risks",
            "",
            risks,
            "",
            "## Validation Commands",
            "",
            commands,
            "",
            "## Proof Boundary",
            "",
            str(report.get("proof_boundary", "")),
            "",
            "## Next Actions",
            "",
            next_actions,
            "",
        ]
    )
