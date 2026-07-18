#!/usr/bin/env python3
"""Emit a fail-closed KLBQ-006 Solidity/source-aware replay status packet."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.klbq_006_solidity_replay_status.v1"
DEFAULT_DATE = "2026-05-05"
LIMITATION_ID = "KLBQ-006"
FINDING_ID = "30522"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_boundary_path(root: Path) -> Path:
    return root / "reports" / f"klbq_006_terminal_boundary_{DEFAULT_DATE}.json"


def default_anchors_path(root: Path) -> Path:
    return root / "reports" / f"klbq_006_real_source_anchors_{DEFAULT_DATE}.json"


def default_output_path(root: Path) -> Path:
    return root / "reports" / f"klbq_006_solidity_replay_status_{DEFAULT_DATE}.json"


def default_docs_path(root: Path) -> Path:
    return root / "docs" / f"KLBQ_006_SOLIDITY_REPLAY_STATUS_{DEFAULT_DATE}.md"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_terminal_boundary_module(root: Path) -> Any:
    tool_path = root / "tools" / "klbq006-terminal-boundary.py"
    spec = importlib.util.spec_from_file_location("klbq006_terminal_boundary", tool_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load terminal boundary module from {tool_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_argv(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _git_stdout(root: Path, args: list[str]) -> str | None:
    proc = _run_argv(["git", "-C", str(root), *args])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _git_text(root: Path, ref: str, rel_path: str) -> str:
    proc = _run_argv(["git", "-C", str(root), "show", f"{ref}:{rel_path}"])
    if proc.returncode == 0:
        return proc.stdout
    if ref in {"HEAD", "WORKTREE"}:
        path = root / rel_path
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    return ""


def _previous_foundry_record(previous_report: dict[str, Any] | None, command: str) -> dict[str, Any] | None:
    if not previous_report:
        return None
    command_consumption = previous_report.get("command_consumption")
    if not isinstance(command_consumption, dict):
        return None
    records = command_consumption.get("commands")
    if not isinstance(records, list):
        return None
    for record in records:
        if not isinstance(record, dict):
            continue
        if (
            record.get("kind") == "foundry_anchor_test"
            and record.get("command") == command
            and record.get("executed") is True
            and isinstance(record.get("execution_blocker"), dict)
        ):
            reused = dict(record)
            reused["reused_existing_execution_record"] = True
            reused["reuse_reason"] = (
                "Preserved the prior observed Foundry dependency failure without re-running "
                "network/submodule fetch work."
            )
            return reused
    return None


def _command_kind(command: str) -> str:
    if "klbq006-terminal-boundary.py" in command:
        return "terminal_boundary_regeneration"
    if "tools/rust-detect.py" in command:
        return "rust_detector_boundary_reference"
    if command.startswith("git ") and " show " in command:
        return "git_show_commit"
    if command.startswith("git ") and " grep " in command:
        if " HEAD " in command:
            return "git_grep_head"
        return "git_grep_pinned"
    if command.startswith("forge test "):
        return "foundry_anchor_test"
    return "other"


def _record_git_command(command: str) -> dict[str, Any]:
    argv = shlex.split(command)
    proc = _run_argv(argv)
    stdout_lines = [line for line in proc.stdout.splitlines() if line.strip()]
    stderr_lines = [line for line in proc.stderr.splitlines() if line.strip()]
    record = {
        "command": command,
        "kind": _command_kind(command),
        "executed": True,
        "exit_code": proc.returncode,
        "status": "passed" if proc.returncode == 0 else "failed",
        "stdout_line_count": len(stdout_lines),
        "stdout_excerpt": stdout_lines[:12],
        "stderr_excerpt": stderr_lines[:12],
        "checks": [],
    }
    if record["kind"] == "git_show_commit":
        record["checks"] = [
            {
                "name": "commit_summary_printed",
                "passed": bool(stdout_lines),
            }
        ]
    elif record["kind"] == "git_grep_pinned":
        record["checks"] = [
            {
                "name": "pinned_guard_anchor_present",
                "passed": any("src/policies/Guard.sol" in line for line in stdout_lines),
            },
            {
                "name": "pinned_factory_anchor_present",
                "passed": any("src/policies/Factory.sol" in line for line in stdout_lines),
            },
            {
                "name": "pinned_direct_setfallbackhandler_selector_absent",
                "passed": not any("setFallbackHandler" in line for line in stdout_lines),
            },
        ]
    elif record["kind"] == "git_grep_head":
        record["checks"] = [
            {
                "name": "head_selector_constant_present",
                "passed": any("gnosis_safe_set_fallback_handler_selector" in line for line in stdout_lines),
            },
            {
                "name": "head_prevented_exploit_test_present",
                "passed": any("SetCustomFallbackHandler.t.sol" in line for line in stdout_lines),
            },
        ]
    return record


def _record_boundary_reference(command: str, kind: str, *, note: str) -> dict[str, Any]:
    return {
        "command": command,
        "kind": kind,
        "executed": False,
        "exit_code": None,
        "status": "imported_from_terminal_boundary",
        "checks": [{"name": "boundary_reference_consumed", "passed": True}],
        "note": note,
    }


def _foundry_execution_blocker(command: str, lines: list[str]) -> dict[str, Any] | None:
    combined = "\n".join(lines)
    if "Source \"" not in combined and "No such file or directory" not in combined and "Could not resolve host" not in combined:
        return None

    missing_paths = sorted(
        {
            match.group(1)
            for line in lines
            for match in [re.search(r'Source "([^"]+)" not found', line)]
            if match
        }
    )
    missing_files = sorted(
        {
            match.group(1)
            for line in lines
            for match in [re.search(r'error="([^"]+)": No such file or directory', line)]
            if match
        }
    )
    failed_urls = sorted(
        {
            match.group(1)
            for line in lines
            for match in [re.search(r"unable to access '([^']+)'", line)]
            if match
        }
    )
    root = None
    argv = shlex.split(command)
    for idx, token in enumerate(argv):
        if token == "--root" and idx + 1 < len(argv):
            root = argv[idx + 1]
            break

    unblock_command = f"git -C {root} submodule update --init --recursive" if root else None
    return {
        "state": "blocked_missing_foundry_dependencies",
        "dependency_install_attempted": "Missing dependencies found. Installing now..." in combined
        or any("Cloning into" in line for line in lines),
        "network_resolution_failure": "Could not resolve host" in combined,
        "missing_import_count": len(missing_paths),
        "missing_source_file_count": len(missing_files),
        "missing_dependency_paths": missing_paths[:20],
        "missing_source_files": missing_files[:20],
        "failed_submodule_urls": failed_urls,
        "unblock_command": unblock_command,
        "rerun_exact_proof_command": command,
        "claim_limits": {
            "executable_solidity_replay_performed": False,
            "exploit_proof_allowed": False,
            "verification_claim_allowed": False,
        },
    }


def _record_foundry_command(command: str, *, execute_foundry: bool) -> dict[str, Any]:
    forge_path = shutil.which("forge")
    record = {
        "command": command,
        "kind": "foundry_anchor_test",
        "executed": False,
        "exit_code": None,
        "status": "not_executed_fail_closed",
        "checks": [
            {
                "name": "head_anchor_command_present",
                "passed": True,
            },
            {
                "name": "head_anchor_test_is_not_exact_30522_proof",
                "passed": True,
            },
            {
                "name": "exact_30522_executable_proof_present",
                "passed": False,
            },
        ],
        "forge_available": bool(forge_path),
        "note": (
            "The terminal boundary only carries a HEAD anchor test. Even if executed, "
            "it is not an exact #30522 vulnerable-path Foundry proof."
        ),
    }
    if not execute_foundry:
        return record
    if not forge_path:
        record["status"] = "forge_missing_fail_closed"
        record["note"] = "forge is not available locally, so the anchor test was not executed."
        return record

    proc = _run_argv(shlex.split(command))
    stdout_lines = [line for line in proc.stdout.splitlines() if line.strip()]
    stderr_lines = [line for line in proc.stderr.splitlines() if line.strip()]
    all_lines = stdout_lines + stderr_lines
    blocker = _foundry_execution_blocker(command, all_lines)
    status = "executed_anchor_test_not_exact_proof" if proc.returncode == 0 else "anchor_test_failed"
    if blocker:
        status = "foundry_dependency_blocked_fail_closed"
    record.update(
        {
            "executed": True,
            "exit_code": proc.returncode,
            "status": status,
            "stdout_line_count": len(stdout_lines),
            "stdout_excerpt": stdout_lines[:12],
            "stderr_excerpt": stderr_lines[:12],
        }
    )
    if blocker:
        record["execution_blocker"] = blocker
        record["checks"].append({"name": "foundry_dependency_blocker_recorded", "passed": True})
    return record


def _probe_pinned_source(root: Path, source_root: Path, pinned_ref: str) -> dict[str, Any]:
    terminal_mod = _load_terminal_boundary_module(root)
    texts = {
        rel_path: _git_text(source_root, pinned_ref, rel_path)
        for rel_path in terminal_mod.SOLIDITY_FILES
    }
    probe = terminal_mod.probe_solidity_texts(texts, ref=pinned_ref, commit=_git_stdout(source_root, ["rev-parse", "--verify", f"{pinned_ref}^{{commit}}"]))
    commit = probe.get("commit")
    if commit:
        raw = _git_stdout(source_root, ["show", "--no-patch", "--format=%H%n%cI%n%s", commit])
        if raw:
            parts = raw.splitlines()
            probe["commit_info"] = {
                "commit": parts[0] if len(parts) > 0 else commit,
                "committed_at": parts[1] if len(parts) > 1 else None,
                "subject": parts[2] if len(parts) > 2 else None,
            }
    return probe


def _citation_status(anchors_packet: dict[str, Any]) -> dict[str, Any]:
    classification = anchors_packet.get("classification")
    if not isinstance(classification, dict):
        classification = {}
    exact_blob_state = str(classification.get("exact_finding_github_blob_anchors") or "unknown")
    exact_metadata_state = str(classification.get("exact_finding_source_metadata") or "unknown")
    exact_spec_state = str(classification.get("exact_finding_source_specs") or "unknown")
    root_state = str(classification.get("exact_renft_source_root") or "unknown")
    real_anchor_state = str(classification.get("real_source_anchors") or "unknown")
    exact_present = (
        exact_blob_state == "present"
        or exact_metadata_state == "eligible"
        or exact_spec_state == "eligible"
    )
    return {
        "exact_finding_github_blob_anchors": exact_blob_state,
        "exact_finding_source_metadata": exact_metadata_state,
        "exact_finding_source_specs": exact_spec_state,
        "exact_renft_source_root": root_state,
        "real_source_anchors": real_anchor_state,
        "exact_citation_present": exact_present,
        "exact_citation_absent": not exact_present,
    }


def _source_citation_acquisition_status(
    *,
    anchors_packet: dict[str, Any],
    source_root: Path,
    pinned_ref: str,
) -> dict[str, Any]:
    classification = anchors_packet.get("classification")
    if not isinstance(classification, dict):
        classification = {}
    summary = anchors_packet.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    exact_blob_state = str(classification.get("exact_finding_github_blob_anchors") or "unknown")
    exact_metadata_state = str(classification.get("exact_finding_source_metadata") or "unknown")
    exact_spec_state = str(classification.get("exact_finding_source_specs") or "unknown")
    exact_present = (
        exact_blob_state == "present"
        or exact_metadata_state == "eligible"
        or exact_spec_state == "eligible"
    )
    absence_proof = anchors_packet.get("absence_proof")
    if not isinstance(absence_proof, dict):
        absence_proof = {}
    source_metadata_candidates = anchors_packet.get("exact_finding_source_metadata_candidates")
    if not isinstance(source_metadata_candidates, list):
        source_metadata_candidates = []
    source_spec_candidates = anchors_packet.get("exact_finding_source_spec_candidates")
    if not isinstance(source_spec_candidates, list):
        source_spec_candidates = []
    root = repo_root()
    scan_root = str(source_root) if source_root.exists() else "<local-renft-source-root>"
    searched_roots = absence_proof.get("searched_roots")
    root_scan_paths = []
    if isinstance(searched_roots, list):
        for item in searched_roots:
            if isinstance(item, dict) and item.get("path"):
                root_scan_paths.append(str(item["path"]))
    if not root_scan_paths:
        root_scan_paths = [scan_root, str(root)]
    root_flags = " ".join(f"--root {shlex.quote(path)}" for path in root_scan_paths)
    root_scan_command = (
        "python3 tools/klbq006-real-source-anchors.py "
        f"{root_flags} "
        "--out reports/klbq_006_real_source_anchors_2026-05-05.json --max-files 100000"
    )
    local_metadata_command = (
        "rg -n "
        "\"Solodit\\s+#30522|solodit_id:\\s*['\\\"]?30522\\b|"
        "30522.*setFallbackHandler|setFallbackHandler.*30522\" "
        "detectors docs reports reference "
        "-g \"*.yaml\" -g \"*.yml\" -g \"*.md\" -g \"*.json\""
    )
    pinned_anchor_command = (
        f"git -C {shlex.quote(scan_root)} grep -n "
        "\"setFallbackHandler\\|fallbackHandler\\|checkTransaction\\|f08a0323\" "
        f"{shlex.quote(pinned_ref or '<reviewed-ref>')} -- \"*.sol\""
    )

    accepted_criteria = absence_proof.get("accepted_exact_citation_criteria")
    if not isinstance(accepted_criteria, list):
        accepted_criteria = [
            "the source artifact names Solodit #30522 or carries solodit_id 30522",
            "the citation is from source metadata, a source spec, or reviewed report evidence rather than generated KLBQ docs",
            "the citation points to re-nft/smart-contracts or an equivalent local checkout for the reviewed vulnerable source",
            "the cited ref resolves locally to the reviewed commit or tag before replay",
            "the cited file/line anchors cover the Guard/Factory fallback-handler path relevant to setFallbackHandler(address)",
        ]
    remaining_missing_inputs = absence_proof.get("remaining_missing_inputs")
    if not isinstance(remaining_missing_inputs, list):
        remaining_missing_inputs = [
            "exact Solodit #30522 source report or source-spec row",
            "exact reviewed GitHub blob URL or local file/line citation for #30522",
            "reviewed commit or tag tied to that exact #30522 citation",
            "local checkout/ref verification for the cited vulnerable source",
        ]

    return {
        "schema": "auditooor.klbq_006_source_citation_acquisition.v1",
        "state": (
            "exact_30522_citation_present"
            if exact_present
            else "blocked_pending_exact_30522_source_citation"
        ),
        "limitation_id": LIMITATION_ID,
        "finding_id": FINDING_ID,
        "candidate_source_root": scan_root,
        "candidate_pinned_ref": pinned_ref,
        "local_evidence_counts": {
            "candidate_renft_roots": int(summary.get("candidate_renft_roots") or 0),
            "possible_renft_source_hits": int(summary.get("possible_renft_source_hits") or 0),
            "renft_base_github_blob_anchors": int(summary.get("renft_base_github_blob_anchors") or 0),
            "exact_finding_github_blob_anchors": int(summary.get("exact_finding_github_blob_anchors") or 0),
            "exact_finding_source_metadata_candidates": int(
                summary.get("exact_finding_source_metadata_candidates") or 0
            ),
            "eligible_exact_finding_source_metadata": int(
                summary.get("eligible_exact_finding_source_metadata") or 0
            ),
            "exact_finding_source_spec_candidates": int(
                summary.get("exact_finding_source_spec_candidates") or 0
            ),
            "eligible_exact_finding_source_specs": int(
                summary.get("eligible_exact_finding_source_specs") or 0
            ),
            "local_reference_hits": int(summary.get("local_reference_hits") or 0),
        },
        "exact_finding_source_metadata": exact_metadata_state,
        "exact_finding_source_specs": exact_spec_state,
        "source_metadata_candidates": source_metadata_candidates[:20],
        "source_spec_candidates": source_spec_candidates[:20],
        "searched_roots": absence_proof.get("searched_roots", []),
        "query_set": absence_proof.get("query_set", []),
        "accepted_exact_citation_criteria": [str(item) for item in accepted_criteria],
        "missing_inputs": (
            []
            if exact_present
            else [str(item) for item in remaining_missing_inputs]
        ),
        "absence_proof": {
            "searched_roots": absence_proof.get("searched_roots", []),
            "query_set": absence_proof.get("query_set", []),
            "accepted_exact_citation_criteria": [str(item) for item in accepted_criteria],
            "remaining_missing_inputs": [] if exact_present else [str(item) for item in remaining_missing_inputs],
            "disqualified_exact_metadata_candidates": absence_proof.get(
                "disqualified_exact_metadata_candidates", []
            ),
            "disqualified_exact_source_spec_candidates": absence_proof.get(
                "disqualified_exact_source_spec_candidates", []
            ),
        },
        "fail_closed_until": [
            "exact_finding_github_blob_anchors is present in reports/klbq_006_real_source_anchors_2026-05-05.json",
            "the cited ref resolves in the local reNFT checkout",
            "the exact #30522 source citation is recorded before any Foundry replay or promotion claim",
        ],
        "exact_next_commands": [root_scan_command, local_metadata_command, pinned_anchor_command],
        "claim_limits": {
            "source_citation_acquired": exact_present,
            "executable_solidity_replay_performed": False,
            "exploit_proof_allowed": False,
            "verification_claim_allowed": False,
            "promotion_ready": False,
        },
    }


def _next_exact_command(
    records: list[dict[str, Any]],
    citation: dict[str, Any],
    citation_acquisition: dict[str, Any],
) -> str | None:
    if citation.get("exact_citation_absent"):
        commands = citation_acquisition.get("exact_next_commands")
        if isinstance(commands, list) and commands:
            return str(commands[0])
    for record in records:
        if record["kind"] == "foundry_anchor_test" and record["status"] in {
            "not_executed_fail_closed",
            "forge_missing_fail_closed",
        }:
            return str(record["command"])
        blocker = record.get("execution_blocker")
        if record["kind"] == "foundry_anchor_test" and isinstance(blocker, dict):
            unblock_command = blocker.get("unblock_command")
            if unblock_command:
                return str(unblock_command)
    return None


def _parse_gitmodules(source_root: Path) -> dict[str, str]:
    gitmodules_path = source_root / ".gitmodules"
    if not gitmodules_path.is_file():
        return {}

    urls: dict[str, str] = {}
    current_path: str | None = None
    for raw_line in gitmodules_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("[submodule "):
            current_path = None
            continue
        if line.startswith("path"):
            _, _, value = line.partition("=")
            current_path = value.strip()
            urls.setdefault(current_path, "")
            continue
        if line.startswith("url") and current_path:
            _, _, value = line.partition("=")
            urls[current_path] = value.strip()
    return urls


def _submodule_statuses(source_root: Path) -> dict[str, dict[str, str]]:
    proc = _run_argv(["git", "-C", str(source_root), "submodule", "status", "--recursive"])
    if proc.returncode != 0:
        return {}

    statuses: dict[str, dict[str, str]] = {}
    for raw_line in proc.stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        state_prefix = line[0]
        parts = line[1:].strip().split()
        if len(parts) < 2:
            continue
        statuses[parts[1]] = {
            "state_prefix": state_prefix,
            "expected_commit": parts[0],
            "initialized": "true" if state_prefix != "-" else "false",
        }
    return statuses


def _is_effectively_empty_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    try:
        return not any(path.iterdir())
    except OSError:
        return False


def _dependency_unblock_status(
    source_root: Path,
    *,
    foundry_blocker: dict[str, Any] | None,
    proof_command: str | None,
) -> dict[str, Any]:
    urls = _parse_gitmodules(source_root)
    statuses = _submodule_statuses(source_root) if source_root.exists() else {}
    submodules: list[dict[str, Any]] = []
    for path, url in sorted(urls.items()):
        status = statuses.get(path, {})
        checkout_path = source_root / path
        initialized = status.get("initialized") == "true"
        submodules.append(
            {
                "path": path,
                "url": url,
                "expected_commit": str(status.get("expected_commit") or ""),
                "state_prefix": status.get("state_prefix"),
                "initialized": initialized,
                "checkout_path": str(checkout_path),
                "checkout_dir_exists": checkout_path.is_dir(),
                "checkout_dir_empty": _is_effectively_empty_dir(checkout_path),
                "git_metadata_present": (checkout_path / ".git").exists(),
            }
        )

    uninitialized = [
        item for item in submodules if not item["initialized"] or item["checkout_dir_empty"]
    ]
    failed_urls = []
    if foundry_blocker and isinstance(foundry_blocker.get("failed_submodule_urls"), list):
        failed_urls = [str(url) for url in foundry_blocker["failed_submodule_urls"]]
    elif urls:
        failed_urls = sorted(urls.values())

    network_command = f"git -C {source_root} submodule update --init --recursive"
    offline_commands = [f"git -C {source_root} submodule status --recursive"]
    for item in uninitialized:
        path = item["path"]
        commit = item.get("expected_commit") or "<expected-submodule-commit>"
        offline_commands.extend(
            [
                f"git -C <local-mirror-for-{path}> cat-file -e {commit}^{{commit}}",
                f"git -C {source_root} config submodule.{path}.url <local-mirror-for-{path}>",
                f"git -C {source_root} -c protocol.file.allow=always submodule update --init --recursive {path}",
            ]
        )

    if not source_root.exists():
        state = "blocked_source_root_missing"
    elif not submodules:
        state = "no_declared_submodule_dependency_blocker"
    elif uninitialized:
        state = "blocked_uninitialized_or_empty_submodules"
    else:
        state = "submodules_materialized"

    return {
        "state": state,
        "source_root": str(source_root),
        "declared_submodule_count": len(submodules),
        "uninitialized_or_empty_submodule_count": len(uninitialized),
        "network_unblock_command": network_command,
        "network_resolution_failure_observed": bool(
            foundry_blocker and foundry_blocker.get("network_resolution_failure")
        ),
        "failed_submodule_urls": failed_urls,
        "submodules": submodules,
        "offline_fallback_requires_exact_submodule_commits": bool(uninitialized),
        "offline_fallback_commands": offline_commands,
        "rerun_exact_proof_command_after_dependencies": proof_command,
        "claim_limits": {
            "non_matching_local_dependency_checkout_allowed": False,
            "executable_solidity_replay_performed": False,
            "exploit_proof_allowed": False,
            "verification_claim_allowed": False,
        },
    }


def build_report(
    *,
    boundary_path: Path,
    anchors_path: Path,
    execute_foundry: bool = False,
    previous_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = repo_root()
    boundary_packet = _load_json(boundary_path)
    anchors_packet = _load_json(anchors_path)
    source_root = Path(str(boundary_packet.get("source_root") or ".")).resolve()
    pinned_ref = str(boundary_packet.get("pinned_ref") or "")
    commands = boundary_packet.get("exact_next_commands")
    command_list = commands if isinstance(commands, list) else []

    records: list[dict[str, Any]] = []
    for command in command_list:
        command_text = str(command)
        kind = _command_kind(command_text)
        if kind in {"git_show_commit", "git_grep_pinned", "git_grep_head"}:
            records.append(_record_git_command(command_text))
            continue
        if kind == "rust_detector_boundary_reference":
            records.append(
                _record_boundary_reference(
                    command_text,
                    kind,
                    note="Rust detector rerun stays in the terminal inapplicability boundary and is not replay evidence.",
                )
            )
            continue
        if kind == "terminal_boundary_regeneration":
            records.append(
                _record_boundary_reference(
                    command_text,
                    kind,
                    note="Boundary regeneration command was consumed as provenance for this replay-status packet.",
                )
            )
            continue
        if kind == "foundry_anchor_test":
            previous_record = None if execute_foundry else _previous_foundry_record(previous_report, command_text)
            if previous_record is not None:
                records.append(previous_record)
                continue
            records.append(_record_foundry_command(command_text, execute_foundry=execute_foundry))
            continue
        records.append(
            {
                "command": command_text,
                "kind": kind,
                "executed": False,
                "exit_code": None,
                "status": "unclassified_fail_closed",
                "checks": [],
            }
        )

    citation = _citation_status(anchors_packet)
    citation_acquisition = _source_citation_acquisition_status(
        anchors_packet=anchors_packet,
        source_root=source_root,
        pinned_ref=pinned_ref,
    )
    probe = _probe_pinned_source(root, source_root, pinned_ref) if source_root.exists() and pinned_ref else {}
    foundry_record = next((record for record in records if record["kind"] == "foundry_anchor_test"), None)
    foundry_blocker = (
        foundry_record.get("execution_blocker")
        if isinstance(foundry_record, dict) and isinstance(foundry_record.get("execution_blocker"), dict)
        else None
    )
    proof_command = str(foundry_record["command"]) if foundry_record else None
    dependency_unblock = _dependency_unblock_status(
        source_root,
        foundry_blocker=foundry_blocker,
        proof_command=proof_command,
    )
    next_command = _next_exact_command(records, citation, citation_acquisition)

    fail_closed_reasons = []
    if citation["exact_citation_absent"]:
        fail_closed_reasons.append(
            "Exact Solodit #30522 GitHub blob/file-line citation is still absent; source-citation acquisition "
            "must run before dependency initialization or forge replay can be proof-grade."
        )
    if foundry_blocker:
        fail_closed_reasons.append(
            "The exact forge command was executed but did not reach proof execution because Foundry dependencies "
            "are missing or uninitialized in the local reNFT mirror."
        )
    if dependency_unblock["state"] == "blocked_uninitialized_or_empty_submodules":
        fail_closed_reasons.append(
            "The dependency unblock path is still blocked: declared Foundry submodules are uninitialized or empty, "
            "and offline fallback requires local mirrors containing the exact recorded submodule commits."
        )
    fail_closed_reasons.extend(
        [
            (
                "No exact #30522 executable Foundry proof is recorded. "
                "The consumed forge command is only a HEAD anchor test."
            ),
            (
                "Rust detector absence on the Solidity-only mirror remains imported from the terminal boundary "
                "as inapplicable, not as pass, replay proof, or exploit proof."
            ),
        ]
    )

    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "limitation_id": str(boundary_packet.get("limitation_id") or LIMITATION_ID),
        "finding_id": str(boundary_packet.get("finding_id") or FINDING_ID),
        "status": "source_aware_replay_commands_consumed_fail_closed",
        "klbq_006_closed": False,
        "promotion_ready": False,
        "verification_claim_allowed": False,
        "terminal_boundary_report": str(boundary_path),
        "real_source_anchors_report": str(anchors_path),
        "source_root": str(source_root),
        "pinned_ref": pinned_ref,
        "citation_status": citation,
        "source_citation_acquisition": citation_acquisition,
        "source_aware_pinned_probe": probe,
        "command_consumption": {
            "consumed_command_count": len(command_list),
            "executed_local_command_count": sum(1 for record in records if record["executed"]),
            "imported_terminal_boundary_count": sum(
                1 for record in records if record["status"] == "imported_from_terminal_boundary"
            ),
            "pending_execution_count": sum(
                1
                for record in records
                if record["status"] in {"not_executed_fail_closed", "forge_missing_fail_closed"}
            ),
            "failed_execution_count": sum(
                1
                for record in records
                if record["executed"] and record["status"] not in {"passed", "executed_anchor_test_not_exact_proof"}
            ),
            "commands": records,
        },
        "replay_gate": {
            "exact_citation_present": citation["exact_citation_present"],
            "exact_citation_absent": citation["exact_citation_absent"],
            "executable_foundry_proof_present": False,
            "foundry_anchor_test_executed": bool(foundry_record and foundry_record["executed"]),
            "foundry_execution_blocked": bool(foundry_blocker),
            "foundry_execution_blocker": foundry_blocker,
            "foundry_dependency_unblock": dependency_unblock,
            "head_anchor_test_is_exact_30522_proof": False,
            "fail_closed": True,
        },
        "foundry_dependency_unblock": dependency_unblock,
        "dependency_next_command": (
            dependency_unblock.get("network_unblock_command")
            if dependency_unblock.get("state") == "blocked_uninitialized_or_empty_submodules"
            else None
        ),
        "remaining_blockers": fail_closed_reasons,
        "exact_next_command": next_command,
        "exact_proof_command": proof_command,
        "do_not_claim": [
            "Do not claim KLBQ-006 closed.",
            "Do not claim the consumed HEAD forge test is an exact #30522 proof.",
            "Do not claim Rust detector absence on the Solidity mirror as a pass or exploit proof.",
            "Do not claim verification or promotion readiness while exact citation or exact proof is absent.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    citation = report["citation_status"]
    probe = report.get("source_aware_pinned_probe") or {}
    command_consumption = report["command_consumption"]
    lines = [
        "# KLBQ-006 Solidity Replay Status",
        "",
        f"Date: {report['date']}",
        f"Status: {report['status']}",
        f"Source root: `{report['source_root']}`",
        f"Pinned ref: `{report['pinned_ref']}`",
        "",
        "## Decision",
        "",
        "Consume the terminal-boundary exact commands as machine-readable local evidence,",
        "execute the git-based source checks, and keep KLBQ-006 fail-closed.",
        "",
        f"- Exact #30522 citation present: `{citation['exact_citation_present']}`",
        "- Executable exact #30522 Foundry proof present: `False`",
    ]

    citation_acquisition = report.get("source_citation_acquisition")
    if isinstance(citation_acquisition, dict):
        counts = citation_acquisition.get("local_evidence_counts")
        if not isinstance(counts, dict):
            counts = {}
        lines.extend(
            [
                "",
                "## Source Citation Acquisition",
                "",
                f"- State: `{citation_acquisition.get('state')}`",
                f"- Candidate source root: `{citation_acquisition.get('candidate_source_root')}`",
                (
                    "- Exact #30522 blob anchors found: "
                    f"`{counts.get('exact_finding_github_blob_anchors')}`"
                ),
                (
                    "- Base reNFT blob anchors found: "
                    f"`{counts.get('renft_base_github_blob_anchors')}`"
                ),
                (
                    "- Exact #30522 source metadata candidates: "
                    f"`{counts.get('exact_finding_source_metadata_candidates')}`"
                ),
                (
                    "- Eligible exact #30522 source metadata candidates: "
                    f"`{counts.get('eligible_exact_finding_source_metadata')}`"
                ),
                (
                    "- Exact #30522 source/spec candidates: "
                    f"`{counts.get('exact_finding_source_spec_candidates')}`"
                ),
                (
                    "- Eligible exact #30522 source/spec candidates: "
                    f"`{counts.get('eligible_exact_finding_source_specs')}`"
                ),
                f"- Exact #30522 source metadata state: `{citation_acquisition.get('exact_finding_source_metadata')}`",
                f"- Exact #30522 source/spec state: `{citation_acquisition.get('exact_finding_source_specs')}`",
                "",
                "Missing inputs:",
                "",
            ]
        )
        for item in citation_acquisition.get("missing_inputs") or []:
            lines.append(f"- {item}")
        metadata_candidates = citation_acquisition.get("source_metadata_candidates") or []
        if metadata_candidates:
            lines.extend(["", "Disqualified exact metadata candidates:", ""])
            for candidate in metadata_candidates[:5]:
                if not isinstance(candidate, dict):
                    continue
                reasons = ", ".join(str(reason) for reason in candidate.get("disqualification_reasons", []))
                lines.append(
                    f"- `{candidate.get('local_path')}` -> `{candidate.get('url')}`"
                    f" ({reasons or 'eligible'})"
                )
        spec_candidates = citation_acquisition.get("source_spec_candidates") or []
        if spec_candidates:
            lines.extend(["", "Disqualified exact source/spec candidates:", ""])
            for candidate in spec_candidates[:5]:
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("exact_source_spec_eligible_for_replay"):
                    continue
                reasons = ", ".join(str(reason) for reason in candidate.get("disqualification_reasons", []))
                lines.append(
                    f"- `{candidate.get('local_path')}`"
                    f" ({candidate.get('source_artifact_kind')}; {reasons or 'eligible'})"
                )
        absence_proof = citation_acquisition.get("absence_proof")
        if isinstance(absence_proof, dict):
            lines.extend(["", "Searched roots:", ""])
            for root in absence_proof.get("searched_roots") or []:
                if isinstance(root, dict):
                    lines.append(f"- `{root.get('path')}` exists=`{root.get('exists')}`")
        lines.extend(["", "Acquisition commands:", "", "```bash"])
        for command in citation_acquisition.get("exact_next_commands") or []:
            lines.append(str(command))
        lines.append("```")

    lines.extend(
        [
            "",
            "## Pinned Source Probe",
            "",
            f"- Classification: `{probe.get('classification', 'unknown')}`",
            f"- Guard rejects setFallbackHandler selector: `{probe.get('signals', {}).get('guard_reverts_setfallbackhandler_selector')}`",
            f"- Test anchor present: `{probe.get('signals', {}).get('test_covers_setfallbackhandler_revert')}`",
            "",
            "## Consumed Commands",
            "",
            "| Kind | Status | Executed |",
            "| --- | --- | --- |",
        ]
    )
    for record in command_consumption["commands"]:
        lines.append(f"| `{record['kind']}` | `{record['status']}` | `{record['executed']}` |")

    lines.extend(["", "## Remaining Blockers", ""])
    for blocker in report["remaining_blockers"]:
        lines.append(f"- {blocker}")

    foundry_blocker = report.get("replay_gate", {}).get("foundry_execution_blocker")
    if isinstance(foundry_blocker, dict):
        lines.extend(
            [
                "",
                "## Foundry Execution Blocker",
                "",
                f"- State: `{foundry_blocker.get('state')}`",
                f"- Dependency install attempted: `{foundry_blocker.get('dependency_install_attempted')}`",
                f"- Network resolution failure: `{foundry_blocker.get('network_resolution_failure')}`",
                f"- Missing import count: `{foundry_blocker.get('missing_import_count')}`",
                f"- Missing source file count: `{foundry_blocker.get('missing_source_file_count')}`",
                "",
                "Unblock command:",
                "",
                "```bash",
                str(foundry_blocker.get("unblock_command") or "# none recorded"),
                "```",
            ]
        )

    dependency_unblock = report.get("foundry_dependency_unblock")
    if isinstance(dependency_unblock, dict):
        lines.extend(
            [
                "",
                "## Dependency Unblock",
                "",
                f"- State: `{dependency_unblock.get('state')}`",
                f"- Declared submodules: `{dependency_unblock.get('declared_submodule_count')}`",
                (
                    "- Uninitialized or empty submodules: "
                    f"`{dependency_unblock.get('uninitialized_or_empty_submodule_count')}`"
                ),
                (
                    "- Network resolution failure observed: "
                    f"`{dependency_unblock.get('network_resolution_failure_observed')}`"
                ),
                (
                    "- Offline fallback requires exact submodule commits: "
                    f"`{dependency_unblock.get('offline_fallback_requires_exact_submodule_commits')}`"
                ),
                "",
                "Network unblock command:",
                "",
                "```bash",
                str(dependency_unblock.get("network_unblock_command") or "# none recorded"),
                "```",
                "",
                "Offline fallback commands:",
                "",
                "```bash",
            ]
        )
        for command in dependency_unblock.get("offline_fallback_commands") or []:
            lines.append(str(command))
        lines.append("```")

    lines.extend(["", "## Exact Next Command", "", "```bash"])
    lines.append(report["exact_next_command"] or "# none recorded")
    lines.extend(["```", "", "## Exact Proof Command", "", "```bash"])
    lines.append(report.get("exact_proof_command") or "# none recorded")
    lines.extend(["```", "", "## Do Not Claim", ""])
    for claim in report["do_not_claim"]:
        lines.append(f"- {claim}")
    return "\n".join(lines).rstrip() + "\n"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boundary", type=Path, default=default_boundary_path(root))
    parser.add_argument("--anchors", type=Path, default=default_anchors_path(root))
    parser.add_argument("--out", type=Path, default=default_output_path(root))
    parser.add_argument("--docs", type=Path, default=default_docs_path(root))
    parser.add_argument("--execute-foundry", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    previous_report = _load_json(args.out) if args.out.exists() and not args.execute_foundry else None
    report = build_report(
        boundary_path=args.boundary,
        anchors_path=args.anchors,
        execute_foundry=args.execute_foundry,
        previous_report=previous_report,
    )
    _write_json(args.out, report)
    _write_text(args.docs, render_markdown(report))
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
