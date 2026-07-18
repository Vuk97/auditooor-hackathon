#!/usr/bin/env python3
"""Fail-closed execution for the three phase-owned audit-deep stages.

The modes are intentionally disjoint:

* engine-substrates runs deep, pre-reasoning language engines which are not
  separate ordered-manifest producers.
* depth-probe consumes fresh reasoner and hunt evidence and produces the live,
  mutation-verified depth certificate. It is not final verification.
* drive consumes Step 4b invariants and the fuzz worklist, then authors and
  executes applicable harness campaigns.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.audit_deep_phase_receipt.v2"
ARTIFACT_SCHEMA = "auditooor.audit_deep_phase_artifacts.v2"
EMPTY_WORKLIST_SCHEMA = "auditooor.audit_deep_empty_worklist_disposition.v1"
MODES = ("engine-substrates", "depth-probe", "drive")
LANG_BY_EXTENSION = {
    ".sol": "solidity", ".vy": "vyper", ".go": "go", ".rs": "rust",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".os": "oscript", ".oscript": "oscript",
    ".aa": "oscript",
}
PHASE_ROLES = {
    "engine-substrates": {"semantic-engine"},
    "depth-probe": {"guard-probe", "function-mutation", "depth-ingest", "depth-certificate"},
    "drive": {"harness-author", "campaign"},
}
REQUIRED_PHASE_ROLES = {
    "engine-substrates": {"semantic-engine"},
    "depth-probe": PHASE_ROLES["depth-probe"],
    "drive": PHASE_ROLES["drive"],
}
ENGINE_EVIDENCE_TIERS = {
    "semantic/compiler-backed", "AST-backed", "lexical/shape-only", "enumerator-only",
    "unsupported", "unsupported_applicable",
}
FORBIDDEN = {
    "engine-substrates": ("dataflow", "state-coupling", "semantic-graph", "fuzz", "harness", "hunt", "exploit", "depth-probe", "verify"),
    "depth-probe": ("fuzz", "harness", "exploit", "audit-complete", "final-screen"),
    "drive": ("hunt", "reasoner-regen", "depth-probe", "final-screen"),
}
WARNING_LINE_RE = re.compile(r"^\s*(?:\[[^\]\r\n]+\]\s*)?warn(?:ing)?\b", re.IGNORECASE | re.MULTILINE)


class PhaseError(RuntimeError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PhaseError(f"malformed JSON: {path}: {exc}") from exc


def _read_jsonl(path: Path, *, required: bool = True) -> list[dict[str, Any]]:
    if not path.is_file():
        if not required:
            return []
        raise PhaseError(f"missing required JSONL: {path}")
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise PhaseError(f"malformed JSONL: {path}:{line_no}: empty row")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PhaseError(f"malformed JSONL: {path}:{line_no}: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise PhaseError(f"malformed JSONL: {path}:{line_no}: object required")
        rows.append(value)
    return rows


def _relative(path: Path, workspace: Path) -> str:
    return path.relative_to(workspace).as_posix()


def _path_summary(path: Path, workspace: Path) -> dict[str, Any]:
    if not path.exists():
        raise PhaseError(f"missing artifact: {_relative(path, workspace)}")
    if path.is_symlink():
        raise PhaseError(f"symlink artifact is not accepted: {_relative(path, workspace)}")
    if path.is_file():
        raw = path.read_bytes()
        return {"path": _relative(path, workspace), "kind": "file", "sha256": _sha256_bytes(raw), "size": len(raw)}
    if not path.is_dir():
        raise PhaseError(f"unsupported artifact type: {_relative(path, workspace)}")
    rows: list[dict[str, Any]] = []
    total = 0
    for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        if child.is_symlink():
            raise PhaseError(f"symlink inside artifact directory: {_relative(child, workspace)}")
        if not child.is_file():
            continue
        raw = child.read_bytes()
        rows.append({"path": child.relative_to(path).as_posix(), "sha256": _sha256_bytes(raw), "size": len(raw)})
        total += len(raw)
    return {"path": _relative(path, workspace), "kind": "directory", "sha256": _sha256_bytes(_canonical_json(rows)), "size": total, "file_count": len(rows)}


def load_inventory(workspace: Path) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    path = workspace / ".auditooor" / "inscope_units.jsonl"
    rows = _read_jsonl(path)
    if not rows:
        raise PhaseError(f"empty canonical in-scope inventory: {path}")
    languages: set[str] = set()
    for index, row in enumerate(rows, 1):
        raw = row.get("file")
        if not isinstance(raw, str) or not raw.strip():
            raise PhaseError(f"inventory row {index} has no file")
        rel = Path(raw.replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts:
            raise PhaseError(f"inventory row {index} escapes workspace: {raw}")
        source = (workspace / rel).resolve()
        if not source.is_file() or workspace not in source.parents:
            raise PhaseError(f"inventory row {index} is missing or out of scope: {raw}")
        language = LANG_BY_EXTENSION.get(rel.suffix.lower())
        if language is None:
            raise PhaseError(f"unknown in-scope language for {raw}")
        declared = row.get("lang")
        aliases = {language, {"solidity": "sol", "rust": "rs", "javascript": "js", "typescript": "ts"}.get(language, language)}
        if isinstance(declared, str) and declared.strip() and declared.strip().lower() not in aliases:
            raise PhaseError(f"inventory language mismatch for {raw}: {declared} != {language}")
        languages.add(language)
    inventory_summary = _path_summary(path, workspace)
    sources = []
    for source_rel in sorted({str(row["file"]).replace("\\", "/") for row in rows}):
        source = workspace / source_rel
        raw = source.read_bytes()
        sources.append({"path": source_rel, "sha256": _sha256_bytes(raw), "size": len(raw)})
    inventory_summary["source_files"] = sources
    inventory_summary["source_snapshot_sha256"] = _sha256_bytes(_canonical_json({"mode": "inscope_inventory", "inventory_sha256": inventory_summary["sha256"], "sources": sources}))
    return rows, sorted(languages), inventory_summary


def _default_registry() -> dict[str, list[dict[str, Any]]]:
    """Existing granular tools with explicit language and output contracts."""
    strict = ".auditooor/strict_audit_deep"
    return {
        "engine-substrates": [
            {"id": "solidity-semantic-engine", "role": "semantic-engine",
             "evidence_tier": "semantic/compiler-backed", "languages": ["solidity"],
             "argv": ["python3", "tools/semantic-engine-substrate.py", "--workspace", "{workspace}", "--language", "solidity", "--output", f"{{workspace}}/{strict}/engine-substrates/solidity.json", "--records-output", f"{{workspace}}/{strict}/engine-substrates/solidity.paths.jsonl"],
             "outputs": [{"path": f"{strict}/engine-substrates/solidity.json", "kind": "json", "contract": "semantic-engine-substrate"}]},
            {"id": "go-semantic-engine", "role": "semantic-engine",
             "evidence_tier": "semantic/compiler-backed", "languages": ["go"],
             "argv": ["python3", "tools/semantic-engine-substrate.py", "--workspace", "{workspace}", "--language", "go", "--output", f"{{workspace}}/{strict}/engine-substrates/go.json", "--records-output", f"{{workspace}}/{strict}/engine-substrates/go.paths.jsonl"],
             "outputs": [{"path": f"{strict}/engine-substrates/go.json", "kind": "json", "contract": "semantic-engine-substrate"}]},
            {"id": "rust-semantic-engine", "role": "semantic-engine",
             "evidence_tier": "semantic/compiler-backed", "languages": ["rust"],
             "argv": ["python3", "tools/semantic-engine-substrate.py", "--workspace", "{workspace}", "--language", "rust", "--output", f"{{workspace}}/{strict}/engine-substrates/rust.json", "--records-output", f"{{workspace}}/{strict}/engine-substrates/rust.paths.jsonl"],
             "outputs": [{"path": f"{strict}/engine-substrates/rust.json", "kind": "json", "contract": "semantic-engine-substrate"}]},
        ],
        "depth-probe": [
            {"id": "live-guard-probes", "role": "guard-probe", "languages": ["*"],
             "argv": ["python3", "tools/depth-probe-runner.py", "--workspace", "{workspace}", "--probes-dir", "{workspace}/.auditooor/depth_probes", "--live", "--json"],
             "stdout_contract": "depth-runner", "outputs": [{"path": ".auditooor/depth_probes", "kind": "dir", "contract": "live-probe-dir"}]},
            {"id": "per-function-mutation", "role": "function-mutation", "languages": ["solidity", "go", "rust"],
             "argv": ["python3", "tools/function-coverage-completeness.py", "--workspace", "{workspace}", "--mutation-verify", "--strict", "--check", "--write", "--json"],
             "outputs": [{"path": ".auditooor/function_coverage_completeness.json", "kind": "json", "contract": "function-completeness"}]},
            {"id": "depth-ingest", "role": "depth-ingest", "languages": ["*"],
             "argv": ["python3", "tools/depth-probe-ingest.py", "--workspace", "{workspace}", "--probes-dir", "{workspace}/.auditooor/depth_probes", "--json"],
             "stdout_contract": "depth-ingest", "outputs": [{"path": ".auditooor/negative_space_gaps.jsonl", "kind": "jsonl"}]},
            {"id": "depth-certificate", "role": "depth-certificate", "languages": ["*"],
             "argv": ["python3", "tools/depth-certificate-build.py", "--workspace", "{workspace}", "--strict"],
             "outputs": [{"path": ".auditooor/depth_certificate.json", "kind": "json", "contract": "depth-certificate"}]},
        ],
        "drive": [
            {"id": "solidity-harness-author", "role": "harness-author", "languages": ["solidity"],
             "argv": ["make", "harness-scaffold", "WS={workspace}", "ALL=1", "FORCE=1"],
             "outputs": [{"path": ".auditooor/harness_plans.json", "kind": "json"}, {"path": ".auditooor/harness_binding_manifest.json", "kind": "json", "contract": "harness-binding"}]},
            {"id": "solidity-campaign", "role": "campaign", "languages": ["solidity"],
             "argv": ["bash", "tools/fuzz-runner.sh", "{workspace}", "--engine", "auto", "--out-dir", f"{{workspace}}/{strict}/drive/solidity-fuzz"],
             "outputs": [{"path": f"{strict}/drive/solidity-fuzz/manifest.json", "kind": "campaign"}]},
            {"id": "go-harness-author", "role": "harness-author", "languages": ["go"],
             "argv": ["python3", "tools/per-function-invariant-gen.py", "--workspace", "{workspace}", "--lang", "go", "--output-dir", f"{{workspace}}/{strict}/drive/go-harnesses", "--overwrite"],
             "outputs": [{"path": f"{strict}/drive/go-harnesses/manifest.json", "kind": "json", "contract": "per-function-harness"}]},
            {"id": "go-campaign", "role": "campaign", "languages": ["go"],
             "argv": ["bash", "tools/go-dynamic-engine-runner.sh", "{workspace}", "--out-dir", f"{{workspace}}/{strict}/drive/go-fuzz"],
             "outputs": [{"path": f"{strict}/drive/go-fuzz/manifest.json", "kind": "campaign"}]},
            {"id": "rust-harness-author", "role": "harness-author", "languages": ["rust"],
             "argv": ["python3", "tools/per-function-invariant-gen.py", "--workspace", "{workspace}", "--lang", "rust", "--output-dir", f"{{workspace}}/{strict}/drive/rust-harnesses", "--overwrite"],
             "outputs": [{"path": f"{strict}/drive/rust-harnesses/manifest.json", "kind": "json", "contract": "per-function-harness"}]},
            {"id": "rust-campaign", "role": "campaign", "languages": ["rust"],
             "argv": ["bash", "tools/rust-proptest-engine-runner.sh", "{workspace}", "--out-dir", f"{{workspace}}/{strict}/drive/rust-fuzz"],
             "outputs": [{"path": f"{strict}/drive/rust-fuzz/manifest.json", "kind": "campaign"}]},
        ],
    }


def _make_targets(repo_root: Path) -> set[str]:
    targets: set[str] = set()
    for line in (repo_root / "Makefile").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?:\s|$)", line)
        if match:
            targets.add(match.group(1))
    return targets


def preflight_registry(registry: dict[str, list[dict[str, Any]]], repo_root: Path = REPO_ROOT) -> None:
    """Prove each default command names a real executable and accepted CLI flags."""
    targets = _make_targets(repo_root)
    checked_help: dict[tuple[str, str], str] = {}
    for mode in MODES:
        for command in registry[mode]:
            argv = command.get("argv")
            if command.get("not_applicable") or not isinstance(argv, list) or not argv:
                continue
            executable = argv[0]
            if shutil.which(executable) is None and not Path(executable).is_file():
                raise PhaseError(f"registry preflight missing executable for {command['id']}: {executable}")
            if executable == "make":
                if len(argv) < 2 or argv[1] not in targets:
                    raise PhaseError(f"registry preflight invalid Make target for {command['id']}: {argv[1] if len(argv) > 1 else '<missing>'}")
                continue
            if executable not in {"python3", "bash"}:
                continue
            if len(argv) < 2 or not argv[1].startswith("tools/"):
                raise PhaseError(f"registry preflight requires a repository tool for {command['id']}")
            tool = repo_root / argv[1]
            if not tool.is_file():
                raise PhaseError(f"registry preflight missing tool for {command['id']}: {argv[1]}")
            key = (executable, argv[1])
            if key not in checked_help:
                probe = subprocess.run([executable, argv[1], "--help"], cwd=repo_root, capture_output=True, text=True, timeout=20, check=False)
                if probe.returncode != 0:
                    raise PhaseError(f"registry preflight --help failed for {argv[1]} rc={probe.returncode}")
                checked_help[key] = (probe.stdout or "") + (probe.stderr or "")
            help_text = checked_help[key]
            for token in argv[2:]:
                if token.startswith("--") and token not in help_text:
                    raise PhaseError(f"registry preflight invalid option for {command['id']}: {token}")


def load_registry(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    registry = _default_registry() if path is None else _read_json(path)
    if not isinstance(registry, dict):
        raise PhaseError("registry must be a JSON object")
    for mode in MODES:
        commands = registry.get(mode)
        if not isinstance(commands, list):
            raise PhaseError(f"registry has no command list for {mode}")
        for command in commands:
            if not isinstance(command, dict) or not isinstance(command.get("id"), str):
                raise PhaseError(f"registry {mode} has malformed command")
            if command.get("role") not in PHASE_ROLES[mode]:
                raise PhaseError(f"registry command {command['id']} has invalid phase role")
            if mode == "engine-substrates":
                tier = command.get("evidence_tier")
                if tier not in ENGINE_EVIDENCE_TIERS:
                    raise PhaseError(f"registry command {command['id']} has invalid engine evidence tier")
                if command.get("role") == "semantic-engine" and tier != "semantic/compiler-backed":
                    raise PhaseError(
                        f"registry command {command['id']} cannot satisfy semantic-engine with evidence tier {tier!r}"
                    )
            if command.get("not_applicable"):
                if not isinstance(command.get("reason"), str) or not command["reason"].strip():
                    raise PhaseError(f"registry command {command['id']} has no N/A reason")
            elif not isinstance(command.get("argv"), list) or not all(isinstance(v, str) for v in command["argv"]):
                raise PhaseError(f"registry command {command['id']} has malformed argv")
            if mode == "engine-substrates" and not command.get("not_applicable"):
                outputs = command.get("outputs")
                if (not isinstance(outputs, list) or not outputs
                        or any(not isinstance(output, dict) or output.get("contract") != "semantic-engine-substrate" for output in outputs)):
                    raise PhaseError(f"registry command {command['id']} has no strict semantic engine output contract")
            if not isinstance(command.get("languages"), list) or not command["languages"]:
                raise PhaseError(f"registry command {command['id']} has malformed languages")
            rendered = " ".join(command.get("argv", [])).lower()
            if any(token in rendered for token in FORBIDDEN[mode]):
                raise PhaseError(f"registry command {command['id']} violates {mode} ownership")
    preflight_registry(registry)  # type: ignore[arg-type]
    return registry  # type: ignore[return-value]


def _validate_contract(data: Any, contract: str, rel: str) -> None:
    if not isinstance(data, dict):
        raise PhaseError(f"output contract requires object: {rel}")
    if contract == "semantic-engine-substrate":
        artifacts = data.get("artifacts")
        if (data.get("schema") != "auditooor.semantic_engine_substrate.v1"
                or data.get("status") != "passed"
                or data.get("evidence_tier") != "semantic/compiler-backed"
                or not isinstance(data.get("language"), str) or not data["language"]
                or not isinstance(data.get("backend"), str) or not data["backend"]
                or not re.fullmatch(r"[0-9a-f]{64}", str(data.get("source_snapshot_sha256") or ""))
                or data.get("degraded") is not False
                or data.get("warnings") not in (None, [])
                or not isinstance(artifacts, list) or not artifacts
                or data.get("artifact_count") != len(artifacts)):
            raise PhaseError(f"semantic engine substrate is malformed or non-terminal: {rel}")
    elif contract == "function-completeness":
        counts = data.get("counts")
        if data.get("schema") != "auditooor.function_coverage_completeness.v1" or data.get("verdict") != "pass-fully-covered" or not isinstance(counts, dict) or counts.get("total", 0) <= 0 or counts.get("hollow") != 0 or counts.get("untouched") != 0:
            raise PhaseError(f"function mutation completeness is not terminal: {rel}")
    elif contract == "harness-binding":
        if data.get("schema") != "auditooor.harness_binding_manifest.v0" or data.get("row_count", 0) <= 0 or data.get("ready_count") != data.get("row_count") or data.get("blocked_count") != 0 or data.get("executable_command_count") != data.get("row_count"):
            raise PhaseError(f"Solidity harness binding is blocked or non-executable: {rel}")
    elif contract == "per-function-harness":
        count = data.get("function_count")
        if data.get("schema") != "auditooor.per_function_invariant_gen.v1" or not isinstance(count, int) or count <= 0 or data.get("sentinel_count") != 0 or data.get("non_sentinel_count") != count or not isinstance(data.get("functions"), list) or len(data["functions"]) != count:
            raise PhaseError(f"per-function harness output is empty or sentinel-only: {rel}")
    elif contract == "depth-certificate":
        if data.get("schema") != "auditooor.depth_certificate.v1" or data.get("verdict") != "depth-audited":
            raise PhaseError(f"depth certificate is not live-terminal: {rel}")
    else:
        raise PhaseError(f"unknown output contract: {contract}")


def _internal_output_failures(value: Any, prefix: str = "$") -> list[str]:
    failures: list[str] = []
    terminal_bad = {"blocked", "dry-run", "env_skip", "error", "failed", "failure", "not-run", "partial", "pending", "skipped", "timeout", "tool-not-installed", "vacuous"}
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{prefix}.{key}"
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in {"warning", "warnings"} and child not in (None, "", [], {}, False, 0):
                failures.append(location)
            if normalized_key in {"status", "verdict"}:
                normalized_value = str(child).strip().lower().replace("-", "_")
                if normalized_value in {item.replace("-", "_") for item in terminal_bad} or normalized_value.startswith(("error_", "fail_", "timeout_", "warn_")):
                    failures.append(location)
            failures.extend(_internal_output_failures(child, location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            failures.extend(_internal_output_failures(child, f"{prefix}[{index}]") )
    return failures


def _validate_probe_dir(path: Path, rel: str) -> None:
    files = sorted(path.glob("*.jsonl"))
    if not files:
        raise PhaseError(f"live probe directory has no batch rows: {rel}")
    rows: list[dict[str, Any]] = []
    for file in files:
        rows.extend(_read_jsonl(file))
    if not rows:
        raise PhaseError(f"live probe directory is empty: {rel}")
    for row in rows:
        reason = str(row.get("why_no_gap_or_exploit") or "").lower()
        source = str(row.get("probe_source") or "").lower()
        if not row.get("guard_id") or not row.get("file_line") or not row.get("code_excerpt") or "stub" in reason or "parse-failure" in reason or "dry-run" in source or "fallback" in source:
            raise PhaseError(f"live probe directory contains stub or malformed rows: {rel}")


def _validate_output(workspace: Path, spec: dict[str, Any]) -> dict[str, Any]:
    rel = spec.get("path")
    kind = spec.get("kind", "exists")
    if not isinstance(rel, str) or not isinstance(kind, str):
        raise PhaseError("malformed output specification")
    path = (workspace / rel).resolve()
    if workspace not in path.parents and path != workspace:
        raise PhaseError(f"output escapes workspace: {rel}")
    data: Any = None
    if kind == "dir":
        if not path.is_dir():
            raise PhaseError(f"missing output directory: {rel}")
    elif kind == "json":
        if not path.is_file():
            raise PhaseError(f"missing JSON output: {rel}")
        data = _read_json(path)
    elif kind == "jsonl":
        _read_jsonl(path)
    elif kind == "campaign":
        data = _read_json(path)
        if not isinstance(data, dict) or data.get("status") not in {"pass", "counterexample"}:
            raise PhaseError(f"campaign is not a real terminal result: {rel}")
    else:
        raise PhaseError(f"unknown output validator: {kind}")
    if data is not None:
        internal_failures = _internal_output_failures(data)
        if internal_failures:
            raise PhaseError(f"output contains internal warning or non-terminal status: {rel}:{','.join(internal_failures[:8])}")
    contract = spec.get("contract")
    if contract == "live-probe-dir":
        _validate_probe_dir(path, rel)
    elif isinstance(contract, str):
        _validate_contract(data, contract, rel)
    summary = _path_summary(path, workspace)
    summary["validator"] = kind
    if contract:
        summary["contract"] = contract
    return summary


def _output_freshness_marker(workspace: Path, spec: dict[str, Any]) -> int:
    rel = spec.get("path")
    if not isinstance(rel, str):
        return -1
    path = (workspace / rel).resolve()
    if not path.exists():
        return -1
    if path.is_file():
        return path.stat().st_mtime_ns
    if path.is_dir():
        marks = [path.stat().st_mtime_ns]
        marks.extend(item.stat().st_mtime_ns for item in path.rglob("*") if item.is_file())
        return max(marks)
    return -1


def _parse_stdout_contract(stdout: str, contract: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise PhaseError(f"malformed {contract} command output: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise PhaseError(f"malformed {contract} command output: object required")
    if contract == "depth-runner":
        if data.get("schema") != "auditooor.depth_probe_runner.v1" or data.get("verdict") != "all-batches-ok" or data.get("batches_failed") != 0 or data.get("packets_read", 0) <= 0 or data.get("probes_emitted", 0) <= 0 or data.get("live_fallback_to_agent_batches"):
            raise PhaseError("live depth runner did not produce terminal non-stub probes")
    elif contract == "depth-ingest":
        if data.get("schema") != "auditooor.depth_probe_ingest.v1" or data.get("verdict") != "ingested-genuine" or data.get("probes_read", 0) <= 0 or data.get("r76_fail") != 0 or data.get("bulk_template_detected") or data.get("genuine") != data.get("probes_read") or data.get("ingested") != data.get("genuine"):
            raise PhaseError("depth ingest rejected, stubbed, or failed to ingest probe rows")
    else:
        raise PhaseError(f"unknown stdout contract: {contract}")
    return data


def _structured_output_has_warning(stream: str) -> bool:
    """Return whether a JSON command result declares an actual warning."""
    try:
        data = json.loads(stream)
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    for key in ("warning", "warnings"):
        value = data.get(key)
        if value not in (None, "", [], {}, False, 0):
            return True
    for key in ("status", "verdict"):
        value = data.get(key)
        if isinstance(value, str) and value.strip().lower().startswith("warn"):
            return True
    return False


def _command_output_has_warning(stdout: str, stderr: str) -> bool:
    """Fail only for diagnostics, not JSON metadata names such as warnings: []."""
    for stream in (stdout, stderr):
        if _structured_output_has_warning(stream) or WARNING_LINE_RE.search(stream):
            return True
    return False


def _input_summary(path: Path, workspace: Path) -> dict[str, Any]:
    return _path_summary(path, workspace)


def _load_repo_module(module_name: str, relative: str) -> Any:
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    tool_path = REPO_ROOT / relative
    spec = importlib.util.spec_from_file_location(module_name, tool_path)
    if spec is None or spec.loader is None:
        raise PhaseError(f"cannot load canonical production tool: {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise PhaseError(f"cannot load canonical production tool {relative}: {exc}") from exc
    return module


def _repository_file_summary(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "kind": "repository_file",
        "sha256": _sha256_bytes(raw),
        "size": len(raw),
    }


def _language_backend_evidence(workspace: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    base = workspace / ".auditooor"
    candidates = [
        base / "language_backend_receipt.json",
        base / "language_backend_receipts.jsonl",
        *(sorted((base / "language_backend_receipts").glob("*.json"))
          if (base / "language_backend_receipts").is_dir() else []),
        *(sorted((base / "language_backend_receipts").glob("*.jsonl"))
          if (base / "language_backend_receipts").is_dir() else []),
    ]
    rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for path in candidates:
        if not path.is_file():
            continue
        summaries.append(_input_summary(path, workspace))
        values: Any
        if path.suffix == ".jsonl":
            values = _read_jsonl(path)
        else:
            values = _read_json(path)
            if isinstance(values, dict) and isinstance(values.get("receipts"), list):
                values = values["receipts"]
            elif isinstance(values, dict):
                values = [values]
        if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
            raise PhaseError(f"malformed language backend receipt collection: {_relative(path, workspace)}")
        for row in values:
            # Strict dataflow producers write receipt_schema. Keep schema as a
            # compatibility read for historical receipts, but never reject the
            # canonical current-run producer format.
            receipt_schema = row.get("receipt_schema", row.get("schema"))
            if receipt_schema != "auditooor.language_backend_receipt.v1":
                raise PhaseError(f"invalid language backend receipt schema: {_relative(path, workspace)}")
            rows.append(row)
    return rows, summaries


def _language_capability_inputs(workspace: Path, languages: list[str]) -> dict[str, Any]:
    module = _load_repo_module("_audit_deep_language_capability", "tools/language-capability-contract.py")
    contract_path = REPO_ROOT / "reference" / "language_capabilities.json"
    try:
        contract = module.load_contract(contract_path)
        issues = module.validate_contract(contract, repo_root=REPO_ROOT)
    except Exception as exc:
        raise PhaseError(f"language capability contract validation failed: {exc}") from exc
    if issues:
        raise PhaseError("language capability contract validation failed: " + "; ".join(issues[:8]))
    evidence, evidence_summaries = _language_backend_evidence(workspace)
    try:
        report = module.query_contract(contract, set(languages), ("engine",), evidence)
    except Exception as exc:
        raise PhaseError(f"language capability query failed: {exc}") from exc
    inputs = {
        "language_capability_contract": _repository_file_summary(contract_path),
        "language_backend_receipts": evidence_summaries,
        "language_capability_query": report,
    }
    return inputs


def _assert_language_capability(report: dict[str, Any]) -> None:
    if report.get("ok"):
        return
    blocked = []
    for row in report.get("languages", []):
        if isinstance(row, dict) and row.get("status") == "blocked":
            blocked.append(f"{row.get('language')}:{','.join(str(item) for item in row.get('missing', []))}")
    unknown = report.get("unknown_inventory_languages") or []
    details = blocked + [f"unknown:{item}" for item in unknown]
    raise PhaseError("language capability contract blocks engine-substrates: " + "; ".join(details))


def _reasoner_and_hunt_inputs(workspace: Path) -> dict[str, Any]:
    ordered = _load_repo_module("_audit_deep_ordered_hunt", "tools/ordered-llm-hunt.py")
    try:
        current = ordered._current_inputs(workspace)
        bus = ordered._validate_bus(workspace, current)
    except Exception as exc:
        raise PhaseError(f"zero-day bus validation failed: {exc}") from exc

    bus_dir = workspace / ".auditooor" / "zero_day_bus"
    freeze_path = bus_dir / "freeze_receipt.json"
    obligations_path = bus_dir / "obligations.jsonl"
    questions_path = bus_dir / "questions.jsonl"
    examined_empty_path = bus_dir / "examined_empty.jsonl"
    hunt_dir = workspace / ".auditooor" / "ordered_hunt"
    manifest_path = hunt_dir / "manifest.json"
    receipt_path = hunt_dir / "receipt.json"
    manifest = _read_json(manifest_path)
    receipt = _read_json(receipt_path)
    expected_questions = {row["question_id"]: row for row in bus["questions"]}
    denominator = len(expected_questions)

    if manifest.get("schema") != ordered.SCHEMA or manifest.get("status") not in {"completed", "completed-examined-empty"}:
        raise PhaseError("ordered hunt manifest is not terminal")
    if manifest.get("errors") not in (None, []):
        raise PhaseError("ordered hunt manifest contains internal errors")
    if manifest.get("bus_receipt_id") != bus["receipt"].get("receipt_id") or manifest.get("bus_input_fingerprint") != bus["receipt"].get("input_fingerprint"):
        raise PhaseError("ordered hunt is stale relative to the zero-day freeze receipt")
    expected_bus_hashes = {
        "freeze_receipt_sha256": _sha256_bytes(freeze_path.read_bytes()),
        "obligations_sha256": _sha256_bytes(obligations_path.read_bytes()),
        "questions_sha256": _sha256_bytes(questions_path.read_bytes()),
        "examined_empty_sha256": _sha256_bytes(examined_empty_path.read_bytes()),
    }
    if manifest.get("bus_fingerprints") != expected_bus_hashes:
        raise PhaseError("ordered hunt bus fingerprints do not match frozen inputs")
    expected_current = {
        "inventory_sha256": current["inventory_sha256"],
        "source_snapshot_sha256": current["source_snapshot_sha256"],
        "scope_sha256": current["scope_sha256"],
        "severity_sha256": current["severity_sha256"],
        "program_rules_sha256": current["program_rules_sha256"],
    }
    current_fingerprints = manifest.get("current_fingerprints")
    if not isinstance(current_fingerprints, dict) or any(current_fingerprints.get(key) != value for key, value in expected_current.items()):
        raise PhaseError("ordered hunt is stale relative to current workspace inputs")
    if manifest.get("all_typed_questions_denominator") != denominator:
        raise PhaseError("ordered hunt typed question denominator mismatch")
    if manifest.get("dispatched_count") != denominator or manifest.get("completed_count") != denominator:
        raise PhaseError("ordered hunt did not complete the full typed question denominator")

    tasks = manifest.get("tasks")
    reconciliation = manifest.get("reconciliation")
    if not isinstance(tasks, list) or not isinstance(reconciliation, dict):
        raise PhaseError("ordered hunt task reconciliation is malformed")
    task_ids = [row.get("task_id") for row in tasks if isinstance(row, dict)]
    expected_ids = list(expected_questions)
    if len(task_ids) != len(tasks) or len(task_ids) != len(set(task_ids)):
        raise PhaseError("ordered hunt has malformed or duplicate task IDs")
    if set(reconciliation.get("expected_task_ids") or []) != set(expected_ids) or set(reconciliation.get("completed_task_ids") or []) != set(expected_ids) or reconciliation.get("missing_task_ids") != []:
        raise PhaseError("ordered hunt reconciliation does not close the full denominator")
    if set(task_ids) != set(expected_ids):
        raise PhaseError("ordered hunt task set does not match frozen questions")
    for task in tasks:
        question = expected_questions[task["task_id"]]
        if task.get("question_id") != question["question_id"] or task.get("parent_ids") != question["parent_ids"] or task.get("axis") != question["axis"]:
            raise PhaseError(f"ordered hunt task linkage mismatch: {task['task_id']}")
        if (not ordered._is_hash(task.get("prompt_sha256"))
                or not ordered._is_hash(task.get("command_sha256"))
                or not isinstance(task.get("provider"), str) or not task["provider"]
                or not isinstance(task.get("model"), str) or not task["model"]
                or task.get("terminal") is not False
                or task.get("evidence_class") != "nonterminal-hunt-evidence"):
            raise PhaseError(f"ordered hunt task semantics are malformed: {task['task_id']}")
        raw_sidecar = task.get("sidecar_path")
        if not isinstance(raw_sidecar, str) or not raw_sidecar:
            raise PhaseError(f"ordered hunt task has no sidecar: {task['task_id']}")
        candidate = Path(raw_sidecar)
        sidecar_path = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        canonical_sidecars = (hunt_dir / "sidecars").resolve()
        if canonical_sidecars not in sidecar_path.parents or not sidecar_path.is_file() or sidecar_path.is_symlink():
            raise PhaseError(f"ordered hunt sidecar is missing or outside workspace: {task['task_id']}")
        if task.get("sidecar_sha256") != _sha256_bytes(sidecar_path.read_bytes()):
            raise PhaseError(f"ordered hunt sidecar hash mismatch: {task['task_id']}")
        sidecar = _read_json(sidecar_path)
        linked_fields = ("question_id", "parent_ids", "axis", "prompt_sha256", "command_sha256", "provider", "model")
        if (sidecar.get("schema") != ordered.SIDECAR_SCHEMA
                or sidecar.get("status") != "captured"
                or sidecar.get("task_id") != task["task_id"]
                or sidecar.get("terminal") is not False
                or sidecar.get("evidence_class") != "nonterminal-hunt-evidence"
                or any(sidecar.get(key) != task.get(key) for key in linked_fields)):
            raise PhaseError(f"ordered hunt sidecar semantics are malformed: {task['task_id']}")
    if denominator == 0:
        if manifest.get("status") != "completed-examined-empty" or tasks or manifest.get("examined_empty_proofs") != bus.get("empty_proofs"):
            raise PhaseError("ordered hunt examined-empty completion is malformed")
    elif manifest.get("status") != "completed":
        raise PhaseError("ordered hunt nonempty denominator is not completed")

    if receipt.get("schema") != ordered.RECEIPT_SCHEMA or receipt.get("manifest_sha256") != _sha256_bytes(manifest_path.read_bytes()):
        raise PhaseError("ordered hunt receipt does not bind the terminal manifest")
    receipt_fields = ("status", "all_typed_questions_denominator", "dispatched_count", "completed_count")
    if receipt.get("terminal_evidence") is not False or any(receipt.get(key) != manifest.get(key) for key in receipt_fields):
        raise PhaseError("ordered hunt receipt counts or semantics do not match the manifest")
    return {
        "zero_day_freeze_receipt": _input_summary(freeze_path, workspace),
        "zero_day_obligations": _input_summary(obligations_path, workspace),
        "zero_day_questions": _input_summary(questions_path, workspace),
        "zero_day_examined_empty": _input_summary(examined_empty_path, workspace),
        "zero_day_obligation_count": len(bus["obligation_by_parent"]),
        "zero_day_question_count": denominator,
        "ordered_hunt_manifest": _input_summary(manifest_path, workspace),
        "ordered_hunt_receipt": _input_summary(receipt_path, workspace),
        "ordered_hunt_completed_denominator": denominator,
    }


def _validate_invariant_inputs(workspace: Path) -> dict[str, Any]:
    markdown_path = workspace / "INVARIANT_LEDGER.md"
    machine_path = workspace / ".auditooor" / "invariant_ledger.json"
    attestation_path = workspace / ".auditooor" / "attestations" / "step-4b.json"
    if not markdown_path.is_file() or not markdown_path.read_text(encoding="utf-8").strip() or "_No rows yet" in markdown_path.read_text(encoding="utf-8"):
        raise PhaseError("Step 4b INVARIANT_LEDGER.md is missing or stubbed")
    machine = _read_json(machine_path)
    if not isinstance(machine, dict) or (machine.get("schema_version") or machine.get("schema")) != "auditooor.invariant_ledger.v1" or not isinstance(machine.get("rows"), list) or not machine["rows"]:
        raise PhaseError("Step 4b machine invariant ledger is missing, malformed, or empty")
    module_name = "_audit_deep_phase_invariant_ledger"
    module = sys.modules.get(module_name)
    if module is None:
        tool_path = REPO_ROOT / "tools" / "invariant-ledger.py"
        spec = importlib.util.spec_from_file_location(module_name, tool_path)
        if spec is None or spec.loader is None:
            raise PhaseError("cannot load canonical invariant ledger parser")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    try:
        raw_payload, canonical_rows = module.validate_ledger_payload(workspace)
        issues = module.validate_rows(canonical_rows, workspace, raw_rows=module._raw_rows_from_payload(raw_payload))
        markdown_rows = module.parse_markdown_ledger(markdown_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PhaseError(f"canonical Step 4b invariant ledger validation failed: {exc}") from exc
    if issues:
        details = "; ".join(f"{item.severity}:{item.row_id}:{item.message}" for item in issues[:8])
        raise PhaseError(f"canonical Step 4b invariant ledger has validation issues: {details}")
    if not 5 <= len(canonical_rows) <= 8:
        raise PhaseError(f"Step 4b requires 5-8 protocol invariants, found {len(canonical_rows)}")
    ids = [row.get("id") for row in machine["rows"] if isinstance(row, dict)]
    if len(ids) != len(machine["rows"]) or any(not isinstance(item, str) or not item.strip() for item in ids) or len(set(ids)) != len(ids):
        raise PhaseError("Step 4b machine invariant ledger has missing or duplicate IDs")
    headings = set(re.findall(r"^##\s+(.+?)\s*$", markdown_path.read_text(encoding="utf-8"), re.MULTILINE))
    if headings != set(ids):
        raise PhaseError("Step 4b machine invariant ledger is not grounded to INVARIANT_LEDGER.md headings")
    comparable_fields = tuple(module.REQUIRED_FIELDS) + ("severity", "notes")
    machine_by_id = {row.id: {field: getattr(row, field) for field in comparable_fields} for row in canonical_rows}
    markdown_by_id = {row.id: {field: getattr(row, field) for field in comparable_fields} for row in markdown_rows}
    if machine_by_id != markdown_by_id:
        raise PhaseError("Step 4b machine invariant ledger content is not grounded to INVARIANT_LEDGER.md")
    attestation = _read_json(attestation_path)
    required = {"completed_at", "attested_by", "summary", "invariant_count", "invariant_ids", "harness_file_paths", "economic_properties_summary"}
    if not isinstance(attestation, dict) or any(key not in attestation for key in required):
        raise PhaseError("Step 4b attestation is missing required fields")
    if attestation.get("attested_by") not in {"operator", "claude-operator-verified"} or attestation.get("invariant_count") != len(ids) or set(attestation.get("invariant_ids") or []) != set(ids) or not isinstance(attestation.get("harness_file_paths"), list) or not str(attestation.get("economic_properties_summary") or "").strip():
        raise PhaseError("Step 4b attestation does not ground the canonical invariant ledger")
    return {"invariant_count": len(ids), "invariant_markdown": _input_summary(markdown_path, workspace), "invariant_machine_ledger": _input_summary(machine_path, workspace), "step_4b_attestation": _input_summary(attestation_path, workspace)}


def _empty_worklist_disposition(workspace: Path, inventory_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    vmf_path = workspace / ".auditooor" / "value_moving_functions.json"
    payload = _read_json(vmf_path)
    if not isinstance(payload, dict) or not isinstance(payload.get("functions"), list) or payload.get("function_count") != len(payload["functions"]):
        raise PhaseError("missing or malformed value_moving_functions.json cannot justify an empty fuzz worklist")
    scoped = {str(row["file"]).replace("\\", "/").lstrip("./") for row in inventory_rows}
    applicable = []
    for row in payload["functions"]:
        if isinstance(row, dict) and str(row.get("file") or "").replace("\\", "/").lstrip("./") in scoped:
            applicable.append(row)
    if applicable:
        raise PhaseError(f"fuzz worklist is missing or empty with {len(applicable)} value-moving in-scope units")
    summary = _input_summary(vmf_path, workspace)
    disposition = {"schema": EMPTY_WORKLIST_SCHEMA, "verdict": "not-applicable-no-value-moving-inscope-units", "value_moving_in_scope_count": 0, "inventory_unit_count": len(inventory_rows), "value_moving_input_sha256": summary["sha256"]}
    return disposition, summary


def _drive_inputs(workspace: Path, inventory_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    inputs = _reasoner_and_hunt_inputs(workspace)
    cert_path = workspace / ".auditooor" / "depth_certificate.json"
    cert = _read_json(cert_path)
    _validate_contract(cert, "depth-certificate", ".auditooor/depth_certificate.json")
    inputs["depth_certificate"] = _input_summary(cert_path, workspace)
    inputs.update(_validate_invariant_inputs(workspace))
    worklist_path = workspace / ".auditooor" / "fuzz_targets.jsonl"
    worklist = _read_jsonl(worklist_path, required=False)
    if worklist:
        scoped_paths = {str(row["file"]).replace("\\", "/").lstrip("./") for row in inventory_rows}
        basenames: dict[str, list[str]] = {}
        for path in scoped_paths:
            basenames.setdefault(Path(path).name, []).append(path)
        for index, row in enumerate(worklist, 1):
            asset = str(row.get("asset_path") or "").replace("\\", "/").lstrip("./")
            resolved_asset = asset
            if asset not in scoped_paths and len(basenames.get(Path(asset).name, [])) == 1:
                resolved_asset = basenames[Path(asset).name][0]
            if row.get("schema_version") != "auditooor.fuzz_target_worklist.v1" or resolved_asset not in scoped_paths or not isinstance(row.get("functions"), list) or not row["functions"] or row.get("needs_campaign") is not True or row.get("verdict") != "campaign-pending":
                raise PhaseError(f"malformed or ungrounded fuzz worklist row {index}")
        inputs["fuzz_worklist"] = _input_summary(worklist_path, workspace)
        inputs["fuzz_target_count"] = len(worklist)
        return inputs, worklist, False
    disposition, vmf_summary = _empty_worklist_disposition(workspace, inventory_rows)
    inputs["empty_worklist_disposition"] = disposition
    inputs["value_moving_functions"] = vmf_summary
    inputs["fuzz_target_count"] = 0
    return inputs, [], True


def _command_applies(command: dict[str, Any], languages: list[str]) -> bool:
    allowed = set(command["languages"])
    return "*" in allowed or bool(allowed.intersection(languages))


def _assert_language_routes(mode: str, commands: list[dict[str, Any]], languages: list[str]) -> None:
    for language in languages:
        for role in sorted(REQUIRED_PHASE_ROLES[mode]):
            routes = [command for command in commands if command.get("role") == role and not command.get("not_applicable") and ("*" in command.get("languages", []) or language in command.get("languages", []))]
            if mode == "engine-substrates" and role == "semantic-engine":
                routes = [command for command in routes if command.get("evidence_tier") == "semantic/compiler-backed"]
            if not routes:
                diagnostic = "no semantic/compiler-backed production backend registered" if role == "semantic-engine" else "no production backend registered"
                raise PhaseError(f"unsupported applicable language '{language}' for {mode} role '{role}': {diagnostic}")


def _expand(argv: list[str], workspace: Path) -> list[str]:
    return [part.replace("{workspace}", str(workspace)) for part in argv]


def _run_command(argv: list[str], timeout: int, execute: Callable[..., Any] | None) -> Any:
    runner = execute or subprocess.run
    try:
        return runner(argv, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return type("Timeout", (), {"returncode": None, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "timed_out": True})()


def _receipt_paths(workspace: Path, mode: str) -> tuple[Path, Path]:
    base = workspace / ".auditooor" / "strict_audit_deep"
    return base / f"{mode}_receipt.json", base / f"{mode}_artifacts.json"


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _write_command_output(workspace: Path, mode: str, command_id: str, stream: str, value: str) -> dict[str, Any]:
    portable = value.replace(str(workspace), "{workspace}")
    path = workspace / ".auditooor" / "strict_audit_deep" / mode / "command_outputs" / f"{command_id}.{stream}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(portable, encoding="utf-8")
    return _path_summary(path, workspace)


def run_phase(workspace: Path, mode: str, registry_path: Path | None = None, timeout: int = 600, runner: Callable[..., Any] | None = None) -> int:
    workspace = workspace.expanduser().resolve()
    receipt_path, artifacts_path = _receipt_paths(workspace, mode)
    result: dict[str, Any] = {"schema": SCHEMA, "mode": mode, "status": "failed", "workspace": ".", "commands": [], "artifacts": [], "inputs": {}}
    try:
        if mode not in MODES:
            raise PhaseError(f"unknown mode: {mode}")
        if timeout <= 0:
            raise PhaseError("timeout must be positive")
        if not workspace.is_dir():
            raise PhaseError(f"workspace is not a directory: {workspace}")
        inventory_rows, languages, inventory_summary = load_inventory(workspace)
        registry = load_registry(registry_path)
        commands = registry[mode]
        result.update({"languages": languages, "registry_sha256": _sha256_bytes(_canonical_json(registry)), "inputs": {"canonical_inventory": inventory_summary}})
        if mode == "engine-substrates":
            capability_inputs = _language_capability_inputs(workspace, languages)
            result["inputs"].update(capability_inputs)
            _assert_language_capability(capability_inputs["language_capability_query"])
        _assert_language_routes(mode, commands, languages)
        empty_disposition = False
        if mode == "depth-probe":
            result["inputs"].update(_reasoner_and_hunt_inputs(workspace))
        elif mode == "drive":
            drive_inputs, _, empty_disposition = _drive_inputs(workspace, inventory_rows)
            result["inputs"].update(drive_inputs)
        for command in commands:
            applies = _command_applies(command, languages)
            record: dict[str, Any] = {"id": command["id"], "role": command["role"], "classification": "applicable" if applies else "not_applicable"}
            result["commands"].append(record)
            if not applies:
                record["reason"] = "language-not-present-in-canonical-inventory"
                continue
            if command.get("not_applicable"):
                record["classification"] = "not_applicable"
                record["reason"] = command["reason"]
                continue
            if mode == "drive" and empty_disposition:
                record["classification"] = "not_required"
                record["reason"] = "typed-empty-worklist-disposition"
                continue
            portable_argv = command["argv"]
            prior_output_marks = [_output_freshness_marker(workspace, output) for output in command.get("outputs", [])]
            completed = _run_command(_expand(portable_argv, workspace), timeout, runner)
            stdout = str(getattr(completed, "stdout", "") or "")
            stderr = str(getattr(completed, "stderr", "") or "")
            record.update({"argv": portable_argv, "argv_sha256": _sha256_bytes(_canonical_json(portable_argv)), "returncode": getattr(completed, "returncode", None), "stdout": _write_command_output(workspace, mode, command["id"], "stdout", stdout), "stderr": _write_command_output(workspace, mode, command["id"], "stderr", stderr)})
            if getattr(completed, "timed_out", False):
                raise PhaseError(f"command timed out: {command['id']}")
            if record["returncode"] != 0:
                raise PhaseError(f"command failed: {command['id']} rc={record['returncode']}")
            if _command_output_has_warning(stdout, stderr):
                raise PhaseError(f"command emitted warning: {command['id']}")
            if command.get("stdout_contract"):
                report = _parse_stdout_contract(stdout, command["stdout_contract"])
                record["stdout_report_sha256"] = _sha256_bytes(_canonical_json(report))
            for index, output in enumerate(command.get("outputs", [])):
                if _output_freshness_marker(workspace, output) <= prior_output_marks[index]:
                    raise PhaseError(f"command did not refresh declared output: {command['id']}:{output.get('path')}")
                result["artifacts"].append(_validate_output(workspace, output))
        if mode == "depth-probe":
            cert_path = workspace / ".auditooor" / "depth_certificate.json"
            ordered_receipt = workspace / ".auditooor" / "ordered_hunt" / "receipt.json"
            if cert_path.stat().st_mtime_ns < ordered_receipt.stat().st_mtime_ns:
                raise PhaseError("depth certificate predates hunt evidence")
        result["status"] = "passed"
    except (PhaseError, OSError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc).replace(str(workspace), "{workspace}")
    _write(receipt_path, result)
    artifact_result = {"schema": ARTIFACT_SCHEMA, "mode": mode, "status": result["status"], "inputs_sha256": _sha256_bytes(_canonical_json(result.get("inputs", {}))), "artifacts": result["artifacts"]}
    _write(artifacts_path, artifact_result)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0 if result["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--registry", type=Path, help="strict command registry JSON")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    return run_phase(args.workspace, args.mode, args.registry, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
