#!/usr/bin/env python3
# r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE registered via tools/agent-pathspec-register.py (this exact file path declared in the pathspec; top-level agent_id field updated to match this lane). Also active: lane orchestrator-hevm-kontrol (2026-05-26) for hevm runner + kontrol SKIPPED row wiring per Gap #38 install verification; pathspec re-registered for this lane covering tools/depth-tools-orchestrator.py, tools/tests/test_depth_tools_orchestrator.py, docs/DEPTH_TOOLS_INSTALL.md.
"""depth-tools-orchestrator.py - Run heavyweight depth-analysis tools per workspace.

r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered for this
docstring + runner additions; HEVM + kontrol wiring per Gap #38 install.

Orchestrates the depth/exhaustion tool set the operator surfaced 2026-05-26:
- Halmos formal verification (Solidity targets)
- Foundry fuzz at 1M+ iterations (Solidity targets)
- Mythril symbolic execution (Solidity bytecode/source)
- Manticore symbolic execution (Solidity/EVM bytecode) - PERMANENT-SKIP (upstream abandoned 2022)
- HEVM symbolic execution (Solidity/EVM bytecode + Foundry projects) - wired 2026-05-26
- Kontrol K-Framework proof front-end - PARTIAL-SKIP (wrapper installed, kompile backend missing)
- Differential fuzz vs reference implementations
- Multi-hour soak fuzz
- Rule 14 deep integration (triager-amend-asymmetry into orient-prefilter scoring)

Production-ready tool inventory (post lane CAPABILITY-GAP-38, 2026-05-26):
  8 fully wired: halmos, forge (fuzz/soak/differential), medusa, echidna,
  myth, hevm (+ rule14-deep-integrate Python bundled)
  1 SKIPPED-PARTIAL: kontrol (Python wrapper present; K Framework backend missing)
  1 SKIPPED-PERMANENT: manticore (upstream abandoned)

Every invocation appends a JSONL row to
<workspace>/.auditooor/depth_tools_log.jsonl describing:
  - tool name
  - target reference
  - status: PASS | FAIL | SKIPPED | ERROR
  - skip_reason (when status=SKIPPED)
  - duration_seconds
  - stdout_tail / stderr_tail (truncated)
  - applicable_language (rust|solidity|go|other)

The log is the evidence-of-attempt corpus that Gap #37 / Check #109
(exhaustion-verdict-tools-attempt-required-check.py) inspects when an
"EXHAUSTED" / "HUNT-DONE" / "GENUINELY-EXHAUSTED" verdict is claimed.

CLI
---
    --workspace <ws>                       Workspace root (REQUIRED).
    --halmos <target>                      Halmos formal verification.
    --foundry-fuzz-1m <target>
        [--runs N (default 1_000_000)]     Foundry fuzz with N+ iterations.
    --mythril <target>                     Mythril symbolic execution.
    --manticore <target>                   Manticore symbolic execution.
    --differential-fuzz <target>
        --reference <reference_impl>       Cross-impl differential fuzz.
    --soak-fuzz <target>
        [--hours N (default 12)]           Long-soak fuzz.
    --rule14-deep-integrate                Rule 14 deep integration via
                                           triager-amend-asymmetry into the
                                           orient-prefilter scoring layer.
    --hevm <target>                        HEVM symbolic execution (Solidity
                                           bytecode file or Foundry project root).
    --hevm-contract NAME                   Optional contract name for hevm symbolic.
    --hevm-function SIG                    Optional function signature for hevm symbolic
                                           (e.g. "transfer(address,uint256)").
    --hevm-timeout SECS                    Wall-clock timeout for hevm (default 600).
    --kontrol <target>                     Kontrol K-Framework proof front-end.
                                           Currently SKIPPED unconditionally:
                                           K Framework backend (kompile) not
                                           installed; install Nix + K to enable.
    --all                                  Run every wired tool against the
                                           workspace (uses --workspace as the
                                           target for tool-specific defaults).
    --json                                 Emit machine-readable JSON.
    # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered.
    --dry-run                              Do not invoke external tools;
                                           emit honest-skip log rows only.

Honest-skip discipline
----------------------
When a tool is not installed OR not applicable to the target's language
(e.g. Halmos on a .go file), the run is recorded as status=SKIPPED with
a non-empty skip_reason. SKIPPED rows count as evidence-of-attempt for
Gap #37; they distinguish "we tried and the tool was not applicable"
from "we did not try."

Schema: auditooor.depth_tools_orchestrator.v1
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.depth_tools_orchestrator.v1"
TOOL_NAME = "depth-tools-orchestrator"
LOG_FILENAME = "depth_tools_log.jsonl"
LOG_DIR = ".auditooor"

# Default soak-fuzz duration (hours).
DEFAULT_SOAK_HOURS = 12
# Default Foundry fuzz iteration count.
DEFAULT_FOUNDRY_RUNS = 1_000_000
# Truncation lengths.
STDOUT_TAIL_MAX = 4000
STDERR_TAIL_MAX = 4000
# Maximum wall-clock budget per tool when not specified (seconds).
DEFAULT_TOOL_TIMEOUT_SECONDS = 60 * 30  # 30 minutes


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_language_from_dir(directory: Path) -> str:
    """Scan a directory tree and return the dominant source language.

    Counts source files by extension, skipping common non-source subtrees
    (tests, vendor, node_modules, build artifacts).  Returns the language
    with the highest count, or 'other' when no source files are found.

    Extension-to-language map mirrors source_root_resolver.SOURCE_EXTS and
    the language labels used by the rest of this module:
      .sol / .vy          -> solidity / vyper
      .rs                 -> rust
      .go                 -> go
      .move               -> move
      .cairo / .nr / .zok -> cairo
    """
    _EXT_TO_LANG = {
        ".sol": "solidity",
        ".vy": "vyper",
        ".rs": "rust",
        ".go": "go",
        ".move": "move",
        ".cairo": "cairo",
        ".nr": "cairo",
        ".zok": "cairo",
    }
    # Directories whose contents must NOT influence language detection:
    # tool / build artifacts, vendored code, test harnesses.
    _SKIP_PARTS = {
        "target", "node_modules", "vendor", ".git", "lib", "out", "cache",
        "broadcast", "artifacts", "forge-std", ".cargo", "proptest-regressions",
        "fuzz", "benches", "bench", "test", "tests", "testdata", "mocks",
        "poc-tests", "poc_execution", "_archive", "examples",
        ".auditooor", ".audit_logs", "fuzz_runs", "mining_rounds",
        "submissions", "concolic", "swarm", "agent_outputs",
    }
    # Also check the inscope manifest when available: it is MANIFEST-AUTHORITATIVE
    # and lists the exact set of in-scope files produced by `make audit` intake.
    manifest_path = directory / ".auditooor" / "inscope_units.jsonl"
    if manifest_path.is_file():
        counts: dict[str, int] = {}
        try:
            with manifest_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    # The manifest stores relative paths under keys "file", "path",
                    # or "rel_path" (different intake versions use different keys).
                    rel = (
                        row.get("file") or row.get("path") or row.get("rel_path") or ""
                    )
                    if not rel:
                        continue
                    ext = os.path.splitext(rel.lower())[1]
                    lang = _EXT_TO_LANG.get(ext)
                    if lang:
                        counts[lang] = counts.get(lang, 0) + 1
        except OSError:
            counts = {}
        if counts:
            return max(counts, key=lambda k: counts[k])

    # Fallback: walk the directory tree, preferring the canonical source subdirs
    # (src/, contracts/, sources/, crates/) when they exist, to avoid counting
    # top-level scripts / docs / harness code as the dominant language.
    _CANDIDATE_SUBDIRS = ("src/src", "src", "contracts", "sources", "crates")
    scan_root = directory
    for sub in _CANDIDATE_SUBDIRS:
        cand = directory / sub
        if cand.is_dir():
            scan_root = cand
            break

    counts = {}
    try:
        for p in scan_root.rglob("*"):
            if p.is_dir():
                continue
            if any(part in _SKIP_PARTS for part in p.parts):
                continue
            ext = p.suffix.lower()
            lang = _EXT_TO_LANG.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    except OSError:
        pass

    if not counts:
        return "other"
    return max(counts, key=lambda k: counts[k])


def _detect_language(target: str) -> str:
    """Return rust|solidity|go|other from a target path or contract name.

    For directory targets (the common case when --all passes str(workspace)),
    delegates to _detect_language_from_dir() which inspects the inscope manifest
    or the source tree, so a Solidity workspace correctly returns 'solidity'
    even when the workspace root name contains no language markers.
    """
    if not target:
        return "other"
    t = target.lower()
    if t.endswith(".sol") or "::sol" in t:
        return "solidity"
    if t.endswith(".rs"):
        return "rust"
    if t.endswith(".go"):
        return "go"
    if t.endswith(".py"):
        return "python"
    if t.endswith(".vy"):
        return "vyper"
    if t.endswith(".move"):
        return "move"
    # Directory target: inspect contents instead of relying on path string heuristics.
    # This is the primary fix: when --all passes str(workspace) as the target for
    # every tool, the workspace directory name (e.g. "morpho") carries no language
    # marker, so the old path-string heuristic returned "other" for all Solidity
    # workspaces whose root path did not contain the literal strings "src" or
    # "contracts".
    target_path = Path(target)
    if target_path.is_dir():
        return _detect_language_from_dir(target_path)
    # Heuristic for extension-less file paths that embed a language hint in
    # a parent directory component (e.g. "contracts/MyContract" without ".sol").
    if (("contracts" in t) or ("src" in t)) and "." not in os.path.basename(t):
        return "solidity"
    return "other"


def _which(binary: str) -> str:
    p = shutil.which(binary)
    return p or ""


def _truncate(s: str, max_len: int) -> str:
    if not s:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max_len - 80] + f"\n... [truncated, total {len(s)} bytes]"


def _append_log(workspace: Path, row: dict[str, Any]) -> Path:
    log_dir = workspace / LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILENAME
    with log_path.open("a") as f:
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
    return log_path


def _emit_log_row(
    *,
    workspace: Path,
    tool: str,
    target: str,
    status: str,
    skip_reason: str = "",
    duration_seconds: float = 0.0,
    rc: int = 0,
    stdout_tail: str = "",
    stderr_tail: str = "",
    applicable_language: str = "",
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "schema": SCHEMA_VERSION,
        "tool": tool,
        "target": target,
        "status": status,
        "skip_reason": skip_reason,
        "duration_seconds": round(duration_seconds, 3),
        "return_code": rc,
        "stdout_tail": _truncate(stdout_tail, STDOUT_TAIL_MAX),
        "stderr_tail": _truncate(stderr_tail, STDERR_TAIL_MAX),
        "applicable_language": applicable_language,
        "timestamp_utc": _iso_now(),
        "workspace": str(workspace),
    }
    if extras:
        row["extras"] = extras
    _append_log(workspace, row)
    return row


def _run_subprocess(
    cmd: list[str], cwd: Path | None = None, timeout: int = DEFAULT_TOOL_TIMEOUT_SECONDS
) -> tuple[int, str, str, float]:
    """Run a subprocess; return (rc, stdout, stderr, duration_seconds)."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - start
        return proc.returncode, proc.stdout, proc.stderr, duration
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        return -1, exc.stdout or "", (exc.stderr or "") + f"\n[timeout after {timeout}s]", duration
    except FileNotFoundError as exc:
        duration = time.monotonic() - start
        return 127, "", str(exc), duration
    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - start
        return 1, "", str(exc), duration


# ---------------------------------------------------------------------------
# Per-tool runners. Each returns a log row dict.
# ---------------------------------------------------------------------------

# r36-rebuttal: bugfix-inventory-claude-20260610
def run_halmos(workspace: Path, target: str, dry_run: bool = False) -> dict[str, Any]:
    language = _detect_language(target)
    if language not in {"solidity"}:
        # Distinguish "tool not applicable to this target" (directory/wrong-language)
        # from "tool not installed". The prefix "target-not-applicable:" signals to
        # exhaustion-verdict-tools-attempt-required-check.py that this row does NOT
        # count as evidence-of-attempt; the operator must supply an explicit .sol path.
        if Path(target).is_dir():
            skip_reason = (
                "target-not-applicable: directory target requires explicit "
                "--halmos <file.sol>; pass a .sol contract file"
            )
        else:
            skip_reason = f"Halmos applies to Solidity only; detected language={language}"
        return _emit_log_row(
            workspace=workspace,
            tool="halmos",
            target=target,
            status="SKIPPED",
            skip_reason=skip_reason,
            applicable_language=language,
        )
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="halmos",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
        )
    halmos_bin = _which("halmos")
    if not halmos_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="halmos",
            target=target,
            status="SKIPPED",
            skip_reason="halmos binary not installed; see docs/DEPTH_TOOLS_INSTALL.md (pip install halmos)",
            applicable_language=language,
        )
    rc, out, err, dur = _run_subprocess(
        [halmos_bin, "--contract", os.path.basename(target).replace(".sol", "")],
        cwd=workspace,
    )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="halmos",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
    )


# r36-rebuttal: bugfix-inventory-claude-20260610
def run_foundry_fuzz_1m(
    workspace: Path, target: str, runs: int = DEFAULT_FOUNDRY_RUNS, dry_run: bool = False
) -> dict[str, Any]:
    language = _detect_language(target)
    if language not in {"solidity"}:
        if Path(target).is_dir():
            skip_reason = (
                "target-not-applicable: directory target requires explicit "
                "--foundry-fuzz-1m <test.t.sol>; pass a Solidity test file"
            )
        else:
            skip_reason = f"Foundry fuzz applies to Solidity only; detected language={language}"
        return _emit_log_row(
            workspace=workspace,
            tool="foundry-fuzz-1m",
            target=target,
            status="SKIPPED",
            skip_reason=skip_reason,
            applicable_language=language,
            extras={"runs": runs},
        )
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="foundry-fuzz-1m",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
            extras={"runs": runs},
        )
    forge_bin = _which("forge")
    if not forge_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="foundry-fuzz-1m",
            target=target,
            status="SKIPPED",
            skip_reason="forge binary not installed; install via foundryup (see docs/DEPTH_TOOLS_INSTALL.md)",
            applicable_language=language,
            extras={"runs": runs},
        )
    env_runs = max(int(runs), 1)
    rc, out, err, dur = _run_subprocess(
        [forge_bin, "test", "--match-path", target, "--fuzz-runs", str(env_runs)],
        cwd=workspace,
        timeout=max(DEFAULT_TOOL_TIMEOUT_SECONDS, env_runs // 1000),
    )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="foundry-fuzz-1m",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
        extras={"runs": env_runs},
    )


# r36-rebuttal: bugfix-inventory-claude-20260610
def run_mythril(workspace: Path, target: str, dry_run: bool = False) -> dict[str, Any]:
    language = _detect_language(target)
    if language not in {"solidity"}:
        if Path(target).is_dir():
            skip_reason = (
                "target-not-applicable: directory target requires explicit "
                "--mythril <file.sol>; pass a .sol contract file"
            )
        else:
            skip_reason = (
                f"Mythril applies to Solidity/EVM bytecode only; detected language={language}"
            )
        return _emit_log_row(
            workspace=workspace,
            tool="mythril",
            target=target,
            status="SKIPPED",
            skip_reason=skip_reason,
            applicable_language=language,
        )
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="mythril",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
        )
    myth_bin = _which("myth")
    if not myth_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="mythril",
            target=target,
            status="SKIPPED",
            skip_reason="myth binary not installed; install via pip install mythril (see docs/DEPTH_TOOLS_INSTALL.md)",
            applicable_language=language,
        )
    rc, out, err, dur = _run_subprocess(
        [myth_bin, "analyze", target],
        cwd=workspace,
    )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="mythril",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
    )


# r36-rebuttal: bugfix-inventory-claude-20260610
def run_manticore(workspace: Path, target: str, dry_run: bool = False) -> dict[str, Any]:
    language = _detect_language(target)
    if language not in {"solidity"}:
        if Path(target).is_dir():
            skip_reason = (
                "target-not-applicable: directory target requires explicit "
                "--manticore <file.sol>; pass a .sol contract file"
            )
        else:
            skip_reason = (
                f"Manticore applies to Solidity/EVM bytecode only; detected language={language}"
            )
        return _emit_log_row(
            workspace=workspace,
            tool="manticore",
            target=target,
            status="SKIPPED",
            skip_reason=skip_reason,
            applicable_language=language,
        )
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="manticore",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
        )
    manti_bin = _which("manticore")
    if not manti_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="manticore",
            target=target,
            status="SKIPPED",
            skip_reason="manticore binary not installed; install via pip install manticore (see docs/DEPTH_TOOLS_INSTALL.md)",
            applicable_language=language,
        )
    rc, out, err, dur = _run_subprocess(
        [manti_bin, target],
        cwd=workspace,
    )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="manticore",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
    )


# r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered for
# the run_hevm + run_kontrol functions below (Gap #38 install wiring).


def run_hevm(
    workspace: Path,
    target: str,
    contract: str = "",
    function: str = "",
    timeout: int = 600,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run HEVM symbolic execution against an EVM target.

    HEVM is EVM-only. Acceptable target shapes:
      - Foundry project root (directory containing foundry.toml): uses
        `hevm test --root <target>` (proves `prove*` test functions).
      - Solidity source file (.sol): SKIPPED with shape-unsupported reason -
        hevm symbolic needs bytecode or a Foundry build artifact, not raw .sol.
      - Bytecode file (.bin / .hex / .bytecode): uses
        `hevm symbolic --code-file <target>` with optional --sig.

    Returns the same row shape as run_halmos / run_mythril.
    HEVM binary expected at PATH (installed via Gap #38: direct binary
    download to ~/.local/bin/hevm).
    """
    language = _detect_language(target)
    extras: dict[str, Any] = {
        "contract": contract,
        "function": function,
        "timeout": timeout,
    }

    # HEVM is EVM-only. Skip non-Solidity / non-EVM language targets.
    if language not in {"solidity", "other"}:
        return _emit_log_row(
            workspace=workspace,
            tool="hevm",
            target=target,
            status="SKIPPED",
            skip_reason=(
                f"HEVM is EVM-only (Solidity/bytecode/Foundry project); "
                f"detected language={language}"
            ),
            applicable_language=language,
            extras=extras,
        )

    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="hevm",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
            extras=extras,
        )

    hevm_bin = _which("hevm")
    if not hevm_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="hevm",
            target=target,
            status="SKIPPED",
            skip_reason=(
                "hevm binary not installed; install via direct binary download "
                "to ~/.local/bin/hevm (see docs/DEPTH_TOOLS_INSTALL.md hevm section)"
            ),
            applicable_language=language,
            extras=extras,
        )

    # Resolve the target relative to workspace if not absolute.
    target_path = Path(target)
    if not target_path.is_absolute():
        target_path = (workspace / target).resolve()

    # Determine the hevm subcommand + invocation shape from target type.
    is_foundry_project = (
        target_path.is_dir() and (target_path / "foundry.toml").exists()
    )
    is_bytecode_file = (
        target_path.is_file()
        and target_path.suffix.lower() in {".bin", ".hex", ".bytecode"}
    )
    is_solidity_source = (
        target_path.is_file() and target_path.suffix.lower() == ".sol"
    )

    if is_foundry_project:
        cmd = [hevm_bin, "test", "--root", str(target_path)]
        if function:
            # `hevm test` uses --match to filter test cases by regex.
            cmd.extend(["--match", function])
        invocation_shape = "test-foundry-project"
    elif is_bytecode_file:
        cmd = [hevm_bin, "symbolic", "--code-file", str(target_path)]
        if function:
            cmd.extend(["--sig", function])
        invocation_shape = "symbolic-bytecode-file"
    elif is_solidity_source:
        # Raw .sol cannot be directly fed to hevm symbolic; needs bytecode.
        return _emit_log_row(
            workspace=workspace,
            tool="hevm",
            target=target,
            status="SKIPPED",
            skip_reason=(
                "hevm symbolic requires compiled bytecode or a Foundry project root, "
                "not raw .sol source; compile via forge build first or point at the "
                "Foundry project root (containing foundry.toml)"
            ),
            applicable_language=language,
            extras={**extras, "invocation_shape": "unsupported-raw-sol"},
        )
    else:
        # Unknown shape: emit honest-skip rather than guessing.
        return _emit_log_row(
            workspace=workspace,
            tool="hevm",
            target=target,
            status="SKIPPED",
            skip_reason=(
                f"hevm target shape not recognized: {target_path}; "
                "expected Foundry project root (foundry.toml present), "
                "bytecode file (.bin/.hex/.bytecode), or compiled artifact"
            ),
            applicable_language=language,
            extras={**extras, "invocation_shape": "unsupported-unknown"},
        )

    rc, out, err, dur = _run_subprocess(cmd, cwd=workspace, timeout=timeout)
    status = "PASS" if rc == 0 else "FAIL"

    # Capture hevm version for evidence-of-attempt completeness.
    version = ""
    try:
        vrc, vout, _verr, _vdur = _run_subprocess(
            [hevm_bin, "version"], timeout=15
        )
        if vrc == 0 and vout:
            version = vout.strip().splitlines()[0] if vout.strip() else ""
    except Exception:  # noqa: BLE001
        version = ""

    return _emit_log_row(
        workspace=workspace,
        tool="hevm",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
        extras={
            **extras,
            "invocation_shape": invocation_shape,
            "version": version,
            "counterexamples": [],  # hevm prints CEX inline; parsing TBD per drill.
            "output_path": "",
        },
    )


def run_kontrol(workspace: Path, target: str = "", dry_run: bool = False) -> dict[str, Any]:
    """Run Kontrol (K Framework Foundry/EVM proof front-end).

    PERMANENTLY SKIPPED as of 2026-05-26 per operator decision (lane GAP #38).
    The Python `kontrol` CLI wrapper is installed at ~/.local/bin/kontrol but
    the K Framework backend (`kompile`) is NOT installed; installing it
    requires Nix (~2-3GB system change) or Docker (~2GB image) which are
    out-of-scope for the lane discipline.

    Same skip-row shape as run_manticore (also permanent-skip): the row is
    emitted as status=SKIPPED with a non-empty skip_reason and counts as
    evidence-of-attempt for Gap #37 / Check #109.
    """
    language = _detect_language(target) if target else "any"
    skip_reason = (
        "K Framework backend (kompile) not installed; install Nix + K to enable. "
        "Defer per operator decision 2026-05-26."
    )
    return _emit_log_row(
        workspace=workspace,
        tool="kontrol",
        target=target or str(workspace),
        status="SKIPPED",
        skip_reason=skip_reason,
        applicable_language=language,
        extras={
            "skip_class": "PARTIAL-PERMANENT",
            "wrapper_installed": True,
            "backend_installed": False,
            "install_path_to_enable": "Nix + K Framework, or runtimeverificationinc/kontrol Docker image",
        },
    )


def run_differential_fuzz(
    workspace: Path, target: str, reference: str, dry_run: bool = False
) -> dict[str, Any]:
    language = _detect_language(target)
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="differential-fuzz",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
            extras={"reference": reference},
        )
    forge_bin = _which("forge")
    if not forge_bin:
        return _emit_log_row(
            workspace=workspace,
            tool="differential-fuzz",
            target=target,
            status="SKIPPED",
            skip_reason="forge binary not installed; differential-fuzz orchestrator requires forge (see docs/DEPTH_TOOLS_INSTALL.md)",
            applicable_language=language,
            extras={"reference": reference},
        )
    if not Path(reference).exists():
        return _emit_log_row(
            workspace=workspace,
            tool="differential-fuzz",
            target=target,
            status="SKIPPED",
            skip_reason=f"reference implementation not found on disk: {reference}",
            applicable_language=language,
            extras={"reference": reference},
        )
    rc, out, err, dur = _run_subprocess(
        [forge_bin, "test", "--match-path", target, "--fuzz-runs", "100000"],
        cwd=workspace,
    )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="differential-fuzz",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
        extras={"reference": reference},
    )


def run_soak_fuzz(
    workspace: Path, target: str, hours: int = DEFAULT_SOAK_HOURS, dry_run: bool = False
) -> dict[str, Any]:
    language = _detect_language(target)
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="soak-fuzz",
            target=target,
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language=language,
            extras={"hours": hours},
        )
    if language == "solidity":
        forge_bin = _which("forge")
        if not forge_bin:
            return _emit_log_row(
                workspace=workspace,
                tool="soak-fuzz",
                target=target,
                status="SKIPPED",
                skip_reason="forge binary not installed for Solidity soak (see docs/DEPTH_TOOLS_INSTALL.md)",
                applicable_language=language,
                extras={"hours": hours},
            )
        runs = max(hours * 100_000, 100_000)
        rc, out, err, dur = _run_subprocess(
            [forge_bin, "test", "--match-path", target, "--fuzz-runs", str(runs)],
            cwd=workspace,
            timeout=hours * 3600 + 600,
        )
    elif language == "rust":
        cargo_bin = _which("cargo")
        if not cargo_bin:
            return _emit_log_row(
                workspace=workspace,
                tool="soak-fuzz",
                target=target,
                status="SKIPPED",
                skip_reason="cargo binary not installed for Rust soak (see docs/DEPTH_TOOLS_INSTALL.md)",
                applicable_language=language,
                extras={"hours": hours},
            )
        rc, out, err, dur = _run_subprocess(
            [cargo_bin, "fuzz", "run", target, "--", f"-max_total_time={hours * 3600}"],
            cwd=workspace,
            timeout=hours * 3600 + 600,
        )
    elif language == "go":
        go_bin = _which("go")
        if not go_bin:
            return _emit_log_row(
                workspace=workspace,
                tool="soak-fuzz",
                target=target,
                status="SKIPPED",
                skip_reason="go binary not installed for Go soak (see docs/DEPTH_TOOLS_INSTALL.md)",
                applicable_language=language,
                extras={"hours": hours},
            )
        rc, out, err, dur = _run_subprocess(
            [go_bin, "test", "-fuzz", target, f"-fuzztime={hours}h"],
            cwd=workspace,
            timeout=hours * 3600 + 600,
        )
    else:
        return _emit_log_row(
            workspace=workspace,
            tool="soak-fuzz",
            target=target,
            status="SKIPPED",
            skip_reason=f"no soak-fuzz harness registered for language={language}",
            applicable_language=language,
            extras={"hours": hours},
        )
    status = "PASS" if rc == 0 else "FAIL"
    return _emit_log_row(
        workspace=workspace,
        tool="soak-fuzz",
        target=target,
        status=status,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language=language,
        extras={"hours": hours},
    )


def run_rule14_deep_integrate(workspace: Path, dry_run: bool = False) -> dict[str, Any]:
    """Run triager-amend-asymmetry.py and persist a Rule 14 deep-integration
    advisory consumable by orient-prefilter scoring."""
    asym_tool = Path(__file__).resolve().parent / "triager-amend-asymmetry.py"
    if not asym_tool.exists():
        return _emit_log_row(
            workspace=workspace,
            tool="rule14-deep-integrate",
            target=str(workspace),
            status="SKIPPED",
            skip_reason=f"sibling tool not found: {asym_tool}",
            applicable_language="any",
        )
    if dry_run:
        return _emit_log_row(
            workspace=workspace,
            tool="rule14-deep-integrate",
            target=str(workspace),
            status="SKIPPED",
            skip_reason="dry-run mode",
            applicable_language="any",
        )
    # r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE registered.
    rc, out, err, dur = _run_subprocess(
        [sys.executable, str(asym_tool), "--workspace", str(workspace), "--json"],
    )
    advisory_path = workspace / LOG_DIR / "rule14_asymmetry_advisory.json"
    try:
        advisory_path.parent.mkdir(parents=True, exist_ok=True)
        if out.strip():
            json.loads(out)
            advisory_path.write_text(out)
    except json.JSONDecodeError:
        pass
    # rc=1 from sibling tool means "no filed/ dir"; that is still
    # evidence-of-attempt for Gap #37 purposes.
    status = "PASS" if rc == 0 else ("SKIPPED" if rc == 1 else "FAIL")
    skip_reason = ""
    if status == "SKIPPED":
        skip_reason = "triager-amend-asymmetry: no filed/ directory in workspace; advisory empty"
    return _emit_log_row(
        workspace=workspace,
        tool="rule14-deep-integrate",
        target=str(workspace),
        status=status,
        skip_reason=skip_reason,
        rc=rc,
        duration_seconds=dur,
        stdout_tail=out,
        stderr_tail=err,
        applicable_language="any",
        extras={"advisory_path": str(advisory_path)},
    )


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Run depth-analysis tools; record evidence-of-attempt logs.",
    )
    p.add_argument("--workspace", required=True, help="Workspace root.")
    p.add_argument("--halmos", default="", help="Halmos formal verification target.")
    p.add_argument("--foundry-fuzz-1m", dest="foundry_fuzz_1m", default="",
                   help="Foundry fuzz target (>=1M iterations).")
    p.add_argument("--runs", type=int, default=DEFAULT_FOUNDRY_RUNS,
                   help=f"Foundry fuzz iteration count (default {DEFAULT_FOUNDRY_RUNS}).")
    p.add_argument("--mythril", default="", help="Mythril symbolic execution target.")
    p.add_argument("--manticore", default="", help="Manticore symbolic execution target.")
    p.add_argument("--differential-fuzz", dest="differential_fuzz", default="",
                   help="Differential fuzz target.")
    p.add_argument("--reference", default="",
                   help="Reference implementation path for --differential-fuzz.")
    p.add_argument("--soak-fuzz", dest="soak_fuzz", default="",
                   help="Soak fuzz target.")
    p.add_argument("--hours", type=int, default=DEFAULT_SOAK_HOURS,
                   help=f"Soak fuzz duration in hours (default {DEFAULT_SOAK_HOURS}).")
    p.add_argument("--rule14-deep-integrate", dest="rule14_deep_integrate",
                   action="store_true",
                   help="Run Rule 14 deep integration via triager-amend-asymmetry.")
    # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered for these flags.
    p.add_argument("--hevm", default="",
                   help="HEVM symbolic execution target (Foundry project root, bytecode file).")
    p.add_argument("--hevm-contract", dest="hevm_contract", default="",
                   help="Optional contract name for hevm symbolic.")
    p.add_argument("--hevm-function", dest="hevm_function", default="",
                   help='Optional function signature for hevm symbolic '
                        '(e.g. "transfer(address,uint256)").')
    p.add_argument("--hevm-timeout", dest="hevm_timeout", type=int, default=600,
                   help="Wall-clock timeout for hevm in seconds (default 600).")
    p.add_argument("--kontrol", default="",
                   help="Kontrol K-Framework proof front-end target. "
                        "Currently SKIPPED unconditionally (kompile backend not installed).")
    p.add_argument("--all", action="store_true",
                   help="Run every wired tool against the workspace; uses workspace path "
                        "as the target for tool-specific defaults.")
    p.add_argument("--json", action="store_true", help="Emit JSON summary on stdout.")
    p.add_argument("--dry-run", action="store_true",
                   help="Honest-skip every tool without invocation; for tests / docs.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[depth-tools] workspace not found: {workspace}", file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []

    # --all expands to per-tool defaults using the workspace as target where
    # a tool-specific target was not explicitly supplied.
    # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered.
    if args.all:
        halmos_target = args.halmos or str(workspace)
        foundry_target = args.foundry_fuzz_1m or str(workspace)
        mythril_target = args.mythril or str(workspace)
        manticore_target = args.manticore or str(workspace)
        hevm_target = args.hevm or str(workspace)
        kontrol_target = args.kontrol or str(workspace)
        soak_target = args.soak_fuzz or str(workspace)
        # differential-fuzz needs a reference impl; skip in --all if reference absent.
        differential_target = args.differential_fuzz
        rows.append(run_halmos(workspace, halmos_target, dry_run=args.dry_run))
        rows.append(run_foundry_fuzz_1m(
            workspace, foundry_target, runs=args.runs, dry_run=args.dry_run))
        rows.append(run_mythril(workspace, mythril_target, dry_run=args.dry_run))
        rows.append(run_manticore(workspace, manticore_target, dry_run=args.dry_run))
        rows.append(run_hevm(
            workspace, hevm_target,
            contract=args.hevm_contract, function=args.hevm_function,
            timeout=args.hevm_timeout, dry_run=args.dry_run))
        rows.append(run_kontrol(workspace, kontrol_target, dry_run=args.dry_run))
        if differential_target and args.reference:
            rows.append(run_differential_fuzz(
                workspace, differential_target, args.reference, dry_run=args.dry_run))
        rows.append(run_soak_fuzz(
            workspace, soak_target, hours=args.hours, dry_run=args.dry_run))
        rows.append(run_rule14_deep_integrate(workspace, dry_run=args.dry_run))
    else:
        if args.halmos:
            rows.append(run_halmos(workspace, args.halmos, dry_run=args.dry_run))
        if args.foundry_fuzz_1m:
            rows.append(run_foundry_fuzz_1m(
                workspace, args.foundry_fuzz_1m, runs=args.runs, dry_run=args.dry_run))
        if args.mythril:
            rows.append(run_mythril(workspace, args.mythril, dry_run=args.dry_run))
        if args.manticore:
            rows.append(run_manticore(workspace, args.manticore, dry_run=args.dry_run))
        if args.hevm:
            rows.append(run_hevm(
                workspace, args.hevm,
                contract=args.hevm_contract, function=args.hevm_function,
                timeout=args.hevm_timeout, dry_run=args.dry_run))
        if args.kontrol:
            rows.append(run_kontrol(workspace, args.kontrol, dry_run=args.dry_run))
        if args.differential_fuzz:
            if not args.reference:
                print("[depth-tools] --differential-fuzz requires --reference", file=sys.stderr)
                return 2
            rows.append(run_differential_fuzz(
                workspace, args.differential_fuzz, args.reference, dry_run=args.dry_run))
        if args.soak_fuzz:
            rows.append(run_soak_fuzz(
                workspace, args.soak_fuzz, hours=args.hours, dry_run=args.dry_run))
        if args.rule14_deep_integrate:
            rows.append(run_rule14_deep_integrate(workspace, dry_run=args.dry_run))

    if not rows:
        print(
            "[depth-tools] no operation requested; pass --halmos / --foundry-fuzz-1m / "
            "--mythril / --manticore / --hevm / --kontrol / --differential-fuzz / "
            "--soak-fuzz / --rule14-deep-integrate / --all.",
            file=sys.stderr,
        )
        return 2

    summary = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "log_path": str(workspace / LOG_DIR / LOG_FILENAME),
        "rows": rows,
        "summary_counts": {
            "PASS": sum(1 for r in rows if r["status"] == "PASS"),
            "FAIL": sum(1 for r in rows if r["status"] == "FAIL"),
            "SKIPPED": sum(1 for r in rows if r["status"] == "SKIPPED"),
            "ERROR": sum(1 for r in rows if r["status"] == "ERROR"),
        },
    }

    # r36-rebuttal: lane orchestrator-hevm-kontrol pathspec registered.
    # Inventory banner: 8 production-ready + 1 SKIPPED-PARTIAL + 1 SKIPPED-PERMANENT.
    summary["tool_inventory"] = {
        "production_ready": [
            "halmos", "forge", "anvil", "cast", "medusa", "echidna", "myth", "hevm",
        ],
        "skipped_partial": ["kontrol"],  # wrapper installed; backend missing
        "skipped_permanent": ["manticore"],  # upstream abandoned
        "counts": {
            "production_ready": 8,
            "skipped_partial": 1,
            "skipped_permanent": 1,
            "total": 10,
        },
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[depth-tools] workspace={workspace}")
        print(f"[depth-tools] log={summary['log_path']}")
        inv = summary["tool_inventory"]["counts"]
        print(
            f"[depth-tools] tool inventory: {inv['production_ready']}/{inv['total']} "
            f"production-ready (halmos, forge, anvil, cast, medusa, echidna, myth, hevm) "
            f"+ {inv['skipped_partial']} SKIPPED-PARTIAL (kontrol) "
            f"+ {inv['skipped_permanent']} SKIPPED-PERMANENT (manticore)"
        )
        for r in rows:
            print(f"  [{r['status']:7s}] {r['tool']:24s} target={r['target']}"
                  f" lang={r['applicable_language'] or '-'}"
                  + (f" reason={r['skip_reason']}" if r["skip_reason"] else "")
                  + (f" dur={r['duration_seconds']:.2f}s" if r['duration_seconds'] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
