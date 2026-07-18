#!/usr/bin/env python3
"""Hypothesis time-falsify wrapper for the auditooor toolkit.

Wraps existing fuzzers (echidna, medusa, halmos, or a custom fuzz-runner.sh)
with a configurable timeout cap per candidate hypothesis.  For each candidate
hypothesis the tool:

  1. Reads the hypothesis file (one JSON object per line).
  2. Invokes the appropriate fuzzer in a subprocess with a hard wall-clock
     timeout (default 60 s).
  3. Writes a JSON sidecar per candidate into the output directory.

CLI:
  python3 tools/hunt-time-falsify.py \
    --workspace <path> \
    --hypothesis-file <path> \
    --timeout-s 60 \
    --output <path>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.hunt_time_fuzz_result.v1"
TOOL_NAME = "hunt-time-falsify"
DEFAULT_TIMEOUT_S = 60
SUPPORTED_FUZZERS = ("echidna", "medusa", "halmos", "fuzz-runner.sh")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_fuzzer() -> Optional[str]:
    """Return the first available fuzzer executable name or ``None``."""
    for name in SUPPORTED_FUZZERS:
        if shutil.which(name):
            return name
    return None


def _build_fuzz_command(
    fuzzer: str,
    hypothesis: Dict[str, Any],
    workspace: Path,
    timeout_s: int,
) -> List[str]:
    """Build the subprocess command list for *fuzzer*.

    Each fuzzer has a slightly different invocation style.  We normalise
    everything into a flat command list so ``subprocess.run`` can execute it.
    """
    contract = hypothesis.get("contract") or hypothesis.get("target", "")
    test_name = hypothesis.get("name") or hypothesis.get("hypothesis_id", "")
    config: Dict[str, Any] = hypothesis.get("config", {})

    if fuzzer == "echidna":
        cmd = [
            "echidna",
            str(contract),
            "--test-mode", "assertion",
            "--timeout", str(timeout_s),
        ]
        corpus_dir = config.get("corpus_dir")
        if corpus_dir:
            cmd += ["--corpus-dir", str(corpus_dir)]
        return cmd

    if fuzzer == "medusa":
        cmd = [
            "medusa",
            "fuzz",
            "--target", str(contract),
            "--timeout", str(timeout_s),
        ]
        seq_len = config.get("seq_len")
        if seq_len:
            cmd += ["--seq-len", str(seq_len)]
        return cmd

    if fuzzer == "halmos":
        cmd = [
            "halmos",
            "--contract", str(contract),
            "--function", str(test_name),
            "--timeout", str(timeout_s),
        ]
        solver = config.get("solver")
        if solver:
            cmd += ["--solver", str(solver)]
        return cmd

    # Default: fuzz-runner.sh  (pass everything as key=value flags)
    cmd = ["fuzz-runner.sh", str(contract)]
    cmd += ["--name", str(test_name)]
    cmd += ["--timeout", str(timeout_s)]
    for k, v in config.items():
        cmd += [f"--{k}", str(v)]
    return cmd


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def run_single_hypothesis(
    hypothesis: Dict[str, Any],
    workspace: Path,
    fuzzer: str,
    timeout_s: int,
) -> Dict[str, Any]:
    """Execute a single hypothesis through the fuzzer and return a result dict.

    The result dict conforms to ``auditooor.hunt_time_fuzz_result.v1``.
    """
    hyp_id = hypothesis.get("hypothesis_id") or hypothesis.get("name", "unknown")
    start_ts = utc_now()
    wall_start = time.monotonic()

    cmd = _build_fuzz_command(fuzzer, hypothesis, workspace, timeout_s)

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hypothesis_id": hyp_id,
        "fuzzer": fuzzer,
        "command": cmd,
        "workspace": str(workspace),
        "timeout_s": timeout_s,
        "started_at": start_ts,
    }

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=timeout_s + 5,  # small grace period beyond wall limit
        )
        wall_elapsed = time.monotonic() - wall_start

        result["exit_code"] = proc.returncode
        result["stdout"] = proc.stdout[-4096:] if proc.stdout else ""
        result["stderr"] = proc.stderr[-4096:] if proc.stderr else ""
        result["elapsed_s"] = round(wall_elapsed, 3)

        # Heuristic classification
        if proc.returncode == 0:
            result["verdict"] = "NOT_FALSIFIED"
            result["summary"] = "Fuzzer exited 0 – no counterexample found within timeout."
        elif proc.returncode == 1:
            result["verdict"] = "FALSIFIED"
            result["summary"] = "Fuzzer exited 1 – potential counterexample detected."
        else:
            result["verdict"] = "ERROR"
            result["summary"] = f"Fuzzer exited with code {proc.returncode}."

    except subprocess.TimeoutExpired as exc:
        wall_elapsed = time.monotonic() - wall_start
        result["exit_code"] = -1
        result["elapsed_s"] = round(wall_elapsed, 3)
        result["verdict"] = "TIMEOUT"
        result["summary"] = (
            f"Fuzzer exceeded timeout of {timeout_s}s and was killed."
        )
        # Capture any partial output
        result["stdout"] = (exc.output or b"")[-4096:].decode(errors="replace")
        result["stderr"] = (exc.stderr or b"")[-4096:].decode(errors="replace")
        # Kill the whole process group if still alive
        if exc.cmd and hasattr(exc, "process"):
            try:
                os.killpg(os.getpgid(exc.process.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass

    except FileNotFoundError:
        wall_elapsed = time.monotonic() - wall_start
        result["exit_code"] = -2
