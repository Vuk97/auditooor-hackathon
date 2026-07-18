#!/usr/bin/env python3
"""econ-simulator.py — PR 207 economic-simulator (iter4 T4 prototype + iter10 T4 live-mode).

First validated target: `POLY-ITER3-R77-06` (Medium, polymarket; the
"Adapter Donation Capture" angle). The pending ledger row landed in iter3
T2 (commit `96db28f5`); PR 207 is the first real end-to-end prototype
against it. PR 207-b (iter10 T4) adds the real `anvil` + `halmos`
invocation path behind `--live`; gate promotion remains PR 207-e's job.

## Doctrine (locked by iter4 T4 + iter10 T4 + playbook §5 + §6)

1. **Advisory-only.** The simulator's output is deliberately kept out of
   `submission-packager.py`'s evidence-matrix verdict computation. A
   simulator manifest can NEVER:
      - move `evidence-matrix.verdict` to `READY`;
      - upgrade a draft's severity (Medium stays Medium);
      - be classified as `PRESENT` (proof-grade) on any evidence row.
   The packager is NOT modified by PR 207-b. PR 206 gate-promotion
   requires ≥3 real engagements per playbook §5 doctrine. We have 1
   (polymarket). The gate stays advisory. Gate promotion is PR 207-e,
   explicitly NOT this PR.

2. **Dry-run is the default.** `ECON_SIM_DRY_RUN=1` (or unset) is honored
   (matching PR 202's `SYMBOLIC_DRY_RUN`). In dry-run we never invoke
   `halmos`, `anvil`, `forge`, or any RPC. We write a scaffolded manifest
   with `status: skipped` + `reason: "dry-run: scaffolded"`. Dry-run is
   exercised by the 4 iter4 T4 offline tests.

3. **`--live` / `ECON_SIM_DRY_RUN=0` activates live-mode (iter10 T4).**
   Real-run path spawns `anvil` (forked RPC background process) + invokes
   `halmos` (symbolic test runner) against the packaged bundle, then
   parses halmos output per design §3.5:
     - SAT (Counterexample:/Failed:) → status=counterexample
     - UNSAT (exit 0, no markers)   → status=no-counterexample
     - timeout (exit 124/137)       → status=timeout
     - anything else                → status=error
   Every live-mode manifest preserves `advisory: true` +
   `severity_upgrade_allowed: false` + `evidence_matrix_contributes:
   false` (design §5 invariant; locked by the
   `test_live_mode_output_still_advisory_only` regression test in
   `tools/tests/test_econ_simulator_live_mode.py`).

4. **No RPC URL literals in code.** Operator must provide the RPC URL
   via `--rpc-url` CLI arg, `ECON_SIM_RPC_URL` environment variable, or
   the replay-manifest JSON (`rpc_url` key). Live-mode without any of
   these sources emits `status: error` with a reason naming the missing
   input. No hardcoded defaults.

5. **Status vocabulary locked** to PR 202's set:
   `{pass, counterexample, no-counterexample, timeout, error, skipped}`.
   No new strings are introduced. `write_manifest()` raises on any
   status outside this set.

6. **Packaged-bundle anchor.** The simulator writes ONLY to
   `<bundle>/econ-simulator/<angle>.json` (plus optional
   `<angle>.ce.txt` and `<angle>.stderr.log` sibling artifacts in
   live-mode). It does NOT touch `<bundle>/evidence-matrix.json`,
   `<bundle>/manifest.json`, or any artifact under `submissions/`.

## Usage

    # Default — dry-run, scaffolded manifest only
    python3 tools/econ-simulator.py \\
        --bundle ~/audits/polymarket/submissions/packaged/r77-06 \\
        --angle A-DONATION-CAPTURE

    # Live-mode — spawns anvil + halmos; advisory-only output
    python3 tools/econ-simulator.py \\
        --bundle ~/audits/polymarket/submissions/packaged/r77-06 \\
        --angle A-DONATION-CAPTURE --live \\
        --rpc-url https://polygon-rpc.com

    # Override the output location
    python3 tools/econ-simulator.py \\
        --bundle ~/audits/polymarket/submissions/packaged/r77-06 \\
        --angle A-DONATION-CAPTURE --out /tmp/sim.json

Exit codes:
  0 — simulator ran to completion (any status in the locked vocabulary).
  2 — misconfiguration (bad --angle, missing --bundle, etc).

See also: `docs/WORKFLOW.md` §"Economic simulator",
`docs/PR_207_LIVE_MODE_DESIGN.md`, `docs/LOOP_ITER_004_PLAN.md` §T4, and
`docs/LOOP_ITER_010_PLAN.md` §T4 (PR 207-b landing).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Repo root used to locate `tools/angle_map.json` + invariant family harnesses
# when `--force-angle` is supplied. Matches `AUDITOOOR_DIR` in
# `tools/submission-packager.py` (this file lives under `tools/`).
# ---------------------------------------------------------------------------
AUDITOOOR_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Locked status vocabulary (docs/10_OF_10_PLAYBOOK.md §5 + PR 202 set)
# ---------------------------------------------------------------------------
STATUS_PASS = "pass"
STATUS_COUNTEREXAMPLE = "counterexample"
STATUS_NO_COUNTEREXAMPLE = "no-counterexample"
STATUS_TIMEOUT = "timeout"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
ALLOWED_STATUSES = frozenset({
    STATUS_PASS,
    STATUS_COUNTEREXAMPLE,
    STATUS_NO_COUNTEREXAMPLE,
    STATUS_TIMEOUT,
    STATUS_ERROR,
    STATUS_SKIPPED,
})

# ---------------------------------------------------------------------------
# Known attack angles. A-DONATION-CAPTURE is R77-06's angle. Any other
# named angle is validated against this list and rejected with status=error
# (never a silent pass). Adding a new angle here is the ONLY way new angles
# enter the vocabulary — same discipline as symbolic-runner.sh.
# ---------------------------------------------------------------------------
KNOWN_ANGLES: Dict[str, Dict[str, str]] = {
    "A-DONATION-CAPTURE": {
        "description": (
            "Balance-delta vs balanceOf(self): attacker donates asset X to "
            "adapter, invokes permissionless redeem, captures the full "
            "post-op balance as if it were the redemption delta."
        ),
        "prototype_target": "POLY-ITER3-R77-06",
    },
    "A-ORACLE-SANDWICH": {
        "description": (
            "Price manipulation via sandwich — donate + atomic redeem in "
            "the same tx window to extract the donated delta."
        ),
        "prototype_target": "future",
    },
    "A-GOVERNANCE-BRIBE": {
        "description": (
            "Governance-level capture where a proposal redirects protocol "
            "assets to the attacker under an economic constraint check."
        ),
        "prototype_target": "future",
    },
}
_HARNESS_CONTRACT_RE = re.compile(
    r"^\s*contract\s+([A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_dry_run() -> bool:
    """Return True if dry-run mode is active (default).

    Matches the PR 202 `SYMBOLIC_DRY_RUN` discipline. `--live` on the CLI
    forces `ECON_SIM_DRY_RUN=0` for the duration of the invocation.
    """
    return os.environ.get("ECON_SIM_DRY_RUN", "1") != "0"


def load_bundle_draft(bundle: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """Return (draft_path, evidence_matrix_path) for a packaged bundle.

    Both are optional — the simulator does not require them (advisory tool);
    if present it uses them only to annotate the output manifest.
    """
    draft = bundle / "source-draft.md"
    em = bundle / "evidence-matrix.json"
    return (draft if draft.is_file() else None,
            em if em.is_file() else None)


def infer_target_contracts(draft_path: Optional[Path]) -> List[str]:
    """Best-effort parse of contract names from the draft.

    Used only for annotation. We deliberately do NOT fail if this returns
    empty — the simulator's dry-run manifest is informative even without
    a parsed target list.
    """
    if draft_path is None:
        return []
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return []
    # Heuristic: look for `\`<ContractName>\`` or `**Target**: <Name>` tokens.
    import re
    names: List[str] = []
    for m in re.finditer(
        r"`([A-Z][A-Za-z0-9_]{2,})\.(?:sol|redeem|convert|split|merge)",
        text,
    ):
        nm = m.group(1)
        if nm not in names:
            names.append(nm)
    for m in re.finditer(r"`([A-Z][A-Za-z0-9_]{3,})`", text):
        nm = m.group(1)
        # Filter obvious non-contract tokens.
        if nm.isupper():
            continue
        if nm in names:
            continue
        # Only keep CamelCase identifiers that look contract-shaped.
        if any(c.islower() for c in nm) and any(c.isupper() for c in nm):
            names.append(nm)
        if len(names) >= 16:
            break
    return names[:16]


def load_replay_manifest(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None:
        return None
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core manifest writers
# ---------------------------------------------------------------------------
def write_manifest(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Final safety net: if a caller ever constructs an out-of-vocabulary
    # status, refuse to write. Never silently downgrade.
    status = payload.get("status")
    if status not in ALLOWED_STATUSES:
        raise ValueError(
            f"econ-simulator refusing to write manifest with out-of-vocabulary "
            f"status={status!r} (allowed: {sorted(ALLOWED_STATUSES)})"
        )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def scaffolded_manifest(
    *, angle: str, bundle: Path, targets: List[str],
    replay_manifest_path: Optional[Path], replay_summary: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    known = KNOWN_ANGLES[angle]
    return {
        "schema_version": 1,
        "pr": 207,
        "tool": "econ-simulator",
        "angle": angle,
        "angle_description": known["description"],
        "prototype_target": known["prototype_target"],
        "bundle": str(bundle),
        "target_contracts": targets,
        "replay_manifest": str(replay_manifest_path) if replay_manifest_path else None,
        "replay_summary": replay_summary,
        "status": STATUS_SKIPPED,
        "reason": "dry-run: scaffolded",
        "advisory": True,
        "severity_upgrade_allowed": False,
        "evidence_matrix_contributes": False,
        "timestamp": iso_now(),
        "notes": (
            "PR 207 iter4 prototype — simulator output is advisory-only. It "
            "cannot promote evidence-matrix.verdict to READY, cannot upgrade "
            "severity, and cannot be classified as proof-grade. See "
            "docs/WORKFLOW.md §'Economic simulator' and "
            "docs/LOOP_ITER_004_PLAN.md §T4."
        ),
    }


def error_manifest(
    *, angle: str, bundle: Path, reason: str, extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema_version": 1,
        "pr": 207,
        "tool": "econ-simulator",
        "angle": angle,
        "bundle": str(bundle),
        "status": STATUS_ERROR,
        "reason": reason,
        "advisory": True,
        "severity_upgrade_allowed": False,
        "evidence_matrix_contributes": False,
        "timestamp": iso_now(),
    }
    if extra:
        payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# Live-mode (PR 207-b, iter10 T4) — real halmos + anvil invocation.
#
# Every live-mode output preserves the advisory-only flag block per design §5.
# Gate promotion is PR 207-e's job, NOT this code path.
# ---------------------------------------------------------------------------

# Hard-cap for the halmos process (seconds). Mirrors PR 109 symbolic-runner
# timeout. Operator override: --halmos-timeout.
DEFAULT_HALMOS_TIMEOUT_SECONDS = 1800

# Hard-cap for waiting on anvil readiness probe (seconds).
ANVIL_READINESS_TIMEOUT_SECONDS = 30


def _preflight_binaries() -> Tuple[Optional[str], Optional[str], List[str]]:
    """Return (halmos_path, anvil_path, missing_names)."""
    halmos_path = shutil.which("halmos")
    anvil_path = shutil.which("anvil")
    missing: List[str] = []
    if halmos_path is None:
        missing.append("halmos")
    if anvil_path is None:
        missing.append("anvil")
    return halmos_path, anvil_path, missing


def _resolve_rpc_url(
    cli_rpc_url: Optional[str],
    replay_manifest: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Resolve RPC URL from (in order): CLI flag, env var, replay manifest.

    No hardcoded defaults — returns None if none of the sources provide
    a value. Caller emits status=error in that case.
    """
    if cli_rpc_url:
        return cli_rpc_url
    env_url = os.environ.get("ECON_SIM_RPC_URL")
    if env_url:
        return env_url
    if isinstance(replay_manifest, dict):
        candidate = replay_manifest.get("rpc_url")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _pick_free_port() -> int:
    """Bind to port 0 and close, returning the OS-assigned port.

    Tiny race window between the close and anvil bind is acceptable for
    advisory-only tooling; live-mode retries on EADDRINUSE are left to a
    later hardening pass (design §8.2).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _spawn_anvil(
    *,
    anvil_binary: str,
    rpc_url: str,
    fork_block: Optional[int],
    port: int,
) -> subprocess.Popen:
    """Spawn anvil --fork-url <rpc_url> [--fork-block-number N] --port <P>.

    Returned Popen handle is ALWAYS killed by the caller's try/finally.
    """
    cmd: List[str] = [
        anvil_binary,
        "--fork-url", rpc_url,
        "--port", str(port),
        "--silent",
    ]
    if fork_block is not None:
        cmd.extend(["--fork-block-number", str(fork_block)])
    # stdout/stderr piped and kept open — we only check process liveness +
    # probe the RPC port; we don't parse anvil logs.
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _probe_anvil_ready(
    port: int,
    timeout_seconds: int = ANVIL_READINESS_TIMEOUT_SECONDS,
) -> bool:
    """Poll the anvil RPC port until it accepts connections or we time out.

    Returns True if ready, False otherwise.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def parse_halmos_output(
    stdout_text: str,
    stderr_text: str,
    exit_code: int,
) -> Tuple[str, str, Optional[str]]:
    """Classify a halmos run's outcome (design §3.5).

    Returns (status, reason, counterexample_block).

    Status is one of {counterexample, no-counterexample, timeout, error}
    — always inside the locked vocabulary. `counterexample_block` is
    non-None only when status == counterexample.

    Classification cascade (matches symbolic-runner.sh lines 591-629):
      1. SAT / counterexample markers in stdout → counterexample
      2. timeout sentinel exit codes (124, 137) → timeout
      3. exit 0, no counterexample markers → no-counterexample
      4. anything else → error
    """
    # Look for counterexample markers first — SAT trumps exit-code shape.
    ce_regex = re.compile(r"Counterexample:|^Failed:", re.MULTILINE)
    match = ce_regex.search(stdout_text or "")
    if match:
        # Capture everything from the first marker onwards so the block
        # can be persisted next to the manifest.
        block = (stdout_text or "")[match.start():]
        return (
            STATUS_COUNTEREXAMPLE,
            "halmos emitted counterexample markers in stdout",
            block,
        )

    if exit_code in (124, 137):
        return (
            STATUS_TIMEOUT,
            f"halmos killed by timeout(1) (exit {exit_code})",
            None,
        )

    if exit_code == 0:
        return (
            STATUS_NO_COUNTEREXAMPLE,
            "halmos explored all paths; no counterexample markers in stdout",
            None,
        )

    # Everything else → error (includes parse crashes, missing imports, etc).
    reason = (
        f"halmos exited non-zero ({exit_code}) with no counterexample markers"
    )
    if stderr_text:
        # Include a short stderr snippet in the reason (kept bounded so the
        # manifest stays small; full stderr goes to a sibling log file).
        snippet = stderr_text.strip().splitlines()[-1][:160] if stderr_text.strip() else ""
        if snippet:
            reason += f"; stderr tail: {snippet}"
    return (STATUS_ERROR, reason, None)


def _parse_harness_contract_name(path: Path) -> Optional[str]:
    """Return the first Solidity contract name declared in `path`, if any."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    match = _HARNESS_CONTRACT_RE.search(text)
    return match.group(1) if match else None


def _load_harness_binding_manifest(bundle: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load the harness binding manifest if present, else return `(None, None)`."""
    manifest_path = bundle / "harness-binding-manifest.json"
    if not manifest_path.is_file():
        return (None, None)
    try:
        payload = json.loads(manifest_path.read_text())
    except Exception:
        return (None, "harness-binding-manifest.json is not valid JSON")
    if not isinstance(payload, dict):
        return (None, "harness-binding-manifest.json must contain a JSON object")
    entries = payload.get("entries")
    unresolved = payload.get("unresolved_angles")
    if not isinstance(entries, list) or not isinstance(unresolved, list):
        return (
            None,
            "harness-binding-manifest.json must contain list fields "
            "`entries` and `unresolved_angles`",
        )
    return (payload, None)


def _select_harness(bundle: Path, angle: str) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
    """Resolve the harness path + contract name for one angle.

    Search order:
      1. `<bundle>/econ-simulator/harness.t.sol` — explicit per-bundle pick.
      2. `<bundle>/harness-binding-manifest.json` — authoritative angle binding.
      3. `<bundle>/harnesses/<angle>.t.sol` — legacy angle-keyed convention.
      4. Any single `<bundle>/harnesses/*.t.sol` — legacy single-file fallback.

    Returns `(path, contract_name, None)` when the selection is usable.
    Returns `(None, None, reason)` when the harness surface is ambiguous,
    malformed, or absent.
    """
    explicit = bundle / "econ-simulator" / "harness.t.sol"
    if explicit.is_file():
        contract_name = _parse_harness_contract_name(explicit)
        if not contract_name:
            return (None, None, "econ-simulator/harness.t.sol is missing a Solidity contract name")
        return (explicit, contract_name, None)

    manifest, manifest_error = _load_harness_binding_manifest(bundle)
    if manifest_error:
        return (None, None, manifest_error)
    if manifest is not None:
        for item in manifest.get("unresolved_angles", []):
            if not isinstance(item, dict):
                continue
            if str(item.get("angle_id") or "").strip() == angle:
                reason = str(item.get("reason") or "unknown").strip() or "unknown"
                return (
                    None,
                    None,
                    f"harness binding for angle {angle} is unresolved: {reason}",
                )
        for entry in manifest.get("entries", []):
            if not isinstance(entry, dict):
                return (None, None, "harness-binding-manifest.json contains a non-object entry")
            if str(entry.get("angle_id") or "").strip() != angle:
                continue
            rel_path = str(entry.get("bundle_harness") or "").strip()
            contract_name = str(entry.get("contract_name") or "").strip()
            if not rel_path or not contract_name:
                return (
                    None,
                    None,
                    f"harness-binding-manifest.json entry for {angle} is missing "
                    "`bundle_harness` or `contract_name`",
                )
            harness_path = bundle / rel_path
            if not harness_path.is_file():
                return (
                    None,
                    None,
                    f"harness-binding-manifest.json points to missing harness `{rel_path}`",
                )
            return (harness_path, contract_name, None)
        harness_count = len(list((bundle / "harnesses").glob("*.t.sol")))
        if harness_count:
            return (
                None,
                None,
                f"harness-binding-manifest.json has no entry for angle {angle}",
            )

    angle_keyed = bundle / "harnesses" / f"{angle}.t.sol"
    if angle_keyed.is_file():
        contract_name = _parse_harness_contract_name(angle_keyed)
        if not contract_name:
            return (None, None, f"harness `{angle_keyed.name}` is missing a Solidity contract name")
        return (angle_keyed, contract_name, None)
    harnesses_dir = bundle / "harnesses"
    if harnesses_dir.is_dir():
        candidates = sorted(harnesses_dir.glob("*.t.sol"))
        if len(candidates) > 1:
            return (
                None,
                None,
                "multiple harnesses present but harness-binding-manifest.json is missing; "
                "refusing ambiguous lexicographic fallback",
            )
        if len(candidates) == 1:
            contract_name = _parse_harness_contract_name(candidates[0])
            if not contract_name:
                return (
                    None,
                    None,
                    f"harness `{candidates[0].name}` is missing a Solidity contract name",
                )
            return (candidates[0], contract_name, None)
    return (None, None, None)


def _run_halmos(
    *,
    halmos_binary: str,
    harness_path: Path,
    contract_name: str,
    rpc_url: str,
    anvil_port: int,
    timeout_seconds: int,
) -> Tuple[int, str, str]:
    """Invoke halmos against the anvil fork. Returns (exit_code, stdout, stderr).

    This function is the subprocess.run call the test suite patches via
    unittest.mock — structured as a thin wrapper so tests can override
    without reaching into subprocess internals directly.
    """
    cmd: List[str] = [
        halmos_binary,
        "--contract", contract_name,
        "--function", "invariant_",
        "--root", str(harness_path.parent),
        "--fork-url", f"http://127.0.0.1:{anvil_port}",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return (result.returncode, result.stdout or "", result.stderr or "")
    except subprocess.TimeoutExpired as exc:
        # Surface a sentinel exit code matching timeout(1) for the parser.
        stdout_bytes = exc.stdout or b""
        stderr_bytes = exc.stderr or b""
        stdout = stdout_bytes.decode("utf-8", errors="replace") if isinstance(stdout_bytes, (bytes, bytearray)) else str(stdout_bytes)
        stderr = stderr_bytes.decode("utf-8", errors="replace") if isinstance(stderr_bytes, (bytes, bytearray)) else str(stderr_bytes)
        return (124, stdout, stderr)


def live_mode_run(
    *,
    angle: str,
    bundle: Path,
    out_path: Path,
    targets: List[str],
    replay_manifest_path: Optional[Path],
    replay_manifest: Optional[Dict[str, Any]],
    replay_summary: Optional[Dict[str, Any]],
    cli_rpc_url: Optional[str],
    halmos_timeout_seconds: int,
) -> Dict[str, Any]:
    """Live-mode code path (PR 207-b, iter10 T4).

    Invariants this function upholds:
      - ALL returned manifests carry `advisory: true`,
        `severity_upgrade_allowed: false`,
        `evidence_matrix_contributes: false`.
      - Status stays inside ALLOWED_STATUSES.
      - anvil subprocess ALWAYS killed in the finally clause.
      - No write to evidence-matrix.json, manifest.json, or any
        submissions/ artifact.
    """

    # 1. Preflight: binaries on PATH.
    halmos_path, anvil_path, missing = _preflight_binaries()
    if missing:
        return error_manifest(
            angle=angle,
            bundle=bundle,
            reason=(
                f"live mode requires binaries on PATH; missing: "
                f"{', '.join(missing)}. Install halmos + anvil before "
                "re-running."
            ),
            extra={
                "halmos_on_path": halmos_path,
                "anvil_on_path": anvil_path,
                "mode": "live",
            },
        )

    # 2. Resolve RPC URL — operator-provided only, no literals in code.
    rpc_url = _resolve_rpc_url(cli_rpc_url, replay_manifest)
    if not rpc_url:
        return error_manifest(
            angle=angle,
            bundle=bundle,
            reason=(
                "live mode requires an RPC URL: pass --rpc-url, set "
                "ECON_SIM_RPC_URL, or include 'rpc_url' in the "
                "replay-manifest JSON. None of these sources provided a value."
            ),
            extra={"mode": "live"},
        )

    # 3. Pick a harness file.
    harness_path, contract_name, harness_error = _select_harness(bundle, angle)
    if harness_path is None or contract_name is None:
        reason = harness_error or (
            f"no compile-green harness found for angle {angle} in bundle. "
            f"Looked under <bundle>/econ-simulator/harness.t.sol and "
            f"<bundle>/harnesses/*.t.sol."
        )
        return error_manifest(
            angle=angle,
            bundle=bundle,
            reason=reason,
            extra={"mode": "live"},
        )

    # 4. Extract fork_block from the replay manifest if present (optional).
    fork_block: Optional[int] = None
    if isinstance(replay_manifest, dict):
        candidate = replay_manifest.get("fork_block") or replay_manifest.get("fork_block_number")
        if isinstance(candidate, int):
            fork_block = candidate
        elif isinstance(candidate, str) and candidate.isdigit():
            fork_block = int(candidate)

    # 5. Pick a free port for anvil.
    port = _pick_free_port()

    # 6. Spawn anvil in a try/finally so it's always reaped.
    anvil_proc: Optional[subprocess.Popen] = None
    started_at = iso_now()
    started_epoch = time.time()
    try:
        anvil_proc = _spawn_anvil(
            anvil_binary=anvil_path or "anvil",
            rpc_url=rpc_url,
            fork_block=fork_block,
            port=port,
        )

        if not _probe_anvil_ready(port):
            # Readiness probe failed — classify as error.
            return error_manifest(
                angle=angle,
                bundle=bundle,
                reason=(
                    f"anvil failed to accept connections on port {port} within "
                    f"{ANVIL_READINESS_TIMEOUT_SECONDS}s"
                ),
                extra={
                    "mode": "live",
                    "anvil_port": port,
                    "harness": str(harness_path),
                    "rpc_url_source": "operator-provided (not logged)",
                },
            )

        # 7. Run halmos against the fork.
        exit_code, stdout_text, stderr_text = _run_halmos(
            halmos_binary=halmos_path or "halmos",
            harness_path=harness_path,
            contract_name=contract_name,
            rpc_url=rpc_url,
            anvil_port=port,
            timeout_seconds=halmos_timeout_seconds,
        )

        # 8. Classify.
        status, reason, ce_block = parse_halmos_output(
            stdout_text, stderr_text, exit_code,
        )

        ended_epoch = time.time()
        duration_seconds = int(ended_epoch - started_epoch)

        # 9. Persist sibling artifacts (ce.txt, stderr.log) if applicable.
        ce_rel_path: Optional[str] = None
        stderr_rel_path: Optional[str] = None
        out_dir = out_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        if status == STATUS_COUNTEREXAMPLE and ce_block:
            ce_file = out_dir / f"{angle}.ce.txt"
            try:
                ce_file.write_text(ce_block)
                ce_rel_path = ce_file.name
            except Exception:
                # Best-effort; absence of the ce file is not a correctness issue.
                ce_rel_path = None

        if stderr_text and status in (STATUS_ERROR, STATUS_TIMEOUT):
            stderr_file = out_dir / f"{angle}.stderr.log"
            try:
                stderr_file.write_text(stderr_text)
                stderr_rel_path = stderr_file.name
            except Exception:
                stderr_rel_path = None

        # 10. Build manifest — advisory-only invariants preserved.
        known = KNOWN_ANGLES[angle]
        payload: Dict[str, Any] = {
            "schema_version": 1,
            "pr": 207,
            "tool": "econ-simulator",
            "mode": "live",
            "angle": angle,
            "angle_description": known["description"],
            "prototype_target": known["prototype_target"],
            "bundle": str(bundle),
            "target_contracts": targets,
            "harness": str(harness_path),
            "halmos_command": (
                f"halmos --contract {contract_name} "
                f"--function invariant_ --root {harness_path.parent} "
                f"--fork-url http://127.0.0.1:{port}"
            ),
            "halmos_exit_code": exit_code,
            "anvil_port": port,
            "fork_block": fork_block,
            "replay_manifest": (
                str(replay_manifest_path) if replay_manifest_path else None
            ),
            "replay_summary": replay_summary,
            "status": status,
            "reason": reason,
            "duration_seconds": duration_seconds,
            "started_at": started_at,
            "ended_at": iso_now(),
            # Advisory-only flag block — LOCKED by test_live_mode_output_still_advisory_only.
            "advisory": True,
            "severity_upgrade_allowed": False,
            "evidence_matrix_contributes": False,
            "notes": (
                "PR 207-b live-mode output is REVIEW signal only. It does "
                "NOT upgrade severity, does NOT move evidence-matrix.verdict "
                "to READY, and is NOT classified as proof-grade. Gate "
                "promotion is PR 207-e's job, not this PR. See "
                "docs/PR_207_LIVE_MODE_DESIGN.md §5-§6."
            ),
        }
        if ce_rel_path:
            payload["counterexample_path"] = ce_rel_path
        if stderr_rel_path:
            payload["stderr_log"] = stderr_rel_path
        return payload
    finally:
        # ALWAYS kill anvil — success, failure, or exception.
        if anvil_proc is not None:
            try:
                anvil_proc.terminate()
                try:
                    anvil_proc.wait(timeout=5)
                except Exception:
                    try:
                        anvil_proc.kill()
                    except Exception:
                        pass
            except Exception:
                # Best-effort cleanup; advisory-only tool must not hang.
                pass


# ---------------------------------------------------------------------------
# `--force-angle` support (iter13 T3)
#
# iter12 T2 surfaced a draft-side gap: `submission-packager.py`'s
# `detect_attack_angles()` scans the draft body for `A-<ANGLE>` tokens.
# Legacy drafts that predate the token convention (e.g. R77-06) yield
# `[]` so the packager quietly skips harness emission (fail-open per
# FM-002). `--force-angle` is the narrow, operator-auditable override:
# pass an explicit angle, bootstrap the matching family harness directly
# into the bundle, and record provenance in the manifest.
#
# Hard rules:
#   - Angle MUST be mapped in `tools/angle_map.json`. Unmapped → exit 2
#     + `status: error` + reason cites the unmapped angle.
#   - `--force-angle` does NOT edit the packager and does NOT modify
#     `angle_map.json`. Read-only on both.
#   - When set, bypasses harness-picker (step 3 of `live_mode_run`) by
#     copying the family harness to `<bundle>/harnesses/<angle>.t.sol`
#     BEFORE live-mode runs (mirrors packager's `bundle_symbolic_harness`
#     logic, but runs on the consumer side).
#   - Advisory-only flags remain preserved on every output path.
#   - `angle_source` is a new PROVENANCE field (not a status string).
#     Locked values: "force-angle-cli" when --force-angle was supplied.
# ---------------------------------------------------------------------------
ANGLE_SOURCE_FORCE_CLI = "force-angle-cli"


def _load_angle_map_for_force(
    angle_map_path: Optional[Path] = None,
) -> Dict[str, str]:
    """Read-only load of `tools/angle_map.json` for `--force-angle` use.

    Mirrors the packager's `load_angle_map` fail-open shape (returns `{}`
    on missing/malformed file) — but `--force-angle`'s caller treats an
    empty map as "not mapped" and errors out rather than silently
    skipping (fail-closed semantics, consistent with known-angle gating).
    """
    path = angle_map_path or (AUDITOOOR_DIR / "tools" / "angle_map.json")
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _pick_family_harness_for_force(
    invariants_dir: Path, family: str,
) -> Optional[Path]:
    """Lex-first pick of `*.t.sol` under `<invariants_dir>/<family>/`.

    Matches packager's `_pick_family_harness`. No fabrication: returns
    None if directory is missing or has no harness file.
    """
    family_dir = invariants_dir / family
    if not family_dir.is_dir():
        return None
    candidates = sorted(family_dir.glob("*.t.sol"))
    return candidates[0] if candidates else None


def bootstrap_forced_harness(
    *, bundle: Path, angle: str,
    angle_map_path: Optional[Path] = None,
    invariants_dir: Optional[Path] = None,
) -> Tuple[Optional[Path], Optional[str]]:
    """Copy the family harness for `angle` into `<bundle>/harnesses/<angle>.t.sol`.

    Returns `(written_dest, error_reason)`:
      - On success: `(Path(<bundle>/harnesses/<angle>.t.sol), None)`.
      - Unmapped angle: `(None, "--force-angle <X> not in angle_map.json")`.
      - Family directory missing / empty: `(None, "...family ... missing ...")`.

    Does NOT clobber an operator-authored destination (same rule as the
    packager's `bundle_symbolic_harness`).
    """
    angle_map = _load_angle_map_for_force(angle_map_path)
    family = angle_map.get(angle)
    if not family:
        return (None, f"--force-angle {angle} not in angle_map.json")

    inv_dir = invariants_dir or (
        AUDITOOOR_DIR / "tools" / "invariants" / "families"
    )
    source = _pick_family_harness_for_force(inv_dir, family)
    if source is None:
        return (
            None,
            f"--force-angle {angle} maps to family {family!r} but no "
            f"*.t.sol harness found under {inv_dir}/{family}/",
        )

    harnesses_dir = bundle / "harnesses"
    dest = harnesses_dir / f"{angle}.t.sol"
    if dest.exists():
        # Operator-authored harness wins; mirror packager's rule. Still
        # treat this as a successful bootstrap — the downstream picker
        # will find it.
        return (dest, None)
    harnesses_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    return (dest, None)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="econ-simulator.py",
        description=(
            "PR 207 economic-simulator prototype (iter4 T4). Advisory-only; "
            "dry-run by default. First validated target: POLY-ITER3-R77-06."
        ),
    )
    p.add_argument(
        "--bundle", required=True, type=Path,
        help="Packaged bundle directory (e.g. <ws>/submissions/packaged/r77-06).",
    )
    p.add_argument(
        "--angle", required=True,
        help=(
            "Named attack angle (e.g. A-DONATION-CAPTURE for R77-06). "
            "Must be present in KNOWN_ANGLES; unknown angles emit "
            "status=error with nonzero exit."
        ),
    )
    p.add_argument(
        "--replay-manifest", type=Path, default=None,
        help="Optional path to an existing fork-replay manifest to cite.",
    )
    p.add_argument(
        "--out", type=Path, default=None,
        help=(
            "Override output path. Defaults to "
            "<bundle>/econ-simulator/<angle>.json."
        ),
    )
    p.add_argument(
        "--live", action="store_true",
        help=(
            "Attempt real-mode run (PR 207-b). Spawns anvil + halmos. "
            "Output is still advisory-only. Requires halmos + anvil on "
            "PATH and an RPC URL (--rpc-url / ECON_SIM_RPC_URL / replay "
            "manifest). Without --live (or ECON_SIM_DRY_RUN=0) the tool "
            "stays in dry-run."
        ),
    )
    p.add_argument(
        "--rpc-url", default=None,
        help=(
            "RPC URL for anvil --fork-url. Alternatively set "
            "ECON_SIM_RPC_URL env or include 'rpc_url' in the replay "
            "manifest. No hardcoded defaults — operator-provided only."
        ),
    )
    p.add_argument(
        "--halmos-timeout", type=int, default=DEFAULT_HALMOS_TIMEOUT_SECONDS,
        help=(
            f"halmos subprocess timeout in seconds "
            f"(default: {DEFAULT_HALMOS_TIMEOUT_SECONDS})."
        ),
    )
    p.add_argument(
        "--force-angle", default=None,
        help=(
            "iter13 T3: operator override for legacy drafts that predate "
            "the `A-<ANGLE>` token convention (e.g. R77-06). Cross-checks "
            "the supplied angle against tools/angle_map.json. If mapped, "
            "bootstraps the matching family harness into "
            "<bundle>/harnesses/<angle>.t.sol and records "
            "angle_source=\"force-angle-cli\" in the manifest. If "
            "unmapped, hard-errors (exit 2, status=error). Never edits "
            "the packager or angle_map.json. Advisory-only flags remain "
            "preserved on every output path."
        ),
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    bundle: Path = args.bundle
    angle: str = args.angle
    replay_manifest_path: Optional[Path] = args.replay_manifest
    out_override: Optional[Path] = args.out
    cli_live: bool = args.live

    # ---- Pre-flight checks -------------------------------------------------
    if not bundle.is_dir():
        payload = {
            "schema_version": 1,
            "pr": 207,
            "tool": "econ-simulator",
            "angle": angle,
            "bundle": str(bundle),
            "status": STATUS_ERROR,
            "reason": f"bundle directory does not exist: {bundle}",
            "advisory": True,
            "severity_upgrade_allowed": False,
            "evidence_matrix_contributes": False,
            "timestamp": iso_now(),
        }
        # We still try to emit the manifest if --out was explicitly set;
        # otherwise just print to stderr.
        if out_override is not None:
            try:
                write_manifest(out_override, payload)
            except Exception:
                pass
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return 2

    if angle not in KNOWN_ANGLES:
        out_path = out_override or (bundle / "econ-simulator" / f"{angle}.json")
        payload = error_manifest(
            angle=angle,
            bundle=bundle,
            reason=(
                f"unknown --angle {angle!r} (allowed: {sorted(KNOWN_ANGLES)})"
            ),
        )
        try:
            write_manifest(out_path, payload)
        except Exception as exc:
            print(f"[econ-simulator] failed to write error manifest: {exc}",
                  file=sys.stderr)
        print(
            f"[econ-simulator] unknown --angle {angle!r}; wrote status=error "
            f"manifest to {out_path}",
            file=sys.stderr,
        )
        return 2

    # ---- Resolve output path ----------------------------------------------
    out_path = out_override or (bundle / "econ-simulator" / f"{angle}.json")

    # Hard-negative guard: the simulator MUST NOT write anywhere under
    # the bundle except <bundle>/econ-simulator/. We allow --out overrides
    # for tests but enforce the bundle-anchored default.
    if out_override is None:
        # Canonicalise to ensure we are under <bundle>/econ-simulator/
        assert str(out_path.parent) == str(bundle / "econ-simulator"), (
            "econ-simulator default output path must live under "
            "<bundle>/econ-simulator/"
        )

    # Annotate the bundle context (advisory-only).
    draft_path, _em_path = load_bundle_draft(bundle)
    targets = infer_target_contracts(draft_path)

    replay_summary: Optional[Dict[str, Any]] = None
    replay_loaded = load_replay_manifest(replay_manifest_path)
    if replay_loaded is not None:
        # We only echo a small shape summary — the simulator never edits
        # the replay manifest.
        replay_summary = {
            "keys": sorted(list(replay_loaded.keys()))[:16],
            "entry_count": len(replay_loaded.get("entries") or [])
                if isinstance(replay_loaded.get("entries"), list) else 0,
        }

    # ---- `--force-angle` bootstrap (iter13 T3) ----------------------------
    # When set, bypass harness-picker (step 3 of live_mode_run) by copying
    # the matching family harness into <bundle>/harnesses/<angle>.t.sol
    # BEFORE live-mode runs (same logic as packager's
    # `bundle_symbolic_harness`, but run-time / consumer-side).
    #
    # Cross-check rules:
    #   - `--force-angle` is authoritative per iter13 plan §T3: "If both
    #     `--force-angle` and a detected-angle set are non-empty,
    #     `--force-angle` wins (operator override is authoritative)."
    #   - The supplied angle is checked against `tools/angle_map.json`
    #     FIRST. Unmapped → hard-error exit 2 + `status: error` +
    #     reason citing "--force-angle <X> not in angle_map.json".
    #   - Advisory-only flags preserved on every output path (locked by
    #     the hard-negative guard in test_econ_simulator_live_mode.py
    #     and mirrored in this CLI's error_manifest builder).
    force_angle: Optional[str] = getattr(args, "force_angle", None)
    angle_source: Optional[str] = None
    if force_angle:
        written_dest, boot_err = bootstrap_forced_harness(
            bundle=bundle, angle=force_angle,
        )
        if boot_err is not None:
            payload = error_manifest(
                angle=angle,
                bundle=bundle,
                reason=boot_err,
                extra={"angle_source": ANGLE_SOURCE_FORCE_CLI},
            )
            try:
                write_manifest(out_path, payload)
            except Exception as exc:
                print(
                    f"[econ-simulator] failed to write error manifest: {exc}",
                    file=sys.stderr,
                )
            print(
                f"[econ-simulator] --force-angle rejected: {boot_err}",
                file=sys.stderr,
            )
            return 2
        angle_source = ANGLE_SOURCE_FORCE_CLI
        print(
            f"[econ-simulator] --force-angle {force_angle}: harness "
            f"bootstrapped at {written_dest}"
        )

    # ---- Live-mode (PR 207-b; iter10 T4) ----------------------------------
    live_mode = cli_live or not env_dry_run()
    if live_mode:
        payload = live_mode_run(
            angle=angle,
            bundle=bundle,
            out_path=out_path,
            targets=targets,
            replay_manifest_path=replay_manifest_path,
            replay_manifest=replay_loaded,
            replay_summary=replay_summary,
            cli_rpc_url=args.rpc_url,
            halmos_timeout_seconds=args.halmos_timeout,
        )
        # Belt-and-braces: enforce the advisory-only invariants here too.
        # A refactor that accidentally drops these flags dies at this check
        # (which complements test_live_mode_output_still_advisory_only).
        payload["advisory"] = True
        payload["severity_upgrade_allowed"] = False
        payload["evidence_matrix_contributes"] = False
        if angle_source is not None:
            payload["angle_source"] = angle_source
        write_manifest(out_path, payload)
        print(
            f"[econ-simulator] live-mode: "
            f"angle={angle} status={payload['status']} "
            f"reason={payload.get('reason')!r} out={out_path}"
        )
        return 0

    # ---- Dry-run (default) -------------------------------------------------
    payload = scaffolded_manifest(
        angle=angle,
        bundle=bundle,
        targets=targets,
        replay_manifest_path=replay_manifest_path,
        replay_summary=replay_summary,
    )
    if angle_source is not None:
        payload["angle_source"] = angle_source
    write_manifest(out_path, payload)
    print(
        f"[econ-simulator] angle={angle} status=skipped "
        f"reason=dry-run:scaffolded out={out_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
