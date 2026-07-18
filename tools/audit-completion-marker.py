#!/usr/bin/env python3
"""audit-completion-marker.py — V5-P0-05 / Gap 45.

Track completion of `make audit` so a back-to-back rerun (or the
`audit:` dependency that fires implicitly from `make audit-deep`) can
short-circuit when nothing meaningful has changed since the last
successful run.

Marker file
-----------
    <workspace>/.audit_logs/audit_completion.json

Schema (``schema=auditooor.audit_completion.v1``)::

    {
      "schema": "auditooor.audit_completion.v1",
      "completed_at": <epoch float>,
      "completed_at_iso": "2026-04-26T17:42:00+00:00",
      "commit_sha": "<repo HEAD short sha or 'unknown'>",
      "audit_toolchain_hash": "<sha256 hex of audit-tool files>",
      "workspace_state_hash": "<sha256 hex of inventory; see _workspace_state_hash>",
      "workspace_state_inventory": [
          {"path": "src/Foo.sol", "mtime": 1714152000.0, "size": 1234},
          ...
      ],
      "stages_completed": ["scan-rust", "scan", ...]   // optional, advisory
    }

The workspace inventory is recorded at ``write`` time with content digests so
``check`` detects target mutations without treating checkout/compiler mtime
churn as a source change.

CLI
---
``write``  — record a fresh marker. Inputs: ``--workspace`` (required),
optional ``--commit-sha``, ``--stages``. Always writes (no freshness
check). Used by ``make audit`` AFTER engage.py exits 0.

``check``  — decide whether a fresh run is needed. Prints
``skip-fresh`` (exit 0) or ``run`` (exit 1). Hard errors exit 2. Honours:

* ``--force`` (or env ``FORCE=1``) — always exits 1 (run).
* ``--max-age-seconds`` (default ``1800``, env override
  ``AUDIT_FRESHNESS_SECONDS``). ``-1`` disables age expiry while retaining
  content, scope, and toolchain invalidation.
* ``--json`` for machine-readable output.

Truthiness: only the literal string ``"0"`` (and ``""``, ``"false"``,
``"no"``) disables FORCE; everything else (``"1"``, ``"true"``,
non-empty truthy) keeps the operator intent. ``--force`` on the CLI
always wins over env.

Decision rules
--------------
A workspace is **fresh** when ALL of the following hold:

1. ``audit_completion.json`` exists AND parses as v1.
2. ``now - completed_at <= max_age_seconds``.
3. ``workspace_state_hash`` recomputed now matches the recorded hash.
4. ``--force`` was NOT supplied AND ``FORCE`` env is not truthy.
5. For new markers, ``audit_toolchain_hash`` matches the current
   audit-tool fingerprint. This catches detector / harness changes
   without rerunning only because an unrelated docs or handoff commit
   moved HEAD.
6. For legacy markers without ``audit_toolchain_hash``, the recorded
   ``commit_sha`` matches the current HEAD (when both can be resolved).
   A mismatch = run. Unknown on either side = ignore this gate.

Any failure → ``run``. The skip path NEVER suppresses real work; an
unreadable / corrupt marker is treated as "no marker" (= run).

Files included in workspace_state_hash
--------------------------------------
- All in-scope source-shaped files under the workspace, recursive
  (sorted): ``*.sol``, ``*.rs``, ``*.go``, and ``*.circom``.
- ``scope.json`` and ``INTAKE_BASELINE.json`` at the workspace root if
  they exist.
- Hidden directories (``.audit_logs``, ``.git``) are excluded so
  recording the marker itself doesn't change the next hash.
- Common vendor / build dirs (``node_modules``, ``lib``, ``out``,
  ``cache``, ``broadcast``, ``forge-cache``) are excluded so dependency
  installs don't trigger false reruns. (Vendor change triggering a
  rerun is the wrong contract — the operator is auditing in-tree code.)

Stdlib only. No network. No subprocess except a single
``git rev-parse HEAD`` to read the repo's commit SHA (best effort).
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

SCHEMA = "auditooor.audit_completion.v1"
MARKER_REL = ".audit_logs/audit_completion.json"
GAP29_MARKER_REL = ".auditooor/last_audit_complete_marker"
DEFAULT_MAX_AGE_SECONDS = 30 * 60  # 30 min
CORE_AUDIT_SENTINEL_STAGE = "report"

# Directory names we walk INTO. Anything else is pruned.
# We use a deny-list (skip these) rather than an allow-list so we
# don't miss subprojects with unconventional layouts.
_PRUNE_DIRS = {
    ".git",
    ".audit_logs",
    ".audit_progress",
    ".swarm",
    "node_modules",
    "lib",  # foundry-style vendored libs (forge-std, etc.)
    "out",
    "cache",
    "broadcast",
    "forge-cache",
    "artifacts",  # hardhat
    "__pycache__",
}
_SOURCE_EXTENSIONS = (".sol", ".rs", ".go", ".circom")
# Filenames at the workspace root (only) we incorporate into the hash
# alongside .sol files. Source-of-truth artefacts that change auditor
# scope without modifying any .sol bytes — Kimi + Minimax pre-review
# flagged this set as the real edge case.
#
# scope.json — auditor scope ledger. INTAKE_BASELINE.json is deliberately
# excluded: strict preflight regenerates it immediately before this freshness
# guard, so treating its generated metadata as audited source self-invalidates
# every retry.
# foundry.toml / remappings.txt    — Foundry remappings, optimizer,
#                                    via-ir; change which contracts the
#                                    audit chain compiles against.
# hardhat.config.js / .ts / .cjs   — Hardhat sources / paths config.
# .gitmodules                      — submodule pin changes (vendored
#                                    libs may shift) — also surfaced as
#                                    workspace-state because the lib/
#                                    contents themselves are excluded.
# foundry.lock                     — pin shifts for git-deps.
_ROOT_TRACKED_FILES = (
    "scope.json",
    "foundry.toml",
    "foundry.lock",
    "remappings.txt",
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    ".gitmodules",
)

# Audit-tool files that affect `make audit` output. We hash file content
# rather than mtimes so a docs-only commit, branch checkout, or worktree
# refresh does not burn a full audit pass when the actual harness is
# unchanged. This intentionally excludes docs and tests.
_TOOLCHAIN_ROOT_FILES = (
    "Makefile",
)
_TOOLCHAIN_ROOTS = (
    "tools",
    "detectors",
    "scanners",
    "reference/patterns.dsl",
)
_TOOLCHAIN_PRUNE_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "out",
    "cache",
    "artifacts",
    "tests",
    "testdata",
}
_TOOLCHAIN_SKIP_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
)


# ---------------------------------------------------------------------------
# Workspace inventory + hashing
# ---------------------------------------------------------------------------
def _iter_source_files(ws: Path) -> Iterable[Path]:
    """Yield every tracked source file under ``ws`` outside the prune set.

    ``os.walk`` is preferred over ``Path.rglob`` because we need to
    mutate ``dirnames`` in-place to prune (rglob has no equivalent).
    """
    ws_str = str(ws)
    for dirpath, dirnames, filenames in os.walk(ws_str):
        # Prune in-place (also drops anything starting with '.').
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _PRUNE_DIRS and not d.startswith(".")
        )
        for fn in sorted(filenames):
            if fn.endswith(_SOURCE_EXTENSIONS):
                yield Path(dirpath) / fn


def _build_inventory(ws: Path) -> list[dict]:
    inv: list[dict] = []
    for p in _iter_source_files(ws):
        try:
            st = p.stat()
        except OSError:
            continue  # racy delete; skip silently
        rel = p.relative_to(ws).as_posix()
        try:
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            continue
        inv.append({"path": rel, "mtime": st.st_mtime, "size": st.st_size, "sha256": digest})
    # Root-level scope.json / INTAKE_BASELINE.json (per Kimi review).
    for fn in _ROOT_TRACKED_FILES:
        rp = ws / fn
        if rp.is_file():
            try:
                st = rp.stat()
            except OSError:
                continue
            try:
                digest = hashlib.sha256(rp.read_bytes()).hexdigest()
            except OSError:
                continue
            inv.append({"path": fn, "mtime": st.st_mtime, "size": st.st_size, "sha256": digest})
    inv.sort(key=lambda e: e["path"])
    return inv


def _hash_inventory(inv: list[dict]) -> str:
    h = hashlib.sha256()
    for e in inv:
        # Content is authoritative. The mtime fallback keeps legacy synthetic
        # inventories readable while new markers remain stable across checkout
        # and compiler timestamp churn.
        if e.get("sha256"):
            line = f"{e['path']}|{e['sha256']}|{e['size']}\n"
        else:
            line = f"{e['path']}|{e['mtime']:.6f}|{e['size']}\n"
        h.update(line.encode("utf-8"))
    return h.hexdigest()


def _workspace_state_hash(ws: Path) -> tuple[str, list[dict]]:
    inv = _build_inventory(ws)
    return _hash_inventory(inv), inv


# ---------------------------------------------------------------------------
# Audit toolchain fingerprint
# ---------------------------------------------------------------------------
def _iter_toolchain_files(repo: Path) -> Iterable[Path]:
    for rel in _TOOLCHAIN_ROOT_FILES:
        p = repo / rel
        if p.is_file():
            yield p

    for rel_root in _TOOLCHAIN_ROOTS:
        root = repo / rel_root
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(str(root)):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in _TOOLCHAIN_PRUNE_DIRS and not d.startswith(".")
            )
            for fn in sorted(filenames):
                if fn.endswith(_TOOLCHAIN_SKIP_SUFFIXES):
                    continue
                yield Path(dirpath) / fn


# ---------------------------------------------------------------------------
# P52: tamper-evident signature / hash chain over the marker.
#
# ADVISORY-FIRST, ADDITIVE-ONLY. The signature block is a NEW read-only key on
# the marker payload (``tamper_signature``); nothing existing reads or requires
# it. audit-done-guard.py verifies it ADVISORY (WARN unless
# AUDITOOOR_MARKER_TAMPER_STRICT is set). We REUSE _audit_toolchain_hash as the
# enforcer_hash and _hash_inventory over the covered-def set - no new hashing.
#
# The chain binds four inputs so a marker cannot be silently edited to fake a
# pass without either matching the enforcer + covered defs or forging the whole
# block:
#   * verdict       - the audit-complete verdict this marker asserts (may be
#                     "unknown" when the completion marker is written before the
#                     authoritative last_result exists; that is HONEST, not a
#                     tamper - the guard treats "unknown" as advisory-neutral).
#   * enforcer_hash - content sha256 of the audit toolchain (_audit_toolchain_hash).
#   * covered_defs  - sha256 over the def-file inventory the gate DID hash,
#                     INCLUDING the gate's own definition files (self-coverage).
#   * nonce         - a per-write random hex so two identical-input markers still
#                     differ (defends against block-copy replay across ws).
# ---------------------------------------------------------------------------
SIGNATURE_SCHEMA = "auditooor.marker_tamper_signature.v1"
# The gate's own definition files (relative to repo root). Self-coverage asserts
# the enforcer_hash / covered-def set actually included the tools that DECIDE the
# verdict - so "did the gate check its own definition?" is not vacuous.
_SELF_DEF_FILES = (
    "tools/audit-completion-marker.py",
    "tools/audit-done-guard.py",
)


def _chain_digest(verdict: str, enforcer_hash: str, covered_defs_hash: str,
                  nonce: str) -> str:
    """Deterministic sha256 over the four chain inputs. Order + separators are
    fixed so producer + verifier agree byte-for-byte. Tolerant of
    enforcer_hash='unknown' (no repo / no files) - it hashes the literal
    string, never crashes."""
    h = hashlib.sha256()
    for part in (verdict, enforcer_hash, covered_defs_hash, nonce):
        h.update(str(part if part is not None else "").encode("utf-8"))
        h.update(b"\x1f")  # unit separator; not valid inside any hex/verdict
    return h.hexdigest()


def _self_coverage_record(repo: Path, toolchain_inventory: list[dict]) -> dict:
    """Record whether the covered-def set (the toolchain inventory that fed
    enforcer_hash) actually included the gate's OWN definition files. A vacuous
    self-coverage (gate never hashed its own code) is surfaced so the verifier
    can flag it rather than silently trust it."""
    covered_paths = {str(e.get("path", "")) for e in (toolchain_inventory or [])}
    covered = {}
    for rel in _SELF_DEF_FILES:
        # toolchain inventory paths are repo-relative posix; match on suffix so
        # a differing repo root does not spuriously read as uncovered.
        hit = any(p == rel or p.endswith(rel) or rel.endswith(p) for p in covered_paths if p)
        covered[rel] = bool(hit)
    return {
        "def_files": list(_SELF_DEF_FILES),
        "covered": covered,
        "all_covered": all(covered.values()) if covered else False,
        "covered_def_count": len(covered_paths),
    }


def compute_marker_signature(
    *,
    verdict: str,
    repo_root: Path,
    toolchain_hash: str,
    toolchain_inventory: list[dict],
    workspace_state_hash: str,
    nonce: str | None = None,
) -> dict:
    """Build the additive tamper-signature block for a marker.

    REUSE: enforcer_hash = the passed ``toolchain_hash`` (from
    _audit_toolchain_hash); covered_defs_hash = _hash_inventory over the
    toolchain inventory PLUS the workspace-state hash (the two hashes the marker
    already commits to). No new hashing primitive is introduced.

    Deterministic given the same nonce; a fresh nonce is minted per write when
    not supplied so byte-identical inputs still yield distinct signatures."""
    if nonce is None:
        nonce = os.urandom(16).hex()
    # covered_defs_hash binds the toolchain inventory content digests (which
    # include the gate's own def files) AND the workspace inventory hash. The
    # toolchain inventory rows are {path,size,sha256} (see _audit_toolchain_hash),
    # so we hash their path+content-digest here rather than reusing
    # _hash_inventory (that helper expects the {path,mtime,size} SOURCE-inventory
    # shape). Folding workspace_state_hash in means the chain also moves if the
    # audited source changes (defence in depth; still no new hash primitive).
    _cd = hashlib.sha256()
    for e in (toolchain_inventory or []):
        _cd.update(str(e.get("path", "")).encode("utf-8"))
        _cd.update(b"\0")
        _cd.update(str(e.get("sha256", e.get("size", ""))).encode("utf-8"))
        _cd.update(b"\n")
    _cd.update(b"__ws_state__\0")
    _cd.update(str(workspace_state_hash or "").encode("utf-8"))
    covered_defs_hash = _cd.hexdigest()
    digest = _chain_digest(verdict, toolchain_hash, covered_defs_hash, nonce)
    return {
        "schema": SIGNATURE_SCHEMA,
        "verdict": str(verdict),
        "enforcer_hash": str(toolchain_hash),
        "covered_defs_hash": covered_defs_hash,
        "nonce": nonce,
        "chain_digest": digest,
        "self_coverage": _self_coverage_record(repo_root, toolchain_inventory),
    }


def verify_marker_signature(
    sig: dict,
    *,
    current_enforcer_hash: str | None = None,
) -> dict:
    """ADVISORY verify of a tamper-signature block. Returns a dict:

        {"ok": bool, "verdict": str, "reasons": [...], "recomputed_digest": str,
         "self_coverage_ok": bool}

    ``ok`` is True iff (a) the block is well-formed, (b) the chain digest
    recomputes over the recorded inputs (no silent field edit), and (c) if
    ``current_enforcer_hash`` is supplied and neither side is 'unknown', it
    matches the recorded enforcer_hash (an enforcer swap under a frozen verdict
    is a tamper signal).

    This never raises: a malformed / absent block returns ok=False with a
    reason, and the CALLER decides whether that is advisory (default) or
    blocking (only under the strict env). enforcer_hash='unknown' on either side
    is tolerated (no repo / no files) - it is NOT treated as a mismatch."""
    reasons: list[str] = []
    if not isinstance(sig, dict):
        return {"ok": False, "verdict": "", "reasons": ["no-signature-block"],
                "recomputed_digest": "", "self_coverage_ok": False}
    if sig.get("schema") != SIGNATURE_SCHEMA:
        reasons.append(f"unexpected-schema:{sig.get('schema')!r}")
    verdict = str(sig.get("verdict", ""))
    enforcer_hash = str(sig.get("enforcer_hash", ""))
    covered_defs_hash = str(sig.get("covered_defs_hash", ""))
    nonce = str(sig.get("nonce", ""))
    recorded_digest = str(sig.get("chain_digest", ""))
    recomputed = _chain_digest(verdict, enforcer_hash, covered_defs_hash, nonce)
    chain_ok = bool(recorded_digest) and recomputed == recorded_digest
    if not chain_ok:
        reasons.append("chain-digest-mismatch")
    enforcer_ok = True
    if current_enforcer_hash is not None:
        cur = str(current_enforcer_hash)
        if enforcer_hash not in ("unknown", "", None) and cur not in ("unknown", ""):
            if enforcer_hash != cur:
                enforcer_ok = False
                reasons.append("enforcer-hash-mismatch")
    sc = sig.get("self_coverage")
    self_coverage_ok = bool(isinstance(sc, dict) and sc.get("all_covered"))
    if not self_coverage_ok:
        reasons.append("self-coverage-incomplete")
    ok = chain_ok and enforcer_ok and sig.get("schema") == SIGNATURE_SCHEMA
    return {
        "ok": bool(ok),
        "verdict": verdict,
        "reasons": reasons,
        "recomputed_digest": recomputed,
        "self_coverage_ok": self_coverage_ok,
    }


def _audit_toolchain_hash(repo: Path) -> tuple[str, list[dict]]:
    try:
        repo = repo.expanduser().resolve()
    except OSError:
        return "unknown", []
    if not repo.is_dir():
        return "unknown", []

    h = hashlib.sha256()
    inv: list[dict] = []
    for p in sorted(_iter_toolchain_files(repo), key=lambda x: x.as_posix()):
        try:
            body = p.read_bytes()
            st = p.stat()
            rel = p.relative_to(repo).as_posix()
        except OSError:
            continue
        digest = hashlib.sha256(body).hexdigest()
        inv.append({"path": rel, "size": st.st_size, "sha256": digest})
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    if not inv:
        return "unknown", []
    return h.hexdigest(), inv


# ---------------------------------------------------------------------------
# Repo SHA helper
# ---------------------------------------------------------------------------
def _current_commit_sha(repo: Path) -> str:
    """Return short SHA at HEAD of ``repo``, or ``'unknown'`` on any failure."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    sha = proc.stdout.strip()
    return sha or "unknown"


# ---------------------------------------------------------------------------
# Marker IO
# ---------------------------------------------------------------------------
AUTHORITATIVE_MARKER_REL = ".auditooor/audit_complete_last_result.json"


def _read_authoritative_verdict(ws: Path) -> str:
    """Read the audit-complete verdict from the authoritative last_result marker
    (written by audit-completeness-check.py). Returns the verdict string, or
    'unknown' when the file is absent / unreadable / carries no verdict. This is
    ADVISORY linkage only: the completion marker may be written before the gate
    result exists, and 'unknown' is an HONEST state (never a tamper)."""
    p = ws / AUTHORITATIVE_MARKER_REL
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unknown"
    if isinstance(data, dict):
        v = data.get("verdict")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def marker_path(ws: Path) -> Path:
    return ws / MARKER_REL


def gap29_marker_path(ws: Path) -> Path:
    return ws / GAP29_MARKER_REL


@dataclasses.dataclass
class MarkerCheck:
    fresh: bool
    reason: str
    marker: dict | None
    age_seconds: float | None
    current_state_hash: str
    forced: bool
    current_toolchain_hash: str


def load_marker(ws: Path) -> dict | None:
    p = marker_path(ws)
    if not p.is_file():
        return None
    try:
        payload = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("schema") != SCHEMA:
        return None
    return payload


def write_marker(
    ws: Path,
    *,
    commit_sha: str | None = None,
    stages_completed: list[str] | None = None,
    repo_root: Path | None = None,
) -> Path:
    """Write a fresh completion marker. Always overwrites."""
    ws.mkdir(parents=True, exist_ok=True)
    log_dir = ws / ".audit_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    state_hash, inventory = _workspace_state_hash(ws)
    toolchain_hash, toolchain_inventory = _audit_toolchain_hash(
        repo_root or Path.cwd()
    )
    if commit_sha is None:
        commit_sha = _current_commit_sha(repo_root or Path.cwd())

    now = time.time()
    payload = {
        "schema": SCHEMA,
        "completed_at": now,
        "completed_at_iso": _dt.datetime.fromtimestamp(
            now, _dt.timezone.utc
        ).isoformat(),
        "commit_sha": commit_sha,
        "audit_toolchain_hash": toolchain_hash,
        "audit_toolchain_inventory": toolchain_inventory,
        "workspace_state_hash": state_hash,
        "workspace_state_inventory": inventory,
        "stages_completed": list(stages_completed or []),
    }
    # P52 (additive, read-only): tamper-signature block over
    # (verdict + enforcer_hash + covered_defs + nonce) + a self-coverage record.
    # The verdict is read ADVISORY from the authoritative last_result marker if
    # it exists; otherwise "unknown" (HONEST - this marker may be written before
    # the gate result). No existing reader depends on this key.
    try:
        _verdict = _read_authoritative_verdict(ws)
        payload["tamper_signature"] = compute_marker_signature(
            verdict=_verdict,
            repo_root=(repo_root or Path.cwd()),
            toolchain_hash=toolchain_hash,
            toolchain_inventory=toolchain_inventory,
            workspace_state_hash=state_hash,
        )
    except Exception:
        # Signature is advisory metadata; never let it block a marker write.
        pass
    out = marker_path(ws)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp.replace(out)
    write_gap29_marker(ws, completed_at_iso=payload["completed_at_iso"])
    return out


def write_gap29_marker(ws: Path, *, completed_at_iso: str | None = None) -> Path:
    """Write the legacy marker consumed by hunt-phase-ordering-check.py."""
    if completed_at_iso is None:
        completed_at_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
    out = gap29_marker_path(ws)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(
        "audit-complete-marker-written-by-audit-completion-marker "
        f"{completed_at_iso}\n",
        encoding="utf-8",
    )
    tmp.replace(out)
    return out


@dataclasses.dataclass(frozen=True)
class CoreAuditCompletion:
    complete: bool
    reason: str
    stages_completed: list[str]


# r36-rebuttal: build lane (CAP-GAP-88 implementation)
CORE_COMPLETE_FALLBACK_SIGNALS = (
    "engage_report.json",
    "engage_report.md",
)


def core_complete_from_artifacts(ws: Path) -> CoreAuditCompletion:
    """CAP-GAP-88 (2026-05-27): degrade-permissive when CSV missing.

    When audit-progress.py did not write the CSV (e.g. fresh-workspace race,
    log dir not created), fall back to artifact-presence inspection. The
    canonical core-complete signal is ``engage_report.json`` +
    ``engage_report.md`` (both written by the report stage). If both exist
    AND are non-empty, treat as core-complete and degrade to permissive
    marker write.
    """
    present: list[str] = []
    missing: list[str] = []
    for name in CORE_COMPLETE_FALLBACK_SIGNALS:
        path = ws / name
        if path.is_file() and path.stat().st_size > 0:
            present.append(name)
        else:
            missing.append(name)
    if missing:
        return CoreAuditCompletion(
            False,
            f"artifact-fallback-missing: {','.join(missing)}",
            present,
        )
    return CoreAuditCompletion(
        True,
        f"artifact-fallback-ok: {','.join(present)}",
        present,
    )


def core_audit_completed_from_csv(csv_path: Path) -> CoreAuditCompletion:
    """Return whether audit-progress CSV proves the core audit completed.

    When the CSV is missing or empty, callers should fall back to
    ``core_complete_from_artifacts`` (CAP-GAP-88 degrade-permissive path).
    This function intentionally only reports CSV-derived state so the
    caller can compose the fallback policy.
    """
    try:
        with csv_path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        return CoreAuditCompletion(False, "csv-missing", [])
    except OSError as exc:
        return CoreAuditCompletion(False, f"csv-read-error: {exc}", [])
    if not rows:
        return CoreAuditCompletion(False, "csv-empty", [])

    stages_completed: list[str] = []
    saw_sentinel = False
    for row in rows:
        stage = (row.get("stage") or "").strip()
        status = (row.get("status") or "").strip()
        if not stage:
            continue
        stages_completed.append(stage)
        if status == "failed":
            return CoreAuditCompletion(
                False,
                f"core-stage-failed-before-{CORE_AUDIT_SENTINEL_STAGE}: {stage}",
                stages_completed,
            )
        if stage == CORE_AUDIT_SENTINEL_STAGE:
            saw_sentinel = True
            if status != "ok":
                return CoreAuditCompletion(
                    False,
                    f"{CORE_AUDIT_SENTINEL_STAGE}-not-ok: {status or 'missing'}",
                    stages_completed,
                )
            return CoreAuditCompletion(
                True,
                f"{CORE_AUDIT_SENTINEL_STAGE}-ok",
                stages_completed,
            )

    if not saw_sentinel:
        return CoreAuditCompletion(
            False,
            f"{CORE_AUDIT_SENTINEL_STAGE}-not-seen",
            stages_completed,
        )
    return CoreAuditCompletion(False, "unreachable", stages_completed)


def _force_env_active(env: dict[str, str]) -> bool:
    """``FORCE=1`` (or any non-zero non-empty truthy form) → True.

    The literal ``"0"`` and unset / empty string disable. We deliberately
    keep this narrow so a stray ``FORCE=`` (empty) does not bypass the
    skip.
    """
    raw = env.get("FORCE")
    if raw is None:
        return False
    raw = raw.strip()
    if raw in ("", "0", "false", "no"):
        return False
    return True


def check_marker(
    ws: Path,
    *,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    force: bool = False,
    env: dict[str, str] | None = None,
    repo_root: Path | None = None,
    now: float | None = None,
) -> MarkerCheck:
    """Decide whether the workspace can short-circuit.

    Order of checks matters: we evaluate ``force`` first (it always
    wins), then marker existence, then schema, then age, then workspace
    state hash, then toolchain hash. Legacy markers without a toolchain
    hash fall back to commit SHA. The first failed gate wins the
    ``reason``.
    """
    if env is None:
        env = dict(os.environ)
    if now is None:
        now = time.time()

    forced = bool(force or _force_env_active(env))
    state_hash, _inv = _workspace_state_hash(ws)
    toolchain_hash = "not-checked"

    if forced:
        return MarkerCheck(
            fresh=False,
            reason="force-override",
            marker=None,
            age_seconds=None,
            current_state_hash=state_hash,
            forced=True,
            current_toolchain_hash=toolchain_hash,
        )

    payload = load_marker(ws)
    if payload is None:
        return MarkerCheck(
            fresh=False,
            reason="no-marker",
            marker=None,
            age_seconds=None,
            current_state_hash=state_hash,
            forced=False,
            current_toolchain_hash=toolchain_hash,
        )

    completed_at = payload.get("completed_at")
    if not isinstance(completed_at, (int, float)):
        return MarkerCheck(
            fresh=False,
            reason="marker-malformed",
            marker=payload,
            age_seconds=None,
            current_state_hash=state_hash,
            forced=False,
            current_toolchain_hash=toolchain_hash,
        )
    age = float(now) - float(completed_at)
    if age < 0:
        # Clock skew or post-epoch tampering. Treat as stale.
        return MarkerCheck(
            fresh=False,
            reason="marker-future-timestamp",
            marker=payload,
            age_seconds=age,
            current_state_hash=state_hash,
            forced=False,
            current_toolchain_hash=toolchain_hash,
        )
    if max_age_seconds >= 0 and age > max_age_seconds:
        return MarkerCheck(
            fresh=False,
            reason=f"marker-stale ({age:.0f}s > {max_age_seconds:.0f}s)",
            marker=payload,
            age_seconds=age,
            current_state_hash=state_hash,
            forced=False,
            current_toolchain_hash=toolchain_hash,
        )

    recorded_hash = payload.get("workspace_state_hash")
    if recorded_hash != state_hash:
        return MarkerCheck(
            fresh=False,
            reason="workspace-dirty",
            marker=payload,
            age_seconds=age,
            current_state_hash=state_hash,
            forced=False,
            current_toolchain_hash=toolchain_hash,
        )

    # Toolchain gate. New markers compare the content fingerprint of the
    # audit harness, detectors, scanners, and DSL patterns. Raw HEAD can
    # move for docs / handoff work without changing audit behavior.
    toolchain_hash, _toolchain_inv = _audit_toolchain_hash(
        repo_root or Path.cwd()
    )
    recorded_toolchain_hash = payload.get("audit_toolchain_hash")
    if (
        recorded_toolchain_hash not in ("unknown", "", None)
        and toolchain_hash not in ("unknown", "", None)
    ):
        if recorded_toolchain_hash != toolchain_hash:
            return MarkerCheck(
                fresh=False,
                reason="toolchain-changed",
                marker=payload,
                age_seconds=age,
                current_state_hash=state_hash,
                forced=False,
                current_toolchain_hash=toolchain_hash,
            )
    else:
        # Legacy commit SHA gate — only reject when both sides are known
        # and disagree. This keeps old v1 markers conservative until the
        # next successful audit writes a toolchain hash.
        recorded_sha = payload.get("commit_sha", "unknown")
        current_sha = _current_commit_sha(repo_root or Path.cwd())
        if (
            recorded_sha not in ("unknown", "", None)
            and current_sha not in ("unknown", "", None)
            and recorded_sha != current_sha
        ):
            return MarkerCheck(
                fresh=False,
                reason=f"commit-changed ({recorded_sha} -> {current_sha})",
                marker=payload,
                age_seconds=age,
                current_state_hash=state_hash,
                forced=False,
                current_toolchain_hash=toolchain_hash,
            )

    # `commit_sha` is still recorded for operator forensics, but new
    # markers no longer use it as the primary invalidation gate.
    # When no usable toolchain hash is available, the legacy branch
    # above already applied the commit check.
    return MarkerCheck(
        fresh=True,
        reason="fresh",
        marker=payload,
        age_seconds=age,
        current_state_hash=state_hash,
        forced=False,
        current_toolchain_hash=toolchain_hash,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _emit(check: MarkerCheck, *, want_json: bool, ws: Path) -> None:
    if want_json:
        out = {
            "schema": "auditooor.audit_completion_check.v1",
            "workspace": str(ws),
            "fresh": check.fresh,
            "reason": check.reason,
            "age_seconds": check.age_seconds,
            "current_state_hash": check.current_state_hash,
            "current_toolchain_hash": check.current_toolchain_hash,
            "forced": check.forced,
            "marker_path": str(marker_path(ws)),
        }
        print(json.dumps(out, indent=2, sort_keys=True))
        return

    if check.fresh:
        print(
            f"[audit-completion-marker] skip-fresh — last completed "
            f"{check.age_seconds:.0f}s ago "
            f"(marker={marker_path(ws)})"
        )
        print(
            "[audit-completion-marker] skipping fresh audit; "
            "rerun with `FORCE=1`"
        )
    else:
        print(
            f"[audit-completion-marker] run — {check.reason} "
            f"(marker={marker_path(ws)})"
        )


def cmd_check(args: argparse.Namespace) -> int:
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(
            f"[audit-completion-marker] ERR workspace not found / not a dir: {ws}",
            file=sys.stderr,
        )
        return 2
    max_age = args.max_age_seconds
    if max_age is None:
        env_raw = os.environ.get("AUDIT_FRESHNESS_SECONDS")
        if env_raw:
            try:
                max_age = float(env_raw)
            except ValueError:
                print(
                    f"[audit-completion-marker] WARN ignoring invalid "
                    f"AUDIT_FRESHNESS_SECONDS={env_raw!r}",
                    file=sys.stderr,
                )
                max_age = DEFAULT_MAX_AGE_SECONDS
        else:
            max_age = DEFAULT_MAX_AGE_SECONDS

    check = check_marker(
        ws,
        max_age_seconds=max_age,
        force=args.force,
        repo_root=args.repo_root,
    )
    _emit(check, want_json=args.json, ws=ws)
    # exit 0 = fresh / can skip; exit 1 = run.
    return 0 if check.fresh else 1


def cmd_write(args: argparse.Namespace) -> int:
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(
            f"[audit-completion-marker] ERR workspace not found / not a dir: {ws}",
            file=sys.stderr,
        )
        return 2
    stages = list(args.stages or [])
    out = write_marker(
        ws,
        commit_sha=args.commit_sha,
        stages_completed=stages,
        repo_root=args.repo_root,
    )
    if args.json:
        print(json.dumps({
            "schema": "auditooor.audit_completion_write.v1",
            "workspace": str(ws),
            "marker_path": str(out),
        }, indent=2, sort_keys=True))
    else:
        print(f"[audit-completion-marker] wrote {out}")
    return 0


def cmd_write_if_core_complete(args: argparse.Namespace) -> int:
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(
            f"[audit-completion-marker] ERR workspace not found / not a dir: {ws}",
            file=sys.stderr,
        )
        return 2
    # r36-rebuttal: build lane (CAP-GAP-88 implementation)
    csv_path = args.progress_csv.expanduser().resolve()
    verdict = core_audit_completed_from_csv(csv_path)
    fallback_used = False
    # CAP-GAP-88 (2026-05-27): when audit-progress CSV is missing/empty/
    # unreadable, fall back to artifact-presence inspection. This unblocks
    # fresh-workspace audits where audit-progress.py did not write the CSV
    # but the report stage succeeded (engage_report.{json,md} both present).
    # Operator can disable via --no-artifact-fallback for strict CSV-only
    # behavior.
    allow_fallback = not getattr(args, "no_artifact_fallback", False)
    csv_missing_or_empty = verdict.reason in (
        "csv-missing",
        "csv-empty",
    ) or verdict.reason.startswith("csv-read-error:")
    if not verdict.complete and allow_fallback and csv_missing_or_empty:
        fallback = core_complete_from_artifacts(ws)
        if fallback.complete:
            verdict = CoreAuditCompletion(
                True,
                f"degrade-permissive: csv-missing + {fallback.reason}",
                fallback.stages_completed,
            )
            fallback_used = True
    if not verdict.complete:
        if args.json:
            print(json.dumps({
                "schema": "auditooor.audit_completion_core_write.v1",
                "workspace": str(ws),
                "progress_csv": str(csv_path),
                "written": False,
                "reason": verdict.reason,
                "stages_completed": verdict.stages_completed,
                "fallback_used": fallback_used,
            }, indent=2, sort_keys=True))
        else:
            print(
                "[audit-completion-marker] core-incomplete - "
                f"{verdict.reason} (csv={csv_path})"
            )
        return 1

    out = write_marker(
        ws,
        commit_sha=args.commit_sha,
        stages_completed=verdict.stages_completed,
        repo_root=args.repo_root,
    )
    # r36-rebuttal: build lane (CAP-GAP-88 implementation)
    if args.json:
        print(json.dumps({
            "schema": "auditooor.audit_completion_core_write.v1",
            "workspace": str(ws),
            "progress_csv": str(csv_path),
            "written": True,
            "reason": verdict.reason,
            "marker_path": str(out),
            "gap29_marker_path": str(gap29_marker_path(ws)),
            "stages_completed": verdict.stages_completed,
            "fallback_used": fallback_used,
        }, indent=2, sort_keys=True))
    else:
        fb = " (degrade-permissive artifact-fallback)" if fallback_used else ""
        print(
            "[audit-completion-marker] wrote core-complete marker "
            f"{out} (gap29={gap29_marker_path(ws)}){fb}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Track `make audit` completion so back-to-back reruns can "
            "short-circuit. Stdlib-only; no network."
        ),
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser(
        "check",
        help="Check freshness; exit 0 if can skip, 1 if should run.",
    )
    check.add_argument("--workspace", type=Path, required=True)
    check.add_argument(
        "--max-age-seconds",
        type=float,
        default=None,
        help=(
            "Freshness window in seconds. "
            f"Default {DEFAULT_MAX_AGE_SECONDS} (30 min); "
            "env override AUDIT_FRESHNESS_SECONDS; -1 disables age expiry."
        ),
    )
    check.add_argument(
        "--force",
        action="store_true",
        help="Always treat marker as stale (run). Wins over FORCE env.",
    )
    check.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    check.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override the repo path used for commit-sha resolution.",
    )
    check.set_defaults(func=cmd_check)

    write = sub.add_parser(
        "write",
        help="Write a fresh completion marker (called after engage.py exits 0).",
    )
    write.add_argument("--workspace", type=Path, required=True)
    write.add_argument(
        "--commit-sha",
        default=None,
        help="Override commit SHA (default: git rev-parse --short HEAD).",
    )
    write.add_argument(
        "--stages",
        nargs="*",
        default=None,
        help="List of stages reported as completed (advisory).",
    )
    write.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    write.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override the repo path used for commit-sha resolution.",
    )
    write.set_defaults(func=cmd_write)

    core = sub.add_parser(
        "write-if-core-complete",
        help=(
            "Write marker when audit-progress CSV shows core audit reached "
            "the report stage, even if later advisory stages failed."
        ),
    )
    core.add_argument("--workspace", type=Path, required=True)
    core.add_argument("--progress-csv", type=Path, required=True)
    core.add_argument(
        "--commit-sha",
        default=None,
        help="Override commit SHA (default: git rev-parse --short HEAD).",
    )
    core.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    core.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override the repo path used for commit-sha resolution.",
    )
    # r36-rebuttal: build lane (CAP-GAP-88 implementation)
    core.add_argument(
        "--no-artifact-fallback",
        action="store_true",
        help=(
            "Disable CAP-GAP-88 degrade-permissive artifact fallback. "
            "When set, missing/empty progress CSV always returns rc=1 "
            "(strict CSV-only behavior)."
        ),
    )
    core.set_defaults(func=cmd_write_if_core_complete)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
