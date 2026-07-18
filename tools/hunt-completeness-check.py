#!/usr/bin/env python3
"""hunt-completeness-check.py - L35 gate: a HUNT is the full end-to-end pipeline.

Background
----------
A target ("NEAR", "Hyperbridge") was reported HUNTED / EXHAUSTED after a
shallow glance - 19 of 1337 in-scope files read, a shallow `git clone`
(so Tier-6 bidirectional commit-mining could never run), no `make
audit-deep`, no capability coverage matrix, and no agent-artifact mining
into the corpus. A hunt that shallow must NEVER again pass as a completed
hunt.

This tool is the mechanical enforcement half of L35 (hunt-completeness-
required). It is deterministic, stdlib-only, offline-safe, and never
re-runs any stage - it reads the artifacts a real end-to-end hunt leaves
behind and refuses to certify a workspace as hunted unless ALL FIVE
completeness signals are present.

The five completeness signals (a)-(e)
-------------------------------------
(a) full-clone           the source tree is a FULL git clone
                         (``git rev-list --count HEAD`` > 1, i.e. not a
                         ``--depth 1`` shallow clone) so Tier-6
                         bidirectional commit-mining COULD run, AND a
                         ``mining_rounds/`` artifact exists proving it
                         actually ran.
(b) audit-deep           ``make audit-deep`` ran - a deep manifest /
                         audit-deep output exists
                         (``.audit_logs/audit_deep_*_manifest.json`` or
                         ``.audit_logs/audit_deep*`` output).
(c) coverage-matrix      a ``<WS>/*CAPABILITY_COVERAGE_MATRIX.md`` exists
                         with ZERO DARK rows across every in-scope cluster
                         AND all program reward categories.
(d) cluster-coverage     every in-scope cluster enumerated from SCOPE.md
                         has >=1 hunt sidecar, skip-set slug, or COVERED
                         coverage-matrix row.
(e) artifact-mining      agent artifacts were mined into the corpus -
                         ``hunt_findings_sidecars/`` is non-empty AND a
                         sidecar-ETL / learn step ran (a learn report or a
                         corpus-delta artifact exists).

Verdict vocabulary
------------------
- ``pass-hunt-complete``                    all signals present.
- ``fail-no-dedup-skip-set``                signal (f) violated.
- ``fail-hunt-provider-obligation-unmet``   per-function hunt was queued but
                                            never dispatched
                                            (hunt_provider_obligation.json
                                            status != "completed").
- ``fail-shallow-clone``                    signal (a) violated.
- ``fail-no-audit-deep``                    signal (b) violated.
- ``fail-no-coverage-matrix``               signal (c): matrix missing.
- ``fail-dark-families``                    signal (c): matrix present but
                                            has DARK rows.
- ``fail-missing-cluster-coverage``         signal (d) violated.
- ``fail-no-artifact-mining``               signal (e) violated.
- ``error``                                 unreadable workspace / internal
                                            error.

The check evaluates all signals and reports every failing one in
``failures``; the top-level ``verdict`` is the FIRST failing signal in the
defined order so the operator gets a stable single-line summary.
<!-- r36-rebuttal: funnel-generic-fixes-wave3 -->

Exit code
---------
- 0 on ``pass-hunt-complete``.
- 1 on any ``fail-*`` verdict.
- 2 on ``error`` (bad arguments / missing workspace).

Override
--------
Visible bounded line ``l35-rebuttal: <reason>`` (<=200 chars) OR HTML-comment
form ``<!-- l35-rebuttal: <reason> -->`` placed in
``<WS>/.auditooor/hunt_completeness_rebuttal.txt``. A non-empty, in-bounds
reason flips a single named signal (``<signal>: <reason>``) or all signals
(``all: <reason>`` or a bare reason) to ``ok-rebuttal``. Empty or oversized
reasons are ignored; the original fail stands. The rebuttal is reserved for
genuinely unmineable targets (e.g. a target shipped only as a release
tarball with no upstream git history).

CLI
---
    python3 tools/hunt-completeness-check.py <workspace> [--json] [--strict]

Usage
-----
    make hunt-complete WS=~/audits/<project>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "auditooor.l35_hunt_completeness.v1"
GATE = "L35-HUNT-COMPLETENESS"

_MATRIX_BUILDER_MOD = None


def _load_matrix_builder():
    """Lazily import capability-coverage-matrix-build.py (hyphenated filename) so
    the cluster parser is shared with the coverage-matrix builder - one source of
    truth, no drift. Cached after first load."""
    global _MATRIX_BUILDER_MOD
    if _MATRIX_BUILDER_MOD is not None:
        return _MATRIX_BUILDER_MOD
    import importlib.util
    path = Path(__file__).resolve().parent / "capability-coverage-matrix-build.py"
    spec = importlib.util.spec_from_file_location("capability_coverage_matrix_build", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _MATRIX_BUILDER_MOD = mod
    return mod

# Ordered signal -> failing verdict map. Order is load-bearing: the
# top-level verdict is the FIRST failing signal in this order.
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
# Signal (f) dedup-first is ordered FIRST: a hunt that never loaded the
# skip-set has not run the mandatory step 0 and is structurally incapable
# of avoiding repeated work, so it is the first thing the gate reports.
#
# PHASE-BAND structure (mirrors tools/audit-completeness-check.py): these 8 hunt
# signals already fall into just two of the 5 headline bands and are ALREADY in
# non-decreasing band order, so no reorder is needed here - but the same
# phase-band + bijection conformance guard (below) pins that invariant so a
# future signal insertion cannot silently drift the headline out of phase order.
#   A engine-reality: dedup/provider-obligation prereqs + full-clone intake + audit-deep engine
#   E per-unit/meta:  coverage-matrix / cluster-coverage / artifact-mining meta axes
_SIGNAL_ORDER = (
    # --- BAND A: engine-reality (prereqs + intake + engine) ---
    ("dedup-first", "fail-no-dedup-skip-set"),
    # r36-rebuttal: funnel-generic-fixes-wave3
    # hunt-provider-obligation is checked second: a hunt whose per-function
    # dispatch was queued but never sent (status=orchestrator-dispatch-required)
    # has not run at all - all downstream signals would be false-greens.
    ("hunt-provider-obligation", "fail-hunt-provider-obligation-unmet"),
    ("full-clone", "fail-shallow-clone"),
    ("audit-deep", "fail-no-audit-deep"),
    # --- BAND E: per-unit / meta coverage ---
    ("coverage-matrix-present", "fail-no-coverage-matrix"),
    ("coverage-matrix-no-dark", "fail-dark-families"),
    ("cluster-coverage", "fail-missing-cluster-coverage"),
    ("artifact-mining", "fail-no-artifact-mining"),
)

# PHASE-BAND conformance (mirror of the audit-completeness upgrade): pin every
# signal to a band and assert _SIGNAL_ORDER is non-decreasing in band rank AND a
# bijection with the band map, so the headline verdict (verdict = failures[0])
# stays the earliest-phase failure and neither order-drift nor registry-drift can
# slip in unnoticed at import time.
_PHASE_BAND_ORDER = ("A", "B", "C", "D", "E")
_SIGNAL_PHASE_BAND = {
    "dedup-first": "A",
    "hunt-provider-obligation": "A",
    "full-clone": "A",
    "audit-deep": "A",
    "coverage-matrix-present": "E",
    "coverage-matrix-no-dark": "E",
    "cluster-coverage": "E",
    "artifact-mining": "E",
}


def _assert_phase_band_conformance():
    """Fail LOUD at import on phase-band drift: every _SIGNAL_ORDER signal carries
    a band (bijection, no orphan band entry) and _SIGNAL_ORDER is non-decreasing in
    band rank. Mirrors tools/audit-completeness-check.py's guard."""
    ordered = [s for s, _ in _SIGNAL_ORDER]
    banded = set(_SIGNAL_PHASE_BAND)
    missing = set(ordered) - banded
    orphan = banded - set(ordered)
    if missing or orphan:
        raise AssertionError(
            "phase-band registry drift: _SIGNAL_ORDER signals missing a band "
            f"{sorted(missing)} / band entries with no signal {sorted(orphan)}")
    rank = {b: i for i, b in enumerate(_PHASE_BAND_ORDER)}
    prev_rank, prev_sig = -1, None
    for s in ordered:
        r = rank[_SIGNAL_PHASE_BAND[s]]
        if r < prev_rank:
            raise AssertionError(
                f"_SIGNAL_ORDER is not phase-band sorted: {s!r} (band "
                f"{_SIGNAL_PHASE_BAND[s]}) follows {prev_sig!r} of a later band")
        prev_rank, prev_sig = r, s


_assert_phase_band_conformance()

_REBUTTAL_MAX = 200
_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?l35-rebuttal:\s*(?P<reason>.+?)(?:\s*-->)?\s*$",
    re.IGNORECASE,
)

# A DARK row in a coverage matrix is one whose status cell is the literal
# token DARK (case-insensitive) or one of the common variants below.
_DARK_TOKENS = ("dark", "uncovered", "not-covered", "not covered", "no-coverage", "no coverage", "gap")

_IN_SCOPE_SECTION_RE = re.compile(
    r"^(?:scope|in[- ]scope\b.*|assets? classes?|assets? in[- ]scope\b.*|"
    r"smart contracts? in[- ]scope\b.*|github targets?)$",
    re.IGNORECASE,
)
_OOS_SECTION_RE = re.compile(
    r"\b(?:out[- ]of[- ]scope|oos|assumptions?|target|protocol summary)\b",
    re.IGNORECASE,
)
_TITLE_SCOPE_RE = re.compile(r"\bscope\b", re.IGNORECASE)


def _is_cluster_section(heading: str) -> bool:
    norm = re.sub(r"\s+", " ", heading.strip().lower())
    if not norm or _OOS_SECTION_RE.search(norm):
        return False
    return bool(_IN_SCOPE_SECTION_RE.match(norm))


def _is_title_scope_heading(heading: str, level: int) -> bool:
    return level == 1 and bool(_TITLE_SCOPE_RE.search(heading))


def _clean_cluster_name(value: str) -> str:
    name = re.split(r"\s+[-:(]", value.strip())[0].strip()
    return name.replace("`", "").strip()


# A hunt CLUSTER must be a CODE cluster (a repo / package / contract) that can
# carry a hunt sidecar. SCOPE.md legitimately lists two OTHER kinds of bullet in
# the in-scope section that are NOT code clusters and can never have a hunt
# sidecar, and must not false-red the cluster-coverage gate:
#   1. scope-directive prose - e.g. "Scope mode: Primacy of Impact for Smart
#      Contract ...", "Primacy model: ..." (a policy line, not an asset).
#   2. Web/App assets - bare domains like `app.nuva.finance` / `nuva.finance`
#      (in-scope for the Web/App audit surface, not the smart-contract hunt).
_SCOPE_DIRECTIVE_PREFIX_RE = re.compile(
    # SCOPE.md metadata bullets (Immunefi format) that are NOT code clusters. Each
    # must be followed by a separator (space/colon/equals) so a bare single-word
    # cluster literally named e.g. "scope" or "types" is NOT stripped.
    r"^(scope mode|primacy model|primacy|scope|pin|deployed|org|docs?|codebase|"
    r"added on|reward|funds?|bounty)\b\s*[:=]|^(scope mode|primacy model|primacy|pin)\b\s",
    re.IGNORECASE)
# a bare hostname: no whitespace, no path separator, >=1 dot, alpha TLD. Code
# clusters are `owner/repo` (has '/') or address-labels ("ethereum eth_...",
# which carry spaces / no dot), so this only strips true web domains.
_WEB_DOMAIN_RE = re.compile(r"^(https?://)?[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


def _is_non_code_cluster(name: str) -> bool:
    n = name.strip()
    if not n:
        return True
    if _SCOPE_DIRECTIVE_PREFIX_RE.match(n):
        return True
    if "/" not in n and " " not in n and "." in n and _WEB_DOMAIN_RE.match(n):
        return True
    return False


@dataclass
class SignalResult:
    signal: str
    ok: bool
    reason: str
    artifacts: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _read_json(p: Path):
    txt = _read_text(p)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except (ValueError, json.JSONDecodeError):
        return None


def _nonempty_dir(p: Path, suffixes: tuple[str, ...] = ()) -> bool:
    """True iff ``p`` is a dir with >=1 non-dotfile entry (optionally with a
    matching suffix). Recurses for suffix matching so
    ``mining_rounds/<date>/manifest.json`` counts."""
    if not _exists(p) or not p.is_dir():
        return False
    try:
        for c in p.iterdir():
            if c.name.startswith("."):
                continue
            if not suffixes:
                return True
            if c.is_file() and c.name.endswith(suffixes):
                return True
            if c.is_dir():
                for g in c.rglob("*"):
                    if g.is_file() and not g.name.startswith(".") and g.name.endswith(suffixes):
                        return True
        return False
    except OSError:
        return False


# --------------------------------------------------------------------------
# Rebuttal parsing
# --------------------------------------------------------------------------
def _load_rebuttal(ws: Path) -> dict[str, str]:
    """Return {signal_name_or_'*': reason}. ``all:<reason>`` flips every
    signal; ``<signal>:<reason>`` flips one named signal; a bare
    ``<reason>`` flips every signal (treated as ``all:``)."""
    out: dict[str, str] = {}
    rb_path = ws / ".auditooor" / "hunt_completeness_rebuttal.txt"
    txt = _read_text(rb_path)
    if not txt:
        return out
    known = {s for s, _ in _SIGNAL_ORDER} | {"all"}
    for line in txt.splitlines():
        m = _REBUTTAL_RE.search(line.strip())
        if not m:
            continue
        reason = m.group("reason").strip()
        if not reason or len(reason) > _REBUTTAL_MAX:
            continue
        key = "*"
        body = reason
        if ":" in reason:
            head, _, tail = reason.partition(":")
            head = head.strip().lower()
            if head in known and tail.strip():
                key = "*" if head == "all" else head
                body = tail.strip()
        out[key] = body
    return out


def _rebuttal_for(rebuttals: dict[str, str], signal: str) -> str | None:
    if signal in rebuttals:
        return rebuttals[signal]
    if "*" in rebuttals:
        return rebuttals["*"]
    return None


# --------------------------------------------------------------------------
# Signal (f): dedup-first skip-set materialized (L36 step 0)
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
# --------------------------------------------------------------------------
def check_dedup_first(ws: Path) -> SignalResult:
    """A real hunt runs the mandatory dedup-load step FIRST, leaving a
    <WS>/.auditooor/hunt_skip_set.json with the L36 schema. Its presence is
    the proof that prior-work consolidation happened so the hunt could skip
    already-filed / killed / dead-ended candidates. An empty skip-set
    (fresh engagement) is acceptable; a MISSING skip-set is not."""
    skip_path = ws / ".auditooor" / "hunt_skip_set.json"
    if not _exists(skip_path) or not skip_path.is_file():
        return SignalResult(
            signal="dedup-first", ok=False,
            reason=(
                "no <WS>/.auditooor/hunt_skip_set.json; the mandatory dedup-load "
                "step 0 (hunt-dedup-load.py) did not run - the hunt cannot have "
                "avoided repeated work"
            ),
            artifacts=[], detail={"skip_set_path": str(skip_path)},
        )
    data = _read_json(skip_path)
    if not isinstance(data, dict) or data.get("schema") != "auditooor.l36_hunt_skip_set.v1":
        return SignalResult(
            signal="dedup-first", ok=False,
            reason=f"{skip_path} is present but not a valid L36 skip-set (wrong/missing schema)",
            artifacts=[str(skip_path)], detail={"skip_set_path": str(skip_path)},
        )
    counts = data.get("source_counts", {}) if isinstance(data.get("source_counts"), dict) else {}
    total = counts.get("total_after_dedup", 0)
    return SignalResult(
        signal="dedup-first", ok=True,
        reason=f"hunt_skip_set.json present with {total} consolidated prior-work entries",
        artifacts=[str(skip_path)], detail={"skip_set_path": str(skip_path), "entries": total},
    )


# --------------------------------------------------------------------------
# Signal (hunt-provider-obligation): per-function hunt actually dispatched
# r36-rebuttal: funnel-generic-fixes-wave3
# --------------------------------------------------------------------------
def check_hunt_provider_obligation(ws: Path) -> SignalResult:
    """Read <WS>/.auditooor/hunt_provider_obligation.json and fail when the
    per-function hunt was QUEUED but never actually dispatched.

    The file is optional: workspaces that ran the hunt via the default inline
    subprocess path never write it, so ABSENT = no constraint. PRESENT but
    status != "completed" means the orchestrator wrote the file to signal that
    dispatching is still required - the hunt never ran and every downstream
    signal would be a false-green.

    Statuses that mean "not done":
      - "orchestrator-dispatch-required"  (canonical; dispatch not yet sent)
      - any status that is not "completed" and not absent

    Fail-closed under STRICT (and always fail-closed for non-completed status,
    since there is no legitimate "partially dispatched" state).
    """
    obl_path = ws / ".auditooor" / "hunt_provider_obligation.json"
    if not _exists(obl_path) or not obl_path.is_file():
        # Absent = not applicable; the hunt used the inline dispatch path.
        return SignalResult(
            signal="hunt-provider-obligation", ok=True,
            reason="hunt_provider_obligation.json absent - inline dispatch path assumed",
            artifacts=[], detail={"path": str(obl_path), "present": False},
        )
    data = _read_json(obl_path)
    if not isinstance(data, dict):
        return SignalResult(
            signal="hunt-provider-obligation", ok=False,
            reason=(
                f"{obl_path.name} is present but not a valid JSON object; "
                "cannot verify dispatch status"
            ),
            artifacts=[str(obl_path)], detail={"path": str(obl_path), "parse_error": True},
        )
    status = data.get("status", "")
    if status == "completed":
        return SignalResult(
            signal="hunt-provider-obligation", ok=True,
            reason=f"hunt_provider_obligation.json status=completed",
            artifacts=[str(obl_path)], detail={"path": str(obl_path), "status": status},
        )
    # Residual-scoping (FIX C.2): when the hunt-coverage gate reports an EMPTY
    # residual (all surface units covered), hunt-scoped records
    # status="residual-empty-no-hunt-required" with residual_surface_units==0.
    # There is genuinely nothing to dispatch, so this is legitimately OK - it is
    # NOT a queued-but-not-run false-green. Gate it strictly on the residual
    # count being zero so a mislabeled obligation can never green this signal.
    next_items = data.get("next", [])
    next_text = " ".join(str(item) for item in next_items) if isinstance(next_items, list) else str(next_items)
    dispatch_pending = "dispatch" in next_text.lower() and (
        "agent_batch" in next_text.lower()
        or "spawn-worker" in next_text.lower()
        or "mimo-corpus-mine" in next_text.lower()
    )
    if (
        status == "residual-empty-no-hunt-required"
        and int(data.get("residual_surface_units") or 0) == 0
        and not dispatch_pending
    ):
        return SignalResult(
            signal="hunt-provider-obligation", ok=True,
            reason=(
                "hunt_provider_obligation.json status=residual-empty-no-hunt-required "
                "(coverage residual is 0 - all surface units covered, nothing to dispatch)"
            ),
            artifacts=[str(obl_path)],
            detail={"path": str(obl_path), "status": status, "residual_surface_units": 0},
        )
    # Any non-completed status (including the canonical
    # "orchestrator-dispatch-required") means the hunt was queued but not run.
    provider = data.get("hunt_provider", "<unknown>")
    nxt = next_items
    nxt_str = "; ".join(nxt[:3]) if isinstance(nxt, list) else str(nxt)
    return SignalResult(
        signal="hunt-provider-obligation", ok=False,
        reason=(
            f"hunt_provider_obligation.json status={status!r} (provider={provider!r}): "
            f"per-function hunt was queued but never dispatched - "
            f"downstream signals are false-greens. "
            f"Next steps: {nxt_str}"
        ),
        artifacts=[str(obl_path)],
        detail={"path": str(obl_path), "status": status, "provider": provider, "next": nxt},
    )


# --------------------------------------------------------------------------
# Signal (a): full clone + mining_rounds artifact
# --------------------------------------------------------------------------
def _git_commit_count(repo: Path) -> int | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def _is_shallow(repo: Path) -> bool | None:
    # A .git/shallow file is the canonical on-disk marker of a `--depth N`
    # clone and is the most robust signal (git's own --is-shallow check
    # also keys off it). Check it directly first so a shallow tree is
    # caught even when the porcelain query is unavailable.
    git_dir = repo / ".git"
    try:
        if git_dir.is_dir() and (git_dir / "shallow").exists():
            return True
        # Submodule / worktree layout: .git is a file pointing at gitdir.
        if git_dir.is_file():
            txt = git_dir.read_text(encoding="utf-8", errors="replace")
            m = txt.strip().split("gitdir:", 1)
            if len(m) == 2:
                gd = (repo / m[1].strip()).resolve()
                if (gd / "shallow").exists():
                    return True
    except OSError:
        pass
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() == "true"


def _find_source_repo(ws: Path) -> Path | None:
    """Locate the in-scope source clone under the workspace. Return the
    first directory containing a ``.git``."""
    if _exists(ws / ".git"):
        return ws
    for sub in ("external", "src", "repo", "target", "source"):
        base = ws / sub
        if not _exists(base) or not base.is_dir():
            continue
        if _exists(base / ".git"):
            return base
        try:
            for c in sorted(base.iterdir()):
                if c.is_dir() and _exists(c / ".git"):
                    return c
        except OSError:
            continue
    try:
        for c in sorted(ws.iterdir()):
            if c.is_dir() and _exists(c / ".git"):
                return c
    except OSError:
        pass
    return None


def check_full_clone(ws: Path) -> SignalResult:
    mining = ws / "mining_rounds"
    mining_ok = _nonempty_dir(mining)
    repo = _find_source_repo(ws)
    arts: list[str] = []
    if mining_ok:
        arts.append(str(mining))

    if repo is None:
        return SignalResult(
            signal="full-clone", ok=False,
            reason=(
                "no in-scope source git clone found under workspace; Tier-6 "
                "bidirectional commit-mining requires a full clone with history"
            ),
            artifacts=arts, detail={"repo": None, "mining_rounds": mining_ok},
        )

    shallow = _is_shallow(repo)
    count = _git_commit_count(repo)
    arts.append(str(repo / ".git"))
    detail = {
        "repo": str(repo), "is_shallow": shallow,
        "commit_count": count, "mining_rounds": mining_ok,
    }
    if shallow is True:
        return SignalResult(
            signal="full-clone", ok=False,
            reason=f"source clone at {repo} is SHALLOW (.git/shallow); Tier-6 mining impossible",
            artifacts=arts, detail=detail,
        )
    if count is not None and count <= 1:
        return SignalResult(
            signal="full-clone", ok=False,
            reason=f"source clone at {repo} has commit_count={count} (<=1); shallow-equivalent",
            artifacts=arts, detail=detail,
        )
    if not mining_ok:
        return SignalResult(
            signal="full-clone", ok=False,
            reason=(
                "full clone present but no mining_rounds/ artifact; Tier-6 "
                "bidirectional commit-mining did not run"
            ),
            artifacts=arts, detail=detail,
        )
    return SignalResult(
        signal="full-clone", ok=True,
        reason=f"full clone (commit_count={count}) + mining_rounds/ present",
        artifacts=arts, detail=detail,
    )


# --------------------------------------------------------------------------
# Signal (b): audit-deep ran
# --------------------------------------------------------------------------
def check_audit_deep(ws: Path) -> SignalResult:
    logs = ws / ".audit_logs"
    candidates: list[Path] = []
    if _exists(logs) and logs.is_dir():
        try:
            for c in logs.iterdir():
                if c.name.startswith("."):
                    continue
                if c.name.startswith("audit_deep") and c.is_file():
                    candidates.append(c)
        except OSError:
            pass
    # Canonical deep-manifest paths the CURRENT audit-deep writes (the legacy
    # `.audit_logs/audit_deep*_manifest.json` glob above misses them - a serving
    # gap that made hunt-complete report `no-audit-deep` on a workspace whose
    # audit-deep genuinely ran). Recognize the real artifacts so the signal is
    # not a false-red. Generic across any solidity workspace.
    canonical = [
        ws / ".auditooor" / "solidity-deep-audit" / "manifest.json",
        ws / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json",
        ws / ".auditooor" / "mutation_verify_coverage.json",
        ws / ".auditooor" / "genuine_coverage_manifest.json",
    ]
    for c in canonical:
        if _exists(c) and c.is_file():
            candidates.append(c)
    deep_dirs = [ws / "deep_candidates", ws / ".audit_logs" / "deep",
                 ws / ".auditooor" / "solidity-deep-audit"]
    extra = [d for d in deep_dirs if _nonempty_dir(d)]
    arts = [str(c) for c in candidates] + [str(d) for d in extra]
    if candidates or extra:
        return SignalResult(
            signal="audit-deep", ok=True,
            reason=f"audit-deep evidence present ({len(candidates)} manifest(s), {len(extra)} dir(s))",
            artifacts=arts, detail={"manifests": [str(c) for c in candidates]},
        )
    return SignalResult(
        signal="audit-deep", ok=False,
        reason=(
            "no audit-deep manifest / output (.audit_logs/audit_deep*_manifest.json); "
            "`make audit-deep WS=...` did not run"
        ),
        artifacts=[], detail={"logs_dir": str(logs)},
    )


# --------------------------------------------------------------------------
# Signal (c): coverage matrix present + no DARK rows
# --------------------------------------------------------------------------
def _find_coverage_matrix(ws: Path) -> list[Path]:
    out: list[Path] = []
    try:
        for c in ws.iterdir():
            if c.is_file() and c.name.endswith("CAPABILITY_COVERAGE_MATRIX.md"):
                out.append(c)
    except OSError:
        pass
    return sorted(out)


def _verdict_cell(cells: list[str], verdict_idx: int | None) -> str:
    """Return the cell to scan for a DARK marker.

    The canonical matrix is ``| # | family | Verdict | Evidence |`` - the
    DARK marker lives in the Verdict column ONLY; the Evidence column holds
    prose that legitimately contains substrings like ``knowledge_gap``. So
    when the header located a Verdict/Status/Coverage column we scan ONLY
    that cell. Without a header we fall back to the cells BEFORE the last
    one (the evidence/notes cell is conventionally last) to avoid the prose
    false-positives, defaulting to the whole joined row only for 1-2 column
    tables that have no separate evidence column.
    """
    low = [c.lower() for c in cells]
    if verdict_idx is not None and 0 <= verdict_idx < len(low):
        return low[verdict_idx]
    if len(low) >= 3:
        # scan everything except the conventionally-last evidence cell
        return " ".join(low[:-1])
    return " ".join(low)


def _norm_cluster_key(value: str) -> str:
    """Normalize a cluster / row-name for in-scope membership comparison.

    Mirrors the normalization used by ``check_cluster_coverage`` so the
    DARK-row in-scope test and the cluster-coverage test agree."""
    return re.sub(r"[^a-z0-9]+", "", value.strip("`").strip().lower())


def _row_is_in_scope(row_cluster: str, scope_keys: set[str]) -> bool:
    """True when a matrix row's cluster cell maps to a current SCOPE.md
    cluster (bidirectional normalized substring match, same as the
    cluster-coverage signal)."""
    rk = _norm_cluster_key(row_cluster)
    if not rk:
        return False
    for sk in scope_keys:
        if not sk:
            continue
        if rk in sk or sk in rk:
            return True
    return False


def _matrix_dark_rows(txt: str, scope_keys: set[str] | None = None) -> list[str]:
    """Return markdown table rows whose Verdict cell is DARK.

    Tracks the Verdict/Status/Coverage column index from the header row so
    only that cell is scanned for a DARK token - evidence-column prose like
    ``knowledge_gap`` must not register as a DARK family (regression locked
    by the hyperbridge dogfood, 2026-05-29).

    When ``scope_keys`` is provided (the normalized current SCOPE.md
    clusters) a DARK row is only counted as a real coverage gap if its
    cluster cell maps to an in-scope cluster. Orphan DARK rows (clusters
    no longer in SCOPE.md, e.g. a stale or hand-authored sibling matrix
    left over from a prior scope) are NOT coverage gaps - they are stale
    bookkeeping and must not fatally zero the hunt. ``scope_keys=None``
    (or empty) preserves the legacy behavior: every DARK row counts (used
    when SCOPE.md is absent, so we cannot prove a row is orphaned)."""
    dark: list[str] = []
    verdict_idx: int | None = None
    name_idx = 0
    for raw in txt.splitlines():
        line = raw.strip()
        if not line.startswith("|") or "|" not in line[1:]:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells if c):
            continue  # separator row
        low_cells = [c.lower() for c in cells]
        # Header row: locate the Verdict/Status/Coverage column and skip it.
        header_hit = [
            i for i, c in enumerate(low_cells)
            if c in ("verdict", "status", "coverage")
        ]
        if header_hit:
            verdict_idx = header_hit[0]
            # The cluster name is conventionally the first non-status column.
            name_idx = 1 if verdict_idx == 0 and len(cells) > 1 else 0
            continue
        scan = _verdict_cell(cells, verdict_idx)
        has_dark = any(
            re.search(rf"(?<![a-z]){re.escape(tok)}(?![a-z])", scan)
            for tok in _DARK_TOKENS
        )
        if not has_dark:
            continue
        # Only count DARK rows whose cluster is still in the current scope.
        # An orphan DARK row (cluster absent from SCOPE.md) is stale and
        # must not fail the gate; without SCOPE.md every DARK row counts.
        if scope_keys:
            row_name = cells[name_idx] if name_idx < len(cells) else (cells[0] if cells else "")
            if not _row_is_in_scope(row_name, scope_keys):
                continue
        dark.append(line)
    return dark


def check_coverage_matrix_present(ws: Path) -> SignalResult:
    mats = _find_coverage_matrix(ws)
    if not mats:
        return SignalResult(
            signal="coverage-matrix-present", ok=False,
            reason="no <WS>/*CAPABILITY_COVERAGE_MATRIX.md found",
            artifacts=[], detail={},
        )
    return SignalResult(
        signal="coverage-matrix-present", ok=True,
        reason=f"{len(mats)} capability coverage matrix file(s) present",
        artifacts=[str(m) for m in mats], detail={"matrices": [str(m) for m in mats]},
    )


def check_coverage_matrix_no_dark(ws: Path, present: SignalResult) -> SignalResult:
    if not present.ok:
        return SignalResult(
            signal="coverage-matrix-no-dark", ok=False,
            reason="no coverage matrix to scan for DARK rows",
            artifacts=[], detail={},
        )
    # In-scope cluster keys (normalized) gate which DARK rows count: a DARK
    # row whose cluster is no longer in SCOPE.md is stale bookkeeping, not a
    # coverage gap, and must not zero the hunt. When SCOPE.md is absent we
    # pass scope_keys=None so every DARK row counts (legacy behavior).
    scope_clusters = _parse_scope_clusters(ws)
    scope_keys = {_norm_cluster_key(c) for c in scope_clusters}
    scope_keys.discard("")
    use_scope_filter = bool(scope_keys)
    all_dark: dict[str, list[str]] = {}
    orphan_dark: dict[str, list[str]] = {}
    mats = present.detail.get("matrices", [])
    for m in mats:
        txt = _read_text(Path(m)) or ""
        dark = _matrix_dark_rows(txt, scope_keys if use_scope_filter else None)
        if dark:
            all_dark[m] = dark
        if use_scope_filter:
            # Record orphan (out-of-scope) DARK rows as advisory only.
            all_rows = _matrix_dark_rows(txt, None)
            orphans = [r for r in all_rows if r not in dark]
            if orphans:
                orphan_dark[m] = orphans
    if all_dark:
        n = sum(len(v) for v in all_dark.values())
        return SignalResult(
            signal="coverage-matrix-no-dark", ok=False,
            reason=f"{n} in-scope DARK row(s) across {len(all_dark)} matrix file(s); coverage incomplete",
            artifacts=list(all_dark.keys()),
            detail={"dark_rows": all_dark, "orphan_dark_rows": orphan_dark},
        )
    reason = "0 in-scope DARK rows in every coverage matrix"
    if orphan_dark:
        n_orph = sum(len(v) for v in orphan_dark.values())
        reason += (
            f" ({n_orph} orphan DARK row(s) for clusters absent from SCOPE.md "
            "ignored as stale bookkeeping)"
        )
    return SignalResult(
        signal="coverage-matrix-no-dark", ok=True,
        reason=reason,
        artifacts=mats,
        detail={"orphan_dark_rows": orphan_dark} if orphan_dark else {},
    )


# --------------------------------------------------------------------------
# Signal (d): every in-scope cluster has coverage
# --------------------------------------------------------------------------

# SCOPE.md intro/metadata bullets ("- Asset class: ...", "- Platform: ...",
# "- Program URL: ...", "- Audit pin: ...", "- Source", "- Local checkout: ...")
# are NOT in-scope clusters. They share the bullet shape and (when listed under
# the title heading) were wrongly counted as clusters, inflating the cluster
# count and making cluster-coverage / dark-families un-passable on any workspace
# whose SCOPE.md carries a metadata header. Filter them out generically.
_SCOPE_METADATA_KEYS = frozenset({
    "asset class", "platform", "program", "program url", "source", "audit pin",
    "local checkout", "license", "bounty", "max bounty", "severity", "website",
    "docs", "documentation", "contact", "reward", "rewards", "repo", "repository",
    "chain", "network", "ecosystem", "language", "commit", "pin", "scope",
    "in-scope", "in scope", "out-of-scope", "out of scope", "program rules",
    "rules", "eligibility", "acceptance", "asset", "url", "homepage", "live since",
    "submission selector", "asset class:", "build assumptions",
})

# Provenance-bullet words (mirrors capability-coverage-matrix-build.py, the
# single source of truth, so the legacy fallback copy never drifts).
_META_PROVENANCE_WORDS = frozenset({
    "deployed", "audited", "pinned", "commit", "checkout", "clone", "cloned",
    "provenance", "revision",
})


def _is_scope_metadata_bullet(name: str) -> bool:
    n = (name or "").strip()
    if not n:
        return True
    if re.match(r"^https?://", n, re.I):
        return True
    low = n.lower().rstrip(":")
    if low in _SCOPE_METADATA_KEYS:
        return True
    # "Label: value" where Label is prose (no path separator) and a known meta key
    m = re.match(r"^([A-Za-z][A-Za-z /]{1,40}?)\s*:", n)
    if m and "/" not in m.group(1):
        if m.group(1).strip().lower() in _SCOPE_METADATA_KEYS:
            return True
    # Provenance bullet ("Deployed/audited version: tag `vX`", "Pinned commit:
    # <sha>") - residual label led by a provenance word, or a short phrase built
    # around "version". Mirrors capability-coverage-matrix-build.py.
    _toks = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    if _toks and (
        _toks[0] in _META_PROVENANCE_WORDS
        or ("version" in _toks and len(_toks) <= 3)
    ):
        return True
    return False


def _parse_scope_clusters(ws: Path) -> list[str]:
    """Enumerate in-scope CODE clusters from SCOPE.md.

    SINGLE SOURCE OF TRUTH: delegate to capability-coverage-matrix-build.py's
    `_parse_scope_clusters` so the cluster-coverage gate and the coverage MATRIX
    can never disagree on what counts as a cluster (they previously drifted: the
    matrix builder was fixed to strip markdown-bold metadata bullets and to skip
    "vulnerability classes / impacts" sections - the rubric axis - but this gate
    kept an older copy that still over-counted SCOPE.md header metadata + impact
    phrases, leaving cluster-coverage un-passable while the matrix showed 0 DARK).
    Returns lowercased names (this gate's historical contract). Falls back to the
    legacy local parse only if the builder cannot be imported."""
    try:
        builder = _load_matrix_builder()
        return [c.lower() for c in builder._parse_scope_clusters(ws)
                if not _is_non_code_cluster(c)]
    except Exception:
        pass
    # --- legacy fallback (builder unavailable) ---
    scope = ws / "SCOPE.md"
    txt = _read_text(scope)
    if not txt:
        return []
    clusters: list[str] = []
    saw_heading = False
    active_section = True
    for raw in txt.splitlines():
        line = raw.strip()
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if heading:
            saw_heading = True
            active_section = (
                _is_title_scope_heading(heading.group(2), len(heading.group(1)))
                or _is_cluster_section(heading.group(2))
            )
            continue
        if saw_heading and not active_section:
            continue
        m = re.match(r"^[-*+]\s+(.+)$", line)
        if m:
            name = _clean_cluster_name(m.group(1))
            if (name and len(name) <= 120 and not _is_scope_metadata_bullet(name)
                    and not _is_non_code_cluster(name)):
                clusters.append(name.lower())
    seen = set()
    out = []
    for c in clusters:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _cluster_brief_tokens(ws: Path) -> set[str]:
    """Coverage tokens sourced from the per-class hunt cluster briefs.

    The per-class hunt writes one markdown brief per SCOPE impact class to
    ``<ws>/.auditooor/hunt_cluster_briefs/<slug>.md`` (e.g.
    ``stealing-or-loss-of-funds.md``). Each brief stem IS the impact-class
    name; its presence evidences that class was hunted. Returned lowercased;
    the caller's normalized-substring matcher reconciles separators. Generic
    across languages - the briefs are language-agnostic SCOPE impact-class
    artifacts.

    r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    """
    tokens: set[str] = set()
    brief_dir = ws / ".auditooor" / "hunt_cluster_briefs"
    if _exists(brief_dir) and brief_dir.is_dir():
        try:
            for c in brief_dir.iterdir():
                if c.is_file() and c.suffix.lower() == ".md" and not c.name.startswith("."):
                    tokens.add(c.stem.lower())
        except OSError:
            pass
    return {t for t in tokens if t}


def _coverage_tokens(ws: Path) -> set[str]:
    """Lowercase tokens evidencing per-cluster coverage.

    DARK matrix rows are not evidence. They are the absence of evidence.

    r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    """
    tokens: set[str] = set()
    tokens.update(_cluster_brief_tokens(ws))
    for sidecars in (
        ws / "hunt_findings_sidecars",
        ws / ".auditooor" / "hunt_findings_sidecars",
    ):
        if _exists(sidecars) and sidecars.is_dir():
            try:
                for c in sidecars.rglob("*"):
                    if c.is_file() and not c.name.startswith("."):
                        tokens.add(c.stem.lower())
            except OSError:
                pass
    skip = ws / ".auditooor" / "hunt_skip_set.json"
    txt = _read_text(skip)
    if txt:
        try:
            d = json.loads(txt)
            for e in d.get("entries", []):
                if isinstance(e, dict) and e.get("slug"):
                    tokens.add(str(e["slug"]).lower())
        except (ValueError, json.JSONDecodeError):
            pass
    for m in _find_coverage_matrix(ws):
        txt = _read_text(m) or ""
        verdict_idx: int | None = None
        for raw in txt.splitlines():
            line = raw.strip()
            if line.startswith("|") and "|" in line[1:]:
                cells = [c.strip() for c in line.strip("|").split("|")]
                if all(set(c) <= set("-: ") for c in cells if c):
                    continue
                low_cells = [c.lower() for c in cells]
                header_hit = [
                    i for i, c in enumerate(low_cells)
                    if c in ("verdict", "status", "coverage")
                ]
                if header_hit:
                    verdict_idx = header_hit[0]
                    continue
                scan = _verdict_cell(cells, verdict_idx)
                has_dark = any(
                    re.search(rf"(?<![a-z]){re.escape(tok)}(?![a-z])", scan)
                    for tok in _DARK_TOKENS
                )
                if cells and not has_dark:
                    tokens.add(cells[0].strip("`").strip().lower())
    return {t for t in tokens if t}


def check_cluster_coverage(ws: Path) -> SignalResult:
    clusters = _parse_scope_clusters(ws)
    if not clusters:
        return SignalResult(
            signal="cluster-coverage", ok=False,
            reason="SCOPE.md absent or enumerates 0 in-scope clusters; cannot verify per-cluster coverage",
            artifacts=[], detail={"clusters": []},
        )
    tokens = _coverage_tokens(ws)
    uncovered: list[str] = []
    for cl in clusters:
        cl_norm = re.sub(r"[^a-z0-9]+", "", cl.lower())
        # A path-form cluster (contracts/.../DiscreteAccounting.sol) must ALSO match
        # on its file BASENAME. hunt sidecars are keyed by contract/fn name
        # (hunt__DiscreteAccounting__fn -> token norm huntdiscreteaccountingfn); the
        # full-path norm carries the dir prefix + `sol` suffix so the shared contract
        # name sits mid-string in BOTH and neither is a substring of the other ->
        # every path cluster false-reads as uncovered (Strata 2026-07-07: 15/16).
        # The basename-without-extension (discreteaccounting) IS a substring of the
        # token, so it credits a cluster that genuinely has a hunt sidecar.
        base = cl.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        base = re.sub(r"\.[a-z0-9]+$", "", base.lower())
        cl_base_norm = re.sub(r"[^a-z0-9]+", "", base)
        covered = False
        for tok in tokens:
            tok_norm = re.sub(r"[^a-z0-9]+", "", tok)
            if not tok_norm:
                continue
            for key in (cl_norm, cl_base_norm):
                if key and (key in tok_norm or tok_norm in key):
                    covered = True
                    break
            if covered:
                break
        if not covered:
            uncovered.append(cl)
    if uncovered:
        return SignalResult(
            signal="cluster-coverage", ok=False,
            reason=f"{len(uncovered)}/{len(clusters)} in-scope cluster(s) have no hunt sidecar or coverage row",
            artifacts=[], detail={"uncovered": uncovered, "clusters": clusters},
        )
    return SignalResult(
        signal="cluster-coverage", ok=True,
        reason=f"all {len(clusters)} in-scope cluster(s) have coverage evidence",
        artifacts=[], detail={"clusters": clusters},
    )


# --------------------------------------------------------------------------
# Signal (e): agent artifacts mined into the corpus
# --------------------------------------------------------------------------
_ARTIFACT_MINING_SCHEMA = "auditooor.agent_artifact_mining.v2"


def _v2_genuine_mining_report(p: Path) -> bool:
    """Return True iff ``p`` is a GENUINE v2 agent-artifact-mining report,
    mirroring the canonical learning-signal validator in
    tools/audit-completeness-check.py.

    Genuine == schema_version 'auditooor.agent_artifact_mining.v2' AND an int
    total_artifacts AND a bool no_learning_reason. A 0-artifacts run
    (total_artifacts=0, no_learning_reason=True) is GENUINE - the miner ran
    over the whole workspace and honestly found nothing to mine. A genuine v2
    report is sufficient artifact-mining evidence ON ITS OWN, even when the
    workspace has no hunt_findings_sidecars/ (a clean workspace with 0 sidecar
    findings is honest, not incomplete).
    """
    if p.suffix != ".json":
        return False
    obj = _read_json(p)
    if not isinstance(obj, dict):
        return False
    if obj.get("schema_version") != _ARTIFACT_MINING_SCHEMA:
        return False
    if not isinstance(obj.get("total_artifacts"), int):
        return False
    if not isinstance(obj.get("no_learning_reason"), bool):
        return False
    return True


def check_artifact_mining(ws: Path) -> SignalResult:
    sidecar_dirs = [
        ws / "hunt_findings_sidecars",
        ws / ".auditooor" / "hunt_findings_sidecars",
    ]
    sidecars = next((d for d in sidecar_dirs if _nonempty_dir(d)), sidecar_dirs[0])
    sidecars_ok = _nonempty_dir(sidecars)
    learn_candidates = [
        ws / "agent_artifact_mining_report.json",
        ws / "reports" / "agent_artifact_mine_report.json",
        ws / ".auditooor" / "agent_artifact_mining_report.json",
        ws / "reports" / "agent_learning_report.json",
        ws / ".audit_logs" / "agent_artifact_mine_report.json",
        ws / ".auditooor" / "corpus_delta.json",
        ws / "reports" / "corpus_delta.json",
    ]
    learn_arts = [str(c) for c in learn_candidates if _exists(c) and Path(c).is_file()]
    reports = ws / "reports"
    if _exists(reports) and reports.is_dir():
        try:
            for c in reports.iterdir():
                if c.is_file() and c.name.endswith(".json") and (
                    "learn" in c.name.lower()
                    or "artifact_mine" in c.name.lower()
                    or "corpus_delta" in c.name.lower()
                ):
                    learn_arts.append(str(c))
        except OSError:
            pass
    learn_arts = sorted(set(learn_arts))

    # Tier 1 (generic non-EVM / clean-workspace fix): a GENUINE v2
    # agent-artifact-mining report IS the artifact-mining evidence on its own,
    # independent of whether hunt_findings_sidecars/ exists. The miner walks
    # the WHOLE workspace (exploit-queue, known-limitations, roadmap gaps,
    # proof-mappings), not just the sidecar dir, so a clean workspace with zero
    # sidecar findings but a genuine mining report (total_artifacts>=0,
    # no_learning_reason coherent) has honestly completed the mining step.
    # 0 candidates is honest, not incomplete. This mirrors the
    # completeness-check `learning` signal, which credits the same report by
    # schema, and the `mined-landed` signal, which treats a zero-sidecar
    # workspace as "mined==landed trivially".
    v2_genuine = [a for a in learn_arts if _v2_genuine_mining_report(Path(a))]
    detail = {
        "sidecars_nonempty": sidecars_ok,
        "learn_reports": learn_arts,
        "v2_genuine_reports": v2_genuine,
    }
    if v2_genuine:
        sidecar_note = (
            "sidecars present"
            if sidecars_ok
            else "no hunt_findings_sidecars (clean workspace; 0 sidecar findings is honest)"
        )
        return SignalResult(
            signal="artifact-mining", ok=True,
            reason=(
                f"{len(v2_genuine)} genuine v2 artifact-mining report(s) present "
                f"({sidecar_note})"
            ),
            artifacts=(
                [str(sidecars), *v2_genuine] if sidecars_ok else v2_genuine
            ),
            detail=detail,
        )

    # Tier 2 (legacy presence-only behavior, preserved): a non-v2 learn /
    # corpus-delta artifact only credits artifact-mining WITH sidecars present
    # (the original sidecars-first contract). A clean workspace lacking BOTH a
    # genuine v2 report and sidecars genuinely did not run the mining step.
    if not sidecars_ok:
        return SignalResult(
            signal="artifact-mining", ok=False,
            reason="hunt_findings_sidecars/ missing or empty; no agent artifacts to mine",
            artifacts=learn_arts, detail=detail,
        )
    if not learn_arts:
        return SignalResult(
            signal="artifact-mining", ok=False,
            reason=(
                "hunt_findings_sidecars/ present but no sidecar-ETL/learn report or "
                "corpus-delta artifact; mining step did not run"
            ),
            artifacts=[str(sidecars)], detail=detail,
        )
    return SignalResult(
        signal="artifact-mining", ok=True,
        reason=f"sidecars present + {len(learn_arts)} learn/corpus-delta artifact(s)",
        artifacts=[str(sidecars), *learn_arts], detail=detail,
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def evaluate(ws: Path) -> dict:
    rebuttals = _load_rebuttal(ws)

    df = check_dedup_first(ws)  # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered
    hpo = check_hunt_provider_obligation(ws)  # r36-rebuttal: funnel-generic-fixes-wave3
    fc = check_full_clone(ws)
    ad = check_audit_deep(ws)
    cmp_ = check_coverage_matrix_present(ws)
    cmd = check_coverage_matrix_no_dark(ws, cmp_)
    cc = check_cluster_coverage(ws)
    am = check_artifact_mining(ws)

    by_signal = {
        "dedup-first": df,
        "hunt-provider-obligation": hpo,
        "full-clone": fc,
        "audit-deep": ad,
        "coverage-matrix-present": cmp_,
        "coverage-matrix-no-dark": cmd,
        "cluster-coverage": cc,
        "artifact-mining": am,
    }

    signals_out = []
    failures = []
    rebutted = []
    for signal, fail_verdict in _SIGNAL_ORDER:
        r = by_signal[signal]
        eff_ok = r.ok
        rb = None
        if not r.ok:
            rb = _rebuttal_for(rebuttals, signal)
            if rb:
                eff_ok = True
                rebutted.append({"signal": signal, "reason": rb})
        signals_out.append({
            "signal": signal,
            "ok": eff_ok,
            "raw_ok": r.ok,
            "verdict": ("ok-rebuttal" if (not r.ok and rb) else ("pass" if r.ok else fail_verdict)),
            "reason": r.reason,
            "artifacts": r.artifacts,
            "detail": r.detail,
        })
        if not eff_ok:
            failures.append(fail_verdict)

    if not failures:
        verdict = "pass-hunt-complete"
        # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered; r36-rebuttal: funnel-generic-fixes-wave3
        reason = "all hunt-completeness signals present (dedup-first + provider-obligation + a-e)"
    else:
        verdict = failures[0]
        first_signal = _SIGNAL_ORDER[[v for _, v in _SIGNAL_ORDER].index(failures[0])][0]
        reason = by_signal[first_signal].reason

    return {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(ws),
        "verdict": verdict,
        "reason": reason,
        "failures": failures,
        "rebutted": rebutted,
        "signals": signals_out,
    }


def _print_human(result: dict) -> None:
    print(f"[{GATE}] verdict={result['verdict']}")
    print(f"[{GATE}] workspace={result['workspace']}")
    for s in result["signals"]:
        mark = "PASS" if s["ok"] else "FAIL"
        rb = " (rebuttal)" if s["verdict"] == "ok-rebuttal" else ""
        print(f"  [{mark}] {s['signal']}{rb}: {s['reason']}")
    if result["failures"]:
        print(f"[{GATE}] reason: {result['reason']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hunt-completeness-check.py",
        description="L35 hunt-completeness gate: a HUNT is the full end-to-end pipeline.",
    )
    p.add_argument("workspace", help="Path to the audit workspace.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    p.add_argument(
        "--strict", action="store_true",
        help="(reserved) treat WARN-class conditions as failures; all completeness "
             "signals already fail closed.",
    )
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": "workspace path does not exist or is not a directory",
            "failures": ["error"], "rebutted": [], "signals": [],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    try:
        result = evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": f"internal error: {exc}",
            "failures": ["error"], "rebutted": [], "signals": [],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)

    if result["verdict"] == "pass-hunt-complete":
        return 0
    if result["verdict"] == "error":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
