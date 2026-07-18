#!/usr/bin/env python3
# r36-rebuttal: lane-K1-keystone-fork-scope-in-emit registered in .auditooor/agent_pathspec.json
"""resolve-fork-bases.py - resolve every fork under a workspace's ``src/`` to its
upstream ``owner/repo`` + base ref, and persist the result to
``<ws>/.auditooor/fork_bases.json``.

WHY: the in-scope manifest emitter (workspace-coverage-heatmap.py
``build_inscope_manifest_rows``) prunes a fork's units down to the FORK-MODIFIED
surface (via tools/lib/fork_modified) ONLY when it can read this sidecar. Without
a resolved (local_name, upstream_repo, base_ref) triple per fork, the emitter
keeps the WHOLE fork tree (completeness-safe but tens of thousands of OOS
inherited-upstream units). This tool produces that sidecar.

RESOLUTION (per fork directory ``<ws>/src/<name>``), in priority order:
  (a) an explicit ``## Fork Bases`` section in ``<ws>/SCOPE.md``. Each non-blank
      line under the heading reads
          ``<local_name> = <owner>/<repo>@<ref>``
      (e.g. ``bor = ethereum/go-ethereum@v1.16.8``). Operator-authoritative.
  (b) else AUTO-DISCOVER from the fork's own git history: the newest merge
      commit whose subject names an upstream version tag, matched against the
      common fork-merge conventions
          ``Merge tag 'vX.Y.Z'``  /  ``Merge tag "vX.Y.Z"``
          ``upstream-vX.Y.Z`` / ``Merge upstream vX.Y.Z`` / ``Merge vX.Y.Z``
      The upstream ``owner/repo`` for (b) is taken from a same-name SCOPE.md row
      if the ref is missing, else from the workspace fork-target markers
      (Cargo/go.mod/origin) - never guessed.

COMPLETENESS-SAFETY: a fork whose upstream ``owner/repo`` cannot be resolved (no
SCOPE.md row, no discoverable base ref, no usable marker) is OMITTED from the
sidecar + a loud WARN is printed with the one-line manual step. An omitted fork
is therefore KEPT-ALL by the emitter (never silently under-scoped).

IDEMPOTENT: re-running over an unchanged workspace writes the SAME sidecar
content (rows sorted by local_name; stable JSON). Exit 0 always (advisory).

Pure stdlib.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.fork_bases.v1"

# "## Fork Bases" heading (any heading level >= 2), case-insensitive.
_FORK_BASES_HEADING_RE = re.compile(r"^\s{0,3}#{2,6}\s+fork\s+bases\b", re.IGNORECASE)
_ANY_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+")
# A SCOPE.md fork-base row: ``name = owner/repo@ref`` (tolerate `-`/list bullets).
_SCOPE_ROW_RE = re.compile(
    r"^\s*[-*]?\s*"
    r"(?P<name>[A-Za-z0-9_.-]+)\s*=\s*"
    r"(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"@(?P<ref>\S+)\s*$"
)
# upstream version tag patterns inside a fork merge-commit subject.
_MERGE_TAG_RES = (
    re.compile(r"""Merge tag ['"](?P<ref>v?[0-9][^'"]*)['"]""", re.IGNORECASE),
    re.compile(r"""\bupstream[- ](?P<ref>v[0-9][0-9A-Za-z.\-]*)\b""", re.IGNORECASE),
    re.compile(r"""\bMerge\s+(?:upstream\s+)?(?P<ref>v[0-9][0-9A-Za-z.\-]*)\b""", re.IGNORECASE),
)

# owner/repo extraction from a github URL of any common shape (Cargo/go.mod/origin).
_GH_URL_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$",
    re.IGNORECASE,
)


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


# ---------------------------------------------------------------------------
# (a) SCOPE.md "## Fork Bases" section
# ---------------------------------------------------------------------------
def parse_scope_fork_bases(ws: Path) -> dict[str, dict]:
    """Parse a ``## Fork Bases`` section of ``<ws>/SCOPE.md``.

    Returns ``{local_name: {"upstream_repo": owner/repo, "base_ref": ref}}`` for
    every well-formed row. Empty dict when no SCOPE.md / no section / no rows.
    """
    out: dict[str, dict] = {}
    txt = _read_text(ws / "SCOPE.md")
    if not txt:
        return out
    in_section = False
    for raw in txt.splitlines():
        if _FORK_BASES_HEADING_RE.match(raw):
            in_section = True
            continue
        if in_section and _ANY_HEADING_RE.match(raw):
            # next heading ends the section
            break
        if not in_section:
            continue
        m = _SCOPE_ROW_RE.match(raw)
        if m:
            out[m.group("name")] = {
                "upstream_repo": m.group("repo"),
                "base_ref": m.group("ref"),
            }
    return out


# ---------------------------------------------------------------------------
# (b) auto-discover from a fork's own git history
# ---------------------------------------------------------------------------
def _git_log_subjects(fork_dir: Path, limit: int = 4000) -> list[str]:
    """Return commit subjects (newest first) of the fork's git history.

    Empty list when the dir has no usable git history (degrade gracefully)."""
    if not (fork_dir / ".git").exists():
        return []
    try:
        rc = subprocess.run(
            ["git", "-C", str(fork_dir), "log", f"-n{int(limit)}",
             "--pretty=%s"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if rc.returncode != 0:
        return []
    return [ln for ln in rc.stdout.splitlines() if ln.strip()]


def discover_base_ref_from_git(fork_dir: Path) -> str | None:
    """Newest upstream-version-tag ref named in a fork merge-commit subject.

    Scans commit subjects newest-first and returns the first ref matched by any
    of the fork-merge conventions. ``None`` if none found."""
    for subj in _git_log_subjects(fork_dir):
        for rx in _MERGE_TAG_RES:
            m = rx.search(subj)
            if m:
                return m.group("ref")
    return None


# ---------------------------------------------------------------------------
# upstream owner/repo from workspace fork-target markers (fallback for (b))
# ---------------------------------------------------------------------------
def _marker_upstream_repo(ws: Path) -> str | None:
    """Best-effort upstream ``owner/repo`` from the workspace's fork markers:
    ``.auditooor/fork_target.json`` ``upstream`` field, then ``FORK_OF.txt``.
    Read-only, offline. ``None`` if none usable."""
    ft = ws / ".auditooor" / "fork_target.json"
    txt = _read_text(ft)
    if txt:
        try:
            data = json.loads(txt)
            up = str(data.get("upstream") or "").strip()
            m = _GH_URL_RE.search(up) if up else None
            if m:
                return f"{m.group(1)}/{m.group(2)}"
            if up and "/" in up and up.count("/") == 1:
                return up
        except (json.JSONDecodeError, AttributeError):
            pass
    fof = _read_text(ws / "FORK_OF.txt")
    if fof:
        for ln in fof.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            m = _GH_URL_RE.search(s)
            if m:
                return f"{m.group(1)}/{m.group(2)}"
            if "/" in s and s.count("/") == 1:
                return s
            break
    return None


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def _fork_dirs(ws: Path) -> list[Path]:
    """Immediate subdirectories of ``<ws>/src`` that look like fork checkouts
    (have their own ``.git``) OR any immediate ``src/`` subdir when none have
    ``.git`` (so a flattened/exported fork tree still gets SCOPE.md resolution).
    Sorted by name for determinism."""
    src = ws / "src"
    if not src.is_dir():
        return []
    subs = sorted([d for d in src.iterdir() if d.is_dir()], key=lambda p: p.name)
    with_git = [d for d in subs if (d / ".git").exists()]
    return with_git if with_git else subs


def resolve_fork_bases(ws: Path) -> tuple[list[dict], list[str]]:
    """Resolve every fork under ``<ws>/src``.

    Returns ``(rows, warnings)`` where each row is
    ``{"local_name", "upstream_repo", "base_ref"}`` (sorted by local_name) and
    ``warnings`` lists the unresolved forks (omitted from rows = kept-all later).
    """
    scope_rows = parse_scope_fork_bases(ws)
    fork_dirs = _fork_dirs(ws)
    # Union of fork dirs on disk and SCOPE.md-declared names (a declared fork
    # whose dir is absent is still recorded; the emitter no-ops on it).
    names: list[str] = sorted(set(d.name for d in fork_dirs) | set(scope_rows.keys()))
    by_name = {d.name: d for d in fork_dirs}

    rows: list[dict] = []
    warnings: list[str] = []
    marker_repo: str | None = None
    marker_loaded = False
    for name in names:
        # (a) explicit SCOPE.md row wins.
        sr = scope_rows.get(name)
        if sr and sr.get("upstream_repo") and sr.get("base_ref"):
            rows.append({
                "local_name": name,
                "upstream_repo": sr["upstream_repo"],
                "base_ref": sr["base_ref"],
                "resolved_via": "scope.md",
            })
            continue
        # (b) auto-discover base ref from the fork's git history.
        fork_dir = by_name.get(name)
        base_ref = discover_base_ref_from_git(fork_dir) if fork_dir else None
        # upstream repo: a SCOPE.md row's repo (even without ref) else markers.
        upstream_repo = (sr.get("upstream_repo") if sr else None)
        if not upstream_repo:
            if not marker_loaded:
                marker_repo = _marker_upstream_repo(ws)
                marker_loaded = True
            upstream_repo = marker_repo
        if base_ref and upstream_repo:
            rows.append({
                "local_name": name,
                "upstream_repo": upstream_repo,
                "base_ref": base_ref,
                "resolved_via": "git-history",
            })
            continue
        # unresolvable -> OMIT + loud WARN + manual step (completeness-safe).
        missing = []
        if not upstream_repo:
            missing.append("upstream owner/repo")
        if not base_ref:
            missing.append("base ref")
        warnings.append(
            f"[resolve-fork-bases] WARN fork '{name}' unresolved "
            f"(missing {', '.join(missing)}); OMITTED from fork_bases.json so the "
            f"in-scope emitter KEEPS ALL its units (completeness-safe). MANUAL STEP: "
            f"add a '## Fork Bases' row to {ws/'SCOPE.md'}: "
            f"`{name} = <owner>/<repo>@<ref>`"
        )
    rows.sort(key=lambda r: r["local_name"])
    return rows, warnings


def write_fork_bases(ws: Path) -> tuple[Path, list[dict], list[str]]:
    """Write ``<ws>/.auditooor/fork_bases.json`` (idempotent). Returns
    ``(path, rows, warnings)``."""
    rows, warnings = resolve_fork_bases(ws)
    out = ws / ".auditooor" / "fork_bases.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    # Stable serialization: schema-versioned wrapper is overkill for the emitter
    # which reads a bare list; persist the bare list (what fork_modified consumers
    # and the emitter expect) sorted by local_name for byte-stable idempotency.
    out.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out, rows, warnings


def _materialize_after_resolve(ws: Path, gotoolchain: str | None) -> list[str]:
    """Materialize the durable fork-delta artifact(s) right after resolving the
    bases (so ``.auditooor/fork_modified/<name>.json`` exists for the hunt
    residual scoper + per-fn brief). Reuses tools/materialize-fork-modified's
    materialize_all. Returns any unresolved-upstream warnings. Best-effort:
    a missing lib / import failure degrades to [] (bases still written)."""
    try:
        _here = Path(__file__).resolve().parent
        for _p in (str(_here), str(_here / "lib")):
            if _p not in sys.path:
                sys.path.insert(0, _p)
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "materialize_fork_modified", _here / "materialize-fork-modified.py"
        )
        if spec is None or spec.loader is None:
            return []
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        summaries, warnings = mod.materialize_all(ws, gotoolchain=gotoolchain)
        for s in summaries:
            _eprint(
                f"[resolve-fork-bases] materialized {s['local_name']}: "
                f"source={s['upstream_source']} verdict={s['verdict']} "
                f"modified={s['modified_count']} added={s['added_count']}"
            )
        return warnings
    except Exception as exc:  # pragma: no cover - defensive, never fatal
        _eprint(f"[resolve-fork-bases] WARN materialize skipped ({exc}); "
                f"run `python3 tools/materialize-fork-modified.py --workspace {ws}`")
        return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True,
                    help="workspace PATH (e.g. ~/audits/polygon)")
    ap.add_argument("--materialize", action="store_true",
                    help="also materialize .auditooor/fork_modified/<name>.json "
                         "(git-clone -> go-mod-cache fallback) after resolving")
    ap.add_argument("--gotoolchain", default=os.environ.get("GOTOOLCHAIN", ""),
                    help="GOTOOLCHAIN for the go-mod-cache fallback (e.g. go1.25.8)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.is_dir():
        _eprint(f"[resolve-fork-bases] ERR workspace not found: {ws}")
        return 2

    out, rows, warnings = write_fork_bases(ws)
    for w in warnings:
        _eprint(w)
    if args.materialize:
        warnings = warnings + _materialize_after_resolve(
            ws, args.gotoolchain or None
        )
    if args.json:
        print(json.dumps({
            "schema": SCHEMA,
            "workspace": str(ws),
            "fork_bases_path": str(out),
            "resolved": rows,
            "unresolved_warnings": warnings,
        }, indent=2))
    else:
        _eprint(f"[resolve-fork-bases] wrote {out} "
                f"({len(rows)} resolved, {len(warnings)} unresolved/omitted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
