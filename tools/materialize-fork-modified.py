#!/usr/bin/env python3
"""materialize-fork-modified.py - materialize the DURABLE fork-delta artifact(s)
for every fork under a workspace's ``src/``, once, at Step 1.

WHY (the SEI gap): for a FORK target, unmodified-upstream code is OUT OF SCOPE,
but the per-function HUNT residual still contained unmodified-upstream units
(e.g. go-ethereum core/rawdb/*, core/state/pruner/*, core/state/journal.go,
deposit.go, transaction.go - byte-identical to upstream v1.15.7). The
in-scope-manifest emitter can prune those, but ONLY when it can git-clone the
upstream ref. On a SHALLOW fork clone whose upstream ref is not a local git
object (the SEI go-ethereum case: only v1.15.7-sei-17 is a local object, not the
upstream v1.15.7 tag), the git clone from github may still work - but if github
is unreachable or the ref is a non-tag pin, the emitter silently keeps-ALL and
the OOS units reach an agent. Some agents fetched upstream via the Go MODULE
CACHE and succeeded; others quarantined. Inconsistent + a correctness risk.

This tool MATERIALIZES the fork-delta ONCE as
``<ws>/.auditooor/fork_modified/<local_name>.json`` with a robust upstream
resolution chain: git-clone -> language-package-cache (for a GO fork:
``go mod download <module>@<base_ref>`` then diff the extracted read-only
module dir under $GOMODCACHE, GOTOOLCHAIN-pinnable) -> unresolved. When upstream
is unresolvable by ANY method the artifact records ``verdict=upstream-unresolved``
+ ``upstream_source=unresolved`` and carries NO drop-list (keep-all) - an audit
must NEVER silently under-scope.

The artifact is then applied to the per-fn HUNT residual by
``residual-scope-per-fn.py`` (unmodified-upstream units dropped, never reach an
agent) and handed to hunt agents as ``fork_delta_status`` by
``per-fn-mimo-batch-gen.py``. Sei-added / Sei-modified files are NEVER dropped.

Reuses tools/lib/fork_modified (materialize_fork_modified) and the
resolve-fork-bases sidecar. Idempotent; exit 0 always (advisory). Pure stdlib.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE / "lib") not in sys.path:
    sys.path.insert(0, str(_HERE / "lib"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from lib.fork_modified import (  # type: ignore  # noqa: E402
    materialize_fork_modified,
    write_fork_modified_artifact,
)

SCHEMA = "auditooor.materialize_fork_modified.v1"


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_fork_bases(ws: Path) -> list[dict]:
    """Read ``<ws>/.auditooor/fork_bases.json`` (bare list of rows). Empty list
    when absent / unreadable - a non-fork workspace has no bases to materialize."""
    fb = ws / ".auditooor" / "fork_bases.json"
    if not fb.is_file():
        return []
    try:
        data = json.loads(fb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict) and r.get("local_name")]


def _lang_for_fork(ws: Path, local_name: str) -> str:
    """Detect the fork's language from its checkout (go.mod -> go, Cargo.toml ->
    rust, else default go). Governs which package-cache fallback is used."""
    fork_dir = ws / "src" / local_name
    if (fork_dir / "go.mod").is_file():
        return "go"
    if (fork_dir / "Cargo.toml").is_file():
        return "rust"
    # scan a couple of common source suffixes as a hint
    try:
        for p in fork_dir.rglob("*.go"):
            _ = p
            return "go"
    except OSError:
        pass
    try:
        for p in fork_dir.rglob("*.rs"):
            _ = p
            return "rust"
    except OSError:
        pass
    return "go"


def materialize_all(
    ws: Path,
    *,
    gotoolchain: str | None = None,
    allow_download: bool = True,
    clone_root: Path | None = None,
) -> tuple[list[dict], list[str]]:
    """Materialize every fork's artifact. Returns (summaries, warnings)."""
    rows = _load_fork_bases(ws)
    summaries: list[dict] = []
    warnings: list[str] = []
    if not rows:
        return summaries, warnings
    for r in rows:
        name = str(r.get("local_name"))
        upstream_repo = str(r.get("upstream_repo") or "")
        base_ref = str(r.get("base_ref") or "")
        fork_dir = ws / "src" / name
        lang = _lang_for_fork(ws, name)
        payload = materialize_fork_modified(
            fork_dir, upstream_repo, base_ref,
            lang=lang, gotoolchain=gotoolchain,
            allow_download=allow_download, clone_root=clone_root,
        )
        out = write_fork_modified_artifact(ws, payload)
        summaries.append({
            "local_name": name,
            "upstream_source": payload.get("upstream_source"),
            "verdict": payload.get("verdict"),
            "modified_count": payload.get("modified_count"),
            "added_count": payload.get("added_count"),
            "unmodified_upstream_count": payload.get("unmodified_upstream_count"),
            "artifact": str(out),
        })
        if payload.get("verdict") == "upstream-unresolved":
            warnings.append(
                f"[materialize-fork-modified] WARN fork '{name}' upstream "
                f"{upstream_repo}@{base_ref} UNRESOLVED (git-clone + "
                f"{lang}-package-cache both failed); artifact carries NO drop-list "
                f"(KEEP-ALL, completeness-safe). MANUAL STEP: ensure the base ref "
                f"is a real upstream tag, or `go mod download {upstream_repo}@{base_ref}` "
                f"(GO fork), then re-run."
            )
    return summaries, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True,
                    help="workspace PATH (e.g. ~/audits/sei)")
    ap.add_argument("--gotoolchain", default=os.environ.get("GOTOOLCHAIN", ""),
                    help="GOTOOLCHAIN to pin for the go-mod-cache fallback "
                         "(e.g. go1.25.8); default from $GOTOOLCHAIN")
    ap.add_argument("--no-download", action="store_true",
                    help="do NOT run `go mod download`; use only an already-"
                         "extracted module cache dir (fully offline)")
    ap.add_argument("--clone-root", default="",
                    help="dir for the shallow upstream git clone (default: temp)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.is_dir():
        _eprint(f"[materialize-fork-modified] ERR workspace not found: {ws}")
        return 2

    clone_root = Path(args.clone_root).expanduser().resolve() if args.clone_root else None
    summaries, warnings = materialize_all(
        ws,
        gotoolchain=(args.gotoolchain or None),
        allow_download=not args.no_download,
        clone_root=clone_root,
    )
    for w in warnings:
        _eprint(w)
    if args.json:
        print(json.dumps({
            "schema": SCHEMA,
            "workspace": str(ws),
            "forks": summaries,
            "unresolved_warnings": warnings,
        }, indent=2))
    else:
        if not summaries:
            _eprint("[materialize-fork-modified] no fork_bases.json / no forks; "
                    "nothing to materialize (non-fork workspace)")
        for s in summaries:
            _eprint(
                f"[materialize-fork-modified] {s['local_name']}: "
                f"source={s['upstream_source']} verdict={s['verdict']} "
                f"modified={s['modified_count']} added={s['added_count']} "
                f"unmodified-upstream={s['unmodified_upstream_count']} "
                f"-> {s['artifact']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
