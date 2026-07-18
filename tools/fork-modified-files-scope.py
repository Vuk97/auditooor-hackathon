#!/usr/bin/env python3
"""fork-modified-files-scope.py - scope a fork's in-scope units to the files the
FORK ACTUALLY MODIFIED vs its upstream (the Polygon-Labs-modified surface).

Most bounty programs that include a fork (bor/cosmos-sdk/cometbft, etc.) put ONLY
the fork's own modifications in scope - "unmodified upstream is OUT OF SCOPE". A
naive in-scope enumeration over the whole fork tree pulls in tens of thousands of
inherited-upstream functions that are OOS, drowning the hunt.

This tool computes the modified+added file set via a CONTENT-HASH TREE DIFF of the
fork checkout against a shallow clone of the upstream at a given ref (no merge-base
needed - robust to rebased/squashed fork history), then filters an
inscope_units.jsonl so that rows under the fork's local_name keep ONLY units whose
repo-relative file was modified/added by the fork. Rows for OTHER repos/langs pass
through untouched.

Completeness-safety: if the upstream clone or ref cannot be resolved, the tool does
NOT drop any unit for that repo (it keeps the full fork set + records
verdict="upstream-unresolved") - an audit must never silently UNDER-scope. Use a
correct --upstream-ref to get the precise (narrow) surface.

Exit 0 always (advisory scoping); --strict exits 2 if upstream was unresolved.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Core logic now lives in tools/lib/fork_modified.py so the step-1 manifest
# emitter (and any other in-process consumer) can call it without shelling out.
# This CLI re-exports the names so its behavior - and the existing
# test_fork_modified_files_scope.py - is unchanged.
# ---------------------------------------------------------------------------
try:  # normal package import
    from lib.fork_modified import (  # type: ignore
        _eprint,
        _go_files,
        _normalized_content_hash,
        compute_modified_files,
        filter_manifest,
    )
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    _HERE = Path(__file__).resolve().parent
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    from lib.fork_modified import (  # type: ignore
        _eprint,
        _go_files,
        _normalized_content_hash,
        compute_modified_files,
        filter_manifest,
    )


def _clone_upstream(upstream_repo: str, ref: str, dest: Path) -> bool:
    """Shallow clone upstream_repo (owner/repo) at ref into dest. True on success."""
    url = f"https://github.com/{upstream_repo}.git"
    for attempt in ([ref] if ref else []):
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", attempt, url, str(dest)],
            capture_output=True, text=True,
        )
        if rc.returncode == 0:
            return True
        _eprint(f"[fork-scope] clone {url}@{attempt} failed: {rc.stderr.strip()[:200]}")
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fork-dir", required=True, help="path to the fork checkout (e.g. <ws>/src/bor)")
    ap.add_argument("--upstream-repo", required=True, help="upstream owner/repo (e.g. cometbft/cometbft)")
    ap.add_argument("--upstream-ref", default="", help="upstream tag/branch to diff against (e.g. v0.38.22)")
    ap.add_argument("--repo-local-name", required=True, help="local_name as it appears in src/<name> + inscope rows")
    ap.add_argument("--inscope-manifest", required=True, help="path to inscope_units.jsonl to filter")
    ap.add_argument("--out", default="", help="output manifest path (default: in place)")
    ap.add_argument("--clone-root", default="", help="dir for the shallow upstream clone (default: temp)")
    ap.add_argument("--include-tests", action="store_true", help="include *_test.go in the diff surface")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 2 if upstream could not be resolved")
    args = ap.parse_args(argv)

    fork_dir = Path(args.fork_dir).expanduser().resolve()
    manifest = Path(args.inscope_manifest).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve() if args.out else manifest
    if not fork_dir.is_dir():
        _eprint(f"[fork-scope] ERR fork-dir not found: {fork_dir}"); return 2
    if not manifest.is_file():
        _eprint(f"[fork-scope] ERR inscope-manifest not found: {manifest}"); return 2

    modified: set[str] | None = None
    verdict = "upstream-unresolved"
    tmp_holder = None
    clone_dest: Path
    if args.clone_root:
        clone_dest = Path(args.clone_root).expanduser().resolve() / f"upstream_{args.repo_local_name}"
        clone_dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        tmp_holder = tempfile.TemporaryDirectory(prefix="fork-scope-")
        clone_dest = Path(tmp_holder.name) / f"upstream_{args.repo_local_name}"

    try:
        if clone_dest.exists() and (clone_dest / ".git").is_dir():
            ok = True
        else:
            ok = _clone_upstream(args.upstream_repo, args.upstream_ref, clone_dest)
        if ok:
            modified = compute_modified_files(
                fork_dir, clone_dest, skip_tests=not args.include_tests
            )
            verdict = "scoped"
        else:
            _eprint(f"[fork-scope] WARN upstream {args.upstream_repo}@{args.upstream_ref or 'HEAD'} "
                    f"unresolved; KEEPING ALL {args.repo_local_name} units (completeness-safe, no under-scope)")
        stats = filter_manifest(manifest, out_path, args.repo_local_name, modified)
    finally:
        if tmp_holder is not None:
            tmp_holder.cleanup()

    payload = {
        "schema": "auditooor.fork_modified_files_scope.v1",
        "verdict": verdict,
        "fork_dir": str(fork_dir),
        "upstream_repo": args.upstream_repo,
        "upstream_ref": args.upstream_ref or "(default-branch HEAD)",
        "modified_file_count": (len(modified) if modified is not None else None),
        "manifest_out": str(out_path),
        **stats,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        _eprint(f"[fork-scope] {verdict} {args.repo_local_name}: kept {stats['kept_in_repo']} "
                f"in-repo units, dropped {stats['dropped_in_repo_oos_upstream']} OOS-upstream "
                f"(modified files={payload['modified_file_count']})")
    if args.strict and verdict == "upstream-unresolved":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
