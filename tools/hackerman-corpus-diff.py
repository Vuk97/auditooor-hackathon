#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - corpus diff between two git refs.

Emits a per-subtree delta over ``audit/corpus_tags/tags/`` between any two
git refs (e.g. PR #724 baseline ``origin/main`` vs PR #726 head ``HEAD``).
The diff is record-aware: it walks the tree at each ref via ``git ls-tree
-r <ref> -- audit/corpus_tags/tags/`` and compares blob OIDs to classify
each path as added / modified / deleted.

Why
~~~

PR reviewers (operator + Codex) need a single-shot answer to "which corpus
subtrees this branch touched, and by how much" without manually `git diff
--stat`-ing 41k files. The companion tools in this Wave-1 batch
(``hackerman-attack-class-distribution`` / ``hackerman-language-stats``)
operate on a single working-tree snapshot. This tool is the orthogonal
diff over time.

Inputs
~~~~~~

- ``--from <ref>``: baseline ref (default ``origin/main``)
- ``--to <ref>``: head ref (default ``HEAD``)
- ``--tags-prefix <path>``: corpus root inside the repo (default
  ``audit/corpus_tags/tags``)
- ``--repo <path>``: git repo path (default: tool's repo root)

Outputs
~~~~~~~

- Human table: rows = subtree, cols = (added, modified, deleted, total)
  sorted by total delta desc.
- JSON envelope ``auditooor.hackerman_corpus_diff.v1`` on ``--json``.

CLI examples
~~~~~~~~~~~~

  # default: origin/main vs HEAD, human table
  python3 tools/hackerman-corpus-diff.py

  # explicit refs, JSON
  python3 tools/hackerman-corpus-diff.py --from origin/main --to HEAD --json

  # alternate repo (used by tests)
  python3 tools/hackerman-corpus-diff.py --repo /tmp/repo
"""
from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_PREFIX = "audit/corpus_tags/tags"
SCHEMA = "auditooor.hackerman_corpus_diff.v1"


def _git(repo: Path, args: list[str]) -> str:
    """Run a git command, returning stdout (text). Raises CalledProcessError
    on failure so callers can decide whether to map to an envelope error."""
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout


def list_tree_blobs(repo: Path, ref: str, prefix: str) -> dict[str, str]:
    """Return ``{path: blob_oid}`` for every blob under ``prefix`` at ``ref``.

    Uses ``git ls-tree -r <ref> -- <prefix>`` which is O(tree-size) and
    avoids any working-tree state. Returned paths are repo-relative posix
    paths (forward slashes), already starting with ``<prefix>/``.
    """
    try:
        out = _git(repo, ["ls-tree", "-r", ref, "--", prefix])
    except RuntimeError:
        # Ref missing prefix entirely -> treat as empty tree.
        return {}
    blobs: dict[str, str] = {}
    for line in out.splitlines():
        # ls-tree format: <mode> SP <type> SP <oid> TAB <path>
        if "\t" not in line:
            continue
        meta, path = line.split("\t", 1)
        parts = meta.split()
        if len(parts) < 3 or parts[1] != "blob":
            continue
        blobs[path] = parts[2]
    return blobs


def _subtree_of(path: str, prefix: str) -> str:
    """Classify a repo-relative path into a subtree bucket.

    ``audit/corpus_tags/tags/lending_protocols/foo/record.yaml`` ->
    ``lending_protocols`` (the first directory under ``prefix``).
    ``audit/corpus_tags/tags/some-flat.yaml`` -> ``_flat`` (no subdir).
    Anything outside ``prefix`` -> ``_outside`` (defensive; ls-tree
    pathspec normally prevents this).
    """
    norm_prefix = prefix.rstrip("/") + "/"
    if not path.startswith(norm_prefix):
        return "_outside"
    rest = path[len(norm_prefix):]
    if "/" not in rest:
        return "_flat"
    return rest.split("/", 1)[0]


def build_diff(
    repo: Path,
    from_ref: str,
    to_ref: str,
    prefix: str = DEFAULT_TAGS_PREFIX,
) -> dict[str, Any]:
    """Build the diff envelope between ``from_ref`` and ``to_ref``.

    Classification per path:
      - in to but not in from -> ``added``
      - in from but not in to -> ``deleted``
      - in both with different OIDs -> ``modified``
      - in both with same OID -> skipped
    """
    base = list_tree_blobs(repo, from_ref, prefix)
    head = list_tree_blobs(repo, to_ref, prefix)

    # Per-subtree counters
    per: dict[str, dict[str, int]] = defaultdict(
        lambda: {"added": 0, "modified": 0, "deleted": 0, "total": 0}
    )

    all_paths = set(base) | set(head)
    totals = {"added": 0, "modified": 0, "deleted": 0, "total": 0}
    for path in all_paths:
        sub = _subtree_of(path, prefix)
        b = base.get(path)
        h = head.get(path)
        if b is None and h is not None:
            cat = "added"
        elif b is not None and h is None:
            cat = "deleted"
        elif b != h:
            cat = "modified"
        else:
            continue  # unchanged
        per[sub][cat] += 1
        per[sub]["total"] += 1
        totals[cat] += 1
        totals["total"] += 1

    # Resolve ref SHAs for provenance (best-effort)
    try:
        from_sha = _git(repo, ["rev-parse", from_ref]).strip()
    except RuntimeError:
        from_sha = ""
    try:
        to_sha = _git(repo, ["rev-parse", to_ref]).strip()
    except RuntimeError:
        to_sha = ""

    subtrees_sorted = sorted(
        per.items(),
        key=lambda kv: (-kv[1]["total"], kv[0]),
    )

    return {
        "schema": SCHEMA,
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": str(repo),
        "tags_prefix": prefix,
        "from_ref": from_ref,
        "from_sha": from_sha,
        "to_ref": to_ref,
        "to_sha": to_sha,
        "totals": totals,
        "subtrees": [
            {
                "subtree": name,
                "added": counts["added"],
                "modified": counts["modified"],
                "deleted": counts["deleted"],
                "total": counts["total"],
            }
            for name, counts in subtrees_sorted
        ],
    }


def render_table(diff: dict[str, Any]) -> str:
    """Render a markdown-style ASCII table for human consumption."""
    lines: list[str] = []
    lines.append(
        f"# hackerman-corpus-diff  {diff['from_ref']} -> {diff['to_ref']}"
    )
    lines.append(f"  from_sha={diff['from_sha'][:12]}  to_sha={diff['to_sha'][:12]}")
    t = diff["totals"]
    lines.append(
        f"  totals: added={t['added']}  modified={t['modified']}  "
        f"deleted={t['deleted']}  total={t['total']}"
    )
    lines.append("")
    if not diff["subtrees"]:
        lines.append("(no changes under tags prefix)")
        return "\n".join(lines)
    name_w = max(len(r["subtree"]) for r in diff["subtrees"])
    name_w = max(name_w, len("subtree"))
    header = (
        f"| {'subtree':<{name_w}} | added | modif. | del. | total |"
    )
    sep = (
        f"|{'-' * (name_w + 2)}|------:|-------:|-----:|------:|"
    )
    lines.append(header)
    lines.append(sep)
    for r in diff["subtrees"]:
        lines.append(
            f"| {r['subtree']:<{name_w}} | "
            f"{r['added']:>5} | {r['modified']:>6} | "
            f"{r['deleted']:>4} | {r['total']:>5} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Emit a per-subtree corpus diff between two git refs over "
            "audit/corpus_tags/tags/."
        ),
    )
    p.add_argument("--from", dest="from_ref", default="origin/main")
    p.add_argument("--to", dest="to_ref", default="HEAD")
    p.add_argument("--tags-prefix", default=DEFAULT_TAGS_PREFIX)
    p.add_argument("--repo", default=str(REPO_ROOT))
    p.add_argument("--json", action="store_true")
    p.add_argument("--out-json", default=None)
    args = p.parse_args(argv)

    repo = Path(args.repo).resolve()
    diff = build_diff(repo, args.from_ref, args.to_ref, args.tags_prefix)

    if args.out_json:
        out_path = Path(args.out_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(diff, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.json:
        sys.stdout.write(json.dumps(diff, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_table(diff) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
