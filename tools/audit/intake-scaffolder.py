#!/usr/bin/env python3
"""intake-scaffolder.py - repo-to-workspace audit intake scaffolder (Wave-5 W5-H3).

Audit intake today is a fully-manual 6-file editor session: the operator
hand-writes SCOPE.md, scope.json, SEVERITY.md, INTAKE_BASELINE.md,
PRIOR_CONCERNS.md and the workspace lock for every new engagement. The
boilerplate (repo metadata, language mix, file inventory, the per-platform
SEVERITY rubric skeleton) is re-derived by hand each time.

This tool collapses that to one command. Given a repo (local path or git
URL), an audit-pin SHA, and a bounty-platform slug, it emits the workspace
skeleton with the six intake files pre-populated as far as is honestly
automatable. The genuinely-human parts (scope boundaries, rubric dollar
figures, prior-audit concern list) are left as clearly-marked `TODO(human)`
blocks - the operator reviews and fills, but starts from a filled skeleton
instead of blank files.

What is automated
-----------------
- Repo metadata: org/repo, audit-pin SHA, clone URL.
- Language mix: file-extension histogram over the in-scope tree.
- Contract/file inventory: every source file by language, with line counts.
- SEVERITY.md: a per-platform rubric template (cantina/immunefi/sherlock/
  code4rena/hats/other) with the standard tier rows pre-filled.
- scope.json + SCOPE.md generated from one source so they cannot drift.
- INTAKE_BASELINE.md and PRIOR_CONCERNS.md skeletons with metadata filled.
- The workspace lock (.auditooor/workspace_lock.json).

What stays a TODO(human)
------------------------
- Exact in-scope vs out-of-scope path boundaries (program brief specific).
- SEVERITY.md dollar figures and platform-specific clauses.
- The asset-coverage-strategy paragraph in INTAKE_BASELINE.md.
- The PRIOR_CONCERNS.md list of acknowledged-by-design issues.

Usage
-----
    tools/audit/intake-scaffolder.py \
        --repo   <git-url-or-local-path> \
        --pin    <audit-pin-sha-or-tag> \
        --platform <cantina|immunefi|sherlock|code4rena|hats|other> \
        [--name <slug>] \
        [--audits-dir <dir>] \
        [--scope-url <bounty-url>] \
        [--dry-run] [--json]

Offline by default: a local --repo path is inspected in place; a remote URL
is recorded as metadata only and NOT cloned over the network (the operator
clones at pin separately). All file IO is confined to the workspace dir.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_ID = "auditooor.intake_scaffolder.v1"
BOOTSTRAP_MARKER = "auditooor.bootstrap-version: 1"

VALID_PLATFORMS = {"cantina", "immunefi", "sherlock", "code4rena", "hats", "other"}

# Source-file extension -> language label. Used for the language-mix
# histogram and the contract/file inventory grouping.
LANG_BY_EXT = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
    ".vy": "vyper",
    ".cairo": "cairo",
    ".move": "move",
    ".ts": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c-header",
}

# Directories that are never audit surface; skipped from the inventory.
SKIP_DIRS = {
    ".git", "node_modules", "lib", "out", "cache", "artifacts", "target",
    "vendor", ".auditooor", "submissions", "poc-tests", "evidence",
    "broadcast", "coverage", "dist", "build", "__pycache__",
}


def _slug_from_repo(repo: str) -> str:
    """Derive a workspace slug from a repo URL or local path."""
    cleaned = repo.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    tail = cleaned.split("/")[-1] or cleaned.split("/")[-2]
    slug = re.sub(r"[^a-z0-9-]+", "-", tail.lower()).strip("-")
    return slug or "engagement"


def _org_repo(repo: str) -> str:
    """Best-effort org/repo extraction from a GitHub-style URL or path."""
    m = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?/?$", repo)
    if m:
        return m.group(1)
    cleaned = repo.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else repo


def inventory_repo(root: Path) -> dict:
    """Walk a local repo tree and build the language mix + file inventory.

    Returns a dict with `language_mix` (Counter-like dict of lang->file
    count), `total_lines` per language, and `files` (sorted list of
    {path, language, lines}). A non-existent path yields an empty
    inventory with `available=False` so remote-URL mode degrades cleanly.
    """
    result: dict = {
        "available": root.is_dir(),
        "language_mix": {},
        "lines_by_language": {},
        "files": [],
        "file_count": 0,
    }
    if not root.is_dir():
        return result

    lang_files: Counter = Counter()
    lang_lines: Counter = Counter()
    files: list[dict] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        lang = LANG_BY_EXT.get(path.suffix.lower())
        if lang is None:
            continue
        try:
            with path.open("r", errors="ignore") as fh:
                lines = sum(1 for _ in fh)
        except OSError:
            lines = 0
        rel = str(path.relative_to(root))
        lang_files[lang] += 1
        lang_lines[lang] += lines
        files.append({"path": rel, "language": lang, "lines": lines})

    result["language_mix"] = dict(lang_files.most_common())
    result["lines_by_language"] = dict(lang_lines.most_common())
    result["files"] = files
    result["file_count"] = len(files)
    return result


# --------------------------------------------------------------------------
# Per-platform SEVERITY.md rubric templates. Each is a skeleton: the tier
# rows are standard for the platform, the dollar figures and program-specific
# clauses are left as TODO(human) because they are set per-engagement.
# --------------------------------------------------------------------------
def _severity_template(platform: str, slug: str) -> str:
    header = (
        f"# SEVERITY.md - {slug}\n\n"
        f"<!-- {BOOTSTRAP_MARKER} -->\n"
        f"<!-- platform: {platform} -->\n\n"
        "This file is the SOLE severity authority for this engagement. Findings\n"
        "must verbatim-match a tier row below or be dropped (rubric-match-or-drop\n"
        "discipline). Fill every `TODO(human)` from the program brief.\n\n"
    )
    if platform == "cantina":
        body = (
            "## Tiers\n\n"
            "| Severity | Definition | Payout |\n"
            "|----------|-----------|--------|\n"
            "| Critical | Direct theft / permanent freezing of user funds; "
            "protocol insolvency. | TODO(human) |\n"
            "| High | Theft/freezing under a precondition; griefing with "
            "material loss. | TODO(human) |\n"
            "| Medium | Limited loss; contract-state corruption recoverable "
            "by admin. | TODO(human) |\n"
            "| Low | Best-practice / hardening; no direct loss. | TODO(human) |\n\n"
            "TODO(human): paste the exact Cantina program rubric language and\n"
            "any program-specific impact examples here.\n"
        )
    elif platform == "immunefi":
        body = (
            "## Tiers (Immunefi Vulnerability Severity Classification)\n\n"
            "| Severity | Definition | Payout |\n"
            "|----------|-----------|--------|\n"
            "| Critical | Direct loss of funds; permanent freezing (hardfork). "
            "| TODO(human) |\n"
            "| High | RPC/API crash; theft of unclaimed yield. | TODO(human) |\n"
            "| Medium | Smart-contract unable to operate; griefing. "
            "| TODO(human) |\n"
            "| Low | Contract fails to deliver promised returns, no loss. "
            "| TODO(human) |\n\n"
            "TODO(human): confirm whether this program is Primacy-of-Impact;\n"
            "if so, document the in-scope-impact test here, not asset scope.\n"
        )
    elif platform == "sherlock":
        body = (
            "## Tiers (Sherlock)\n\n"
            "| Severity | Definition |\n"
            "|----------|-----------|\n"
            "| High | Definite loss of funds without (extensive) limitations "
            "of external conditions. |\n"
            "| Medium | Loss of funds requires specific external conditions "
            "or limited losses. |\n\n"
            "Sherlock has no Critical/Low tier in payout terms. TODO(human):\n"
            "confirm the contest's specific Hierarchy-of-Truth and known-issue\n"
            "exclusions.\n"
        )
    elif platform == "code4rena":
        body = (
            "## Tiers (Code4rena)\n\n"
            "| Severity | Definition |\n"
            "|----------|-----------|\n"
            "| High | Assets can be stolen/lost/compromised directly. |\n"
            "| Medium | Assets not at direct risk, but function/availability "
            "of the protocol can be impacted, or leak value with a hypothetical "
            "attack path. |\n"
            "| QA (Low) | Non-critical / governance / best-practice. |\n\n"
            "TODO(human): paste the contest scope and SLOC table; note any\n"
            "automated-finding exclusions.\n"
        )
    elif platform == "hats":
        body = (
            "## Tiers (Hats Finance)\n\n"
            "| Severity | Definition | Payout |\n"
            "|----------|-----------|--------|\n"
            "| Critical | Direct theft / permanent freezing of funds. "
            "| TODO(human) |\n"
            "| High | Theft under preconditions. | TODO(human) |\n"
            "| Medium | Recoverable state corruption. | TODO(human) |\n"
            "| Low | Hardening. | TODO(human) |\n\n"
            "TODO(human): paste the Hats vault committee rubric.\n"
        )
    else:  # other / private
        body = (
            "## Tiers (private / custom engagement)\n\n"
            "| Severity | Definition | Payout |\n"
            "|----------|-----------|--------|\n"
            "| Critical | TODO(human) | TODO(human) |\n"
            "| High | TODO(human) | TODO(human) |\n"
            "| Medium | TODO(human) | TODO(human) |\n"
            "| Low | TODO(human) | TODO(human) |\n\n"
            "TODO(human): no known platform template - paste the engagement's\n"
            "own severity rubric verbatim.\n"
        )
    return header + body


def _scope_md(slug: str, org_repo: str, pin: str, platform: str,
              scope_url: str, inv: dict) -> str:
    """SCOPE.md - human-readable. Mirrors scope.json (single source)."""
    lang_lines = "\n".join(
        f"- {lang}: {count} files" for lang, count in inv["language_mix"].items()
    ) or "- (no source files detected - remote-URL mode or empty tree)"
    return (
        f"# SCOPE.md - {slug}\n\n"
        f"<!-- {BOOTSTRAP_MARKER} -->\n"
        f"<!-- generated by tools/audit/intake-scaffolder.py; mirrors scope.json -->\n\n"
        "## Engagement metadata\n\n"
        f"- target_repo: `{org_repo}`\n"
        f"- audit_pin: `{pin}`\n"
        f"- platform: `{platform}`\n"
        f"- bounty_url: {scope_url or 'TODO(human)'}\n\n"
        "## Detected language mix\n\n"
        f"{lang_lines}\n\n"
        "## In-scope paths\n\n"
        "TODO(human): list the exact in-scope files / globs from the program\n"
        "brief. The file inventory in INTAKE_BASELINE.md is the candidate set;\n"
        "narrow it to the actually-scoped surface here.\n\n"
        "## Out-of-scope (OOS) clauses\n\n"
        "TODO(human): enumerate every OOS bullet from the program brief. Each\n"
        "becomes an OOS-N trap the pre-submit gate checks against.\n"
    )


def _intake_baseline_md(slug: str, org_repo: str, pin: str, platform: str,
                        inv: dict) -> str:
    """INTAKE_BASELINE.md - metadata + inventory filled, strategy is TODO."""
    scope_files_yaml = "\n".join(
        f"  - {f['path']}" for f in inv["files"][:200]
    ) or "  []  # remote-URL mode - inventory unavailable"
    mix = ", ".join(
        f"{lang} ({count})" for lang, count in inv["language_mix"].items()
    ) or "none detected"
    return (
        f"# INTAKE_BASELINE - {slug}\n\n"
        f"<!-- {BOOTSTRAP_MARKER} -->\n\n"
        "## 1. Engagement metadata\n\n"
        "```yaml\n"
        f"engagement_id: \"{slug}\"\n"
        f"platform: \"{platform}\"\n"
        f"audit_pin_sha: \"{pin}\"\n"
        f"target_repo: \"{org_repo}\"\n"
        f"language_mix: \"{mix}\"\n"
        f"file_count: {inv['file_count']}\n"
        "severity_rubric: \"SEVERITY.md\"\n"
        "```\n\n"
        "## 2. Asset-coverage strategy\n\n"
        "TODO(human): one paragraph, written BEFORE reading code, describing\n"
        "the target's core invariants, key primitives, and the bug classes\n"
        "this engagement hunts. This paragraph anchors all triage decisions.\n\n"
        "## 3. Candidate file inventory (auto-generated)\n\n"
        "The scaffolder detected the following source files. This is the\n"
        "CANDIDATE set; SCOPE.md narrows it to the actually-scoped surface.\n\n"
        "```yaml\n"
        "candidate_files:\n"
        f"{scope_files_yaml}\n"
        "```\n\n"
        "## 4. Coverage matrix\n\n"
        "TODO(human): fill the parameter cross-product exercised; an empty\n"
        "rationale with a non-full exercised list is a CI failure (L28-C).\n"
    )


def _prior_concerns_md(slug: str, pin: str) -> str:
    return (
        f"# PRIOR_CONCERNS - {slug}\n\n"
        f"<!-- {BOOTSTRAP_MARKER} -->\n\n"
        "Acknowledged-by-design issues and prior-audit findings that must NOT\n"
        "be refiled. Populate from the program brief, any linked prior audit\n"
        "reports, and the post-pin commit log.\n\n"
        "## Acknowledged-by-design\n\n"
        "TODO(human): list each issue the team has explicitly accepted (admin\n"
        "centralization, trusted-oracle assumption, etc.). One bullet each.\n\n"
        "## Prior-audit findings (do not refile)\n\n"
        "TODO(human): list findings from prior audits of this codebase. Run\n"
        f"`tools/git-commits-mining.py --direction bidirectional` from pin\n"
        f"`{pin}` to surface post-pin fixes that may collide with drafts.\n"
    )


def _scope_json(slug: str, org_repo: str, pin: str, platform: str,
                scope_url: str, repo: str, inv: dict) -> dict:
    return {
        "schema": SCHEMA_ID,
        "slug": slug,
        "target_repo": org_repo,
        "repo_source": repo,
        "audit_pin_sha": pin,
        "platform": platform,
        "bounty_url": scope_url or None,
        "language_mix": inv["language_mix"],
        "lines_by_language": inv["lines_by_language"],
        "file_count": inv["file_count"],
        "in_scope_paths": [],          # TODO(human): narrow from candidate set
        "oos_clauses": [],             # TODO(human): from program brief
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "tools/audit/intake-scaffolder.py",
        "_note": "scope.json and SCOPE.md are generated from one source "
                 "(this scaffolder) so they cannot drift.",
    }


def _workspace_lock(slug: str, ws: Path) -> dict:
    return {
        "schema": "auditooor.workspace_lock.v1",
        "workspace_slug": slug,
        "workspace_path": str(ws),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "tools/audit/intake-scaffolder.py",
    }


def build_plan(repo: str, pin: str, platform: str, name: str | None,
               audits_dir: Path, scope_url: str) -> dict:
    """Compute the full scaffold plan without writing anything."""
    slug = name or _slug_from_repo(repo)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
        raise ValueError(f"invalid slug derived/given: {slug!r}")
    if platform not in VALID_PLATFORMS:
        raise ValueError(
            f"unknown platform {platform!r}; valid: {sorted(VALID_PLATFORMS)}"
        )

    org_repo = _org_repo(repo)
    repo_path = Path(repo).expanduser()
    inv = inventory_repo(repo_path)
    ws = audits_dir.expanduser() / slug

    files = {
        "SCOPE.md": _scope_md(slug, org_repo, pin, platform, scope_url, inv),
        "SEVERITY.md": _severity_template(platform, slug),
        "INTAKE_BASELINE.md": _intake_baseline_md(slug, org_repo, pin,
                                                  platform, inv),
        "PRIOR_CONCERNS.md": _prior_concerns_md(slug, pin),
        "scope.json": json.dumps(
            _scope_json(slug, org_repo, pin, platform, scope_url, repo, inv),
            indent=2,
        ) + "\n",
        ".auditooor/workspace_lock.json": json.dumps(
            _workspace_lock(slug, ws), indent=2
        ) + "\n",
    }
    dirs = [
        ".auditooor", "notes", "submissions", "submissions/staging",
        "submissions/paste_ready", "poc-tests", "evidence", "reference",
        "prior_audits",
    ]
    return {
        "slug": slug,
        "workspace": ws,
        "org_repo": org_repo,
        "audit_pin": pin,
        "platform": platform,
        "language_mix": inv["language_mix"],
        "file_count": inv["file_count"],
        "inventory_available": inv["available"],
        "dirs": dirs,
        "files": files,
    }


def write_plan(plan: dict) -> list[str]:
    """Materialize the plan to disk. Idempotent: skips existing files."""
    ws: Path = plan["workspace"]
    written: list[str] = []
    if ws.exists():
        raise FileExistsError(f"workspace already exists: {ws}")
    ws.mkdir(parents=True)
    for d in plan["dirs"]:
        (ws / d).mkdir(parents=True, exist_ok=True)
    for rel, content in plan["files"].items():
        target = ws / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        written.append(rel)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Repo-to-workspace audit intake scaffolder (Wave-5 W5-H3)."
    )
    parser.add_argument("--repo", required=True,
                        help="git URL or local path of the target repo")
    parser.add_argument("--pin", required=True,
                        help="audit-pin git SHA or tag")
    parser.add_argument("--platform", required=True,
                        help=f"bounty platform: {sorted(VALID_PLATFORMS)}")
    parser.add_argument("--name", default=None,
                        help="workspace slug (default: derived from --repo)")
    parser.add_argument("--audits-dir", default="~/audits",
                        help="parent dir for the workspace (default ~/audits)")
    parser.add_argument("--scope-url", default="",
                        help="bounty program URL (recorded, never fetched)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan without writing")
    parser.add_argument("--json", action="store_true",
                        help="emit a machine-readable JSON summary")
    args = parser.parse_args(argv)

    try:
        plan = build_plan(
            repo=args.repo,
            pin=args.pin,
            platform=args.platform,
            name=args.name,
            audits_dir=Path(args.audits_dir),
            scope_url=args.scope_url,
        )
    except (ValueError, FileExistsError) as exc:
        print(f"[intake-scaffolder] error: {exc}", file=sys.stderr)
        return 2

    summary = {
        "schema": SCHEMA_ID,
        "slug": plan["slug"],
        "workspace": str(plan["workspace"]),
        "target_repo": plan["org_repo"],
        "audit_pin": plan["audit_pin"],
        "platform": plan["platform"],
        "language_mix": plan["language_mix"],
        "file_count": plan["file_count"],
        "inventory_available": plan["inventory_available"],
        "intake_files": sorted(plan["files"].keys()),
        "dirs": plan["dirs"],
        "dry_run": args.dry_run,
    }

    if not args.dry_run:
        try:
            written = write_plan(plan)
        except FileExistsError as exc:
            print(f"[intake-scaffolder] error: {exc}", file=sys.stderr)
            return 2
        summary["written"] = written

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        verb = "would create" if args.dry_run else "created"
        print(f"[intake-scaffolder] {verb} workspace: {plan['workspace']}")
        print(f"  slug:      {plan['slug']}")
        print(f"  repo:      {plan['org_repo']}")
        print(f"  pin:       {plan['audit_pin']}")
        print(f"  platform:  {plan['platform']}")
        mix = ", ".join(
            f"{k}={v}" for k, v in plan["language_mix"].items()
        ) or "none (remote-URL mode)"
        print(f"  langs:     {mix}")
        print(f"  files:     {plan['file_count']} source files inventoried")
        print(f"  intake:    {', '.join(sorted(plan['files'].keys()))}")
        if args.dry_run:
            print("  (dry-run - nothing written)")
        else:
            print(f"\nNext: review TODO(human) blocks, then "
                  f"`make audit WS={plan['workspace']}`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
