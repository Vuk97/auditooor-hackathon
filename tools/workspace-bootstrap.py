#!/usr/bin/env python3
"""workspace-bootstrap.py — scaffold a new engagement workspace.

Reduces operator friction for starting a new engagement. Creates the
minimal `~/audits/<name>/` tree the rest of the auditooor toolchain
expects, seeded with a SCOPE.md header that records the scope URL and
platform for operator reference.

Two operator surfaces are exposed by this tool:

1.  Slug + platform mode (the original ITER-7 flow). Creates the workspace
    directory tree itself.

2.  Engage-stubs mode (V5-P0-06 / Gap 16). Operates on an *existing*
    workspace path and seeds the minimal stubs the engage chain expects so
    that ``make audit WS=<ws>`` does not deadlock on missing files. The
    stubs are idempotent: each stub is written only when absent, and each
    one carries a machine-readable ``auditooor.bootstrap-version: 1``
    marker so re-runs become no-ops without destroying operator content.

Usage
-----

    # New-engagement scaffold (original ITER-7 flow)
    tools/workspace-bootstrap.py \
        --name   <project-slug> \
        --platform <hackenproof|cantina|sherlock|immunefi|other> \
        --scope-url <url> \
        [--severity-rubric <path>] \
        [--audits-dir <dir>] \
        [--dry-run]

    # Engage-stubs idempotent seeding (V5-P0-06 / Gap 16)
    tools/workspace-bootstrap.py \
        --engage-stubs <workspace> \
        [--dry-run]

Inputs
------

    --name              Required. Slug format `[a-z0-9-]+`.
    --platform          Required. Must be in track-submissions.py's
                        VALID_PLATFORMS.
    --scope-url         Required. Written into SCOPE.md header. Never
                        fetched over the network.
    --severity-rubric   Optional. A path to a local rubric file, copied
                        into the new workspace as `severity-rubric.md`.
    --audits-dir        Default `~/audits/`. The parent directory the
                        workspace is created under.
    --dry-run           Print the plan of files/dirs that would be
                        created; do not touch the filesystem.

Outputs
-------

    <audits-dir>/<name>/
        SCOPE.md                  (template with scope-url + platform)
        reference/
            outcomes.jsonl        (empty)
        submissions/
            staging/              (empty)
            packaged/             (empty)
        agent_outputs/            (empty)
        BOOTSTRAP_ITER7.md        (timestamp + args)

Failure modes
-------------

    * `<audits-dir>/<name>/` already exists  -> exit 2, no writes.
    * `--name` not slug-safe                 -> exit 2.
    * `--platform` not in allowlist          -> exit 2.
    * `--severity-rubric` path does not exist -> exit 2.
    * `--scope-url` blank                    -> argparse error.

Hard rules
----------

    * No network fetch. The tool only records the URL in SCOPE.md.
    * No `git init`. Operator decides.
    * No status vocabulary emission. BOOTSTRAP_ITER7.md records metadata
      only; the ledger status vocabulary is managed by
      track-submissions.py.
    * No `--force` flag. Refusal on existing dir is absolute this iter.

Truth-audit
-----------

    1. Overclaim risk: "bootstrap succeeded" does NOT mean the workspace
       is engagement-ready — SCOPE.md contains TODOs the operator must
       fill in from the live scope URL. BOOTSTRAP_ITER7.md flags this.
    2. Status vocabulary: tool emits no tokens that collide with the
       submission ledger's locked `{pending, accepted, paid, duplicate,
       rejected}` set.
    3. Artifact classification: SCOPE.md + BOOTSTRAP_ITER7.md are
       operator notes, not proof of anything.
    4. Cannot-judge behaviour: `--dry-run` prints the plan + exits 0
       without writing.
    5. Duplicate guard: re-running into an existing `<name>/` exits 2
       without overwriting, preserving whatever state is already there.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Platform allowlist — imported from track-submissions.py so the two
# never drift. The hyphen in the filename blocks a plain `import`, so we
# load the module by path.
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent


def _load_valid_platforms() -> Set[str]:
    """Return the VALID_PLATFORMS set from track-submissions.py."""
    path = _THIS_DIR / "track-submissions.py"
    spec = importlib.util.spec_from_file_location("track_submissions", path)
    if spec is None or spec.loader is None:
        # Fall back to a hardcoded mirror if the import ever breaks. Kept
        # in sync with tools/track-submissions.py VALID_PLATFORMS.
        return {"hackenproof", "cantina", "sherlock", "immunefi", "other"}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(getattr(module, "VALID_PLATFORMS"))


VALID_PLATFORMS = _load_valid_platforms()

# Slug format: lowercase letters, digits, hyphens. Must start with
# alphanumeric (so leading hyphen like `-foo` is rejected). Length 1+.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


# ---------------------------------------------------------------------------
# SCOPE.md template
# ---------------------------------------------------------------------------

SCOPE_TEMPLATE = """# {name} Audit Scope

**Platform**: {platform}
**Scope URL**: {scope_url}
**Bootstrapped**: {timestamp} via `tools/workspace-bootstrap.py`

## In-scope contracts

<TODO: fill in from scope URL>

## Out-of-scope

<TODO: fill in>

## Severity rubric

See `{platform}`'s default rubric unless operator provides a custom one.{rubric_note}

## Acceptance criteria

<TODO: from bounty platform>
"""


BOOTSTRAP_META_TEMPLATE = """# Bootstrap metadata (iter7 T5)

This workspace was scaffolded by `tools/workspace-bootstrap.py`. The tool
writes the directory shape + a SCOPE.md header and stops. It does NOT:

- fetch scope data from the `--scope-url` (no network call),
- initialise git in this workspace,
- emit any submission-ledger status tokens.

To make this workspace engagement-ready, the operator still needs to:

1. Fill in `SCOPE.md` §"In-scope contracts" / §"Out-of-scope" /
   §"Acceptance criteria" from the live bounty page.
2. Clone the target repo under this workspace (convention: `src/`).
3. Run CCIA + mining-prioritizer via `make audit WS=<this-dir>` or the
   individual stage entrypoints.
4. Wire `reference/outcomes.jsonl` into telemetry via
   `tools/track-submissions.py record`.

## Bootstrap arguments

| key | value |
|---|---|
| name | {name} |
| platform | {platform} |
| scope_url | {scope_url} |
| severity_rubric | {severity_rubric} |
| audits_dir | {audits_dir} |
| timestamp (UTC) | {timestamp} |
"""


# ---------------------------------------------------------------------------
# Plan / execution
# ---------------------------------------------------------------------------

def _planned_dirs(workspace: Path) -> List[Path]:
    return [
        workspace,
        workspace / "reference",
        workspace / "submissions",
        workspace / "submissions" / "staging",
        workspace / "submissions" / "packaged",
        workspace / "agent_outputs",
    ]


def _planned_files(
    workspace: Path,
    severity_rubric: Optional[Path],
) -> List[Path]:
    files = [
        workspace / "SCOPE.md",
        workspace / "reference" / "outcomes.jsonl",
        workspace / "BOOTSTRAP_ITER7.md",
    ]
    if severity_rubric is not None:
        files.append(workspace / "severity-rubric.md")
    return files


def _render_scope_md(
    name: str,
    platform: str,
    scope_url: str,
    timestamp: str,
    severity_rubric: Optional[Path],
) -> str:
    rubric_note = (
        f" Operator-supplied rubric copied to `severity-rubric.md`"
        f" (source: `{severity_rubric}`)."
        if severity_rubric is not None
        else ""
    )
    return SCOPE_TEMPLATE.format(
        name=name,
        platform=platform,
        scope_url=scope_url,
        timestamp=timestamp,
        rubric_note=rubric_note,
    )


def _render_bootstrap_meta(
    name: str,
    platform: str,
    scope_url: str,
    severity_rubric: Optional[Path],
    audits_dir: Path,
    timestamp: str,
) -> str:
    return BOOTSTRAP_META_TEMPLATE.format(
        name=name,
        platform=platform,
        scope_url=scope_url,
        severity_rubric=str(severity_rubric) if severity_rubric else "<none>",
        audits_dir=str(audits_dir),
        timestamp=timestamp,
    )


def _print_plan(
    workspace: Path,
    severity_rubric: Optional[Path],
    out=None,
) -> None:
    # Default resolved at call time so stdout redirects (used in tests)
    # are honoured.
    if out is None:
        out = sys.stdout
    print(f"[workspace-bootstrap] DRY RUN — no filesystem writes.", file=out)
    print(f"Workspace root: {workspace}", file=out)
    print("Directories that would be created:", file=out)
    for d in _planned_dirs(workspace):
        print(f"  mkdir {d}", file=out)
    print("Files that would be created:", file=out)
    for f in _planned_files(workspace, severity_rubric):
        print(f"  write {f}", file=out)
    if severity_rubric is not None:
        print(
            f"  copy  {severity_rubric} -> "
            f"{workspace / 'severity-rubric.md'}",
            file=out,
        )


def _execute_plan(
    workspace: Path,
    scope_md: str,
    meta_md: str,
    severity_rubric: Optional[Path],
    complete_existing: bool = False,
) -> None:
    # complete_existing (=--force): scaffold an EXISTING workspace idempotently
    # and non-destructively. Dirs are created exist_ok; seed files are written
    # only when absent so prior_audits/, .auditooor/, src/ and an already-authored
    # SCOPE.md / targets.tsv are never clobbered (R55 sibling-preservation).
    for d in _planned_dirs(workspace):
        d.mkdir(parents=True, exist_ok=complete_existing)

    def _write_if_appropriate(path: Path, content: str) -> None:
        if complete_existing and path.exists():
            return
        path.write_text(content)

    _write_if_appropriate(workspace / "SCOPE.md", scope_md)
    # Empty JSONL stream — outcomes.jsonl is append-only, so we start
    # with a genuine zero-length file, not a file with an empty line.
    _write_if_appropriate(workspace / "reference" / "outcomes.jsonl", "")
    _write_if_appropriate(workspace / "BOOTSTRAP_ITER7.md", meta_md)

    # r36-rebuttal: lane gap-fix-ni-bootstrap-2026-05-28
    # CAP-GAP-NI-1: emit targets.tsv stub so `make audit` finds the file
    # (otherwise audit-target-commit-mining fails immediately). Operator
    # still has to fill in real repo URLs + pinned commits, but the file
    # is present with the canonical 3-column comment-header schema.
    targets_path = workspace / "targets.tsv"
    if not targets_path.exists():
        targets_path.write_text(_stub_targets_tsv())

    if severity_rubric is not None:
        dest = workspace / "severity-rubric.md"
        if not (complete_existing and dest.exists()):
            dest.write_text(severity_rubric.read_text())


# ---------------------------------------------------------------------------
# Engage-stubs (V5-P0-06 / Gap 16)
# ---------------------------------------------------------------------------
#
# `make audit WS=<ws>` and the engage chain expect a handful of operator
# files to exist in the workspace before downstream stages can run truthfully.
# A fresh workspace from `--name`/`--platform` mode does not seed all of
# them, and operators were filing 9+ stub files by hand to unblock Monetrix.
# This block ships idempotent stub seeding.
#
# Each stub carries a machine-readable marker line:
#
#     <!-- auditooor.bootstrap-version: 1 -->
#
# Re-runs detect that marker and skip the stub. Operator-edited files (no
# marker, or content that no longer matches the stub template) are left
# untouched — bootstrap NEVER overwrites without explicit operator request.
#
# Targets.tsv is the only non-Markdown stub: it uses a `#` comment marker
# in the same `auditooor.bootstrap-version: 1` namespace.

BOOTSTRAP_VERSION = 1
BOOTSTRAP_MARKER_MD = (
    "<!-- auditooor.bootstrap-version: {ver} -->"
).format(ver=BOOTSTRAP_VERSION)
BOOTSTRAP_MARKER_HASH = (
    "# auditooor.bootstrap-version: {ver}"
).format(ver=BOOTSTRAP_VERSION)


def _stub_md(title: str, body_lines: List[str]) -> str:
    """Render a minimal-valid Markdown stub with the bootstrap marker."""
    parts = [
        f"# {title}",
        "",
        BOOTSTRAP_MARKER_MD,
        "",
        "TBD — operator edit.",
        "",
    ]
    parts.extend(body_lines)
    if parts[-1] != "":
        parts.append("")
    return "\n".join(parts)


def _stub_targets_tsv() -> str:
    return "\n".join([
        BOOTSTRAP_MARKER_HASH,
        "# targets.tsv - one in-scope GitHub repository per row.",
        "# Required before make audit: repo_url<TAB>pinned_40_hex_commit<TAB>local_name.",
        "# Example: https://github.com/owner/repo.git<TAB><40-hex-sha><TAB>repo",
        "# TBD - operator edit; remove this header once real rows are added.",
        "",
    ])


# Stub catalog. Each entry: relative path, render fn (no args), short label
# used in dry-run / progress output. Order matches the V5-P0-06 spec.
ENGAGE_STUB_CATALOG: List[Tuple[str, str, str]] = [
    (
        "SCOPE.md",
        "scope",
        "scope contracts and bounty references",
    ),
    (
        "AUDIT.md",
        "audit-notes",
        "audit running notes",
    ),
    (
        "SESSION_LOG.md",
        "session-log",
        "per-session timeline (operator log)",
    ),
    (
        "FINDINGS.md",
        "findings",
        "candidate / verified findings ledger",
    ),
    (
        "SEVERITY.md",
        "severity",
        "per-finding severity rationale ledger",
    ),
    (
        "RUBRIC_COVERAGE.md",
        "rubric-coverage",
        "severity-rubric coverage tracker",
    ),
    (
        "targets.tsv",
        "targets",
        "in-scope contract list (engage stage 6+)",
    ),
    (
        "SEVERITY_CAPS.md",
        "severity-caps",
        "machine-readable severity caps (consumed by extract-oos.sh / "
        "llm-scope-triage)",
    ),
    (
        "OOS_CHECKLIST.md",
        "oos-checklist",
        "out-of-scope guardrails (consumed by dispatch-brief / "
        "llm-scope-triage)",
    ),
    (
        "concolic/SUMMARY.md",
        "concolic-summary",
        "concolic / symbolic deep-profile summary",
    ),
    (
        "economic_hypotheses.md",
        "economic-hypotheses",
        "economic-attack hypothesis sheet (engage stage 16)",
    ),
]


def _render_engage_stub(rel_path: str) -> str:
    """Render the stub content for a given catalog entry."""
    if rel_path == "SCOPE.md":
        return _stub_md(
            "Audit scope",
            [
                "## In-scope contracts",
                "",
                "<TODO: list contracts / addresses / commits in scope>",
                "",
                "## Out-of-scope",
                "",
                "<TODO: list explicit OOS surfaces / prior-known issues>",
                "",
                "## Acceptance criteria",
                "",
                "<TODO: from bounty platform>",
            ],
        )
    if rel_path == "AUDIT.md":
        return _stub_md(
            "Audit running notes",
            [
                "## Day 1",
                "",
                "<TODO: hypotheses, surface map, leads>",
            ],
        )
    if rel_path == "SESSION_LOG.md":
        return _stub_md(
            "Session log",
            [
                "| ts | event | notes |",
                "|---|---|---|",
                "| TBD | start | <operator edit> |",
            ],
        )
    if rel_path == "FINDINGS.md":
        return _stub_md(
            "Findings ledger",
            [
                "| id | severity | status | summary |",
                "|---|---|---|---|",
                "| F-1 | TBD | candidate | <operator edit> |",
            ],
        )
    if rel_path == "SEVERITY.md":
        return _stub_md(
            "Severity rationale",
            [
                "## Severity decisions",
                "",
                "| finding | severity | rubric-tag | rationale |",
                "|---|---|---|---|",
                "| TBD | TBD | TBD | <operator edit> |",
            ],
        )
    if rel_path == "RUBRIC_COVERAGE.md":
        return _stub_md(
            "Rubric coverage",
            [
                "## Coverage tracker",
                "",
                "| rubric-tag | covered? | evidence |",
                "|---|---|---|",
                "| TBD | no | <operator edit> |",
            ],
        )
    if rel_path == "targets.tsv":
        return _stub_targets_tsv()
    if rel_path == "SEVERITY_CAPS.md":
        return _stub_md(
            "Severity caps",
            [
                "## Caps",
                "",
                "<!-- machine-readable cap rows; consumed by extract-oos.sh -->",
                "<!-- format: SEV-CAP: <rubric-tag>: <cap> -->",
                "SEV-CAP: TBD: TBD",
            ],
        )
    if rel_path == "OOS_CHECKLIST.md":
        return _stub_md(
            "Out-of-scope checklist",
            [
                "## OOS bullets",
                "",
                "<!-- machine-readable rows; consumed by dispatch-brief, "
                "llm-scope-triage, pre-submit gates. -->",
                "- OOS-1: TBD — <operator edit>",
            ],
        )
    if rel_path == "concolic/SUMMARY.md":
        return _stub_md(
            "Concolic / symbolic summary",
            [
                "## Symbolic / concolic results",
                "",
                "<TODO: populate after `make audit-deep`-style runs.>",
                "",
                "Status: stub.",
            ],
        )
    if rel_path == "economic_hypotheses.md":
        return _stub_md(
            "Economic hypotheses",
            [
                "## Hypotheses",
                "",
                "<TODO: enumerate plausible economic-attack paths. "
                "Generated by stage 16 (`economic-hypotheses.sh`); "
                "operator may seed leads here in advance.>",
            ],
        )
    raise KeyError(f"unknown engage stub: {rel_path!r}")


def plan_engage_stubs(
    workspace: Path,
) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]:
    """Return (will_create, will_skip) for the engage-stub plan.

    ``will_create`` is rows whose target file does not yet exist.
    ``will_skip`` is rows whose target already exists (kept either because
    operator content is present, or because a previous bootstrap run wrote
    a marker-tagged stub).
    """
    will_create: List[Tuple[str, str, str]] = []
    will_skip: List[Tuple[str, str, str]] = []
    for rel, label, desc in ENGAGE_STUB_CATALOG:
        target = workspace / rel
        if target.exists():
            will_skip.append((rel, label, desc))
        else:
            will_create.append((rel, label, desc))
    return will_create, will_skip


def execute_engage_stubs(workspace: Path) -> List[Tuple[str, str]]:
    """Materialize missing stubs in `workspace`. Return list of
    (relative_path, action) where action is "created" or "skipped".

    Idempotency contract:
      * Stubs whose target file already exists are NOT overwritten.
        We never look inside the file to decide; existence alone is the
        skip signal. Operator content always wins.
      * Bootstrap will create parent directories (e.g. `concolic/`) only
        when needed.
    """
    if not workspace.is_dir():
        raise FileNotFoundError(
            f"engage-stubs target workspace does not exist: {workspace}"
        )

    actions: List[Tuple[str, str]] = []
    for rel, _label, _desc in ENGAGE_STUB_CATALOG:
        target = workspace / rel
        if target.exists():
            actions.append((rel, "skipped"))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_render_engage_stub(rel))
        actions.append((rel, "created"))
    return actions


def _print_engage_plan(
    workspace: Path,
    will_create: List[Tuple[str, str, str]],
    will_skip: List[Tuple[str, str, str]],
    out=None,
) -> None:
    if out is None:
        out = sys.stdout
    print(f"[workspace-bootstrap engage-stubs] DRY RUN — no writes.", file=out)
    print(f"Workspace: {workspace}", file=out)
    if will_create:
        print("Stubs that would be created:", file=out)
        for rel, _label, desc in will_create:
            print(f"  write {workspace / rel}    # {desc}", file=out)
    else:
        print("No stubs to create (all already present).", file=out)
    if will_skip:
        print("Stubs already present (left untouched):", file=out)
        for rel, _label, _desc in will_skip:
            print(f"  skip  {workspace / rel}", file=out)


# ---------------------------------------------------------------------------
# Hyperbridge sp1-beefy private-dep patches (CAPABILITY-GAP-6)
# ---------------------------------------------------------------------------
#
# Hyperbridge's `tesseract/consensus/beefy/zk` crate depends on
# `polytope-labs/sp1-beefy.git` via `ssh://git@github.com/...`, which
# blocks `cargo metadata` for any tool that does not have authenticated
# SSH access. This unblocks every metadata-driven capability lane that
# operates on the hyperbridge tree (predicate runner, dependency-graph
# audit, etc.). The rewrite replaces the two `[dependencies.sp1-beefy*]`
# blocks in that Cargo.toml with `path = "<stub>"` references to two
# minimal stub crates the bootstrapper writes under `<hyperbridge>/stubs/`.
#
# See `tools/templates/hyperbridge_cargo_config.toml` for the full
# rationale and the template documentation.

HYPERBRIDGE_PATCH_VERSION = 1
HYPERBRIDGE_PATCH_MARKER_BEGIN = (
    "# auditooor.hyperbridge-cargo-patch-version: "
    "{ver}".format(ver=HYPERBRIDGE_PATCH_VERSION)
)
HYPERBRIDGE_PATCH_MARKER_END = "# auditooor.hyperbridge-cargo-patch-end"

# Targets the bootstrapper looks for to confirm a workspace contains a
# hyperbridge tree (any one is sufficient). The tree must contain the
# consuming Cargo.toml; if it does not, the run fails with a clear error
# so the operator does not silently no-op against an unrelated workspace.
HYPERBRIDGE_DETECT_PATHS = (
    Path("src/hyperbridge/modules/ismp/core"),
    Path("src/hyperbridge/modules/ismp"),
    Path("src/hyperbridge/tesseract"),
    Path("src/hyperbridge/parachain"),
)

HYPERBRIDGE_ZK_BEEFY_CARGO_TOML = Path(
    "src/hyperbridge/tesseract/consensus/beefy/zk/Cargo.toml"
)

HYPERBRIDGE_STUBS_DIR = Path("src/hyperbridge/stubs")

# Stub crate manifests. Version 1.0.0 mirrors the upstream `tag = "v1.0.0"`.
# Features mirror the consuming crate's `[features]` block so the
# `sp1-beefy/local` and `sp1-beefy/cluster` feature paths resolve.
HYPERBRIDGE_STUB_SP1_BEEFY_CARGO = """\
# auditooor.hyperbridge-cargo-patch-version: 1
# Minimal stub crate for sp1-beefy. Unblocks `cargo metadata` for the
# hyperbridge tree. NOT a functional implementation - any `cargo build`
# against zk-beefy will fail with missing-impl errors (intended fail-loud).
[package]
name = "sp1-beefy"
version = "1.0.0"
edition = "2021"

[features]
default = []
local = []
cluster = []
"""

HYPERBRIDGE_STUB_SP1_BEEFY_LIB = """\
// auditooor.hyperbridge-cargo-patch-version: 1
//
// Minimal stub for `sp1-beefy`. Declares the trait surface the hyperbridge
// `tesseract/consensus/beefy/zk` crate imports. This file is NOT meant to
// produce a functional sp1-beefy implementation; it exists only so that
// `cargo metadata` succeeds for the hyperbridge workspace. Any attempt to
// `cargo build` the zk-beefy crate against this stub will fail with
// missing-impl errors (intended fail-loud behaviour).
//
// Trait surface enumerated by greppping the hyperbridge audit pin tree
// (70c8429d9b5c) for `sp1_beefy::` and `sp1_beefy_primitives::`:
//   * `sp1_beefy::BeefyProver` trait + `prove(...)` method
//   * `sp1_beefy::local::LocalProver` re-export
//   * `sp1_beefy::cluster::ClusterProver` re-export
//   * `sp1_beefy_primitives::{AuthoritiesProof, BeefyCommitment,
//     KeccakHasher, MmrLeafProof, ParachainHeader, ParachainProof,
//     SignatureWithAuthorityIndex}` types

#![allow(dead_code, unused_variables, unused_imports)]

pub trait BeefyProver: Send + Sync + 'static {
    type Proof;
}

pub mod local {
    pub struct LocalProver;
}

pub mod cluster {
    pub struct ClusterProver;
}
"""

HYPERBRIDGE_STUB_SP1_BEEFY_PRIMITIVES_CARGO = """\
# auditooor.hyperbridge-cargo-patch-version: 1
# Minimal stub crate for sp1-beefy-primitives. Unblocks `cargo metadata`
# for the hyperbridge tree. NOT a functional implementation.
[package]
name = "sp1-beefy-primitives"
version = "1.0.0"
edition = "2021"
"""

HYPERBRIDGE_STUB_SP1_BEEFY_PRIMITIVES_LIB = """\
// auditooor.hyperbridge-cargo-patch-version: 1
//
// Minimal stub for `sp1-beefy-primitives`. Declares the types the
// hyperbridge `tesseract/consensus/beefy/zk` crate imports. NOT a
// functional implementation. See sp1-beefy stub lib.rs for rationale.

#![allow(dead_code, unused_variables, unused_imports)]

pub struct BeefyCommitment;
pub struct AuthoritiesProof;
pub struct KeccakHasher;
pub struct MmrLeafProof;
pub struct ParachainHeader;
pub struct ParachainProof;
pub struct SignatureWithAuthorityIndex;
"""


def _sha256_path(path: Path) -> str:
    """Return the SHA256 of the contents of `path` as a hex string."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _detect_hyperbridge(workspace: Path) -> bool:
    """Return True iff the workspace contains a hyperbridge tree.

    We look for any of HYPERBRIDGE_DETECT_PATHS under `workspace`. Any
    one match is sufficient. We do not validate the audit pin SHA here;
    the operator is responsible for picking a workspace pinned to a
    sp1-beefy-using commit.
    """
    return any((workspace / sub).is_dir() for sub in HYPERBRIDGE_DETECT_PATHS)


def _rewrite_zk_beefy_cargo_toml(
    original: str,
    sp1_beefy_path: str,
    sp1_beefy_primitives_path: str,
) -> str:
    """Rewrite the zk-beefy Cargo.toml: replace the two
    `[dependencies.sp1-beefy*]` blocks with path-based references and
    wrap the rewritten region with sentinel marker comments.

    `sp1_beefy_path` and `sp1_beefy_primitives_path` are the paths to
    the stub crate directories relative to the zk-beefy Cargo.toml file.

    Idempotency: if the file already contains
    `HYPERBRIDGE_PATCH_MARKER_BEGIN`, return `original` unchanged.
    """
    if HYPERBRIDGE_PATCH_MARKER_BEGIN in original:
        return original

    lines = original.split("\n")

    def _block_indices(target_header: str) -> Optional[Tuple[int, int]]:
        for i, line in enumerate(lines):
            if line.strip() == target_header:
                # End is the next line that starts with '[' or is blank.
                j = i + 1
                while j < len(lines):
                    nxt = lines[j]
                    if nxt.startswith("[") or nxt.strip() == "":
                        break
                    j += 1
                return (i, j)
        return None

    sp1_block = _block_indices("[dependencies.sp1-beefy]")
    primitives_block = _block_indices("[dependencies.sp1-beefy-primitives]")

    if sp1_block is None or primitives_block is None:
        raise ValueError(
            "expected [dependencies.sp1-beefy] and "
            "[dependencies.sp1-beefy-primitives] table headers in "
            "zk-beefy Cargo.toml; one or both not found"
        )

    blocks = sorted(
        [
            ("sp1-beefy", sp1_block),
            ("sp1-beefy-primitives", primitives_block),
        ],
        key=lambda kv: kv[1][0],
    )

    # We rewrite in reverse-block order so earlier indices remain valid
    # while we splice.
    rewritten = list(lines)
    for name, (start, end) in reversed(blocks):
        original_block = rewritten[start:end]
        commented = [
            ("# " + ln) if ln.strip() else "#"
            for ln in original_block
        ]
        if name == "sp1-beefy":
            replacement = [
                "[dependencies.sp1-beefy]",
                f"path = \"{sp1_beefy_path}\"",
                "default-features = false",
            ]
        else:
            replacement = [
                "[dependencies.sp1-beefy-primitives]",
                f"path = \"{sp1_beefy_primitives_path}\"",
                "default-features = false",
            ]
        spliced = (
            [HYPERBRIDGE_PATCH_MARKER_BEGIN]
            + commented
            + [""]
            + replacement
            + [HYPERBRIDGE_PATCH_MARKER_END]
        )
        rewritten[start:end] = spliced

    return "\n".join(rewritten)


def plan_hyperbridge_patches(
    workspace: Path,
) -> Dict[str, object]:
    """Return a plan describing what `--hyperbridge-patches` would do.

    Plan fields:
      * detected: bool, True if the workspace contains a hyperbridge tree
      * zk_beefy_cargo_toml: absolute path to the consuming Cargo.toml
      * stubs_dir: absolute path to the stubs directory
      * already_patched: bool, True if the consuming Cargo.toml already
        carries the patch marker
      * files: list of (absolute path, action) where action is one of
        "create", "skip", "rewrite", "missing"
    """
    detected = _detect_hyperbridge(workspace)
    zk_beefy = workspace / HYPERBRIDGE_ZK_BEEFY_CARGO_TOML
    stubs_dir = workspace / HYPERBRIDGE_STUBS_DIR
    stub_files = [
        stubs_dir / "sp1-beefy" / "Cargo.toml",
        stubs_dir / "sp1-beefy" / "src" / "lib.rs",
        stubs_dir / "sp1-beefy-primitives" / "Cargo.toml",
        stubs_dir / "sp1-beefy-primitives" / "src" / "lib.rs",
    ]

    already_patched = False
    if zk_beefy.is_file():
        current = zk_beefy.read_text()
        already_patched = HYPERBRIDGE_PATCH_MARKER_BEGIN in current

    files: List[Tuple[Path, str]] = []
    for f in stub_files:
        files.append((f, "skip" if f.exists() else "create"))
    if zk_beefy.is_file():
        files.append((zk_beefy, "skip" if already_patched else "rewrite"))
    else:
        files.append((zk_beefy, "missing"))

    return {
        "detected": detected,
        "zk_beefy_cargo_toml": zk_beefy,
        "stubs_dir": stubs_dir,
        "already_patched": already_patched,
        "files": files,
    }


def execute_hyperbridge_patches(
    workspace: Path,
) -> Dict[str, object]:
    """Apply the hyperbridge sp1-beefy patches to `workspace`.

    Behaviour:
      * Refuses (raises) if the workspace is not a hyperbridge tree.
      * Refuses (raises) if `tesseract/consensus/beefy/zk/Cargo.toml`
        does not exist (no zk-beefy crate to patch).
      * Idempotent: if the patch marker is already present in the
        consuming Cargo.toml AND every stub file exists with the
        expected content, the run is a no-op apart from re-emitting the
        sidecar with the same file SHAs.
      * Writes the sidecar at `<workspace>/.auditooor/hyperbridge_patches.json`
        with the SHA256 of every (re)written file.

    Returns a dict mirroring the sidecar contents.
    """
    if not _detect_hyperbridge(workspace):
        raise FileNotFoundError(
            f"workspace does not contain a hyperbridge tree (looked for "
            f"any of: {[str(p) for p in HYPERBRIDGE_DETECT_PATHS]}); "
            f"refusing to patch."
        )

    zk_beefy = workspace / HYPERBRIDGE_ZK_BEEFY_CARGO_TOML
    if not zk_beefy.is_file():
        raise FileNotFoundError(
            f"expected zk-beefy Cargo.toml at "
            f"{HYPERBRIDGE_ZK_BEEFY_CARGO_TOML}; not found in workspace"
        )

    stubs_dir = workspace / HYPERBRIDGE_STUBS_DIR
    sp1_stub_dir = stubs_dir / "sp1-beefy"
    sp1_prim_stub_dir = stubs_dir / "sp1-beefy-primitives"

    actions: List[Tuple[Path, str]] = []

    # 1. Write stub crates (idempotent: skip if file exists AND content matches).
    stub_specs = [
        (sp1_stub_dir / "Cargo.toml", HYPERBRIDGE_STUB_SP1_BEEFY_CARGO),
        (sp1_stub_dir / "src" / "lib.rs", HYPERBRIDGE_STUB_SP1_BEEFY_LIB),
        (
            sp1_prim_stub_dir / "Cargo.toml",
            HYPERBRIDGE_STUB_SP1_BEEFY_PRIMITIVES_CARGO,
        ),
        (
            sp1_prim_stub_dir / "src" / "lib.rs",
            HYPERBRIDGE_STUB_SP1_BEEFY_PRIMITIVES_LIB,
        ),
    ]
    for path, content in stub_specs:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_text() == content:
            actions.append((path, "skipped"))
            continue
        path.write_text(content)
        actions.append((path, "created"))

    # 2. Rewrite the consuming Cargo.toml (idempotent via marker check).
    original = zk_beefy.read_text()
    # Path from the zk-beefy Cargo.toml directory to the stub crates.
    # zk-beefy lives at:   src/hyperbridge/tesseract/consensus/beefy/zk/Cargo.toml
    # stubs live at:       src/hyperbridge/stubs/sp1-beefy
    # So the relative path is "../../../../stubs/sp1-beefy".
    sp1_rel = "../../../../stubs/sp1-beefy"
    sp1_prim_rel = "../../../../stubs/sp1-beefy-primitives"
    rewritten = _rewrite_zk_beefy_cargo_toml(
        original, sp1_rel, sp1_prim_rel
    )
    if rewritten == original:
        actions.append((zk_beefy, "skipped"))
    else:
        zk_beefy.write_text(rewritten)
        actions.append((zk_beefy, "rewritten"))

    # 3. Emit sidecar.
    sidecar_dir = workspace / ".auditooor"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    sidecar_path = sidecar_dir / "hyperbridge_patches.json"
    file_records = []
    for path, action in actions:
        file_records.append(
            {
                "path": str(path),
                "action": action,
                "sha256": _sha256_path(path) if path.exists() else None,
            }
        )
    sidecar = {
        "schema": "auditooor.hyperbridge_patches.v1",
        "version": HYPERBRIDGE_PATCH_VERSION,
        "workspace": str(workspace),
        "timestamp": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "files": file_records,
    }
    sidecar_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True))
    return sidecar


def _print_hyperbridge_plan(
    workspace: Path,
    plan: Dict[str, object],
    out=None,
) -> None:
    if out is None:
        out = sys.stdout
    print(
        f"[workspace-bootstrap hyperbridge-patches] DRY RUN - no writes.",
        file=out,
    )
    print(f"Workspace: {workspace}", file=out)
    print(f"Hyperbridge tree detected: {plan['detected']}", file=out)
    print(
        f"zk-beefy Cargo.toml: {plan['zk_beefy_cargo_toml']}", file=out
    )
    print(f"Stubs dir: {plan['stubs_dir']}", file=out)
    print(f"Already patched: {plan['already_patched']}", file=out)
    for path, action in plan["files"]:
        print(f"  {action:>9} {path}", file=out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="workspace-bootstrap.py",
        description=(
            "Scaffold a new engagement workspace with SCOPE.md, reference/, "
            "submissions/, agent_outputs/ — or seed engage-chain stubs into "
            "an existing workspace (--engage-stubs). No network fetch; no "
            "git init."
        ),
    )
    p.add_argument(
        "--name",
        required=False,
        default=None,
        help=(
            "New-engagement workspace slug (must match [a-z0-9][a-z0-9-]*). "
            "Required unless --engage-stubs is used."
        ),
    )
    p.add_argument(
        "--platform",
        required=False,
        default=None,
        help=(
            "Bounty platform. Required unless --engage-stubs is used. "
            f"Allowed values: {sorted(VALID_PLATFORMS)}."
        ),
    )
    p.add_argument(
        "--scope-url",
        required=False,
        default=None,
        help=(
            "URL of the contest / bounty page (recorded, not fetched). "
            "Required unless --engage-stubs is used."
        ),
    )
    p.add_argument(
        "--severity-rubric",
        default=None,
        help=(
            "Optional path to a local rubric file to copy into the new "
            "workspace as severity-rubric.md."
        ),
    )
    p.add_argument(
        "--audits-dir",
        default=str(Path.home() / "audits"),
        help="Parent directory (default ~/audits/).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print the plan; do not touch the filesystem.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        default=False,
        help=(
            "Complete the scaffold of an EXISTING workspace instead of refusing. "
            "Idempotent + non-destructive: creates only missing dirs (exist_ok) and "
            "writes SCOPE.md/outcomes.jsonl/BOOTSTRAP/targets.tsv only if absent. "
            "Existing content (prior_audits/, .auditooor/, src/, authored SCOPE.md) "
            "is never overwritten. Use to re-bootstrap a re-pinned / re-audited target."
        ),
    )
    p.add_argument(
        "--engage-stubs",
        default=None,
        metavar="WORKSPACE",
        help=(
            "Idempotent engage-chain stub seeding (V5-P0-06 / Gap 16). "
            "Targets an existing workspace directory. Creates SCOPE.md, "
            "AUDIT.md, SESSION_LOG.md, FINDINGS.md, SEVERITY.md, "
            "RUBRIC_COVERAGE.md, targets.tsv, SEVERITY_CAPS.md, "
            "OOS_CHECKLIST.md, concolic/SUMMARY.md, economic_hypotheses.md "
            "only if missing. Re-running is a no-op."
        ),
    )
    p.add_argument(
        "--hyperbridge-patches",
        default=None,
        metavar="WORKSPACE",
        help=(
            "Idempotent hyperbridge sp1-beefy patches (CAPABILITY-GAP-6). "
            "Targets an existing workspace that contains a hyperbridge "
            "tree under src/hyperbridge/. Writes minimal stub crates at "
            "src/hyperbridge/stubs/sp1-beefy{,-primitives}/ and rewrites "
            "src/hyperbridge/tesseract/consensus/beefy/zk/Cargo.toml to "
            "depend on those stubs via path-based references instead of "
            "ssh://git@github.com/polytope-labs/sp1-beefy.git. Unblocks "
            "`cargo metadata`. Emits sidecar at "
            ".auditooor/hyperbridge_patches.json. Re-running is a no-op."
        ),
    )
    return p


def _validate_args(args: argparse.Namespace) -> Tuple[int, str]:
    """Return (exit_code, error_message). 0 = ok.

    Validation rules differ between the two modes:

    * `--engage-stubs <ws>` mode does not require `--name`/`--platform`/
      `--scope-url`. The workspace path is taken from `--engage-stubs`
      directly. Validation only checks that the target directory exists.
    * Original new-engagement mode requires `--name`, `--platform`, and
      `--scope-url` and runs all the slug/platform checks.
    """
    if args.engage_stubs is not None:
        ws = Path(args.engage_stubs).expanduser()
        if not ws.exists():
            return 2, f"error: --engage-stubs target does not exist: {ws}"
        if not ws.is_dir():
            return (
                2,
                f"error: --engage-stubs target is not a directory: {ws}",
            )
        return 0, ""

    if args.hyperbridge_patches is not None:
        ws = Path(args.hyperbridge_patches).expanduser()
        if not ws.exists():
            return (
                2,
                f"error: --hyperbridge-patches target does not exist: {ws}",
            )
        if not ws.is_dir():
            return (
                2,
                f"error: --hyperbridge-patches target is not a directory: "
                f"{ws}",
            )
        return 0, ""

    # Original new-engagement-mode validation.
    if args.name is None:
        return (
            2,
            "error: --name is required (unless --engage-stubs is used).",
        )
    if not SLUG_RE.match(args.name):
        return (
            2,
            f"error: --name {args.name!r} is not slug-safe; expected "
            f"[a-z0-9][a-z0-9-]*.",
        )
    if args.platform is None:
        return (
            2,
            "error: --platform is required (unless --engage-stubs is used).",
        )
    if args.platform not in VALID_PLATFORMS:
        return (
            2,
            f"error: --platform {args.platform!r} not in allowed list "
            f"{sorted(VALID_PLATFORMS)}.",
        )
    if args.scope_url is None or not args.scope_url.strip():
        return (
            2,
            "error: --scope-url is required (unless --engage-stubs is used).",
        )
    if args.severity_rubric is not None:
        p = Path(args.severity_rubric).expanduser()
        if not p.exists():
            return (
                2,
                f"error: --severity-rubric path does not exist: {p}",
            )
    return 0, ""


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    rc, err = _validate_args(args)
    if rc != 0:
        print(err, file=sys.stderr)
        return rc

    # Branch: engage-stubs (V5-P0-06 / Gap 16) is a separate code path
    # because it operates on an existing workspace and never touches the
    # SCOPE.md/BOOTSTRAP_ITER7.md scaffold from the original ITER-7 flow.
    if args.engage_stubs is not None:
        workspace = Path(args.engage_stubs).expanduser().resolve()
        will_create, will_skip = plan_engage_stubs(workspace)
        if args.dry_run:
            _print_engage_plan(workspace, will_create, will_skip)
            return 0
        actions = execute_engage_stubs(workspace)
        created = [rel for rel, action in actions if action == "created"]
        skipped = [rel for rel, action in actions if action == "skipped"]
        print(
            f"[workspace-bootstrap engage-stubs] workspace: {workspace}"
        )
        if created:
            print(
                f"[workspace-bootstrap engage-stubs] created "
                f"{len(created)} stub(s):"
            )
            for rel in created:
                print(f"  + {rel}")
        if skipped:
            print(
                f"[workspace-bootstrap engage-stubs] skipped "
                f"{len(skipped)} (already present):"
            )
            for rel in skipped:
                print(f"  = {rel}")
        if not created and not skipped:
            # Defensive — catalog is non-empty, so this branch is unreachable.
            print("[workspace-bootstrap engage-stubs] nothing to do.")
        return 0

    # Branch: hyperbridge-patches (CAPABILITY-GAP-6) is a separate code
    # path that operates on an existing workspace and only touches the
    # hyperbridge tree under src/hyperbridge/.
    if args.hyperbridge_patches is not None:
        workspace = Path(args.hyperbridge_patches).expanduser().resolve()
        plan = plan_hyperbridge_patches(workspace)
        if not plan["detected"]:
            print(
                f"error: --hyperbridge-patches: workspace does not "
                f"contain a hyperbridge tree (looked under "
                f"{workspace}); refusing to patch.",
                file=sys.stderr,
            )
            return 2
        if args.dry_run:
            _print_hyperbridge_plan(workspace, plan)
            return 0
        try:
            sidecar = execute_hyperbridge_patches(workspace)
        except FileNotFoundError as exc:
            print(f"error: --hyperbridge-patches: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"error: --hyperbridge-patches: {exc}", file=sys.stderr)
            return 2
        actions_counter: Dict[str, int] = {}
        for record in sidecar["files"]:
            actions_counter[record["action"]] = (
                actions_counter.get(record["action"], 0) + 1
            )
        print(
            f"[workspace-bootstrap hyperbridge-patches] workspace: "
            f"{workspace}"
        )
        for action, count in sorted(actions_counter.items()):
            print(
                f"[workspace-bootstrap hyperbridge-patches] {action}: "
                f"{count} file(s)"
            )
        print(
            f"[workspace-bootstrap hyperbridge-patches] sidecar: "
            f"{workspace / '.auditooor' / 'hyperbridge_patches.json'}"
        )
        return 0

    audits_dir = Path(args.audits_dir).expanduser()
    workspace = audits_dir / args.name
    severity_rubric = (
        Path(args.severity_rubric).expanduser()
        if args.severity_rubric
        else None
    )

    if workspace.exists() and not args.force:
        print(
            f"error: workspace already exists: {workspace}. "
            f"Refusing to overwrite. Pass --force to complete the scaffold "
            f"idempotently (non-destructive: existing content is preserved).",
            file=sys.stderr,
        )
        return 2

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.dry_run:
        _print_plan(workspace, severity_rubric)
        return 0

    # Non-dry-run: parent directory must exist OR be creatable.
    audits_dir.mkdir(parents=True, exist_ok=True)

    scope_md = _render_scope_md(
        name=args.name,
        platform=args.platform,
        scope_url=args.scope_url,
        timestamp=timestamp,
        severity_rubric=severity_rubric,
    )
    meta_md = _render_bootstrap_meta(
        name=args.name,
        platform=args.platform,
        scope_url=args.scope_url,
        severity_rubric=severity_rubric,
        audits_dir=audits_dir,
        timestamp=timestamp,
    )

    _execute_plan(
        workspace, scope_md, meta_md, severity_rubric,
        complete_existing=bool(args.force and workspace.exists()),
    )

    print(f"[workspace-bootstrap] created: {workspace}")
    print(f"[workspace-bootstrap] platform: {args.platform}")
    print(f"[workspace-bootstrap] scope-url: {args.scope_url}")
    print(
        "[workspace-bootstrap] next step: fill in SCOPE.md TODOs from "
        "the live bounty page."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
