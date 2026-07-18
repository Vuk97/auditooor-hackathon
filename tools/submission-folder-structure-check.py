#!/usr/bin/env python3
# r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS registered via tools/agent-pathspec-register.py to .auditooor/agent_pathspec.json
"""Rule 41 per-finding submission folder structure preflight.

Every bounty submission's artifacts must live together in a single folder
named by the finding slug, under a status directory:

    submissions/<status>/<finding-slug>/<finding-slug>.<ext>

Status directories: staging, ready, filed, packaged, _killed, _oos_rejected,
plus the Spark / L27 workflow vocabulary paste_ready, held, superseded. The
set can be extended (or replaced) via the env hook AUDITOOOR_R41_STATUS_DIRS
(newline- or comma-separated; a leading `=` or `REPLACE` token discards the
defaults).

A finding folder is identified by containing exactly one `<finding-slug>.md`
whose stem equals the folder name. All other artifacts for that finding (the
`.md.hash`, `.hackenproof-plain.txt`, `.hackenproof-plain.json`,
`.hackenproof-plain.txt.hash`, `.hardening.md`, the `-poc.zip`, the
`.poc-transcript.txt`) live in the same folder. No submission artifact may lie
flat directly inside a status directory.

Modes:
  --workspace <path> / --submissions-dir <path> : scan submissions/<status>/.
  --check (default)  : report flat artifacts and folder-name mismatches; exit
                       non-zero on any violation.
  --fix              : reorganize - group each flat non-.md artifact into the
                       per-finding folder whose slug is the LONGEST prefix
                       match of the file name; create `<slug>/` and move the
                       files. Idempotent.
  --draft <path>     : per-draft form used by pre-submit-check.sh - pass/fail
                       on whether the draft sits at
                       submissions/<status>/<slug>/<slug>.md.
  --completeness     : extend --draft form with R41 artifact-completeness
                       check (Gap #36). For drafts that cite executed-PoC
                       evidence (forge / cargo / Foundry harness / "X/X tests
                       PASS" / Suite-result transcript phrasing), require the
                       per-finding folder to also contain a poc-zip plus a
                       poc-transcript artifact in addition to the standard
                       hash + platform-plain sidecars. Default off; preserves
                       pass-through behavior. Honors the override marker
                       `r41-completeness-rebuttal: <reason>` (visible bounded
                       line, <=200 chars) or the HTML-comment form
                       `<!-- r41-completeness-rebuttal: <reason> -->`.
  --json             : emit a JSON verdict (schema below).

Verdict vocabulary:
  pass-compliant, pass-empty, fail-flat-artifact, fail-folder-name-mismatch,
  fail-draft-not-in-finding-folder, pass-out-of-scope,
  pass-all-artifacts-present, ok-rebuttal, fail-artifact-missing, error.

Exit codes:
  0 - pass / pass-empty / fix applied successfully
  1 - Rule 41 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r41_submission_folder_structure.v1"
GATE = "R41-SUBMISSION-FOLDER-STRUCTURE"
# <!-- r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS registered via tools/agent-pathspec-register.py in .auditooor/agent_pathspec.json -->

# ---------------------------------------------------------------------------
# Gap #36: R41 artifact-completeness extension (added 2026-05-26).
# ---------------------------------------------------------------------------
# Operator anchor: DRILL-9 paste-ready (smt-eth-branch-isempty-value-conflation)
# was promoted to paste-ready citing "13/13 Foundry tests PASS" but the
# per-finding folder was missing the -poc.zip + .poc-transcript.txt artifacts.
# Operator caught it at HackenProof paste time. R41 (folder grouping) passed
# because every artifact already in the folder was correctly grouped, but the
# REQUIRED set was incomplete. The completeness check closes that gap: for any
# draft that cites executed-PoC evidence, require the executed-PoC artifact
# bundle (zip + transcript) in addition to the standard sidecars.
#
# Trigger phrases (case-insensitive substring or regex match against the draft
# body). Hitting any one is sufficient to require the executed-PoC bundle.
# Env extension: AUDITOOOR_R41_POC_EVIDENCE_PATTERNS (newline-separated regex
# list appended to defaults).
_POC_EVIDENCE_PATTERNS_DEFAULT = (
    r"PoC\s+PASS",
    r"PoC\s+transcript",
    r"\d+\s*/\s*\d+\s+(?:Foundry\s+)?tests?\s+(?:PASS|passed)",
    r"\d+\s+passed;\s*0\s+failed",
    r"Suite\s+result:\s*ok",
    r"forge\s+test\b",
    r"cargo\s+test\b",
    r"go\s+test\b",
    r"Foundry\s+harness",
    r"Foundry\s+PoC",
    r"---\s*PASS:",
    r"transcript\s+at\s+`?[^`\s]+\.txt`?",
)

# Required artifacts (relative to per-finding folder) when the completeness
# trigger fires. Each entry is a suffix that must appear on at least one file
# in the folder (the actual basename varies - e.g. <slug>-poc.zip vs
# <slug>-SEVERITY-poc.zip vs <slug-base>-poc.zip - so suffix-match is used).
_COMPLETENESS_REQUIRED_SUFFIXES = (
    "-poc.zip",
    ".poc-transcript.txt",
)

_R41_COMPLETENESS_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?r41-completeness-rebuttal:\s*(?P<reason>.{1,200}?)\s*(?:-->|$)",
    re.IGNORECASE | re.MULTILINE,
)


def _resolve_poc_evidence_patterns() -> tuple[re.Pattern[str], ...]:
    """Compile the trigger pattern list, extended via env hook."""
    raw = os.environ.get("AUDITOOOR_R41_POC_EVIDENCE_PATTERNS", "")
    extra = [p.strip() for p in raw.split("\n") if p.strip()]
    out: list[re.Pattern[str]] = []
    for pat in list(_POC_EVIDENCE_PATTERNS_DEFAULT) + extra:
        try:
            out.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            continue
    return tuple(out)


def _detect_poc_evidence_markers(draft_text: str) -> list[str]:
    """Return the matched trigger phrases (verbatim hits) in the draft body."""
    hits: list[str] = []
    for pat in _resolve_poc_evidence_patterns():
        m = pat.search(draft_text)
        if m:
            hits.append(m.group(0))
    return hits


def _detect_completeness_rebuttal(draft_text: str) -> str | None:
    """Return the rebuttal reason text if `r41-completeness-rebuttal:` is set."""
    m = _R41_COMPLETENESS_REBUTTAL_RE.search(draft_text)
    if not m:
        return None
    reason = m.group("reason").strip()
    if not reason:
        return None
    return reason[:200]


def _folder_artifact_suffixes(folder: Path) -> list[str]:
    """All file-name suffixes present in the per-finding folder.

    Suffix matching keeps the check resilient to severity-tagged basenames
    (e.g. `<slug>-poc.zip` vs `<slug>-HIGH-poc.zip` vs `<slug-base>-poc.zip`).
    """
    suffixes: list[str] = []
    if not folder.is_dir():
        return suffixes
    for entry in folder.iterdir():
        if entry.is_file():
            suffixes.append(entry.name)
    return suffixes


def _missing_required_artifacts(folder: Path) -> list[str]:
    """Return the list of required suffixes that no file in `folder` ends with."""
    names = _folder_artifact_suffixes(folder)
    missing: list[str] = []
    for required in _COMPLETENESS_REQUIRED_SUFFIXES:
        if not any(name.endswith(required) for name in names):
            missing.append(required)
    return missing


def check_completeness(draft: Path) -> tuple[int, dict[str, Any]]:
    """Per-draft form: does the per-finding folder hold the full required set?

    Trigger gating: this check is OUT-OF-SCOPE when the draft body contains
    none of the executed-PoC-evidence phrases. It fires when at least one
    trigger phrase is present, and demands a `-poc.zip` + `.poc-transcript.txt`
    artifact in the per-finding folder (suffix-match).

    Honors the rebuttal marker `r41-completeness-rebuttal: <reason>`
    (visible bounded line OR HTML comment, <=200 chars, non-empty).
    """
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": "R41-ARTIFACT-COMPLETENESS",
        "file": str(draft),
        "mode": "completeness",
        "required_suffixes": list(_COMPLETENESS_REQUIRED_SUFFIXES),
        "remediation_options": [
            "Place the executed-PoC artifact bundle in the per-finding folder: "
            "`<slug>-poc.zip` (or `<slug-base>-poc.zip`) AND `<slug>.poc-transcript.txt`.",
            "If the draft body does NOT cite executed-PoC evidence, walk back "
            "the PoC-evidence phrasing (the check skips drafts without trigger "
            "phrases).",
            "Add a visible `r41-completeness-rebuttal: <reason>` line or HTML "
            "comment `<!-- r41-completeness-rebuttal: <reason> -->` (<=200 "
            "chars, non-empty) to acknowledge an intentional exception.",
        ],
    }
    resolved = draft.resolve()
    if not resolved.is_file():
        payload["verdict"] = "error"
        payload["reason"] = f"draft not found: {draft}"
        return 2, payload
    if resolved.suffix != ".md":
        payload["verdict"] = "error"
        payload["reason"] = "draft is not a .md file"
        return 2, payload

    try:
        body = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        payload["verdict"] = "error"
        payload["reason"] = f"could not read draft: {exc}"
        return 2, payload

    folder = resolved.parent
    payload["folder"] = str(folder)
    payload["folder_artifacts"] = sorted(_folder_artifact_suffixes(folder))

    rebuttal = _detect_completeness_rebuttal(body)
    if rebuttal is not None:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal_reason"] = rebuttal
        payload["reason"] = (
            f"R41 artifact-completeness rebuttal accepted: {rebuttal[:120]}"
        )
        return 0, payload

    evidence_markers = _detect_poc_evidence_markers(body)
    payload["poc_evidence_markers_hit"] = evidence_markers
    if not evidence_markers:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = (
            "draft does not cite executed-PoC evidence; completeness check skipped"
        )
        return 0, payload

    missing = _missing_required_artifacts(folder)
    payload["missing_artifact_suffixes"] = missing
    if not missing:
        payload["verdict"] = "pass-all-artifacts-present"
        payload["reason"] = (
            "draft cites executed-PoC evidence and per-finding folder holds the "
            "full required artifact set (poc-zip + poc-transcript)"
        )
        return 0, payload

    payload["verdict"] = "fail-artifact-missing"
    payload["reason"] = (
        "draft cites executed-PoC evidence (markers: "
        + ", ".join(evidence_markers[:3])
        + ") but per-finding folder is missing required artifact(s): "
        + ", ".join(missing)
    )
    return 1, payload

# Built-in status directories. The first group is the canonical staged-finding
# lifecycle; the second group (paste_ready / held / superseded) is the Spark /
# L27 workflow vocabulary. Both are recognized out of the box so the gate is
# engagement-agnostic.
_DEFAULT_STATUS_DIRS = (
    "staging", "ready", "filed", "packaged", "_killed", "_oos_rejected",
    # Spark / L27 legacy workflow status dirs.
    "paste_ready", "held", "superseded",
)


def _resolve_status_dirs() -> tuple[str, ...]:
    """Status dirs, extended by the env hook AUDITOOOR_R41_STATUS_DIRS.

    The env var is newline- or comma-separated. Its entries EXTEND the
    built-in defaults (a leading entry of `=` or the literal token `REPLACE`
    on its own line discards the defaults and uses only the env entries).
    Order is preserved; duplicates are dropped.
    """
    raw = os.environ.get("AUDITOOOR_R41_STATUS_DIRS", "")
    parts = [p.strip() for p in re.split(r"[,\n]", raw) if p.strip()]
    replace = False
    if parts and parts[0] in ("=", "REPLACE"):
        replace = True
        parts = parts[1:]
    seen: dict[str, None] = {}
    base = [] if replace else list(_DEFAULT_STATUS_DIRS)
    for name in base + parts:
        if name not in seen:
            seen[name] = None
    return tuple(seen)


STATUS_DIRS = _resolve_status_dirs()

# Files that are allowed to lie flat in a status directory (not submission
# artifacts - they are status-dir-level bookkeeping).
ALLOWED_FLAT_NAMES = {
    "README.md",
    "SUBMISSIONS.md",
    ".gitkeep",
    ".DS_Store",
}

# Known submission sidecar suffixes. Needed so dotted draft stems like
# `R89-Blue-consolidated.notes.md` are treated as finding roots while true
# sidecars like `.hardening.md` still group under the root draft.
_KNOWN_ARTIFACT_SUFFIXES = (
    ".hackenproof-plain.txt.hash",
    ".hackenproof-plain.json",
    ".hackenproof-plain.txt",
    ".poc-transcript.txt",
    ".hardening.md",
    ".md.hash",
    "-poc.zip",
    ".md",
)

_NON_ROOT_MD_SUFFIXES = (
    ".hardening.md",
)

_BACKUP_SUFFIXES = (
    ".backup-old",
    ".bak",
    ".old",
)


def _strip_backup_suffix(name: str) -> str:
    """Strip backup-style suffixes before root/sidecar detection."""
    lower = name.lower()
    for suffix in _BACKUP_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)]
        if f"{suffix}-" in lower:
            idx = lower.find(f"{suffix}-")
            return name[:idx]
    return name


def _strip_known_artifact_suffix(name: str) -> str:
    """Return the best-effort finding base name for a submission artifact."""
    candidate = _strip_backup_suffix(name)
    for suffix in sorted(_KNOWN_ARTIFACT_SUFFIXES, key=len, reverse=True):
        if candidate.endswith(suffix):
            return candidate[: -len(suffix)]
    if "." in candidate:
        return candidate.split(".", 1)[0]
    return candidate


def _is_non_root_artifact_md(name: str) -> bool:
    """True when `name` is a known md sidecar, not the finding root draft."""
    candidate = _strip_backup_suffix(name)
    return any(candidate.endswith(suffix) for suffix in _NON_ROOT_MD_SUFFIXES)


def _is_finding_folder(directory: Path) -> str | None:
    """Return the slug if `directory` is a valid per-finding folder, else None.

    A per-finding folder contains exactly one `<slug>.md` whose stem equals the
    folder name.
    """
    if not directory.is_dir():
        return None
    md_files = [p for p in directory.iterdir() if p.is_file() and p.suffix == ".md"]
    stem_match = [p for p in md_files if p.stem == directory.name]
    if len(stem_match) == 1:
        return directory.name
    return None


def _status_dir_slugs(status_dir: Path) -> list[str]:
    """All finding slugs known to a status dir (folders + flat `<slug>.md`)."""
    slugs: set[str] = set()
    for entry in status_dir.iterdir():
        if entry.is_dir():
            slug = _is_finding_folder(entry)
            if slug:
                slugs.add(slug)
        elif (
            entry.is_file()
            and entry.suffix == ".md"
            and entry.name not in ALLOWED_FLAT_NAMES
            and not _is_non_root_artifact_md(entry.name)
        ):
            slugs.add(entry.stem)
    return sorted(slugs)


def _longest_prefix_slug(filename: str, slugs: list[str]) -> str | None:
    """Slug whose name shares the longest token-prefix with `filename`.

    The artifact naming is not always a strict slug prefix: the poc zip drops
    the severity suffix (`<slug-base>-poc.zip` for a `<slug-base>-HIGH.md`
    finding). So matching is token-aware - score each slug by the longest
    common run of leading hyphen-delimited tokens it shares with the file's
    base name, with a tie-break bonus when the filename strictly starts with
    the slug. The highest-scoring slug wins; ties break to the longer slug.
    """
    file_base = _strip_known_artifact_suffix(filename)
    file_tokens = file_base.split("-")
    best: str | None = None
    best_score = -1.0
    for slug in slugs:
        slug_tokens = slug.split("-")
        common = 0
        for ft, st in zip(file_tokens, slug_tokens):
            if ft == st:
                common += 1
            else:
                break
        if common == 0:
            continue
        score = float(len("-".join(slug_tokens[:common])))
        if filename.startswith(slug):
            score += 0.5  # strict-prefix tie-break bonus
        if score > best_score or (score == best_score and best is not None and len(slug) > len(best)):
            best = slug
            best_score = score
    return best


def _scan_status_dir(status_dir: Path) -> dict[str, Any]:
    """Inspect one status directory for Rule 41 compliance."""
    flat_artifacts: list[str] = []
    folder_mismatches: list[dict[str, str]] = []
    finding_folders: list[str] = []

    for entry in sorted(status_dir.iterdir()):
        if entry.is_file():
            if entry.name in ALLOWED_FLAT_NAMES:
                continue
            flat_artifacts.append(entry.name)
            continue
        if entry.is_dir():
            slug = _is_finding_folder(entry)
            if slug:
                finding_folders.append(slug)
                continue
            # A directory that is not a valid finding folder. If it holds an
            # .md file at all, its name does not match the .md stem.
            md_files = [p for p in entry.iterdir() if p.is_file() and p.suffix == ".md"]
            if md_files:
                folder_mismatches.append(
                    {
                        "folder": entry.name,
                        "md_stems": ",".join(sorted(p.stem for p in md_files)),
                    }
                )
            # Directories with no .md (e.g. ready/poc-tests) are left alone.
    return {
        "status_dir": status_dir.name,
        "flat_artifacts": flat_artifacts,
        "folder_mismatches": folder_mismatches,
        "finding_folders": sorted(finding_folders),
    }


def _resolve_submissions_dir(workspace: Path | None, submissions_dir: Path | None) -> Path | None:
    if submissions_dir is not None:
        return submissions_dir
    if workspace is not None:
        return workspace / "submissions"
    return None


def check(submissions_dir: Path) -> tuple[int, dict[str, Any]]:
    """Scan every status dir; report violations. Hard gate."""
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "submissions_dir": str(submissions_dir),
        "mode": "check",
        "status_dirs": [],
        "violations": [],
    }
    if not submissions_dir.is_dir():
        payload["verdict"] = "pass-empty"
        payload["reason"] = f"no submissions directory at {submissions_dir}"
        return 0, payload

    any_artifact = False
    flat_violations: list[dict[str, Any]] = []
    mismatch_violations: list[dict[str, Any]] = []

    for status_name in _resolve_status_dirs():
        status_dir = submissions_dir / status_name
        if not status_dir.is_dir():
            continue
        scan = _scan_status_dir(status_dir)
        payload["status_dirs"].append(scan)
        if scan["flat_artifacts"] or scan["folder_mismatches"] or scan["finding_folders"]:
            any_artifact = True
        for name in scan["flat_artifacts"]:
            flat_violations.append({"status_dir": status_name, "artifact": name})
        for mismatch in scan["folder_mismatches"]:
            mismatch_violations.append(
                {
                    "status_dir": status_name,
                    "folder": mismatch["folder"],
                    "md_stems": mismatch["md_stems"],
                }
            )

    payload["remediation_options"] = [
        "Group every submission artifact into a per-finding folder: "
        "submissions/<status>/<slug>/<slug>.<ext>.",
        "Rename each finding folder so its name equals the contained <slug>.md stem.",
        "Run this tool with --fix to reorganize flat artifacts automatically.",
        "Files allowed flat in a status dir: README.md, SUBMISSIONS.md, .gitkeep.",
    ]

    if flat_violations:
        payload["verdict"] = "fail-flat-artifact"
        payload["violations"] = flat_violations + mismatch_violations
        payload["reason"] = (
            f"{len(flat_violations)} submission artifact(s) lie flat in a status "
            "directory instead of inside a per-finding folder"
        )
        return 1, payload

    if mismatch_violations:
        payload["verdict"] = "fail-folder-name-mismatch"
        payload["violations"] = mismatch_violations
        payload["reason"] = (
            f"{len(mismatch_violations)} finding folder(s) whose name does not "
            "match the contained <slug>.md stem"
        )
        return 1, payload

    if not any_artifact:
        payload["verdict"] = "pass-empty"
        payload["reason"] = "no submission artifacts found"
        return 0, payload

    payload["verdict"] = "pass-compliant"
    payload["reason"] = "every submission artifact is grouped in a per-finding folder"
    return 0, payload


def fix(submissions_dir: Path) -> tuple[int, dict[str, Any]]:
    """Reorganize flat artifacts into per-finding folders. Idempotent."""
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "submissions_dir": str(submissions_dir),
        "mode": "fix",
        "moves": [],
        "unmatched": [],
    }
    if not submissions_dir.is_dir():
        payload["verdict"] = "pass-empty"
        payload["reason"] = f"no submissions directory at {submissions_dir}"
        return 0, payload

    moves: list[dict[str, str]] = []
    unmatched: list[dict[str, str]] = []

    for status_name in _resolve_status_dirs():
        status_dir = submissions_dir / status_name
        if not status_dir.is_dir():
            continue

        # First pass: place each flat finding-root `<slug>.md` into its own
        # folder. A finding-root .md is one whose stem has no further dotted
        # artifact suffix (`<slug>.md`, not `<slug>.hardening.md`). This seeds
        # the slug list for grouping every other artifact.
        for entry in sorted(status_dir.iterdir()):
            if not (entry.is_file() and entry.suffix == ".md"):
                continue
            if entry.name in ALLOWED_FLAT_NAMES:
                continue
            if _is_non_root_artifact_md(entry.name):
                # Artifact .md (e.g. <slug>.hardening.md) - grouped in pass 2.
                continue
            slug = entry.stem
            dest_dir = status_dir / slug
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / entry.name
            shutil.move(str(entry), str(dest))
            moves.append(
                {"status_dir": status_name, "file": entry.name, "into": slug}
            )

        slugs = _status_dir_slugs(status_dir)

        # Second pass: group every remaining flat artifact (non-.md plus
        # artifact .md like <slug>.hardening.md) by longest-prefix slug.
        for entry in sorted(status_dir.iterdir()):
            if not entry.is_file():
                continue
            if entry.name in ALLOWED_FLAT_NAMES:
                continue
            slug = _longest_prefix_slug(entry.name, slugs)
            if slug is None:
                unmatched.append({"status_dir": status_name, "file": entry.name})
                continue
            dest_dir = status_dir / slug
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / entry.name
            shutil.move(str(entry), str(dest))
            moves.append(
                {"status_dir": status_name, "file": entry.name, "into": slug}
            )

    payload["moves"] = moves
    payload["unmatched"] = unmatched
    if unmatched:
        payload["verdict"] = "fail-flat-artifact"
        payload["reason"] = (
            f"{len(unmatched)} flat artifact(s) had no matching finding slug; "
            "moved nothing for those"
        )
        return 1, payload

    payload["verdict"] = "pass-compliant"
    payload["reason"] = (
        f"{len(moves)} artifact(s) regrouped into per-finding folders"
        if moves
        else "tree already compliant - nothing to move"
    )
    return 0, payload


def check_draft(draft: Path) -> tuple[int, dict[str, Any]]:
    """Per-draft form: is `draft` at submissions/<status>/<slug>/<slug>.md?"""
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "mode": "draft",
        "remediation_options": [
            "Move the draft to submissions/<status>/<slug>/<slug>.md and place "
            "all its sibling artifacts (.md.hash, .hackenproof-plain.*, "
            ".hardening.md, -poc.zip, .poc-transcript.txt) in the same folder.",
            "The finding folder name must equal the draft stem.",
        ],
    }
    resolved = draft.resolve()
    if not resolved.is_file():
        payload["verdict"] = "error"
        payload["reason"] = f"draft not found: {draft}"
        return 2, payload
    if resolved.suffix != ".md":
        payload["verdict"] = "error"
        payload["reason"] = "draft is not a .md file"
        return 2, payload

    folder = resolved.parent
    grandparent = folder.parent
    slug = resolved.stem

    # R41 (#85): an escalation/variant draft may co-reside in the base
    # finding's folder. Accept when the draft stem is a structural extension of
    # the folder name (`<folder>-<variant>`) AND the base finding `<folder>.md`
    # actually exists in that folder. The prefix requires the literal `<name>-`
    # separator so an unrelated slug that merely shares a leading substring
    # (e.g. folder `hb-orbit` / draft `hb-orbitals.md`) is NOT accepted, and the
    # base-file requirement means a wrongly-named folder with no base finding
    # still fails.
    exact_name_ok = folder.name == slug
    is_variant = bool(folder.name) and slug.startswith(folder.name + "-")
    base_finding_exists = (folder / f"{folder.name}.md").is_file()
    variant_ok = is_variant and base_finding_exists
    folder_name_ok = exact_name_ok or variant_ok
    status_ok = grandparent.name in _resolve_status_dirs()
    submissions_ok = grandparent.parent.name == "submissions"

    payload["expected_layout"] = "submissions/<status>/<slug>/<slug>.md"
    payload["observed"] = {
        "slug": slug,
        "folder": folder.name,
        "status_dir": grandparent.name,
        "submissions_parent": grandparent.parent.name,
        "folder_name_matches_slug": exact_name_ok,
        "accepted_as_escalation_variant": variant_ok,
        "status_dir_recognized": status_ok,
        "under_submissions": submissions_ok,
    }

    if folder_name_ok and status_ok and submissions_ok:
        payload["verdict"] = "pass-compliant"
        if variant_ok and not exact_name_ok:
            payload["reason"] = (
                "draft is an escalation/variant of base finding "
                f"'{folder.name}' co-residing in submissions/<status>/"
                f"{folder.name}/ (base {folder.name}.md present)"
            )
        else:
            payload["reason"] = "draft sits at submissions/<status>/<slug>/<slug>.md"
        return 0, payload

    payload["verdict"] = "fail-draft-not-in-finding-folder"
    payload["reason"] = (
        "draft is not at submissions/<status>/<slug>/<slug>.md "
        f"(folder={folder.name}, status={grandparent.name}, "
        f"submissions_parent={grandparent.parent.name})"
    )
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    # <!-- r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS registered via tools/agent-pathspec-register.py in .auditooor/agent_pathspec.json -->
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument("--submissions-dir", type=Path, default=None)
    parser.add_argument("--draft", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--fix", action="store_true")
    parser.add_argument(
        "--completeness",
        action="store_true",
        help=(
            "Gap #36: when used with --draft, run the R41 artifact-completeness "
            "extension. For drafts citing executed-PoC evidence, require a "
            "-poc.zip + .poc-transcript.txt artifact in the per-finding folder."
        ),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.draft is not None:
        if args.completeness:
            rc, payload = check_completeness(args.draft)
        else:
            rc, payload = check_draft(args.draft)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"{payload['verdict']}: {payload.get('reason', '')}")
        return rc

    submissions_dir = _resolve_submissions_dir(args.workspace, args.submissions_dir)
    if submissions_dir is None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": "error",
            "reason": "one of --workspace, --submissions-dir, or --draft is required",
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"error: {payload['reason']}", file=sys.stderr)
        return 2

    if args.fix:
        rc, payload = fix(submissions_dir)
    else:
        rc, payload = check(submissions_dir)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{payload['verdict']}: {payload.get('reason', '')}")
        if payload.get("mode") == "fix":
            for move in payload.get("moves", []):
                print(f"  moved {move['status_dir']}/{move['file']} -> {move['into']}/")
            for item in payload.get("unmatched", []):
                print(f"  UNMATCHED {item['status_dir']}/{item['file']}")
        else:
            for violation in payload.get("violations", []):
                if "artifact" in violation:
                    print(
                        f"  FLAT  {violation['status_dir']}/{violation['artifact']}"
                    )
                else:
                    print(
                        f"  MISMATCH  {violation['status_dir']}/{violation['folder']} "
                        f"(md stems: {violation['md_stems']})"
                    )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
