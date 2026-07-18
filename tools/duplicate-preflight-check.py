#!/usr/bin/env python3
"""duplicate-preflight-check.py — universal L31 pre-filing duplicate gate.

Runs the platform-published 2-question duplicate test against any draft
report before it is promoted to paste_ready/. Refuses promotion if the new
draft is a duplicate of a prior filed/staged report under the platform's
own rules.

Cross-platform applicability:

    Immunefi   — https://immunefi.com/help/ (Duplicate Reports article):
                 "Are the files/endpoints different? Does fixing one
                 automatically fix the second? If one fix addresses both,
                 the second report is a duplicate and not eligible."

    Cantina    — https://docs.cantina.xyz (Bug Bounty / Duplicate handling):
                 same Q1+Q2 logic; additionally, asset-selector must overlap
                 for a cross-asset comparison to be flagged as duplicate.
                 Drafts carry a <!-- cantina-asset: <name> --> comment.

    Sherlock   — https://docs.sherlock.xyz/audits (Duplicates):
                 watson's "duplicate of #N" decision rests on same fix;
                 "uniqueness escalation" — a strictly novel impact-class
                 (<!-- sherlock-impact: <class> -->) survives Q2 even with
                 a shared fix.

    Code4rena  — https://docs.code4rena.com (Judging / Duplicates):
                 Q1 auto (same files → flag); Q2 routes to manual judge
                 review unless --c4-judge-flag is set (then behaves like
                 Immunefi). Without --c4-judge-flag the verdict is
                 manual-review-required rather than dupe when Q2 ambiguous.

    Private    — operator's prior-fix log + ~/audits/<ws>/prior_reports/;
                 reads from --prior-reports-dir (no workspace-implicit path).
                 Identical to immunefi logic otherwise.

Test logic (Q1 + Q2):

    Q1: Are the files / endpoints in the new draft different from any
        prior report's files / endpoints?
    Q2: Does the fix for any prior report also fix the new draft?

    If EITHER Q1=No or Q2=No → DUPLICATE (cannot file as separate).
    Both must be "different" for the new draft to be distinct.

The script extracts files / endpoints / fix-references from drafts via
heuristic markdown parsing (see EXTRACTION_PATTERNS below). The output is
machine-parseable JSON so pre-submit-check.sh check #49 can consume it.

Usage:
    duplicate-preflight-check.py <draft.md> --workspace <ws-dir>
        [--platform immunefi|cantina|sherlock|code4rena|private|auto]
        [--asset-selector <name>]    # required for cantina platform
        [--impact-class <class>]     # used by sherlock uniqueness escalation
        [--c4-judge-flag]            # code4rena: treat Q2 like immunefi
        [--strict]
        [--prior-reports-dir <dir>]

Exit codes:
    0 = no duplicate detected, safe to promote
    1 = duplicate detected (Q1=No OR Q2=No against any prior report)
    2 = no prior reports to compare against (advisory)
    3 = parse error (draft or prior reports unreadable)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.duplicate_preflight_check.v2"

# Platform identifiers.
PLATFORMS = ("immunefi", "cantina", "sherlock", "code4rena", "private", "auto")

# Regex to extract platform metadata comments embedded in draft markdown.
CANTINA_ASSET_RE = re.compile(r"<!--\s*cantina-asset:\s*(.+?)\s*-->")
SHERLOCK_IMPACT_RE = re.compile(r"<!--\s*sherlock-impact:\s*(.+?)\s*-->")
L31_REBUTTAL_COMMENT_RE = re.compile(r"<!--\s*l31-rebuttal:\s*(\S+)\s+(.+?)-->", re.DOTALL)
L31_REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?l31[-_ ]rebuttal\s*:\s*(\S+)\s+(.+?)\s*$"
)


# Regex patterns to extract files, endpoints, and fix-references from a
# markdown draft. Drafts following the canonical Cantina paste template
# expose these explicitly in code-block-fenced citations and in body text.
FILE_PATH_RE = re.compile(
    r"`([a-zA-Z0-9_./-]+\.(?:sol|go|rs|ts|tsx|py|js|jsx|move|cairo|vy|fc))(?::\d+(?:-\d+)?)?`"
)
ENDPOINT_RE = re.compile(
    r"`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`?"  # function-call syntax
    r"|`([A-Z][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)`"  # Type.method form
    r"|`(\w+::\w+)`"  # rust path form
)
FIX_CONTEXT_RE = re.compile(
    r"\b(?:fix(?:es|ed)?|patch(?:es|ed)?|remediat(?:e|es|ed|ion)|"
    r"mitigat(?:e|es|ed|ion)|recommended fix|same fix|one fix|"
    r"pull request|pr|commit|sha)\b",
    re.IGNORECASE,
)
NON_FIX_CONTEXT_RE = re.compile(
    r"\b(?:audit[-_ ]?pin|source[-_ ]?pin|repo[-_ ]?pin|target[-_ ]?pin|"
    r"commit under test|tested commit|source commit|head sha|base sha|"
    r"audit commit|workspace pin)\b",
    re.IGNORECASE,
)
FIX_COMMIT_RE = re.compile(
    r"\b([0-9a-f]{7,40})\b"  # git SHA in a fix context
    r"|#(\d{2,6})\b"  # PR number in a fix context
)
GUARD_NAME_RE = re.compile(
    r"`(only[A-Z]\w+)`"  # solidity onlyOwner-style
    r"|`(when\w+)`"  # solidity whenNotPaused-style
    r"|`(non[A-Z]\w+)`"  # nonReentrant style
    r"|`(validate\w+)`"  # validateTransferLeavesNotExitedToL1 style
    r"|`(require\w+)`"  # requireAuth style
    r"|`(_lock)\b`"  # _lock-style
    r"|`(\w+_authorized)`"  # is_authorized rust style
)

# Family-id extraction patterns (filename and frontmatter).
# Filename-prefix family: RG-01, RG-N6-S1, RG-01A, LEAD-1, LEAD-CMTBFT-FORK-LAG, etc.
# All-caps; we anchor at start-of-token (^ or after a non-alnum) to avoid
# matching mid-string substrings, and we stop at the first non-[A-Z0-9-] char
# to prevent extending into lowercase suffix words like "-something".
FAMILY_FILENAME_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])"
    r"(RG-N\d+-S\d+"        # RG-N6-S1 style (must come before bare RG-\d+)
    r"|RG-\d+[A-Z]+"        # RG-01A style
    r"|RG-\d+"              # RG-01 style
    r"|LEAD-[A-Z0-9]+(?:-[A-Z0-9]+)*"  # LEAD-1 / LEAD-CMTBFT-FORK-LAG
    r")"
    r"(?![A-Za-z0-9])"      # stop at lowercase/alnum continuation
)
# Frontmatter family / lead identifiers; tolerate YAML-ish or HTML-comment forms.
FAMILY_FRONTMATTER_RE = re.compile(
    r"(?:^|\n)\s*(?:<!--\s*)?(?:family[_-]id|lead[_-]id)\s*[:=]\s*([A-Za-z0-9._\-]+)",
    re.IGNORECASE,
)


def _extract_family_id(path: Path, text: str) -> str | None:
    """Best-effort family-id extraction for self-skip-same-family.

    Priority:
      1. Frontmatter `family_id:` / `lead_id:` (most authoritative).
      2. Filename-prefix regex (RG-/LEAD- families).
    Returns a normalized lowercase family id, or None if no signal found.
    """
    fm = FAMILY_FRONTMATTER_RE.search(text)
    if fm:
        return fm.group(1).strip().lower()
    fn = FAMILY_FILENAME_RE.search(path.name)
    if fn:
        return fn.group(1).strip().lower()
    return None


def _read_paste_hash_sidecar(path: Path) -> str | None:
    """Return the paste_content_hash from the .paste_hash sidecar, or None.

    The sidecar lives next to the draft as `<draft>.paste_hash`. Its content
    is either a bare hex digest or a JSON object with a `paste_content_hash`
    key — accept both shapes.
    """
    sidecar = path.with_suffix(path.suffix + ".paste_hash")
    if not sidecar.is_file():
        return None
    try:
        raw = sidecar.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return None
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except Exception:
            return None
        v = obj.get("paste_content_hash") or obj.get("hash")
        return str(v).strip().lower() if v else None
    return raw.split()[0].lower()


def _same_family(
    new_path: Path,
    new_text: str,
    prior_path: Path,
    prior_text: str | None = None,
) -> tuple[bool, str | None]:
    """Return (is_same_family, signal) for the self-skip heuristic.

    Signals checked in order:
      1. Same `.paste_hash` sidecar content (paste_content_hash equality).
      2. Same family/lead id from frontmatter or filename prefix.
    """
    new_hash = _read_paste_hash_sidecar(new_path)
    prior_hash = _read_paste_hash_sidecar(prior_path)
    if new_hash and prior_hash and new_hash == prior_hash:
        return True, f"paste_content_hash={new_hash[:12]}"

    if prior_text is None:
        prior_text = _read_text(prior_path)
    new_fam = _extract_family_id(new_path, new_text)
    prior_fam = _extract_family_id(prior_path, prior_text)
    if new_fam and prior_fam and new_fam == prior_fam:
        return True, f"family_id={new_fam}"

    return False, None


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[error] read {p}: {e}", file=sys.stderr)
        return ""


def _extract_features(text: str) -> dict[str, set]:
    """Pull files/endpoints/fix-refs/guard-names out of a markdown draft."""
    files = set()
    endpoints = set()
    fix_refs = set()
    guards = set()

    for m in FILE_PATH_RE.finditer(text):
        files.add(m.group(1))

    for m in ENDPOINT_RE.finditer(text):
        for v in m.groups():
            if v:
                endpoints.add(v)

    for line in text.splitlines():
        if not FIX_CONTEXT_RE.search(line) or NON_FIX_CONTEXT_RE.search(line):
            continue
        for m in FIX_COMMIT_RE.finditer(line):
            sha, pr = m.group(1), m.group(2)
            if sha and len(sha) >= 7:
                fix_refs.add(f"sha:{sha[:12]}")
            if pr:
                fix_refs.add(f"pr:#{pr}")

    for m in GUARD_NAME_RE.finditer(text):
        for v in m.groups():
            if v:
                guards.add(v)

    return {
        "files": files,
        "endpoints": endpoints,
        "fix_refs": fix_refs,
        "guards": guards,
    }


def _extract_cantina_asset(text: str) -> str | None:
    """Extract <!-- cantina-asset: <name> --> from draft text, or None."""
    m = CANTINA_ASSET_RE.search(text)
    return m.group(1).strip() if m else None


def _extract_sherlock_impacts(text: str) -> set[str]:
    """Extract all <!-- sherlock-impact: <class> --> tags from draft text."""
    return {m.group(1).strip() for m in SHERLOCK_IMPACT_RE.finditer(text)}


def _gather_prior_reports(ws: Path, prior_reports_dir: Path | None) -> list[dict[str, Any]]:
    """Collect prior reports from the workspace's submissions/* and any
    operator-pasted prior_reports/ cache.

    Default scan lanes: paste_ready, staging, packaged, held, filed.
    The "filed" lane is intentionally included so findings already
    submitted to a platform are detected as duplicates at next-promotion
    time (CAP-GAP-81)."""
    priors = []

    # Workspace's own filed/staged/paste_ready submissions.
    # "filed" is included so already-submitted findings are also checked
    # against new drafts - catches same-engagement dupes that slipped through
    # at promotion time (CAP-GAP-81, 2026-05-27).
    for lane in ("paste_ready", "staging", "packaged", "held", "filed"):
        d = ws / "submissions" / lane
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md")):
            if f.name.startswith("HOLD_NOTE_") or f.name.startswith("README"):
                continue
            text = _read_text(f)
            if not text:
                continue
            feats = _extract_features(text)
            priors.append({
                "id": f.stem,
                "path": str(f),
                "lane": lane,
                "features": {k: sorted(v) for k, v in feats.items()},
            })

    # External prior_reports/ cache (operator-pasted reports from other hunters).
    if prior_reports_dir and prior_reports_dir.is_dir():
        for f in sorted(prior_reports_dir.glob("*.md")):
            text = _read_text(f)
            if not text:
                continue
            feats = _extract_features(text)
            priors.append({
                "id": f"external:{f.stem}",
                "path": str(f),
                "lane": "external_prior",
                "features": {k: sorted(v) for k, v in feats.items()},
            })

    return priors


def _q1_same_files(new: dict[str, set], prior_features: dict[str, list]) -> tuple[bool, list]:
    """Q1: same files? Returns (same, overlapping_files)."""
    prior_files = set(prior_features.get("files", []))
    overlap = sorted(new["files"] & prior_files)
    return (len(overlap) > 0), overlap


def _q2_same_fix(new: dict[str, set], prior_features: dict[str, list]) -> tuple[bool, list, list]:
    """Q2: shared fix? Returns (likely_same, shared_fix_refs, shared_guards).

    Heuristic: if the new draft cites the same fix-commit (SHA or PR#) as
    a prior report, OR the same missing-guard name, we treat Q2 as YES
    (likely same fix). Operator override required for nuanced cases.
    """
    prior_fixes = set(prior_features.get("fix_refs", []))
    prior_guards = set(prior_features.get("guards", []))
    shared_fixes = sorted(new["fix_refs"] & prior_fixes)
    shared_guards = sorted(new["guards"] & prior_guards)
    return (len(shared_fixes) > 0 or len(shared_guards) > 0), shared_fixes, shared_guards


def _apply_platform_rules(
    platform: str,
    new_text: str,
    new_feats: dict[str, set],
    priors: list[dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[list[dict], list[str]]:
    """Apply platform-specific Q1+Q2 rules and return (duplicates, warnings).

    Returns a list of duplicate-match dicts (same shape as immunefi baseline)
    and a list of advisory warning strings.
    """
    duplicates: list[dict] = []
    warnings: list[str] = []

    if platform in ("immunefi", "private", "auto"):
        # Baseline: standard Q1+Q2, no extra metadata needed.
        for pr in priors:
            prior_features = pr["features"]
            q1_same, q1_overlap = _q1_same_files(new_feats, prior_features)
            q2_same, q2_fixes, q2_guards = _q2_same_fix(new_feats, prior_features)
            if q1_same or q2_same:
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "verdict": "DUPLICATE" if (q1_same and q2_same) else "PARTIAL_OVERLAP",
                })

    elif platform == "cantina":
        # Cantina: additionally require asset-selector overlap before flagging.
        # Asset is read from <!-- cantina-asset: <name> --> in the draft OR
        # from --asset-selector CLI arg.
        new_asset = args.asset_selector or _extract_cantina_asset(new_text)
        if new_asset is None:
            warnings.append(
                "[L31][cantina] No asset-selector found in draft (<!-- cantina-asset: ... --> or "
                "--asset-selector). Cross-asset dedup skipped; falling back to immunefi baseline."
            )

        for pr in priors:
            prior_features = pr["features"]
            q1_same, q1_overlap = _q1_same_files(new_feats, prior_features)
            q2_same, q2_fixes, q2_guards = _q2_same_fix(new_feats, prior_features)
            if not (q1_same or q2_same):
                continue

            # Cantina extra rule: only flag DUPLICATE if asset-selectors overlap.
            prior_asset = _extract_cantina_asset(
                _read_text(Path(pr["path"])) if new_asset else ""
            )
            asset_overlaps = (
                new_asset is None           # no asset info — be conservative, flag it
                or prior_asset is None      # prior has no asset tag — conservative
                or new_asset.strip().lower() == prior_asset.strip().lower()
            )

            if not asset_overlaps:
                # Different asset rows — per Cantina rules, cross-asset filings
                # are treated as separate submissions even with shared fix.
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "cantina_asset_new": new_asset,
                    "cantina_asset_prior": prior_asset,
                    "verdict": "DISTINCT_CROSS_ASSET",
                })
            else:
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "cantina_asset_new": new_asset,
                    "cantina_asset_prior": prior_asset,
                    "verdict": "DUPLICATE" if (q1_same and q2_same) else "PARTIAL_OVERLAP",
                })

    elif platform == "sherlock":
        # Sherlock: uniqueness escalation — if Q2 would flag duplicate but
        # the new draft's impact-class is NOT present in any prior report,
        # the verdict is distinct-by-uniqueness-escalation.
        new_impacts = _extract_sherlock_impacts(new_text)
        if args.impact_class:
            new_impacts.add(args.impact_class.strip())

        for pr in priors:
            prior_features = pr["features"]
            q1_same, q1_overlap = _q1_same_files(new_feats, prior_features)
            q2_same, q2_fixes, q2_guards = _q2_same_fix(new_feats, prior_features)
            if not (q1_same or q2_same):
                continue

            prior_text = _read_text(Path(pr["path"]))
            prior_impacts = _extract_sherlock_impacts(prior_text)

            # Check if new draft's impact-classes are ALL novel vs this prior.
            novel_impacts = new_impacts - prior_impacts if new_impacts else set()
            all_novel = bool(novel_impacts) and not (new_impacts & prior_impacts)

            if q2_same and all_novel:
                # Uniqueness escalation applies — shared fix but novel impact-class.
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "sherlock_new_impacts": sorted(new_impacts),
                    "sherlock_prior_impacts": sorted(prior_impacts),
                    "sherlock_novel_impacts": sorted(novel_impacts),
                    "verdict": "DISTINCT_BY_UNIQUENESS_ESCALATION",
                })
                warnings.append(
                    f"[L31][sherlock] Q2 shared fix with {pr['id']} BUT impact-class "
                    f"{sorted(novel_impacts)} is novel → distinct-by-uniqueness-escalation. "
                    "Sherlock watson may still merge at judge discretion."
                )
            else:
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "sherlock_new_impacts": sorted(new_impacts),
                    "sherlock_prior_impacts": sorted(prior_impacts),
                    "sherlock_novel_impacts": [],
                    "verdict": "DUPLICATE" if (q1_same and q2_same) else "PARTIAL_OVERLAP",
                })

    elif platform == "code4rena":
        # Code4rena: Q1 auto; Q2 routes to manual judge review unless
        # --c4-judge-flag is set (then behaves like immunefi).
        for pr in priors:
            prior_features = pr["features"]
            q1_same, q1_overlap = _q1_same_files(new_feats, prior_features)
            q2_same, q2_fixes, q2_guards = _q2_same_fix(new_feats, prior_features)
            if not (q1_same or q2_same):
                continue

            if args.c4_judge_flag:
                # With --c4-judge-flag: treat exactly like immunefi.
                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "c4_judge_flag": True,
                    "verdict": "DUPLICATE" if (q1_same and q2_same) else "PARTIAL_OVERLAP",
                })
            else:
                # Without --c4-judge-flag: Q1 auto, Q2 → manual-review-required.
                if q1_same and not q2_same:
                    # Q1 fires alone → definite auto-flag.
                    verdict = "DUPLICATE"
                elif q2_same and not q1_same:
                    # Q2 fires alone → manual review.
                    verdict = "MANUAL_REVIEW_REQUIRED"
                elif q1_same and q2_same:
                    # Both fire — still route Q2 portion to manual.
                    verdict = "MANUAL_REVIEW_REQUIRED"
                else:
                    verdict = "PARTIAL_OVERLAP"

                duplicates.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "prior_lane": pr["lane"],
                    "q1_same_files": q1_same,
                    "q1_overlapping_files": q1_overlap,
                    "q2_same_fix": q2_same,
                    "q2_shared_fix_refs": q2_fixes,
                    "q2_shared_guards": q2_guards,
                    "c4_judge_flag": False,
                    "verdict": verdict,
                })
                if verdict == "MANUAL_REVIEW_REQUIRED":
                    warnings.append(
                        f"[L31][code4rena] Q2 overlap with {pr['id']} requires manual judge "
                        "review. Use --c4-judge-flag if pre-cleared by C4 judge."
                    )

    return duplicates, warnings


def main() -> int:
    p = argparse.ArgumentParser(description="Universal L31 duplicate-preflight gate")
    p.add_argument("draft", help="path to the new draft markdown")
    p.add_argument("--workspace", required=True, help="workspace dir (e.g. ~/audits/dydx)")
    p.add_argument(
        "--platform",
        default="immunefi",
        choices=PLATFORMS,
        help="immunefi|cantina|sherlock|code4rena|private|auto (default: immunefi)",
    )
    p.add_argument(
        "--asset-selector",
        default=None,
        dest="asset_selector",
        help="[cantina] asset row name (e.g. 'v4-chain (protocol)'); "
             "alternative to <!-- cantina-asset: ... --> in the draft",
    )
    p.add_argument(
        "--impact-class",
        default=None,
        dest="impact_class",
        help="[sherlock] impact class for uniqueness escalation; "
             "alternative to <!-- sherlock-impact: ... --> in the draft",
    )
    p.add_argument(
        "--c4-judge-flag",
        action="store_true",
        dest="c4_judge_flag",
        help="[code4rena] treat Q2 like immunefi (pre-cleared by judge)",
    )
    p.add_argument("--prior-reports-dir", help="optional dir of operator-pasted prior reports")
    p.add_argument(
        "--self-skip-same-family",
        action="store_true",
        dest="self_skip_same_family",
        help="skip prior-report comparisons against drafts that share the same "
             "family/lead id (filename prefix RG-N6-S1 / RG-01A / LEAD-1, "
             "frontmatter family_id/lead_id, or shared .paste_hash sidecar). "
             "Avoids the self-collision FP where paste_ready/foo.md and "
             "staging/foo.md represent the same finding family.",
    )
    p.add_argument("--strict", action="store_true", help="exit 1 on any duplicate signal (default: warn-only)")
    p.add_argument("--json", action="store_true", help="emit machine-parseable JSON only")
    args = p.parse_args()

    draft_path = Path(args.draft).expanduser().resolve()
    ws = Path(args.workspace).expanduser().resolve()
    prior_dir = Path(args.prior_reports_dir).expanduser().resolve() if args.prior_reports_dir else None

    if not draft_path.is_file():
        print(f"[error] draft not found: {draft_path}", file=sys.stderr)
        return 3

    text = _read_text(draft_path)
    if not text:
        print(f"[error] draft empty/unreadable: {draft_path}", file=sys.stderr)
        return 3

    new_feats = _extract_features(text)
    priors = _gather_prior_reports(ws, prior_dir)

    # L31-rebuttal override. Prefer the paste-safe visible line form because
    # final paste hygiene rejects HTML comments in operator submissions.
    rebuttal = L31_REBUTTAL_LINE_RE.search(text) or L31_REBUTTAL_COMMENT_RE.search(text)

    # Don't compare against the draft itself (if it's already in submissions/).
    priors = [pr for pr in priors if Path(pr["path"]).resolve() != draft_path]

    # Optional: drop priors that belong to the same finding family as the new
    # draft (paste_ready/foo.md vs staging/foo.md self-collision FP). The
    # filter is OFF by default — pre-submit-check.sh's existing `--strict`
    # call site keeps unchanged behavior.
    self_skip_filtered: list[dict[str, Any]] = []
    if args.self_skip_same_family:
        kept_priors = []
        for pr in priors:
            same, signal = _same_family(draft_path, text, Path(pr["path"]))
            if same:
                self_skip_filtered.append({
                    "prior_id": pr["id"],
                    "prior_path": pr["path"],
                    "signal": signal,
                })
            else:
                kept_priors.append(pr)
        priors = kept_priors

    if not priors:
        result = {
            "schema": SCHEMA_VERSION,
            "draft": str(draft_path),
            "platform": args.platform,
            "verdict": "no_priors_to_compare",
            "duplicates": [],
            "rebuttal": bool(rebuttal),
            "self_skip_same_family": bool(args.self_skip_same_family),
            "self_skipped_priors": self_skip_filtered,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[L31] No prior reports in workspace {ws} — first filing assumed.")
        return 2

    duplicates, warnings = _apply_platform_rules(args.platform, text, new_feats, priors, args)

    rebuttal_payload = None
    if rebuttal:
        rebuttal_payload = {"prior_id": rebuttal.group(1), "reason": rebuttal.group(2).strip()}

    # Determine final verdict — platform-specific "non-duplicate" sub-verdicts
    # (DISTINCT_CROSS_ASSET, DISTINCT_BY_UNIQUENESS_ESCALATION) do not count
    # as duplicates for exit-code purposes.
    non_dupe_verdicts = {"DISTINCT_CROSS_ASSET", "DISTINCT_BY_UNIQUENESS_ESCALATION"}
    real_duplicates = [d for d in duplicates if d["verdict"] not in non_dupe_verdicts]

    if duplicates and rebuttal_payload:
        verdict = "duplicate_with_operator_override"
        exit_code = 0
    elif any(d["verdict"] == "MANUAL_REVIEW_REQUIRED" for d in duplicates):
        verdict = "manual_review_required"
        exit_code = 1 if args.strict else 0
    elif any(d["verdict"] == "DUPLICATE" for d in real_duplicates):
        verdict = "duplicate"
        exit_code = 1 if args.strict else 0
    elif any(d["verdict"] == "DISTINCT_BY_UNIQUENESS_ESCALATION" for d in duplicates):
        verdict = "distinct_by_uniqueness_escalation"
        exit_code = 0
    elif any(d["verdict"] == "DISTINCT_CROSS_ASSET" for d in duplicates):
        verdict = "distinct_cross_asset"
        exit_code = 0
    elif real_duplicates:
        verdict = "partial_overlap_review_required"
        exit_code = 1 if args.strict else 0
    else:
        verdict = "distinct"
        exit_code = 0

    result = {
        "schema": SCHEMA_VERSION,
        "draft": str(draft_path),
        "platform": args.platform,
        "verdict": verdict,
        "new_features": {k: sorted(v) for k, v in new_feats.items()},
        "duplicates": duplicates,
        "warnings": warnings,
        "rebuttal": rebuttal_payload,
        "strict_mode": args.strict,
        "self_skip_same_family": bool(args.self_skip_same_family),
        "self_skipped_priors": self_skip_filtered,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return exit_code

    # Human-readable output.
    print(f"[L31] duplicate-preflight against workspace {ws}")
    print(f"      platform: {args.platform}")
    print(f"      draft:    {draft_path.name}")
    print(f"      verdict:  {verdict}")
    print(f"      priors compared: {len(priors)}")
    if duplicates:
        print(f"      flagged entries: {len(duplicates)}")
        for d in duplicates:
            print(f"        - {d['prior_id']} (lane={d['prior_lane']}, verdict={d['verdict']})")
            if d.get("q1_overlapping_files"):
                print(f"            Q1 overlap files: {', '.join(d['q1_overlapping_files'][:5])}")
            if d.get("q2_shared_fix_refs"):
                print(f"            Q2 shared fix refs: {', '.join(d['q2_shared_fix_refs'])}")
            if d.get("q2_shared_guards"):
                print(f"            Q2 shared guards:   {', '.join(d['q2_shared_guards'])}")
    for w in warnings:
        print(f"      WARN: {w}")
    if rebuttal_payload:
        print(f"      rebuttal: {rebuttal_payload['prior_id']} -- {rebuttal_payload['reason'][:80]}")

    if exit_code != 0:
        print()
        print("[L31] Per Immunefi/Cantina/Sherlock/Code4rena published rules:")
        print("      Q1+Q2 = different files AND different fix → file as distinct.")
        print("      Q1+Q2 indicate overlap → MERGE into prior report or DROP.")
        print("      To override: add `<!-- l31-rebuttal: <prior-id> <reason> -->` to draft body.")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
