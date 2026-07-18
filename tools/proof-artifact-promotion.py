#!/usr/bin/env python3
"""Proof-artifact promotion and outcome linkage for the Hackerman corpus.

Plan item J3a from docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:
  - Promotes the 52 promotion-ready candidates from
    audit/corpus_tags/derived/proof_artifact_index.jsonl into a
    promotion-output sidecar (never clobbers existing data).
  - Emits per-blocked-candidate work rows naming the exact missing field.
  - Computes proof density for submission-derived/filed corpus rows and
    reports whether the 10%-density acceptance threshold is met.
  - For every filed/submitted corpus row, checks it links to an outcome
    row in reference/outcomes.jsonl or carries OUTCOME_LINK_PENDING_REASON.

Schema: auditooor.proof_artifact_promotion.v1

Modes
-----
  (default / --report)    Human-readable summary report.
  --promote               Write promotion-ready rows to the promotion output
                          sidecar (idempotent; never downgrades/deletes).
  --unblock-audit         Emit one work row per blocked candidate naming the
                          first missing field.
  --json                  Emit machine-readable JSON to stdout instead of
                          human prose.
  --strict                Exit non-zero when filed rows lack outcome links
                          and have no OUTCOME_LINK_PENDING_REASON.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths (relative to repo root; tool assumes cwd = repo root)
# ---------------------------------------------------------------------------
PROOF_INDEX_PATH = Path("audit/corpus_tags/derived/proof_artifact_index.jsonl")
PROMOTION_OUTPUT_PATH = Path("audit/corpus_tags/derived/proof_artifact_promotion_output.jsonl")
OUTCOMES_PATH = Path("reference/outcomes.jsonl")

# Submission statuses that count as "filed/submitted"
FILED_STATUSES = frozenset(
    {
        "paste_ready",
        "submitted",
        "filed",
        "packaged",
        "final_cantina_paste",
        "cantina_paste",
        "paste_ready_full",
        "hardened",
        "clean",
        "ready",
    }
)

# Blocker -> human-readable missing-field description
BLOCKER_MISSING_FIELD: dict[str, str] = {
    "submission_status_not_paste_ready_or_filed": "submission_status must be paste_ready or filed",
    "confidence_not_high": "confidence must be 'high' (currently medium/low)",
    "candidate_artifact_missing": "candidate_proof_path artifact does not exist on disk",
    "path_fanout_above_promotion_limit": "candidate appears in too many paths (low specificity); supply a single exact artifact path",
    "match_not_explicit_reference": "match_method must be submission-explicit-path; supply an explicit submission reference",
}

SOURCE_REF_FIELDS = (
    "source_refs",
    "source_ref",
    "current_workspace_source_refs",
    "source_locations",
    "target_source_refs",
    "target_source_ref",
)

BLOCKER_FIELDS = (
    "promotion_blockers",
    "blockers",
    "execution_blockers",
    "terminal_blockers",
)

EVIDENCE_FIELDS = (
    "pass_evidence_lines",
    "proof_evidence",
    "harness_evidence",
    "terminal_evidence",
    "test_transcript",
    "poc_path",
)

CONCRETE_ARTIFACT_KINDS = frozenset(
    {
        "accepted-proof-artifact",
        "execution-output",
        "foundry-test",
        "go-test",
        "harness-file",
        "poc-file",
        "poc-tests",
        "proof-log",
        "proof-note",
        "replay-log",
        "test-file",
        "test-output",
        "transcript",
    }
)

ADVISORY_MARKER_RE = re.compile(
    r"\b(advisory[-_ ]?only|reference[-_ ]?only|informational[-_ ]?only|"
    r"taxonomy[-_ ]?only|synthetic[-_ ]?taxonomy|precedent[-_ ]?only)\b",
    re.IGNORECASE,
)
PLACEHOLDER_REF_RE = re.compile(
    r"^(?:n/?a|none|null|unknown|todo|tbd|conceptual|hypothetical|pattern|sample)(?::|$)",
    re.IGNORECASE,
)
SOURCE_FILE_RE = re.compile(
    r"\.(?:sol|vy|rs|go|move|cairo|ts|tsx|js|jsx|py|java|kt|c|cc|cpp|h|hpp)(?::\d+)?(?:-\d+)?$",
    re.IGNORECASE,
)
PROOFISH_PATH_RE = re.compile(
    r"(^|/)(?:poc|pocs|poc-tests|proof|proofs|harness|harnesses|test|tests|"
    r"differential_fuzz|verification_runs)(?:/|$)|"
    r"(?:_test\.go|\.t\.sol|run_stdout|transcript|execution|forge|foundry|replay)",
    re.IGNORECASE,
)
CONCRETE_PROOF_PATH_RE = re.compile(
    r"(^|/)(?:poc|pocs|poc-tests|proof|proofs|harness|harnesses|test|tests|"
    r"differential_fuzz|verification_runs)(?:/|$)|"
    r"(?:_test\.go|\.t\.sol|run_stdout|transcript|execution|forge|foundry|replay|\.log$)",
    re.IGNORECASE,
)

SCHEMA = "auditooor.proof_artifact_promotion.v1"
PROMOTED_SCHEMA = "auditooor.proof_artifact_promotion_output.v1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file; return empty list if absent or empty."""
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def _dedup_key(row: dict[str, Any]) -> str:
    """Stable identity key for idempotency check in promotion output."""
    # Use candidate_proof_path + submission_path as composite key
    cp = row.get("candidate_proof_path", "")
    sp = row.get("submission_path", "")
    return f"{cp}\x1f{sp}"


def load_promotion_output() -> dict[str, dict[str, Any]]:
    """Return existing promoted rows keyed by dedup_key."""
    rows = read_jsonl(PROMOTION_OUTPUT_PATH)
    return {_dedup_key(r): r for r in rows}


def _blocker_missing_field(blockers: list[str]) -> str:
    """Return a human description of the first recognised blocker."""
    for b in blockers:
        if b in BLOCKER_MISSING_FIELD:
            return BLOCKER_MISSING_FIELD[b]
        # Unknown blocker - return raw
        return f"unknown blocker: {b}"
    return "no blockers listed (unexpected)"


def _as_text_list(value: Any) -> list[str]:
    """Return non-empty strings from common scalar/list/dict shapes."""
    out: list[str] = []

    def add(item: Any) -> None:
        if isinstance(item, str):
            text = item.strip()
            if text:
                out.append(text)
        elif isinstance(item, dict):
            for key in ("path", "file", "source_ref", "source", "ref", "value"):
                raw = item.get(key)
                if isinstance(raw, str) and raw.strip():
                    out.append(raw.strip())
                    break
        elif item is not None and not isinstance(item, (list, tuple, set, dict)):
            text = str(item).strip()
            if text:
                out.append(text)

    if isinstance(value, (list, tuple, set)):
        for item in value:
            add(item)
    else:
        add(value)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in out:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _row_source_refs(row: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for field in SOURCE_REF_FIELDS:
        refs.extend(_as_text_list(row.get(field)))
    return list(dict.fromkeys(refs))


def _row_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for field in BLOCKER_FIELDS:
        blockers.extend(_as_text_list(row.get(field)))
    return list(dict.fromkeys(blockers))


def _clean_pathish_ref(ref: str) -> str:
    text = ref.strip()
    for prefix in ("workspace:", "file:", "path:"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):].strip()
    if "#" in text:
        text = text.split("#", 1)[0]
    return text.strip()


def _pathish_without_line(ref: str) -> str:
    cleaned = _clean_pathish_ref(ref)
    return re.sub(r":\d+(?:-\d+)?$", "", cleaned).strip()


def _row_workspace_tokens(row: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("engagement", "workspace", "workspace_name"):
        value = str(row.get(key) or "").strip().strip("/")
        if value:
            tokens.add(value)
    workspace_path = str(row.get("workspace_path") or "").strip()
    if workspace_path:
        tokens.add(Path(workspace_path).name)
    for key in ("submission_path", "candidate_proof_path"):
        text = str(row.get(key) or "")
        m = re.search(r"(?:^|/)audits/([^/]+)/", text)
        if m:
            tokens.add(m.group(1))
    return {item for item in tokens if item}


def _ref_is_current_workspace(ref: str, row: dict[str, Any]) -> bool:
    pathish = _pathish_without_line(ref)
    if not pathish:
        return False

    workspace_path = str(row.get("workspace_path") or "").strip()
    if workspace_path and Path(pathish).is_absolute():
        try:
            Path(pathish).resolve().relative_to(Path(workspace_path).expanduser().resolve())
            return True
        except (OSError, ValueError):
            return False

    workspace_tokens = _row_workspace_tokens(row)
    audit_match = re.search(r"(?:^|/)audits/([^/]+)/", pathish)
    if audit_match:
        return audit_match.group(1) in workspace_tokens

    if workspace_tokens:
        first = pathish.strip("/").split("/", 1)[0]
        if first in workspace_tokens:
            return True
        if Path(pathish).is_absolute():
            return False

    return not Path(pathish).is_absolute()


def _ref_is_protocol_source(ref: str) -> bool:
    pathish = _pathish_without_line(ref)
    if not SOURCE_FILE_RE.search(pathish):
        return False
    return PROOFISH_PATH_RE.search(pathish) is None


def _valid_current_workspace_source_refs(row: dict[str, Any]) -> list[str]:
    valid: list[str] = []
    for ref in _row_source_refs(row):
        if PLACEHOLDER_REF_RE.search(ref):
            continue
        if _ref_is_protocol_source(ref) and _ref_is_current_workspace(ref, row):
            valid.append(ref)
    return valid


def _has_stale_workspace_source_refs(row: dict[str, Any]) -> bool:
    refs = [
        ref
        for ref in _row_source_refs(row)
        if not PLACEHOLDER_REF_RE.search(ref) and _ref_is_protocol_source(ref)
    ]
    if not refs:
        return False
    return not any(_ref_is_current_workspace(ref, row) for ref in refs)


def _has_advisory_only_marker(row: dict[str, Any]) -> bool:
    if row.get("advisory_only") is True:
        return True
    texts: list[str] = []
    for key in (
        "candidate_artifact_kind",
        "match_method",
        "promotion_review_reason",
        "proof_status",
        "record_kind",
        "raw_reference",
    ):
        texts.extend(_as_text_list(row.get(key)))
    texts.extend(_as_text_list(row.get("source_reasons")))
    texts.extend(_as_text_list(row.get("tags")))
    return any(ADVISORY_MARKER_RE.search(text) for text in texts)


def _has_concrete_proof_evidence(row: dict[str, Any]) -> bool:
    if row.get("candidate_artifact_exists") is not True:
        return False
    proof_path = str(row.get("candidate_proof_path") or "").strip()
    kind = str(row.get("candidate_artifact_kind") or "").strip().lower()
    if not proof_path:
        return False
    if ADVISORY_MARKER_RE.search(kind) or ADVISORY_MARKER_RE.search(proof_path):
        return False
    if kind in CONCRETE_ARTIFACT_KINDS or CONCRETE_PROOF_PATH_RE.search(proof_path):
        return True
    for field in EVIDENCE_FIELDS:
        if _as_text_list(row.get(field)):
            return True
    return False


def strict_promotion_rejection_reasons(row: dict[str, Any]) -> list[str]:
    """Return typed reasons that prevent promotion under the strict gate."""
    reasons: list[str] = []

    if row.get("promotion_ready") is not True:
        reasons.append("promotion_ready_not_true")
    if str(row.get("promotion_review_status") or "ready") != "ready":
        reasons.append("promotion_review_status_not_ready")

    for blocker in _row_blockers(row):
        reasons.append(f"promotion_blocker:{blocker}")

    valid_refs = _valid_current_workspace_source_refs(row)
    if not valid_refs:
        if _has_stale_workspace_source_refs(row):
            reasons.append("stale_workspace_source_refs")
        else:
            reasons.append("missing_current_workspace_source_refs")

    if not _has_concrete_proof_evidence(row):
        reasons.append("missing_concrete_harness_or_proof_evidence")

    if _has_advisory_only_marker(row):
        reasons.append("advisory_only_marker")

    return list(dict.fromkeys(reasons))


def _promotion_rejection_row(row: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "record_kind": "promotion_rejection",
        "engagement": row.get("engagement", ""),
        "candidate_proof_path": row.get("candidate_proof_path", ""),
        "candidate_artifact_kind": row.get("candidate_artifact_kind", ""),
        "submission_path": row.get("submission_path", ""),
        "submission_status": row.get("submission_status", ""),
        "submission_title": row.get("submission_title", ""),
        "confidence": row.get("confidence", ""),
        "promotion_rejection_reasons": reasons,
        "first_rejection_reason": reasons[0] if reasons else "",
        "source_refs": _row_source_refs(row),
        "valid_current_workspace_source_refs": _valid_current_workspace_source_refs(row),
    }


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def load_and_split_index() -> tuple[list[dict], list[dict]]:
    """Return (ready_rows, blocked_rows) from proof_artifact_index.jsonl."""
    all_rows = read_jsonl(PROOF_INDEX_PATH)
    ready = [r for r in all_rows if r.get("promotion_ready") is True]
    blocked = [r for r in all_rows if r.get("promotion_review_status") == "blocked"
               or (r.get("promotion_ready") is False and r.get("promotion_review_status") != "ready")]
    return ready, blocked


def compute_density(index_rows: list[dict]) -> dict[str, Any]:
    """Compute proof density for filed/submitted corpus rows.

    Density = (rows with non-empty candidate_proof_path AND candidate_artifact_exists=True)
              / total filed rows.
    Threshold: 10%.
    """
    filed = [r for r in index_rows if r.get("submission_status", "") in FILED_STATUSES]
    total_filed = len(filed)
    if total_filed == 0:
        return {
            "filed_rows": 0,
            "rows_with_proof": 0,
            "density_pct": 0.0,
            "threshold_pct": 10.0,
            "threshold_met": False,
            "note": "no filed/submitted rows found",
        }

    with_proof = [
        r for r in filed
        if r.get("candidate_proof_path", "") and r.get("candidate_artifact_exists") is True
    ]
    density_pct = 100.0 * len(with_proof) / total_filed
    return {
        "filed_rows": total_filed,
        "rows_with_proof": len(with_proof),
        "density_pct": round(density_pct, 2),
        "threshold_pct": 10.0,
        "threshold_met": density_pct >= 10.0,
        "by_engagement": dict(
            Counter(r.get("engagement", "unknown") for r in with_proof)
        ),
    }


def load_outcomes() -> list[dict[str, Any]]:
    return read_jsonl(OUTCOMES_PATH)


def build_outcome_link_index(outcomes: list[dict]) -> dict[str, dict]:
    """Build lookup: (workspace, finding_id) -> outcome row, and title -> outcome row."""
    by_fid: dict[str, dict] = {}
    by_title: dict[str, dict] = {}
    for o in outcomes:
        ws = o.get("workspace", "")
        fid = str(o.get("finding_id", ""))
        if fid:
            by_fid[f"{ws}:{fid}"] = o
        title = o.get("title", "").strip().lower()
        if title:
            by_title[title] = o
    return {"by_fid": by_fid, "by_title": by_title}


def check_outcome_links(
    index_rows: list[dict],
    outcome_index: dict[str, dict],
    strict: bool = False,
) -> dict[str, Any]:
    """For every filed/submitted row, check it links to an outcome or has OUTCOME_LINK_PENDING_REASON."""
    filed = [r for r in index_rows if r.get("submission_status", "") in FILED_STATUSES]
    by_fid = outcome_index.get("by_fid", {})
    by_title = outcome_index.get("by_title", {})

    missing_link: list[dict] = []
    linked: list[dict] = []
    pending_reason: list[dict] = []

    for r in filed:
        # Check for inline pending reason marker
        if r.get("OUTCOME_LINK_PENDING_REASON"):
            pending_reason.append(r)
            continue

        # Try to match via title
        title = (r.get("submission_title") or "").strip().lower()
        eng = r.get("engagement", "")

        # Try direct title match
        if title and title in by_title:
            linked.append(r)
            continue

        # Try partial title match (title starts-with any outcome title)
        matched = False
        for outcome_title in by_title:
            if title and outcome_title and (
                title.startswith(outcome_title[:40]) or outcome_title.startswith(title[:40])
            ):
                matched = True
                break
        if matched:
            linked.append(r)
            continue

        # Not linked
        missing_link.append(r)

    strict_fail = strict and bool(missing_link)

    return {
        "filed_rows": len(filed),
        "linked": len(linked),
        "pending_reason": len(pending_reason),
        "missing_link": len(missing_link),
        "missing_link_rows": [
            {
                "submission_path": r.get("submission_path", ""),
                "submission_title": r.get("submission_title", ""),
                "engagement": r.get("engagement", ""),
                "candidate_proof_path": r.get("candidate_proof_path", ""),
                "remedy": "Add OUTCOME_LINK_PENDING_REASON field, or add a matching row in reference/outcomes.jsonl",
            }
            for r in missing_link[:50]  # cap for large outputs
        ],
        "strict_fail": strict_fail,
    }


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def do_promote(ready_rows: list[dict]) -> dict[str, Any]:
    """Promote ready rows into the promotion output sidecar (idempotent)."""
    if not ready_rows:
        return {
            "promoted_new": 0,
            "already_present": 0,
            "rejected": 0,
            "rejection_counts": {},
            "rejected_rows": [],
            "output_path": str(PROMOTION_OUTPUT_PATH),
            "note": "no promotion-ready rows to write",
        }

    existing = load_promotion_output()
    new_rows: list[dict] = []
    rejected_rows: list[dict] = []
    rejection_counts: Counter[str] = Counter()

    for r in ready_rows:
        rejection_reasons = strict_promotion_rejection_reasons(r)
        if rejection_reasons:
            rejected = _promotion_rejection_row(r, rejection_reasons)
            rejected_rows.append(rejected)
            rejection_counts.update(rejection_reasons)
            continue
        key = _dedup_key(r)
        if key in existing:
            continue  # idempotent: skip already promoted
        promoted_row: dict[str, Any] = {
            "schema": PROMOTED_SCHEMA,
            "promoted_at": now_utc(),
            "promotion_source": "proof_artifact_index",
            "promotion_gate_version": r.get("promotion_gate_version", ""),
            "engagement": r.get("engagement", ""),
            "candidate_proof_path": r.get("candidate_proof_path", ""),
            "candidate_artifact_kind": r.get("candidate_artifact_kind", ""),
            "candidate_artifact_exists": r.get("candidate_artifact_exists", False),
            "submission_path": r.get("submission_path", ""),
            "submission_status": r.get("submission_status", ""),
            "submission_title": r.get("submission_title", ""),
            "confidence": r.get("confidence", ""),
            "confidence_score": r.get("confidence_score", 0.0),
            "match_method": r.get("match_method", ""),
            "raw_reference": r.get("raw_reference", ""),
            "source_refs": _row_source_refs(r),
            "valid_current_workspace_source_refs": _valid_current_workspace_source_refs(r),
            "source_reasons": r.get("source_reasons", []),
            "token_overlap": r.get("token_overlap", []),
            "proof_status": "promotion_ready",
            "strict_promotion_checks": {
                "current_workspace_source_refs": True,
                "concrete_harness_or_proof_evidence": True,
                "no_blocker_or_advisory_only_markers": True,
            },
            "OUTCOME_LINK_PENDING_REASON": "",
            "original_record": r,
        }
        new_rows.append(promoted_row)

    if new_rows:
        PROMOTION_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with PROMOTION_OUTPUT_PATH.open("a", encoding="utf-8") as fh:
            for row in new_rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {
        "promoted_new": len(new_rows),
        "already_present": len(ready_rows) - len(new_rows) - len(rejected_rows),
        "rejected": len(rejected_rows),
        "rejection_counts": dict(sorted(rejection_counts.items())),
        "rejected_rows": rejected_rows[:200],
        "output_path": str(PROMOTION_OUTPUT_PATH),
    }


def do_unblock_audit(blocked_rows: list[dict]) -> list[dict]:
    """Emit one work row per blocked candidate naming the first missing field."""
    work_rows = []
    for r in blocked_rows:
        blockers = r.get("promotion_blockers", [])
        strict_reasons = strict_promotion_rejection_reasons(r)
        missing_field = _blocker_missing_field(blockers)
        work_rows.append(
            {
                "schema": SCHEMA,
                "record_kind": "unblock_work_row",
                "engagement": r.get("engagement", ""),
                "candidate_proof_path": r.get("candidate_proof_path", ""),
                "submission_path": r.get("submission_path", ""),
                "submission_status": r.get("submission_status", ""),
                "submission_title": r.get("submission_title", ""),
                "confidence": r.get("confidence", ""),
                "promotion_blockers": blockers,
                "promotion_rejection_reasons": strict_reasons,
                "first_missing_field": missing_field,
                "remedy": _remedy_for_blockers(blockers, r),
            }
        )
    return work_rows


def _remedy_for_blockers(blockers: list[str], row: dict) -> str:
    parts = []
    for b in blockers:
        if b == "submission_status_not_paste_ready_or_filed":
            parts.append(
                f"Move submission '{row.get('submission_path','')}' to paste_ready or filed status"
            )
        elif b == "confidence_not_high":
            parts.append(
                "Verify artifact matches submission exactly (confidence is currently medium/low)"
            )
        elif b == "candidate_artifact_missing":
            parts.append(
                f"Provide artifact at path '{row.get('candidate_proof_path','')}' or update raw_reference"
            )
        elif b == "path_fanout_above_promotion_limit":
            parts.append(
                "Supply a single explicit artifact path (high fanout means multiple candidates match)"
            )
        elif b == "match_not_explicit_reference":
            parts.append(
                "Add an explicit submission reference pointing to the exact artifact path"
            )
        else:
            parts.append(f"Resolve blocker: {b}")
    return "; ".join(parts) if parts else "review manually"


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(
    ready_rows: list[dict],
    blocked_rows: list[dict],
    index_rows: list[dict],
    density: dict,
    outcome_links: dict,
    promote_result: dict | None = None,
    unblock_rows: list[dict] | None = None,
) -> dict[str, Any]:
    total = len(index_rows)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": now_utc(),
        "sidecar_path": str(PROOF_INDEX_PATH),
        "summary": {
            "total_candidates": total,
            "promotion_ready": len(ready_rows),
            "blocked": len(blocked_rows),
            "other": total - len(ready_rows) - len(blocked_rows),
        },
        "blocked_by_reason": dict(
            Counter(
                b
                for r in blocked_rows
                for b in r.get("promotion_blockers", ["unknown"])
            )
        ),
        "density": density,
        "outcome_links": outcome_links,
    }
    if promote_result is not None:
        report["promote_result"] = promote_result
    if unblock_rows is not None:
        report["unblock_audit"] = {
            "total_blocked": len(blocked_rows),
            "work_rows_emitted": len(unblock_rows),
            "work_rows": unblock_rows[:200],  # cap for large outputs
        }
    return report


def print_human_report(report: dict) -> None:
    s = report["summary"]
    d = report["density"]
    ol = report["outcome_links"]

    print("=" * 60)
    print("Proof Artifact Promotion Report")
    print(f"Generated: {report['generated_at']}")
    print("=" * 60)
    print()
    print("[Candidate Split]")
    print(f"  Total candidates : {s['total_candidates']}")
    print(f"  Promotion-ready  : {s['promotion_ready']}")
    print(f"  Blocked          : {s['blocked']}")
    print(f"  Other            : {s['other']}")
    print()
    print("[Blocked-by-Reason]")
    for reason, count in sorted(
        report["blocked_by_reason"].items(), key=lambda x: -x[1]
    ):
        print(f"  {count:4d}  {reason}")
    print()
    print("[Proof Density (filed/submitted rows)]")
    print(f"  Filed rows       : {d['filed_rows']}")
    print(f"  With proof       : {d['rows_with_proof']}")
    print(f"  Density          : {d['density_pct']}%")
    print(f"  Threshold        : {d['threshold_pct']}%")
    threshold_msg = "PASS" if d["threshold_met"] else "BELOW THRESHOLD"
    print(f"  Status           : {threshold_msg}")
    if "note" in d:
        print(f"  Note             : {d['note']}")
    print()
    print("[Outcome Links (filed/submitted rows)]")
    print(f"  Filed rows       : {ol['filed_rows']}")
    print(f"  Linked           : {ol['linked']}")
    print(f"  Pending reason   : {ol['pending_reason']}")
    print(f"  Missing link     : {ol['missing_link']}")
    if ol["missing_link_rows"]:
        print("  Missing (up to 10):")
        for row in ol["missing_link_rows"][:10]:
            title = (row.get("submission_title") or "")[:60]
            print(f"    - [{row.get('engagement','')}] {title}")
            print(f"      remedy: {row.get('remedy','')}")
    print()

    pr = report.get("promote_result")
    if pr is not None:
        print("[Promote Result]")
        print(f"  New promoted     : {pr.get('promoted_new', 0)}")
        print(f"  Already present  : {pr.get('already_present', 0)}")
        print(f"  Rejected         : {pr.get('rejected', 0)}")
        print(f"  Output path      : {pr.get('output_path', '')}")
        if pr.get("rejection_counts"):
            print("  Rejection reasons:")
            for reason, count in sorted(pr["rejection_counts"].items(), key=lambda x: (-x[1], x[0])):
                print(f"    {count:4d}  {reason}")
        if pr.get("rejected_rows"):
            print("  Rejected (up to 5):")
            for row in pr["rejected_rows"][:5]:
                title = (row.get("submission_title") or "")[:50]
                first = row.get("first_rejection_reason", "")
                print(f"    [{row.get('engagement','')}] {title}")
                print(f"      reason: {first}")
        print()

    ua = report.get("unblock_audit")
    if ua is not None:
        print("[Unblock Audit]")
        print(f"  Total blocked    : {ua.get('total_blocked', 0)}")
        print(f"  Work rows        : {ua.get('work_rows_emitted', 0)}")
        if ua.get("work_rows"):
            print("  First 5 work rows:")
            for wr in ua["work_rows"][:5]:
                print(f"    [{wr.get('engagement','')}] {(wr.get('submission_title') or '')[:50]}")
                print(f"      missing: {wr.get('first_missing_field','')}")
        print()

    print("=" * 60)
    if ol.get("strict_fail"):
        print("STRICT MODE: filed rows without outcome links detected")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="J3a proof-artifact promotion and outcome linkage tool."
    )
    p.add_argument(
        "--proof-index",
        default=str(PROOF_INDEX_PATH),
        help="Path to proof_artifact_index.jsonl (default: %(default)s)",
    )
    p.add_argument(
        "--promotion-output",
        default=str(PROMOTION_OUTPUT_PATH),
        help="Path for promotion output sidecar (default: %(default)s)",
    )
    p.add_argument(
        "--outcomes",
        default=str(OUTCOMES_PATH),
        help="Path to reference/outcomes.jsonl (default: %(default)s)",
    )
    p.add_argument(
        "--promote",
        action="store_true",
        help="Write promotion-ready rows to the promotion output sidecar (idempotent).",
    )
    p.add_argument(
        "--unblock-audit",
        action="store_true",
        dest="unblock_audit",
        help="Emit one work row per blocked candidate naming the first missing field.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Emit machine-readable JSON to stdout.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when filed rows lack outcome links and have no OUTCOME_LINK_PENDING_REASON.",
    )
    p.add_argument(
        "--density-threshold",
        type=float,
        default=10.0,
        metavar="PCT",
        help="Proof density acceptance threshold in percent (default: 10.0).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Override module-level paths from CLI args
    global PROOF_INDEX_PATH, PROMOTION_OUTPUT_PATH, OUTCOMES_PATH
    PROOF_INDEX_PATH = Path(args.proof_index)
    PROMOTION_OUTPUT_PATH = Path(args.promotion_output)
    OUTCOMES_PATH = Path(args.outcomes)

    # Load data
    index_rows = read_jsonl(PROOF_INDEX_PATH)

    if not index_rows:
        result: dict[str, Any] = {
            "schema": SCHEMA,
            "generated_at": now_utc(),
            "error": "missing_artifact",
            "message": f"proof artifact sidecar not found or empty: {PROOF_INDEX_PATH}",
        }
        if args.json_mode:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"WARNING: {result['message']}")
        return 0  # not a crash

    ready_rows = [r for r in index_rows if r.get("promotion_ready") is True]
    blocked_rows = [
        r for r in index_rows
        if r.get("promotion_review_status") == "blocked"
        or (r.get("promotion_ready") is False and r.get("promotion_review_status") != "ready")
    ]

    outcomes = load_outcomes()
    outcome_index = build_outcome_link_index(outcomes)

    density = compute_density(index_rows)
    density["threshold_pct"] = args.density_threshold
    density["threshold_met"] = density["density_pct"] >= args.density_threshold

    outcome_links = check_outcome_links(index_rows, outcome_index, strict=args.strict)

    promote_result: dict | None = None
    unblock_rows: list[dict] | None = None

    if args.promote:
        promote_result = do_promote(ready_rows)

    if args.unblock_audit:
        unblock_rows = do_unblock_audit(blocked_rows)

    report = build_report(
        ready_rows,
        blocked_rows,
        index_rows,
        density,
        outcome_links,
        promote_result,
        unblock_rows,
    )

    if args.json_mode:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if outcome_links.get("strict_fail"):
            return 1
    else:
        print_human_report(report)
        # strict exit is handled inside print_human_report via sys.exit(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
