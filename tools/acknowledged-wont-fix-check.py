#!/usr/bin/env python3
"""Rule 47 Acknowledged-Wont-Fix precheck (Check #94).

# Rule 47: this tool emits no corpus record.

TRIGGER: HIGH+ drafts before paste-ready promotion.

When a finding's root cause has already been acknowledged or accepted-as-wont-fix
in a prior audit report, a known-issues catalog (SRL, GHSA, Security Council),
or a program SECURITY.md, the draft MUST demonstrate "extension-distinct" evidence
before promotion: i.e., the new finding exploits a downstream surface NOT
contemplated by the acknowledgement, or breaks the acknowledged mitigation in a
NEW way.

Required section: "Acknowledgement Scan" with 4 sub-fields:
  1. Scan paths: workspace prior_audits/, SECURITY.md, audit/postmortems/,
     reference/known_issues_catalogs/ plus any workspace-operator-declared URL paths.
  2. Acknowledgement found: yes/no + verbatim quote + URL or file:line citation.
  3. Extension-distinct evidence: if acknowledged, does this finding exploit a
     downstream surface or break the mitigation in a new way?
  4. Verdict.

Verdicts:
  pass-out-of-scope                      - severity below HIGH or missing
  pass-no-acknowledgement-found          - scan performed, no acknowledgement found
  pass-extension-distinct-from-acknowledgement - ack found but new finding is distinct
  ok-rebuttal                            - valid r47-rebuttal marker present
  fail-acknowledged-without-extension-distinct - ack found, no extension-distinct evidence
  fail-no-acknowledgement-scan-performed - HIGH+ draft missing "Acknowledgement Scan" section
  error

CLI: <draft.md> [--workspace <ws>] [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}]
     [--strict] [--json]

Override marker: r47-rebuttal: <reason> <=200 chars OR <!-- r47-rebuttal: <reason> -->

Schema: auditooor.r47_acknowledged_wont_fix.v1

Exit codes:
  0 - pass / ok-rebuttal / out-of-scope
  1 - Rule 47 violation (fail-* verdict); with --strict also fires on close-fail
  2 - input error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# RANK-2 wiring: the structured known-issues registry
# (.auditooor/known_issues.json) is the durable home for operator-declared
# acknowledged / OOS / won't-fix issues. R47's workspace scan previously read
# ONLY prose .md/.txt docs, so a registry-declared acknowledgement was invisible
# to the paste-ready gate. ADDITIVE: synthesize ack lines from the registry on
# top of the prose scan. The r47-rebuttal override is unaffected.
_AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
try:
    from tools.lib import known_issues_registry as _ki_registry  # type: ignore
except Exception:  # pragma: no cover - direct-script fallback
    try:
        sys.path.insert(0, str(_AUDITOOOR_ROOT / "tools" / "lib"))
        import known_issues_registry as _ki_registry  # type: ignore
    except Exception:
        _ki_registry = None  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.r47_acknowledged_wont_fix.v1"
GATE = "R47-ACKNOWLEDGED-WONT-FIX-PRECHECK"
REBUTTAL_MAX_CHARS = 200

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Acknowledgement signals in workspace documents
# ---------------------------------------------------------------------------

# Phrases in prior_audits / known-issues catalogs that signal a root-cause
# acknowledgement or accepted-risk entry.
DEFAULT_ACK_PATTERNS: list[str] = [
    r"\backnowledged\b",
    r"\baccepted[- ]risk\b",
    r"\bwont[- ]fix\b",
    r"\bwon['']t\s+fix\b",
    r"\bby[- ]design\b",
    r"\bintentional(?:ly)?\b",
    r"\bknown[- ](?:issue|limitation|risk|behavior)\b",
    r"\bnot[- ]exploitable\b",
    r"\brisk[- ]accepted\b",
    r"\bout[- ]of[- ]scope\b.*\backnowledged\b",
    r"\backnowledged\b.*\bout[- ]of[- ]scope\b",
    r"\bno[- ](?:fix|patch|mitigation)\s+(?:planned|required|needed)\b",
    r"\blocal[- ]consensus[- ]only\b",
    r"\bduplicate\b.*\bknown\b",
    r"\bsrl[- ]\d",      # SRL catalog entries e.g. SRL-6.10
    r"\bghsa[- ][a-z0-9-]+",  # GHSA IDs
    r"\btrusted[- ]node[- ]assumption\b",
]

# Source comments use less formal wording than audit reports.  These signals
# are only meaningful when the comment is attached to a security-sensitive
# path; a repository-wide TODO grep would turn ordinary maintenance notes into
# false acknowledgements.
SOURCE_ACK_PATTERNS: list[str] = [
    r"\bknown[- ]issue\b",
    r"\bteam\s+aware\b",
    r"\bwill\s+wire\b",
    r"\bplanned\s+fix\b",
    r"\baccepted[- ]risk\b",
    r"\bwont[- ]fix\b",
    r"\bwon['']t\s+fix\b",
]

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".move", ".py", ".rs", ".sol", ".swift", ".ts",
    ".tsx", ".vy",
}
SOURCE_SKIP_DIRS = {
    ".git", ".auditooor", "cache", "node_modules", "out", "target",
    "vendor",
}
COMMENT_TERMINAL_DISPOSITIONS = {
    "ordinary-comment",
    "known-issue-oos",
    "planned-remediation-oos",
    "risk-accepted-oos",
    "wont-fix-oos",
    "duplicate-oos",
    "claimed-fixed-verified",
    "claimed-fixed-disproved",
    "not-applicable",
}
SOURCE_COMMENT_REFRESH_SCHEMA = "auditooor.source_comment_analysis_refresh_required.v1"

# Terms that indicate the comment is attached to an authorization, validation,
# state-transition, value-moving, consensus, or cryptographic path.
SECURITY_PATH_RE = re.compile(
    r"\b(?:access|admin|allowance|amount|auth(?:or(?:ity|ization))?|balance|"
    r"bridge|burn|check|claim|consensus|deposit|execute|finali[sz]e|guard|"
    r"mint|nonce|oracle|owner|permission|price|proof|redeem|reentr|role|"
    r"root|sign(?:ature|er)?|state|transfer|validate|verify|vote|withdraw)\w*\b",
    re.IGNORECASE,
)

SOURCE_COMMENT_RE = re.compile(r"(?://|#|/\*|\*)\s*(.*)$")

# Patterns in the DRAFT that signal the scan section is present.
ACK_SCAN_SECTION_RE = re.compile(
    r"(?im)^#+\s*acknowledgement\s+scan"
    r"|^##\s*acknowledgement\s+scan\b"
    r"|^acknowledgement\s+scan\s*:?$"
    r"|^#+\s*known[- ]issues?\s+scan\b",
)

# Sub-field 1: Scan paths declaration
SCAN_PATHS_RE = re.compile(
    r"(?im)scan\s+path[s]?\s*:"
    r"|paths?\s+scanned\s*:"
    r"|scanned\s+location[s]?\s*:",
)

# Sub-field 2: Acknowledgement found
ACK_FOUND_RE = re.compile(
    r"(?im)acknowledgement\s+found\s*:"
    r"|ack(?:nowledgement)?\s+found\s*:"
    r"|found\s*:\s*(?:yes|no)\b",
)
ACK_FOUND_YES_RE = re.compile(
    r"(?im)acknowledgement\s+found\s*:\s*yes\b"
    r"|ack\s+found\s*:\s*yes\b"
    r"|found\s*:\s*yes\b",
)

# Sub-field 3: Extension-distinct evidence
EXTENSION_DISTINCT_RE = re.compile(
    r"(?im)extension[- ]distinct\s+evidence\s*:"
    r"|extension[- ]distinct\s*:"
    r"|distinct\s+(?:from|evidence)\s*:",
)
EXTENSION_DISTINCT_POSITIVE_RE = re.compile(
    r"(?im)extension[- ]distinct\s*(?:evidence)?\s*:\s*yes\b"
    r"|extension[- ]distinct\s*:\s*yes\b"
    r"|distinct\s*:\s*yes\b",
)
EXTENSION_DISTINCT_CONTENT_RE = re.compile(
    # Substantive extension-distinct language in the section body
    r"(?:downstream\s+surface|new\s+(?:attack\s+)?(?:surface|vector|path)|"
    r"breaks?\s+the\s+(?:acknowledged\s+)?mitigation|"
    r"not\s+contemplated\s+by\s+the\s+acknowledgement|"
    r"exploit[s]?\s+a\s+(?:separate|different|new|distinct)\s+(?:surface|vector|path|function|call\s*site)|"
    r"novel\s+(?:entry\s*point|path|attack)|"
    r"circumvents?\s+the\s+(?:acknowledged\s+)?(?:fix|mitigation|guard)|"
    r"residual\s+(?:gap|risk|exposure)|"
    r"bypass\s+(?:the\s+)?(?:fix|mitigation|guard)|"
    r"the\s+fix\s+(?:did\s+not|does\s+not|doesn['']t)\s+(?:address|cover|close|patch))",
    re.IGNORECASE,
)

# Sub-field 4: Verdict line
VERDICT_LINE_RE = re.compile(
    r"(?im)^\s*[-*]?\s*verdict\s*:\s*(?:pass|fail|extension[- ]distinct|acknowledged|no[- ]ack)\b"
    r"|verdict\s*:\s*(?:pass|fail|extension[- ]distinct|acknowledged|no[- ]ack)",
)

# Verbatim quote / citation evidence in the scan section
VERBATIM_QUOTE_RE = re.compile(
    r'"[^"]{10,}"'           # double-quoted 10+ char string
    r"|'[^']{10,}'"          # single-quoted
    r"|>[^\n]{10,}"          # blockquote
    r"|file:[^\s]+:\d+"      # file:line
    r"|https?://\S{10,}"     # URL
    r"|SRL-\d+\.\d+"         # SRL catalog ID
    r"|GHSA-[a-z0-9-]+"      # GHSA ID
    r"|\bprior_audits/\S+"   # file reference
    r"|\baudit/postmortems/\S+",
    re.IGNORECASE,
)

# Rebuttal markers
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r47-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r47[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)

# Workspace scan paths to check for acknowledgements
WORKSPACE_SCAN_PATHS = [
    "prior_audits",
    "reference/known_issues_catalogs",
    "audit/postmortems",
    "SECURITY.md",
    "security.md",
    "KNOWN_ISSUES.md",
    "known_issues.md",
]

SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")
SCOPE_FILE_NAMES = ("SCOPE.md", "scope.md", "Scope.md")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*\**\s*:\s*\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 10) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({
                "line": idx,
                "token": m.group(0)[:80],
                "text": line.strip()[:240],
            })
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _workspace_root(draft: Path, ws_override: Path | None) -> Path:
    if ws_override is not None:
        return ws_override.resolve()
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
        for name in (*SEVERITY_FILE_NAMES, *SCOPE_FILE_NAMES):
            if (parent / name).is_file():
                return parent
    return draft.resolve().parent


def _scan_workspace_for_acknowledgements(
    ws: Path,
    ack_re: re.Pattern[str],
) -> list[dict[str, Any]]:
    """Scan workspace scan paths for acknowledgement signals.

    Returns list of hit dicts with source_file, line, token, text.
    """
    results: list[dict[str, Any]] = []

    # Env-declared extra paths
    extra_paths = _env_patterns("AUDITOOOR_R47_EXTRA_SCAN_PATHS")
    all_scan_paths = WORKSPACE_SCAN_PATHS + extra_paths

    for rel_path in all_scan_paths:
        candidate = ws / rel_path
        if candidate.is_file():
            try:
                text = _read_text(candidate)
                hits = _line_hits(text, ack_re)
                for h in hits:
                    h["source_file"] = str(candidate)
                results.extend(hits)
            except Exception:
                pass
        elif candidate.is_dir():
            # Scan .md, .txt, .pdf.txt within the directory recursively
            for ext in ("*.md", "*.txt"):
                for p in sorted(candidate.rglob(ext)):
                    if p.is_file():
                        try:
                            text = _read_text(p)
                            hits = _line_hits(text, ack_re, limit=5)
                            for h in hits:
                                h["source_file"] = str(p)
                            results.extend(hits)
                            if len(results) >= 50:
                                return results
                        except Exception:
                            pass

    return results


def _scan_source_comments_for_acknowledgements(ws: Path) -> list[dict[str, Any]]:
    """Find explicit disposition comments attached to security-relevant code.

    The disposition and security-path terms may be on adjacent code/comment
    lines to support comments such as ``// known issue`` immediately above a
    guarded function.  Generic TODOs and prose outside code files are ignored.
    """
    disposition_re = _compile_union(SOURCE_ACK_PATTERNS)
    results: list[dict[str, Any]] = []
    try:
        paths = _source_paths(ws)
    except OSError:
        return results

    for path in paths:
        try:
            lines = _read_text(path).splitlines()
        except Exception:
            continue
        for index, line in enumerate(lines):
            comment = SOURCE_COMMENT_RE.search(line)
            if not comment or not disposition_re.search(comment.group(1)):
                continue
            start = max(0, index - 2)
            end = min(len(lines), index + 3)
            context = "\n".join(lines[start:end])
            if not SECURITY_PATH_RE.search(context):
                continue
            signal = disposition_re.search(comment.group(1))
            results.append({
                "line": index + 1,
                "token": signal.group(0)[:80] if signal else "source disposition",
                "text": line.strip()[:240],
                "source_file": str(path),
                "evidence_class": "known-issue/oos",
                "source_comment": True,
            })
            if len(results) >= 50:
                return results
    return results


def _registry_ack_hits(ws: Path) -> list[dict[str, Any]]:
    """RANK-2 additive: synthesize acknowledgement hits from the structured
    known-issues registry (.auditooor/known_issues.json). Each OOS / acknowledged
    / won't-fix issue becomes one ack-hit row keyed to the registry file, so the
    R47 workspace scan sees operator-declared acknowledgements that live in the
    registry rather than only in prose docs. Degrades to [] when the registry is
    absent or the shared lib is unavailable. Never raises."""
    if _ki_registry is None:
        return []
    try:
        issues = _ki_registry.load_known_oos(ws)
    except Exception:  # pragma: no cover - defensive, never break the gate
        return []
    src = str(ws / ".auditooor" / "known_issues.json")
    hits: list[dict[str, Any]] = []
    for issue in issues:
        terms = ", ".join((issue.get("keywords") or [])[:6])
        text = (
            f"known-issue registry [{issue.get('status')}] "
            f"{issue.get('id')}: {issue.get('title')}"
            + (f" (keywords: {terms})" if terms else "")
        ).strip()
        hits.append({
            "line": 0,
            "token": (issue.get("status") or "known-issue")[:80],
            "text": text[:240],
            "source_file": src,
            "registry_issue_id": issue.get("id"),
        })
    return hits


def _extract_source_comments(ws: Path) -> list[dict[str, Any]]:
    """Extract source comments without deciding what they mean.

    This is deliberately a small lexical extractor, not a semantic detector.
    Every extracted comment is handed to contextual review so a phrase such as
    ``will be wired`` cannot disappear because it failed a keyword pattern.
    False positives such as URLs in strings are acceptable here: the reviewer
    has the source context and the reconciliation is fail-closed on ambiguity.
    """
    try:
        paths = _source_paths(ws)
    except OSError:
        return []

    comments: list[dict[str, Any]] = []
    for path in paths:
        try:
            lines = _read_text(path).splitlines()
        except Exception:
            continue
        block: list[str] = []
        block_start = 0
        for index, line in enumerate(lines):
            remainder = line
            line_no = index + 1
            while remainder:
                if block:
                    close = remainder.find("*/")
                    if close < 0:
                        block.append(remainder)
                        break
                    block.append(remainder[:close])
                    text = "\n".join(block).strip()
                    if text:
                        comments.append(_comment_record(path, lines, block_start - 1, text, "block"))
                    block = []
                    remainder = remainder[close + 2:]
                    continue

                markers = [(remainder.find("//"), "line")]
                if path.suffix.lower() in {".py", ".sh", ".bash", ".yaml", ".yml"}:
                    markers.append((remainder.find("#"), "line"))
                markers.append((remainder.find("/*"), "block"))
                present = [(pos, kind) for pos, kind in markers if pos >= 0]
                if not present:
                    break
                pos, kind = min(present)
                if kind == "block":
                    block_start = line_no
                    remainder = remainder[pos + 2:]
                    block = []
                    continue
                text = remainder[pos + 2:] if remainder.startswith("//", pos) else remainder[pos + 1:]
                if text.strip():
                    comments.append(_comment_record(path, lines, index, text.strip(), "line"))
                break

    return comments


def _source_paths(ws: Path) -> list[Path]:
    """Return source files, preferring the structured CUT manifest.

    The manifest is an inclusion boundary, not a semantic filter. This keeps
    generated dependencies and test corpora out of the agent queue while still
    extracting every comment from each in-scope file. Without a manifest, the
    generic source-tree fallback remains available.
    """
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    allowed: set[Path] = set()
    if manifest.is_file():
        for raw in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            value = row.get("file") if isinstance(row, dict) else None
            if not isinstance(value, str) or not value.strip():
                continue
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = ws / candidate
            allowed.add(candidate.resolve())
    if allowed:
        return sorted(
            p for p in allowed
            if p.is_file()
            and p.suffix.lower() in SOURCE_EXTENSIONS
            and not SOURCE_SKIP_DIRS.intersection(p.parts)
        )
    return sorted(
        p for p in ws.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SOURCE_EXTENSIONS
        and not SOURCE_SKIP_DIRS.intersection(p.parts)
    )


def _comment_record(path: Path, lines: list[str], index: int, text: str, kind: str) -> dict[str, Any]:
    start = max(0, index - 2)
    end = min(len(lines), index + 3)
    source_file = str(path)
    identity = f"{source_file}:{index + 1}:{text}"
    return {
        "comment_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "source_file": source_file,
        "line": index + 1,
        "comment_kind": kind,
        "text": text,
        "context": "\n".join(lines[start:end]),
        "analysis_status": "pending",
    }


def _load_comment_analysis(ws: Path) -> list[dict[str, Any]]:
    """Load reviewer dispositions from the explicit import artifact."""
    path = ws / ".auditooor" / "source_comment_analysis.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = payload.get("analyses", []) if isinstance(payload, dict) else []
    return rows if isinstance(rows, list) else []


def _source_snapshot_sha256(comments: list[dict[str, Any]]) -> str:
    """Hash reviewed source bytes, making freshness independent of mtime churn."""
    paths = sorted({str(row["source_file"]) for row in comments if row.get("source_file")})
    digest = hashlib.sha256()
    for raw_path in paths:
        path = Path(raw_path)
        digest.update(raw_path.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def _analysis_freshness(
    ws: Path, comments: list[dict[str, Any]], analyses: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare the review artifact identity and mtime with the current source.

    Comment IDs include the source path, line, and text.  The exact set therefore
    detects additions, removals, edits, and workspace-path changes.  The mtime
    check also catches contextual source edits that leave the comment itself
    unchanged.  Neither check grants terminal status; they only decide whether
    the existing review can be considered current.
    """
    analysis_path = ws / ".auditooor" / "source_comment_analysis.json"
    if not analysis_path.is_file():
        return {
            "fresh": True,
            "reasons": [],
            "missing_comment_ids": [],
            "stale_analysis_ids": [],
            "duplicate_analysis_ids": [],
            "current_comment_count": len(comments),
            "analysis_row_count": len(analyses),
            "declared_comment_count": None,
            "source_mtime_ns": 0,
            "analysis_mtime_ns": 0,
            "current_comment_ids_sha256": hashlib.sha256(
                "\n".join(sorted(row["comment_id"] for row in comments)).encode("utf-8")
            ).hexdigest(),
        }
    current_ids = [row["comment_id"] for row in comments]
    current_set = set(current_ids)
    analysis_ids = [
        row.get("comment_id") for row in analyses
        if isinstance(row, dict) and row.get("comment_id")
    ]
    analysis_set = set(analysis_ids)
    duplicate_ids = sorted({item for item in analysis_ids if analysis_ids.count(item) > 1})
    missing_ids = sorted(current_set - analysis_set)
    stale_ids = sorted(analysis_set - current_set)
    reasons: list[str] = []

    if missing_ids:
        reasons.append(f"{len(missing_ids)} current comment identities have no analysis row")
    if stale_ids:
        reasons.append(f"{len(stale_ids)} analysis rows reference comments absent from current source")
    if duplicate_ids:
        reasons.append(f"{len(duplicate_ids)} duplicate analysis comment identities")

    declared_count = None
    if analysis_path.is_file():
        try:
            raw = json.loads(analysis_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("comment_count") is not None:
                declared_count = raw.get("comment_count")
                if declared_count != len(comments):
                    reasons.append(
                        f"analysis declares comment_count={declared_count}, current source has {len(comments)}"
                    )
        except (OSError, json.JSONDecodeError):
            reasons.append("source comment analysis artifact is unreadable")

    source_mtime_ns = 0
    for row in comments:
        try:
            source_mtime_ns = max(source_mtime_ns, Path(row["source_file"]).stat().st_mtime_ns)
        except (KeyError, OSError):
            reasons.append(f"source file is unavailable for {row.get('comment_id', '<unknown>')}")
    analysis_mtime_ns = analysis_path.stat().st_mtime_ns if analysis_path.is_file() else 0
    current_snapshot = _source_snapshot_sha256(comments)
    stored_snapshot = None
    try:
        raw = json.loads(analysis_path.read_text(encoding="utf-8"))
        stored_snapshot = raw.get("source_snapshot_sha256") if isinstance(raw, dict) else None
    except (OSError, json.JSONDecodeError):
        pass
    if stored_snapshot:
        if stored_snapshot != current_snapshot:
            reasons.append("source bytes differ from the source comment analysis snapshot")
    elif analysis_mtime_ns and source_mtime_ns > analysis_mtime_ns:
        # Legacy artifacts predate content snapshots. Keep their conservative
        # mtime guard until the workspace is semantically reviewed once.
        reasons.append("source files are newer than the source comment analysis artifact")

    return {
        "fresh": not reasons,
        "reasons": reasons,
        "missing_comment_ids": missing_ids,
        "stale_analysis_ids": stale_ids,
        "duplicate_analysis_ids": duplicate_ids,
        "current_comment_count": len(comments),
        "analysis_row_count": len(analyses),
        "declared_comment_count": declared_count,
        "source_mtime_ns": source_mtime_ns,
        "analysis_mtime_ns": analysis_mtime_ns,
        "source_snapshot_sha256": current_snapshot,
        "stored_source_snapshot_sha256": stored_snapshot,
        "current_comment_ids_sha256": hashlib.sha256(
            "\n".join(sorted(current_set)).encode("utf-8")
        ).hexdigest(),
    }


def _write_refresh_required_artifact(ws: Path, freshness: dict[str, Any]) -> Path:
    """Persist an explicit refresh request instead of allowing stale review."""
    out = ws / ".auditooor" / "source_comment_analysis_refresh_required.json"
    payload = {
        "schema_version": SOURCE_COMMENT_REFRESH_SCHEMA,
        "verdict": "refresh-required",
        "analysis_status": "refresh-required",
        "workspace": str(ws),
        "reason": "Current source comments and source_comment_analysis.json do not describe the same fresh source snapshot.",
        "required_action": (
            "Have an attributed reviewer create .auditooor/source_comment_review_decisions.json, "
            "run python3 tools/semantic-review-source-comments.py <workspace>, and rerun source-comment-reconciliation."
        ),
        "freshness": freshness,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def _source_comment_reconciliation_hits(ws: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Turn reviewed comment dispositions into downstream R47 evidence."""
    path = ws / ".auditooor" / "source_comment_reconciliation.json"
    if not path.exists():
        return [], None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], "invalid"
    if payload.get("schema_version") != "auditooor.source_comment_reconciliation.v2":
        return [], "legacy"
    status = str(payload.get("analysis_status") or "")
    if status != "complete":
        return [], status or "pending"
    comments = {row.get("comment_id"): row for row in payload.get("comments", []) if isinstance(row, dict)}
    hits = []
    for row in payload.get("analyses", []):
        if not isinstance(row, dict):
            continue
        disposition = row.get("disposition")
        if disposition not in {
            "known-issue-oos", "planned-remediation-oos", "risk-accepted-oos",
            "wont-fix-oos", "duplicate-oos", "claimed-fixed-verified",
        }:
            continue
        comment = comments.get(row.get("comment_id"), {})
        hits.append({
            "line": comment.get("line", 0),
            "text": comment.get("text", ""),
            "source_file": comment.get("source_file", ""),
            "evidence_class": disposition,
            "source_comment": True,
            "agent_rationale": row.get("rationale", ""),
        })
    return hits, status


def scan_workspace_source_comments(ws: Path) -> tuple[int, dict[str, Any]]:
    """Persist extracted comments and require contextual review before promotion."""
    comments = _extract_source_comments(ws)
    analyses = _load_comment_analysis(ws)
    freshness = _analysis_freshness(ws, comments, analyses)
    current_ids = {row["comment_id"] for row in comments}
    analyzed_ids = {
        row.get("comment_id") for row in analyses
        if isinstance(row, dict) and row.get("comment_id")
    }
    pending = [row for row in comments if row["comment_id"] not in analyzed_ids]
    unresolved = [
        row for row in analyses
        if isinstance(row, dict)
        and (
            row.get("disposition") not in COMMENT_TERMINAL_DISPOSITIONS
            or row.get("disposition") in {"needs-manual-review", "claimed-fixed"}
            or row.get("comment_id") not in current_ids
            or not str(row.get("rationale") or "").strip()
            or (
                row.get("disposition") in {"claimed-fixed-verified", "claimed-fixed-disproved"}
                and not str(row.get("current_code_evidence") or "").strip()
            )
        )
    ]
    refresh_artifact = None
    if not freshness["fresh"]:
        verdict = "refresh-required-source-comment-analysis"
        refresh_artifact = str(_write_refresh_required_artifact(ws, freshness))
    elif pending:
        verdict = "pending-agent-analysis"
    elif unresolved:
        verdict = "review-required"
    else:
        verdict = "pass-comment-analysis-complete"
    payload = {
        "schema_version": "auditooor.source_comment_reconciliation.v2",
        "workspace": str(ws),
        "verdict": verdict,
        "analysis_status": "pending" if pending else ("review-required" if unresolved else "complete"),
        "comments": comments,
        "comment_count": len(comments),
        "analyses": analyses,
        "analyzed_count": len(comments) - len(pending),
        "pending_count": len(pending),
        "unresolved_count": len(unresolved),
        "stale_analysis_count": sum(
            1 for row in analyses
            if isinstance(row, dict) and row.get("comment_id") not in current_ids
        ),
        "freshness": freshness,
        "policy": (
            "Comments are evidence, not automatic scope rulings. Agent review must classify "
            "known/planned/team-aware or accepted behavior as OOS for new findings. A claimed "
            "FIXED item remains fileable only when current executable evidence disproves the fix."
        ),
    }
    out = ws / ".auditooor" / "source_comment_reconciliation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload["evidence_path"] = str(out)
    if refresh_artifact:
        payload["refresh_required_artifact"] = refresh_artifact
        payload["analysis_status"] = "refresh-required"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return (1 if verdict != "pass-comment-analysis-complete" else 0), payload


def _extract_section_body(text: str, section_re: re.Pattern[str]) -> str:
    """Extract the body of a section from section header to next ## header."""
    m = section_re.search(text)
    if not m:
        return ""
    start = m.start()
    # Find next heading of same or higher level
    rest = text[m.end():]
    next_h = re.search(r"(?m)^#{1,3}\s+\S", rest)
    if next_h:
        return text[start: m.end() + next_h.start()]
    return text[start:]


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    workspace: Path | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    # ---- read draft ----
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add an 'Acknowledgement Scan' section with 4 sub-fields: (1) Scan paths, "
            "(2) Acknowledgement found yes/no + verbatim quote + citation, "
            "(3) Extension-distinct evidence, (4) Verdict.",
            "If an acknowledgement exists, provide extension-distinct evidence: cite the "
            "downstream surface or novel attack path not covered by the prior ack.",
            "Use 'r47-rebuttal: <reason>' (<=200 chars) or <!-- r47-rebuttal: <reason> --> "
            "for operator-approved exceptions.",
        ],
    }

    # Below HIGH: out of scope
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing; R47 does not fire"
        return 0, payload

    # Check rebuttal before heavy analysis
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= REBUTTAL_MAX_CHARS:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # --- Check for "Acknowledgement Scan" section in draft ---
    has_section = bool(ACK_SCAN_SECTION_RE.search(text))
    payload["evidence"]["has_acknowledgement_scan_section"] = has_section

    if not has_section:
        payload["verdict"] = "fail-no-acknowledgement-scan-performed"
        payload["reason"] = (
            "HIGH+ draft is missing an 'Acknowledgement Scan' section. "
            "Add a section with 4 sub-fields: scan paths, ack-found (yes/no + quote + citation), "
            "extension-distinct evidence, and verdict."
        )
        return 1, payload

    # Extract the section body for sub-field analysis
    section_body = _extract_section_body(text, ACK_SCAN_SECTION_RE)
    payload["evidence"]["section_body_length"] = len(section_body)

    # Sub-field presence checks
    has_scan_paths = bool(SCAN_PATHS_RE.search(section_body))
    has_ack_found = bool(ACK_FOUND_RE.search(section_body))
    has_extension_distinct = bool(EXTENSION_DISTINCT_RE.search(section_body))
    has_verdict_line = bool(VERDICT_LINE_RE.search(section_body))

    payload["evidence"]["sub_fields"] = {
        "has_scan_paths": has_scan_paths,
        "has_ack_found": has_ack_found,
        "has_extension_distinct": has_extension_distinct,
        "has_verdict_line": has_verdict_line,
    }

    # --- Resolve workspace and scan for acknowledgements ---
    ws = _workspace_root(draft, workspace)
    payload["workspace"] = str(ws)

    ack_re = _compile_union(
        DEFAULT_ACK_PATTERNS + _env_patterns("AUDITOOOR_R47_ACK_PATTERNS")
    )

    # Scan workspace documents for actual acknowledgement signals
    ws_ack_hits = _scan_workspace_for_acknowledgements(ws, ack_re)
    # RANK-2 additive: also surface acknowledgements declared in the structured
    # known-issues registry (.auditooor/known_issues.json), which the prose scan
    # above does not read. Prepend so registry-declared acks are visible first.
    registry_ack_hits = _registry_ack_hits(ws)
    source_comment_ack_hits, comment_analysis_status = _source_comment_reconciliation_hits(ws)
    if comment_analysis_status is None:
        # Legacy draft-only behavior remains available when the mandatory
        # workspace reconciliation has not run. The pipeline target always
        # runs the extraction gate first.
        source_comment_ack_hits = _scan_source_comments_for_acknowledgements(ws)
    elif comment_analysis_status != "complete":
        payload["evidence"]["source_comment_analysis_status"] = comment_analysis_status
        payload["verdict"] = "fail-source-comment-analysis-pending"
        payload["reason"] = (
            "Source comments were extracted but contextual agent analysis is not complete; "
            "do not promote or dismiss a candidate until every comment has a disposition."
        )
        return 1, payload
    if registry_ack_hits:
        ws_ack_hits = registry_ack_hits + ws_ack_hits
    if source_comment_ack_hits:
        ws_ack_hits = source_comment_ack_hits + ws_ack_hits
    payload["evidence"]["registry_ack_count"] = len(registry_ack_hits)
    payload["evidence"]["source_comment_ack_count"] = len(source_comment_ack_hits)
    payload["evidence"]["workspace_ack_hits"] = ws_ack_hits[:20]  # cap for readability
    payload["evidence"]["workspace_ack_count"] = len(ws_ack_hits)

    # --- Determine whether the DRAFT claims acknowledgement found ---
    draft_says_ack_found = bool(ACK_FOUND_YES_RE.search(section_body))
    payload["evidence"]["draft_claims_ack_found"] = draft_says_ack_found

    # Check for verbatim quote / citation evidence in the section
    verbatim_hits = VERBATIM_QUOTE_RE.findall(section_body)
    payload["evidence"]["verbatim_citation_count"] = len(verbatim_hits)
    payload["evidence"]["verbatim_citations"] = verbatim_hits[:5]

    # --- Branch on whether an acknowledgement is declared ---
    if not draft_says_ack_found:
        # Draft says "Acknowledgement found: no" (or is ambiguous)
        # Verify workspace scan corroborates (or if no workspace scan needed, trust draft)
        payload["verdict"] = "pass-no-acknowledgement-found"
        payload["reason"] = (
            "Acknowledgement Scan section present; draft declares no acknowledgement found. "
            "Workspace scan corroboration: "
            f"{len(ws_ack_hits)} potential signals in workspace docs (review if any are direct matches)."
        )
        return 0, payload

    # --- Acknowledgement found: yes --- check extension-distinct evidence ---
    # Look for extension-distinct positive marker or substantive content
    extension_distinct_positive = bool(EXTENSION_DISTINCT_POSITIVE_RE.search(section_body))
    extension_distinct_content = bool(EXTENSION_DISTINCT_CONTENT_RE.search(section_body))
    has_extension_evidence = extension_distinct_positive or extension_distinct_content

    payload["evidence"]["extension_distinct_positive_marker"] = extension_distinct_positive
    payload["evidence"]["extension_distinct_content_match"] = extension_distinct_content

    if not has_extension_distinct:
        # Extension-distinct sub-field entirely missing
        payload["verdict"] = "fail-acknowledged-without-extension-distinct"
        payload["reason"] = (
            "Acknowledgement Scan declares an acknowledgement was found but contains no "
            "'Extension-distinct evidence' sub-field. Add field 3 explaining how this finding "
            "exploits a downstream surface or breaks the mitigation in a new way not covered "
            "by the prior acknowledgement."
        )
        return 1, payload

    if not has_extension_evidence:
        # Extension-distinct field present but not substantiated
        payload["verdict"] = "fail-acknowledged-without-extension-distinct"
        payload["reason"] = (
            "Extension-distinct evidence sub-field is present but contains no substantive "
            "evidence of a novel attack surface or mitigation bypass. Cite the exact downstream "
            "function, file:line, or attack path that the prior acknowledgement did not cover."
        )
        return 1, payload

    # Extension-distinct evidence is present and substantive
    payload["verdict"] = "pass-extension-distinct-from-acknowledgement"
    payload["reason"] = (
        "Acknowledgement found but extension-distinct evidence is present: the new finding "
        "exploits a downstream surface or breaks the acknowledged mitigation in a new way."
    )
    return 0, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R47 Acknowledged-Wont-Fix precheck (Check #94).",
    )
    parser.add_argument("draft", type=Path, nargs="?", help="Path to draft .md file")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root (prior_audits/, SECURITY.md, etc.). "
             "Inferred from draft path if omitted.",
    )
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
        ],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--scan-workspace-comments",
        action="store_true",
        help="run and persist the workspace source-comment reconciliation scan",
    )
    args = parser.parse_args(argv)

    if args.scan_workspace_comments:
        if args.workspace is None:
            parser.error("--scan-workspace-comments requires --workspace")
        rc, payload = scan_workspace_source_comments(args.workspace.resolve())
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"[source-comment-reconciliation] {payload['verdict']} comments={payload['comment_count']} pending={payload['pending_count']}")
        return rc

    if args.draft is None:
        parser.error("draft is required unless --scan-workspace-comments is used")

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        workspace=args.workspace,
        strict=args.strict,
    )

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        verdict = payload.get("verdict", "error")
        reason = payload.get("reason", payload.get("error", ""))
        is_pass = verdict.startswith("pass") or verdict == "ok-rebuttal"
        prefix = "[PASS]" if is_pass else "[FAIL]"
        print(f"{prefix} {GATE}: {verdict}")
        if reason:
            print(f"  reason: {reason}")
        ws_count = payload.get("evidence", {}).get("workspace_ack_count", 0)
        if ws_count:
            print(f"  workspace acknowledgement signals found: {ws_count}")
        cites = payload.get("evidence", {}).get("verbatim_citations", [])
        if cites:
            print(f"  verbatim citations in section: {cites[:3]}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
