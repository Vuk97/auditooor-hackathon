#!/usr/bin/env python3
"""Wave-3 capability lift (PR #729) - published-source originality scanner.

HONEST DISCLAIMER (operator-facing, mandatory)
==============================================
This scanner only checks PUBLIC PUBLISHED sources. Private submissions on
Cantina, Immunefi, Sherlock, and Code4rena are NOT checkable - no public
submission feed exists for those platforms. A PASS_clean verdict here means
no PUBLIC collision was found, NOT that no private submission exists. The
historical pattern of being dupe'd by an external private reporter (Spark
LEAD H-D and LEAD F-N closed as duplicates of external Immunefi report
#77043; the dYdX Megavault prior-rejection) is NOT preventable by any
automated tool. The only mitigations for private-reporter collision are
(a) speed and (b) L31 duplicate-preflight discipline against the workspace's
own historical filings, both already in the auditooor playbook.

Sources checked (all PUBLIC):
  1. NVD CVE database (https://nvd.nist.gov)
  2. GitHub Security Advisories (https://github.com/advisories)
  3. Published audit firm portfolios (audit/corpus_tags/tags/audit_firm_*/)
  4. Code4rena public contest archive (reference/contest_cache/code4rena/)
  5. Sherlock public contest archive (reference/contest_cache/sherlock/)
  6. Workspace prior_audits/*.txt (operator-saved PDF extractions)
  7. Workspace submissions/SUBMISSIONS.md (this workspace's own filings)
  8. Vault vault_dupe_rejection_context MCP callable
  9. Public protocol disclosure pages (optional via --disclosure-url)

CLI
---
  --finding-draft <path>      operator's draft to check (required)
  --target-protocol <name>    target protocol slug (required)
  --workspace <ws>            workspace path (default: cwd)
  --cve-id <id>               optional NVD CVE-YYYY-NNNN
  --ghsa-id <id>              optional GHSA-XXXX-YYYY-ZZZZ
  --disclosure-url <url>      optional protocol disclosure page
  --sources <comma-list>      restrict to subset of the 9 sources
  --cache-dir <path>          override published-source cache root
  --json                      JSON output (default: human-readable)
  --strict                    exit 1 on any BLOCK verdict

Verdict labels (per-source and aggregate)
-----------------------------------------
  PASS_clean              - no match found
  WARNING_adjacent        - fuzzy / partial match - operator review needed
  BLOCK_published_dupe    - exact-shape match in a published source
  ERROR_source_unavailable - offline / cache-not-yet-populated

JSON schema: ``auditooor.wave3_published_source_originality_scanner.v1``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = "auditooor.wave3_published_source_originality_scanner.v1"

ALL_SOURCES = (
    "nvd",
    "ghsa",
    "audit_firm_portfolios",
    "code4rena",
    "sherlock",
    "prior_audits",
    "auditooor_submissions",
    "vault_dupe_rejection",
    "disclosure_pages",
)

VERDICT_PASS = "PASS_clean"
VERDICT_WARNING = "WARNING_adjacent"
VERDICT_BLOCK = "BLOCK_published_dupe"
VERDICT_ERROR = "ERROR_source_unavailable"

VERDICT_RANK = {
    VERDICT_PASS: 0,
    VERDICT_ERROR: 1,
    VERDICT_WARNING: 2,
    VERDICT_BLOCK: 3,
}

DISCLAIMER_TEXT = (
    "This scanner only checks PUBLIC PUBLISHED sources. Private submissions on "
    "Cantina/Immunefi/Sherlock/Code4rena are NOT checkable. A PASS verdict here "
    "means no PUBLIC collision was found, NOT that no private submission exists. "
    "The historical pattern of being dupe'd by an external private reporter "
    "(Spark LEAD H-D/F-N, dydx Megavault) is NOT preventable by any automated tool."
)


# ----------------------------------------------------------------------
# Fingerprint extraction
# ----------------------------------------------------------------------

_TOKEN_MIN = 4
_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "into", "when",
    "where", "what", "have", "been", "will", "would", "could", "should",
    "your", "their", "there", "these", "those", "about", "which", "while",
    "after", "before", "between", "across", "under", "above", "than",
    "then", "also", "such", "some", "more", "most", "less", "many", "much",
    "very", "into", "onto", "upon", "over", "below", "report", "finding",
    "severity", "high", "medium", "critical", "informational", "info",
    "low", "audit", "issue", "bug", "vulnerability", "vuln",
}


def _normalise_tokens(text: str) -> set[str]:
    text = text.lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    return {t for t in tokens if len(t) >= _TOKEN_MIN and t not in _STOPWORDS}


def _title_from_draft(draft_text: str) -> str:
    for line in draft_text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
        if line.startswith("Title:"):
            return line.split(":", 1)[1].strip()
    return ""


def extract_fingerprint(draft_text: str) -> dict[str, Any]:
    """Pull deterministic fingerprint fields from a draft."""
    title = _title_from_draft(draft_text)
    tokens = _normalise_tokens(draft_text)
    attack_hint = ""
    if title:
        for w in re.split(r"\s+", title):
            if "-" in w and len(w) >= 6:
                attack_hint = w.lower()
                break
    return {
        "title": title,
        "tokens": sorted(tokens),
        "token_count": len(tokens),
        "attack_hint": attack_hint,
    }


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# ----------------------------------------------------------------------
# Per-source check helpers
# ----------------------------------------------------------------------

def _verdict_from_score(score: float, *, block_threshold: float, warn_threshold: float) -> str:
    if score >= block_threshold:
        return VERDICT_BLOCK
    if score >= warn_threshold:
        return VERDICT_WARNING
    return VERDICT_PASS


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def check_nvd(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    cve_id: str | None,
    cache_dir: Path,
) -> dict[str, Any]:
    """Check NVD via local cache (cache_dir/nvd/CVE-*.json)."""
    nvd_dir = cache_dir / "nvd"
    matches: list[dict[str, Any]] = []
    fp_tokens = set(fingerprint.get("tokens", []))

    if cve_id:
        candidate = nvd_dir / f"{cve_id}.json"
        if not candidate.exists():
            return {
                "source": "nvd",
                "verdict": VERDICT_ERROR,
                "reason": f"NVD cache miss for {cve_id} at {candidate}",
                "matches": [],
            }
        try:
            entry = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "source": "nvd",
                "verdict": VERDICT_ERROR,
                "reason": f"NVD cache parse error: {exc}",
                "matches": [],
            }
        descr = (entry.get("description") or "").lower()
        descr_tokens = _normalise_tokens(descr)
        score = _jaccard(fp_tokens, descr_tokens)
        matches.append({
            "cve_id": cve_id,
            "description_excerpt": descr[:200],
            "jaccard": round(score, 4),
        })
        verdict = _verdict_from_score(score, block_threshold=0.55, warn_threshold=0.25)
        return {
            "source": "nvd",
            "verdict": verdict,
            "reason": f"direct CVE lookup, jaccard={score:.4f}",
            "matches": matches,
        }

    if not nvd_dir.exists():
        return {
            "source": "nvd",
            "verdict": VERDICT_ERROR,
            "reason": f"NVD cache not populated at {nvd_dir} (run an NVD pull or supply --cve-id)",
            "matches": [],
        }
    best_score = 0.0
    for f in sorted(nvd_dir.glob("CVE-*.json")):
        try:
            entry = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        descr = (entry.get("description") or "").lower()
        if target_protocol.lower() not in descr:
            continue
        descr_tokens = _normalise_tokens(descr)
        score = _jaccard(fp_tokens, descr_tokens)
        if score > 0.0:
            matches.append({
                "cve_id": entry.get("id") or f.stem,
                "description_excerpt": descr[:200],
                "jaccard": round(score, 4),
            })
        if score > best_score:
            best_score = score
    verdict = _verdict_from_score(best_score, block_threshold=0.55, warn_threshold=0.25)
    return {
        "source": "nvd",
        "verdict": verdict,
        "reason": f"protocol-name search, best_jaccard={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def check_ghsa(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    ghsa_id: str | None,
    cache_dir: Path,
) -> dict[str, Any]:
    """Check GitHub Security Advisories via local cache."""
    ghsa_dir = cache_dir / "ghsa"
    fp_tokens = set(fingerprint.get("tokens", []))
    matches: list[dict[str, Any]] = []

    if ghsa_id:
        candidate = ghsa_dir / f"{ghsa_id}.json"
        if not candidate.exists():
            return {
                "source": "ghsa",
                "verdict": VERDICT_ERROR,
                "reason": f"GHSA cache miss for {ghsa_id} at {candidate}",
                "matches": [],
            }
        try:
            entry = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "source": "ghsa",
                "verdict": VERDICT_ERROR,
                "reason": f"GHSA cache parse error: {exc}",
                "matches": [],
            }
        summary = (entry.get("summary") or "").lower()
        body = (entry.get("description") or "").lower()
        text_tokens = _normalise_tokens(summary + " " + body)
        score = _jaccard(fp_tokens, text_tokens)
        matches.append({
            "ghsa_id": ghsa_id,
            "summary_excerpt": summary[:200],
            "jaccard": round(score, 4),
        })
        verdict = _verdict_from_score(score, block_threshold=0.55, warn_threshold=0.25)
        return {
            "source": "ghsa",
            "verdict": verdict,
            "reason": f"direct GHSA lookup, jaccard={score:.4f}",
            "matches": matches,
        }

    if not ghsa_dir.exists():
        return {
            "source": "ghsa",
            "verdict": VERDICT_ERROR,
            "reason": f"GHSA cache not populated at {ghsa_dir} (supply --ghsa-id or pre-populate)",
            "matches": [],
        }
    best_score = 0.0
    for f in sorted(ghsa_dir.glob("GHSA-*.json")):
        try:
            entry = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        text = (
            (entry.get("summary") or "") + " " + (entry.get("description") or "")
        ).lower()
        if target_protocol.lower() not in text:
            continue
        text_tokens = _normalise_tokens(text)
        score = _jaccard(fp_tokens, text_tokens)
        if score > 0.0:
            matches.append({
                "ghsa_id": entry.get("ghsa_id") or f.stem,
                "summary_excerpt": text[:200],
                "jaccard": round(score, 4),
            })
        if score > best_score:
            best_score = score
    verdict = _verdict_from_score(best_score, block_threshold=0.55, warn_threshold=0.25)
    return {
        "source": "ghsa",
        "verdict": verdict,
        "reason": f"protocol-name search, best_jaccard={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def _record_text(path: Path) -> str:
    raw = _read_text(path)
    if not raw:
        return ""
    if path.suffix == ".json":
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        parts: list[str] = []
        for key in (
            "target_repo", "target_component", "attacker_action_sequence",
            "bug_class", "attack_class", "impact_class", "fix_pattern",
            "source_audit_ref",
        ):
            v = obj.get(key)
            if isinstance(v, str):
                parts.append(v)
        return " ".join(parts)
    return raw


def check_audit_firm_portfolios(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    workspace: Path,
) -> dict[str, Any]:
    """Check published audit firm portfolios (W2.4 PDF parser output)."""
    fp_tokens = set(fingerprint.get("tokens", []))
    proto = target_protocol.lower()
    tags_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags"
    candidates: list[Path] = []
    for d_name in ("audit_firm_public_reports", "audit_firm_findings"):
        d = tags_dir / d_name
        if not d.exists():
            continue
        for child in sorted(d.iterdir()):
            if not child.is_dir():
                continue
            record_json = child / "record.json"
            record_yaml = child / "record.yaml"
            if record_json.exists():
                candidates.append(record_json)
            elif record_yaml.exists():
                candidates.append(record_yaml)
    if tags_dir.exists():
        for child in sorted(tags_dir.iterdir()):
            if not child.is_dir():
                continue
            if not (child.name.startswith("firm-") or child.name.endswith("-audits")):
                continue
            for sub in sorted(child.iterdir()):
                if sub.is_dir():
                    rj = sub / "record.json"
                    ry = sub / "record.yaml"
                    if rj.exists():
                        candidates.append(rj)
                    elif ry.exists():
                        candidates.append(ry)

    if not candidates:
        return {
            "source": "audit_firm_portfolios",
            "verdict": VERDICT_ERROR,
            "reason": "no audit_firm_public_reports / audit_firm_findings / firm-* tags found",
            "matches": [],
        }

    matches: list[dict[str, Any]] = []
    best_score = 0.0
    for rec in candidates:
        body = _record_text(rec).lower()
        if proto not in body:
            continue
        tokens = _normalise_tokens(body)
        score = _jaccard(fp_tokens, tokens)
        if score > 0.0:
            matches.append({
                "record_path": str(rec.relative_to(REPO_ROOT)),
                "jaccard": round(score, 4),
            })
        if score > best_score:
            best_score = score

    verdict = _verdict_from_score(best_score, block_threshold=0.5, warn_threshold=0.2)
    return {
        "source": "audit_firm_portfolios",
        "verdict": verdict,
        "reason": f"corpus search, best_jaccard={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def _check_contest_archive(
    *,
    label: str,
    fingerprint: dict[str, Any],
    target_protocol: str,
    cache_dir: Path,
) -> dict[str, Any]:
    archive_dir = cache_dir / label
    if not archive_dir.exists():
        return {
            "source": label,
            "verdict": VERDICT_ERROR,
            "reason": f"{label} contest cache not yet populated at {archive_dir}",
            "matches": [],
        }
    fp_tokens = set(fingerprint.get("tokens", []))
    proto = target_protocol.lower()
    matches: list[dict[str, Any]] = []
    best_score = 0.0
    for f in sorted(archive_dir.rglob("*.json")):
        try:
            obj = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        text = json.dumps(obj, ensure_ascii=False).lower()
        if proto not in text:
            continue
        tokens = _normalise_tokens(text)
        score = _jaccard(fp_tokens, tokens)
        if score > 0.0:
            matches.append({
                "report_path": str(f.relative_to(cache_dir)),
                "jaccard": round(score, 4),
            })
        if score > best_score:
            best_score = score
    verdict = _verdict_from_score(best_score, block_threshold=0.5, warn_threshold=0.2)
    return {
        "source": label,
        "verdict": verdict,
        "reason": f"contest-archive search, best_jaccard={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def check_code4rena(**kw: Any) -> dict[str, Any]:
    return _check_contest_archive(label="code4rena", **kw)


def check_sherlock(**kw: Any) -> dict[str, Any]:
    return _check_contest_archive(label="sherlock", **kw)


def check_prior_audits(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    workspace: Path,
) -> dict[str, Any]:
    """Grep prior_audits/*.txt for the draft's key terms."""
    prior_dir = workspace / "prior_audits"
    if not prior_dir.exists():
        return {
            "source": "prior_audits",
            "verdict": VERDICT_PASS,
            "reason": f"no prior_audits/ dir at {prior_dir} (treated as clean)",
            "matches": [],
        }
    fp_tokens = set(fingerprint.get("tokens", []))
    title_token_seed = _normalise_tokens(fingerprint.get("title") or "")
    matches: list[dict[str, Any]] = []
    best_score = 0.0
    for f in sorted(prior_dir.glob("*.txt")):
        body = _read_text(f).lower()
        if not body:
            continue
        tokens = _normalise_tokens(body)
        title_overlap = (
            len(title_token_seed & tokens) / max(1, len(title_token_seed))
            if title_token_seed else 0.0
        )
        full_jaccard = _jaccard(fp_tokens, tokens)
        score = 0.6 * title_overlap + 0.4 * full_jaccard
        if score > 0.0:
            matches.append({
                "audit_path": str(f.relative_to(workspace)),
                "title_overlap": round(title_overlap, 4),
                "jaccard": round(full_jaccard, 4),
                "combined": round(score, 4),
            })
        if score > best_score:
            best_score = score
    verdict = _verdict_from_score(best_score, block_threshold=0.55, warn_threshold=0.25)
    return {
        "source": "prior_audits",
        "verdict": verdict,
        "reason": f"prior_audits grep, best_combined={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def check_auditooor_submissions(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    workspace: Path,
) -> dict[str, Any]:
    """Grep workspace's own submissions/SUBMISSIONS.md (and paste_ready/)."""
    submissions_md = workspace / "submissions" / "SUBMISSIONS.md"
    paste_ready = workspace / "submissions" / "paste_ready"
    fp_tokens = set(fingerprint.get("tokens", []))
    title_tokens = _normalise_tokens(fingerprint.get("title") or "")
    matches: list[dict[str, Any]] = []
    best_score = 0.0
    files_to_scan: list[Path] = []
    if submissions_md.exists():
        files_to_scan.append(submissions_md)
    if paste_ready.exists():
        files_to_scan.extend(sorted(paste_ready.glob("*.md")))
    if not files_to_scan:
        return {
            "source": "auditooor_submissions",
            "verdict": VERDICT_PASS,
            "reason": f"no submissions/ at {workspace}/submissions (treated as clean)",
            "matches": [],
        }
    for f in files_to_scan:
        body = _read_text(f).lower()
        if not body:
            continue
        tokens = _normalise_tokens(body)
        title_overlap = (
            len(title_tokens & tokens) / max(1, len(title_tokens))
            if title_tokens else 0.0
        )
        jacc = _jaccard(fp_tokens, tokens)
        score = 0.6 * title_overlap + 0.4 * jacc
        if score > 0.0:
            matches.append({
                "submission_path": str(f.relative_to(workspace)),
                "title_overlap": round(title_overlap, 4),
                "jaccard": round(jacc, 4),
                "combined": round(score, 4),
            })
        if score > best_score:
            best_score = score
    verdict = _verdict_from_score(best_score, block_threshold=0.5, warn_threshold=0.2)
    return {
        "source": "auditooor_submissions",
        "verdict": verdict,
        "reason": f"workspace-own filings grep, best_combined={best_score:.4f}, hits={len(matches)}",
        "matches": matches[:5],
    }


def check_vault_dupe_rejection(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    workspace: Path,
) -> dict[str, Any]:
    """Invoke vault_dupe_rejection_context MCP callable."""
    mcp_server = REPO_ROOT / "tools" / "vault-mcp-server.py"
    if not mcp_server.exists():
        return {
            "source": "vault_dupe_rejection",
            "verdict": VERDICT_ERROR,
            "reason": f"vault-mcp-server.py not found at {mcp_server}",
            "matches": [],
        }
    args_payload = json.dumps({
        "workspace_path": str(workspace),
        "target_protocol": target_protocol,
        "title": fingerprint.get("title", ""),
        "limit": 5,
    })
    try:
        proc = subprocess.run(
            [
                sys.executable, str(mcp_server),
                "--call", "vault_dupe_rejection_context",
                "--args", args_payload,
            ],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "source": "vault_dupe_rejection",
            "verdict": VERDICT_ERROR,
            "reason": f"vault MCP invocation failed: {exc}",
            "matches": [],
        }
    if proc.returncode != 0:
        return {
            "source": "vault_dupe_rejection",
            "verdict": VERDICT_ERROR,
            "reason": f"vault MCP non-zero exit: {proc.returncode}: {proc.stderr[:200]}",
            "matches": [],
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "source": "vault_dupe_rejection",
            "verdict": VERDICT_ERROR,
            "reason": "vault MCP stdout not JSON",
            "matches": [],
        }
    rejections = payload.get("rejections") or payload.get("matches") or []
    if not isinstance(rejections, list):
        rejections = []
    if not rejections:
        return {
            "source": "vault_dupe_rejection",
            "verdict": VERDICT_PASS,
            "reason": "vault returned 0 prior rejections matching fingerprint",
            "matches": [],
        }
    has_exact = any(isinstance(r, dict) and r.get("exact_match") for r in rejections)
    verdict = VERDICT_BLOCK if has_exact else VERDICT_WARNING
    return {
        "source": "vault_dupe_rejection",
        "verdict": verdict,
        "reason": f"vault returned {len(rejections)} prior rejections (exact_match={has_exact})",
        "matches": rejections[:5],
    }


def check_disclosure_pages(
    *,
    fingerprint: dict[str, Any],
    target_protocol: str,
    disclosure_url: str | None,
) -> dict[str, Any]:
    """Optional: fetch a protocol disclosure URL and grep it.

    No network access by default. Caller must supply --disclosure-url AND
    set AUDITOOOR_DISCLOSURE_PAGE_CACHE to a local pre-fetched copy. This
    avoids unsanctioned outbound requests."""
    if not disclosure_url:
        return {
            "source": "disclosure_pages",
            "verdict": VERDICT_PASS,
            "reason": "no --disclosure-url supplied (treated as clean)",
            "matches": [],
        }
    cache_path_env = os.environ.get("AUDITOOOR_DISCLOSURE_PAGE_CACHE")
    if not cache_path_env:
        return {
            "source": "disclosure_pages",
            "verdict": VERDICT_ERROR,
            "reason": "set AUDITOOOR_DISCLOSURE_PAGE_CACHE to a local pre-fetched HTML/MD copy",
            "matches": [],
        }
    cache_path = Path(cache_path_env)
    if not cache_path.exists():
        return {
            "source": "disclosure_pages",
            "verdict": VERDICT_ERROR,
            "reason": f"disclosure-page cache not found at {cache_path}",
            "matches": [],
        }
    body = _read_text(cache_path).lower()
    fp_tokens = set(fingerprint.get("tokens", []))
    tokens = _normalise_tokens(body)
    score = _jaccard(fp_tokens, tokens)
    verdict = _verdict_from_score(score, block_threshold=0.55, warn_threshold=0.25)
    return {
        "source": "disclosure_pages",
        "verdict": verdict,
        "reason": f"disclosure page jaccard={score:.4f}, url={disclosure_url}",
        "matches": [{"jaccard": round(score, 4), "url": disclosure_url}],
    }


# ----------------------------------------------------------------------
# Aggregation
# ----------------------------------------------------------------------

def run_scan(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace).resolve() if args.workspace else Path.cwd().resolve()
    cache_dir = Path(args.cache_dir).resolve() if args.cache_dir else REPO_ROOT / "reference" / "contest_cache"
    draft_path = Path(args.finding_draft).resolve()
    if not draft_path.exists():
        raise SystemExit(f"finding draft not found: {draft_path}")
    draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
    fingerprint = extract_fingerprint(draft_text)

    requested_sources = list(ALL_SOURCES)
    if args.sources:
        requested_sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        unknown = [s for s in requested_sources if s not in ALL_SOURCES]
        if unknown:
            raise SystemExit(f"unknown source(s): {unknown}; valid={list(ALL_SOURCES)}")

    per_source: list[dict[str, Any]] = []
    for src in requested_sources:
        if src == "nvd":
            r = check_nvd(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                cve_id=args.cve_id,
                cache_dir=cache_dir,
            )
        elif src == "ghsa":
            r = check_ghsa(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                ghsa_id=args.ghsa_id,
                cache_dir=cache_dir,
            )
        elif src == "audit_firm_portfolios":
            r = check_audit_firm_portfolios(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                workspace=workspace,
            )
        elif src == "code4rena":
            r = check_code4rena(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                cache_dir=cache_dir,
            )
        elif src == "sherlock":
            r = check_sherlock(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                cache_dir=cache_dir,
            )
        elif src == "prior_audits":
            r = check_prior_audits(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                workspace=workspace,
            )
        elif src == "auditooor_submissions":
            r = check_auditooor_submissions(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                workspace=workspace,
            )
        elif src == "vault_dupe_rejection":
            r = check_vault_dupe_rejection(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                workspace=workspace,
            )
        elif src == "disclosure_pages":
            r = check_disclosure_pages(
                fingerprint=fingerprint,
                target_protocol=args.target_protocol,
                disclosure_url=args.disclosure_url,
            )
        else:
            r = {
                "source": src,
                "verdict": VERDICT_ERROR,
                "reason": f"unimplemented source: {src}",
                "matches": [],
            }
        per_source.append(r)

    aggregate = VERDICT_PASS
    for entry in per_source:
        if VERDICT_RANK[entry["verdict"]] > VERDICT_RANK[aggregate]:
            aggregate = entry["verdict"]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": DISCLAIMER_TEXT,
        "finding_draft": str(draft_path),
        "target_protocol": args.target_protocol,
        "workspace": str(workspace),
        "fingerprint": fingerprint,
        "sources_checked": requested_sources,
        "per_source_verdicts": per_source,
        "aggregate_verdict": aggregate,
    }


def _format_human(result: dict[str, Any]) -> str:
    lines = []
    lines.append("Wave-3 published-source originality scanner")
    lines.append("=" * 60)
    lines.append("")
    lines.append("DISCLAIMER")
    lines.append("-" * 10)
    lines.append(result["disclaimer"])
    lines.append("")
    lines.append(f"finding_draft     : {result['finding_draft']}")
    lines.append(f"target_protocol   : {result['target_protocol']}")
    lines.append(f"workspace         : {result['workspace']}")
    lines.append(f"title             : {result['fingerprint'].get('title','')}")
    lines.append(f"tokens            : n={result['fingerprint'].get('token_count',0)}")
    lines.append("")
    lines.append("Per-source verdicts")
    lines.append("-" * 19)
    for entry in result["per_source_verdicts"]:
        lines.append(f"  [{entry['verdict']:<24}] {entry['source']:<24} {entry['reason']}")
        for m in entry.get("matches", [])[:3]:
            lines.append(f"      match: {m}")
    lines.append("")
    lines.append(f"AGGREGATE VERDICT : {result['aggregate_verdict']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Wave-3 published-source originality scanner (PR #729).",
    )
    p.add_argument("--finding-draft", required=True, help="path to draft .md to check")
    p.add_argument("--target-protocol", required=True, help="protocol slug, e.g. dydx, spark")
    p.add_argument("--workspace", default=None, help="workspace path (default: cwd)")
    p.add_argument("--cve-id", default=None, help="optional NVD CVE-YYYY-NNNN")
    p.add_argument("--ghsa-id", default=None, help="optional GHSA-XXXX-YYYY-ZZZZ")
    p.add_argument("--disclosure-url", default=None, help="optional protocol disclosure URL")
    p.add_argument("--sources", default=None, help=f"comma-separated subset of: {','.join(ALL_SOURCES)}")
    p.add_argument("--cache-dir", default=None, help="published-source cache root")
    p.add_argument("--json", action="store_true", help="emit JSON instead of human text")
    p.add_argument("--strict", action="store_true", help="exit 1 on any BLOCK verdict")
    args = p.parse_args(argv)

    result = run_scan(args)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_format_human(result))

    if args.strict and result["aggregate_verdict"] == VERDICT_BLOCK:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
