#!/usr/bin/env python3
"""Bounded originality/dupe pre-proof gate.

Advisory status:
  - pass: no strong indicators
  - warn: missing corpus or only weak signals
  - fail: strong duplicate/prior-disclosure indicator
  - error: malformed input / fatal scan failure

The gate reuses:
  - tools/dedup-grep.py (extract_keywords + grep_prior_audits)
  - tools/vault-mcp-server.py (vault_originality_context)
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
DEDUP_PATH = REPO_ROOT / "tools" / "dedup-grep.py"

# PR2b: route originality corpus consumption through the shared trusted-corpus
# resolver so the gate output states the trust_scope its corpus was read under.
sys.path.insert(0, str(REPO_ROOT / "tools" / "lib"))
try:
    import trusted_corpus_resolver as _tcr  # noqa: E402
except Exception:  # pragma: no cover - defensive
    _tcr = None


def _corpus_trust_annotation() -> dict[str, Any]:
    if _tcr is None:
        return {"trust_scope": "raw-fallback", "is_fallback": True,
                "reason": "trusted_corpus_resolver unavailable"}
    inc = os.environ.get("INCLUDE_ADVISORY") == "1"
    return _tcr.resolve_active_corpus(repo_root_path=REPO_ROOT,
                                      include_advisory=inc).as_dict()
SCHEMA = "auditooor.originality_before_proof_gate.v1"
RECORDED_POSTURE_SCHEMA = "auditooor.originality_before_proof_recorded_posture.v1"

DEFAULT_MAX_EVIDENCE = 12
MAX_RECORDED_EVIDENCE_LINES = 8
MAX_FINGERPRINT_ITEMS = 8
MAX_FINGERPRINT_TERM_CHARS = 96
STRONG_SCORE_THRESHOLD = 4
LOCAL_STRONG_LINE_THRESHOLD = 3
LOCAL_STRONG_TERM_THRESHOLD = 2

STATUS_STRONG_HINTS = {"duplicate", "dupe", "ack", "acknowledged", "not_a_bug", "oos", "rejected", "out_of_scope"}
STATUS_WEAK_HINTS = {"possible", "review", "investigating"}

ENTRYPOINT_ACTION_HINTS = (
    "withdraw",
    "deposit",
    "borrow",
    "repay",
    "liquidat",
    "redeem",
    "claim",
    "swap",
    "mint",
    "burn",
    "stake",
    "unstake",
)
HELPER_NAME_HINTS = ("require", "check", "verify", "validate", "assert", "guard", "enforce", "get", "sorted")
INVARIANT_CUES = (
    "invariant",
    "relies on",
    "assum",
    "proof obligation",
    "ordering",
    "sentinel",
    "health",
    "collateral",
)
INVARIANT_LEXICON = {
    "invariant",
    "ordering",
    "order",
    "icr",
    "ltv",
    "health",
    "sentinel",
    "collateral",
    "undercollateralized",
    "principal",
    "accrual",
    "proxy",
    "proof",
    "obligation",
    "live",
}
IMPACT_CUES = ("impact", "bypass", "blocked", "withdraw", "loss", "drain", "denial", "dos", "liquidation", "stuck", "freeze")
IMPACT_LEXICON = {
    "bypass",
    "blocked",
    "block",
    "drain",
    "loss",
    "steal",
    "withdraw",
    "freeze",
    "dos",
    "denial",
    "liquidation",
    "stuck",
    "grief",
    "impact",
}
FIX_CUES = ("fix", "patch", "replace", "repair", "mitigation", "enforce", "validate", "check", "guard")
FIX_LEXICON = {
    "fix",
    "patch",
    "replace",
    "repair",
    "mitigation",
    "guard",
    "check",
    "validate",
    "enforce",
    "sentinel",
    "ordering",
    "icr",
    "live",
}

CODE_SYMBOL_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]{2,80}(?:\.[A-Za-z_][A-Za-z0-9_]{2,80})?(?:\([A-Za-z0-9_,\s\[\]\.]{0,80}\))?"
)
WORD_RE = re.compile(r"[a-z][a-z0-9_]{2,40}")
ORIGINALITY_SECTION_HEADING_RE = re.compile(
    r"^##+\s+(?:Originality(?:\s*/\s*Duplicate Review)?|Originality defense)\b",
    re.IGNORECASE,
)
ORIGINALITY_RELEVANT_LINE_RE = re.compile(
    r"(?:originality(?:[- ]before[- ]proof)?|duplicate posture|dupe(?:-risk)?|prior audit grep|novelty|novel vector)",
    re.IGNORECASE,
)
STRUCTURED_ORIGINALITY_STATUS_RE = re.compile(
    r"originality(?:[- ]before[- ]proof)?\s*[:|]\s*(PASS|WARN|FAIL|NOVEL|DUPE|PENDING)",
    re.IGNORECASE,
)
RECORDED_FAIL_PATTERNS = (
    re.compile(r"\bduplicate of\b", re.IGNORECASE),
    re.compile(r"\bdupe of\b", re.IGNORECASE),
    re.compile(r"\bnot novel\b", re.IGNORECASE),
    re.compile(r"\balready filed\b", re.IGNORECASE),
    re.compile(r"\bsame finding\b", re.IGNORECASE),
    re.compile(r"\bknown duplicate\b", re.IGNORECASE),
    re.compile(r"\bknown issue\b", re.IGNORECASE),
    re.compile(r"\bdoa\b", re.IGNORECASE),
)
RECORDED_PASS_PATTERNS = (
    re.compile(r"\bno hits\b", re.IGNORECASE),
    re.compile(r"\bzero hits\b", re.IGNORECASE),
    re.compile(r"\blocally novel\b", re.IGNORECASE),
    re.compile(r"\bappears novel\b", re.IGNORECASE),
    re.compile(r"\bthis is a novel vector\b", re.IGNORECASE),
    re.compile(r"\bnovel vector\b", re.IGNORECASE),
    re.compile(r"\bno local submitted duplicate\b", re.IGNORECASE),
    re.compile(r"\boriginality strong\b", re.IGNORECASE),
    re.compile(r"\bclean\b", re.IGNORECASE),
)
RECORDED_WARN_PATTERNS = (
    re.compile(r"\bpartial dupe\b", re.IGNORECASE),
    re.compile(r"\bpending grep\b", re.IGNORECASE),
    re.compile(r"\bneeds review\b", re.IGNORECASE),
    re.compile(r"\bweak match\b", re.IGNORECASE),
    re.compile(r"\bfresh-or-weak-match\b", re.IGNORECASE),
    re.compile(r"\bprivate .*duplicate.* unavailable\b", re.IGNORECASE),
    re.compile(r"\bcaveat\b", re.IGNORECASE),
    re.compile(r"\bdupe-risk\b", re.IGNORECASE),
    re.compile(r"\bnot provably unique\b", re.IGNORECASE),
    re.compile(r"\bpartial[- ]fix\b", re.IGNORECASE),
)
RECORDED_OVERRIDE_PATTERNS = (
    re.compile(r"\bdupe override\b", re.IGNORECASE),
    re.compile(r"\bnovel vector\b", re.IGNORECASE),
    re.compile(r"\bdistinct from\b", re.IGNORECASE),
    re.compile(r"\bdifferent vector\b", re.IGNORECASE),
    re.compile(r"\bnot a dupe\b", re.IGNORECASE),
    re.compile(r"\bsame class\b", re.IGNORECASE),
)


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _load_vault_query(vault_dir: str | None) -> tuple[Any, str | None]:
    server = _load_module(SERVER_PATH, "vault_mcp_server_for_gate")
    argv = ["--vault-dir", vault_dir] if vault_dir else []
    resolved_vault, note = server.resolve_vault_dir(str(vault_dir or server.DEFAULT_VAULT), argv=argv)
    return server.VaultQuery(vault_dir=resolved_vault), note


def _load_dedup() -> Any:
    return _load_module(DEDUP_PATH, "dedup_grep_for_gate")


def _normalize_kw(raw: str, dedup_mod: Any) -> str:
    if hasattr(dedup_mod, "_normalize_keyword"):
        return str(dedup_mod._normalize_keyword(raw)).strip()  # type: ignore[attr-defined]
    return str(raw or "").strip().strip(".,;:()[]{}<>\"'`").strip().lower()


def _dedupe_items(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        low = str(value).strip().lower()
        if not low or low in seen:
            continue
        seen.add(low)
        out.append(low)
    return out


def _bounded_unique(values: list[str], *, max_items: int = MAX_FINGERPRINT_ITEMS, max_chars: int = MAX_FINGERPRINT_TERM_CHARS) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        item = " ".join(str(raw or "").strip().split())
        if not item:
            continue
        item = item[:max_chars]
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= max_items:
            break
    return out


def _extract_keywords_from_draft(draft: Path, dedup_mod: Any) -> list[str]:
    text = draft.read_text(encoding="utf-8", errors="replace")
    if hasattr(dedup_mod, "extract_keywords"):
        keywords = list(dedup_mod.extract_keywords(text))  # type: ignore[attr-defined]
    else:
        tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
        keywords = [tok for tok in tokens if len(tok) >= 3]
    normalized = [_normalize_kw(tok, dedup_mod) for tok in keywords]
    return _dedupe_items([kw for kw in normalized if kw])


def _extract_code_symbols_from_text(text: str) -> list[str]:
    if not text:
        return []
    symbols: list[str] = []
    for match in CODE_SYMBOL_RE.finditer(text):
        token = match.group(0).strip().strip("`").rstrip(".,;:")
        if len(token) < 3:
            continue
        # Keep only likely code references, not plain prose words.
        if "." not in token and "(" not in token and not token.startswith("_"):
            continue
        symbols.append(token)
    return _bounded_unique(symbols, max_items=MAX_FINGERPRINT_ITEMS * 3)


def _extract_terms_from_text(text: str, *, cues: tuple[str, ...], lexicon: set[str]) -> list[str]:
    if not text:
        return []
    terms: list[str] = []
    for chunk in re.split(r"[\n\.;:]+", text):
        low = chunk.lower()
        if not any(cue in low for cue in cues):
            continue
        for word in WORD_RE.findall(low):
            if word in lexicon:
                terms.append(word)
    return _bounded_unique(terms)


def _extract_terms_from_keywords(keywords: list[str], *, lexicon: set[str]) -> list[str]:
    out: list[str] = []
    for kw in keywords:
        low = str(kw or "").strip().lower()
        if not low:
            continue
        if low in lexicon:
            out.append(low)
            continue
        for term in lexicon:
            if term in low:
                out.append(low)
                break
    return _bounded_unique(out)


def _extract_root_cause_fingerprint(*, draft_text: str, keywords: list[str]) -> dict[str, list[str]]:
    code_symbols = _extract_code_symbols_from_text(draft_text)
    keyword_symbols = [
        kw.strip()
        for kw in keywords
        if any(ch in kw for ch in "._()")
    ]
    all_symbols = _bounded_unique([*code_symbols, *keyword_symbols], max_items=MAX_FINGERPRINT_ITEMS * 4)

    entrypoints: list[str] = []
    helpers: list[str] = []
    for sym in all_symbols:
        func = sym.split(".")[-1].split("(", 1)[0].lstrip("_").lower()
        if sym.startswith("_") or any(h in func for h in HELPER_NAME_HINTS):
            helpers.append(sym)
            continue
        if any(func.startswith(hint) for hint in ENTRYPOINT_ACTION_HINTS):
            entrypoints.append(sym)

    for kw in keywords:
        low = kw.strip().lower()
        if low.startswith("_"):
            helpers.append(low)

    invariant_terms = _bounded_unique(
        [
            *_extract_terms_from_text(draft_text, cues=INVARIANT_CUES, lexicon=INVARIANT_LEXICON),
            *_extract_terms_from_keywords(keywords, lexicon=INVARIANT_LEXICON),
        ]
    )
    impact_terms = _bounded_unique(
        [
            *_extract_terms_from_text(draft_text, cues=IMPACT_CUES, lexicon=IMPACT_LEXICON),
            *_extract_terms_from_keywords(keywords, lexicon=IMPACT_LEXICON),
        ]
    )
    fix_terms = _bounded_unique(
        [
            *_extract_terms_from_text(draft_text, cues=FIX_CUES, lexicon=FIX_LEXICON),
            *_extract_terms_from_keywords(keywords, lexicon=FIX_LEXICON),
        ]
    )

    return {
        "entrypoints": _bounded_unique(entrypoints),
        "helpers": _bounded_unique(helpers),
        "invariant_terms": invariant_terms,
        "impact_terms": impact_terms,
        "fix_terms": fix_terms,
    }


def _infer_recorded_severity(text: str) -> str:
    for pattern in (
        r"^\*\*Severity:\*\*\s*(Critical|High|Medium|Low|Info)",
        r"^Severity:\s*(Critical|High|Medium|Low|Info)",
        r"^-\s*\*\*Severity:\*\*\s*(Critical|High|Medium|Low|Info)",
    ):
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).upper()
    section_match = re.search(r"^##\s*Severity\s*$", text, flags=re.IGNORECASE | re.MULTILINE)
    if section_match:
        after = text[section_match.end() :].splitlines()
        for line in after:
            stripped = line.strip()
            if not stripped:
                continue
            sev = re.search(r"\b(Critical|High|Medium|Low|Info)\b", stripped, re.IGNORECASE)
            if sev:
                return sev.group(1).upper()
            break
    return ""


def _collect_recorded_originality_lines(text: str) -> list[str]:
    lines = text.splitlines()
    evidence: list[str] = []
    capture = False
    for line in lines:
        stripped = line.strip()
        if ORIGINALITY_SECTION_HEADING_RE.match(stripped):
            capture = True
            continue
        if capture and re.match(r"^##+\s+", stripped):
            capture = False
        if capture and stripped:
            evidence.append(stripped)
        elif ORIGINALITY_RELEVANT_LINE_RE.search(stripped):
            evidence.append(stripped)

    deduped: list[str] = []
    seen: set[str] = set()
    for line in evidence:
        normalized = re.sub(r"\s+", " ", line).strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)
        if len(deduped) >= MAX_RECORDED_EVIDENCE_LINES:
            break
    return deduped


def _recorded_posture_line_classes(lines: list[str]) -> dict[str, bool]:
    joined = "\n".join(lines)
    structured_statuses = [
        match.group(1).upper()
        for match in STRUCTURED_ORIGINALITY_STATUS_RE.finditer(joined)
    ]
    has_structured_fail = any(status in {"FAIL", "DUPE"} for status in structured_statuses)
    has_structured_pass = any(status in {"PASS", "NOVEL"} for status in structured_statuses)
    has_structured_warn = any(status in {"WARN", "PENDING"} for status in structured_statuses)
    return {
        "structured_fail": has_structured_fail,
        "structured_pass": has_structured_pass,
        "structured_warn": has_structured_warn,
        "fail": has_structured_fail or any(pattern.search(joined) for pattern in RECORDED_FAIL_PATTERNS),
        "pass": has_structured_pass or any(pattern.search(joined) for pattern in RECORDED_PASS_PATTERNS),
        "warn": has_structured_warn or any(pattern.search(joined) for pattern in RECORDED_WARN_PATTERNS),
        "override": any(pattern.search(joined) for pattern in RECORDED_OVERRIDE_PATTERNS),
    }


def build_packet(draft: Path, *, severity: str | None = None) -> dict[str, Any]:
    """Classify the draft's recorded originality/dupe posture without scanning corpora."""
    draft = draft.expanduser().resolve()
    if not draft.is_file():
        return {
            "schema": RECORDED_POSTURE_SCHEMA,
            "draft_path": str(draft),
            "severity": (severity or "").upper(),
            "verdict": "error",
            "code": "draft-not-found",
            "message": f"draft not found: {draft}",
            "evidence_lines": [],
        }

    text = draft.read_text(encoding="utf-8", errors="replace")
    severity_upper = (severity or _infer_recorded_severity(text) or "").upper()
    evidence_lines = _collect_recorded_originality_lines(text)
    classes = _recorded_posture_line_classes(evidence_lines)
    if not evidence_lines:
        verdict = "warn"
        code = "missing-recorded-originality-posture"
        message = "No bounded originality/duplicate posture is recorded in the draft."
    elif classes["fail"] and classes["override"]:
        verdict = "warn"
        code = "mixed-duplicate-posture"
        message = "Originality posture mentions duplicate risk but also records a distinct-vector override."
    elif classes["fail"]:
        verdict = "fail"
        code = "recorded-duplicate-or-fail"
        message = "Draft records an explicit duplicate/fail originality posture."
    elif classes["warn"]:
        verdict = "warn"
        code = "recorded-originality-warning"
        message = "Draft records uncertain or caveated originality posture."
    elif classes["pass"]:
        verdict = "pass"
        code = "recorded-originality-pass"
        message = "Draft records a bounded novel/no-hits originality posture."
    else:
        verdict = "warn"
        code = "unclassified-recorded-originality-posture"
        message = "Originality posture is present but not classifiable as pass/fail."

    return {
        "schema": RECORDED_POSTURE_SCHEMA,
        "draft_path": str(draft),
        "severity": severity_upper,
        "verdict": verdict,
        "code": code,
        "message": message,
        "evidence_lines": evidence_lines,
        "line_classes": classes,
        "source_refs": ["tools/originality-before-proof-gate.py:build_packet"],
    }


def _safe_local_source_ref(workspace: Path, raw_path: str) -> str:
    path = Path(raw_path)
    if path.is_absolute():
        try:
            return "prior_audit/" + str(path.resolve().relative_to(workspace.resolve()))
        except ValueError:
            return f"prior_audit/{path.name}"
    return f"prior_audit/{path.as_posix()}"


def _safe_vault_source_ref(value: str, safe_ref_func: Any) -> str:
    safe = safe_ref_func(value)
    if safe:
        return safe
    return "vault://UNKNOWN"


def _status_string(value: object) -> str:
    text = str(value or "").strip().lower()
    return text


def _is_strong_status(status: str) -> bool:
    if not status:
        return False
    text = _status_string(status)
    return any(token in text for token in STATUS_STRONG_HINTS)


def _is_weak_status(status: str) -> bool:
    if not status:
        return False
    text = _status_string(status)
    return any(token in text for token in STATUS_WEAK_HINTS)


def _classify_vault_hit(vault_hit: dict[str, Any]) -> str:
    status = _status_string(vault_hit.get("status"))
    if _is_strong_status(status):
        return "strong"
    score = int(vault_hit.get("score", 0) or 0)
    matched = vault_hit.get("matched_terms") or []
    if score >= STRONG_SCORE_THRESHOLD and len(matched) >= 2:
        return "strong"
    if score > 0 or _is_weak_status(status):
        return "weak"
    return "weak"


def _classify_local_file_hits(hit_count: int, term_count: int) -> str:
    if hit_count >= LOCAL_STRONG_LINE_THRESHOLD and term_count >= LOCAL_STRONG_TERM_THRESHOLD:
        return "strong"
    return "weak"


def _run(
    workspace: Path,
    *,
    keywords: list[str],
    draft: Path | None = None,
    vault_dir: str | None = None,
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "pass",
        "workspace": "",
        "workspace_name": "",
        "keywords": [],
        "evidence": [],
        "counts": {},
        "warnings": [],
        "errors": [],
        "status_reason": [],
        "source_refs": [],
        "corpus_trust": _corpus_trust_annotation(),
        "source": {
            "local_scan": "tools/dedup-grep.py:grep_prior_audits",
            "vault_scan": "tools/vault-mcp-server.py:vault_originality_context",
        },
        "source_scan": [
            "tools/dedup-grep.py",
            "tools/vault-mcp-server.py:vault_originality_context",
        ],
        "root_cause_fingerprint": {
            "entrypoints": [],
            "helpers": [],
            "invariant_terms": [],
            "impact_terms": [],
            "fix_terms": [],
        },
    }

    workspace = workspace.expanduser().resolve()
    payload["workspace"] = str(workspace)
    payload["workspace_name"] = workspace.name

    if not workspace.is_dir():
        payload["status"] = "error"
        payload["errors"].append({
            "code": "workspace_missing",
            "message": f"workspace not found: {workspace}",
        })
        return payload

    try:
        dedup_mod = _load_dedup()
    except Exception as exc:
        payload["status"] = "error"
        payload["errors"].append({
            "code": "dedup_import_error",
            "message": f"failed loading dedup logic: {exc}",
        })
        return payload

    if not keywords and draft:
        if not draft.is_file():
            payload["status"] = "error"
            payload["errors"].append({
                "code": "draft_not_found",
                "message": f"draft not found: {draft}",
            })
            return payload
        try:
            keywords = _extract_keywords_from_draft(draft, dedup_mod)
        except Exception as exc:
            payload["status"] = "error"
            payload["errors"].append({
                "code": "draft_parse_failed",
                "message": f"cannot extract keywords from draft {draft}: {exc}",
            })
            return payload

    draft_text = ""
    if draft and draft.is_file():
        try:
            draft_text = draft.read_text(encoding="utf-8", errors="replace")
        except Exception:
            draft_text = ""

    keywords = _dedupe_items([_normalize_kw(kw, dedup_mod) for kw in keywords])
    if not keywords:
        payload["status"] = "error"
        payload["errors"].append({
            "code": "missing_keywords",
            "message": "provide --keyword/--keywords or --draft",
        })
        return payload
    payload["keywords"] = keywords
    payload["root_cause_fingerprint"] = _extract_root_cause_fingerprint(
        draft_text=draft_text,
        keywords=keywords,
    )

    # Local workspace corpus scan (full-text prior_audits).
    local_scan = {"files_scanned_count": 0, "hits": []}
    local_hits: list[dict[str, Any]] = []
    try:
        local_scan = dedup_mod.grep_prior_audits(workspace, keywords)  # type: ignore[attr-defined]
        local_hits = local_scan.get("hits", [])
    except Exception as exc:
        payload["warnings"].append({
            "code": "local_scan_error",
            "message": f"prior_audit scan failed: {exc}",
        })

    local_file_hits: dict[str, list[dict[str, Any]]] = {}
    for hit in local_hits:
        local_file_hits.setdefault(str(hit.get("file", "")), []).append(hit)

    # Vault-backed prior-audit extract scan.
    vault_payload: dict[str, Any] = {"degraded": True, "reason": "scan_not_run", "hits": []}
    vault_hits: list[dict[str, Any]] = []
    vault_scan_note: str | None = None
    try:
        vault_query, vault_scan_note = _load_vault_query(vault_dir)
        if vault_scan_note:
            payload["source"]["vault_note"] = vault_scan_note
        vault_payload = vault_query.vault_originality_context(
            workspace_path=str(workspace),
            keywords=keywords,
            limit=20,
        )
        vault_hits = vault_payload.get("hits", [])
        payload["source"]["vault_scan_enabled"] = True
    except Exception as exc:
        payload["warnings"].append({
            "code": "vault_scan_error",
            "message": f"prior-audit extract scan unavailable: {exc}",
        })
        payload["source"]["vault_scan_enabled"] = False

    vault_missing = (
        bool(vault_payload.get("degraded"))
        and vault_payload.get("reason") == "section_missing"
    )
    local_missing = int(local_scan.get("files_scanned_count", 0) or 0) == 0
    if vault_missing and local_missing:
        payload["warnings"].append({
            "code": "corpus_missing",
            "message": "no local prior_audits and no prior-audits-extracts corpus",
        })

    # Build evidence, keeping privacy-safe source refs.
    safe_source_refs: set[str] = set()
    vault_safe_ref: Any = None
    try:
        vault_server = _load_module(SERVER_PATH, "vault_mcp_server_for_gate_refs")
        vault_safe_ref = getattr(vault_server, "_safe_source_ref")
    except Exception:
        vault_safe_ref = None

    strong_hits = 0
    weak_hits = 0
    evidence_rows: list[dict[str, Any]] = []

    for hit in sorted(vault_hits, key=lambda row: int(row.get("score", 0) or 0), reverse=True)[:max_evidence]:
        strength = _classify_vault_hit(hit)
        if strength == "strong":
            strong_hits += 1
        else:
            weak_hits += 1

        source_ref = str(hit.get("source_ref", ""))
        if vault_safe_ref is not None:
            source_ref = _safe_vault_source_ref(source_ref, vault_safe_ref)
        if source_ref:
            safe_source_refs.add(source_ref)
        evidence_rows.append({
            "source": "prior_audit_extract",
            "strength": strength,
            "source_ref": source_ref,
            "finding_id": str(hit.get("finding_id", "")),
            "status": str(hit.get("status", "")),
            "score": int(hit.get("score", 0) or 0),
            "matched_terms": hit.get("matched_terms", []),
            "snippet": str(hit.get("snippet", ""))[:240],
        })

    for file_path, hits in local_file_hits.items():
        terms = _dedupe_items([_normalize_kw(str(h.get("keyword", "")), dedup_mod) for h in hits])
        strength = _classify_local_file_hits(len(hits), len(terms))
        if strength == "strong":
            strong_hits += 1
        else:
            weak_hits += 1
        ref = _safe_local_source_ref(workspace, str(file_path))
        safe_source_refs.add(ref)
        evidence_rows.append({
            "source": "prior_audit_scan",
            "strength": strength,
            "source_ref": ref,
            "match_count": len(hits),
            "matched_terms": terms,
            "sample_line": str(hits[0].get("snippet", "")) if hits else "",
        })

    evidence_rows.sort(
        key=lambda row: (0 if row["strength"] == "strong" else 1, -int(row.get("score", 0) or 0))
    )
    payload["evidence"] = evidence_rows[:max_evidence]
    payload["source_refs"] = sorted(safe_source_refs)

    payload["counts"] = {
        "keyword_count": len(keywords),
        "vault_hits": len(vault_hits),
        "local_hits": len(local_hits),
        "local_files_scanned": int(local_scan.get("files_scanned_count", 0) or 0),
        "local_files_with_hits": len(local_file_hits),
        "strong_hits": strong_hits,
        "weak_hits": weak_hits,
    }

    if payload["errors"]:
        payload["status"] = "error"
    elif strong_hits > 0:
        payload["status"] = "fail"
    elif weak_hits > 0 or payload["warnings"]:
        payload["status"] = "warn"
    else:
        payload["status"] = "pass"

    if payload["status"] != "pass":
        payload["status_reason"] = [
            row["code"] for row in payload["warnings"] + payload["errors"]
        ]

    return payload


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", nargs="?", help="workspace root directory path")
    parser.add_argument(
        "--keyword",
        "-k",
        action="append",
        default=[],
        help="keyword (repeatable)",
    )
    parser.add_argument(
        "--keywords",
        nargs="+",
        default=[],
        help="keywords to use (space-separated list)",
    )
    parser.add_argument("--draft", help="draft/brief path for keyword extraction")
    parser.add_argument(
        "--recorded-posture",
        action="store_true",
        help="classify only the draft's recorded originality/dupe posture",
    )
    parser.add_argument(
        "--severity",
        choices=(
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ),
        help="explicit severity for recorded-posture classification",
    )
    parser.add_argument("--vault-dir", help="explicit vault override for vault_originality_context")
    parser.add_argument(
        "--max-evidence",
        type=int,
        default=DEFAULT_MAX_EVIDENCE,
        help=f"max evidence rows to emit (default: {DEFAULT_MAX_EVIDENCE})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="explicit JSON output flag (JSON is always emitted)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.recorded_posture:
        if not args.draft:
            print(json.dumps({
                "schema": RECORDED_POSTURE_SCHEMA,
                "verdict": "error",
                "code": "draft-required",
                "message": "--recorded-posture requires --draft",
                "evidence_lines": [],
            }, indent=2, sort_keys=True))
            return 2
        packet = build_packet(Path(args.draft), severity=args.severity)
        print(json.dumps(packet, indent=2, sort_keys=True))
        if packet["verdict"] == "fail":
            return 1
        if packet["verdict"] == "error":
            return 2
        return 0

    if not args.workspace:
        print(json.dumps({
            "schema": SCHEMA,
            "status": "error",
            "errors": [{"code": "workspace_required", "message": "workspace is required unless --recorded-posture is used"}],
        }, indent=2, sort_keys=True))
        return 2
    workspace = Path(args.workspace)
    draft = Path(args.draft).expanduser() if args.draft else None
    payload = _run(
        workspace,
        keywords=[*(args.keyword or []), *(args.keywords or [])],
        draft=draft,
        vault_dir=args.vault_dir,
        max_evidence=max(1, int(args.max_evidence)),
    )
    payload["args"] = {
        "workspace": str(workspace),
        "draft": str(draft) if draft else None,
        "vault_dir": args.vault_dir or os.environ.get("AUDITOOOR_VAULT_DIR"),
        "max_evidence": int(args.max_evidence),
    }
    payload["status_digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    print(json.dumps(payload, indent=2, sort_keys=True))

    if payload["status"] == "fail":
        return 1
    if payload["status"] == "error":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
