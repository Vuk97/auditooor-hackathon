#!/usr/bin/env python3
"""Bridge mined findings into audit-time hacker-question obligations.

The bridge is intentionally offline and fail-closed.  It turns local mined
source obligations, corpus records, and secondary agent/provider lesson
artifacts into bounded advisory work items.  It does not prove exploitability,
does not assign severity, and never creates source-read receipts.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    import yaml  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_INPUT_BYTES = 20_000_000
MAX_CORPUS_RECORDS = 2500
MAX_PROFILE_SOURCE_FILES = 80
DEFAULT_MIN_CORPUS_RELEVANCE = 0.35
SCHEMA = "auditooor.mined_findings_hunter_bridge.v1"
OBLIGATION_SCHEMA = "auditooor.hacker_question_obligation.v1"
PROOF_BOUNDARY = (
    "Advisory hunter obligation only; it is not exploitability, impact, "
    "severity, duplicate, OOS, or submission-readiness evidence."
)
SCOPE_POLICY = (
    "Answer against the evidence surface declared by program scope: in-scope "
    "source is sufficient for source-only bounties; exact deployed address, "
    "configuration, or live state proof is required only for deployed/live-only "
    "programs, mixed-scope deployment claims, or claims that depend on live config."
)
NO_FAKE_RECEIPTS = (
    "This bridge never creates source_read_receipts. Only the source-read "
    "injection flow may record those after actual source inspection."
)
LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9+.-]:)/(?:Users|private/var|var|tmp|Volumes|home)/[^\s,\"')\]}]+"
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_text(value: Any, *, max_chars: int = 600) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:max_chars]


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _short_hash(value: Any, length: int = 12) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]


def _stable_id(prefix: str, parts: Sequence[Any]) -> str:
    return f"{prefix}-{_short_hash(list(parts))}"


def _redact_path(path: str | Path, workspace: Path) -> str:
    raw = str(path)
    p = Path(raw)
    try:
        rel = p.resolve().relative_to(workspace.resolve())
        if rel.as_posix() == ".":
            return "<workspace>"
        return "<workspace>/" + rel.as_posix()
    except (OSError, ValueError):
        pass
    try:
        if p.is_absolute():
            return f"<local-path>/{p.name or 'path'}"
    except OSError:
        pass
    return raw


def _workspace_prefixes(workspace: Path) -> list[str]:
    prefixes = {str(workspace), str(workspace.resolve())}
    for prefix in list(prefixes):
        if prefix.startswith("/private/var/"):
            prefixes.add(prefix.replace("/private/var/", "/var/", 1))
        elif prefix.startswith("/var/"):
            prefixes.add(prefix.replace("/var/", "/private/var/", 1))
    return sorted(prefixes, key=len, reverse=True)


def _redact_text(text: str, workspace: Path) -> str:
    out = text
    for prefix in _workspace_prefixes(workspace):
        pattern = re.compile(rf"{re.escape(prefix)}(?=$|/|[\"'\s,}}\]])")
        out = pattern.sub("<workspace>", out)
    out = LOCAL_PATH_RE.sub(lambda match: f"<local-path>/{Path(match.group(0)).name or 'path'}", out)
    return out


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _read_structured(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".json":
            payload = json.loads(text)
        elif yaml is not None:
            payload = yaml.safe_load(text)
        else:
            return None
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _target_profile(workspace: Path) -> dict[str, Any]:
    """Return bounded local target signals used to decide corpus relevance."""
    signals: list[str] = []
    paths: list[str] = []
    oos_paths: list[str] = []
    for rel in (
        "SCOPE.md",
        "README.md",
        "SEVERITY.md",
        "Cargo.toml",
        "go.mod",
        "package.json",
        "foundry.toml",
    ):
        path = workspace / rel
        if path.is_file():
            try:
                signals.append(path.read_text(encoding="utf-8", errors="replace")[:4000])
                paths.append(rel)
            except OSError:
                pass
    if (workspace / "OOS_PASTED.md").is_file():
        oos_paths.append("OOS_PASTED.md")
        paths.append("OOS_PASTED.md")
    source_exts = Counter()
    source_dirs = ("src", "contracts", "pallets", "runtime", "protocol", "x", "programs")
    source_files_seen = 0
    for dirname in source_dirs:
        root = workspace / dirname
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".sol", ".rs", ".go", ".move", ".vy", ".cairo"}:
                source_files_seen += 1
                source_exts[path.suffix.lower()] += 1
                if len(paths) < 80:
                    paths.append(_redact_path(path, workspace))
                if source_files_seen >= MAX_PROFILE_SOURCE_FILES:
                    break
        if source_files_seen >= MAX_PROFILE_SOURCE_FILES:
            break
    joined = "\n".join(signals + paths)
    language_hints: set[str] = set()
    if ".sol" in source_exts or re.search(r"\b(solidity|evm|smart contract|etherscan)\b", joined, re.I):
        language_hints.add("solidity")
    if ".rs" in source_exts or re.search(r"\b(rust|substrate|pallet|runtime|cargo)\b", joined, re.I):
        language_hints.add("rust")
    if ".go" in source_exts or re.search(r"\b(go|cosmos|keeper|msgserver|cometbft)\b", joined, re.I):
        language_hints.add("go")
    if ".move" in source_exts or re.search(r"\b(move|aptos|sui)\b", joined, re.I):
        language_hints.add("move")
    if ".vy" in source_exts or re.search(r"\bvyper\b", joined, re.I):
        language_hints.add("vyper")
    domain_hints = [
        word
        for word in (
            "bridge",
            "vault",
            "dex",
            "oracle",
            "lending",
            "staking",
            "governance",
            "cosmos",
            "zk",
            "rollup",
        )
        if re.search(rf"\b{re.escape(word)}\b", joined, re.I)
    ]
    return {
        "has_target_signals": bool(signals or source_exts),
        "signal_paths": paths[:80],
        "oos_signal_paths": oos_paths,
        "language_hints": sorted(language_hints),
        "domain_hints": sorted(set(domain_hints)),
        "text": joined[:12000],
    }


def _corpus_relevance(row: dict[str, Any], profile: dict[str, Any]) -> float:
    if not profile.get("has_target_signals"):
        return 0.0
    score = 0.0
    language = str(row.get("target_language") or row.get("language") or "").lower()
    if language and language in set(profile.get("language_hints") or []):
        score += 0.18
    domain = str(row.get("target_domain") or row.get("platform") or "").lower()
    if domain and domain in set(profile.get("domain_hints") or []):
        score += 0.25
    text = str(profile.get("text") or "").lower()
    title = _safe_text(
        row.get("title")
        or row.get("target_component")
        or (row.get("record_extensions") or {}).get("title"),
        max_chars=200,
    ).lower()
    for token in re.findall(r"[a-z0-9]{4,}", title)[:8]:
        if token in text:
            score += 0.05
    attack_class = str(row.get("attack_class") or row.get("bug_class") or "").lower()
    for token in re.findall(r"[a-z0-9]{4,}", attack_class)[:5]:
        if token in text:
            score += 0.06
    return min(score, 0.75)


def _severity_weight(value: Any) -> float:
    sev = str(value or "").lower()
    if "critical" in sev:
        return 1.35
    if "high" in sev:
        return 1.20
    if "medium" in sev:
        return 1.0
    if "low" in sev:
        return 0.75
    if "info" in sev:
        return 0.40
    return 0.85


def _tier_weight(value: Any) -> float:
    tier = str(value or "").lower()
    if "tier-1" in tier:
        return 1.25
    if "tier-2" in tier:
        return 1.10
    if "tier-3" in tier:
        return 0.80
    if "tier-4" in tier:
        return 0.60
    if "tier-5" in tier or "quarantine" in tier:
        return 0.0
    return 0.75


def _infer_attack_class(*values: Any) -> str:
    haystack = " ".join(_safe_text(v, max_chars=1200).lower() for v in values)
    explicit = re.search(r"\battack[_ -]?class['\"]?\s*[:=]\s*['\"]?([a-z0-9_.:-]+)", haystack)
    if explicit:
        return explicit.group(1).strip("-_:") or "mined-lesson"
    checks = (
        ("bridge-message-validation", ("bridge", "cross-chain", "cross chain", "state root", "message root", "export", "import")),
        ("replay-protection", ("replay", "nonce", "processedtx", "txid", "double spend")),
        ("access-control", ("access control", "permission", "unauthorized", "onlyowner", "role")),
        ("admin-bypass", ("admin", "governance bypass", "privileged")),
        ("oracle-manipulation", ("oracle", "price", "twap", "stale", "confidence")),
        ("signature-replay", ("signature", "eip-712", "permit", "ecrecover")),
        ("reentrancy", ("reentrant", "reentrancy", "callback")),
        ("accounting-invariant", ("accounting", "solvency", "reserve", "collateral", "shares", "rounding")),
        ("liquidation-accounting", ("liquidation", "liquidator", "margin")),
        ("denial-of-service", ("dos", "denial of service", "revert", "grief", "freeze")),
        ("upgrade-safety", ("upgrade", "proxy", "initializer")),
    )
    for attack_class, needles in checks:
        if any(needle in haystack for needle in needles):
            return attack_class
    words = re.findall(r"[a-z0-9]+", haystack)
    return "-".join(words[:3])[:80] if words else "mined-lesson"


def _scope_mode_from_text(*values: Any) -> str:
    haystack = " ".join(_safe_text(v, max_chars=1000).lower() for v in values)
    source = any(marker in haystack for marker in ("source-only", "source only", "github", "repository", "runtime", "pallet", "smart contract"))
    live = any(marker in haystack for marker in ("deployed", "live state", "etherscan", "on-chain", "contract address", "configuration", "storage slot"))
    if source and live:
        return "mixed"
    if live:
        return "deployed_live_only"
    if source:
        return "source_only"
    return "unknown"


def _scope_fields(mode: str) -> dict[str, Any]:
    if mode == "source_only":
        return {
            "scope_evidence_mode": "source_only",
            "source_proof_required": True,
            "live_proof_required": False,
            "deployment_state_proof_required": False,
            "scope_evidence_policy": SCOPE_POLICY,
        }
    if mode == "deployed_live_only":
        return {
            "scope_evidence_mode": "deployed_live_only",
            "source_proof_required": False,
            "live_proof_required": True,
            "deployment_state_proof_required": True,
            "scope_evidence_policy": SCOPE_POLICY,
        }
    if mode == "mixed":
        return {
            "scope_evidence_mode": "mixed",
            "source_proof_required": True,
            "live_proof_required": True,
            "deployment_state_proof_required": True,
            "scope_evidence_policy": SCOPE_POLICY,
        }
    return {
        "scope_evidence_mode": "unknown",
        "source_proof_required": True,
        "live_proof_required": False,
        "deployment_state_proof_required": False,
        "scope_evidence_policy": SCOPE_POLICY + " Unknown scope defaults to source proof debt, not live-proof debt.",
    }


def _grep_token(*values: Any) -> str:
    stop = {"candidate", "lesson", "source", "finding", "bridge", "attack", "proof", "local", "with", "from"}
    for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", " ".join(str(v or "") for v in values)):
        if word.lower() not in stop:
            return word.replace("'", "")
    return "TODO"


def _verification_cmd(*values: Any) -> str:
    return f"rg -n '{_grep_token(*values)}' ."


def _dedupe_refs(refs: Iterable[Any], workspace: Path) -> list[str]:
    out: list[str] = []
    for ref in refs:
        text = _safe_text(ref, max_chars=260)
        if not text:
            continue
        text = _redact_text(text, workspace)
        out.append(text)
    return list(dict.fromkeys(out))[:10]


def _base_question(attack_class: str, title: str, summary: str) -> str:
    mechanism = _safe_text(summary or title or attack_class, max_chars=260)
    return f"Can the mined {attack_class} mechanism apply on this target's in-scope code path: {mechanism}?"


def _proof_obligation(mode: str) -> str:
    return (
        "Confirm attacker control and concrete impact on the scope-appropriate evidence surface: "
        "in-scope source for source-only programs; exact deployed address/state proof only for "
        "deployed/live-only or deployment/config claims. Then add a negative control or kill it."
    )


def _kill_condition() -> str:
    return (
        "Kill if no in-scope path exists, attacker control is missing, the source already has the "
        "guard/accounting fix, the claim is duplicate/OOS, or the impact cannot be demonstrated."
    )


def _mining_dashboard_lessons(payload: dict[str, Any], path: Path, workspace: Path) -> list[dict[str, Any]]:
    lessons: list[dict[str, Any]] = []
    rows = payload.get("rows") or payload.get("sources") or []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        obligations = row.get("source_obligations") or row.get("obligations") or []
        source_name = _safe_text(row.get("name") or row.get("source_id") or row.get("source_family"), max_chars=120)
        for ob in obligations if isinstance(obligations, list) else []:
            if not isinstance(ob, dict):
                continue
            if str(ob.get("status") or "open").lower() not in {"open", "pending", "backlog", "todo"}:
                continue
            required = _safe_text(ob.get("required_evidence") or ob.get("question") or ob.get("description"), max_chars=500)
            if not required:
                continue
            attack_class = _infer_attack_class(ob.get("obligation_type"), required, source_name)
            mode = _scope_mode_from_text(row, ob, required)
            source_id = str(ob.get("obligation_id") or ob.get("id") or _short_hash([source_name, required]))
            refs = [f"{_redact_path(path, workspace)}#{source_id}", *(ob.get("source_refs") or []), row.get("output_path")]
            lesson = {
                "lesson_id": _stable_id("mfhb", ["mining_dashboard", row.get("source_id"), source_id, required]),
                "source_kind": "mining_coverage_source_obligation",
                "source_obligation_id": source_id,
                "title": f"{source_name}: {source_id}",
                "lesson_statement": required,
                "lesson_kind": str(ob.get("obligation_type") or "source_obligation"),
                "attack_class": attack_class,
                "reuse_score": round(1.05 + (0.20 if "root" in required.lower() else 0.0), 4),
                "source_refs": _dedupe_refs(refs, workspace),
                "hunter_question": _base_question(attack_class, source_name, required),
                "local_verification_cmd": _verification_cmd(required, source_name, attack_class),
                "required_human_review": True,
                "advisory_only": True,
                "promotion_allowed": False,
                "source_read_receipts_created": False,
                "proof_boundary": PROOF_BOUNDARY,
                "blockers": ["source_obligation_open", "scope_appropriate_verification_required"],
                **_scope_fields(mode),
            }
            lessons.append(lesson)
    return lessons


def _candidate_lessons(payload: dict[str, Any], path: Path, workspace: Path) -> list[dict[str, Any]]:
    lessons: list[dict[str, Any]] = []
    rows = payload.get("candidates") or payload.get("lesson_candidates") or []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        title = _safe_text(row.get("title"), max_chars=180)
        statement = _safe_text(row.get("lesson_statement") or row.get("content"), max_chars=600)
        if not title and not statement:
            continue
        attack_class = _infer_attack_class(row.get("attack_class"), row.get("lesson_kind"), title, statement)
        mode = _scope_mode_from_text(row, title, statement)
        score = 0.35
        try:
            score = max(score, min(float(row.get("confidence_score") or 0.0), 1.0))
        except (TypeError, ValueError):
            pass
        score = round(score * 0.72, 4)
        refs = [_redact_path(path, workspace)]
        for item in row.get("provenance") or []:
            if isinstance(item, dict):
                refs.extend(item.get(k) for k in ("path", "source_ref", "report_path"))
        lesson = {
            "lesson_id": _stable_id("mfhb", ["agent_candidate", row.get("candidate_id"), title, statement]),
            "source_kind": "agent_artifact_lesson_candidate",
            "source_candidate_id": str(row.get("candidate_id") or ""),
            "title": title or statement[:120],
            "lesson_statement": statement,
            "lesson_kind": str(row.get("lesson_kind") or "agent_lesson"),
            "attack_class": attack_class,
            "reuse_score": score,
            "source_refs": _dedupe_refs(refs, workspace),
            "hunter_question": _base_question(attack_class, title, statement),
            "local_verification_cmd": _verification_cmd(title, statement, attack_class),
            "required_human_review": True,
            "advisory_only": True,
            "promotion_allowed": False,
            "source_read_receipts_created": False,
            "proof_boundary": PROOF_BOUNDARY,
            "blockers": ["secondary_agent_artifact", "human_review_required"],
            **_scope_fields(mode),
        }
        lessons.append(lesson)
    return lessons


def _provider_lessons(payload: dict[str, Any], path: Path, workspace: Path) -> list[dict[str, Any]]:
    lessons: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for key in ("items", "terminal_judgment_items", "deduped_items"):
        rows = payload.get(key)
        if isinstance(rows, list):
            items.extend(row for row in rows if isinstance(row, dict))
    for item in items:
        nested = [row for row in item.get("rows") or [] if isinstance(row, dict)]
        first = nested[0] if nested else {}
        summary = _safe_text(first.get("claim_summary") or item.get("next_action") or item.get("next_command"), max_chars=500)
        if not summary:
            continue
        family = _safe_text(item.get("source_family") or item.get("judgment_family") or "provider", max_chars=80)
        ident = _safe_text(item.get("source_collection_id") or item.get("terminal_judgment_id") or item.get("fingerprint"), max_chars=100)
        attack_class = _infer_attack_class(family, summary)
        mode = _scope_mode_from_text(item, summary)
        refs = [_redact_path(path, workspace), ident]
        for row in nested[:4]:
            refs.extend(row.get(k) for k in ("result_path", "provider_output_path", "claim_id", "task_id"))
        lesson = {
            "lesson_id": _stable_id("mfhb", ["provider", ident, family, summary]),
            "source_kind": "provider_source_collection",
            "source_candidate_id": ident,
            "title": f"{family}: {summary[:120]}",
            "lesson_statement": summary,
            "lesson_kind": "source_collection_gap",
            "attack_class": attack_class,
            "reuse_score": 0.31,
            "source_refs": _dedupe_refs(refs, workspace),
            "hunter_question": _base_question(attack_class, family, summary),
            "local_verification_cmd": _safe_text(item.get("next_action") or item.get("next_command") or _verification_cmd(summary), max_chars=240),
            "required_human_review": True,
            "advisory_only": True,
            "promotion_allowed": False,
            "source_read_receipts_created": False,
            "proof_boundary": PROOF_BOUNDARY,
            "blockers": ["provider_output_is_secondary", "local_source_verification_required"],
            **_scope_fields(mode),
        }
        lessons.append(lesson)
    return lessons


def _corpus_record_paths() -> list[Path]:
    return _corpus_record_paths_bounded(MAX_CORPUS_RECORDS)


def _corpus_record_paths_bounded(max_records: int) -> list[Path]:
    if max_records <= 0:
        return []
    roots = [
        ROOT / "audit" / "corpus_tags" / "tags" / "solodit_high_backfill_20260521",
        ROOT / "audit" / "corpus_tags" / "tags" / "defimon_blog_incidents",
        ROOT / "audit" / "corpus_tags" / "tags" / "audit_firm_findings_pashov",
        ROOT / "audit" / "corpus_tags" / "tags" / "audit_firm_findings_sb_security",
        ROOT / "audit" / "corpus_tags" / "tags",
    ]
    out: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        patterns = ["record.yaml", "record.yml", "record.json"]
        if root.name in {"solodit_high_backfill_20260521", "tags"}:
            patterns.extend(["*.yaml", "*.yml", "*.json"])
        for pattern in patterns:
            iterator = root.rglob(pattern) if pattern.startswith("record.") else root.glob(pattern)
            for path in iterator:
                resolved = path.resolve()
                if resolved in seen or not path.is_file():
                    continue
                seen.add(resolved)
                out.append(path)
                if len(out) >= max_records:
                    return out
    return out


def _corpus_lesson(
    path: Path,
    workspace: Path,
    profile: dict[str, Any],
    *,
    min_relevance: float,
) -> dict[str, Any] | None:
    row = _read_structured(path)
    if not row:
        return None
    relevance = _corpus_relevance(row, profile)
    if relevance < min_relevance:
        return None
    record_id = _safe_text(row.get("record_id") or row.get("id") or row.get("pattern"), max_chars=180)
    title = _safe_text(
        row.get("title")
        or row.get("target_component")
        or (row.get("record_extensions") or {}).get("title")
        or row.get("source_audit_ref"),
        max_chars=180,
    )
    summary = _safe_text(
        row.get("attacker_action_sequence")
        or (row.get("record_extensions") or {}).get("summary")
        or (row.get("record_extensions") or {}).get("description")
        or row.get("wiki_exploit_scenario")
        or row.get("help"),
        max_chars=650,
    )
    if not (record_id or title or summary):
        return None
    attack_class = str(row.get("attack_class") or "").strip()
    if not attack_class or attack_class in {"unknown-attack", "audit-firm-public-report"}:
        attack_class = _infer_attack_class(row.get("bug_class"), title, summary, row.get("tags"))
    ext = row.get("record_extensions") if isinstance(row.get("record_extensions"), dict) else {}
    if str(row.get("attack_class") or "") == "audit-firm-public-report" and not (ext.get("summary") or row.get("wiki_exploit_scenario")):
        return None
    mode = _scope_mode_from_text(row, title, summary)
    base = 3.0
    try:
        base = float(row.get("record_quality_score") or row.get("quality_score") or base)
    except (TypeError, ValueError):
        pass
    score = (base / 5.0) * _severity_weight(row.get("severity_at_finding") or row.get("severity")) * _tier_weight(row.get("verification_tier") or row.get("record_tier"))
    score += relevance
    if row.get("record_source_url") or row.get("source_url"):
        score += 0.05
    if row.get("target_repo") and row.get("target_repo") != "unknown":
        score += 0.05
    score = round(max(0.01, min(score, 0.98)), 4)
    refs = [
        record_id,
        row.get("record_source_url") or row.get("source_url"),
        row.get("source_audit_ref"),
        "repo:" + path.resolve().relative_to(ROOT.resolve()).as_posix(),
        *(row.get("related_records") or []),
    ]
    lesson = {
        "lesson_id": _stable_id("mfhb", ["corpus", record_id, title, attack_class]),
        "source_kind": "corpus_mined_finding",
        "source_candidate_id": record_id,
        "title": title or record_id,
        "lesson_statement": summary or title,
        "lesson_kind": "public_mined_finding",
        "attack_class": attack_class,
        "reuse_score": score,
        "severity_at_finding": row.get("severity_at_finding") or row.get("severity") or "",
        "verification_tier": row.get("verification_tier") or row.get("record_tier") or "",
        "target_language": row.get("target_language") or row.get("language") or "",
        "target_domain": row.get("target_domain") or row.get("platform") or "",
        "source_refs": _dedupe_refs(refs, workspace),
        "hunter_question": _base_question(attack_class, title or record_id, summary or title),
        "local_verification_cmd": _verification_cmd(title, summary, attack_class),
        "required_human_review": True,
        "advisory_only": True,
        "promotion_allowed": False,
        "source_read_receipts_created": False,
        "proof_boundary": PROOF_BOUNDARY,
        "blockers": ["target_source_match_required", "scope_appropriate_verification_required"],
        **_scope_fields(mode),
    }
    return lesson


def _discover_workspace_inputs(auditooor_dir: Path) -> list[Path]:
    paths = [auditooor_dir / "mining_coverage_dashboard.json", auditooor_dir / "agent_artifact_lesson_candidates.json"]
    paths.extend(sorted(auditooor_dir.glob("provider_source_collection_queue*.json")))
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(path)
    return out


def _workspace_lessons(workspace: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    statuses: list[dict[str, Any]] = []
    lessons: list[dict[str, Any]] = []
    for path in _discover_workspace_inputs(workspace / ".auditooor"):
        status: dict[str, Any] = {"path": _redact_path(path, workspace), "status": "missing"}
        payload = _read_json(path)
        if payload is None:
            statuses.append(status)
            continue
        status["status"] = "loaded"
        status["schema"] = str(payload.get("schema") or payload.get("schema_version") or "")
        if path.name == "mining_coverage_dashboard.json":
            extracted = _mining_dashboard_lessons(payload, path, workspace)
        elif path.name == "agent_artifact_lesson_candidates.json":
            extracted = _candidate_lessons(payload, path, workspace)
        else:
            extracted = _provider_lessons(payload, path, workspace)
        status["lessons_extracted"] = len(extracted)
        statuses.append(status)
        lessons.extend(extracted)
    return lessons, statuses


def _corpus_lessons(
    workspace: Path,
    max_records: int,
    profile: dict[str, Any],
    *,
    min_relevance: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not profile.get("has_target_signals"):
        return [], {
            "records_considered": 0,
            "lessons_extracted": 0,
            "max_records": max_records,
            "skipped_reason": "no_target_profile_signals",
            "min_relevance": min_relevance,
        }
    if max_records <= 0:
        return [], {
            "records_considered": 0,
            "lessons_extracted": 0,
            "max_records": max_records,
            "skipped_reason": "max_records_zero",
            "min_relevance": min_relevance,
        }
    lessons: list[dict[str, Any]] = []
    considered = 0
    for path in _corpus_record_paths_bounded(max_records):
        considered += 1
        lesson = _corpus_lesson(path, workspace, profile, min_relevance=min_relevance)
        if lesson:
            lessons.append(lesson)
    return lessons, {
        "records_considered": considered,
        "lessons_extracted": len(lessons),
        "max_records": max_records,
        "min_relevance": min_relevance,
    }


def _dedupe_rank(lessons: Iterable[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for lesson in lessons:
        key = _stable_json([lesson.get("attack_class"), str(lesson.get("title") or "").lower(), str(lesson.get("lesson_statement") or "")[:240].lower()])
        existing = by_key.get(key)
        if existing is None or float(lesson.get("reuse_score") or 0) > float(existing.get("reuse_score") or 0):
            by_key[key] = dict(lesson)
            existing = by_key[key]
        refs = list(existing.get("source_refs") or [])
        refs.extend(lesson.get("source_refs") or [])
        existing["source_refs"] = list(dict.fromkeys(str(ref) for ref in refs if ref))[:10]
    ranked = sorted(by_key.values(), key=lambda row: (-float(row.get("reuse_score") or 0), str(row.get("source_kind") or ""), str(row.get("lesson_id") or "")))
    for idx, row in enumerate(ranked[:limit], start=1):
        row["rank"] = idx
    return ranked[:limit]


def _load_obligation_tool() -> Any | None:
    path = TOOLS_DIR / "hacker-question-obligations.py"
    try:
        spec = importlib.util.spec_from_file_location("_mfhb_hq_obligations", str(path))
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules["_mfhb_hq_obligations"] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def _fallback_obligation(workspace: Path, lesson: dict[str, Any], bridge_file: str, now: str, context_pack_id: str) -> dict[str, Any]:
    file_path = bridge_file
    signature = str(lesson.get("lesson_id") or "")
    question = str(lesson.get("hunter_question") or "")
    oid = hashlib.sha256(json.dumps([str(workspace), file_path, signature, question], sort_keys=True).encode()).hexdigest()[:12]
    row = {
        "schema": OBLIGATION_SCHEMA,
        "obligation_id": oid,
        "workspace": str(workspace),
        "file": file_path,
        "function_signature": signature,
        "function_name": "mined_findings_hunter_bridge",
        "attack_class": str(lesson.get("attack_class") or "mined-lesson"),
        "question": question,
        "question_source": "mined-finding",
        "corpus_provenance": str(lesson.get("lesson_id") or ""),
        "state": "open",
        "source_refs": [str(ref) for ref in lesson.get("source_refs") or []][:8],
        "local_verification_cmd": str(lesson.get("local_verification_cmd") or ""),
        "operator_notes": "Generated by mined-findings-hunter-bridge; answer or kill before reusing the lesson.",
        "proof_gate": "scope_appropriate_mined_lesson_verification",
        "claim_boundary": PROOF_BOUNDARY,
        "proof_obligation": _proof_obligation(str(lesson.get("scope_evidence_mode") or "unknown")),
        "kill_condition": _kill_condition(),
        "reasoning_axis": "mined_lesson_reuse",
        "rationale": str(lesson.get("lesson_statement") or "")[:500],
        "created_at_utc": now,
        "updated_at_utc": now,
        "context_pack_id": context_pack_id,
    }
    row.update(_scope_fields(str(lesson.get("scope_evidence_mode") or "unknown")))
    row["advisory_only"] = True
    row["promotion_allowed"] = False
    return row


def _obligations(workspace: Path, lessons: Sequence[dict[str, Any]], bridge_file: str, context_pack_id: str) -> tuple[list[dict[str, Any]], str]:
    module = _load_obligation_tool()
    rows: list[dict[str, Any]] = []
    now = _utc_now()
    for lesson in lessons:
        if module is not None and hasattr(module, "make_obligation"):
            row = module.make_obligation(
                workspace=str(workspace),
                file=bridge_file,
                function_signature=str(lesson.get("lesson_id") or ""),
                function_name="mined_findings_hunter_bridge",
                attack_class=str(lesson.get("attack_class") or "mined-lesson"),
                question=str(lesson.get("hunter_question") or ""),
                question_source="mined-finding",
                corpus_provenance=str(lesson.get("lesson_id") or ""),
                source_refs=[str(ref) for ref in lesson.get("source_refs") or []][:8],
                local_verification_cmd=str(lesson.get("local_verification_cmd") or ""),
                operator_notes="Generated by mined-findings-hunter-bridge; answer or kill before reusing the lesson.",
                context_pack_id=context_pack_id,
                proof_gate="scope_appropriate_mined_lesson_verification",
                claim_boundary=PROOF_BOUNDARY,
                proof_obligation=_proof_obligation(str(lesson.get("scope_evidence_mode") or "unknown")),
                kill_condition=_kill_condition(),
                reasoning_axis="mined_lesson_reuse",
                rationale=str(lesson.get("lesson_statement") or "")[:500],
                state="open",
            )
            row.update(_scope_fields(str(lesson.get("scope_evidence_mode") or "unknown")))
            row["advisory_only"] = True
            row["promotion_allowed"] = False
        else:
            row = _fallback_obligation(workspace, lesson, bridge_file, now, context_pack_id)
        rows.append(row)
        row.update(
            {
                "rank": lesson.get("rank"),
                "reuse_score": lesson.get("reuse_score"),
                "source_kind": lesson.get("source_kind"),
                "source_obligation_id": lesson.get("source_obligation_id", ""),
                "source_candidate_id": lesson.get("source_candidate_id", ""),
                "lesson_kind": lesson.get("lesson_kind"),
                "network_access": "not_required",
                "source_ref_boundary": "source refs are reference only; local scope-appropriate verification is still required",
                "fail_closed": True,
            }
        )
    return rows, "tool_make_obligation" if module is not None else "fallback_schema_match"


def _append_obligations(workspace: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    module = _load_obligation_tool()
    if module is not None and hasattr(module, "append_obligations"):
        try:
            return {"mode": "tool_append_obligations", **module.append_obligations(workspace, rows)}
        except Exception as exc:
            return {"mode": "tool_append_failed", "appended": 0, "skipped_duplicate": 0, "error": str(exc)}
    path = workspace / ".auditooor" / "hacker_question_obligations.jsonl"
    existing: list[dict[str, Any]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    existing.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    ids = {str(row.get("obligation_id") or "") for row in existing}
    new_rows = [row for row in rows if str(row.get("obligation_id") or "") not in ids]
    if new_rows:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in [*existing, *new_rows]), encoding="utf-8")
    return {"mode": "fallback_append", "appended": len(new_rows), "skipped_duplicate": len(rows) - len(new_rows)}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _redacted_payload(payload: dict[str, Any], workspace: Path) -> dict[str, Any]:
    text = json.dumps(payload, sort_keys=True)
    text = _redact_text(text, workspace)
    return json.loads(text)


def build_bridge(
    workspace: Path,
    output_dir: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    max_corpus_records: int = MAX_CORPUS_RECORDS,
    min_corpus_relevance: float = DEFAULT_MIN_CORPUS_RELEVANCE,
    generated_at: str | None = None,
) -> dict[str, Any]:
    ws = workspace.expanduser().resolve()
    out_dir = output_dir.expanduser().resolve()
    bounded_limit = max(0, min(int(limit), MAX_LIMIT))
    profile = _target_profile(ws)
    workspace_lessons, input_statuses = _workspace_lessons(ws)
    corpus_cap = max(0, min(int(max_corpus_records), MAX_CORPUS_RECORDS))
    corpus_lessons, corpus_status = _corpus_lessons(
        ws,
        corpus_cap,
        profile,
        min_relevance=float(min_corpus_relevance),
    )
    ranked = _dedupe_rank([*workspace_lessons, *corpus_lessons], bounded_limit)
    context_pack_id = _stable_id("mfhb-context", [str(ws), [lesson.get("lesson_id") for lesson in ranked]])
    bridge_path = out_dir / "mined_findings_hunter_bridge.json"
    obligations_path = out_dir / "mined_findings_hunter_obligations.jsonl"
    bridge_file = _redact_path(bridge_path, ws)
    rows, mode = _obligations(ws, ranked, bridge_file, context_pack_id)
    redacted_rows = [_redacted_payload(row, ws) for row in rows]
    append_result = _append_obligations(ws, redacted_rows)
    by_source_kind = Counter(str(row.get("source_kind") or "unknown") for row in ranked)
    by_attack_class = Counter(str(row.get("attack_class") or "unknown") for row in ranked)
    status = "ok" if ranked else "no_mined_finding_questions_fail_closed"
    payload = {
        "schema": SCHEMA,
        "generated_at_utc": generated_at or _utc_now(),
        "workspace": "<workspace>",
        "output_dir": _redact_path(out_dir, ws),
        "status": status,
        "advisory_only": True,
        "fail_closed": True,
        "promotion_authority": False,
        "submit_ready": False,
        "network_access": "not_required",
        "network_used": False,
        "limit": bounded_limit,
        "bounded": len(workspace_lessons) + len(corpus_lessons) > bounded_limit,
        "input_artifacts": input_statuses,
        "corpus_inputs": corpus_status,
        "target_profile": {
            "has_target_signals": profile.get("has_target_signals"),
            "signal_paths": profile.get("signal_paths"),
            "oos_signal_paths": profile.get("oos_signal_paths"),
            "language_hints": profile.get("language_hints"),
            "domain_hints": profile.get("domain_hints"),
        },
        "summary": {
            "workspace_lessons": len(workspace_lessons),
            "corpus_lessons": len(corpus_lessons),
            "lessons_returned": len(ranked),
            "obligations_emitted": len(redacted_rows),
            "obligations_written": len(redacted_rows),
            "by_source_kind": dict(sorted(by_source_kind.items())),
            "by_attack_class": dict(sorted(by_attack_class.items())),
        },
        "ranked_lessons": ranked,
        "local_source_refs": sorted({ref for lesson in ranked for ref in lesson.get("source_refs", []) if str(ref).startswith("<workspace>/")})[:20],
        "bridge_artifact": _redact_path(bridge_path, ws),
        "obligations_artifact": _redact_path(obligations_path, ws),
        "canonical_obligations_path": "<workspace>/.auditooor/hacker_question_obligations.jsonl",
        "canonical_obligation_build_mode": mode,
        "canonical_append": append_result,
        "source_read_receipts_created": False,
        "source_read_receipt_policy": NO_FAKE_RECEIPTS,
        "scope_evidence_policy": SCOPE_POLICY,
        "proof_boundary": PROOF_BOUNDARY,
        "blocked_reasons": [] if ranked else ["no mined finding questions could be derived from local artifacts or corpus records"],
        "next_action": (
            "Answer or kill the appended obligations against the evidence surface declared by program scope. "
            "Run make hacker-question-workflow-audit and make exploit-queue after this bridge."
        ),
    }
    _write_jsonl(obligations_path, redacted_rows)
    _write_json(bridge_path, _redacted_payload(payload, ws))
    return _redacted_payload(payload, ws)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--max-corpus-records", type=int, default=MAX_CORPUS_RECORDS)
    parser.add_argument("--min-corpus-relevance", type=float, default=DEFAULT_MIN_CORPUS_RELEVANCE)
    parser.add_argument("--generated-at", default=None, help="Deterministic timestamp override for tests.")
    parser.add_argument("--json", "--print-json", dest="json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 2
    output_dir = args.output_dir.expanduser().resolve() if args.output_dir else workspace / ".auditooor"
    payload = build_bridge(
        workspace,
        output_dir,
        limit=args.limit,
        max_corpus_records=args.max_corpus_records,
        min_corpus_relevance=args.min_corpus_relevance,
        generated_at=args.generated_at,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "mined-findings-hunter-bridge: "
            f"{summary['lessons_returned']} lessons, {summary['obligations_written']} obligations, "
            f"status={payload['status']}"
        )
        print(f"  bridge      -> {payload['bridge_artifact']}")
        print(f"  obligations -> {payload['obligations_artifact']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
