#!/usr/bin/env python3
"""Rule 58 invariant-grounded finding preflight.

High/Critical finding drafts and proof packets must cite an indexed ``INV-*``
invariant or carry a bounded no-invariant-binding justification. Medium drafts
for an attack class already covered by the invariant library must cite an
indexed ``INV-*`` invariant, or carry the same bounded justification.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 58 violation
  2 - input/corpus error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r58_invariant_grounded_finding.v1"
GATE = "R58-INVARIANT-GROUNDED-FINDING"
TOOL_REL_PATH = "tools/invariant-grounded-finding-check.py"

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json"
DEFAULT_PILOT_AUDITED = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"
DEFAULT_PILOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"
DEFAULT_EXTRACTED = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_MAX_DISCOVERED_SIDECARS = 16
DEFAULT_DISCOVERY_READ_LIMIT_BYTES = 1024 * 1024

INV_ID_RE = re.compile(r"\bINV-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
REBUTTAL_RE = re.compile(
    r"<!--\s*(?:r58-rebuttal|r58-no-invariant-binding|no-invariant-binding)\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:"
    r"r58[-_ ]rebuttal|"
    r"r58[-_ ]no[-_ ]invariant[-_ ]binding|"
    r"no[-_ ]invariant[-_ ]binding|"
    r"no\s+invariant\s+binding|"
    r"no_invariant_binding_justification"
    r")\s*[:=]\s*[\"'`]?(.*?)[\"'`]?\s*,?\s*$"
)

ATTACK_CLASS_PATTERNS = [
    re.compile(r"(?im)^\s*[\"']attack_class[\"']\s*:\s*[\"']?([A-Za-z0-9_\-/.]+)[\"']?\s*,?\s*$"),
    re.compile(r"(?im)^\s*attack_class\s*:\s*[\"']?([A-Za-z0-9_\-/.]+)[\"']?\s*$"),
    re.compile(r"(?im)^\s*\**\s*Attack[ _]Class\s*:\**\s*[\"']?([A-Za-z0-9_\-/.]+)"),
    re.compile(r"(?im)\battack_class\s*=\s*[\"']?([A-Za-z0-9_\-/.]+)"),
]

CLAIM_RE = re.compile(
    r"\binvariant\b|\bmust not\b|\bmust be\b|\buniqueness\b|\bmonotonicity\b|"
    r"\bconservation\b|\batomicity\b|\bfreshness\b|\bcustody\b|\bbounds?\b|"
    r"\bauthorization\b|\bordering\b|\bdeterminism\b",
    re.IGNORECASE,
)

STOPWORDS = {
    "class",
    "attack",
    "finding",
    "issue",
    "bug",
    "missing",
    "without",
    "with",
    "from",
    "into",
    "that",
    "this",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _first_title(text: str) -> str | None:
    for line in text.splitlines():
        match = re.match(r"^\s*#\s+(.+?)\s*$", line)
        if match:
            return " ".join(match.group(1).split())
    return None


def _identity_tokens(draft: Path, workspace: Path | None, text: str) -> list[str]:
    tokens: list[str] = []

    def add(value: str | None) -> None:
        if not value:
            return
        value = str(value).strip()
        if value and value not in tokens:
            tokens.append(value)

    try:
        resolved = draft.resolve()
        add(str(resolved))
    except Exception:
        resolved = draft
        add(str(draft))

    if workspace is not None:
        try:
            add(str(resolved.relative_to(workspace.resolve())))
        except Exception:
            pass

    generic_stems = {"source-draft", "draft", "finding", "submission"}
    if draft.stem.lower() not in generic_stems:
        add(draft.name)
        add(draft.stem)
    if draft.parent.name and draft.parent.name.lower() not in {"ready", "staging", "packaged", "filed", "submitted"}:
        add(draft.parent.name)
    add(_first_title(text))
    return tokens


def _read_bounded(path: Path, limit_bytes: int = DEFAULT_DISCOVERY_READ_LIMIT_BYTES) -> tuple[str, bool]:
    with path.open("rb") as fh:
        data = fh.read(limit_bytes + 1)
    truncated = len(data) > limit_bytes
    return data[:limit_bytes].decode("utf-8", errors="replace"), truncated


def discover_relevant_proof_packet_sidecars(
    draft: Path,
    *,
    workspace: Path | None,
    max_candidates: int = DEFAULT_MAX_DISCOVERED_SIDECARS,
    read_limit_bytes: int = DEFAULT_DISCOVERY_READ_LIMIT_BYTES,
) -> tuple[list[Path], dict[str, Any]]:
    """Find bounded, draft-relevant proof-packet sidecars.

    This intentionally inspects only immediate files in ``<workspace>/.auditooor``.
    It never walks submissions or recursively scans the workspace, preserving L34
    draft ownership while still catching proof-packet sidecars colocated with the
    audit control artifacts.
    """
    meta: dict[str, Any] = {
        "enabled": True,
        "mode": "bounded-immediate-auditooor-proof-packet-files",
        "searched_dir": None,
        "max_candidates": max_candidates,
        "read_limit_bytes": read_limit_bytes,
        "candidates_considered": 0,
        "matched_count": 0,
        "skipped": [],
    }
    if workspace is None:
        meta["skipped"].append({"reason": "workspace-not-provided"})
        return [], meta

    try:
        ws = workspace.expanduser().resolve()
    except Exception as exc:
        meta["skipped"].append({"reason": f"workspace-resolve-failed: {exc}"})
        return [], meta
    auditooor_dir = ws / ".auditooor"
    meta["searched_dir"] = str(auditooor_dir)
    if not auditooor_dir.is_dir():
        meta["skipped"].append({"reason": "auditooor-dir-missing", "path": str(auditooor_dir)})
        return [], meta

    try:
        draft_text = _read_text(draft)
    except Exception:
        draft_text = ""
    identities = _identity_tokens(draft, ws, draft_text)
    meta["identity_tokens"] = identities[:12]

    candidates: list[Path] = []
    for path in sorted(auditooor_dir.iterdir()):
        if len(candidates) >= max_candidates:
            meta["skipped"].append({"reason": "candidate-limit-reached", "limit": max_candidates})
            break
        if not path.is_file():
            continue
        name = path.name.lower()
        if "proof" not in name or "packet" not in name:
            continue
        if not _is_relative_to(path, auditooor_dir):
            meta["skipped"].append({"reason": "outside-auditooor-dir", "path": str(path)})
            continue
        candidates.append(path)

    matched: list[Path] = []
    for path in candidates:
        meta["candidates_considered"] += 1
        try:
            body, truncated = _read_bounded(path, read_limit_bytes)
        except Exception as exc:
            meta["skipped"].append({"reason": f"read-failed: {exc}", "path": str(path)})
            continue

        filename_hit = any(token and token.lower() in path.name.lower() for token in identities)
        content_hit = any(token and token in body for token in identities)
        if filename_hit or content_hit:
            matched.append(path)
            if truncated:
                meta["skipped"].append({"reason": "matched-file-read-truncated", "path": str(path)})
        else:
            meta["skipped"].append({"reason": "not-draft-relevant", "path": str(path)})

    meta["matched_count"] = len(matched)
    meta["matched_paths"] = [str(path) for path in matched]
    return matched, meta


def _severity_from_text(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    patterns = [
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*[\"'`*]*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*[-*]?\s*Severity claim\s*:\s*[\"'`*]*(Critical|High|Medium|Low)\b", "proof-packet-severity"),
        (r"(?im)^\s*[\"']severity_claim[\"']\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "proof-packet-severity"),
        (r"(?im)^\s*[\"']?severity_implied[\"']?\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "program-impact-mapping"),
        (r"(?im)^\s*[\"']?severity_tier[\"']?\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "impact-contract"),
        (r"(?im)^\s*[\"']?selected_severity[\"']?\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "selected-severity"),
    ]
    for pattern, source in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _extract_attack_class(text: str) -> str | None:
    for pattern in ATTACK_CLASS_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).strip().lower()
    return None


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        match = REBUTTAL_LINE_RE.search(text)
    if not match:
        return None
    value = " ".join(match.group(1).split())
    if not value or value.lower() in {"<reason>", "reason", "tbd", "todo", "n/a", "na", "none"}:
        return None
    return value


def _visible_text(text: str) -> str:
    return HTML_COMMENT_RE.sub("", text)


def _normalize(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in _normalize(value).split("-")
        if token and (len(token) >= 4 or token in {"dos", "zk"}) and token not in STOPWORDS
    }


def _matches_class(attack_class: str, haystack: str) -> bool:
    class_norm = _normalize(attack_class)
    hay_norm = _normalize(haystack)
    if not class_norm or not hay_norm:
        return False
    if class_norm in hay_norm or hay_norm in class_norm:
        return True
    class_tokens = _tokens(attack_class)
    if not class_tokens:
        return False
    hay_tokens = _tokens(haystack)
    if len(class_tokens) == 1:
        only = next(iter(class_tokens))
        return only in hay_tokens or only in hay_norm
    return class_tokens.issubset(hay_tokens)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _iter_record_haystacks(row: dict[str, Any]) -> list[str]:
    haystacks: list[str] = []
    for key in ("attack_signature", "category", "statement", "commit_point_pattern", "defense_layer"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            haystacks.extend(part.strip() for part in value.split("|") if part.strip())
    source_ids = row.get("source_finding_ids")
    if isinstance(source_ids, list):
        haystacks.extend(str(item) for item in source_ids if isinstance(item, str))
    return haystacks


def _load_corpus(
    *,
    index_path: Path,
    pilot_audited_path: Path,
    pilot_path: Path,
    extracted_path: Path,
) -> tuple[set[str], set[str], list[dict[str, Any]], dict[str, list[str]], list[str]]:
    known_ids: set[str] = set()
    audited_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    source_to_ids: dict[str, list[str]] = {}
    source_refs: list[str] = []

    if index_path.exists():
        data = json.loads(_read_text(index_path))
        reverse = data.get("reverse_lookup_finding_to_invariant")
        if not isinstance(reverse, dict):
            raise ValueError(f"{index_path}: missing reverse_lookup_finding_to_invariant")
        for source, ids in reverse.items():
            if not isinstance(ids, list):
                continue
            clean_ids = sorted({str(item).strip() for item in ids if str(item).strip()})
            if clean_ids:
                source_to_ids[str(source)] = clean_ids
                known_ids.update(clean_ids)
        source_refs.append(str(index_path))

    def _quality_passed(row: dict[str, Any]) -> bool:
        quality_audited = row.get("quality_audited")
        if isinstance(quality_audited, bool) and not quality_audited:
            return False
        if isinstance(quality_audited, str):
            qa_norm = quality_audited.strip().lower()
            if qa_norm in {"0", "false", "no"}:
                return False
        verdict = str(row.get("audit_verdict") or "").strip().lower()
        if verdict.startswith("false-positive") or verdict in {
            "false-positive",
            "drop",
            "reject",
            "rejected",
            "quarantine",
        }:
            return False
        return True

    for path in (pilot_audited_path, pilot_path, extracted_path):
        rows = _load_jsonl(path)
        if rows:
            source_refs.append(str(path))
        for row in rows:
            inv_id = str(row.get("invariant_id") or "").strip()
            if not inv_id:
                continue
            if path == pilot_audited_path and not _quality_passed(row):
                continue
            known_ids.add(inv_id)
            if path == pilot_audited_path:
                audited_ids.add(inv_id)
            records.append(row)
            for source in row.get("source_finding_ids") or []:
                if isinstance(source, str) and source.strip():
                    source_to_ids.setdefault(source, [])
                    if inv_id not in source_to_ids[source]:
                        source_to_ids[source].append(inv_id)

    if not known_ids:
        raise ValueError("no invariant IDs loaded from index or JSONL corpus")
    return known_ids, audited_ids, records, source_to_ids, source_refs


def _known_invariants_for_class(
    attack_class: str,
    *,
    records: list[dict[str, Any]],
    source_to_ids: dict[str, list[str]],
    limit: int = 24,
) -> tuple[list[str], list[str]]:
    matched_ids: set[str] = set()
    matched_haystacks: list[str] = []

    for source, inv_ids in source_to_ids.items():
        if _matches_class(attack_class, source):
            matched_ids.update(inv_ids)
            if len(matched_haystacks) < limit:
                matched_haystacks.append(source)

    for row in records:
        inv_id = str(row.get("invariant_id") or "").strip()
        if not inv_id:
            continue
        for haystack in _iter_record_haystacks(row):
            if _matches_class(attack_class, haystack):
                matched_ids.add(inv_id)
                if len(matched_haystacks) < limit:
                    matched_haystacks.append(haystack)
                break

    return sorted(matched_ids), matched_haystacks


def _line_hits(text: str, pattern: re.Pattern[str], *, limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append({"line": line_no, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    index_path: Path = DEFAULT_INDEX,
    pilot_audited_path: Path = DEFAULT_PILOT_AUDITED,
    pilot_path: Path = DEFAULT_PILOT,
    extracted_path: Path = DEFAULT_EXTRACTED,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL_REL_PATH,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity_from_text(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "file": str(draft),
        "severity_observed": severity,
        "severity_source": severity_source,
        "strict": strict,
        "rebuttal": None,
        "evidence": {},
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below MEDIUM or missing"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload
    if rebuttal:
        payload["rebuttal_oversize"] = True
        payload["rebuttal_observed_length"] = len(rebuttal)

    try:
        known_ids, audited_ids, records, source_to_ids, source_refs = _load_corpus(
            index_path=index_path,
            pilot_audited_path=pilot_audited_path,
            pilot_path=pilot_path,
            extracted_path=extracted_path,
        )
    except Exception as exc:
        payload["verdict"] = "error"
        payload["reason"] = f"invariant corpus load failed: {exc}"
        payload["corpus_paths"] = {
            "index": str(index_path),
            "pilot_audited_jsonl": str(pilot_audited_path),
            "pilot_jsonl": str(pilot_path),
            "extracted_jsonl": str(extracted_path),
        }
        return 2, payload

    visible = _visible_text(text)
    cited_ids = sorted(set(INV_ID_RE.findall(visible)))
    unknown_cited = [inv_id for inv_id in cited_ids if inv_id not in known_ids]
    attack_class = _extract_attack_class(visible)
    known_for_class: list[str] = []
    matched_haystacks: list[str] = []
    if attack_class:
        known_for_class, matched_haystacks = _known_invariants_for_class(
            attack_class,
            records=records,
            source_to_ids=source_to_ids,
        )

    payload["attack_class_observed"] = attack_class
    payload["cited_invariant_ids"] = cited_ids
    payload["unknown_cited_invariant_ids"] = unknown_cited
    payload["cited_audited_invariant_ids"] = sorted(
        inv_id for inv_id in cited_ids if inv_id in audited_ids
    )
    payload["cited_unaudited_invariant_ids"] = sorted(
        inv_id for inv_id in cited_ids if inv_id in known_ids and inv_id not in audited_ids
    )
    payload["audited_known_invariant_count"] = len(audited_ids)
    payload["known_invariant_count"] = len(known_ids)
    payload["source_refs"] = source_refs
    payload["evidence"] = {
        "invariant_claim_hits": _line_hits(visible, CLAIM_RE),
        "class_matched_invariant_ids": known_for_class[:24],
        "class_match_evidence": matched_haystacks[:12],
    }

    if unknown_cited:
        payload["verdict"] = "fail-invariant-cited-but-not-indexed"
        payload["reason"] = "draft cites invariant ID(s) absent from the invariant library index/JSONL corpus"
        payload["remediation"] = [
            "Replace the citation with an indexed INV-* ID from audit/corpus_tags/derived/invariant_library_index.json or invariants JSONL.",
            "If the invariant is intentionally new, add <!-- r58-rebuttal: <reason> --> (<=200 chars).",
        ]
        return 1, payload

    if cited_ids:
        payload["verdict"] = "pass-invariant-cited-and-indexed"
        payload["reason"] = "all cited invariant IDs are present in the invariant library"
        return 0, payload

    if attack_class and known_for_class:
        payload["verdict"] = "fail-no-invariant-cited-but-class-has-known-invariant"
        payload["reason"] = f"attack_class {attack_class!r} maps to indexed invariant(s) but draft cites none"
        payload["remediation"] = [
            "Cite the relevant indexed INV-* ID in the draft's invariant or proof section.",
            "Use <!-- r58-no-invariant-binding: <source-backed reason> --> only for a bounded exception.",
        ]
        return 1, payload

    if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]:
        payload["verdict"] = "fail-no-invariant-cited-or-binding-justification"
        payload["reason"] = (
            "HIGH/CRITICAL finding draft or proof packet cites no indexed invariant "
            "and has no bounded no-invariant-binding justification"
        )
        payload["remediation"] = [
            "Cite the relevant indexed INV-* ID in the draft/proof packet.",
            "If no invariant binds, add <!-- r58-no-invariant-binding: <source-backed reason> --> (<=200 chars).",
        ]
        return 1, payload

    payload["verdict"] = "pass-out-of-scope"
    payload["reason"] = "no indexed invariant citation needed for this draft/class"
    return 0, payload


def run_with_discovery(
    draft: Path,
    *,
    workspace: Path | None,
    severity_override: str | None = None,
    index_path: Path = DEFAULT_INDEX,
    pilot_audited_path: Path = DEFAULT_PILOT_AUDITED,
    pilot_path: Path = DEFAULT_PILOT,
    extracted_path: Path = DEFAULT_EXTRACTED,
    strict: bool = False,
    max_discovered_sidecars: int = DEFAULT_MAX_DISCOVERED_SIDECARS,
) -> tuple[int, dict[str, Any]]:
    primary_rc, primary = run(
        draft,
        severity_override=severity_override,
        index_path=index_path,
        pilot_audited_path=pilot_audited_path,
        pilot_path=pilot_path,
        extracted_path=extracted_path,
        strict=strict,
    )
    sidecar_paths, discovery = discover_relevant_proof_packet_sidecars(
        draft,
        workspace=workspace,
        max_candidates=max_discovered_sidecars,
    )

    results: list[dict[str, Any]] = [
        {
            "kind": "primary",
            "path": str(draft),
            "rc": primary_rc,
            "verdict": primary.get("verdict"),
            "reason": primary.get("reason"),
            "payload": primary,
        }
    ]
    aggregate_rc = primary_rc
    for sidecar_path in sidecar_paths:
        rc, payload = run(
            sidecar_path,
            severity_override=severity_override,
            index_path=index_path,
            pilot_audited_path=pilot_audited_path,
            pilot_path=pilot_path,
            extracted_path=extracted_path,
            strict=strict,
        )
        results.append(
            {
                "kind": "discovered-proof-packet-sidecar",
                "path": str(sidecar_path),
                "rc": rc,
                "verdict": payload.get("verdict"),
                "reason": payload.get("reason"),
                "payload": payload,
            }
        )
        if rc == 1:
            aggregate_rc = 1
        elif rc == 2 and aggregate_rc == 0:
            aggregate_rc = 2

    failing = [row for row in results if row["rc"] == 1]
    errors = [row for row in results if row["rc"] == 2]
    if failing:
        verdict = "fail-batch"
        reason = f"{len(failing)} R58 artifact(s) failed across primary draft and discovered proof-packet sidecars"
    elif errors:
        verdict = "error"
        reason = f"{len(errors)} R58 artifact(s) returned input/corpus errors"
    elif sidecar_paths:
        verdict = "pass-batch"
        reason = f"primary draft and {len(sidecar_paths)} discovered proof-packet sidecar(s) passed"
    else:
        verdict = primary.get("verdict", "pass-batch")
        reason = f"primary draft checked; no relevant proof-packet sidecars discovered ({primary.get('reason', 'no detail')})"

    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "file": str(draft),
        "workspace": str(workspace) if workspace is not None else None,
        "verdict": verdict,
        "reason": reason,
        "strict": strict,
        "discovery": discovery,
        "primary": primary,
        "results": results,
    }
    return aggregate_rc, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low", "auto"])
    parser.add_argument("--workspace", type=Path, help="Accepted for pre-submit parity; corpus paths remain explicit/defaulted.")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--pilot-audited-jsonl", type=Path, default=DEFAULT_PILOT_AUDITED)
    parser.add_argument("--pilot-jsonl", type=Path, default=DEFAULT_PILOT)
    parser.add_argument("--extracted-jsonl", type=Path, default=DEFAULT_EXTRACTED)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--discover-sidecars",
        action="store_true",
        help="Also check draft-relevant immediate <workspace>/.auditooor/*proof*packet* sidecars.",
    )
    parser.add_argument("--max-discovered-sidecars", type=int, default=DEFAULT_MAX_DISCOVERED_SIDECARS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    severity_override = None if args.severity in (None, "auto") else args.severity
    if args.discover_sidecars:
        rc, payload = run_with_discovery(
            args.draft,
            workspace=args.workspace,
            severity_override=severity_override,
            index_path=args.index,
            pilot_audited_path=args.pilot_audited_jsonl,
            pilot_path=args.pilot_jsonl,
            extracted_path=args.extracted_jsonl,
            strict=args.strict,
            max_discovered_sidecars=max(0, args.max_discovered_sidecars),
        )
    else:
        rc, payload = run(
            args.draft,
            severity_override=severity_override,
            index_path=args.index,
            pilot_audited_path=args.pilot_audited_jsonl,
            pilot_path=args.pilot_jsonl,
            extracted_path=args.extracted_jsonl,
            strict=args.strict,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
