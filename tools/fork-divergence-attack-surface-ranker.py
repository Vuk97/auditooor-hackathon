#!/usr/bin/env python3
"""fork-divergence-attack-surface-ranker.

Compose fork-ancestry/prober output into prioritized attack-surface rows.

Inputs are JSON documents from:
  - tools/gomod-fork-ancestry-check.py --json
  - tools/cargo-fork-ancestry-check.py --json
  - tools/fork-divergence-prober.py --json
  - a manifest with rows/items/dependencies/packages/modules

The ranker is advisory only. It does not prove exploitability or make a
finding; it orders local follow-up work and emits the next command to run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA = "auditooor.fork_divergence_attack_surface_ranker.v1"
TOOL_NAME = "fork-divergence-attack-surface-ranker"
SCORING_MODEL_VERSION = "fdasr-2026-05-24"

MANIFEST_KEYS = ("rows", "items", "dependencies", "packages", "modules")

SURFACE_SIGNALS: tuple[tuple[str, int, str, str], ...] = (
    (
        r"\b(consensus|validator|blocksync|vote[-_ ]?extension|mempool|abci|cometbft)\b",
        25,
        "consensus/validator safety",
        "Consensus or validator surface: prove fork/upstream behavioral divergence can cause halt, split, or invalid acceptance.",
    ),
    (
        r"\b(bridge|ibc|light[-_ ]?client|merkle|proof|cross[-_ ]?chain|packet)\b",
        23,
        "bridge/proof boundary",
        "Bridge or proof boundary: test invalid proof/state acceptance across the fork and upstream.",
    ),
    (
        r"\b(signature|signer|auth|access|permission|role|governance|upgrade|owner)\b",
        20,
        "auth/signature boundary",
        "Authentication or signature surface: test replay, identity binding, and privilege-boundary drift.",
    ),
    (
        r"\b(oracle|price|liquidat|collateral|borrow|debt|solvency|margin)\b",
        18,
        "economic/oracle boundary",
        "Economic or oracle surface: quantify whether stale or divergent state changes liquidation, collateral, or solvency outcomes.",
    ),
    (
        r"\b(withdraw|deposit|transfer|vault|accounting|reward|claim|balance|asset)\b",
        16,
        "fund/accounting boundary",
        "Fund or accounting surface: prove user-controlled flow reaches loss, freeze, or incorrect balance movement.",
    ),
    (
        r"\b(panic|crash|halt|dos|denial|oom|nil|bounds?|overflow|underflow)\b",
        14,
        "availability/bounds boundary",
        "Availability wording needs a production, user-triggerable halt or denial path; local panic alone is not enough.",
    ),
    (
        r"\b(validat|verify|sanitize|replay|encode|decode|parse|invariant|check)\b",
        12,
        "validation/parsing boundary",
        "Validation or parsing drift: build a differential case that upstream rejects and the fork accepts.",
    ),
)

SECURITY_SIGNAL_RE = re.compile(
    r"\b(fix|verif|valid|harden|security|panic|consens|halt|crash|nil|"
    r"overflow|underflow|reentran|access|auth|signature|replay|exploit|"
    r"advisory|ghsa|cve|backport|cherry-pick|vuln|dos|denial|unsound|race)\b",
    re.IGNORECASE,
)
LOW_VALUE_RE = re.compile(r"\b(test|tests|fixture|fixtures|mock|mocks|doc|docs|readme|example)\b", re.IGNORECASE)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def _compact(parts: Iterable[Any], *, limit: int = 8) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        text = _text(part).strip()
        if not text:
            continue
        if len(text) > 240:
            text = text[:237].rstrip() + "..."
        if text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _norm_repo(value: Any) -> str:
    text = _text(value).strip()
    if not text:
        return ""
    text = re.sub(r"^git\+", "", text)
    text = re.sub(r"^https?://", "", text)
    text = text.rstrip("/")
    text = re.sub(r"\.git$", "", text)
    return text


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug[:80] or "fork"


def _first(row: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", []):
            return row[key]
    return None


def _source_schema(doc: Any) -> str:
    if isinstance(doc, dict):
        return _text(doc.get("schema") or "unknown")
    return "list"


def load_input(token: str, ordinal: int) -> dict[str, Any]:
    """Load one JSON input token.

    A token can be a path, '-' for stdin, or an inline JSON object/list.
    """
    raw = token.strip()
    if raw == "-":
        return {"label": "<stdin>", "doc": json.loads(sys.stdin.read())}
    if raw.startswith("{") or raw.startswith("["):
        return {"label": f"<inline:{ordinal}>", "doc": json.loads(raw)}

    path = Path(token)
    if not path.is_file():
        raise FileNotFoundError(f"input JSON not found: {token}")
    return {"label": str(path), "doc": json.loads(path.read_text(encoding="utf-8"))}


def _iter_manifest_rows(doc: Any) -> Iterable[dict[str, Any]]:
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(doc, dict):
        return
    for key in MANIFEST_KEYS:
        value = doc.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item
            return
        if isinstance(value, dict):
            for name, item in value.items():
                if isinstance(item, dict):
                    merged = dict(item)
                    merged.setdefault("module", name)
                    yield merged
            return


def _candidate_commit_parts(commits: Any) -> list[str]:
    parts: list[str] = []
    for commit in _as_list(commits):
        if isinstance(commit, dict):
            sha = commit.get("commit_sha") or commit.get("sha")
            tag = commit.get("tag") or commit.get("version")
            subject = commit.get("subject") or commit.get("summary") or commit.get("title")
            bits = []
            if sha:
                bits.append(str(sha)[:12])
            if tag:
                bits.append(f"in {tag}")
            if subject:
                bits.append(str(subject))
            if bits:
                parts.append(" ".join(bits))
        else:
            parts.append(_text(commit))
    return parts


def normalize_gomod_row(row: dict[str, Any], source_label: str, schema: str, index: int) -> dict[str, Any]:
    replace = row.get("replace") if isinstance(row.get("replace"), dict) else {}
    module = row.get("module") or row.get("name") or replace.get("from")
    fork_repo = row.get("fork_repo") or row.get("repo") or row.get("fork_url") or replace.get("to")
    pin = row.get("pin_sha") or row.get("fork_sha") or row.get("audit_pin") or replace.get("version")
    missing_tags = row.get("not_in_fork") or row.get("missing_tags") or []
    candidate_commits = row.get("candidate_security_commits") or row.get("candidate_commits") or []

    evidence = _compact(
        [
            f"replace {replace.get('from')} => {replace.get('to')} {replace.get('version')}"
            if replace
            else None,
            f"fork_sha={row.get('fork_sha')}" if row.get("fork_sha") else None,
            f"base_version={row.get('base_version')}" if row.get("base_version") else None,
            f"missing_upstream_tags={', '.join(map(str, missing_tags[:8]))}" if isinstance(missing_tags, list) and missing_tags else None,
            *_candidate_commit_parts(candidate_commits),
            f"error={row.get('error')}" if row.get("error") else None,
        ]
    )
    changed = _compact(
        [
            row.get("changed_surface"),
            row.get("component"),
            row.get("path"),
            *_candidate_commit_parts(candidate_commits),
            *(missing_tags if isinstance(missing_tags, list) else []),
        ],
        limit=6,
    )
    return {
        "raw": row,
        "source": {"input": source_label, "schema": schema, "row_index": index},
        "source_kind": "gomod-ancestry",
        "ecosystem": row.get("ecosystem") or "go",
        "module_package": _text(module or fork_repo or "<unknown-go-module>"),
        "fork_repo": _norm_repo(fork_repo),
        "pin": _text(pin),
        "upstream_reference": ", ".join(map(str, missing_tags[:3])) if isinstance(missing_tags, list) else "",
        "classification": "candidate-divergence" if missing_tags or candidate_commits else "blocked-needs-input",
        "evidence": evidence,
        "changed_parts": changed,
        "reachability": "unknown",
        "fork_missing_status": "lagging" if missing_tags or candidate_commits else "unknown",
        "candidate_commit_count": len(candidate_commits) if isinstance(candidate_commits, list) else 0,
        "missing_tag_count": len(missing_tags) if isinstance(missing_tags, list) else 0,
    }


def normalize_cargo_row(row: dict[str, Any], source_label: str, schema: str, index: int) -> dict[str, Any]:
    module = row.get("module") or row.get("name") or row.get("package")
    fork_repo = row.get("fork_repo") or row.get("repo") or row.get("git_url")
    divergence = _text(row.get("divergence") or row.get("fork_missing_status") or "unknown")
    pin = row.get("pin_sha") or row.get("lock_sha") or row.get("audit_pin") or row.get("ref")
    candidate_commits = row.get("candidate_security_commits") or row.get("candidate_commits") or []
    evidence = _compact(
        [
            f"git={row.get('git_url')}" if row.get("git_url") else None,
            f"lock_sha={row.get('lock_sha')}" if row.get("lock_sha") else None,
            f"divergence={divergence}",
            f"upstream_latest={row.get('upstream_latest') or row.get('upstream_latest_version')}" if row.get("upstream_latest") or row.get("upstream_latest_version") else None,
            f"upstream_repository={row.get('upstream_repository')}" if row.get("upstream_repository") else None,
            row.get("reason"),
            row.get("audit_pin_lag_note"),
            *_candidate_commit_parts(candidate_commits),
        ]
    )
    return {
        "raw": row,
        "source": {"input": source_label, "schema": schema, "row_index": index},
        "source_kind": "cargo-ancestry",
        "ecosystem": row.get("ecosystem") or "cargo",
        "module_package": _text(module or fork_repo or "<unknown-cargo-package>"),
        "fork_repo": _norm_repo(fork_repo),
        "pin": _text(pin),
        "upstream_reference": _text(row.get("upstream_latest") or row.get("upstream_latest_version") or row.get("upstream_repository")),
        "classification": "candidate-divergence" if divergence not in ("same", "current") else "current-pin",
        "evidence": evidence,
        "changed_parts": _compact([row.get("changed_surface"), row.get("reason"), *_candidate_commit_parts(candidate_commits)], limit=6),
        "reachability": _text(row.get("reachable_in_scope_code_path") or row.get("reachability") or "unknown"),
        "fork_missing_status": "lagging" if divergence in ("behind", "forked", "diverged", "lagging") else divergence,
        "candidate_commit_count": len(candidate_commits) if isinstance(candidate_commits, list) else 0,
        "missing_tag_count": 0,
    }


def normalize_prober_row(row: dict[str, Any], source_label: str, schema: str, index: int) -> dict[str, Any]:
    pin = row.get("pin") if isinstance(row.get("pin"), dict) else {}
    module = pin.get("module") or row.get("module") or row.get("package") or row.get("module_package")
    fork_repo = pin.get("fork_repo") or row.get("fork_repo") or row.get("repo")
    evidence = _compact(
        [
            row.get("upstream_fix_or_advisory"),
            f"fork_missing_status={row.get('fork_missing_status')}" if row.get("fork_missing_status") else None,
            f"reachable_in_scope_code_path={row.get('reachable_in_scope_code_path')}" if row.get("reachable_in_scope_code_path") else None,
            *_as_list(row.get("reachability_evidence")),
            row.get("reachability_reason"),
        ]
    )
    changed = _compact(
        [
            row.get("changed_surface"),
            row.get("upstream_fix_or_advisory"),
            *_as_list(row.get("reachability_evidence")),
        ],
        limit=6,
    )
    return {
        "raw": row,
        "source": {"input": source_label, "schema": schema, "row_index": index},
        "source_kind": "fork-divergence-prober",
        "ecosystem": pin.get("ecosystem") or row.get("ecosystem") or "unknown",
        "module_package": _text(module or fork_repo or "<unknown-pin>"),
        "fork_repo": _norm_repo(fork_repo),
        "pin": _text(pin.get("pin_sha") or pin.get("pin_version") or row.get("pin_sha") or row.get("pin_version")),
        "upstream_reference": _text(row.get("upstream_fix_or_advisory")),
        "classification": _text(row.get("classification") or "blocked-needs-input"),
        "evidence": evidence,
        "changed_parts": changed,
        "reachability": _text(row.get("reachable_in_scope_code_path") or "unknown"),
        "fork_missing_status": _text(row.get("fork_missing_status") or "unknown"),
        "candidate_commit_count": 1 if SECURITY_SIGNAL_RE.search(_text(row.get("upstream_fix_or_advisory"))) else 0,
        "missing_tag_count": 0,
    }


def normalize_manifest_row(row: dict[str, Any], source_label: str, schema: str, index: int) -> dict[str, Any]:
    module = _first(row, ("module_package", "module", "package", "name", "crate", "dependency"))
    fork_repo = _first(row, ("fork_repo", "repo", "repository", "git_url", "fork_url"))
    candidate_commits = _first(row, ("candidate_security_commits", "candidate_commits", "commits")) or []
    missing = _first(row, ("not_in_fork", "missing_tags", "missing_upstream_tags", "behind")) or []
    evidence = _compact(
        [
            *_as_list(row.get("evidence")),
            row.get("reason"),
            row.get("summary"),
            row.get("advisory"),
            row.get("upstream_fix_or_advisory"),
            *_candidate_commit_parts(candidate_commits),
            *(_as_list(missing) if not isinstance(missing, bool) else []),
        ]
    )
    changed = _compact(
        [
            row.get("changed_surface"),
            *_as_list(row.get("changed_surfaces")),
            row.get("surface"),
            row.get("component"),
            row.get("path"),
            *_as_list(row.get("vulnerable_paths")),
            *_candidate_commit_parts(candidate_commits),
        ],
        limit=6,
    )
    fork_missing = _text(row.get("fork_missing_status") or row.get("divergence") or row.get("status"))
    if not fork_missing:
        fork_missing = "lagging" if missing or candidate_commits else "unknown"
    return {
        "raw": row,
        "source": {"input": source_label, "schema": schema, "row_index": index},
        "source_kind": "manifest",
        "ecosystem": _text(row.get("ecosystem") or row.get("language") or "unknown"),
        "module_package": _text(module or fork_repo or "<unknown-package>"),
        "fork_repo": _norm_repo(fork_repo),
        "pin": _text(_first(row, ("pin", "pin_sha", "lock_sha", "fork_sha", "pin_version", "version"))),
        "upstream_reference": _text(_first(row, ("upstream_reference", "upstream_fix_or_advisory", "fixed_in", "upstream_latest", "advisory"))),
        "classification": _text(row.get("classification") or row.get("priority") or "advisory-row"),
        "evidence": evidence,
        "changed_parts": changed,
        "reachability": _text(row.get("reachable_in_scope_code_path") or row.get("reachability") or ("reachable" if row.get("actionable") else "unknown")),
        "fork_missing_status": fork_missing,
        "candidate_commit_count": len(candidate_commits) if isinstance(candidate_commits, list) else (1 if candidate_commits else 0),
        "missing_tag_count": len(missing) if isinstance(missing, list) else (1 if missing else 0),
    }


def normalize_input(doc: Any, source_label: str) -> list[dict[str, Any]]:
    schema = _source_schema(doc)
    rows: list[dict[str, Any]] = []
    if isinstance(doc, dict) and isinstance(doc.get("leads"), list):
        for index, row in enumerate(doc["leads"]):
            if isinstance(row, dict):
                rows.append(normalize_prober_row(row, source_label, schema, index))
        return rows
    if isinstance(doc, dict) and isinstance(doc.get("forks"), list):
        for index, row in enumerate(doc["forks"]):
            if isinstance(row, dict):
                rows.append(normalize_gomod_row(row, source_label, schema, index))
        return rows
    if isinstance(doc, dict) and isinstance(doc.get("git_deps"), list):
        for index, row in enumerate(doc["git_deps"]):
            if isinstance(row, dict):
                rows.append(normalize_cargo_row(row, source_label, schema, index))
        return rows

    for index, row in enumerate(_iter_manifest_rows(doc)):
        rows.append(normalize_manifest_row(row, source_label, schema, index))
    return rows


def _surface_scan_text(row: dict[str, Any]) -> str:
    return "\n".join(
        [
            row.get("module_package", ""),
            row.get("fork_repo", ""),
            row.get("upstream_reference", ""),
            "\n".join(row.get("evidence", [])),
            "\n".join(row.get("changed_parts", [])),
        ]
    )


def surface_terms(row: dict[str, Any]) -> tuple[int, list[str], list[str]]:
    haystack = _surface_scan_text(row)
    labels: list[str] = []
    hints: list[str] = []
    max_score = 0
    for pattern, weight, label, hint in SURFACE_SIGNALS:
        if re.search(pattern, haystack, re.IGNORECASE):
            max_score = max(max_score, weight)
            if label not in labels:
                labels.append(label)
            if hint not in hints:
                hints.append(hint)
    return max_score, labels, hints


def score_row(row: dict[str, Any]) -> tuple[int, dict[str, int], list[str], str]:
    raw = row["raw"]
    classification = row.get("classification", "")
    fork_missing = row.get("fork_missing_status", "")
    reachability = row.get("reachability", "")
    haystack = _surface_scan_text(row)

    lag = 0
    if raw.get("actionable") is True or fork_missing == "lagging" or classification == "actionable-lead":
        lag = 28
    elif fork_missing in ("behind", "forked", "diverged"):
        lag = 24
    elif classification == "candidate-divergence":
        lag = 22
    elif fork_missing in ("unknown", "blocked") or classification == "blocked-needs-input":
        lag = 8

    reach = 0
    if reachability == "reachable" or raw.get("actionable") is True:
        reach = 22
    elif reachability in ("unknown", "", None):
        reach = 8
    elif reachability == "not-reachable":
        reach = -18

    commit_count = int(row.get("candidate_commit_count") or 0)
    missing_tag_count = int(row.get("missing_tag_count") or 0)
    security = min(25, (8 if commit_count else 0) + commit_count * 5 + missing_tag_count * 2)
    if SECURITY_SIGNAL_RE.search(haystack):
        security = max(security, 10)
    if "GHSA" in haystack or "CVE-" in haystack or "advisory" in haystack.lower():
        security = min(25, security + 5)

    surface, labels, derived_hints = surface_terms(row)
    exploit = 0
    if re.search(r"\b(untrusted|public|external|attacker|forged|malicious|callback|replay|invalid)\b", haystack, re.IGNORECASE):
        exploit += 8
    if reachability == "reachable":
        exploit += 5
    exploit = min(13, exploit)

    dampening = 0
    if classification in ("not-a-finding", "current-pin") or fork_missing in ("same", "current"):
        dampening -= 20
    if LOW_VALUE_RE.search(haystack):
        dampening -= 6

    score = max(0, min(100, 5 + lag + reach + security + surface + exploit + dampening))
    terms = {
        "base": 5,
        "lag": lag,
        "reachability": reach,
        "security_signal": security,
        "surface": surface,
        "exploitability": exploit,
        "dampening": dampening,
    }
    changed = _compact([*labels, *row.get("changed_parts", [])], limit=6)
    changed_surface = "; ".join(changed) if changed else "fork/upstream divergence surface not specified"
    return int(score), terms, derived_hints, changed_surface


def priority_band(score: int) -> str:
    if score >= 80:
        return "urgent"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def derive_hints(row: dict[str, Any], derived: list[str]) -> list[str]:
    raw = row["raw"]
    hints = []
    hints.extend(_as_list(raw.get("exploitability_hints")))
    hints.extend(_as_list(raw.get("hints")))
    if row.get("reachability") == "reachable" or raw.get("actionable") is True:
        hints.append("Reachable from in-scope source; prioritize a fork/upstream differential harness.")
    elif row.get("reachability") == "not-reachable":
        hints.append("Version divergence appears unreachable; keep as advisory until scope evidence changes.")
    else:
        hints.append("Reachability unresolved; trace imports/call paths before making severity claims.")
    if row.get("candidate_commit_count"):
        hints.append("Missing upstream security-fix commits; enumerate the exact behavior delta before filing.")
    hints.extend(derived)
    return _compact(hints, limit=6)


def derive_next_command(row: dict[str, Any]) -> str:
    raw = row["raw"]
    explicit = _first(raw, ("next_command", "command", "local_replay_or_harness_task"))
    if explicit:
        return _text(explicit)

    source_kind = row.get("source_kind")
    source_input = row["source"]["input"]
    fork_repo = row.get("fork_repo") or "<fork-repo>"
    pin = row.get("pin") or "<pin>"
    module = row.get("module_package") or "dep"
    upstream = row.get("upstream_reference") or "<upstream-fix-ref>"

    if source_kind in ("gomod-ancestry", "cargo-ancestry"):
        report_arg = source_input if not source_input.startswith("<") else "<ancestry-report.json>"
        return (
            "python3 tools/fork-divergence-prober.py "
            f"--workspace <workspace> --ancestry-report {report_arg} --json"
        )
    if fork_repo and fork_repo != "<fork-repo>":
        return (
            f"git clone https://{fork_repo} /tmp/fdasr-{_slug(module)} && "
            f"cd /tmp/fdasr-{_slug(module)} && "
            f"git log --oneline {pin or '<pin>'}..{upstream}"
        )
    return "python3 tools/fork-divergence-prober.py --workspace <workspace> --json"


def build_rows(normalized: list[dict[str, Any]], top: int = 0) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for row in normalized:
        score, terms, derived_hints, changed_surface = score_row(row)
        ranked.append(
            {
                "rank": 0,
                "priority_score": score,
                "priority_band": priority_band(score),
                "module_package": row.get("module_package") or "<unknown>",
                "ecosystem": row.get("ecosystem") or "unknown",
                "fork_repo": row.get("fork_repo") or "",
                "pin": row.get("pin") or "",
                "upstream_reference": row.get("upstream_reference") or "",
                "classification": row.get("classification") or "advisory-row",
                "changed_surface": changed_surface,
                "exploitability_hints": derive_hints(row, derived_hints),
                "evidence": row.get("evidence", []),
                "next_command": derive_next_command(row),
                "terms": terms,
                "source": row["source"],
                "advisory_only": True,
            }
        )

    ranked.sort(
        key=lambda r: (
            -int(r["priority_score"]),
            r["module_package"],
            r["fork_repo"],
            r["source"]["input"],
            int(r["source"]["row_index"]),
        )
    )
    if top and top > 0:
        ranked = ranked[:top]
    for idx, row in enumerate(ranked, 1):
        row["rank"] = idx
    return ranked


def build_envelope(inputs: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    input_summary = [
        {
            "label": item["label"],
            "schema": _source_schema(item["doc"]),
        }
        for item in inputs
    ]
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "scoring_model": {
            "version": SCORING_MODEL_VERSION,
            "advisory_only": True,
            "score_range": "0..100",
            "signals": [
                "fork lag/divergence",
                "reachable in-scope path",
                "upstream security/advisory evidence",
                "changed attack surface keywords",
                "exploitability trigger hints",
            ],
        },
        "advisory_only": True,
        "inputs": input_summary,
        "summary": {
            "inputs": len(inputs),
            "rows": len(rows),
            "urgent": sum(1 for row in rows if row["priority_band"] == "urgent"),
            "high": sum(1 for row in rows if row["priority_band"] == "high"),
            "medium": sum(1 for row in rows if row["priority_band"] == "medium"),
            "low": sum(1 for row in rows if row["priority_band"] == "low"),
            "not_a_finding_or_current": sum(
                1 for row in rows if row["classification"] in ("not-a-finding", "current-pin")
            ),
        },
        "run_id": digest,
        "rows": rows,
    }


def render_markdown(envelope: dict[str, Any]) -> str:
    lines = [
        "# Fork-Divergence Attack-Surface Ranking",
        "",
        f"- Schema: `{envelope['schema']}`",
        "- Mode: advisory only; rows are leads for local proof work, not findings.",
        f"- Rows: {envelope['summary']['rows']}",
        "",
    ]
    for row in envelope["rows"]:
        lines.extend(
            [
                f"## {row['rank']}. {row['module_package']} ({row['priority_score']} / {row['priority_band']})",
                f"- Ecosystem: `{row['ecosystem']}`",
                f"- Fork repo: `{row['fork_repo']}`",
                f"- Changed surface: {row['changed_surface']}",
                f"- Classification: `{row['classification']}`",
                f"- Next command: `{row['next_command']}`",
                "- Evidence:",
            ]
        )
        for evidence in row["evidence"] or ["n/a"]:
            lines.append(f"  - {evidence}")
        lines.append("- Exploitability hints:")
        for hint in row["exploitability_hints"] or ["n/a"]:
            lines.append(f"  - {hint}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="JSON path, '-' for stdin, or inline JSON. Repeatable.",
    )
    parser.add_argument(
        "--manifest",
        action="append",
        default=[],
        help="Alias for --input when passing a hand-authored manifest.",
    )
    parser.add_argument("--top", type=int, default=0, help="emit only the top N rows (default: all)")
    parser.add_argument("--out", type=Path, help="write output to this path")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    tokens = [*args.input, *args.manifest]
    if not tokens:
        print("error: at least one --input/--manifest JSON path or inline JSON document is required", file=sys.stderr)
        return 1

    try:
        inputs = [load_input(token, idx) for idx, token in enumerate(tokens, 1)]
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    normalized: list[dict[str, Any]] = []
    for item in inputs:
        normalized.extend(normalize_input(item["doc"], item["label"]))

    rows = build_rows(normalized, top=max(args.top, 0))
    envelope = build_envelope(inputs, rows)
    rendered = (
        json.dumps(envelope, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else render_markdown(envelope)
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
