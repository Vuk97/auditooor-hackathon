#!/usr/bin/env python3
"""Derive workspace-local memory context requirements.

This is the first executable slice of the memory auto-linking contract. It
keeps matching deterministic and local: inspect workspace artifacts, derive the
bounded MCP context packs that must be loaded, and optionally write
``<ws>/.auditooor/memory_requirements.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.workspace_memory_requirements.v1"
GENERATOR = "tools/memory-auto-link.py"
MAX_SCAN_FILES = 8000
TEXT_LIMIT = 200_000
SKIP_DIRS = {
    ".git",
    ".auditooor",
    ".audit_logs",
    "agent_outputs",
    "cache",
    "cost_runs",
    "deep_counterexamples",
    "fuzz_runs",
    "lib",
    "node_modules",
    "out",
    "prior_audits",
    "symbolic_runs",
    "target",
}
LANG_EXT = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".circom": "circom",
}
HARNESS_HINTS = {
    "forge",
    "foundry",
    "halmos",
    "medusa",
    "echidna",
    "chimera",
    "cargo test",
    "go test",
    "go test ./...",
    "go test -run",
    "k2-c4",
    "soroban",
}
HM_RE = re.compile(r"\b(?:severity|risk|impact)\s*[:=]\s*(?:high|medium|critical)\b", re.I)
NEGATIVE_CANDIDATE_RE = re.compile(r"\b(?:killed|duplicate|oos|out of scope|false positive|no hm|no high|no medium)\b", re.I)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def read_text(path: Path, limit: int = TEXT_LIMIT) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def has_nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def newest_mtime(paths: list[Path]) -> int | None:
    mtimes: list[int] = []
    for path in paths:
        try:
            if path.exists():
                mtimes.append(int(path.stat().st_mtime))
        except OSError:
            continue
    return max(mtimes) if mtimes else None


def workspace_text(ws: Path) -> str:
    parts: list[str] = []
    for name in (
        "SCOPE.md",
        "AUDIT.md",
        "FINDINGS.md",
        "OOS_CHECKLIST.md",
        "SEVERITY_CAPS.md",
        "PRIOR_CONCERNS.md",
        "engage_report.md",
        "README.md",
        "src/README.md",
        "src/README_SPONSOR.md",
    ):
        path = ws / name
        if path.is_file():
            parts.append(read_text(path, 60_000))
    return "\n".join(parts)


def target_roots(ws: Path) -> list[Path]:
    roots: list[Path] = []
    targets = ws / "targets.tsv"
    if targets.is_file():
        for line in read_text(targets, 80_000).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            first = line.split("\t", 1)[0].strip()
            if not first:
                continue
            path = Path(first)
            roots.append(path if path.is_absolute() else ws / path)
    for rel_root in ("src/contracts", "src", "contracts", "external/contracts/src", "packages/contracts/src"):
        root = ws / rel_root
        if root.exists():
            roots.append(root)
    roots.append(ws)
    deduped: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(root)
    return deduped


def scan_source(ws: Path) -> tuple[list[str], list[str], list[Path]]:
    languages: set[str] = set()
    roots: set[str] = set()
    touched: list[Path] = []
    scanned = 0
    for root in target_roots(ws):
        if scanned >= MAX_SCAN_FILES:
            break
        if root.is_file():
            suffix = root.suffix.lower()
            if suffix in LANG_EXT:
                languages.add(LANG_EXT[suffix])
                roots.add(rel(root.parent, ws))
                touched.append(root)
                scanned += 1
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in root.walk():
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
            for filename in filenames:
                if scanned >= MAX_SCAN_FILES:
                    break
                path = dirpath / filename
                suffix = path.suffix.lower()
                if suffix not in LANG_EXT:
                    continue
                languages.add(LANG_EXT[suffix])
                roots.add(rel(path.parent, ws))
                touched.append(path)
                scanned += 1
            if scanned >= MAX_SCAN_FILES:
                break
    text = workspace_text(ws).lower()
    if "soroban" in text or "stellar" in text or (ws / "src" / "soroban").exists():
        languages.add("soroban")
    if not languages:
        languages.add("unknown")
    return sorted(languages), sorted(roots)[:80], touched


def platform_from_text(text: str) -> str | None:
    lower = text.lower()
    if "code4rena" in lower or "c4" in lower or "warden" in lower:
        return "code4rena"
    if "cantina" in lower:
        return "cantina"
    if "sherlock" in lower:
        return "sherlock"
    if "immunefi" in lower:
        return "immunefi"
    return None


def protocol_family_from_text(text: str) -> str | None:
    lower = text.lower()
    if any(term in lower for term in ("lending", "borrow", "liquidation", "health factor", "aave")):
        return "lending"
    if any(term in lower for term in ("frost", "statechain", "taproot", "bitcoin", "lightning", "htlc")):
        return "bitcoin-statechain"
    if any(term in lower for term in ("governor", "governance", "timelock", "proposal")):
        return "governance"
    if any(term in lower for term in ("stableswap", "stable swap", "amm", "liquidity pool")):
        return "amm"
    if "bridge" in lower:
        return "bridge"
    return None


def any_files(root: Path, patterns: tuple[str, ...]) -> bool:
    if not root.is_dir():
        return False
    for pattern in patterns:
        try:
            if any(root.glob(pattern)):
                return True
        except OSError:
            continue
    return False


def has_prior_audits(ws: Path) -> bool:
    if has_nonempty(ws / "PRIOR_CONCERNS.md"):
        return True
    prior = ws / "prior_audits"
    return any_files(prior, ("*.md", "*.txt", "*.pdf", "DIGEST_*.md", "v12/*.md"))


def has_submission_drafts(ws: Path) -> bool:
    candidates = [
        ws / "submissions" / "staging",
        ws / "submissions" / "ready",
        ws / "submissions" / "paste-ready",
        ws / "submissions" / "packaged",
        ws / "final_cantina_paste",
        ws / "final_paste",
        ws / "poc_notes",
    ]
    for root in candidates:
        if any_files(root, ("*.md", "**/*.md", "*.txt", "**/*.txt", "manifest.json", "**/manifest.json")):
            return True
    return False


def has_hm_candidate(ws: Path) -> bool:
    roots = [
        ws / "submissions" / "staging",
        ws / "submissions" / "ready",
        ws / "submissions" / "paste-ready",
        ws / "final_cantina_paste",
        ws / "final_paste",
        ws / "poc_notes",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for path in list(root.glob("*.md")) + list(root.glob("**/*.md")):
            text = read_text(path, 80_000)
            head = text[:1600]
            if HM_RE.search(text) and not NEGATIVE_CANDIDATE_RE.search(head):
                return True
    return False


def collect_facts(ws: Path) -> tuple[dict[str, Any], list[Path]]:
    text = workspace_text(ws)
    languages, source_roots, source_files = scan_source(ws)
    artifact_paths: list[Path] = [
        ws / "AUDIT.md",
        ws / "FINDINGS.md",
        ws / "SESSION_LOG.md",
        ws / "SCOPE.md",
        ws / "SCAN_REPORT.md",
        ws / "PATTERN_HITS.md",
        ws / "OOS_CHECKLIST.md",
        ws / "SEVERITY_CAPS.md",
        ws / "PRIOR_CONCERNS.md",
        ws / "RUBRIC_COVERAGE.md",
        ws / "engage_report.md",
        ws / "swarm" / "brief_candidates.json",
        ws / "swarm" / "agent_verdicts.json",
        ws / ".audit_logs" / "audit_deep_all_manifest.json",
    ]
    predicates: list[str] = []
    if has_nonempty(ws / "SCAN_REPORT.md"):
        predicates.append("has_scan_report")
    if has_nonempty(ws / "PATTERN_HITS.md"):
        predicates.append("has_pattern_hits")
    if has_nonempty(ws / "engage_report.md"):
        predicates.append("has_engage_report")
    if has_prior_audits(ws):
        predicates.append("has_prior_audits")
    if has_nonempty(ws / "OOS_CHECKLIST.md"):
        predicates.append("has_oos_checklist")
    if has_nonempty(ws / "SEVERITY_CAPS.md"):
        predicates.append("has_severity_caps")
    if (
        any_files(ws / "poc_task_briefs", ("*.json", "*.md"))
        or any_files(ws / "deep_counterexamples", ("*.json", "*.md"))
        or any_files(ws / "symbolic_runs", ("**/manifest.json",))
        or any_files(ws / "fuzz_runs", ("**/manifest.json",))
        or has_nonempty(ws / ".audit_logs" / "audit_deep_all_manifest.json")
        or has_nonempty(ws / "src" / "tests" / "c4" / "src" / "lib.rs")
    ):
        predicates.append("has_harness_queue")
    if any_files(ws / "poc_task_briefs", ("*.json", "*.md")) or any_files(ws / "deep_counterexamples", ("*.json", "*.md")):
        predicates.append("has_poc_queue")
    if has_submission_drafts(ws):
        predicates.append("has_submission_drafts")
    if has_hm_candidate(ws):
        predicates.append("has_high_or_medium_candidate")
    facts = {
        "languages": languages,
        "platform": platform_from_text(text),
        "protocol_family": protocol_family_from_text(text),
        "source_roots": source_roots,
        "source_file_sample": [rel(path, ws) for path in source_files[:40]],
        "artifact_predicates": sorted(set(predicates)),
        "newest_input_mtime": newest_mtime([path for path in artifact_paths if path.exists()] + source_files[:100]),
    }
    return facts, artifact_paths


def existing_refs(ws: Path, refs: list[str]) -> list[str]:
    out: list[str] = []
    for item in refs:
        if (ws / item).exists():
            out.append(item)
    return out


def build_requirements(ws: Path, legacy_audit_import: bool = False) -> dict[str, Any]:
    ws = ws.resolve()
    facts, artifact_paths = collect_facts(ws)
    predicates = set(facts["artifact_predicates"])
    requirements: list[dict[str, Any]] = []

    def add(
        requirement_id: str,
        context_kind: str,
        tool: str,
        args: dict[str, Any],
        required_by: list[str],
        reason: str,
        matched_predicates: list[str],
        fresh_after_refs: list[str],
        strictness: str = "warn_default",
    ) -> None:
        requirements.append(
            {
                "requirement_id": requirement_id,
                "context_kind": context_kind,
                "tool": tool,
                "args": args,
                "required_by": required_by,
                "reason": reason,
                "matched_predicates": sorted(set(matched_predicates)),
                "fresh_after_refs": existing_refs(ws, fresh_after_refs),
                "strictness": strictness,
            }
        )

    base_refs = ["AUDIT.md", "FINDINGS.md", "SESSION_LOG.md", "SCOPE.md"]
    add(
        "base.resume",
        "resume",
        "vault_resume_context",
        {"workspace_path": str(ws), "limit": 8},
        ["flow-gate", "dispatch", "closeout"],
        "Every workspace needs bounded resume/context continuity before audit work continues.",
        ["workspace_exists"],
        base_refs,
    )
    add(
        "base.knowledge-gap",
        "knowledge_gap",
        "vault_knowledge_gap_context",
        {"status": "open", "limit": 8},
        ["dispatch", "audit-deep", "closeout"],
        "Open knowledge gaps must be recalled before closing or dispatching workspace work.",
        ["workspace_exists"],
        base_refs,
    )

    if "has_engage_report" in predicates:
        add(
            "audit.engage-report",
            "engage_report_context",
            "vault_engage_report_context",
            {"workspace_path": str(ws), "limit": 12},
            ["scan", "dispatch", "audit-deep", "closeout"],
            "`make audit` detector clusters must be loaded through Vault MCP before the next hacker-mind/source-reasoning pass.",
            ["has_engage_report"],
            ["engage_report.md"],
        )

    exploit_predicates = {
        "has_scan_report",
        "has_pattern_hits",
        "has_submission_drafts",
        "has_poc_queue",
    }
    if has_nonempty(ws / "swarm" / "brief_candidates.json"):
        predicates.add("has_brief_candidates")
    if any_files(ws / "deep_counterexamples", ("*.json", "*.md")):
        predicates.add("has_deep_candidates")
    if predicates & exploit_predicates or "has_brief_candidates" in predicates or "has_deep_candidates" in predicates:
        add(
            "exploit.surface",
            "exploit",
            "vault_exploit_context",
            {"workspace_path": str(ws), "limit": 8},
            ["scan", "dispatch", "audit-deep", "closeout"],
            "Workspace has scan, pattern, candidate, or proof artifacts that require exploit-memory recall.",
            sorted(predicates & (exploit_predicates | {"has_brief_candidates", "has_deep_candidates"})),
            ["SCAN_REPORT.md", "PATTERN_HITS.md", "swarm/brief_candidates.json", "submissions", "poc_task_briefs", "deep_counterexamples"],
        )

    languages = set(facts["languages"])
    text = workspace_text(ws).lower()
    if (
        languages & {"rust", "soroban", "solidity", "circom", "cosmos", "go"}
        or "has_harness_queue" in predicates
        or any(hint in text for hint in HARNESS_HINTS)
    ):
        add(
            "harness.language",
            "harness",
            "vault_harness_context",
            {"limit": 8},
            ["poc", "audit-deep", "closeout"],
            "Workspace language or proof artifacts require harness-failure memory before PoC work.",
            sorted((languages - {"unknown"}) | ({"has_harness_queue"} if "has_harness_queue" in predicates else set())),
            ["SCOPE.md", "src/rust-toolchain.toml", "src/foundry.toml", ".audit_logs/audit_deep_all_manifest.json"],
        )

    if "go" in languages:
        add(
            "language.go.surface",
            "dispatch",
            "vault_dispatch_context",
            {
                "task_type": "go-audit",
                "routing_purpose": "audit",
                "limit": 8,
            },
            ["dispatch", "audit-deep", "closeout"],
            "Go-heavy targets need model routing and prior tooling recall before manual or delegated review.",
            ["go"],
            ["SCOPE.md", "AUDIT.md", "targets.tsv", "external"],
        )
        add(
            "language.go.patterns",
            "resume",
            "vault_resume_context",
            {
                "workspace_path": str(ws),
                "query": f"go bitcoin statechain frost {ws.name}",
                "limit": 8,
            },
            ["scan", "audit-deep", "closeout"],
            "Go / Bitcoin / statechain targets require explicit recall because the default EVM detector corpus is thin.",
            ["go"],
            ["SCOPE.md", "AUDIT.md", "PRIOR_CONCERNS.md"],
        )

    if predicates & {"has_prior_audits", "has_oos_checklist", "has_severity_caps"}:
        add(
            "prior.oos",
            "resume",
            "vault_resume_context",
            {"workspace_path": str(ws), "query": f"prior OOS severity {ws.name}", "limit": 8},
            ["flow-gate", "pre-submit", "closeout"],
            "Prior-audit, OOS, or severity artifacts require bounded recall before filing or closing.",
            sorted(predicates & {"has_prior_audits", "has_oos_checklist", "has_severity_caps"}),
            ["PRIOR_CONCERNS.md", "OOS_CHECKLIST.md", "SEVERITY_CAPS.md", "prior_audits"],
        )

    if "has_high_or_medium_candidate" in predicates:
        hm_refs = ["submissions", "final_cantina_paste", "final_paste", "poc_notes", "FINDINGS.md", "SUBMISSIONS.md"]
        add(
            "promotion.hm.exploit",
            "exploit",
            "vault_exploit_context",
            {"workspace_path": str(ws), "limit": 8},
            ["poc", "pre-submit", "closeout"],
            "High/Medium promotion requires fresh exploit-memory recall after the promoted artifact.",
            ["has_high_or_medium_candidate"],
            hm_refs,
            strictness="fail_for_hm_promotion",
        )
        add(
            "promotion.hm.knowledge-gap",
            "knowledge_gap",
            "vault_knowledge_gap_context",
            {"status": "open", "limit": 8},
            ["pre-submit", "closeout"],
            "High/Medium promotion requires fresh missing-truth recall before paste-ready closure.",
            ["has_high_or_medium_candidate"],
            hm_refs,
            strictness="fail_for_hm_promotion",
        )

    if legacy_audit_import:
        facts["legacy_audit_import"] = True

    return {
        "schema": SCHEMA,
        "workspace": ws.name,
        "workspace_path": str(ws),
        "generated_at": utc_now(),
        "generator": GENERATOR,
        "workspace_facts": facts,
        "requirements": requirements,
    }


def validate_requirements(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if doc.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if doc.get("generator") != GENERATOR:
        errors.append(f"generator must be {GENERATOR}")
    if not isinstance(doc.get("workspace"), str) or not doc["workspace"]:
        errors.append("workspace must be non-empty string")
    if not isinstance(doc.get("workspace_path"), str) or not doc["workspace_path"]:
        errors.append("workspace_path must be non-empty string")
    facts = doc.get("workspace_facts")
    if not isinstance(facts, dict):
        errors.append("workspace_facts must be object")
    else:
        if not isinstance(facts.get("languages"), list) or not facts["languages"]:
            errors.append("workspace_facts.languages must be non-empty array")
        if not isinstance(facts.get("artifact_predicates"), list):
            errors.append("workspace_facts.artifact_predicates must be array")
    seen: set[str] = set()
    requirements = doc.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        errors.append("requirements must be non-empty array")
        return errors
    for idx, req in enumerate(requirements):
        if not isinstance(req, dict):
            errors.append(f"requirements[{idx}] must be object")
            continue
        rid = req.get("requirement_id")
        if not isinstance(rid, str) or not re.match(r"^[a-z0-9_.-]+$", rid):
            errors.append(f"requirements[{idx}].requirement_id invalid")
        elif rid in seen:
            errors.append(f"duplicate requirement_id: {rid}")
        else:
            seen.add(rid)
        if req.get("context_kind") not in {
            "resume",
            "exploit",
            "harness",
            "knowledge_gap",
            "dispatch",
            "finalization",
            "engage_report_context",
        }:
            errors.append(f"{rid or idx}: context_kind invalid")
        if req.get("tool") not in {
            "vault_resume_context",
            "vault_exploit_context",
            "vault_harness_context",
            "vault_knowledge_gap_context",
            "vault_dispatch_context",
            "vault_finalization_context",
            "vault_engage_report_context",
        }:
            errors.append(f"{rid or idx}: tool invalid")
        if not isinstance(req.get("args"), dict):
            errors.append(f"{rid or idx}: args must be object")
        if not isinstance(req.get("required_by"), list) or not req["required_by"]:
            errors.append(f"{rid or idx}: required_by must be non-empty array")
        if not isinstance(req.get("reason"), str) or not req["reason"]:
            errors.append(f"{rid or idx}: reason must be non-empty")
        if req.get("strictness") not in {"warn_default", "fail_when_strict", "fail_for_hm_promotion"}:
            errors.append(f"{rid or idx}: strictness invalid")
    return errors


def requirement_signatures(doc: dict[str, Any]) -> dict[str, str]:
    signatures: dict[str, str] = {}
    for req in doc.get("requirements", []):
        if not isinstance(req, dict) or not isinstance(req.get("requirement_id"), str):
            continue
        signatures[req["requirement_id"]] = canonical_json(
            {
                "context_kind": req.get("context_kind"),
                "tool": req.get("tool"),
                "args": req.get("args"),
                "required_by": req.get("required_by"),
                "matched_predicates": req.get("matched_predicates"),
                "fresh_after_refs": req.get("fresh_after_refs"),
                "strictness": req.get("strictness"),
            }
        )
    return signatures


def fact_signature(doc: dict[str, Any]) -> str:
    facts = doc.get("workspace_facts") if isinstance(doc.get("workspace_facts"), dict) else {}
    return canonical_json(
        {
            "languages": facts.get("languages"),
            "platform": facts.get("platform"),
            "protocol_family": facts.get("protocol_family"),
            "artifact_predicates": facts.get("artifact_predicates"),
        }
    )


def requirements_path(ws: Path) -> Path:
    return ws / ".auditooor" / "memory_requirements.json"


def check_existing(ws: Path, strict: bool = False) -> tuple[int, dict[str, Any]]:
    path = requirements_path(ws)
    if not path.is_file():
        return (
            1 if strict else 2,
            {
                "status": "missing",
                "path": str(path),
                "next_command": f"python3 tools/memory-auto-link.py --workspace {ws} --write",
            },
        )
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return 1, {"status": "invalid_json", "path": str(path), "error": str(exc)}
    errors = validate_requirements(doc)
    if errors:
        return 1, {"status": "invalid", "path": str(path), "errors": errors}
    current = build_requirements(ws)
    current_sigs = requirement_signatures(current)
    existing_sigs = requirement_signatures(doc)
    current_ids = set(current_sigs)
    existing_ids = set(existing_sigs)
    missing_ids = sorted(current_ids - existing_ids)
    extra_ids = sorted(existing_ids - current_ids)
    changed_ids = sorted(rid for rid in current_ids & existing_ids if current_sigs[rid] != existing_sigs[rid])
    facts_changed = fact_signature(current) != fact_signature(doc)
    stale = missing_ids or extra_ids or changed_ids or facts_changed
    if stale:
        return (
            1 if strict else 2,
            {
                "status": "stale",
                "path": str(path),
                "missing_requirement_ids": missing_ids,
                "extra_requirement_ids": extra_ids,
                "changed_requirement_ids": changed_ids,
                "workspace_facts_changed": facts_changed,
                "next_command": f"python3 tools/memory-auto-link.py --workspace {ws} --write",
            },
        )
    return (
        0,
        {
            "status": "ok",
            "path": str(path),
            "requirements_hash": hashlib_sha256_file(path),
            "required_count": len(doc["requirements"]),
        },
    )


def hashlib_sha256_file(path: Path) -> str:
    return __import__("hashlib").sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Audit workspace root")
    parser.add_argument("--write", action="store_true", help="Write .auditooor/memory_requirements.json")
    parser.add_argument("--json", action="store_true", help="Print generated/check JSON")
    parser.add_argument("--check", action="store_true", help="Validate existing requirements file")
    parser.add_argument("--strict", action="store_true", help="Treat missing/stale requirements as failure in --check")
    parser.add_argument("--legacy-audit-import", action="store_true", help="Mark generated facts as legacy import migration")
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[memory-auto-link] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    if args.check:
        rc, result = check_existing(ws, strict=args.strict)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            status = result.get("status")
            print(f"[memory-auto-link] {status}: {result.get('path', ws)}")
            if result.get("next_command"):
                print(f"[memory-auto-link] next: {result['next_command']}")
        return rc

    doc = build_requirements(ws, legacy_audit_import=args.legacy_audit_import)
    errors = validate_requirements(doc)
    if errors:
        for error in errors:
            print(f"[memory-auto-link] ERR {error}", file=sys.stderr)
        return 1
    if args.write:
        out = requirements_path(ws)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[memory-auto-link] wrote {out} ({len(doc['requirements'])} requirements)")
    if args.json or not args.write:
        print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
