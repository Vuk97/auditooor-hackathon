#!/usr/bin/env python3
"""Offline Go/Cosmos Hackerman corpus inventory and import gap report."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import re
from pathlib import Path
from typing import Any, Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_REFERENCE_ROOT = REPO_ROOT
TEXT_EXTENSIONS = {".md", ".markdown", ".txt"}
FINDINGS_GLOB = "findings_go*.jsonl"

GO_HINTS = (
    "golang",
    ".go",
    "go module",
    "github.com/cosmos",
    "github.com/cometbft",
    "github.com/tendermint",
    "github.com/dydxprotocol/v4",
    "cosmos-sdk",
    "cosmos sdk",
    "cometbft",
    "tendermint",
    "iavl",
    "msgserver",
    "keeper",
    "validatebasic",
    "prepareproposal",
    "processproposal",
    "extendvote",
    "finalizeblock",
    "beginblocker",
    "endblocker",
    "antehandler",
    "x/bank",
    "x/gov",
    "x/clob",
    "ibc",
)
COSMOS_HINTS = (
    "cosmos",
    "cosmos-sdk",
    "cosmos sdk",
    "cometbft",
    "tendermint",
    "iavl",
    "msgserver",
    "keeper",
    "validatebasic",
    "prepareproposal",
    "processproposal",
    "extendvote",
    "finalizeblock",
    "beginblocker",
    "endblocker",
    "antehandler",
    "module account",
    "x/bank",
    "x/gov",
    "x/clob",
    "ibc",
    "slinky",
    "dydxprotocol/v4-chain",
)
STRONG_COSMOS_HINTS = tuple(hint for hint in COSMOS_HINTS if hint != "cosmos")
DYDX_RELEVANCE_TERMS = (
    (120, ("dydx", "dydxprotocol/v4", "v4-chain", "x/clob", "clob")),
    (100, ("cometbft", "tendermint", "iavl", "cosmos sdk", "cosmos-sdk", "prepareproposal", "processproposal", "extendvote", "finalizeblock")),
    (90, ("slinky", "oracle", "price feed", "pyth")),
    (80, ("msgserver", "keeper", "validatebasic", "module account", "x/bank", "x/gov", "ibc")),
    (70, ("osmosis", "nibiru", "injective", "thorchain", "zetachain", "fairyring", "atomone", "all in bits")),
    (65, ("gte clob", "gte perps", "perps", "matching engine", "liquidation")),
)
DYDX_RELEVANT_BUG_CLASSES = {
    "input-validation",
    "consensus",
    "oracle",
    "accounting",
    "denial-of-service",
    "authorization",
    "bridge",
}
REPO_FAMILY_RULES = (
    ("dydx", ("dydx", "dydxprotocol/v4", "v4-chain", "x/clob", "clob", "perps", "liquidation")),
    ("spark", ("buildonspark", "spark", "sparkdotfi")),
    ("mezo", ("mezo", "mezo-org", "mezonetwork")),
    ("cosmos-sdk", ("cosmos/cosmos-sdk", "cosmos-sdk", "cosmos sdk", "module account", "x/bank", "x/gov", "msgserver", "validatebasic")),
    ("cometbft", ("cometbft", "tendermint", "prepareproposal", "processproposal", "extendvote", "finalizeblock")),
    ("iavl", ("iavl", "cosmos/iavl")),
    ("ibc", ("ibc-go", "cosmos/ibc", "inter-blockchain", "ibc packet", "ibc", "bridge")),
)
PRIORITY_ORDER = {
    "P0-dydx-critical-proof": 0,
    "P1-consensus-core": 1,
    "P2-ibc-bridge": 2,
    "P3-spark-mezo-adjacent": 3,
    "P4-cosmos-app-adjacent": 4,
    "P5-other-go-cosmos": 5,
}
LOW_DYDX_RELEVANCE_TERMS = (
    "solana",
    "erc20",
    "erc721",
    "erc4626",
    "openzeppelin",
    "ethereum",
    "evm-contracts",
    "smart contract",
)
TOP_LEVEL_GO_RE = re.compile(r'(?m)^target_language:\s*["\']?go["\']?\s*$')


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.expanduser().resolve().as_posix()


def blob_from(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {blob_from(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(blob_from(item) for item in value)
    return str(value or "")


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def scope_for_blob(text: str, language: str | None = None) -> str:
    if contains_any(text, STRONG_COSMOS_HINTS):
        return "cosmos"
    if "cosmos" in text.lower() and not contains_any(text, LOW_DYDX_RELEVANCE_TERMS):
        return "cosmos"
    if language == "go" or contains_any(text, GO_HINTS):
        return "go"
    return "other"


def repo_family_for_blob(text: str) -> str:
    low = text.lower()
    for family, terms in REPO_FAMILY_RULES:
        if contains_any(low, terms):
            return family
    if contains_any(low, COSMOS_HINTS):
        return "other-cosmos"
    if contains_any(low, GO_HINTS):
        return "other-go"
    return "unknown"


def repo_family_for_item(item: dict[str, Any]) -> str:
    fields = (
        "repo_family",
        "target_repo",
        "source_path",
        "source_family",
        "bug_class",
        "scope",
        "summary",
        "finding_id",
        "record_id",
        "source_audit_ref",
    )
    return repo_family_for_blob(" ".join(str(item.get(field) or "") for field in fields))


def staging_priority_for_item(item: dict[str, Any]) -> tuple[str, str]:
    family = str(item.get("repo_family") or repo_family_for_item(item))
    bug_class = str(item.get("bug_class") or "").lower()
    blob = " ".join(
        str(item.get(field) or "")
        for field in ("target_repo", "source_path", "bug_class", "scope", "summary", "finding_id")
    ).lower()
    if family == "dydx" or contains_any(blob, ("x/clob", "clob", "perps", "liquidation", "dydx")):
        return "P0-dydx-critical-proof", "Direct dYdX/CLOB/perps/oracle/accounting relevance."
    if family in {"cometbft", "iavl"} or (
        family == "cosmos-sdk"
        and (bug_class in {"consensus", "input-validation", "denial-of-service"} or contains_any(blob, ("prepareproposal", "processproposal", "extendvote", "finalizeblock")))
    ):
        return "P1-consensus-core", "Consensus, state-store, or Cosmos SDK execution path coverage."
    if family == "ibc" or bug_class == "bridge":
        return "P2-ibc-bridge", "IBC or bridge path coverage that can support cross-chain proof work."
    if family in {"spark", "mezo"}:
        return "P3-spark-mezo-adjacent", "Spark/Mezo adjacent Go/Cosmos corpus coverage."
    if family == "cosmos-sdk" or str(item.get("scope")) == "cosmos":
        return "P4-cosmos-app-adjacent", "General Cosmos app coverage for keeper/module import expansion."
    return "P5-other-go-cosmos", "Lower-specificity Go/Cosmos coverage candidate."


def dydx_relevance_score(item: dict[str, Any]) -> int:
    """Rank uncovered inputs by usefulness for dYdX Go/Cosmos hunting."""
    blob = " ".join(
        str(item.get(field) or "")
        for field in ("source_path", "target_repo", "bug_class", "scope", "summary", "finding_id")
    ).lower()
    score = 0
    for weight, terms in DYDX_RELEVANCE_TERMS:
        if contains_any(blob, terms):
            score += weight
    bug_class = str(item.get("bug_class") or "").lower()
    if bug_class in DYDX_RELEVANT_BUG_CLASSES:
        score += 20
    if item.get("scope") == "cosmos":
        score += 15
    elif item.get("scope") == "go":
        score += 8
    source_family = str(item.get("source_family") or "")
    if source_family == "findings-go":
        score += 20
    elif source_family in {"prior-audit", "audit-text-corpus"}:
        score += 10
    if contains_any(blob, LOW_DYDX_RELEVANCE_TERMS) and not contains_any(
        blob, ("cosmos", "cometbft", "dydx", "pyth", "slinky", "clob", "perps", "ibc")
    ):
        score -= 25
    return score


def repo_from_ref(github_ref: object, fallback_text: str = "") -> str:
    text = f"{github_ref or ''} {fallback_text}"
    match = re.search(r"github\.com[:/]+([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", text)
    if match:
        repo = match.group(1).rstrip("-.")
        if repo.lower() in {"dydxprotocol/v4", "dydxprotocol/v4-chain"} or repo.lower().startswith("dydxprotocol/v4-"):
            return "dydxprotocol/v4-chain"
        return repo
    path_match = re.search(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", fallback_text)
    if path_match:
        owner, repo = path_match.group(1).split("/", 1)
        if owner.lower() not in {"x", "proto", "types", "keeper", "module", "ibc"} and not repo.endswith((".go", ".md", ".txt")):
            return f"{owner}/{repo}"
    return "unknown"


def source_family(source_ref: object, record_id: object = "") -> str:
    text = str(source_ref or record_id or "")
    if text.startswith("findings-go:"):
        return "findings-go"
    if text.startswith("prior-audit:"):
        return "prior-audit"
    if text.startswith("corpus-txt:"):
        return "audit-text-corpus"
    if text.startswith("solodit-spec:"):
        return "solodit-spec"
    if text.startswith("corpus-mined:"):
        return "corpus-mined"
    if text.startswith("git-mining:"):
        return "git-mining"
    if text.startswith("sig-extract:"):
        return "sig-extract"
    if text.startswith("external_audit/") or "sibling_" in text or text.startswith("legacy:sibling"):
        return "sibling"
    if text.startswith("legacy:"):
        return "legacy"
    return "unknown"


def load_tag_records(tag_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not tag_dir.exists():
        return records, [f"tag directory not found: {tag_dir}"]
    for path in sorted(tag_dir.glob("*.yaml")):
        try:
            raw = path.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rel(path)}: read failed: {exc}")
            continue
        if not TOP_LEVEL_GO_RE.search(raw):
            continue
        try:
            doc = yaml.safe_load(raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rel(path)}: YAML parse failed: {exc}")
            continue
        if not isinstance(doc, dict):
            continue
        if doc.get("target_language") != "go":
            continue
        text = blob_from(doc)
        scope = scope_for_blob(text, "go")
        if scope == "other":
            continue
        record = {
            "path": rel(path),
            "record_id": str(doc.get("record_id") or ""),
            "source_audit_ref": str(doc.get("source_audit_ref") or ""),
            "target_repo": str(doc.get("target_repo") or "unknown"),
            "bug_class": str(doc.get("bug_class") or "unknown"),
            "source_family": source_family(doc.get("source_audit_ref"), doc.get("record_id")),
            "scope": scope,
        }
        record["repo_family"] = repo_family_for_item(record)
        records.append(record)
    return records, errors


def load_source_coverage_records(tag_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not tag_dir.exists():
        return records, [f"tag directory not found: {tag_dir}"]
    for path in sorted(tag_dir.glob("*.yaml")):
        try:
            raw = path.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rel(path)}: read failed: {exc}")
            continue
        if "source_audit_ref:" not in raw:
            continue
        try:
            doc = yaml.safe_load(raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rel(path)}: YAML parse failed: {exc}")
            continue
        if not isinstance(doc, dict):
            continue
        source_ref = str(doc.get("source_audit_ref") or "")
        if not source_ref:
            continue
        records.append(
            {
                "path": rel(path),
                "record_id": str(doc.get("record_id") or ""),
                "source_audit_ref": source_ref,
                "source_family": source_family(source_ref, doc.get("record_id")),
            }
        )
    return records, errors


def discover_findings_files(reference_root: Path) -> list[Path]:
    candidates: set[Path] = set()
    if reference_root.name == "reference":
        candidates.update(reference_root.glob(FINDINGS_GLOB))
    candidates.update((reference_root / "reference").glob(FINDINGS_GLOB))
    candidates.update(reference_root.glob(FINDINGS_GLOB))
    return sorted(path for path in candidates if path.is_file())


def load_findings_inputs(reference_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in discover_findings_files(reference_root):
        with path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    errors.append(f"{rel(path)}:{lineno}: invalid JSON: {exc}")
                    continue
                if not isinstance(row, dict):
                    errors.append(f"{rel(path)}:{lineno}: row is not an object")
                    continue
                if row.get("language") != "go":
                    continue
                text = blob_from(row)
                scope = scope_for_blob(text, "go")
                rows.append(
                    {
                        "source_family": "findings-go",
                        "source_path": rel(path),
                        "line": lineno,
                        "finding_id": str(row.get("finding_id") or ""),
                        "target_repo": repo_from_ref(row.get("github_ref"), text),
                        "bug_class": str(row.get("bug_class") or "unknown"),
                        "scope": scope,
                        "summary": re.sub(r"\s+", " ", str(row.get("summary") or "")).strip()[:240],
                    }
                )
                rows[-1]["repo_family"] = repo_family_for_item(rows[-1])
    return rows, errors


def discover_audit_docs(reference_root: Path) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    candidate_dirs: set[Path] = set()
    for name in ("prior_audits", "extracted_audits"):
        direct = reference_root / name
        if direct.is_dir():
            candidate_dirs.add(direct)
    try:
        children = [path for path in reference_root.iterdir() if path.is_dir()]
    except OSError:
        children = []
    for child in children:
        if child.name in {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "audit", "agent_outputs", "reports"}:
            continue
        for name in ("prior_audits", "extracted_audits"):
            candidate = child / name
            if candidate.is_dir():
                candidate_dirs.add(candidate)

    for audit_dir in sorted(candidate_dirs):
        workspace = audit_dir.parent
        for path in sorted(audit_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scope = scope_for_blob(f"{path.as_posix()}\n{text}")
            if scope == "other":
                continue
            repo = repo_from_ref("", text)
            bug_class = infer_doc_bug_class(text)
            docs.append(
                {
                    "source_family": "prior-audit",
                    "source_path": rel(path),
                    "workspace": rel(workspace),
                    "workspace_name": workspace.name or ".",
                    "audit_kind": audit_dir.name,
                    "target_repo": repo,
                    "bug_class": bug_class,
                    "scope": scope,
                    "summary": first_heading_or_line(text),
                }
            )
            docs[-1]["repo_family"] = repo_family_for_blob(f"{repo}\n{bug_class}\n{path.as_posix()}\n{text}")
    return docs


def discover_corpus_text_docs(reference_root: Path) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    candidate_roots: set[Path] = set()
    direct = reference_root / "corpus_txt"
    if direct.is_dir():
        candidate_roots.add(direct)
    nested = reference_root / "reference" / "corpus_txt"
    if nested.is_dir():
        candidate_roots.add(nested)

    for corpus_root in sorted(candidate_roots):
        for path in sorted(corpus_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scope = scope_for_blob(f"{path.as_posix()}\n{text}")
            if scope == "other":
                continue
            docs.append(
                {
                    "source_family": "audit-text-corpus",
                    "source_path": rel(path),
                    "target_repo": repo_from_ref("", text),
                    "bug_class": infer_doc_bug_class(text),
                    "scope": scope,
                    "summary": first_heading_or_line(text),
                }
            )
            docs[-1]["repo_family"] = repo_family_for_blob(f"{path.as_posix()}\n{text}")
    return docs


def first_heading_or_line(text: str) -> str:
    for line in text.splitlines():
        cleaned = line.strip(" #\t")
        if len(cleaned) >= 8:
            return re.sub(r"\s+", " ", cleaned)[:240]
    return ""


def infer_doc_bug_class(text: str) -> str:
    low = text.lower()
    rules = (
        ("input-validation", ("validatebasic", "missing validation", "not validated", "unchecked", "malformed")),
        ("consensus", ("prepareproposal", "processproposal", "extendvote", "consensus", "cometbft")),
        ("accounting", ("accounting", "balance", "module account", "supply", "state drift")),
        ("authorization", ("authorization", "unauthorized", "permission", "authz")),
        ("oracle", ("oracle", "price", "slinky")),
        ("bridge", ("ibc", "bridge", "cross-chain", "cross chain")),
        ("denial-of-service", ("denial of service", " dos ", "halt", "panic")),
    )
    for bug_class, needles in rules:
        if contains_any(low, needles):
            return bug_class
    return "logic-error"


def covered_findings_ids(tag_records: list[dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for record in tag_records:
        source = record["source_audit_ref"]
        if not source.startswith("findings-go:"):
            continue
        parts = source.split(":")
        if len(parts) >= 3:
            covered.add(parts[-1])
    return covered


def covered_prior_doc_keys(tag_records: list[dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for record in tag_records:
        source = record["source_audit_ref"]
        if not source.startswith("prior-audit:"):
            continue
        match = re.match(r"prior-audit:([^:]+):(.+?)(?::L\d+:S\d+)?$", source)
        if match:
            covered.add(f"{match.group(1)}:{match.group(2)}")
    return covered


def covered_corpus_text_doc_keys(tag_records: list[dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for record in tag_records:
        source = record["source_audit_ref"]
        if not source.startswith("corpus-txt:"):
            continue
        body = source.removeprefix("corpus-txt:")
        covered.add(re.sub(r":L\d+:S\d+$", "", body))
    return covered


def prior_doc_key(doc: dict[str, Any]) -> str:
    source_path = Path(str(doc["source_path"]))
    workspace_path = Path(str(doc.get("workspace") or ""))
    try:
        rel_source = source_path.relative_to(workspace_path)
    except (ValueError, RuntimeError):
        rel_source = source_path
    return f"{doc['workspace_name']}:{rel_source.as_posix()}"


def corpus_text_doc_key(doc: dict[str, Any]) -> str:
    return str(doc["source_path"])


def annotate_coverage(
    findings_rows: list[dict[str, Any]],
    prior_docs: list[dict[str, Any]],
    corpus_text_docs: list[dict[str, Any]],
    tag_records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    finding_ids = covered_findings_ids(tag_records)
    prior_keys = covered_prior_doc_keys(tag_records)
    corpus_text_keys = covered_corpus_text_doc_keys(tag_records)
    annotated_rows: list[dict[str, Any]] = []
    for row in findings_rows:
        item = dict(row)
        item["covered"] = bool(item["finding_id"] and item["finding_id"] in finding_ids)
        item["ingest_command"] = (
            f"python3 tools/hackerman-etl-from-findings-go.py --path {item['source_path']} "
            "--out-dir audit/corpus_tags/tags --json-summary"
        )
        annotated_rows.append(item)

    annotated_docs: list[dict[str, Any]] = []
    for doc in prior_docs:
        item = dict(doc)
        item["covered"] = prior_doc_key(item) in prior_keys
        item["ingest_command"] = (
            f"python3 tools/hackerman-etl-from-prior-audits.py --workspace {item['workspace']} "
            "--out-dir audit/corpus_tags/tags --json-summary"
        )
        annotated_docs.append(item)

    annotated_corpus_docs: list[dict[str, Any]] = []
    for doc in corpus_text_docs:
        item = dict(doc)
        item["covered"] = corpus_text_doc_key(item) in corpus_text_keys
        item["ingest_command"] = (
            f"python3 tools/hackerman-etl-from-prior-audits.py --source-file {item['source_path']} "
            "--out-dir audit/corpus_tags/tags --json-summary"
        )
        annotated_corpus_docs.append(item)
    return annotated_rows, annotated_docs, annotated_corpus_docs


def grouped_counts(items: Iterable[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    counter: Counter[tuple[str, ...]] = Counter()
    for item in items:
        counter[tuple(str(item.get(field, "unknown")) for field in fields)] += 1
    rows = []
    for key, count in sorted(counter.items(), key=lambda pair: (-pair[1], pair[0])):
        row = {field: value for field, value in zip(fields, key)}
        row["count"] = count
        rows.append(row)
    return rows


def priority_sort_key(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, 99)


def repo_family_gap_rows(
    tag_records: list[dict[str, Any]],
    local_inputs: list[dict[str, Any]],
    uncovered: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    tag_by_family: Counter[str] = Counter(str(item.get("repo_family") or repo_family_for_item(item)) for item in tag_records)
    local_by_family: Counter[str] = Counter(str(item.get("repo_family") or repo_family_for_item(item)) for item in local_inputs)
    uncovered_by_family: Counter[str] = Counter(str(item.get("repo_family") or repo_family_for_item(item)) for item in uncovered)
    rows = []
    for family in sorted(set(tag_by_family) | set(local_by_family) | set(uncovered_by_family)):
        family_uncovered = [
            item for item in uncovered if str(item.get("repo_family") or repo_family_for_item(item)) == family
        ]
        priority_candidates = [
            staging_priority_for_item({**item, "repo_family": str(item.get("repo_family") or repo_family_for_item(item))})
            for item in family_uncovered
        ]
        if priority_candidates:
            priority, reason = sorted(priority_candidates, key=lambda pair: priority_sort_key(pair[0]))[0]
        else:
            priority, reason = staging_priority_for_item({"repo_family": family})
        rows.append(
            {
                "repo_family": family,
                "tagged_records": tag_by_family[family],
                "local_input_records": local_by_family[family],
                "uncovered_local_records": uncovered_by_family[family],
                "staging_priority": priority,
                "priority_reason": reason,
            }
        )
    rows.sort(
        key=lambda row: (
            priority_sort_key(str(row["staging_priority"])),
            -int(row["uncovered_local_records"]),
            -int(row["local_input_records"]),
            str(row["repo_family"]),
        )
    )
    return rows


def top_staging_priorities(uncovered: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for item in uncovered:
        enriched = dict(item)
        enriched["repo_family"] = str(enriched.get("repo_family") or repo_family_for_item(enriched))
        priority, reason = staging_priority_for_item(enriched)
        key = (priority, enriched["repo_family"])
        bucket = buckets.setdefault(
            key,
            {
                "staging_priority": priority,
                "repo_family": enriched["repo_family"],
                "priority_reason": reason,
                "uncovered_count": 0,
                "max_dydx_relevance_score": 0,
                "source_families": Counter(),
                "bug_classes": Counter(),
                "example_sources": [],
            },
        )
        bucket["uncovered_count"] += 1
        bucket["max_dydx_relevance_score"] = max(
            int(bucket["max_dydx_relevance_score"]),
            dydx_relevance_score(enriched),
        )
        bucket["source_families"][str(enriched.get("source_family") or "unknown")] += 1
        bucket["bug_classes"][str(enriched.get("bug_class") or "unknown")] += 1
        if len(bucket["example_sources"]) < 3:
            bucket["example_sources"].append(str(enriched.get("source_path") or enriched.get("finding_id") or "unknown"))

    rows: list[dict[str, Any]] = []
    for bucket in buckets.values():
        source_families = bucket.pop("source_families")
        bug_classes = bucket.pop("bug_classes")
        bucket["top_source_families"] = [
            {"source_family": family, "count": count}
            for family, count in sorted(source_families.items(), key=lambda pair: (-pair[1], pair[0]))[:5]
        ]
        bucket["top_bug_classes"] = [
            {"bug_class": bug_class, "count": count}
            for bug_class, count in sorted(bug_classes.items(), key=lambda pair: (-pair[1], pair[0]))[:5]
        ]
        rows.append(bucket)
    rows.sort(
        key=lambda row: (
            priority_sort_key(str(row["staging_priority"])),
            -int(row["max_dydx_relevance_score"]),
            -int(row["uncovered_count"]),
            str(row["repo_family"]),
        )
    )
    return rows[:limit]


def candidate_targets(local_inputs: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in local_inputs:
        if item.get("covered"):
            continue
        repo_family = str(item.get("repo_family") or repo_family_for_item(item))
        staging_priority, priority_reason = staging_priority_for_item({**item, "repo_family": repo_family})
        key = (
            str(item.get("source_family", "unknown")),
            str(item.get("source_path", "")),
            str(item.get("target_repo", "unknown")),
            str(item.get("bug_class", "unknown")),
        )
        entry = grouped.setdefault(
            key,
            {
                "source_family": key[0],
                "source_path": key[1],
                "target_repo": key[2],
                "bug_class": key[3],
                "repo_family": repo_family,
                "staging_priority": staging_priority,
                "priority_reason": priority_reason,
                "scope": item.get("scope", "go"),
                "dydx_relevance_score": 0,
                "uncovered_count": 0,
                "examples": [],
                "ingest_command": item.get("ingest_command", ""),
                "import_selector": {
                    "source_family": key[0],
                    "source_path": key[1],
                    "target_repo": key[2],
                    "bug_class": key[3],
                    "repo_family": repo_family,
                },
            },
        )
        if priority_sort_key(staging_priority) < priority_sort_key(str(entry.get("staging_priority") or "")):
            entry["staging_priority"] = staging_priority
            entry["priority_reason"] = priority_reason
        entry["dydx_relevance_score"] = max(
            int(entry.get("dydx_relevance_score") or 0),
            dydx_relevance_score(item),
        )
        entry["uncovered_count"] += 1
        if len(entry["examples"]) < 3:
            example = item.get("finding_id") or item.get("summary") or item.get("source_path")
            entry["examples"].append(str(example))
    return sorted(
        grouped.values(),
        key=lambda item: (
            priority_sort_key(str(item.get("staging_priority") or "")),
            -int(item.get("dydx_relevance_score") or 0),
            0 if item["scope"] == "cosmos" else 1,
            -int(item["uncovered_count"]),
            item["source_family"],
            item["source_path"],
        ),
    )[:limit]


def summarize(args: argparse.Namespace) -> dict[str, Any]:
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    reference_root = Path(args.reference_root).expanduser().resolve()
    tag_records, tag_errors = load_tag_records(tag_dir)
    source_coverage_records, source_coverage_errors = load_source_coverage_records(tag_dir)
    findings_rows, findings_errors = load_findings_inputs(reference_root)
    prior_docs = discover_audit_docs(reference_root)
    corpus_text_docs = discover_corpus_text_docs(reference_root)
    findings_rows, prior_docs, corpus_text_docs = annotate_coverage(
        findings_rows, prior_docs, corpus_text_docs, source_coverage_records
    )
    local_inputs = findings_rows + prior_docs + corpus_text_docs
    uncovered = [item for item in local_inputs if not item.get("covered")]

    tag_by_repo: defaultdict[str, int] = defaultdict(int)
    local_by_repo: defaultdict[str, int] = defaultdict(int)
    uncovered_by_repo: defaultdict[str, int] = defaultdict(int)
    for record in tag_records:
        tag_by_repo[record["target_repo"]] += 1
    for item in local_inputs:
        local_by_repo[str(item.get("target_repo", "unknown"))] += 1
        if not item.get("covered"):
            uncovered_by_repo[str(item.get("target_repo", "unknown"))] += 1

    repos = sorted(set(tag_by_repo) | set(local_by_repo) | set(uncovered_by_repo))
    repo_gap_rows = [
        {
            "target_repo": repo,
            "tagged_records": tag_by_repo[repo],
            "local_input_records": local_by_repo[repo],
            "uncovered_local_records": uncovered_by_repo[repo],
        }
        for repo in repos
        if tag_by_repo[repo] or local_by_repo[repo] or uncovered_by_repo[repo]
    ]
    repo_gap_rows.sort(key=lambda row: (-row["uncovered_local_records"], -row["local_input_records"], row["target_repo"]))
    family_gap_rows = repo_family_gap_rows(tag_records, local_inputs, uncovered)
    staging_priorities = top_staging_priorities(uncovered)

    return {
        "schema_version": "auditooor.hackerman_go_cosmos_inventory.v1",
        "tag_dir": rel(tag_dir),
        "reference_root": rel(reference_root),
        "existing_etl": {
            "findings_go": "tools/hackerman-etl-from-findings-go.py",
            "prior_audits": "tools/hackerman-etl-from-prior-audits.py",
        },
        "summary": {
            "tag_records_go_cosmos": len(tag_records),
            "local_findings_go_rows": len(findings_rows),
            "local_prior_audit_candidate_docs": len(prior_docs),
            "local_audit_text_corpus_candidate_docs": len(corpus_text_docs),
            "local_importable_uncovered_records": len(uncovered),
            "importable_local_go_cosmos_records_found": bool(uncovered),
            "parse_errors": len(tag_errors) + len(source_coverage_errors) + len(findings_errors),
        },
        "coverage": {
            "tagged_by_source_family": grouped_counts(tag_records, ("source_family", "scope")),
            "tagged_by_repo": grouped_counts(tag_records, ("target_repo", "scope")),
            "tagged_by_bug_class": grouped_counts(tag_records, ("bug_class", "scope")),
            "local_inputs_by_source_family": grouped_counts(local_inputs, ("source_family", "scope")),
            "local_inputs_by_repo_family": grouped_counts(local_inputs, ("repo_family", "scope")),
            "uncovered_by_repo": grouped_counts(uncovered, ("target_repo", "scope")),
            "uncovered_by_repo_family": grouped_counts(uncovered, ("repo_family", "scope")),
            "uncovered_by_bug_class": grouped_counts(uncovered, ("bug_class", "scope")),
            "repo_gap_rows": repo_gap_rows,
            "repo_family_gap_rows": family_gap_rows,
        },
        "import_planning": {
            "top_staging_priorities": staging_priorities,
            "mechanical_fields": [
                "staging_priority",
                "repo_family",
                "source_family",
                "source_path",
                "target_repo",
                "bug_class",
                "ingest_command",
            ],
        },
        "candidate_import_targets": candidate_targets(local_inputs),
        "local_inputs": sorted(
            local_inputs,
            key=lambda item: (
                -dydx_relevance_score(item),
                0 if item.get("scope") == "cosmos" else 1,
                item.get("source_family", ""),
                item.get("source_path", ""),
            ),
        ),
        "errors": tag_errors + source_coverage_errors + findings_errors,
    }


def render_table(rows: list[dict[str, Any]], columns: list[str], limit: int = 20) -> list[str]:
    if not rows:
        return ["_None._"]
    out = ["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows[:limit]:
        values = [str(row.get(column, "")).replace("|", "\\|") for column in columns]
        out.append("| " + " | ".join(values) + " |")
    return out


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Hackerman Go/Cosmos Inventory",
        "",
        "## Summary",
        "",
        f"- Tag directory: `{report['tag_dir']}`",
        f"- Reference root: `{report['reference_root']}`",
        f"- Existing Go findings ETL: `{report['existing_etl']['findings_go']}`",
        f"- Existing prior-audit ETL: `{report['existing_etl']['prior_audits']}`",
        f"- Current top-level Go/Cosmos tag records: {summary['tag_records_go_cosmos']}",
        f"- Local `findings_go*.jsonl` Go rows: {summary['local_findings_go_rows']}",
        f"- Local prior/extracted-audit candidate docs: {summary['local_prior_audit_candidate_docs']}",
        f"- Local audit-text corpus candidate docs: {summary['local_audit_text_corpus_candidate_docs']}",
        f"- Importable uncovered local Go/Cosmos records found: {str(summary['importable_local_go_cosmos_records_found']).lower()} ({summary['local_importable_uncovered_records']})",
        "",
        "## Coverage By Source Family",
        "",
        *render_table(report["coverage"]["tagged_by_source_family"], ["source_family", "scope", "count"]),
        "",
        "## Coverage Gaps By Repo",
        "",
        *render_table(
            report["coverage"]["repo_gap_rows"],
            ["target_repo", "tagged_records", "local_input_records", "uncovered_local_records"],
            limit=30,
        ),
        "",
        "## Coverage Gaps By Repo Family",
        "",
        *render_table(
            report["coverage"]["repo_family_gap_rows"],
            ["repo_family", "staging_priority", "tagged_records", "local_input_records", "uncovered_local_records"],
            limit=30,
        ),
        "",
        "## Import Planning Priorities",
        "",
        *render_table(
            report["import_planning"]["top_staging_priorities"],
            ["staging_priority", "repo_family", "uncovered_count", "max_dydx_relevance_score", "priority_reason"],
            limit=20,
        ),
        "",
        "## Uncovered By Bug Class",
        "",
        *render_table(report["coverage"]["uncovered_by_bug_class"], ["bug_class", "scope", "count"], limit=30),
        "",
        "## Candidate Import Targets",
        "",
    ]
    if report["candidate_import_targets"]:
        for idx, item in enumerate(report["candidate_import_targets"], start=1):
            lines.extend(
                [
                    f"{idx}. `{item['source_path']}`",
                    f"   - Source family: `{item['source_family']}`; scope: `{item['scope']}`",
                    f"   - Repo family / repo / bug class: `{item.get('repo_family', 'unknown')}` / `{item['target_repo']}` / `{item['bug_class']}`",
                    f"   - Staging priority: `{item.get('staging_priority', 'P5-other-go-cosmos')}` ({item.get('priority_reason', '')})",
                    f"   - dYdX relevance score: {item.get('dydx_relevance_score', 0)}",
                    f"   - Uncovered records: {item['uncovered_count']}",
                    f"   - Ingest command: `{item['ingest_command']}`",
                ]
            )
    else:
        lines.append("_No uncovered local Go/Cosmos import targets were found._")
    if report["errors"]:
        lines.extend(["", "## Parse Errors", ""])
        lines.extend(f"- `{err}`" for err in report["errors"][:50])
    lines.append("")
    return "\n".join(lines)


def write_output(report: dict[str, Any], out_path: Path | None, as_json: bool) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n" if as_json else render_markdown(report)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Directory of Hackerman YAML tag records.")
    parser.add_argument(
        "--reference-root",
        default=str(DEFAULT_REFERENCE_ROOT),
        help="Root used to discover reference/findings_go*.jsonl plus prior_audits/extracted_audits.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--out", help="Optional report output path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = summarize(args)
    out_path = Path(args.out).expanduser().resolve() if args.out else None
    write_output(report, out_path, args.json)
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
