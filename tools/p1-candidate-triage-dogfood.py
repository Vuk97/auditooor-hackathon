#!/usr/bin/env python3
"""Read-only P1 candidate triage dogfood joiner.

Joins an engagement's detector clusters, filed/killed submissions,
candidate/proof packets, exploit queue rows, and the P1 invariant library.
It reports indexed INV citation coverage and suggests candidate->INV mappings
without editing any draft or submission files.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.p1_candidate_triage_dogfood.v2"
TOOL_VERSION = "0.2.2"

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PILOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"
DEFAULT_AUDITED_PRIMARY = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"
)
DEFAULT_EXTRACTED = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
DEFAULT_OUT_DIR = (
    REPO_ROOT
    / "reports"
    / "v3_iter_2026-05-23"
    / "lane_HB_P1_CANDIDATE_TRIAGE_DOGFOOD_TOOL"
)
DEFAULT_P1_ATTRIBUTION_SIDECAR = "p1_invariant_attribution_sidecar.json"

INV_RE = re.compile(r"\bINV-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
EQ_RE = re.compile(r"\bEQ-\d+\b")
CLUSTER_RE = re.compile(
    r"^###\s+Cluster:\s+`?([^`\n(]+?)`?\s*\((\d+)\s+hits?\)",
    re.MULTILINE,
)
HIT_RE = re.compile(
    r"^\s*[-*]\s+\*{0,2}\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]"
    r"\s+`(?P<detector>[^`]+)`\*{0,2}\s+[-]+|\s+",
)
HIT_LINE_RE = re.compile(
    r"^\s*[-*]\s+\*{0,2}\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]"
    r"\s+`(?P<detector>[^`]+)`\*{0,2}\s+[-\u2014]+\s+"
    r"`(?P<file_path>[^`:]+):(?P<line>\d+)`",
    re.MULTILINE,
)
SNIPPET_RE = re.compile(r"^\s*[-*]\s+snippet:\s+`?(.+?)`?\s*$", re.MULTILINE)

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*|[0-9]+")
CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "audits",
    "be",
    "by",
    "can",
    "candidate",
    "check",
    "class",
    "code",
    "contract",
    "does",
    "file",
    "for",
    "from",
    "go",
    "has",
    "have",
    "hyperbridge",
    "if",
    "in",
    "into",
    "is",
    "it",
    "line",
    "may",
    "must",
    "no",
    "not",
    "of",
    "on",
    "or",
    "path",
    "proof",
    "row",
    "source",
    "state",
    "src",
    "that",
    "the",
    "this",
    "to",
    "via",
    "with",
    "without",
    "wolf",
    "sol",
    "rs",
    "tmp",
    "ws",
}

CATEGORY_KEYWORDS: dict[str, set[str]] = {
    "authorization": {
        "access",
        "admin",
        "auth",
        "authorization",
        "caller",
        "control",
        "eoa",
        "forgery",
        "msgsender",
        "owner",
        "permission",
        "role",
        "signature",
        "signer",
        "unauthorized",
        "verify",
    },
    "atomicity": {
        "atomic",
        "callback",
        "call",
        "external",
        "half",
        "interaction",
        "partial",
        "reentry",
        "reentrant",
        "reentrancy",
        "state",
        "tstore",
        "transient",
    },
    "bounds": {
        "alloc",
        "bound",
        "cap",
        "cast",
        "division",
        "downcast",
        "int",
        "length",
        "limit",
        "loop",
        "overflow",
        "scale",
        "size",
        "uint",
        "unbounded",
        "underflow",
        "zero",
    },
    "conservation": {
        "accounting",
        "amount",
        "balance",
        "credit",
        "debit",
        "decimal",
        "fee",
        "refund",
        "scale",
        "solvency",
        "sum",
        "transfer",
    },
    "custody": {
        "allowance",
        "approve",
        "burn",
        "custody",
        "mint",
        "token",
        "transfer",
        "withdraw",
    },
    "determinism": {
        "codec",
        "consensus",
        "deterministic",
        "divergence",
        "parser",
        "random",
        "trie",
    },
    "freshness": {
        "deadline",
        "expiry",
        "finalized",
        "fresh",
        "stale",
        "timeout",
        "unfinalized",
    },
    "monotonicity": {
        "advance",
        "decrease",
        "finality",
        "height",
        "increase",
        "monotonic",
        "period",
        "round",
    },
    "ordering": {
        "after",
        "before",
        "order",
        "ordering",
        "precede",
        "queue",
        "sequence",
    },
    "uniqueness": {
        "consumed",
        "duplicate",
        "message",
        "nonce",
        "once",
        "replay",
        "signature",
        "unique",
    },
}


@dataclass
class Invariant:
    invariant_id: str
    category: str
    target_lang: str
    statement: str
    search_text: str
    tokens: set[str]
    source_path: str


@dataclass
class Candidate:
    candidate_id: str
    title: str = ""
    disposition: str = "open"
    sources_present: set[str] = field(default_factory=set)
    text_parts: list[str] = field(default_factory=list)
    source_refs: set[str] = field(default_factory=set)
    submission_paths: list[str] = field(default_factory=list)
    engage_clusters: list[dict[str, Any]] = field(default_factory=list)
    blocked_reasons: list[str] = field(default_factory=list)

    def add_text(self, text: str | None) -> None:
        if text:
            self.text_parts.append(str(text))

    @property
    def search_text(self) -> str:
        pieces = [self.candidate_id, self.title, self.disposition]
        pieces.extend(sorted(self.source_refs))
        pieces.extend(self.text_parts)
        pieces.extend(
            " ".join(
                [
                    str(cluster.get("cluster_name", "")),
                    " ".join(cluster.get("detectors", [])),
                    " ".join(cluster.get("files", [])),
                    " ".join(cluster.get("snippets", [])),
                ]
            )
            for cluster in self.engage_clusters
        )
        return "\n".join(p for p in pieces if p)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def tokens(value: str) -> set[str]:
    value = CAMEL_RE.sub(" ", value.replace("_", " ").replace("-", " ").replace("/", " "))
    raw = {tok.lower() for tok in TOKEN_RE.findall(value)}
    return {tok for tok in raw if len(tok) > 1 and tok not in STOPWORDS}


def safe_rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def load_invariants(paths: list[Path]) -> tuple[dict[str, Invariant], list[str]]:
    invariants: dict[str, Invariant] = {}
    warnings: list[str] = []
    for path in paths:
        if not path.exists():
            warnings.append(f"missing invariant source: {path}")
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            warnings.append(f"failed reading invariant source {path}: {exc}")
            continue
        for lineno, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                warnings.append(f"bad jsonl row: {path}:{lineno}")
                continue
            inv_id = str(row.get("invariant_id", "")).strip()
            if not INV_RE.fullmatch(inv_id) or inv_id in invariants:
                continue
            search = " ".join(
                str(row.get(k, ""))
                for k in (
                    "category",
                    "statement",
                    "commit_point_pattern",
                    "defense_layer",
                    "defense_invariant",
                    "attack_signature",
                    "abstraction_level",
                )
            )
            invariants[inv_id] = Invariant(
                invariant_id=inv_id,
                category=str(row.get("category", "")).strip().lower(),
                target_lang=str(row.get("target_lang", "any")).strip().lower() or "any",
                statement=str(row.get("statement", "")).strip(),
                search_text=search,
                tokens=tokens(search),
                source_path=f"{path}:{lineno}",
            )
    return invariants, warnings


def _sidecar_invariant_sources(row: dict[str, Any]) -> list[Path]:
    refs = row.get("evidence_refs") or row.get("evidence_artifacts") or []
    if not isinstance(refs, list):
        refs = [refs]
    paths: list[Path] = []
    for ref in refs:
        text = str(ref)
        match = re.match(r"^(?P<path>.+?\.jsonl)(?::\d+)?$", text)
        if not match:
            continue
        path = Path(match.group("path")).expanduser()
        if not path.is_absolute():
            path = REPO_ROOT / path
        paths.append(path)
    paths.append(DEFAULT_PILOT)

    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def resolve_sidecar_invariant(
    inv_id: str,
    row: dict[str, Any],
    *,
    primary_invariants: dict[str, Invariant],
    supplemental_cache: dict[Path, dict[str, Invariant]],
    warnings: list[str],
) -> tuple[Invariant | None, bool]:
    if inv_id in primary_invariants:
        return primary_invariants[inv_id], False
    for path in _sidecar_invariant_sources(row):
        if path not in supplemental_cache:
            loaded, load_warnings = load_invariants([path])
            supplemental_cache[path] = loaded
            warnings.extend(f"sidecar supplemental invariant source warning: {warning}" for warning in load_warnings)
        if inv_id in supplemental_cache[path]:
            return supplemental_cache[path][inv_id], True
    return None, False


def resolve_invariant_paths(
    invariant_paths: list[Path] | None = None,
    *,
    include_extracted: bool = False,
) -> tuple[list[Path], dict[str, Any], list[str]]:
    if invariant_paths:
        explicit_paths = list(invariant_paths)
        return explicit_paths, {
            "quality_source": "explicit",
            "paths": [str(path) for path in explicit_paths],
            "explicit_invariants": True,
            "include_extracted_broad": any(
                path == DEFAULT_EXTRACTED or path.name == DEFAULT_EXTRACTED.name
                for path in explicit_paths
            ),
        }, []

    warnings: list[str] = []
    paths: list[Path]
    quality_source: str
    if DEFAULT_AUDITED_PRIMARY.exists():
        paths = [DEFAULT_AUDITED_PRIMARY]
        quality_source = "audited_primary"
    else:
        paths = [DEFAULT_PILOT]
        quality_source = "pilot_fallback"
        warnings.append(
            f"audited primary invariant source missing; fell back to pilot source: {DEFAULT_AUDITED_PRIMARY}"
        )

    if include_extracted:
        paths.append(DEFAULT_EXTRACTED)

    return paths, {
        "quality_source": quality_source,
        "paths": [str(path) for path in paths],
        "explicit_invariants": False,
        "include_extracted_broad": include_extracted,
        "broad_extracted_policy": "opt_in_only",
    }, warnings


def parse_engage_report(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not path.exists():
        return [], {"path": str(path), "present": False, "total_hits": 0}
    text = path.read_text(encoding="utf-8", errors="replace")
    total_match = re.search(r"Total hits:\s*\*{0,2}(\d+)\*{0,2}", text)
    cluster_starts = [
        (m.start(), m.end(), m.group(1).strip(), int(m.group(2)))
        for m in CLUSTER_RE.finditer(text)
    ]
    clusters: list[dict[str, Any]] = []
    for idx, (_, header_end, name, expected_hits) in enumerate(cluster_starts):
        seg_end = cluster_starts[idx + 1][0] if idx + 1 < len(cluster_starts) else len(text)
        segment = text[header_end:seg_end]
        hits: list[dict[str, Any]] = []
        for hm in HIT_LINE_RE.finditer(segment):
            after = segment[hm.end() : hm.end() + 350]
            snippet_m = SNIPPET_RE.search(after)
            hits.append(
                {
                    "severity": hm.group("severity").upper(),
                    "detector_id": hm.group("detector").strip(),
                    "file_path": hm.group("file_path").strip(),
                    "line": int(hm.group("line")),
                    "snippet": snippet_m.group(1).strip() if snippet_m else "",
                }
            )
        files = sorted({h["file_path"] for h in hits})
        detectors = sorted({h["detector_id"] for h in hits})
        snippets = [h["snippet"] for h in hits if h.get("snippet")]
        detector_text = " ".join([name, *detectors])
        clusters.append(
            {
                "cluster_name": name,
                "expected_hits": expected_hits,
                "parsed_hits": len(hits),
                "detectors": detectors,
                "files": files,
                "snippets": snippets[:8],
                "hits": hits,
                "tokens": sorted(tokens(detector_text)),
                "snippet_tokens": sorted(tokens(" ".join(snippets))),
                "file_tokens": sorted(tokens(" ".join(files))),
            }
        )
    return clusters, {
        "path": str(path),
        "present": True,
        "total_hits": int(total_match.group(1)) if total_match else sum(c["parsed_hits"] for c in clusters),
        "cluster_count": len(clusters),
    }


def get_candidate(candidates: dict[str, Candidate], candidate_id: str) -> Candidate:
    if candidate_id not in candidates:
        candidates[candidate_id] = Candidate(candidate_id=candidate_id)
    return candidates[candidate_id]


def infer_lang(text: str, source_refs: set[str]) -> set[str]:
    joined = " ".join([text, *source_refs]).lower()
    langs: set[str] = set()
    if ".sol" in joined or "solidity" in joined or "evm" in joined:
        langs.add("solidity")
    if ".go" in joined or "cosmos" in joined or "cometbft" in joined:
        langs.add("go")
    if ".rs" in joined or "rust" in joined or "substrate" in joined:
        langs.add("rust")
    if "move" in joined:
        langs.add("move")
    return langs


def collect_exploit_queue(workspace: Path, candidates: dict[str, Candidate]) -> dict[str, Any]:
    path = workspace / ".auditooor" / "exploit_queue.json"
    data = read_json(path)
    meta = {"path": str(path), "present": data is not None, "rows": 0}
    if not isinstance(data, dict):
        return meta
    rows = data.get("queue") or []
    if not isinstance(rows, list):
        return meta
    meta["rows"] = len(rows)
    for row in rows:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("lead_id") or row.get("candidate_id") or "").strip()
        if not cid:
            continue
        cand = get_candidate(candidates, cid)
        cand.sources_present.add("exploit_queue")
        cand.title = cand.title or str(row.get("title", "")).strip()
        cand.disposition = str(
            row.get("proof_status") or row.get("quality_gate_status") or cand.disposition
        )
        cand.add_text(json.dumps(row, sort_keys=True))
        for ref in row.get("source_refs") or []:
            cand.source_refs.add(str(ref))
        blockers = row.get("blockers") or []
        blockedish = " ".join(
            str(row.get(k, "")) for k in ("proof_status", "quality_gate_status", "source_mined_proof_status")
        ).lower()
        if "killed" in blockedish or "disqualified" in blockedish:
            cand.blocked_reasons.append("exploit_queue marks candidate killed/disqualified")
        if blockers and ("killed" in blockedish or "disqualified" in blockedish):
            cand.blocked_reasons.append(str(blockers[0])[:240])
    return meta


def collect_candidate_packets(workspace: Path, candidates: dict[str, Candidate]) -> dict[str, Any]:
    aud = workspace / ".auditooor"
    paths = [aud / "candidate_judgment_packet.json", aud / "prove_top_leads_candidate_judgment_packet.json"]
    packets_dir = aud / "candidate_judgment_packets"
    if packets_dir.is_dir():
        paths.extend(sorted(packets_dir.glob("*.json")))
    seen: set[Path] = set()
    packet_count = 0
    for path in paths:
        if path in seen or not path.exists():
            continue
        seen.add(path)
        data = read_json(path)
        rows: list[Any] = []
        if isinstance(data, dict) and isinstance(data.get("packets"), list):
            rows = data["packets"]
        elif isinstance(data, dict) and data.get("candidate_id"):
            rows = [data]
        for packet in rows:
            if not isinstance(packet, dict):
                continue
            cid = str(packet.get("candidate_id") or "").strip()
            if not cid:
                continue
            packet_count += 1
            cand = get_candidate(candidates, cid)
            cand.sources_present.add("candidate_packet")
            cand.title = cand.title or str(packet.get("title", "")).strip()
            verdict = str(packet.get("verdict") or packet.get("judgment") or "").strip()
            if verdict:
                cand.disposition = verdict
            cand.add_text(json.dumps(packet, sort_keys=True))
            if "blocked" in verdict.lower() or "killed" in verdict.lower():
                cand.blocked_reasons.append(f"candidate_packet verdict={verdict}")
    return {"searched": [str(p) for p in paths], "packets": packet_count}


def collect_proof_packets(workspace: Path, candidates: dict[str, Candidate]) -> dict[str, Any]:
    aud = workspace / ".auditooor"
    paths = [aud / "proof_obligation_queue.json", aud / "proof_obligation_queue.freshness.json"]
    stress_dir = aud / "prefiling_stress_tests"
    if stress_dir.is_dir():
        paths.extend(sorted(stress_dir.glob("*.json")))
    paths.extend(sorted(aud.glob("*proof*packet*.json"))) if aud.is_dir() else None
    attached = 0
    seen: set[Path] = set()
    for path in paths:
        if path in seen or not path.exists():
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        data = read_json(path)
        if isinstance(data, dict) and isinstance(data.get("tasks"), list):
            for task in data["tasks"]:
                if not isinstance(task, dict):
                    continue
                task_text = json.dumps(task, sort_keys=True)
                for cid in sorted(set(EQ_RE.findall(task_text))):
                    cand = get_candidate(candidates, cid)
                    cand.sources_present.add("proof_packet")
                    cand.add_text(task_text)
                    attached += 1
            continue
        explicit_ids = set(EQ_RE.findall(path.name))
        if isinstance(data, dict):
            if data.get("candidate_id"):
                explicit_ids.add(str(data["candidate_id"]))
        for cid in explicit_ids:
            cand = get_candidate(candidates, cid)
            cand.sources_present.add("proof_packet")
            cand.add_text(text[:20000])
            attached += 1
    return {"searched": [str(p) for p in paths], "attachments": attached}


def submission_status(path: Path) -> str:
    parts = path.parts
    if "filed" in parts:
        return "filed"
    if "_killed" in parts:
        return "killed"
    return "unknown"


def submission_slug(path: Path) -> str:
    stem = path.name
    for suffix in (".hackenproof-plain.md", ".hardening.md", ".md"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def collect_submissions(workspace: Path, candidates: dict[str, Candidate]) -> dict[str, Any]:
    submissions = workspace / "submissions"
    paths: list[Path] = []
    for rel in ("filed", "_killed"):
        root = submissions / rel
        if root.is_dir():
            paths.extend(sorted(root.rglob("*.md")))
    read_count = 0
    status_counts: Counter[str] = Counter()
    for path in paths:
        if path.name.endswith(".hardening.md") or path.name == "SUBMISSIONS.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        read_count += 1
        status = submission_status(path)
        status_counts[status] += 1
        explicit = EQ_RE.findall(text)
        cid = explicit[0] if explicit else submission_slug(path)
        cand = get_candidate(candidates, cid)
        cand.sources_present.add(f"submission:{status}")
        cand.disposition = status
        cand.submission_paths.append(str(path))
        cand.title = cand.title or first_heading(text) or submission_slug(path)
        cand.add_text(text)
        if status == "killed":
            cand.blocked_reasons.append("submission is under submissions/_killed")
    return {"paths_read": read_count, "by_status": dict(status_counts)}


def first_heading(text: str) -> str | None:
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            title = line.lstrip("#").strip()
            if title:
                return title[:180]
    return None


def attach_engage_clusters(candidates: dict[str, Candidate], clusters: list[dict[str, Any]]) -> int:
    attachments = 0
    for cand in candidates.values():
        c_tokens = tokens(cand.search_text)
        source_blob = " ".join(cand.source_refs).lower()
        for cluster in clusters:
            cl_tokens = set(cluster.get("tokens") or [])
            token_overlap = c_tokens & cl_tokens
            source_hit = False
            for file_path in cluster.get("files", []):
                fp = str(file_path).lower()
                file_tail = "/".join(Path(fp).parts[-3:])
                if fp in source_blob or file_tail in source_blob:
                    source_hit = True
                    break
            if source_hit or len(token_overlap) >= 2:
                slim = {
                    "cluster_name": cluster["cluster_name"],
                    "parsed_hits": cluster["parsed_hits"],
                    "detectors": cluster["detectors"],
                    "files": cluster["files"][:6],
                    "matched_tokens": sorted(token_overlap)[:12],
                    "match_reason": "source-ref-overlap" if source_hit else "token-overlap",
                }
                cand.engage_clusters.append(slim)
                cand.sources_present.add("engage_cluster")
                attachments += 1
    return attachments


def infer_categories(cand_tokens: set[str]) -> Counter[str]:
    scored: Counter[str] = Counter()
    for category, kws in CATEGORY_KEYWORDS.items():
        scored[category] = len(cand_tokens & kws)
    return scored


def is_lang_applicable(inv: Invariant, langs: set[str]) -> bool:
    if inv.target_lang in {"", "any", "unknown"}:
        return True
    if not langs:
        return True
    return inv.target_lang in langs


def score_invariant(cand: Candidate, inv: Invariant) -> dict[str, Any]:
    cand_tokens = tokens(cand.search_text)
    common = cand_tokens & inv.tokens
    categories = infer_categories(cand_tokens)
    category_hits = categories.get(inv.category, 0)
    langs = infer_lang(cand.search_text, cand.source_refs)
    if not is_lang_applicable(inv, langs):
        return {"score": 0.0, "matched_tokens": [], "reason": "language-mismatch"}
    score = float(len(common) * 2)
    if category_hits:
        score += 5.0 + category_hits
    if inv.target_lang in langs:
        score += 2.0
    if cand.engage_clusters:
        score += min(3.0, len(cand.engage_clusters) * 0.5)
    if len(common) < 2 and not category_hits:
        score = 0.0
    denom = math.sqrt(max(len(inv.tokens), 1))
    score += min(4.0, len(common) / denom * 4.0)
    reason_bits = []
    if common:
        reason_bits.append("token-overlap")
    if category_hits:
        reason_bits.append(f"category={inv.category}")
    if inv.target_lang in langs:
        reason_bits.append(f"lang={inv.target_lang}")
    return {
        "score": round(score, 2),
        "matched_tokens": sorted(common)[:18],
        "reason": "+".join(reason_bits) or "no-match",
    }


def load_attribution_sidecar(
    workspace: Path,
    invariants: dict[str, Invariant],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[str]]:
    path = workspace / ".auditooor" / DEFAULT_P1_ATTRIBUTION_SIDECAR
    if not path.exists():
        return {}, {"path": str(path), "present": False, "accepted_count": 0}, []
    data = read_json(path)
    warnings: list[str] = []
    accepted: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(data, dict):
        return {}, {"path": str(path), "present": True, "accepted_count": 0}, [f"invalid sidecar JSON object: {path}"]
    supplemental_cache: dict[Path, dict[str, Invariant]] = {}
    supplemental_count = 0
    for idx, row in enumerate(data.get("mappings") or [], start=1):
        if not isinstance(row, dict):
            warnings.append(f"invalid sidecar mapping #{idx}: expected object")
            continue
        candidate_id = str(row.get("candidate_id", "")).strip()
        inv_id = str(row.get("p1_invariant_id") or row.get("invariant_id") or "").strip()
        status = str(row.get("attribution_status", "")).strip()
        if status != "accepted_by_local_review":
            continue
        if row.get("suggested_only") is True or row.get("category_only") is True:
            continue
        if not candidate_id or not INV_RE.fullmatch(inv_id):
            warnings.append(f"invalid sidecar mapping #{idx}: missing candidate_id or invariant_id")
            continue
        inv, supplemental = resolve_sidecar_invariant(
            inv_id,
            row,
            primary_invariants=invariants,
            supplemental_cache=supplemental_cache,
            warnings=warnings,
        )
        if inv is None:
            warnings.append(f"sidecar mapping #{idx} references unknown invariant: {inv_id}")
            continue
        if supplemental:
            supplemental_count += 1
        accepted[candidate_id].append(
            {
                "invariant_id": inv_id,
                "category": inv.category,
                "attribution_status": status,
                "basis": "accepted_by_local_review_sidecar",
                "evidence": str(row.get("evidence", ""))[:500],
                "evidence_refs": row.get("evidence_refs") or row.get("evidence_artifacts") or [],
                "invariant_statement": inv.statement[:300],
                "invariant_source": inv.source_path,
                "sidecar_source": str(path),
            }
        )
    for rows in accepted.values():
        rows.sort(key=lambda item: item["invariant_id"])
    meta = {
        "path": str(path),
        "present": True,
        "schema": data.get("schema") or data.get("schema_version"),
        "accepted_count": sum(len(rows) for rows in accepted.values()),
        "supplemental_invariant_count": supplemental_count,
        "supplemental_policy": "exact_id_only_for_accepted_local_review_sidecar_rows",
        "policy": data.get("policy") if isinstance(data.get("policy"), dict) else {},
    }
    return dict(accepted), meta, warnings


def classify_candidate(
    cand: Candidate,
    invariants: dict[str, Invariant],
    *,
    max_suggestions: int,
    accepted_by_candidate: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    body = cand.search_text
    cited = sorted({m.group(0) for m in INV_RE.finditer(body)})
    indexed_cited = [inv_id for inv_id in cited if inv_id in invariants]
    unindexed_cited = [inv_id for inv_id in cited if inv_id not in invariants]
    accepted_mappings = accepted_by_candidate.get(cand.candidate_id, [])
    suggestions: list[dict[str, Any]] = []
    has_filed_submission = "submission:filed" in cand.sources_present
    effectively_blocked = bool(cand.blocked_reasons) and not has_filed_submission
    if not indexed_cited and not accepted_mappings and not effectively_blocked:
        for inv in invariants.values():
            scored = score_invariant(cand, inv)
            if scored["score"] < 8.0:
                continue
            suggestions.append(
                {
                    "invariant_id": inv.invariant_id,
                    "category": inv.category,
                    "score": scored["score"],
                    "matched_tokens": scored["matched_tokens"],
                    "reason": scored["reason"],
                    "invariant_statement": inv.statement[:300],
                    "invariant_source": inv.source_path,
                }
            )
        suggestions.sort(key=lambda row: (-row["score"], row["invariant_id"]))
        suggestions = suggestions[:max_suggestions]

    if indexed_cited:
        state = "cited"
    elif accepted_mappings:
        state = "accepted"
    elif effectively_blocked:
        state = "blocked"
    elif suggestions:
        state = "suggested"
    else:
        state = "no-match"

    return {
        "candidate_id": cand.candidate_id,
        "title": cand.title[:220],
        "state": state,
        "disposition": cand.disposition,
        "sources_present": sorted(cand.sources_present),
        "submission_paths": cand.submission_paths,
        "source_refs": sorted(cand.source_refs)[:20],
        "indexed_cited_invariant_ids": indexed_cited,
        "unindexed_cited_invariant_ids": unindexed_cited,
        "accepted_mappings": accepted_mappings,
        "suggested_mappings": suggestions,
        "attached_engage_clusters": cand.engage_clusters[:8],
        "blocked_reasons": cand.blocked_reasons[:6],
        "coverage": {
            "cited_inv_count": len(cited),
            "indexed_cited_inv_count": len(indexed_cited),
            "accepted_inv_count": len(accepted_mappings),
            "suggested_inv_count": len(suggestions),
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    rows = result["candidate_rows"]
    lines = [
        "# HB P1 Candidate Triage Dogfood Tool",
        "",
        f"- Schema: `{result['schema']}`",
        f"- Tool version: `{result['tool_version']}`",
        f"- Workspace: `{result['workspace']}`",
        f"- Generated: `{result['generated_at_utc']}`",
        f"- No draft/submission edits: `{str(summary['no_draft_or_submission_edits']).lower()}`",
        "",
        "## Summary",
        "",
        f"- Candidates: {summary['candidate_count']}",
        f"- Indexed invariants loaded: {summary['indexed_invariant_count']}",
        f"- Invariant quality source: `{summary['invariant_quality_source']}`",
        f"- Broad extracted invariants included: `{str(summary['include_extracted_broad']).lower()}`",
        f"- Engage clusters parsed: {summary['engage_cluster_count']}",
        f"- States: cited={summary['states'].get('cited', 0)} accepted={summary['states'].get('accepted', 0)} suggested={summary['states'].get('suggested', 0)} no-match={summary['states'].get('no-match', 0)} blocked={summary['states'].get('blocked', 0)}",
        "",
        "## Candidate Coverage",
        "",
        "| State | Candidate | Disposition | Cited INV IDs | Accepted INV IDs | Suggested INV IDs | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        cited = ", ".join(row["indexed_cited_invariant_ids"]) or "-"
        accepted = ", ".join(s["invariant_id"] for s in row["accepted_mappings"]) or "-"
        suggested = ", ".join(s["invariant_id"] for s in row["suggested_mappings"]) or "-"
        evidence = ", ".join(row["sources_present"]) or "-"
        lines.append(
            "| {state} | `{cid}` {title} | {disp} | {cited} | {accepted} | {suggested} | {evidence} |".format(
                state=row["state"],
                cid=row["candidate_id"],
                title=(row["title"][:80].replace("|", "\\|") if row["title"] else ""),
                disp=row["disposition"].replace("|", "\\|"),
                cited=cited,
                accepted=accepted,
                suggested=suggested,
                evidence=evidence.replace("|", "\\|"),
            )
        )
    lines.extend(
        [
            "",
            "## Top Suggested Mappings",
            "",
        ]
    )
    top = [
        (row, suggestion)
        for row in rows
        for suggestion in row["suggested_mappings"][:1]
        if row["state"] == "suggested"
    ][:12]
    if not top:
        lines.append("- None.")
    else:
        for row, suggestion in top:
            lines.append(
                "- `{}` -> `{}` ({}, score={}): {}".format(
                    row["candidate_id"],
                    suggestion["invariant_id"],
                    suggestion["category"],
                    suggestion["score"],
                    suggestion["reason"],
                )
            )
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- `cited` means the candidate/submission already cites an indexed `INV-*` ID.",
            "- `accepted` means the read-only local-review sidecar maps the candidate to an indexed invariant with `attribution_status=accepted_by_local_review`.",
            "- `suggested` means no indexed citation was found, but the read-only matcher found a candidate invariant.",
            "- `no-match` means no indexed citation or sufficiently strong candidate mapping was found.",
            "- `blocked` means the candidate is killed/disqualified or packet-blocked, so the tool does not invent a mapping.",
        ]
    )
    if result.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {w}" for w in result["warnings"])
    return "\n".join(lines) + "\n"


def run_triage(
    workspace: Path,
    out_dir: Path,
    *,
    invariant_paths: list[Path] | None = None,
    include_extracted: bool = False,
    max_suggestions: int = 3,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    out_dir = out_dir.expanduser()
    invariant_paths, invariant_policy, policy_warnings = resolve_invariant_paths(
        invariant_paths,
        include_extracted=include_extracted,
    )

    invariants, warnings = load_invariants(invariant_paths)
    warnings = [*policy_warnings, *warnings]
    candidates: dict[str, Candidate] = {}
    engage_clusters, engage_meta = parse_engage_report(workspace / "engage_report.md")
    sources = {
        "engage_report": engage_meta,
        "exploit_queue": collect_exploit_queue(workspace, candidates),
        "candidate_packets": collect_candidate_packets(workspace, candidates),
        "proof_packets": collect_proof_packets(workspace, candidates),
        "submissions": collect_submissions(workspace, candidates),
    }
    attachments = attach_engage_clusters(candidates, engage_clusters)
    accepted_by_candidate, sidecar_meta, sidecar_warnings = load_attribution_sidecar(workspace, invariants)
    warnings.extend(sidecar_warnings)
    sources["p1_attribution_sidecar"] = sidecar_meta

    rows = [
        classify_candidate(
            cand,
            invariants,
            max_suggestions=max_suggestions,
            accepted_by_candidate=accepted_by_candidate,
        )
        for cand in candidates.values()
    ]
    order = {"cited": 0, "accepted": 1, "suggested": 2, "no-match": 3, "blocked": 4}
    rows.sort(key=lambda row: (order.get(row["state"], 9), row["candidate_id"]))
    states = Counter(row["state"] for row in rows)
    state_counts = {state: states.get(state, 0) for state in ("cited", "accepted", "suggested", "no-match", "blocked")}
    result = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": utc_now(),
        "workspace": str(workspace),
        "out_dir": str(out_dir),
        "invariant_source_policy": invariant_policy,
        "sources": sources,
        "summary": {
            "candidate_count": len(rows),
            "indexed_invariant_count": len(invariants),
            "invariant_quality_source": invariant_policy["quality_source"],
            "include_extracted_broad": invariant_policy["include_extracted_broad"],
            "engage_cluster_count": len(engage_clusters),
            "engage_cluster_attachments": attachments,
            "states": state_counts,
            "indexed_citation_coverage": {
                "candidates_with_indexed_citation": state_counts["cited"],
                "candidates_without_indexed_citation": len(rows) - state_counts["cited"],
            },
            "accepted_sidecar_mappings": sidecar_meta["accepted_count"],
            "accepted_sidecar_supplemental_invariants": sidecar_meta.get("supplemental_invariant_count", 0),
            "no_draft_or_submission_edits": True,
        },
        "candidate_rows": rows,
        "warnings": warnings,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "p1_candidate_triage_dogfood.json"
    md_path = out_dir / "p1_candidate_triage_dogfood.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    result["written"] = {"json": str(json_path), "markdown": str(md_path)}
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--invariants",
        type=Path,
        action="append",
        help=(
            "Explicit invariant JSONL source. May be passed multiple times. "
            "Overrides audited-primary defaults; passing extracted rows is broad opt-in."
        ),
    )
    parser.add_argument(
        "--include-extracted",
        action="store_true",
        help="Opt in to broad template-heavy extracted invariants in addition to audited-primary defaults.",
    )
    parser.add_argument("--max-suggestions", type=int, default=3)
    parser.add_argument("--json", action="store_true", help="Print compact run summary as JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    result = run_triage(
        args.workspace,
        args.out_dir,
        invariant_paths=args.invariants,
        include_extracted=args.include_extracted,
        max_suggestions=max(args.max_suggestions, 0),
    )
    if args.json:
        print(
            json.dumps(
                {
                    "schema": result["schema"],
                    "workspace": result["workspace"],
                    "summary": result["summary"],
                    "written": result["written"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"wrote {result['written']['json']}")
        print(f"wrote {result['written']['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
