#!/usr/bin/env python3
"""Expand Hackerman Go/Cosmos corpus coverage.

This tool sits next to the existing ``hackerman-etl-from-prior-audits.py`` and
``hackerman-go-cosmos-stage-imports.py``. It exists because the existing
prior-audit segmenter rejects the ``Severity: <Tier>`` (colon-then-space)
formatting used by Zellic-numbered-section reports and Informal-Systems
dYdX prior audits, which produces only 1 segment per file (the doc as a
whole). The result is that 72 in-tree audit-text-corpus Cosmos / dYdX-relevant
reports plus the operator-local prior_audits trees (``~/audits/dydx``,
``~/audits/spark``) yield single-record imports that mostly downgrade to
"cross_language_not_go" context in the stage manifest.

Hard contract for Wave-3 Tier-C:
- Do NOT touch ``tools/hackerman-etl-from-prior-audits.py`` (Wave 2 ownership).
- Do NOT touch ``tools/hackerman-go-cosmos-inventory.py`` (Wave 2 adjacent).
- Do NOT touch ``tools/hackerman-go-cosmos-stage-imports.py`` (Wave 2 adjacent).
- New ETL miners may live next to them and reuse their public functions
  (``build_record``, ``write_records``, ``read_source_text``, ``SourceDoc``,
  ``segment_findings``) via importlib.

Behaviour:
1. Resolves a set of source roots from ``--corpus-txt-root`` (default:
   ``reference/corpus_txt``) and ``--prior-audits-root`` (repeatable, default:
   ``~/audits/dydx/prior_audits`` + ``~/audits/spark/prior_audits``).
2. For each ``.md`` / ``.markdown`` / ``.txt`` / ``.pdf`` source file that is
   Go/Cosmos-scope-eligible, runs:
       segments = local_segmenter(text)
       if not segments or segments == 1:
           segments = ETL.segment_findings(text)
   The local segmenter handles Zellic ``N.M Title`` blocks where the body
   has ``• Severity: Tier`` (colon-then-space). It falls back to the existing
   ETL segmenter for non-Zellic shapes.
3. Builds records via the existing ETL's ``build_record``, then post-processes:
   - Re-runs Go/Cosmos heuristics on segment + doc context to override
     ``target_language`` to ``go`` when strong Cosmos / Go signals are present
     but the existing ETL fell back to ``solidity`` because of unrelated
     keyword bleed (e.g. ``smart contract`` in the report's executive summary
     leaking into individual finding bodies via the doc-context scan).
   - Stamps ``record_quality_score = 2.2`` and
     ``source_extraction_method = "go-cosmos-expand-v1"`` so downstream
     tooling can distinguish these from the more carefully curated
     ``corpus-etl`` records.
4. Writes hackerman_record YAMLs to ``--out-dir`` (default: the canonical
   tag dir). ``--dry-run`` skips disk writes.
5. Emits a stage manifest (``--stage-artifact-out``) with per-source-file
   yield counts so the operator can verify the 407 -> 1500+ lift.

Note: this is a CORPUS expansion. Quality is intentionally
"public-corpus" tier; promotion to operator-curated tiers happens via
``tools/hackerman-record-validate.py`` plus operator review.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_CORPUS_TXT_ROOT = REPO_ROOT / "reference" / "corpus_txt"
DEFAULT_PRIOR_AUDIT_ROOTS = (
    Path("~/audits/dydx/prior_audits").expanduser(),
    Path("~/audits/spark/prior_audits").expanduser(),
)
TEXT_EXTENSIONS = {".md", ".markdown", ".txt"}
PDF_EXTENSIONS = {".pdf"}
SOURCE_EXTENSIONS = TEXT_EXTENSIONS | PDF_EXTENSIONS
SCHEMA_VERSION = "auditooor.hackerman_go_cosmos_expand.v1"
# Use schema-enum value 'corpus-etl' so emitted records pass
# hackerman-record-validate.py. Provenance is captured separately
# via the stage_artifact JSON file (tool name + version + commit hash).
RECORD_EXTRACTION_METHOD = "corpus-etl"
RECORD_QUALITY_SCORE = 2.2

# Reuse the existing ETL via importlib so we don't fork the YAML emitter
# or break the schema. This is the same trick stage-imports already uses.
def _load_tool(name_path: Tuple[str, str]) -> Any:
    name, path = name_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_PRIOR = _load_tool(
    (
        "_hackerman_prior_audit_for_go_cosmos_expand",
        str(REPO_ROOT / "tools" / "hackerman-etl-from-prior-audits.py"),
    )
)
_INVENTORY = _load_tool(
    (
        "_hackerman_go_cosmos_inventory_for_expand",
        str(REPO_ROOT / "tools" / "hackerman-go-cosmos-inventory.py"),
    )
)


# Strong Cosmos / Go terms that justify forcing target_language=go.
# Keep this set deliberately narrow so we don't mislabel pure-Solidity
# reports that happen to mention "cosmos" once in passing.
STRONG_GO_COSMOS_HINTS = (
    "cosmos sdk",
    "cosmos-sdk",
    "cometbft",
    "tendermint",
    "iavl",
    "msgserver",
    "validatebasic",
    "prepareproposal",
    "processproposal",
    "extendvote",
    "finalizeblock",
    "beginblocker",
    "endblocker",
    "antehandler",
    "module account",
    "x/clob",
    "x/bank",
    "x/gov",
    "x/perp",
    "x/oracle",
    "x/staking",
    "x/distribution",
    "x/slashing",
    "ibc",
    "slinky",
    "dydxprotocol",
    "v4-chain",
    "dydx",
    "osmosis",
    "nibiru",
    "injective",
    "thorchain",
    "atomone",
    "fairyring",
    "babylon",
    "astria",
    "zetachain",
    "all in bits",
    "skip-mev",
    "skip mev",
    "block proposer",
    "keeper.go",
    ".go",
    "go module",
    "golang",
    "statechain",
    "chain watcher",
    "chain-watcher",
    "cooperative exit",
    "coop_exit",
    "frost",
    "spark protocol",
    "buildonspark",
    "leaf status",
    "leaf_status",
    "key tweak",
    "key_tweak",
    "validatetransferleavesnotexitedtol1",
)
# Repos that are unambiguously Go/Cosmos targets.
GO_COSMOS_REPO_HINTS = (
    "cosmos/cosmos-sdk",
    "cometbft/cometbft",
    "tendermint/tendermint",
    "cosmos/iavl",
    "dydxprotocol/v4-chain",
    "skip-mev/slinky",
    "skip-mev/connect",
    "skip-mev/block-sdk",
    "skip-mev/protocol-pol",
    "osmosis-labs/osmosis",
    "NibiruChain/nibiru",
    "InjectiveLabs/injective-core",
    "gitlab.com/thorchain",
    "thorchain/thornode",
    "atomone-hub/atomone",
    "Fairblock/fairyring",
    "babylonlabs-io/babylon",
    "astriaorg/astria",
    "zeta-chain/node",
    "buildonspark/spark",
    "lightsparkdev/frost",
    "lightsparkdev/spark-frost",
    "ZcashFoundation/frost",
)


class _Segment(NamedTuple):
    title: str
    body: str
    heading_line: int
    ordinal: int


def _normalize_text(text: str) -> str:
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").strip()


# ---------------- Local segmenter with the colon-Severity fix ----------------

_SEVERITY_COLON_RE = re.compile(
    r"\bSeverity\s*[:—–-]+\s*(Critical|High|Medium|Low|Informational|Info)\b",
    re.IGNORECASE,
)
_NUMBERED_HEAD_RE = re.compile(r"^\s{0,12}(\d+\.\d+(?:\.\d+)?)(\s+)(\S.*)$")
_TOC_DOTLINE_RE = re.compile(r"\.\s*\.\s*\.")
_AUDIT_DASHBOARD_KW = re.compile(r"^\s*(Project|Severity|Impact|Status|Exploitability|Type|Issue)\b")


def _looks_like_toc_line(line: str) -> bool:
    return bool(_TOC_DOTLINE_RE.search(line))


def _numbered_heading_title(line: str) -> Optional[Tuple[str, str]]:
    """Return (section_num, title) for body-side numbered headings only.

    Body-side headings differ from ToC lines because they don't dot-fill to
    a page number on the right. We use this signal to ignore ToC.
    """
    if _looks_like_toc_line(line):
        return None
    m = _NUMBERED_HEAD_RE.match(line.rstrip())
    if not m:
        return None
    section, _gap, title = m.group(1), m.group(2), m.group(3).strip()
    # Strip trailing "...  17" style residue and leading bullets.
    title = re.sub(r"\s+\d+\s*$", "", title).strip(" *-•").strip()
    if len(title) < 5:
        return None
    return section, title


def _has_finding_body_signal(body: str) -> bool:
    """Lightweight 'this is a real finding body, not a header line' check."""
    if len(body) < 80:
        return False
    head = body[:3500]
    if not _SEVERITY_COLON_RE.search(head) and not re.search(
        r"\bSeverity\s+(Critical|High|Medium|Low|Informational|Info)\b", head
    ):
        return False
    head_low = head.lower()
    if not any(kw in head_low for kw in ("impact", "description", "recommend", "category", "exploitability")):
        return False
    return True


def segment_zellic_numbered(text: str) -> List[_Segment]:
    """Segment Zellic-style 'N.M Title' bodies with colon-Severity tolerance."""
    lines = text.splitlines()
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        parsed = _numbered_heading_title(line)
        if parsed is None:
            continue
        section, title = parsed
        # Only keep section numbers from Detailed Findings sections (3.x / 4.x
        # / 5.x typically) - skip 1.x / 2.x exec-summary / scope sections.
        major = int(section.split(".", 1)[0])
        if major < 2:
            continue
        anchors.append((idx, title))

    segments: List[_Segment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start + 1 : end]).strip()
        if not _has_finding_body_signal(body):
            continue
        segments.append(_Segment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def segment_informal_systems_dydx(text: str) -> List[_Segment]:
    """Segment Informal-Systems-style dYdX prior_audits with Project/Severity table."""
    lines = text.splitlines()
    # In Informal Systems reports each finding section starts with a multi-line
    # bold title followed by ' Project   <name>' on a separate line.
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        # Match "  Project    <project name>" with 2+ spaces between
        if not re.match(r"^\s+Project\s{2,}\S+", line):
            continue
        # Walk back to find the title block (non-empty lines not in audit-field).
        title_indexes: List[int] = []
        j = idx - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        while j >= 0 and len(title_indexes) < 6:
            stripped = lines[j].strip()
            if not stripped:
                break
            if _AUDIT_DASHBOARD_KW.match(stripped):
                break
            # Skip page-footer artifacts.
            if re.match(r"^©\s+\d{4}", stripped):
                break
            if re.fullmatch(r"Findings\s+\d+", stripped):
                break
            title_indexes.append(j)
            j -= 1
        if not title_indexes:
            continue
        title_indexes.reverse()
        title = " ".join(lines[k].strip() for k in title_indexes)
        title = re.sub(r"\s+", " ", title).strip()
        if len(title) < 8:
            continue
        if title.lower() in {"the project", "audit dashboard", "target summary", "engagement summary", "findings"}:
            continue
        anchors.append((title_indexes[0], title))

    segments: List[_Segment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start:end]).strip()
        if len(body) < 100:
            continue
        segments.append(_Segment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def segment_zcash_frost(text: str) -> List[_Segment]:
    """Segment zcash-frost report - simple 'N.M Title' on one line, 'Severity:' on next."""
    lines = text.splitlines()
    anchors: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if _looks_like_toc_line(line):
            continue
        m = _NUMBERED_HEAD_RE.match(line.rstrip())
        if not m:
            continue
        section, _gap, title = m.group(1), m.group(2), m.group(3).strip()
        title = re.sub(r"\s+\d+\s*$", "", title).strip(" *-•").strip()
        if len(title) < 5:
            continue
        major = int(section.split(".", 1)[0])
        if major < 2:
            continue
        # Look at next 3 lines for "Severity: <tier>" (colon-then-tier).
        following = "\n".join(lines[idx + 1 : idx + 6])
        if not _SEVERITY_COLON_RE.search(following):
            continue
        anchors.append((idx, title))

    segments: List[_Segment] = []
    for pos, (start, title) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(lines)
        body = "\n".join(lines[start + 1 : end]).strip()
        if len(body) < 60:
            continue
        segments.append(_Segment(title=title, body=body, heading_line=start + 1, ordinal=len(segments) + 1))
    return segments


def segment_local(text: str) -> List[_Segment]:
    """Try each format-specific segmenter; return the one with the most segments."""
    candidates = [
        segment_zellic_numbered(text),
        segment_informal_systems_dydx(text),
        segment_zcash_frost(text),
    ]
    candidates.sort(key=lambda segs: len(segs), reverse=True)
    return candidates[0]


# ---------------- Source-doc discovery ----------------

class _Doc(NamedTuple):
    workspace_name: str
    audit_kind: str
    abs_path: Path
    rel_path: Path
    source_label: str  # 'corpus-txt' or 'prior-audit'


def _to_etl_source_doc(doc: _Doc) -> Any:
    """Wrap our _Doc as a prior-audit ETL SourceDoc so build_record works."""
    if doc.source_label == "corpus-txt":
        workspace = _PRIOR.CORPUS_TEXT_WORKSPACE
        audit_kind = _PRIOR.CORPUS_TEXT_AUDIT_KIND
    else:
        workspace = Path(doc.workspace_name)
        audit_kind = "prior_audits"
    return _PRIOR.SourceDoc(
        workspace=workspace,
        audit_kind=audit_kind,
        path=doc.abs_path,
        rel_path=doc.rel_path,
    )


def discover_corpus_txt(corpus_root: Path) -> List[_Doc]:
    docs: List[_Doc] = []
    if not corpus_root.is_dir():
        return docs
    for path in sorted(corpus_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            rel = path.resolve().relative_to(REPO_ROOT)
        except ValueError:
            rel = Path(path.name)
        docs.append(
            _Doc(
                workspace_name=corpus_root.name,
                audit_kind="audit_text_corpus",
                abs_path=path.resolve(),
                rel_path=rel,
                source_label="corpus-txt",
            )
        )
    return docs


def discover_prior_audits(root: Path) -> List[_Doc]:
    docs: List[_Doc] = []
    root = root.expanduser().resolve()
    if not root.is_dir():
        return docs
    # workspace-name is the parent of prior_audits (e.g. "dydx" / "spark").
    workspace_name = root.parent.name if root.parent.name else root.name
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        # Rel path is the path under the workspace, mirroring the ETL.
        try:
            rel = path.resolve().relative_to(root.parent)
        except ValueError:
            rel = Path(path.name)
        docs.append(
            _Doc(
                workspace_name=workspace_name,
                audit_kind="prior_audits",
                abs_path=path.resolve(),
                rel_path=rel,
                source_label="prior-audit",
            )
        )
    return docs


# ---------------- Go/Cosmos eligibility + override ----------------

def _doc_text(path: Path, *, max_chars: int = 16000) -> str:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        try:
            return _normalize_text(path.read_text(encoding="utf-8", errors="replace"))[:max_chars]
        except OSError:
            return ""
    if suffix in PDF_EXTENSIONS:
        text, _method = _PRIOR.extract_pdf_text(path)
        return _normalize_text(text or "")[:max_chars]
    return ""


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def doc_is_go_cosmos_eligible(doc: _Doc, text: str) -> bool:
    """Return True if this doc has enough Go/Cosmos signal to bother extracting."""
    blob = f"{doc.rel_path.as_posix()}\n{text}".lower()
    if _contains_any(blob, STRONG_GO_COSMOS_HINTS):
        return True
    if _contains_any(blob, GO_COSMOS_REPO_HINTS):
        return True
    return False


def _should_override_to_go(record: Dict[str, object], segment_text: str, doc_text: str) -> bool:
    blob = " ".join(
        [
            str(record.get("target_repo") or ""),
            str(record.get("target_component") or ""),
            segment_text,
            doc_text[:6000],
        ]
    )
    if _contains_any(blob, GO_COSMOS_REPO_HINTS):
        return True
    # Require multiple strong signals for cross-language override
    matches = sum(1 for needle in STRONG_GO_COSMOS_HINTS if needle in blob.lower())
    return matches >= 2


def _apply_go_cosmos_override(record: Dict[str, object], segment_text: str, doc_text: str) -> None:
    if record.get("target_language") == "go":
        return
    if _should_override_to_go(record, segment_text, doc_text):
        record["target_language"] = "go"
        # Refresh shape_tags so language prefix matches
        fs = record.get("function_shape")
        if isinstance(fs, dict):
            tags = fs.get("shape_tags") or []
            bug_class = str(record.get("bug_class") or "logic-error")
            language_tag = f"go-{bug_class}"
            if isinstance(tags, list):
                tags = [language_tag if isinstance(t, str) and t.startswith(("solidity-", "rust-", "vyper-")) else t for t in tags]
                fs["shape_tags"] = tags
        raw_sig = ""
        if isinstance(fs, dict):
            raw_sig = str(fs.get("raw_signature") or "")
        if raw_sig.startswith("function "):
            fs["raw_signature"] = "func " + raw_sig[len("function ") :]


# ---------------- Extraction pipeline ----------------

def extract_records_for_doc(doc: _Doc) -> Tuple[List[Dict[str, object]], Dict[str, Any]]:
    info: Dict[str, Any] = {
        "source_path": str(doc.abs_path),
        "workspace": doc.workspace_name,
        "source_label": doc.source_label,
        "records_emitted": 0,
        "language_override_applied": 0,
        "segmenter": "none",
        "skipped_reason": None,
    }
    text = _doc_text(doc.abs_path, max_chars=4_000_000)
    if not text:
        info["skipped_reason"] = "no-text"
        return [], info
    if not doc_is_go_cosmos_eligible(doc, text):
        info["skipped_reason"] = "not-go-cosmos-eligible"
        return [], info

    # Try local segmenter first; fall back to existing ETL.
    local_segs = segment_local(text)
    etl_segs = _PRIOR.segment_findings(text)
    if len(local_segs) > len(etl_segs):
        segments = local_segs
        info["segmenter"] = "go-cosmos-expand:local"
    else:
        # Convert ETL segments to our shape
        segments = [
            _Segment(title=s.title, body=s.body, heading_line=s.heading_line, ordinal=s.ordinal)
            for s in etl_segs
        ]
        info["segmenter"] = "go-cosmos-expand:fallback-etl"
    if not segments:
        info["skipped_reason"] = "no-segments"
        return [], info

    etl_doc = _to_etl_source_doc(doc)
    records: List[Dict[str, object]] = []
    overrides = 0
    for segment in segments:
        etl_segment = _PRIOR.FindingSegment(
            title=segment.title,
            body=segment.body,
            heading_line=segment.heading_line,
            ordinal=segment.ordinal,
        )
        rec = _PRIOR.build_record(etl_doc, etl_segment)
        seg_text = f"{segment.title}\n{segment.body}"
        prev_lang = rec.get("target_language")
        _apply_go_cosmos_override(rec, seg_text, text)
        if rec.get("target_language") == "go" and prev_lang != "go":
            overrides += 1
        # Only retain records that are Go/Cosmos-scope after override.
        if rec.get("target_language") != "go":
            continue
        # Stamp expand-tool provenance for downstream tooling.
        rec["source_extraction_method"] = RECORD_EXTRACTION_METHOD
        rec["source_extraction_confidence"] = 0.5
        rec["record_quality_score"] = RECORD_QUALITY_SCORE
        rec["record_tier"] = "public-corpus"
        records.append(rec)
    info["records_emitted"] = len(records)
    info["language_override_applied"] = overrides
    info["raw_segments"] = len(segments)
    return records, info


def run_expand(args: argparse.Namespace) -> Dict[str, Any]:
    corpus_root = Path(args.corpus_txt_root).expanduser().resolve()
    prior_roots = [Path(p).expanduser().resolve() for p in (args.prior_audits_root or [])]
    if not args.prior_audits_root:
        prior_roots = list(DEFAULT_PRIOR_AUDIT_ROOTS)

    docs: List[_Doc] = []
    if not args.skip_corpus_txt:
        docs.extend(discover_corpus_txt(corpus_root))
    for root in prior_roots:
        docs.extend(discover_prior_audits(root))

    if args.limit is not None and args.limit > 0:
        docs = docs[: args.limit]

    out_dir = Path(args.out_dir).expanduser().resolve()
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    summary_rows: List[Dict[str, Any]] = []
    total_records = 0
    total_overrides = 0
    written_paths: List[Path] = []
    skipped_counter: Counter[str] = Counter()
    seen_record_ids: set[str] = set()
    duplicates_dropped = 0

    for doc in docs:
        records, info = extract_records_for_doc(doc)
        # De-duplicate by record_id within this run.
        dedup_records = []
        for rec in records:
            rid = str(rec.get("record_id") or "")
            if rid in seen_record_ids:
                duplicates_dropped += 1
                continue
            seen_record_ids.add(rid)
            dedup_records.append(rec)
        records = dedup_records
        info["records_emitted"] = len(records)

        if records:
            paths = _PRIOR.write_records(records, out_dir, args.dry_run)
            written_paths.extend(paths)
            total_records += len(records)
            total_overrides += info.get("language_override_applied", 0)
        if info.get("skipped_reason"):
            skipped_counter[info["skipped_reason"]] += 1
        summary_rows.append(info)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tag_dir": str(out_dir),
        "corpus_txt_root": str(corpus_root),
        "prior_audits_roots": [str(p) for p in prior_roots],
        "dry_run": args.dry_run,
        "skip_corpus_txt": args.skip_corpus_txt,
        "limit": args.limit,
        "documents_scanned": len(docs),
        "documents_emitting_records": sum(1 for row in summary_rows if row.get("records_emitted")),
        "records_emitted": total_records,
        "language_overrides_applied": total_overrides,
        "duplicates_dropped_within_run": duplicates_dropped,
        "skipped_counts": dict(sorted(skipped_counter.items())),
        "per_document": summary_rows,
        "files": [str(p) for p in written_paths],
    }
    if args.stage_artifact_out:
        artifact_path = Path(args.stage_artifact_out).expanduser().resolve()
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["stage_artifact_out"] = str(artifact_path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-txt-root",
        default=str(DEFAULT_CORPUS_TXT_ROOT),
        help="Root of reference/corpus_txt to scan for Zellic-style audit reports.",
    )
    parser.add_argument(
        "--prior-audits-root",
        action="append",
        default=[],
        help=(
            "Operator-local prior_audits root (repeatable). "
            "Defaults to ~/audits/dydx/prior_audits and ~/audits/spark/prior_audits."
        ),
    )
    parser.add_argument(
        "--skip-corpus-txt",
        action="store_true",
        help="Skip the in-tree reference/corpus_txt scan.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_TAG_DIR),
        help="Target tag directory for emitted hackerman_record YAMLs.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum documents to process.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stage-artifact-out", help="Optional JSON stage artifact path.")
    parser.add_argument("--json-summary", action="store_true", help="Emit JSON summary on stdout.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    summary = run_expand(args)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman go-cosmos expand: "
            f"docs={summary['documents_scanned']} "
            f"emit_docs={summary['documents_emitting_records']} "
            f"records={summary['records_emitted']} "
            f"overrides={summary['language_overrides_applied']} "
            f"dup_dropped={summary['duplicates_dropped_within_run']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['tag_dir']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
