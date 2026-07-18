#!/usr/bin/env python3
"""Wave-5 L2 Hackerman ETL: SWC registry (Smart Contract Weakness Classification).

Mines the canonical SWC registry - the 37-entry taxonomy of Solidity smart
contract weakness classes maintained by the SmartContractSecurity working
group at ``github.com/SmartContractSecurity/SWC-registry``. Each
``entries/docs/SWC-<NNN>.md`` file is one canonical weakness-class entry
(SWC-100 .. SWC-136) carrying a title, a CWE relationship, a description,
and a remediation block.

The SWC registry is a TAXONOMY, not an archive of individual incidents.
Each record therefore carries a first-class
``verification_tier = tier-3-synthetic-taxonomy-anchored`` (Rule 37). The
tier is honest: an SWC entry is a deterministic, source-anchored weakness
*class* (it carries a canonical SWC id and a real per-entry URL) but it is
not an individually-verified incident, so it is NOT acceptable as sole
evidence for HIGH+ findings (Rule 37 severity-vs-tier composition). It is a
clean detector-taxonomy anchor for breadth.

Each emitted hackerman record cites the canonical per-entry GitHub blob URL
(``https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-<NNN>.md``)
in ``record_source_url`` so the record's claim is independently verifiable
from the URL alone.

Hard rules (M14-trap / real-source discipline, per ``~/.claude/CLAUDE.md``):

* Honest-zero gate (mirrors the Wave-5 L1 go-vuln-db miner pattern): the
  import / dry-run path performs ZERO network I/O. Network I/O requires
  ``--fetch``. With neither ``--fetch`` nor a populated cache / injected
  bytes, the miner prints ``BLOCKED-NO-REAL-SOURCE`` to stderr and emits
  zero records. There are NO training-data-recalled SWC entries in this
  file - the registry markdown is parsed from the real source bytes.
* ``verification_tier = tier-3-synthetic-taxonomy-anchored`` -- the SWC
  registry is a taxonomy, not an individual-incident archive. The tier is
  a first-class field set at emit time on every record (Rule 37).
* The miner refuses to emit any record lacking a canonical ``SWC-<NNN>``
  id parsed from the source filename.

CLI:

    # Honest-zero (no network, no cache) -> BLOCKED-NO-REAL-SOURCE:
    python3 tools/hackerman-etl-from-swc-registry.py \\
        --out-dir audit/corpus_tags/tags/hackerman_swc_registry --dry-run

    # Live pull:
    python3 tools/hackerman-etl-from-swc-registry.py \\
        --out-dir audit/corpus_tags/tags/hackerman_swc_registry --fetch

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-swc-registry.py \\
        --out-dir audit/corpus_tags/tags/hackerman_swc_registry \\
        --cache-file /tmp/swc-cache.json

Rule 37: this miner emits at tier-3-synthetic-taxonomy-anchored.

Shape anchor: ``tools/hackerman-etl-from-go-vuln-db.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Rule 37 (Check #77): CVE/GHSA verifier shim - works both when run
# from repo-root (`python3 tools/<miner>.py`) and as a module.
try:
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore
except ImportError:  # pragma: no cover - bootstrap when tools not on sys.path
    import os as _r37_os
    import sys as _r37_sys
    _r37_sys.path.insert(0, _r37_os.path.dirname(_r37_os.path.dirname(_r37_os.path.abspath(__file__))))
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.swc_registry.summary.v1"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

# SWC-registry canonical paths (per upstream repo layout).
SWC_REPO_OWNER = "SmartContractSecurity/SWC-registry"
SWC_DEFAULT_BRANCH = "master"
SWC_ENTRIES_DIR = "entries/docs"
SWC_RAW_BASE = (
    f"https://raw.githubusercontent.com/{SWC_REPO_OWNER}/"
    f"{SWC_DEFAULT_BRANCH}/{SWC_ENTRIES_DIR}"
)
SWC_BLOB_BASE = (
    f"https://github.com/{SWC_REPO_OWNER}/blob/"
    f"{SWC_DEFAULT_BRANCH}/{SWC_ENTRIES_DIR}"
)
SWC_CONTENTS_API = f"/repos/{SWC_REPO_OWNER}/contents/{SWC_ENTRIES_DIR}"

# The canonical SWC id range. SWC ids run SWC-100 .. SWC-136 (37 entries);
# this range is used ONLY to bound the contents listing and as the cache
# key set - it carries NO weakness content (that is parsed from the real
# registry markdown). Gaps in the live listing are handled gracefully.
SWC_ID_MIN = 100
SWC_ID_MAX = 136

_SWC_FILE_RE = re.compile(r"^SWC-(\d{3})\.md$")
_SWC_ID_RE = re.compile(r"SWC-(\d{3})")


# ---------------------------------------------------------------------------
# Slug / YAML helpers (shape-matched to the go-vuln-db / RustSec miners)
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            lines.append(
                                f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}"
                            )
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Network fetch (gated behind --fetch; honest-zero otherwise)
# ---------------------------------------------------------------------------


def _curl_get(url: str) -> Optional[bytes]:
    """Fetch ``url`` via ``curl -fsSL``. Returns body bytes or ``None``."""
    try:
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "45", url],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _gh_api(path: str) -> Optional[Any]:
    """Call ``gh api <path>`` and return the parsed JSON or ``None``."""
    try:
        proc = subprocess.run(
            ["gh", "api", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def list_swc_files(*, fetch_live: bool) -> List[str]:
    """Return the ``SWC-<NNN>.md`` filenames present in the registry.

    Uses the GitHub contents API when ``fetch_live``; falls back to the
    deterministic SWC-100..136 enumeration when the API is unreachable so
    a live pull can still proceed off the canonical id range.
    """
    if fetch_live:
        listing = _gh_api(SWC_CONTENTS_API)
        if isinstance(listing, list):
            names: List[str] = []
            for entry in listing:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or ""
                if _SWC_FILE_RE.match(name):
                    names.append(name)
            if names:
                return sorted(names)
    # Deterministic id-range fallback - bounds only, no content.
    return [f"SWC-{n}.md" for n in range(SWC_ID_MIN, SWC_ID_MAX + 1)]


def fetch_payload(
    *,
    fetch_live: bool,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
) -> Optional[Dict[str, Any]]:
    """Build the cached payload ``{"entries": {SWC-<NNN>: "<markdown>"}}``.

    Returns ``None`` when no real source is available (honest-zero gate):
    no cache file, no injected prefetched bytes, and ``--fetch`` not set.
    """
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))

    prefetched = dict(prefetched or {})

    # Honest-zero gate: zero network and zero injected bytes -> BLOCKED.
    if not fetch_live and not prefetched:
        return None

    def _get_text(url: str) -> Optional[str]:
        if url in prefetched:
            raw = prefetched[url]
        elif fetch_live:
            raw = _curl_get(url)
        else:
            return None
        if raw is None:
            return None
        return raw.decode("utf-8", errors="replace")

    filenames = list_swc_files(fetch_live=fetch_live)
    entries: Dict[str, str] = {}
    for fname in filenames:
        m = _SWC_FILE_RE.match(fname)
        if not m:
            continue
        swc_id = f"SWC-{m.group(1)}"
        text = _get_text(f"{SWC_RAW_BASE}/{fname}")
        if text is None or not text.strip():
            continue
        entries[swc_id] = text

    payload: Dict[str, Any] = {
        "_meta": {
            "files_listed": len(filenames),
            "entries_fetched": len(entries),
        },
        "entries": entries,
    }
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
    return payload


# ---------------------------------------------------------------------------
# SWC markdown parser.
#
# Each entries/docs/SWC-<NNN>.md file is a markdown page with H1/H2
# headers. We parse the canonical sections:
#
#     # Title
#     <weakness title>
#     ## Relationships
#     [CWE-NNN: ...](https://cwe.mitre.org/...)
#     ## Description
#     <prose>
#     ## Remediation
#     <prose>
#
# Earlier-leading boilerplate ("no longer actively maintained") and the
# trailing "## Samples" code blocks are ignored.
# ---------------------------------------------------------------------------


def _split_sections(text: str) -> Dict[str, str]:
    """Return a ``{header-lowercase: body}`` map of markdown sections.

    Both ``#`` and ``##`` headers are treated as section boundaries; the
    body is everything up to the next header of any level.
    """
    sections: Dict[str, str] = {}
    current: Optional[str] = None
    buf: List[str] = []
    for line in text.splitlines():
        m = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if m:
            if current is not None:
                sections[current] = "\n".join(buf).strip()
            current = m.group(1).strip().lower()
            buf = []
        else:
            if current is not None:
                buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).strip()
    return sections


def _extract_cwe(relationships: str) -> Tuple[Optional[str], str]:
    """Return ``(cwe-id, cwe-title)`` from the Relationships section body."""
    if not relationships:
        return None, ""
    m = re.search(r"(CWE-\d+)\s*:?\s*([^\]\)\n]*)", relationships)
    if not m:
        m2 = re.search(r"(CWE-\d+)", relationships)
        return (m2.group(1) if m2 else None), ""
    return m.group(1), one_line(m.group(2), "", max_len=240)


def parse_swc_markdown(text: str) -> Dict[str, Any]:
    """Parse one SWC ``.md`` entry into a structured dict.

    Returns ``{"title", "cwe_id", "cwe_title", "description", "remediation"}``.
    The title falls back to an empty string if the ``# Title`` section is
    absent or empty (handled at emit time).
    """
    sections = _split_sections(text)
    # The SWC convention is a "# Title" header followed by the weakness
    # name as the section body.
    title = one_line(sections.get("title"), "", max_len=240)
    cwe_id, cwe_title = _extract_cwe(sections.get("relationships") or "")
    description = one_line(sections.get("description"), "", max_len=4000)
    remediation = one_line(sections.get("remediation"), "", max_len=2000)
    return {
        "title": title,
        "cwe_id": cwe_id,
        "cwe_title": cwe_title,
        "description": description,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# SWC weakness -> hackerman taxonomy.
#
# The SWC registry has no structured category enum; we derive a
# conservative attack_class / impact_class / severity from the parsed
# title text via a closed keyword table. Unmatched entries fall back to a
# generic SWC-weakness class. attack_class is tagged off the SWC id so it
# is deterministically traceable to the source entry.
# ---------------------------------------------------------------------------

_TITLE_TABLE: Tuple[Tuple[str, str, str, str], ...] = (
    # keyword (lowercase), attack_class, impact_class, severity
    ("reentrancy", "swc-reentrancy", "theft", "high"),
    ("integer overflow", "swc-integer-overflow", "precision-loss", "medium"),
    ("integer underflow", "swc-integer-overflow", "precision-loss", "medium"),
    ("arithmetic", "swc-integer-overflow", "precision-loss", "medium"),
    ("access control", "swc-access-control", "privilege-escalation", "high"),
    ("authorization", "swc-access-control", "privilege-escalation", "high"),
    ("default visibility", "swc-default-visibility", "privilege-escalation", "high"),
    ("unprotected", "swc-unprotected-function", "privilege-escalation", "high"),
    ("delegatecall", "swc-delegatecall", "privilege-escalation", "high"),
    ("selfdestruct", "swc-unexpected-selfdestruct", "freeze", "high"),
    ("uninitialized storage", "swc-uninitialized-storage", "privilege-escalation", "high"),
    ("denial of service", "swc-denial-of-service", "dos", "medium"),
    ("dos", "swc-denial-of-service", "dos", "medium"),
    ("unchecked", "swc-unchecked-return-value", "dos", "medium"),
    ("call to the unknown", "swc-unchecked-low-level-call", "theft", "medium"),
    ("transaction order", "swc-transaction-ordering", "theft", "medium"),
    ("front", "swc-transaction-ordering", "theft", "medium"),
    ("timestamp", "swc-timestamp-dependence", "precision-loss", "medium"),
    ("randomness", "swc-weak-randomness", "theft", "medium"),
    ("tx.origin", "swc-tx-origin-auth", "privilege-escalation", "high"),
    ("signature", "swc-signature-malleability", "theft", "high"),
    ("replay", "swc-signature-replay", "theft", "high"),
    ("short address", "swc-short-address", "theft", "medium"),
    ("assert violation", "swc-assert-violation", "dos", "low"),
    ("shadowing", "swc-state-shadowing", "precision-loss", "low"),
    ("hash collision", "swc-hash-collision", "theft", "medium"),
    ("typographical", "swc-typographical-error", "precision-loss", "low"),
    ("requirement violation", "swc-requirement-violation", "dos", "low"),
    ("deprecated", "swc-deprecated-construct", "dos", "low"),
    ("floating pragma", "swc-floating-pragma", "dos", "low"),
    ("outdated compiler", "swc-outdated-compiler", "dos", "low"),
    ("code with no effects", "swc-dead-code", "dos", "low"),
    ("incorrect inheritance", "swc-inheritance-order", "privilege-escalation", "medium"),
    ("arbitrary jump", "swc-arbitrary-jump", "privilege-escalation", "high"),
    ("write to arbitrary", "swc-arbitrary-storage-write", "privilege-escalation", "high"),
    ("presence of unused", "swc-unused-variables", "dos", "low"),
    ("message call with hardcoded gas", "swc-hardcoded-gas", "dos", "low"),
)


def _classify(title: str, description: str) -> Tuple[str, str, str]:
    """Return ``(attack_class, impact_class, severity)`` from the entry text."""
    blob = f"{title} {description}".lower()
    for kw, ac, ic, sev in _TITLE_TABLE:
        if kw in blob:
            return ac, ic, sev
    return "swc-weakness-class", "dos", "low"


def _dollar_class(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    return "non-financial"


def _impact_actor(impact_class: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    return "arbitrary-user"


def _record_id(swc_id: str) -> str:
    sid_slug = slugify(swc_id, max_len=64) or "swc-unknown"
    payload = f"swc-registry|{swc_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    rid = f"swc-registry:{sid_slug}:{digest}"
    return rid[:160]


def _function_shape(
    swc_id: str,
    attack_class: str,
    cwe_id: Optional[str],
) -> Dict[str, Any]:
    shape_tags: List[str] = [
        slugify(swc_id, max_len=64),
        "swc-registry",
        slugify(attack_class, max_len=64),
    ]
    if cwe_id:
        shape_tags.append(slugify(cwe_id, max_len=64))
    seen: set = set()
    uniq: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    if not uniq:
        uniq = ["swc-weakness"]
    return {"raw_signature": f"swc-registry :: {swc_id}"[:500], "shape_tags": uniq}


def _required_preconditions(
    swc_id: str,
    cwe_id: Optional[str],
    blob_url: str,
) -> List[str]:
    out: List[str] = [
        f"Reference SWC registry entry at {blob_url}",
        f"Weakness-class id {swc_id}",
    ]
    if cwe_id:
        out.append(f"Related weakness {cwe_id}")
    out.append(f"verification_tier={VERIFICATION_TIER}")
    out.append(
        "SWC registry is a taxonomy anchor; not sole evidence for HIGH+ "
        "findings (Rule 37 severity-vs-tier composition)"
    )
    seen: set = set()
    uniq: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            uniq.append(cleaned)
    return uniq


def _fix_pattern(remediation: str, title: str) -> str:
    if remediation:
        return one_line(
            remediation,
            "Apply the SWC registry remediation guidance for this weakness.",
            max_len=900,
        )
    return one_line(
        f"Apply the canonical remediation for the {title or 'SWC'} weakness "
        f"class per the SWC registry entry.",
        "Apply the SWC registry remediation guidance for this weakness.",
        max_len=900,
    )


def _anti_pattern(title: str, attack_class: str) -> str:
    return one_line(
        f"Shipping Solidity code exhibiting the {title or attack_class} "
        f"weakness class without the SWC-registry remediation; ignoring "
        f"the canonical SWC taxonomy entry.",
        "Shipping code with a documented SWC weakness class unaddressed.",
        max_len=900,
    )


def _attacker_action_sequence(
    swc_id: str,
    title: str,
    description: str,
    attack_class: str,
) -> str:
    text = title or swc_id
    if description:
        text = f"{text}. {description}"
    text = re.sub(r"\s+", " ", text).strip()
    marker = (
        f" [swc_id={swc_id}; attack_class={attack_class}; "
        f"verification_tier={VERIFICATION_TIER}]"
    )
    body_max = 4900 - len(marker)
    body = one_line(text, "SWC registry weakness class", max_len=body_max)
    return (body + marker).strip()


def entry_to_record(
    *,
    swc_id: str,
    parsed: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build one schema-v1.1 hackerman record from one parsed SWC entry.

    Returns ``None`` when ``swc_id`` is not a canonical ``SWC-<NNN>`` id.
    """
    if not isinstance(swc_id, str) or not _SWC_ID_RE.fullmatch(swc_id):
        return None
    title = parsed.get("title") or ""
    description = parsed.get("description") or ""
    remediation = parsed.get("remediation") or ""
    cwe_id = parsed.get("cwe_id")
    attack_class, impact_class, severity = _classify(title, description)
    blob_url = f"{SWC_BLOB_BASE}/{swc_id}.md"
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id(swc_id),
        "source_audit_ref": one_line(
            blob_url, f"swc-registry:{swc_id}", max_len=240
        ),
        "target_domain": "smart-contract",
        "target_language": "solidity",
        "target_repo": "SmartContractSecurity/SWC-registry",
        "target_component": one_line(
            f"{swc_id}:{title}" if title else f"{swc_id}:weakness",
            f"{swc_id}:weakness",
            max_len=240,
        ),
        "function_shape": _function_shape(swc_id, attack_class, cwe_id),
        "bug_class": "swc-weakness-taxonomy",
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(
            swc_id, title, description, attack_class
        ),
        "required_preconditions": _required_preconditions(
            swc_id, cwe_id, blob_url
        ),
        "impact_class": impact_class,
        "impact_actor": _impact_actor(impact_class),
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": _fix_pattern(remediation, title),
        "fix_anti_pattern_avoided": _anti_pattern(title, attack_class),
        "severity_at_finding": severity,
        "year": 2020,  # SWC registry content frozen since 2020 (per upstream).
        "record_tier": "public-corpus",
        "record_quality_score": 3.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,
        "verification_method": "manual",
        "verification_tier": VERIFICATION_TIER,
        "record_source_url": blob_url,
        "cross_language_analogues": [],
        "related_records": [],
    }
    if cwe_id:
        # SWC entries cite a CWE, not a CVE; surface it as a dedicated field.
        record["cwe_id"] = cwe_id
    return record


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_records(payload: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int]:
    """Return ``(emitted_records, entries_pre_filter)``.

    One record per SWC entry. Entries with no parseable content are
    skipped; the pre-filter count is the number of raw entries seen.
    """
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    entries_map = payload.get("entries") or {}
    pre_filter = 0
    for swc_id in sorted(entries_map.keys()):
        text = entries_map[swc_id]
        if not isinstance(text, str) or not text.strip():
            continue
        pre_filter += 1
        parsed = parse_swc_markdown(text)
        record = entry_to_record(swc_id=swc_id, parsed=parsed)
        if record is None:
            continue
        if record["record_id"] in seen_ids:
            continue
        seen_ids.add(record["record_id"])
        records.append(record)
    return records, pre_filter


def slug_for_record(record: Dict[str, Any]) -> str:
    target = record["target_component"].replace(":", "__").replace("/", "__")
    return slugify(target, max_len=140)


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    fetch_live: bool = False,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
) -> Dict[str, Any]:
    payload = fetch_payload(
        fetch_live=fetch_live,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
        prefetched=prefetched,
    )
    if payload is None:
        # Honest-zero gate (mirrors the Wave-5 L1 go-vuln-db miner pattern).
        sys.stderr.write(
            "BLOCKED-NO-REAL-SOURCE: SWC registry not fetched and no cache "
            "supplied. Re-run with --fetch (live pull) or --cache-file "
            "<payload.json> (offline replay). No records emitted; zero "
            "training-data-recalled SWC entries.\n"
        )
        return {
            "schema_version": SUMMARY_SCHEMA,
            "out_dir": str(out_dir),
            "dry_run": dry_run,
            "verification_tier": VERIFICATION_TIER,
            "blocked": True,
            "blocked_reason": "BLOCKED-NO-REAL-SOURCE",
            "records_pre_filter": 0,
            "records_emitted": 0,
            "by_attack_class": {},
            "by_impact_class": {},
            "by_severity": {},
            "sample_source_urls": [],
            "files": [],
            "errors": [],
        }

    records, records_pre_filter = build_records(payload)
    if limit is not None:
        records = records[:limit]

    by_attack_class: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    sample_urls: List[str] = []
    files: List[str] = []
    head_checks: Dict[str, str] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_attack_class[record["attack_class"]] = (
            by_attack_class.get(record["attack_class"], 0) + 1
        )
        by_impact[record["impact_class"]] = (
            by_impact.get(record["impact_class"], 0) + 1
        )
        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        if len(sample_urls) < 5:
            sample_urls.append(record["record_source_url"])

        slug = slug_for_record(record)
        rec_subdir = out_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))
        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            yaml_path.write_text(yaml_dump(record), encoding="utf-8")
            try:
                ok_emit, reason = pre_emit_check(record, strict=False)
                head_checks[record["record_id"]] = (
                    f"{'ok' if ok_emit else 'skip'}:{reason}"
                )
                if not ok_emit:
                    print(
                        f"r37-skip {reason}: {record.get('record_id', '?')}",
                        file=sys.stderr,
                    )
            except Exception as exc:  # pragma: no cover - verifier best-effort
                head_checks[record["record_id"]] = f"error:{exc}"

    meta = payload.get("_meta") or {}
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": VERIFICATION_TIER,
        "blocked": False,
        "files_listed": int(meta.get("files_listed") or 0),
        "entries_fetched": int(meta.get("entries_fetched") or 0),
        "records_pre_filter": records_pre_filter,
        "records_emitted": len(records),
        "by_attack_class": by_attack_class,
        "by_impact_class": by_impact,
        "by_severity": by_severity,
        "sample_source_urls": sample_urls,
        "files": files[:50],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Perform live network I/O against the SWC registry. Without it "
        "(and without --cache-file) the miner emits BLOCKED-NO-REAL-SOURCE.",
    )
    parser.add_argument(
        "--cache-file",
        help="Read a previously-cached SWC registry payload instead of fetching.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched payload to this path for later offline replay.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        fetch_live=bool(args.fetch),
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=Path(args.write_cache_file).expanduser().resolve()
        if args.write_cache_file
        else None,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        if summary.get("blocked"):
            print(
                "hackerman swc-registry ETL: BLOCKED-NO-REAL-SOURCE "
                "(re-run with --fetch or --cache-file)"
            )
        else:
            print(
                "hackerman swc-registry ETL: "
                f"records={summary['records_emitted']}/{summary['records_pre_filter']} "
                f"entries_fetched={summary.get('entries_fetched', 0)} "
                f"verification_tier={summary['verification_tier']} "
                f"by_severity={summary['by_severity']} "
                f"by_impact={summary['by_impact_class']} "
                f"errors={len(summary['errors'])}"
            )
    # Honest-zero BLOCKED is not an error exit; it is an explicit verdict.
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
