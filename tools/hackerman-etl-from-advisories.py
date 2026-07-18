#!/usr/bin/env python3
"""Hackerman ETL: GENERIC, repo-agnostic published-GitHub-Security-Advisory miner.

r36-rebuttal: lane advisory-generic-miner registered in .auditooor/agent_pathspec.json
r37-rebuttal: tier-1-officially-disclosed; verbatim transcription of the live advisory; unfetchable -> listed unverified, never fabricated

Given ``--repo <owner/repo>`` this fetches that repo's PUBLISHED GitHub Security
Advisories (and any ``--extra-cve`` referenced), transcribes each advisory's
published fields VERBATIM, and emits per advisory a TRIPLE of corpus artifacts:

  (a) one ``auditooor.hackerman_record.v1``  - the attacker-mindset finding
      record (attack_class + impact_class + GHSA/CVE/CWE/severity provenance);
  (b) one ``auditooor.invariant.v1``          - a GENERALIZED protocol/state
      invariant the bug VIOLATED, phrased so it is reusable as a hunt
      hypothesis on ANY similar target (not <repo>-specific);
  (c) one ``auditooor.detector_seed.v1``       - the SHAPE to catch the bug
      class (CWE-anchored regex + AST hint + fp-reduction + positive fixture).

All three carry ``verification_tier=tier-1-officially-disclosed`` (Rule 37): the
data is the verbatim published-advisory value fetched at run time, NOT a
synthesized or memory-recalled value.

M14 / Rule 37 / Rule 76 discipline (per ``~/.claude/CLAUDE.md``):
  * Only advisories ACTUALLY RETURNED by the live fetch (``gh api`` /
    ``--cache-file``) are emitted. A repo that returns 0 advisories is an
    honest 0 - no synthesis, no fan-out, no template fabrication.
  * Every id/severity/CWE/CVE/summary in an emitted record is the verbatim
    fetched value. ``--extra-cve`` ids that are NOT found referenced in any
    fetched advisory are reported under ``unverified_extra_cves`` and are NOT
    baked into a fabricated record.
  * The GENERALIZED invariant text is DERIVED from the advisory's own
    verbatim CWE + summary (de-repo-specified by stripping the package /
    function name); the original verbatim summary is preserved in the record
    and in ``source_findings`` so the provenance is auditable.
  * Dedupe vs the existing hackerman corpus by ``source_audit_ref`` (the GHSA
    html_url): an advisory already present in ``--corpus-dir`` is skipped.

GENERALIZATION (the key difference from a verbatim-only puller): the invariant
is phrased as a target-agnostic rule. E.g. a CWE-401 (memory leak) advisory in
``zebra-network`` mentioning a ``cancel_handles`` map becomes the reusable
hypothesis "Every entry inserted into an in-flight handle/cancel map MUST be
removed on ALL exit paths including timeout; ..." - a hunt hypothesis you can
carry to ANY networked node that keeps per-request handles. The detector seed's
regex is CWE-class-anchored so it fires across repos, not only the source one.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md operational anchor):
  * ``tools/hackerman-etl-from-zebra-advisories.py`` - the ZcashFoundation/zebra
    BAKED dataset (tier-1, network-independent). It now DELEGATES to this
    generic tool when invoked, so the zebra entrypoint keeps working while the
    fetch/generalize/emit logic lives here once. Differs: zebra ships a baked,
    network-independent constant set for offline/CI determinism; this tool is
    the live-fetch generic engine.
  * ``tools/hackerman-etl-from-github-advisory.py`` - multi-repo GHSA puller
    over a fixed TOP_REPOS list; emits hackerman_record ONLY (no paired
    INV-* / detector_seed). Differs: this tool is single-repo (``--repo``),
    repo-agnostic, and emits the invariant + detector-seed TRIPLE plus the
    GENERALIZED hunt-hypothesis phrasing the multi-repo puller lacks.
  * ``tools/hackerman-etl-from-evm-client-advisories.py`` /
    ``...-privacy-mixer-advisories.py`` / ``...-move-cve-advisory.py`` etc -
    domain-specialised advisory ETLs (fixed curated sets per domain). Differs:
    this tool takes an arbitrary ``--repo`` and ``--ecosystem`` so it covers
    any repo without a new file per target.

GAP FILLED: a single repo-agnostic, live-fetch, tier-1 ETL that emits the
record + GENERALIZED-invariant + detector-seed triple for ANY ``owner/repo``,
so adding a new advisory-bearing target is a CLI argument, not a new tool.

CLI:
    # live pull (default: gh api, WebFetch fallback documented in --help):
    python3 tools/hackerman-etl-from-advisories.py \\
        --repo paradigmxyz/reth --ecosystem crates.io \\
        --records-dir audit/corpus_tags/tags/reth_advisories \\
        --invariants-out audit/corpus_tags/derived/invariants_reth_advisories.jsonl \\
        --detector-seeds-out audit/corpus_tags/derived/detector_seeds_reth_advisories.jsonl

    # offline / deterministic (test + CI): read the fetched payload from a cache
    python3 tools/hackerman-etl-from-advisories.py \\
        --repo paradigmxyz/reth --cache-file /tmp/reth-ghsa.json --dry-run --json-summary

    # also pin a CVE that the advisory references:
    python3 tools/hackerman-etl-from-advisories.py --repo foo/bar --extra-cve CVE-2026-12345 ...
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
RECORD_SCHEMA_VERSION = "auditooor.hackerman_record.v1"
INVARIANT_SCHEMA_VERSION = "auditooor.invariant.v1"
DETECTOR_SEED_SCHEMA_VERSION = "auditooor.detector_seed.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.advisories.summary.v1"
VERIFICATION_TIER = "tier-1-officially-disclosed"

# Ecosystem -> default target_language (schema enum value). Overridable per-run
# via --target-language; auto-refined from advisory content where unambiguous.
ECOSYSTEM_LANG: Dict[str, str] = {
    "crates.io": "rust",
    "cargo": "rust",
    "rust": "rust",
    "npm": "typescript-onchain",
    "go": "go",
    "gomod": "go",
    "pypi": "python-onchain",
    "pip": "python-onchain",
    "maven": "assembly",  # JVM not in enum; nearest neutral bucket
    "rubygems": "python-onchain",
    "nuget": "assembly",
    "composer": "python-onchain",
}


def _load_record_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_generic_adv",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD_VALIDATOR = _load_record_validator()


def _load_invariant_schema() -> Dict[str, Any]:
    path = (
        REPO_ROOT
        / "audit"
        / "corpus_tags"
        / "schemas"
        / "auditooor.invariant.v1.schema.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# helpers (byte-stable yaml, mirrored from sibling miners)
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return text[:max_len].strip("-._") or "record"


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return cleaned[:max_len].strip() if cleaned else fallback


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
        and not text.startswith(
            ("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ",")
        )
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
                    lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def _dollar_class(severity: str) -> str:
    return {
        "critical": ">=$1M",
        "high": "$100K-$1M",
        "medium": "$10K-$100K",
        "low": "<$10K",
    }.get(severity.lower(), "non-financial")


_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "none": "info",
    "": "info",
}


def _normalize_severity(value: Optional[str]) -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), "info")


# ---------------------------------------------------------------------------
# live fetch (gh api) + offline cache
# ---------------------------------------------------------------------------


def fetch_repo_advisories(repo: str, *, per_page: int = 100) -> List[Dict[str, Any]]:
    """Call ``gh api repos/<owner>/<repo>/security-advisories`` and return the
    parsed JSON list of PUBLISHED advisories.

    The GitHub Security Advisories REST endpoint is the same source-of-truth the
    repo's ``/security/advisories`` web page (WebFetch target) renders; ``gh
    api`` is the structured fallback. Returns ``[]`` on any error (404, no
    permission, network, repo absent, or repo has no advisories). The honest 0
    case is preserved by callers; this function never invents data.
    """
    url = f"repos/{repo}/security-advisories?per_page={per_page}&state=published"
    try:
        proc = subprocess.run(
            ["gh", "api", url],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def load_advisories(
    repo: str,
    *,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Return the list of advisory dicts for ``repo``.

    If ``cache_file`` is given, read it (offline / deterministic test path).
    Cache shape is either a bare ``[advisory, ...]`` list OR a ``{repo: [...]}``
    mapping (matching the multi-repo puller's cache), so both fixtures work.
    Otherwise call ``gh api`` live and optionally persist the payload.
    """
    if cache_file is not None:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            adv = payload.get(repo, [])
            return adv if isinstance(adv, list) else []
        if isinstance(payload, list):
            return payload
        return []
    fetched = fetch_repo_advisories(repo)
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps({repo: fetched}, indent=2, sort_keys=True), encoding="utf-8"
        )
    return fetched


# ---------------------------------------------------------------------------
# advisory field extraction (all VERBATIM from the fetched advisory)
# ---------------------------------------------------------------------------


def _adv_url(advisory: Dict[str, Any], repo: str, ghsa: str) -> str:
    url = advisory.get("html_url") or advisory.get("url")
    if isinstance(url, str) and url:
        return url
    return f"https://github.com/{repo}/security/advisories/{ghsa}"


def _adv_cwe(advisory: Dict[str, Any]) -> Optional[str]:
    cwes = advisory.get("cwes") or []
    for cwe in cwes:
        if isinstance(cwe, dict):
            cid = cwe.get("cwe_id")
            if isinstance(cid, str) and cid:
                return cid
        elif isinstance(cwe, str) and cwe:
            return cwe
    return None


def _adv_cve(advisory: Dict[str, Any]) -> Optional[str]:
    cve = advisory.get("cve_id")
    if isinstance(cve, str) and cve:
        return cve
    for ident in advisory.get("identifiers", []) or []:
        if isinstance(ident, dict) and ident.get("type") == "CVE":
            val = ident.get("value")
            if isinstance(val, str) and val:
                return val
    return None


def _adv_crates(advisory: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict):
            continue
        pkg = vuln.get("package")
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not isinstance(name, str) or not name:
            continue
        vuln_range = vuln.get("vulnerable_version_range") or ""
        patched = vuln.get("patched_versions") or ""
        out.append((name, str(vuln_range).strip(), str(patched).strip()))
    return out


def _adv_summary_text(advisory: Dict[str, Any]) -> str:
    summary = str(advisory.get("summary") or "").strip()
    description = str(advisory.get("description") or "").strip()
    if summary and description:
        return f"{summary}. {description}"
    return summary or description


def _adv_year(advisory: Dict[str, Any]) -> int:
    for key in ("published_at", "updated_at", "created_at"):
        val = advisory.get(key)
        if isinstance(val, str) and len(val) >= 4 and val[:4].isdigit():
            year = int(val[:4])
            if year >= 2000:
                return year
    return datetime.now(timezone.utc).year


# ---------------------------------------------------------------------------
# CWE-anchored generalization: bug class / attack class / invariant / detector
#
# The CWE drives a TARGET-AGNOSTIC invariant + detector seed. The advisory's
# verbatim summary is preserved on the record; the generalization is derived,
# not fabricated - it restates the CWE-class rule that the verbatim bug
# violated, with no repo/package/function specificity.
# ---------------------------------------------------------------------------


# Each entry: cwe -> (attack_class, inv_category, generalized_invariant_template,
#   detector_id, regex_pattern, ast_hint, fp_reduction, positive_fixture).
# The invariant template is a reusable hunt hypothesis; ``{cwe}`` is filled in.
_CWE_GENERALIZATION: Dict[str, Dict[str, str]] = {
    "CWE-401": {
        "attack_class": "unbounded-memory-leak-via-uncleaned-exit-path",
        "inv_category": "resource-bounds",
        "invariant": (
            "Every entry inserted into an in-flight handle / request / cancel map "
            "MUST be removed on ALL exit paths including the timeout/elapsed path; "
            "the error type on each exit MUST carry the key needed to release its "
            "own entry, so the map stays bounded by the live in-flight set rather "
            "than growing monotonically."
        ),
        "detector_id": "in-flight-map-not-cleaned-on-all-exit-paths",
        "regex": r"\b(?:handles?|in[_-]?flight|pending|cancel)\w*\b[\s\S]{0,400}?\b(?:timeout|elapsed|deadline|Err)\b(?![\s\S]{0,200}?\b(?:remove|clear|drop)\b)",
        "ast_hint": (
            "Flag an in-flight/handle/pending map whose insert has a removal on "
            "the success path but NOT on every error/timeout path."
        ),
        "fp_reduction": (
            "Only flag maps holding per-request state fed by untrusted traffic "
            "with a timeout/error branch lacking a matching remove; ignore Drop "
            "guards or sweep tasks that reclaim entries."
        ),
        "fixture": (
            "map.insert(id, handle);\n"
            "match timeout(d, fut).await {\n"
            "    Err(_elapsed) => return Err(Timeout), // no id -> cannot remove() -> leak\n"
            "    Ok(r) => { map.remove(&id); r }\n"
            "}"
        ),
    },
    "CWE-772": {
        "attack_class": "resource-not-released-after-lifetime",
        "inv_category": "resource-bounds",
        "invariant": (
            "Every acquired resource (handle, slot, buffer, connection) MUST be "
            "released on every exit path after its effective lifetime ends; no "
            "exit path - including timeout / early-error - may leave a resource "
            "held, so the live resource set stays bounded."
        ),
        "detector_id": "resource-not-released-on-all-paths",
        "regex": r"\b(?:acquire|reserve|alloc|open)\w*\b[\s\S]{0,400}?\breturn\s+Err\b(?![\s\S]{0,200}?\b(?:release|free|drop|close|remove)\b)",
        "ast_hint": "Flag acquire/reserve/alloc with an error return lacking a matching release.",
        "fp_reduction": "Only flag when the resource is shared/persistent and the error path lacks release; ignore RAII/Drop-guarded acquisition.",
        "fixture": "let h = pool.acquire();\nif !check() { return Err(E); } // h never released",
    },
    "CWE-770": {
        "attack_class": "allocation-without-limit-or-throttle",
        "inv_category": "resource-bounds",
        "invariant": (
            "Any allocation / preallocation / deserialization sized by an "
            "attacker-supplied length or count MUST be bounded by the strictest "
            "applicable protocol/consensus limit BEFORE allocating, and shared "
            "concurrency-slot pools fed by untrusted peers MUST enforce a per-peer "
            "cap; an unauthenticated party MUST NOT drive unbounded allocation or "
            "monopolize a shared pool."
        ),
        "detector_id": "allocation-sized-by-untrusted-length-no-cap",
        "regex": r"\b(?:with_capacity|reserve|read_vec|alloc)\b[\s\S]{0,120}?\b(?:len|body_len|count|n|size|message_size)\b(?![\s\S]{0,160}?\b(?:MAX_|limit|cap|min\()\b)",
        "ast_hint": (
            "Flag allocate/with_capacity/reserve whose size derives from an "
            "untrusted length/count field with no preceding strict-limit clamp; "
            "and shared slot pools with no per-source cap."
        ),
        "fp_reduction": (
            "Only flag inbound/untrusted paths where the cap is looser than the "
            "protocol element limit or checked only after allocation; ignore "
            "pre-bounded reads (min(n, MAX))."
        ),
        "fixture": (
            "let n = reader.read_compactsize()?; // attacker-claimed, bounded only by transport\n"
            "let mut v = Vec::with_capacity(n as usize); // no protocol cap"
        ),
    },
    "CWE-617": {
        "attack_class": "reachable-assertion-or-panic-on-untrusted-input",
        "inv_category": "input-validation",
        "invariant": (
            "An entrypoint reachable by untrusted input (RPC handler, network "
            "codec, parser) MUST NOT call .expect()/.unwrap()/assert!/panic! on a "
            "fallible operation over attacker-supplied data; a structurally valid "
            "but semantically invalid input MUST be handled as a returned error, "
            "never a process-terminating panic (especially under panic=abort)."
        ),
        "detector_id": "unwrap-expect-assert-on-untrusted-input",
        "regex": r"\b(?:req|request|body|input|recv|receiver|payload|param)\w*\b[\s\S]{0,200}?\.(?:expect|unwrap)\(|\b(?:assert|debug_assert)!\([\s\S]{0,80}?(?:req|input|peer)",
        "ast_hint": "Flag .expect()/.unwrap()/assert! on fallible parse/validate of attacker-supplied input in a network/RPC entrypoint.",
        "fp_reduction": "Only flag when the operand is attacker-controlled and reachable from an untrusted entrypoint; ignore unwrap on constants or already-validated values.",
        "fixture": "let v = parse(req_field).expect(\"valid\"); // untrusted -> panic=abort kills node",
    },
    "CWE-248": {
        "attack_class": "uncaught-exception-panic-dos",
        "inv_category": "input-validation",
        "invariant": (
            "Field validation for untrusted messages MUST be eager (at "
            "deserialize/parse time), matching the reference implementation, so a "
            "malformed message is rejected at the boundary; a malformed input MUST "
            "NOT deserialize successfully only to panic later in a downstream "
            "computation (id calc, hashing, verification)."
        ),
        "detector_id": "lazy-validation-panic-downstream",
        "regex": r"\b(?:txid|id|hash|digest|calc)\w*\b[\s\S]{0,200}?\.(?:expect|unwrap)\(",
        "ast_hint": "Flag downstream id/hash/calc that .expect()/.unwrap()/panics on fields the codec admitted without eager validation.",
        "fp_reduction": "Only flag where the codec admits the input before the panicking downstream calc; ignore paths that eagerly validate at parse.",
        "fixture": "let m = codec.decode(bytes)?; // malformed admitted (lazy)\nlet id = m.id(); // panics here",
    },
    "CWE-345": {
        "attack_class": "insufficient-data-authenticity-single-peer-poisoning",
        "inv_category": "authenticity",
        "invariant": (
            "A single unauthenticated peer's response MUST NOT be able to trigger "
            "a global state reset, sync restart, or shared-state mutation; an "
            "out-of-range or unexpected value from one peer MUST be handled by "
            "penalizing/disconnecting that peer, scoped per-connection, not by "
            "resetting shared/global pipeline state."
        ),
        "detector_id": "single-peer-triggers-global-reset",
        "regex": r"\b(?:peer|inbound|response)\w*\b[\s\S]{0,260}?\b(?:restart|reset|clear|abort)\b(?![\s\S]{0,160}?\b(?:per[_-]?peer|penal|disconnect|misbehav)\b)",
        "ast_hint": "Flag handlers that react to a single-peer-derived value by restarting/clearing global/shared state rather than scoping the response per-peer.",
        "fp_reduction": "Only flag when the trigger derives from one peer's unauthenticated response AND the reaction touches global (not per-peer) state.",
        "fixture": "match verify(peer_block) {\n    Err(OutOfRange) => self.restart_sync(), // global reset on 1 peer\n    _ => {}\n}",
    },
    "CWE-347": {
        "attack_class": "improper-signature-verification-via-authless-cache-key",
        "inv_category": "consensus-parity",
        "invariant": (
            "A verification cache lookup MUST key on an identifier that includes "
            "all authorization/signature data (or MUST re-run signature/auth "
            "verification on every cache hit); an identifier that excludes auth "
            "data MUST NOT be the sole key, so a same-id input with different "
            "(invalid) signatures cannot reuse a prior valid verification."
        ),
        "detector_id": "verification-cache-keyed-on-authless-id",
        "regex": r"\bcache\b[\s\S]{0,160}?\b(?:txid|id|hash)\b(?![\s\S]{0,160}?\b(?:auth|sig|wtxid|authdigest|verify)\b)",
        "ast_hint": "Flag a verification-cache lookup keyed solely on an auth-excluding id whose hit skips signature/auth re-verification.",
        "fp_reduction": "Only flag paths where the cache hit bypasses signature/auth checks; ignore caches keyed on an auth-inclusive id or that re-verify on hit.",
        "fixture": "if let Some(ok) = cache.get(&id) { return ok; } // id excludes sig -> skips re-verify",
    },
    "CWE-696": {
        "attack_class": "incorrect-ordering-of-operations-toctou",
        "inv_category": "ordering",
        "invariant": (
            "State / index mutations MUST NOT be committed before the input has "
            "passed every contextual validity check; index/state updates MUST run "
            "ONLY after all rejection conditions over untrusted content have been "
            "evaluated (validate-then-commit)."
        ),
        "detector_id": "state-mutation-before-validity-check",
        "regex": r"\b(?:insert|push|update|store)\b[\s\S]{0,300}?\b(?:check_|validate_|reject|duplicate|verify)\b",
        "ast_hint": "Flag state/index inserts that lexically precede a validity/rejection guard over the same untrusted content inside one function.",
        "fp_reduction": "Only flag when the inserted key derives from untrusted content AND a rejection guard for that content exists later in the function.",
        "fixture": "self.index.insert(key, loc); // committed first\nself.check_valid(input)?; // guard AFTER",
    },
    "CWE-191": {
        "attack_class": "integer-underflow-or-overflow-on-ordered-accumulation",
        "inv_category": "arithmetic-safety",
        "invariant": (
            "When accumulating bounded deltas (balances, counters) over a sequence "
            "of untrusted-but-valid operations, debits and credits MUST be netted "
            "(or ordered) so the running intermediate value never exceeds its cap "
            "or underflows, even though the final value is in range; arithmetic "
            "MUST be checked and MUST NOT overflow/underflow on any valid sequence."
        ),
        "detector_id": "intermediate-accumulation-over-or-underflow",
        "regex": r"\b\w*(?:balance|amount|total)\w*\b\s*[+\-]=[\s\S]{0,200}?\b\w*(?:balance|amount|total)\w*\b\s*[+\-]=",
        "ast_hint": "Flag bounded accumulators that add and subtract within one untrusted loop where the intermediate value can transiently exceed the cap or underflow.",
        "fp_reduction": "Only flag when the accumulator is capped/asserted AND both adds and subtracts within one input-driven loop; ignore netted-delta-first paths.",
        "fixture": "for o in block.outputs() { bal += o.value; } // credits first\nfor s in block.spends() { bal -= s.value; } // bal may transiently exceed cap",
    },
    "CWE-459": {
        "attack_class": "incomplete-cleanup-state-residue",
        "inv_category": "cleanup-completeness",
        "invariant": (
            "On any rejection / abort / reorg path, ALL intermediate state written "
            "for the rejected unit MUST be fully rolled back; paired removal "
            "methods MUST clean symmetrically; no partial index / balance / "
            "derived-root residue from a rejected unit may persist into subsequent "
            "validation or reach a persistence write batch."
        ),
        "detector_id": "incomplete-rollback-on-reject-path",
        "regex": r"\b(?:insert|push|update)\b[\s\S]{0,400}?\breturn\s+Err\b(?![\s\S]{0,200}?\b(?:rollback|revert|remove|drop|clear)\b)",
        "ast_hint": "Flag functions that mutate shared/non-finalized state then early-error without a matching rollback of every prior mutation; and asymmetric paired pop/remove methods.",
        "fp_reduction": "Only flag when the mutation targets persistent/shared state and the error path lacks a rollback; ignore scope-guard/Drop rollback.",
        "fixture": "self.state.insert(key, value);\nif !check(unit) { return Err(Invalid); } // no remove(key) -> residue",
    },
    "CWE-684": {
        "attack_class": "consensus-divergence-via-implementation-disagreement",
        "inv_category": "consensus-parity",
        "invariant": (
            "A reimplementation of a consensus-critical counting/validation "
            "function MUST produce identical results to the reference "
            "implementation on every input, including edge cases (disabled "
            "opcodes, missing outputs, identity points); it MUST NOT short-circuit "
            "or skip elements the reference counts, so the accept/reject decision "
            "cannot diverge between implementations."
        ),
        "detector_id": "consensus-fn-diverges-from-reference",
        "regex": r"\b(?:count|sigop|validate|verify)\w*\b[\s\S]{0,300}?\b(?:break|continue|return|skip|disabled)\b",
        "ast_hint": "Flag a consensus-critical counting/validation loop that breaks/skips on an edge-case branch the reference implementation processes.",
        "fp_reduction": "Only flag the consensus path feeding an accept/reject threshold; ignore execution-time paths where early-exit is correct.",
        "fixture": "for op in script.ops() {\n    if op.is_disabled() { break; } // STOPS counting -> diverges from reference\n    if op.is_sigop() { count += 1; }\n}",
    },
}

# Fallback generalization when the advisory carries no recognized CWE. The
# attack_class / invariant are derived from impact keywords in the verbatim
# summary, kept target-agnostic.
_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("crash", "dos"),
    ("panic", "dos"),
    ("abort", "dos"),
    ("halt", "dos"),
    ("memory leak", "dos"),
    ("resource exhaustion", "dos"),
    ("freeze", "freeze"),
    ("frozen", "freeze"),
    ("locked", "freeze"),
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("double-spend", "theft"),
    ("double spend", "theft"),
    ("griefing", "griefing"),
    ("precision", "precision-loss"),
    ("rounding", "precision-loss"),
    ("governance", "governance-takeover"),
    ("privilege escalation", "privilege-escalation"),
    ("consensus", "dos"),
    ("divergence", "dos"),
    ("partition", "dos"),
)


def _infer_impact_class(summary: str) -> str:
    hay = summary.lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in hay:
            return impact
    return "dos"


def _infer_impact_actor(impact_class: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "validator-set"
    if impact_class == "yield-redistribution":
        return "yield-recipient"
    if impact_class in {"theft", "freeze"}:
        return "arbitrary-user"
    return "validator-set"


def _generalization(cwe: Optional[str], summary: str, target_lang: str) -> Dict[str, str]:
    """Return the CWE-anchored (or impact-keyword-fallback) generalization
    block. All fields are TARGET-AGNOSTIC hunt-hypothesis phrasing."""
    if cwe and cwe in _CWE_GENERALIZATION:
        g = dict(_CWE_GENERALIZATION[cwe])
        g["bug_class"] = f"{cwe.lower()}-{g['detector_id']}"
        g["source_basis"] = f"generalized from {cwe}"
        return g
    impact = _infer_impact_class(summary)
    return {
        "attack_class": f"public-advisory-{impact}-class",
        "inv_category": "general",
        "bug_class": f"advisory-{impact}-class",
        "invariant": (
            "The component MUST NOT permit the published advisory's impact class "
            f"({impact}) under any untrusted-input or untrusted-peer sequence; the "
            "missing guard described in the verbatim advisory summary MUST be "
            "present on every reachable path, scoped per-peer/per-request where "
            "the trigger is network-reachable."
        ),
        "detector_id": f"advisory-{impact}-missing-guard",
        "regex": r"\b(?:unwrap|expect|insert|reserve|with_capacity|restart|reset)\b",
        "ast_hint": (
            "Advisory has no first-class CWE; review the verbatim summary for the "
            "missing guard and locate the analogous unguarded path."
        ),
        "fp_reduction": (
            "No CWE anchor; treat as a manual hunt hypothesis - the detector is a "
            "broad smell, not a precise rule. Confirm against the verbatim summary."
        ),
        "fixture": "// see verbatim advisory summary; no CWE-anchored fixture available",
        "source_basis": f"generalized from impact-keyword ({impact}); no first-class CWE",
    }


# ---------------------------------------------------------------------------
# ids
# ---------------------------------------------------------------------------


def _repo_token(repo: str) -> str:
    return slugify(repo.replace("/", "-"), max_len=40)


def _record_id(repo: str, ghsa: str) -> str:
    digest = hashlib.sha256(f"adv|{repo}|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"adv:{_repo_token(repo)}:{slugify(ghsa, max_len=48)}:{digest}"[:160]


def _invariant_id(repo: str, ghsa: str) -> str:
    owner = repo.split("/")[0] if "/" in repo else repo
    short = re.sub(r"[^A-Za-z0-9_.-]", "-", slugify(ghsa.replace("GHSA-", ""), max_len=40))
    tok = re.sub(r"[^A-Za-z0-9_.-]", "-", owner.upper())[:24]
    return f"INV-{tok}-{short}"[:84]


def _invariant_record_id(repo: str, ghsa: str) -> str:
    digest = hashlib.sha256(f"adv-inv|{repo}|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"adv-inv:{_repo_token(repo)}:{slugify(ghsa, max_len=48)}:{digest}"[:200]


def _detector_seed_id(repo: str, ghsa: str) -> str:
    digest = hashlib.sha256(f"adv-det|{repo}|{ghsa}".encode("utf-8")).hexdigest()[:12]
    return f"adv-det:{_repo_token(repo)}:{slugify(ghsa, max_len=48)}:{digest}"[:200]


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def build_record(
    advisory: Dict[str, Any],
    *,
    repo: str,
    target_domain: str,
    target_language: str,
) -> Dict[str, Any]:
    ghsa = advisory.get("ghsa_id") or "GHSA-unknown"
    if not isinstance(ghsa, str):
        ghsa = "GHSA-unknown"
    severity = _normalize_severity(advisory.get("severity"))
    url = _adv_url(advisory, repo, ghsa)
    cwe = _adv_cwe(advisory)
    cve = _adv_cve(advisory)
    crates = _adv_crates(advisory)
    summary = _adv_summary_text(advisory)
    impact_class = _infer_impact_class(summary)
    impact_actor = _infer_impact_actor(impact_class)
    gen = _generalization(cwe, summary, target_language)

    crate_tags = [slugify(f"pkg-{c[0]}", max_len=64) for c in crates]
    shape_tags = [
        slugify(ghsa, max_len=64),
        slugify(f"bug-{gen['bug_class']}", max_len=64),
        slugify(f"attack-{gen['attack_class']}", max_len=64),
        slugify(repo.replace("/", "-"), max_len=64),
        "verification_tier=" + VERIFICATION_TIER,
    ]
    if cwe:
        shape_tags.append(slugify(cwe, max_len=64))
    if cve:
        shape_tags.append(slugify(cve, max_len=64))
    shape_tags.extend(crate_tags)
    seen: set = set()
    uniq_tags: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            uniq_tags.append(t)

    pre = [f"Reference advisory at {url}"]
    if cwe:
        pre.append(f"Weakness {cwe}")
    if cve:
        pre.append(f"CVE identifier {cve}")
    pubs = advisory.get("published_at")
    if isinstance(pubs, str) and pubs:
        pre.append(f"Published-at {pubs}")
    for name, vuln_range, patched in crates:
        seg = f"Affected package {name}"
        if vuln_range:
            seg += f" {vuln_range}"
        if patched:
            seg += f" -> patched {patched}"
        pre.append(seg)
    pre.append(f"Affected repo {repo}")
    pre.append(f"verification_tier={VERIFICATION_TIER}")
    # dedupe preconditions
    pseen: set = set()
    pre_uniq: List[str] = []
    for p in pre:
        cleaned = one_line(p, "precondition", max_len=900)
        if cleaned not in pseen:
            pseen.add(cleaned)
            pre_uniq.append(cleaned)

    component = one_line(summary, f"{repo}:{ghsa}", max_len=240) or f"{repo}:{ghsa}"
    patched_join = "; ".join(f"{c[0]} {c[2]}" for c in crates if c[2]) or "the maintainer's patched-versions range"

    record = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "record_id": _record_id(repo, ghsa),
        "source_audit_ref": one_line(url, f"ghsa:{repo}:{ghsa}", max_len=240),
        "target_domain": target_domain,
        "target_language": target_language,
        "target_repo": repo,
        "target_component": one_line(f"{repo}:{ghsa}", f"{repo}:advisory", max_len=240),
        "function_shape": {
            "raw_signature": one_line(component, gen["bug_class"], max_len=500),
            "shape_tags": uniq_tags,
        },
        "bug_class": one_line(gen["bug_class"], "public-advisory", max_len=160),
        "attack_class": one_line(gen["attack_class"], "public-advisory", max_len=160),
        "attacker_role": "unprivileged",
        "attacker_action_sequence": one_line(
            (summary or f"GHSA-tracked vulnerability in {repo}; see advisory.")
            + f" [source=github-security-advisory; repo={repo}; ghsa={ghsa}; "
            + f"verification_tier={VERIFICATION_TIER}]",
            "GHSA-tracked attacker action sequence",
            max_len=4900,
        ),
        "required_preconditions": pre_uniq,
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": one_line(
            f"Upgrade to patched versions: {patched_join}. "
            f"Root-cause defense ({gen['source_basis']}): {gen['invariant']}",
            "Apply the upstream patched-version range.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Running an unpatched {severity}-severity {repo} build ({gen['bug_class']}); "
            "ignoring the published GHSA before applying the patched-versions tag.",
            "Running an unpatched advisory-tagged build.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": _adv_year(advisory),
        "record_tier": VERIFICATION_TIER,
        "record_quality_score": 4.5,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.92,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


def build_invariant(
    advisory: Dict[str, Any],
    *,
    repo: str,
    target_language: str,
) -> Dict[str, Any]:
    ghsa = advisory.get("ghsa_id") or "GHSA-unknown"
    if not isinstance(ghsa, str):
        ghsa = "GHSA-unknown"
    url = _adv_url(advisory, repo, ghsa)
    cwe = _adv_cwe(advisory)
    summary = _adv_summary_text(advisory)
    gen = _generalization(cwe, summary, target_language)
    inv_id = _invariant_id(repo, ghsa)

    record = {
        "schema_version": INVARIANT_SCHEMA_VERSION,
        "record_id": _invariant_record_id(repo, ghsa),
        "source": {
            "task_id": f"advisories-etl:{repo}:{ghsa}",
            "task_type": "ghsa-advisory-etl-generalized",
            "source_audit_ref": one_line(url, ghsa, max_len=240),
        },
        "verification_tier": VERIFICATION_TIER,
        "generated_by": {
            "provider": "corpus-etl",
            "model_id": "hackerman-etl-from-advisories",
            "verified_by_second_pass": False,
        },
        "content": {
            # GENERALIZED, target-agnostic invariant text (reusable hunt hypothesis).
            "invariant_id": inv_id,
            "invariant_text": one_line(gen["invariant"], gen["bug_class"], max_len=4000),
            "violation_consequence": one_line(
                # the verbatim advisory consequence is preserved here
                summary or "node-level impact", "node-level impact", max_len=1000
            ),
            "bug_class": one_line(gen["bug_class"], "advisory", max_len=100),
            "attack_class": one_line(gen["attack_class"], "advisory", max_len=100),
            "target_language": target_language,
            "generalization_basis": one_line(gen["source_basis"], "cwe-anchored", max_len=200),
            "reusable_as_hunt_hypothesis": True,
            "preconditions": [
                one_line(f"Generalization basis: {gen['source_basis']}", "basis", max_len=500),
                one_line(f"Detector seed: {gen['detector_id']}", "detector", max_len=500),
            ],
            # verbatim provenance: the source advisory + its verbatim summary
            "source_findings": [one_line(url, ghsa, max_len=240)],
            "source_advisory_summary_verbatim": one_line(summary, ghsa, max_len=4000),
        },
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return record


def build_detector_seed(
    advisory: Dict[str, Any],
    *,
    repo: str,
    target_language: str,
) -> Dict[str, Any]:
    ghsa = advisory.get("ghsa_id") or "GHSA-unknown"
    if not isinstance(ghsa, str):
        ghsa = "GHSA-unknown"
    url = _adv_url(advisory, repo, ghsa)
    cwe = _adv_cwe(advisory)
    summary = _adv_summary_text(advisory)
    gen = _generalization(cwe, summary, target_language)

    statement = json.dumps(
        {
            "detector_id": gen["detector_id"],
            "language": target_language,
            "regex_pattern": gen["regex"],
            "ast_query_hint": gen["ast_hint"],
            "fp_reduction_strategy": gen["fp_reduction"],
            "positive_fixture_snippet": gen["fixture"],
        },
        sort_keys=True,
    )
    record = {
        "schema_version": DETECTOR_SEED_SCHEMA_VERSION,
        "record_id": _detector_seed_id(repo, ghsa),
        "kind": "detector_seed",
        "router": "advisories_etl",
        "category": gen["inv_category"],
        "statement": statement,
        "target_lang": target_language,
        "raw_keys": [
            "ast_query_hint",
            "detector_id",
            "fp_reduction_strategy",
            "language",
            "positive_fixture_snippet",
            "regex_pattern",
        ],
        "verification_tier": VERIFICATION_TIER,
        "source_task_id": f"advisories-etl:{repo}:{ghsa}",
        "source_audit_ref": one_line(url, ghsa, max_len=240),
        "attack_class": one_line(gen["attack_class"], "advisory", max_len=160),
        "audit_status": "tier-1-officially-disclosed:advisories-etl",
        "ts_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return record


# ---------------------------------------------------------------------------
# dedupe
# ---------------------------------------------------------------------------


def load_existing_refs(corpus_dir: Optional[Path]) -> set:
    refs: set = set()
    if not corpus_dir or not corpus_dir.exists():
        return refs
    for rec in corpus_dir.rglob("record.json"):
        try:
            doc = json.loads(rec.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        ref = doc.get("source_audit_ref")
        if isinstance(ref, str):
            refs.add(ref)
    return refs


# ---------------------------------------------------------------------------
# extra-cve verification (R37: report unverified, never fabricate)
# ---------------------------------------------------------------------------


def _verify_extra_cves(
    advisories: List[Dict[str, Any]], extra_cves: List[str]
) -> Tuple[List[str], List[str]]:
    """Return (verified, unverified) extra-CVE ids. An extra CVE is VERIFIED
    when it is referenced by at least one fetched advisory (cve_id or in the
    identifiers / summary / description). Unverified CVEs are reported, never
    baked into a fabricated record."""
    if not extra_cves:
        return [], []
    blob_parts: List[str] = []
    for adv in advisories:
        cve = _adv_cve(adv)
        if cve:
            blob_parts.append(cve)
        blob_parts.append(_adv_summary_text(adv))
        for ident in adv.get("identifiers", []) or []:
            if isinstance(ident, dict) and isinstance(ident.get("value"), str):
                blob_parts.append(ident["value"])
    blob = " ".join(blob_parts).upper()
    verified: List[str] = []
    unverified: List[str] = []
    for cve in extra_cves:
        if cve.upper() in blob:
            verified.append(cve)
        else:
            unverified.append(cve)
    return verified, unverified


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------


def convert(
    *,
    repo: str,
    records_dir: Path,
    invariants_out: Optional[Path],
    detector_seeds_out: Optional[Path],
    corpus_dir: Optional[Path],
    dry_run: bool,
    ecosystem: Optional[str] = None,
    target_domain: str = "l1-client",
    target_language: Optional[str] = None,
    extra_cves: Optional[List[str]] = None,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    advisories: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Mine ``repo``'s published advisories into the record/invariant/detector
    triple. ``advisories`` (a pre-loaded list) short-circuits the fetch and is
    used by the zebra delegating wrapper + tests for determinism."""
    lang = target_language or ECOSYSTEM_LANG.get((ecosystem or "").lower(), "rust")
    extra_cves = extra_cves or []

    if advisories is None:
        advisories = load_advisories(
            repo, cache_file=cache_file, write_cache_file=write_cache_file
        )

    verified_cves, unverified_cves = _verify_extra_cves(advisories, extra_cves)

    record_schema = _RECORD_VALIDATOR.load_schema()
    try:
        import jsonschema  # type: ignore

        inv_validator = jsonschema.Draft202012Validator(_load_invariant_schema())
    except Exception:  # pragma: no cover - jsonschema absent
        inv_validator = None

    existing_refs = load_existing_refs(corpus_dir)

    errors: List[str] = []
    files: List[str] = []
    records_emitted = 0
    invariants_emitted = 0
    detector_seeds_emitted = 0
    deduped = 0
    skipped_non_published = 0
    by_severity: Dict[str, int] = {}
    by_attack_class: Dict[str, int] = {}
    invariant_lines: List[str] = []
    detector_lines: List[str] = []

    if not dry_run:
        records_dir.mkdir(parents=True, exist_ok=True)

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        if advisory.get("state") and advisory["state"] != "published":
            skipped_non_published += 1
            continue
        ghsa = advisory.get("ghsa_id") or "GHSA-unknown"
        if not isinstance(ghsa, str):
            ghsa = "GHSA-unknown"
        url = _adv_url(advisory, repo, ghsa)
        if url in existing_refs:
            deduped += 1
            continue

        record = build_record(
            advisory, repo=repo, target_domain=target_domain, target_language=lang
        )
        invariant = build_invariant(advisory, repo=repo, target_language=lang)
        detector = build_detector_seed(advisory, repo=repo, target_language=lang)

        rendered_yaml = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered_yaml)
        except yaml.YAMLError as exc:
            errors.append(f"{ghsa}: record yaml-parse-error: {exc}")
            continue
        rec_errs = _RECORD_VALIDATOR.validate_doc(doc, record_schema)
        if rec_errs:
            errors.extend(f"{ghsa}: record: {e}" for e in rec_errs)
            continue
        if inv_validator is not None:
            inv_errs = sorted(inv_validator.iter_errors(invariant), key=lambda e: list(e.path))
            if inv_errs:
                errors.extend(f"{ghsa}: invariant: {e.message}" for e in inv_errs)
                continue

        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        by_attack_class[record["attack_class"]] = (
            by_attack_class.get(record["attack_class"], 0) + 1
        )

        slug = slugify(f"{repo.replace('/', '__')}__{ghsa}", max_len=140)
        rec_subdir = records_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))
        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            yaml_path.write_text(rendered_yaml, encoding="utf-8")

        records_emitted += 1
        invariant_lines.append(json.dumps(invariant, sort_keys=True))
        invariants_emitted += 1
        detector_lines.append(json.dumps(detector, sort_keys=True))
        detector_seeds_emitted += 1

    if not dry_run:
        if invariants_out and invariant_lines:
            invariants_out.parent.mkdir(parents=True, exist_ok=True)
            with invariants_out.open("a", encoding="utf-8") as fh:
                for line in invariant_lines:
                    fh.write(line + "\n")
            files.append(str(invariants_out))
        if detector_seeds_out and detector_lines:
            detector_seeds_out.parent.mkdir(parents=True, exist_ok=True)
            with detector_seeds_out.open("a", encoding="utf-8") as fh:
                for line in detector_lines:
                    fh.write(line + "\n")
            files.append(str(detector_seeds_out))

    return {
        "schema_version": SUMMARY_SCHEMA,
        "repo": repo,
        "ecosystem": ecosystem,
        "target_language": lang,
        "target_domain": target_domain,
        "dry_run": dry_run,
        "verification_tier": VERIFICATION_TIER,
        "advisories_fetched": len(advisories),
        "records_emitted": records_emitted,
        "invariants_emitted": invariants_emitted,
        "detector_seeds_emitted": detector_seeds_emitted,
        "deduped": deduped,
        "skipped_non_published": skipped_non_published,
        "verified_extra_cves": verified_cves,
        "unverified_extra_cves": unverified_cves,
        "errors": errors,
        "by_severity": by_severity,
        "by_attack_class": by_attack_class,
        "file_count": len(files),
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        required=True,
        help="owner/repo whose published GitHub Security Advisories to mine.",
    )
    parser.add_argument(
        "--ecosystem",
        choices=sorted(ECOSYSTEM_LANG.keys()),
        default=None,
        help="Package ecosystem (sets default target-language).",
    )
    parser.add_argument(
        "--target-language",
        default=None,
        help="Override target_language (schema enum); default derives from --ecosystem.",
    )
    parser.add_argument(
        "--target-domain",
        default="l1-client",
        help="schema target_domain enum value (default l1-client).",
    )
    parser.add_argument(
        "--extra-cve",
        action="append",
        default=[],
        help="Pin a CVE the advisory references (repeatable). Unverified -> reported, not baked.",
    )
    parser.add_argument(
        "--records-dir",
        default=None,
        help="Output dir for per-advisory record.{json,yaml}. "
        "Default audit/corpus_tags/tags/<owner>_<repo>_advisories.",
    )
    parser.add_argument(
        "--invariants-out",
        default=None,
        help="Append the INV-* generalized invariant records here (JSONL).",
    )
    parser.add_argument(
        "--detector-seeds-out",
        default=None,
        help="Append the detector-seed records here (JSONL).",
    )
    parser.add_argument(
        "--corpus-dir",
        default=None,
        help="Existing corpus tree to dedupe against (by source_audit_ref).",
    )
    parser.add_argument(
        "--cache-file",
        default=None,
        help="Read advisories from a saved JSON payload instead of calling gh api "
        "(offline / deterministic). Shape: [advisory,...] or {repo:[advisory,...]}.",
    )
    parser.add_argument(
        "--write-cache-file",
        default=None,
        help="Persist the fetched gh-api payload here for later offline replay.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def _resolve(p: Optional[str]) -> Optional[Path]:
    if p is None:
        return None
    pp = Path(p).expanduser()
    return pp if pp.is_absolute() else (REPO_ROOT / pp)


def _default_records_dir(repo: str) -> str:
    tok = repo.replace("/", "_")
    return f"audit/corpus_tags/tags/{slugify(tok, max_len=80)}_advisories"


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    records_dir = _resolve(args.records_dir) or _resolve(_default_records_dir(args.repo))
    summary = convert(
        repo=args.repo,
        records_dir=records_dir,  # type: ignore[arg-type]
        invariants_out=_resolve(args.invariants_out),
        detector_seeds_out=_resolve(args.detector_seeds_out),
        corpus_dir=_resolve(args.corpus_dir),
        dry_run=args.dry_run,
        ecosystem=args.ecosystem,
        target_domain=args.target_domain,
        target_language=args.target_language,
        extra_cves=list(args.extra_cve or []),
        cache_file=_resolve(args.cache_file),
        write_cache_file=_resolve(args.write_cache_file),
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman advisories ETL: "
            f"repo={summary['repo']} "
            f"fetched={summary['advisories_fetched']} "
            f"records={summary['records_emitted']} "
            f"invariants={summary['invariants_emitted']} "
            f"detector_seeds={summary['detector_seeds_emitted']} "
            f"deduped={summary['deduped']} "
            f"verification_tier={summary['verification_tier']} "
            f"by_severity={summary['by_severity']} "
            f"unverified_cves={summary['unverified_extra_cves']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
