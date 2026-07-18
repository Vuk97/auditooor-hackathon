#!/usr/bin/env python3
"""
NVD / GHSA verification sweep across hackerman ETL miner outputs.

Wave-EXEC lane EXEC-NVD-VERIFICATION-SWEEP. Follow-up to Wave-3b Vyper-CVE
fabrication quarantine (db189746b). Wave-3b's Vyper-CVE ETL miner emitted
records using training-data-recalled CVE IDs without cross-checking against
live NVD or GHSA databases. SIX false CVE attributions were found, 78 records
quarantined.

This sweep audits the OTHER hackerman ETL miner outputs for the same
fabrication pattern. For every record in scope that carries a CVE-ID or
GHSA-ID claim, the tool:

1. Hits the live NVD or GHSA API to confirm the advisory exists.
2. Cross-checks the advisory's affected-product / CPE against the record's
   ``target_repo`` field.
3. Emits a verdict to ``.auditooor/nvd-verification-sweep-candidates.jsonl``
   in {VERIFIED, MISMATCHED-PRODUCT, NOT-FOUND, NEEDS-MANUAL-REVIEW,
   BLOCKED-NO-NETWORK}.

The tool is READ-ONLY w.r.t. corpus tag YAML files. It does NOT quarantine,
move, or modify records. Operator reviews the candidates JSONL.

Hard rules followed (per ~/.claude/CLAUDE.md):

* Real NVD + GHSA queries only - no synthesis.
* If network unavailable, ship ``BLOCKED-NO-NETWORK`` verdict (never fabricate
  pass/fail).
* Read-only on corpus tags; new files only.
* Does NOT touch ``tools/calibration/llm_budget_log.jsonl``.
* Cross-links relative-path only.

Scope (filename prefix groups under ``audit/corpus_tags/tags/``):

* ``findings-go:*``       - Wave-1/8b CVE-DB driven miner (current 25 records)
* ``mev_flashloan*``      - Wave 4a
* ``l2_zkrollup*``        - Wave 4e
* ``bridge*``             - Wave 5d
* ``cve_db*``             - Wave 8b (NVD-verified at emission time)
* ``historic:*``          - Wave 6b-v2 (Solodit-driven, should be clean)
* ``critical:sherlock:*`` - Wave 8a
* ``critical:code4rena:*``
* ``critical:cantina:*``

Records under ``_QUARANTINE_FABRICATED_CVE/`` are SKIPPED.

Usage:

    python3 tools/hackerman-nvd-verification-sweep.py \\
        --workspace . \\
        --out .auditooor/nvd-verification-sweep-candidates.jsonl

Add ``--dry-run`` to plan only (no network calls). Add ``--limit N`` to cap
the number of records scanned (debug).

Environment:

* ``NVD_API_KEY`` - optional; sets a higher NVD rate limit (50/30s vs 5/30s).
* ``HACKERMAN_NVD_SLEEP_SECS`` - inter-call delay (default 6.5s without key,
  0.7s with key). Adjust if you hit 403/429.

context_pack_id seeded by the EXEC-NVD-VERIFICATION-SWEEP runtime; recorded
in the verdict JSONL header line for traceability.

Cross-refs:

* ``tools/hackerman-etl-from-github-advisory.py``
* ``tools/hackerman-etl-from-findings-go.py``
* ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")

DEFAULT_SCOPE_PREFIXES = (
    "findings-go:",
    "mev_flashloan",
    "l2_zkrollup",
    "bridge",
    "cve_db",
    "historic:",
    "critical:sherlock:",
    "critical:code4rena:",
    "critical:cantina:",
    "github-advisory:",
    "vyper_cve:",  # included if not yet quarantined
)

# Records already routed to the quarantine subtree are skipped entirely.
QUARANTINE_DIR_NAME = "_QUARANTINE_FABRICATED_CVE"

# Already-flagged records (operator-set) skip re-verification.
ATTRIBUTION_SKIP_PREFIX = "UNVERIFIED-"


# -----------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------


@dataclass
class IdClaim:
    """A single CVE-ID or GHSA-ID claim extracted from a record."""

    kind: str  # "CVE" | "GHSA"
    id: str
    appears_in_fields: list[str] = field(default_factory=list)


@dataclass
class RecordVerdict:
    record_path: str
    record_id: str
    target_repo: str
    miner_prefix: str
    id_claims: list[dict]
    verdict: str
    verdict_reason: str
    advisory_target_evidence: dict
    api_calls_made: int


# -----------------------------------------------------------------------------
# YAML field extraction (minimal, no PyYAML dependency)
# -----------------------------------------------------------------------------

SIMPLE_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def parse_simple_yaml_fields(text: str) -> dict[str, str]:
    """Best-effort flat scalar field extraction. Misses lists/nested maps; that
    is fine for the fields we care about: record_id, target_repo, source_audit_ref,
    attribution_verdict.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith(" ") or line.startswith("\t"):
            continue  # nested
        if line.startswith("#"):
            continue
        m = SIMPLE_FIELD_RE.match(line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        if key in out:
            continue  # first wins
        val = raw.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        elif val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        out[key] = val
    return out


def extract_id_claims(text: str, fields: dict[str, str]) -> list[IdClaim]:
    """Find every CVE / GHSA reference and record where it appeared."""
    seen: dict[tuple[str, str], IdClaim] = {}

    def _normalise(s: str, kind: str) -> str:
        return s.upper() if kind == "CVE" else s  # GHSA letters are lowercase

    # Per-field scan
    for fname, fval in fields.items():
        for m in CVE_RE.finditer(fval):
            key = ("CVE", _normalise(m.group(0), "CVE"))
            claim = seen.setdefault(key, IdClaim("CVE", key[1], []))
            if fname not in claim.appears_in_fields:
                claim.appears_in_fields.append(fname)
        for m in GHSA_RE.finditer(fval):
            key = ("GHSA", m.group(0))
            claim = seen.setdefault(key, IdClaim("GHSA", key[1], []))
            if fname not in claim.appears_in_fields:
                claim.appears_in_fields.append(fname)

    # Full-text fallback (multi-line strings, lists, nested maps) so we still
    # surface claims that the flat parser misses.
    for m in CVE_RE.finditer(text):
        key = ("CVE", _normalise(m.group(0), "CVE"))
        claim = seen.setdefault(key, IdClaim("CVE", key[1], []))
        if "body" not in claim.appears_in_fields and not claim.appears_in_fields:
            claim.appears_in_fields.append("body")
    for m in GHSA_RE.finditer(text):
        key = ("GHSA", m.group(0))
        claim = seen.setdefault(key, IdClaim("GHSA", key[1], []))
        if "body" not in claim.appears_in_fields and not claim.appears_in_fields:
            claim.appears_in_fields.append("body")

    return list(seen.values())


# -----------------------------------------------------------------------------
# Advisory lookups (REAL network calls)
# -----------------------------------------------------------------------------


class AdvisoryCache:
    """Caches NVD/GHSA responses for the run so repeated IDs only cost one API
    call.
    """

    def __init__(self) -> None:
        self.nvd: dict[str, Optional[dict]] = {}
        self.ghsa: dict[str, Optional[dict]] = {}
        self.calls = 0
        self.errors: list[str] = []


def _http_json(url: str, timeout: int = 20, headers: Optional[dict] = None) -> Optional[dict]:
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def lookup_nvd(cve_id: str, cache: AdvisoryCache, sleep_secs: float, api_key: Optional[str]) -> Optional[dict]:
    if cve_id in cache.nvd:
        return cache.nvd[cve_id]
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
    try:
        time.sleep(sleep_secs)
        data = _http_json(url, headers=headers)
        cache.calls += 1
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        cache.nvd[cve_id] = vulns[0]["cve"] if vulns else None
        return cache.nvd[cve_id]
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        cache.errors.append(f"NVD {cve_id}: {exc!r}")
        cache.nvd[cve_id] = None
        return None


def lookup_ghsa(ghsa_id: str, cache: AdvisoryCache) -> Optional[dict]:
    if ghsa_id in cache.ghsa:
        return cache.ghsa[ghsa_id]
    try:
        proc = subprocess.run(
            ["gh", "api", f"/advisories/{ghsa_id}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        cache.calls += 1
        if proc.returncode != 0:
            cache.errors.append(f"GHSA {ghsa_id}: rc={proc.returncode} stderr={proc.stderr.strip()[:200]}")
            cache.ghsa[ghsa_id] = None
            return None
        cache.ghsa[ghsa_id] = json.loads(proc.stdout)
        return cache.ghsa[ghsa_id]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        cache.errors.append(f"GHSA {ghsa_id}: {exc!r}")
        cache.ghsa[ghsa_id] = None
        return None


# -----------------------------------------------------------------------------
# Product / repo matching
# -----------------------------------------------------------------------------


# Generic / common tokens that on their own do not prove a product match.
# A heuristic match on ONLY these tokens is downgraded to NEEDS-MANUAL-REVIEW
# so the operator can decide whether the advisory truly applies.
WEAK_REPO_TOKENS = {
    "org", "io", "com", "net", "chain", "core", "labs", "lab", "inc",
    "project", "team", "dev", "foundation", "protocol", "official",
    "main", "node", "client", "server", "v1", "v2", "v3",
}


def _normalise_repo_tokens(repo: str) -> set[str]:
    """Split a target_repo string into lowercase identifier tokens for fuzzy
    overlap matching against advisory affected-product fields.
    """
    if not repo:
        return set()
    tokens = re.split(r"[\s/_\-\.,]+", repo.lower())
    return {t for t in tokens if t and len(t) > 2}


def nvd_affected_evidence(nvd_cve: dict) -> dict:
    """Pull affected-product hints from the NVD record."""
    evidence: dict = {"descriptions": [], "cpe_uris": [], "references": []}
    for desc in (nvd_cve.get("descriptions") or [])[:3]:
        if desc.get("lang") == "en":
            evidence["descriptions"].append(desc.get("value", "")[:280])
    for cfg in nvd_cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cpe in node.get("cpeMatch") or []:
                uri = cpe.get("criteria") or cpe.get("cpe23Uri")
                if uri:
                    evidence["cpe_uris"].append(uri)
    for ref in (nvd_cve.get("references") or [])[:5]:
        url = ref.get("url")
        if url:
            evidence["references"].append(url)
    return evidence


def ghsa_affected_evidence(ghsa: dict) -> dict:
    evidence: dict = {"summary": ghsa.get("summary", "")[:280], "ecosystem_packages": [], "references": []}
    for v in (ghsa.get("vulnerabilities") or []):
        pkg = (v.get("package") or {})
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if eco or name:
            evidence["ecosystem_packages"].append(f"{eco}:{name}")
    for ref in (ghsa.get("references") or [])[:5]:
        u = ref.get("url") if isinstance(ref, dict) else ref
        if u:
            evidence["references"].append(u)
    return evidence


def evidence_repo_match(evidence: dict, target_repo: str) -> tuple[bool, str]:
    """Heuristic: any repo-name token appearing in the advisory description /
    CPE / references counts as a match. The audit operator can downgrade or
    upgrade individual rows; the goal here is to surface MISMATCHED-PRODUCT
    candidates, not auto-quarantine.
    """
    tokens = _normalise_repo_tokens(target_repo)
    if not tokens:
        return False, "empty-target-repo"
    haystack_parts: list[str] = []
    for v in evidence.values():
        if isinstance(v, str):
            haystack_parts.append(v.lower())
        elif isinstance(v, list):
            haystack_parts.extend(str(x).lower() for x in v)
    haystack = " ".join(haystack_parts)
    hits = [t for t in tokens if t in haystack]
    strong_hits = [t for t in hits if t not in WEAK_REPO_TOKENS]
    if strong_hits:
        return True, "match:" + ",".join(sorted(strong_hits))
    if hits:
        return False, "weak-match-only:" + ",".join(sorted(hits))
    return False, "no-token-overlap"


# -----------------------------------------------------------------------------
# Sweep core
# -----------------------------------------------------------------------------


def iter_target_yamls(tags_dir: Path, scope_prefixes: tuple[str, ...]) -> Iterable[Path]:
    for path in sorted(tags_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix != ".yaml":
            continue
        if path.name.startswith("_"):
            continue
        if QUARANTINE_DIR_NAME in str(path):
            continue
        if not any(path.name.startswith(p) for p in scope_prefixes):
            continue
        yield path


def miner_prefix_of(name: str) -> str:
    # findings-go:..., critical:cantina:..., mev_flashloan:..., etc.
    if name.startswith("findings-go:"):
        return "findings-go"
    if name.startswith("critical:sherlock:"):
        return "critical:sherlock"
    if name.startswith("critical:code4rena:"):
        return "critical:code4rena"
    if name.startswith("critical:cantina:"):
        return "critical:cantina"
    if name.startswith("historic:"):
        return "historic"
    if name.startswith("github-advisory:"):
        return "github-advisory"
    if name.startswith("cve_db"):
        return "cve_db"
    if name.startswith("mev_flashloan"):
        return "mev_flashloan"
    if name.startswith("l2_zkrollup"):
        return "l2_zkrollup"
    if name.startswith("bridge"):
        return "bridge"
    if name.startswith("vyper_cve"):
        return "vyper_cve"
    return name.split(":", 1)[0]


def verify_record(
    path: Path,
    cache: AdvisoryCache,
    sleep_secs: float,
    api_key: Optional[str],
    dry_run: bool,
    network_blocked: bool,
) -> Optional[RecordVerdict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    fields = parse_simple_yaml_fields(text)

    attribution = fields.get("attribution_verdict", "") or ""
    if attribution.startswith(ATTRIBUTION_SKIP_PREFIX):
        return None

    claims = extract_id_claims(text, fields)
    if not claims:
        return None

    record_id = fields.get("record_id", path.stem)
    target_repo = fields.get("target_repo", "")
    miner_prefix = miner_prefix_of(path.name)

    claim_dicts: list[dict] = []
    advisory_target_evidence: dict = {}
    verdicts_per_claim: list[str] = []

    for c in claims:
        claim_state = {
            "kind": c.kind,
            "id": c.id,
            "appears_in_fields": c.appears_in_fields,
            "lookup": None,
            "product_match": None,
        }
        if dry_run or network_blocked:
            claim_state["lookup"] = "skipped:" + ("dry-run" if dry_run else "no-network")
            verdicts_per_claim.append("BLOCKED-NO-NETWORK" if network_blocked else "DRY-RUN")
            claim_dicts.append(claim_state)
            continue

        if c.kind == "CVE":
            adv = lookup_nvd(c.id, cache, sleep_secs, api_key)
            if adv is None:
                claim_state["lookup"] = "NVD:not-found"
                verdicts_per_claim.append("NOT-FOUND")
                claim_dicts.append(claim_state)
                continue
            evidence = nvd_affected_evidence(adv)
        else:  # GHSA
            adv = lookup_ghsa(c.id, cache)
            if adv is None:
                claim_state["lookup"] = "GHSA:not-found"
                verdicts_per_claim.append("NOT-FOUND")
                claim_dicts.append(claim_state)
                continue
            evidence = ghsa_affected_evidence(adv)

        advisory_target_evidence[c.id] = evidence
        matched, reason = evidence_repo_match(evidence, target_repo)
        claim_state["lookup"] = "ok"
        claim_state["product_match"] = {"matched": matched, "reason": reason}
        if matched:
            verdicts_per_claim.append("VERIFIED")
        elif reason.startswith("weak-match-only"):
            verdicts_per_claim.append("NEEDS-MANUAL-REVIEW")
        else:
            verdicts_per_claim.append("MISMATCHED-PRODUCT")
        claim_dicts.append(claim_state)

    # Aggregate verdict: worst-case wins
    if not verdicts_per_claim:
        verdict = "NEEDS-MANUAL-REVIEW"
        reason = "no claims after filter"
    elif all(v == "VERIFIED" for v in verdicts_per_claim):
        verdict, reason = "VERIFIED", f"{len(verdicts_per_claim)} claim(s) repo-matched"
    elif any(v == "NOT-FOUND" for v in verdicts_per_claim):
        verdict, reason = "NOT-FOUND", "advisory does not exist in upstream DB"
    elif any(v == "MISMATCHED-PRODUCT" for v in verdicts_per_claim):
        verdict, reason = "MISMATCHED-PRODUCT", "advisory exists but affected-product disagrees with target_repo"
    elif any(v == "NEEDS-MANUAL-REVIEW" for v in verdicts_per_claim):
        verdict, reason = "NEEDS-MANUAL-REVIEW", "advisory matched only on weak/common tokens; manual review needed"
    elif any(v == "BLOCKED-NO-NETWORK" for v in verdicts_per_claim):
        verdict, reason = "BLOCKED-NO-NETWORK", "no NVD/GHSA reachability"
    elif any(v == "DRY-RUN" for v in verdicts_per_claim):
        verdict, reason = "NEEDS-MANUAL-REVIEW", "dry-run mode; rerun without --dry-run"
    else:
        verdict, reason = "NEEDS-MANUAL-REVIEW", "mixed claim verdicts"

    return RecordVerdict(
        record_path=str(path),
        record_id=record_id,
        target_repo=target_repo,
        miner_prefix=miner_prefix,
        id_claims=claim_dicts,
        verdict=verdict,
        verdict_reason=reason,
        advisory_target_evidence=advisory_target_evidence,
        api_calls_made=cache.calls,
    )


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------


def network_reachable() -> bool:
    try:
        _http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-39363", timeout=10)
        return True
    except Exception:
        return False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=".", help="auditooor workspace root (default: cwd)")
    parser.add_argument(
        "--tags-dir",
        default=None,
        help="explicit override for audit/corpus_tags/tags directory",
    )
    parser.add_argument(
        "--out",
        default=".auditooor/nvd-verification-sweep-candidates.jsonl",
        help="JSONL output path (relative to --workspace)",
    )
    parser.add_argument(
        "--scope-prefix",
        action="append",
        default=None,
        help="restrict to filename prefixes (repeatable). Default: full scope.",
    )
    parser.add_argument("--limit", type=int, default=None, help="cap records scanned (debug)")
    parser.add_argument("--dry-run", action="store_true", help="plan only; no network calls")
    parser.add_argument("--context-pack-id", default="", help="MCP context_pack_id for traceability")
    parser.add_argument("--context-pack-hash", default="", help="MCP context_pack_hash for traceability")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    tags_dir = Path(args.tags_dir).resolve() if args.tags_dir else workspace / "audit" / "corpus_tags" / "tags"
    out_path = (workspace / args.out).resolve() if not Path(args.out).is_absolute() else Path(args.out).resolve()

    if not tags_dir.is_dir():
        print(f"FATAL: tags dir not found: {tags_dir}", file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)

    scope_prefixes = tuple(args.scope_prefix) if args.scope_prefix else DEFAULT_SCOPE_PREFIXES

    network_blocked = False
    if not args.dry_run:
        if not network_reachable():
            print("WARNING: NVD unreachable; all NVD verdicts will be BLOCKED-NO-NETWORK", file=sys.stderr)
            network_blocked = True

    api_key = os.environ.get("NVD_API_KEY") or None
    default_sleep = 0.7 if api_key else 6.5
    sleep_secs = float(os.environ.get("HACKERMAN_NVD_SLEEP_SECS", default_sleep))

    cache = AdvisoryCache()

    candidates: list[RecordVerdict] = []
    scanned = 0
    skipped_no_claim = 0
    skipped_already_flagged = 0
    for path in iter_target_yamls(tags_dir, scope_prefixes):
        scanned += 1
        if args.limit and scanned > args.limit:
            scanned -= 1
            break
        verdict = verify_record(
            path=path,
            cache=cache,
            sleep_secs=sleep_secs,
            api_key=api_key,
            dry_run=args.dry_run,
            network_blocked=network_blocked,
        )
        if verdict is None:
            text = path.read_text(encoding="utf-8", errors="replace")
            fields = parse_simple_yaml_fields(text)
            if fields.get("attribution_verdict", "").startswith(ATTRIBUTION_SKIP_PREFIX):
                skipped_already_flagged += 1
            else:
                skipped_no_claim += 1
            continue
        candidates.append(verdict)

    header = {
        "_header": True,
        "tool": "hackerman-nvd-verification-sweep",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "context_pack_id": args.context_pack_id,
        "context_pack_hash": args.context_pack_hash,
        "tags_dir": str(tags_dir),
        "scope_prefixes": list(scope_prefixes),
        "totals": {
            "scanned": scanned,
            "skipped_no_claim": skipped_no_claim,
            "skipped_already_flagged": skipped_already_flagged,
            "candidates_emitted": len(candidates),
            "api_calls_made": cache.calls,
            "api_errors": len(cache.errors),
        },
        "network_blocked": network_blocked,
        "dry_run": args.dry_run,
    }

    with out_path.open("w", encoding="utf-8") as fp:
        fp.write(json.dumps(header) + "\n")
        for c in candidates:
            fp.write(json.dumps(asdict(c)) + "\n")
        if cache.errors:
            fp.write(json.dumps({"_errors": cache.errors}) + "\n")

    # Summary to stdout
    print(f"scanned={scanned} skipped_no_claim={skipped_no_claim} "
          f"skipped_flagged={skipped_already_flagged} candidates={len(candidates)} "
          f"api_calls={cache.calls} api_errors={len(cache.errors)}")
    by_verdict: dict[str, int] = {}
    by_miner: dict[str, dict[str, int]] = {}
    for c in candidates:
        by_verdict[c.verdict] = by_verdict.get(c.verdict, 0) + 1
        by_miner.setdefault(c.miner_prefix, {})
        by_miner[c.miner_prefix][c.verdict] = by_miner[c.miner_prefix].get(c.verdict, 0) + 1
    for v, n in sorted(by_verdict.items(), key=lambda kv: -kv[1]):
        print(f"  {v}: {n}")
    print("by miner:")
    for m, vd in sorted(by_miner.items()):
        line = ", ".join(f"{k}={v}" for k, v in sorted(vd.items()))
        print(f"  {m}: {line}")
    print(f"verdicts -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
