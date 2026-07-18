#!/usr/bin/env python3
"""
Hackerman CVE/GHSA pre-emit verification library.

Reusable verification primitives for every hackerman ETL miner. Wave-3b shipped
78 records with 6 fabricated CVE IDs because the Vyper-CVE miner emitted
records using training-data-recalled CVE numbers without checking the live
NVD or GHSA databases. Wave-8b's CVE-DB-driven miner caught it because it was
NVD-verified by design. EXEC-NVD-VERIFICATION-SWEEP then post-hoc audited the
rest of the corpus.

Going forward, every miner that emits a hackerman record claiming a CVE-ID
or GHSA-ID MUST import this library and call ``pre_emit_check`` before
writing the YAML. Records that fail verification must be routed to a
quarantine subdirectory and carry an ``UNVERIFIED-*`` attribution shape_tag.

This module is the canonical implementation. It is intentionally:

* network-aware, but disk-cached: every NVD / GHSA response is persisted to
  ``~/.auditooor/nvd_cache.jsonl`` with a 7-day TTL so the same ID isn't
  re-fetched on every miner run, and so offline rebuilds don't hammer the
  upstream APIs.
* deterministic at the call boundary: ``verify_cve_id`` / ``verify_ghsa_id``
  return ``{}`` (not ``None``) when not-found / blocked, and surface the
  per-call status under a ``__verification__`` envelope key so callers can
  tell "API said no" from "API was unreachable".
* compatible with the existing post-hoc sweep (`hackerman-nvd-verification-sweep.py`).
  The repo-token-overlap heuristic in `attribution_matches_repo` mirrors the
  one in the sweep tool so a record that the sweep would flag as MATCH /
  MISMATCH / WEAK is treated identically by the pre-emit gate.

Public API
----------

* ``verify_cve_id(cve_id, *, cache=None, force_refresh=False) -> dict``
* ``verify_ghsa_id(ghsa_id, *, cache=None, force_refresh=False) -> dict``
* ``attribution_matches_repo(advisory_record, target_repo) -> tuple[bool, str]``
* ``pre_emit_check(record, *, strict=True, cache=None) -> tuple[bool, str]``
* ``DiskCache`` - small JSONL-backed cache with TTL pruning
* ``UNVERIFIED_SHAPE_TAGS`` - canonical attribution shape_tag prefixes that a
  miner should set on a record routed to quarantine

The library deliberately avoids any third-party dependency (no ``requests``,
no ``PyYAML``) so miners running inside locked-down sandboxes can use it.

Environment knobs
-----------------

* ``NVD_API_KEY`` - if set, used as ``apiKey`` header; bumps rate limit.
* ``HACKERMAN_NVD_SLEEP_SECS`` - inter-call delay (default 6.5s without key,
  0.7s with key).
* ``HACKERMAN_VERIFY_CACHE_PATH`` - override the disk cache path (default
  ``~/.auditooor/nvd_cache.jsonl``).
* ``HACKERMAN_VERIFY_CACHE_TTL_DAYS`` - cache TTL (default 7).
* ``HACKERMAN_VERIFY_OFFLINE`` - when ``1``/``true``, do not touch the
  network; cached hits still resolve, cache-miss returns ``{}`` with
  ``status='blocked-offline'``.

Cross-refs:

* ``tools/hackerman-nvd-verification-sweep.py``
* ``tools/hackerman-etl-from-github-advisory.py``
* ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``
* ``docs/HACKERMAN_MINER_CONTRACT_NVD_VERIFICATION.md``
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")

DEFAULT_CACHE_PATH = Path("~/.auditooor/nvd_cache.jsonl").expanduser()
DEFAULT_TTL_DAYS = 7
DEFAULT_SLEEP_WITH_KEY = 0.7
DEFAULT_SLEEP_NO_KEY = 6.5

# Canonical attribution shape_tag prefixes a miner can write into a record's
# function_shape.shape_tags array (and optionally as a top-level
# ``attribution_verdict`` field) to route the record to quarantine.
UNVERIFIED_SHAPE_TAGS = (
    "UNVERIFIED-NOT-FOUND",          # advisory does not exist in NVD/GHSA
    "UNVERIFIED-MISMATCHED-PRODUCT", # advisory exists but affected product != target_repo
    "UNVERIFIED-WEAK-MATCH",         # only weak/common tokens overlapped
    "UNVERIFIED-BLOCKED-NO-NETWORK", # could not reach NVD/GHSA; cached miss
    "UNVERIFIED-FABRICATED",         # explicit operator override (eg Wave-3b)
)

# Generic / common tokens that on their own do not prove a product match.
# Mirrors `hackerman-nvd-verification-sweep.py::WEAK_REPO_TOKENS`.
WEAK_REPO_TOKENS = {
    "org", "io", "com", "net", "chain", "core", "labs", "lab", "inc",
    "project", "team", "dev", "foundation", "protocol", "official",
    "main", "node", "client", "server", "v1", "v2", "v3",
}


# -----------------------------------------------------------------------------
# Disk cache
# -----------------------------------------------------------------------------


class DiskCache:
    """Append-only JSONL cache of NVD/GHSA responses with TTL pruning.

    Each line is ``{"kind":"cve"|"ghsa", "id":"<UPPER>", "fetched_at":<epoch>,
    "response":<json|null>}``. The most recent entry for a given (kind, id)
    wins; older entries are tolerated and pruned on rewrite. ``response=null``
    is a tombstone meaning "the upstream API explicitly said this advisory
    does not exist" - it is treated as a real cache hit, not a miss.
    """

    def __init__(
        self,
        path: Optional[Path | str] = None,
        ttl_days: Optional[int] = None,
    ) -> None:
        self.path: Path = Path(path) if path else Path(
            os.environ.get("HACKERMAN_VERIFY_CACHE_PATH") or DEFAULT_CACHE_PATH
        ).expanduser()
        ttl_days_env = os.environ.get("HACKERMAN_VERIFY_CACHE_TTL_DAYS")
        if ttl_days is None and ttl_days_env:
            try:
                ttl_days = int(ttl_days_env)
            except ValueError:
                ttl_days = None
        self.ttl_seconds: int = (ttl_days if ttl_days is not None else DEFAULT_TTL_DAYS) * 86400
        self._mem: dict[tuple[str, str], tuple[float, Any]] = {}
        self._loaded = False

    # ---------- loading / persisting ----------

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    kind = row.get("kind")
                    rid = row.get("id")
                    fetched_at = row.get("fetched_at")
                    if not (isinstance(kind, str) and isinstance(rid, str) and isinstance(fetched_at, (int, float))):
                        continue
                    self._mem[(kind, rid)] = (float(fetched_at), row.get("response"))
        except OSError:
            return

    def _is_fresh(self, fetched_at: float) -> bool:
        return (time.time() - fetched_at) <= self.ttl_seconds

    def get(self, kind: str, rid: str) -> tuple[bool, Any]:
        """Return ``(hit, payload)``. ``hit=True`` means cache had a fresh entry
        (including a tombstone ``payload=None``); ``hit=False`` means caller
        should hit the network.
        """
        self._load()
        key = (kind.lower(), rid.upper() if kind.lower() == "cve" else rid)
        if key not in self._mem:
            return False, None
        fetched_at, payload = self._mem[key]
        if not self._is_fresh(fetched_at):
            return False, None
        return True, payload

    def put(self, kind: str, rid: str, payload: Any) -> None:
        self._load()
        key = (kind.lower(), rid.upper() if kind.lower() == "cve" else rid)
        now = time.time()
        self._mem[key] = (now, payload)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps({
                    "kind": key[0],
                    "id": key[1],
                    "fetched_at": now,
                    "response": payload,
                }) + "\n")
        except OSError:
            pass

    # ---------- maintenance ----------

    def prune(self) -> int:
        """Rewrite the JSONL keeping only the most recent fresh entry per key.
        Returns the number of rows kept.
        """
        self._load()
        if not self.path.exists():
            return 0
        rows = []
        for (kind, rid), (fetched_at, payload) in self._mem.items():
            if not self._is_fresh(fetched_at):
                continue
            rows.append({
                "kind": kind, "id": rid, "fetched_at": fetched_at, "response": payload,
            })
        rows.sort(key=lambda r: (r["kind"], r["id"]))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fp:
                for r in rows:
                    fp.write(json.dumps(r) + "\n")
            tmp.replace(self.path)
        except OSError:
            return len(rows)
        return len(rows)


# Module-level shared cache so multiple miners in the same Python process
# share the in-memory cache view.
_SHARED_CACHE: Optional[DiskCache] = None


def get_shared_cache() -> DiskCache:
    global _SHARED_CACHE
    if _SHARED_CACHE is None:
        _SHARED_CACHE = DiskCache()
    return _SHARED_CACHE


# -----------------------------------------------------------------------------
# Network primitives
# -----------------------------------------------------------------------------


def _offline_mode() -> bool:
    v = (os.environ.get("HACKERMAN_VERIFY_OFFLINE") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _http_json(url: str, *, timeout: int = 20, headers: Optional[dict] = None) -> Any:
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_nvd(cve_id: str) -> tuple[Any, str]:
    """Returns ``(payload, status)`` where payload is the NVD ``cve`` dict or
    ``None`` (tombstone) and status is one of
    ``"hit" | "not-found" | "blocked-offline" | "network-error"``.
    """
    if _offline_mode():
        return None, "blocked-offline"
    api_key = os.environ.get("NVD_API_KEY") or None
    sleep_default = DEFAULT_SLEEP_WITH_KEY if api_key else DEFAULT_SLEEP_NO_KEY
    try:
        sleep_secs = float(os.environ.get("HACKERMAN_NVD_SLEEP_SECS", sleep_default))
    except ValueError:
        sleep_secs = sleep_default
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
    try:
        time.sleep(sleep_secs)
        data = _http_json(url, headers=headers)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return None, "network-error"
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if not vulns:
        return None, "not-found"
    return vulns[0].get("cve"), "hit"


def _fetch_ghsa(ghsa_id: str) -> tuple[Any, str]:
    """GHSA fetch uses ``gh api`` so we inherit operator authentication. If
    ``gh`` is not installed or returns non-zero, we treat that as a network
    error rather than a definitive not-found.
    """
    if _offline_mode():
        return None, "blocked-offline"
    try:
        proc = subprocess.run(
            ["gh", "api", f"/advisories/{ghsa_id}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, "network-error"
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        # gh returns rc=1 with "HTTP 404" on genuine not-found
        if "404" in stderr or "Not Found" in stderr:
            return None, "not-found"
        return None, "network-error"
    try:
        return json.loads(proc.stdout), "hit"
    except json.JSONDecodeError:
        return None, "network-error"


# -----------------------------------------------------------------------------
# Public verification API
# -----------------------------------------------------------------------------


def _envelope(record: Any, *, status: str, source: str, cve_or_ghsa: str, rid: str) -> dict:
    """Wrap a raw advisory record (or empty) with a ``__verification__``
    envelope so the caller can tell hit vs not-found vs blocked apart even
    when the body is empty.
    """
    out: dict = {}
    if isinstance(record, dict):
        out.update(record)
    out["__verification__"] = {
        "kind": cve_or_ghsa,
        "id": rid,
        "status": status,         # "hit" | "not-found" | "blocked-offline" | "network-error" | "cache-hit" | "cache-tombstone"
        "source": source,         # "nvd-live" | "ghsa-live" | "nvd-cache" | "ghsa-cache"
        "checked_at": int(time.time()),
    }
    return out


def verify_cve_id(
    cve_id: str,
    *,
    cache: Optional[DiskCache] = None,
    force_refresh: bool = False,
) -> dict:
    """Look up ``cve_id`` against NVD with disk caching.

    Returns a dict with a ``__verification__`` envelope. When the advisory
    exists, the dict also carries the upstream NVD fields (``descriptions``,
    ``configurations``, ``references``, ...). When it does NOT exist (or the
    network is unreachable), only ``__verification__`` is populated; the
    dict is otherwise empty and evaluates truthy ONLY because of the envelope.
    Callers should inspect ``result.get("__verification__", {}).get("status")``
    to decide.
    """
    if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
        return _envelope({}, status="invalid-id", source="local", cve_or_ghsa="CVE", rid=str(cve_id))

    cve_id_norm = cve_id.upper()
    c = cache or get_shared_cache()

    if not force_refresh:
        hit, payload = c.get("cve", cve_id_norm)
        if hit:
            if payload is None:
                return _envelope({}, status="cache-tombstone", source="nvd-cache",
                                 cve_or_ghsa="CVE", rid=cve_id_norm)
            return _envelope(payload, status="cache-hit", source="nvd-cache",
                             cve_or_ghsa="CVE", rid=cve_id_norm)

    payload, status = _fetch_nvd(cve_id_norm)
    if status in ("hit", "not-found"):
        # cache both hits and explicit not-found (tombstone)
        c.put("cve", cve_id_norm, payload)
    return _envelope(payload, status=status, source="nvd-live",
                     cve_or_ghsa="CVE", rid=cve_id_norm)


def verify_ghsa_id(
    ghsa_id: str,
    *,
    cache: Optional[DiskCache] = None,
    force_refresh: bool = False,
) -> dict:
    """Look up ``ghsa_id`` against GitHub's advisory DB via ``gh api`` with
    disk caching. Semantics mirror ``verify_cve_id``.
    """
    if not isinstance(ghsa_id, str) or not GHSA_RE.fullmatch(ghsa_id):
        return _envelope({}, status="invalid-id", source="local", cve_or_ghsa="GHSA", rid=str(ghsa_id))

    c = cache or get_shared_cache()
    if not force_refresh:
        hit, payload = c.get("ghsa", ghsa_id)
        if hit:
            if payload is None:
                return _envelope({}, status="cache-tombstone", source="ghsa-cache",
                                 cve_or_ghsa="GHSA", rid=ghsa_id)
            return _envelope(payload, status="cache-hit", source="ghsa-cache",
                             cve_or_ghsa="GHSA", rid=ghsa_id)

    payload, status = _fetch_ghsa(ghsa_id)
    if status in ("hit", "not-found"):
        c.put("ghsa", ghsa_id, payload)
    return _envelope(payload, status=status, source="ghsa-live",
                     cve_or_ghsa="GHSA", rid=ghsa_id)


# -----------------------------------------------------------------------------
# Product/repo attribution
# -----------------------------------------------------------------------------


def _normalise_repo_tokens(repo: str) -> set[str]:
    if not repo:
        return set()
    tokens = re.split(r"[\s/_\-\.,]+", repo.lower())
    return {t for t in tokens if t and len(t) > 2}


def _flatten_advisory_evidence(advisory_record: dict) -> list[str]:
    """Pull strings (descriptions, CPE URIs, references, ecosystem packages)
    out of an NVD or GHSA record so we can do token-overlap matching against
    a target_repo string. Mirrors the sweep tool's evidence shape.
    """
    if not isinstance(advisory_record, dict):
        return []
    parts: list[str] = []

    # NVD-shape descriptions
    for desc in (advisory_record.get("descriptions") or [])[:5]:
        if isinstance(desc, dict):
            v = desc.get("value")
            if isinstance(v, str):
                parts.append(v)

    # NVD-shape configurations -> CPE
    for cfg in advisory_record.get("configurations") or []:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for cpe in node.get("cpeMatch") or []:
                if not isinstance(cpe, dict):
                    continue
                for k in ("criteria", "cpe23Uri"):
                    v = cpe.get(k)
                    if isinstance(v, str):
                        parts.append(v)

    # NVD-shape references
    for ref in advisory_record.get("references") or []:
        if isinstance(ref, dict):
            u = ref.get("url")
            if isinstance(u, str):
                parts.append(u)
        elif isinstance(ref, str):
            parts.append(ref)

    # GHSA-shape summary
    summary = advisory_record.get("summary")
    if isinstance(summary, str):
        parts.append(summary)

    # GHSA-shape vulnerabilities[].package
    for v in (advisory_record.get("vulnerabilities") or []):
        if not isinstance(v, dict):
            continue
        pkg = v.get("package") or {}
        if isinstance(pkg, dict):
            for k in ("ecosystem", "name"):
                val = pkg.get(k)
                if isinstance(val, str):
                    parts.append(val)

    return [p for p in parts if p]


def attribution_matches_repo(advisory_record: dict, target_repo: str) -> tuple[bool, str]:
    """Heuristic repo-token-overlap check.

    Returns ``(matched, reason)``:

    * ``matched=True, reason='match:<tokens>'`` - one or more strong tokens
      (i.e. NOT in :data:`WEAK_REPO_TOKENS`) appear in the advisory's
      description / CPE / references / package.
    * ``matched=False, reason='weak-match-only:<tokens>'`` - only common
      tokens overlap. Caller should treat as ``UNVERIFIED-WEAK-MATCH``.
    * ``matched=False, reason='no-token-overlap'`` - definitive mismatch.
    * ``matched=False, reason='empty-target-repo'`` - cannot decide.
    * ``matched=False, reason='no-advisory-body'`` - advisory dict was empty
      / not-found. Caller decides whether that's a quarantine reason.
    """
    if not isinstance(advisory_record, dict) or not _flatten_advisory_evidence(advisory_record):
        # If we have ONLY an envelope (or nothing), there is no body to
        # match against. The caller should usually treat this as a hard
        # fail (UNVERIFIED-NOT-FOUND or UNVERIFIED-BLOCKED-NO-NETWORK)
        # based on the envelope's status.
        if "__verification__" in (advisory_record or {}):
            return False, "no-advisory-body"
        return False, "no-advisory-body"
    tokens = _normalise_repo_tokens(target_repo)
    if not tokens:
        return False, "empty-target-repo"
    haystack = " ".join(_flatten_advisory_evidence(advisory_record)).lower()
    hits = [t for t in tokens if t in haystack]
    strong_hits = [t for t in hits if t not in WEAK_REPO_TOKENS]
    if strong_hits:
        return True, "match:" + ",".join(sorted(strong_hits))
    if hits:
        return False, "weak-match-only:" + ",".join(sorted(hits))
    return False, "no-token-overlap"


# -----------------------------------------------------------------------------
# Pre-emit gate
# -----------------------------------------------------------------------------


def _iter_record_strings(node: Any) -> Iterable[str]:
    """Yield every string scalar reachable from a YAML-style nested dict/list.
    Used to scrape CVE/GHSA IDs out of a record without forcing the miner
    to enumerate every field.
    """
    if isinstance(node, str):
        yield node
        return
    if isinstance(node, dict):
        for v in node.values():
            yield from _iter_record_strings(v)
        return
    if isinstance(node, list):
        for v in node:
            yield from _iter_record_strings(v)


def _extract_ids_from_record(record: dict) -> tuple[list[str], list[str]]:
    cves: list[str] = []
    ghsas: list[str] = []
    seen_c: set[str] = set()
    seen_g: set[str] = set()
    for s in _iter_record_strings(record):
        for m in CVE_RE.finditer(s):
            cid = m.group(0).upper()
            if cid not in seen_c:
                seen_c.add(cid)
                cves.append(cid)
        for m in GHSA_RE.finditer(s):
            gid = m.group(0)
            if gid not in seen_g:
                seen_g.add(gid)
                ghsas.append(gid)
    return cves, ghsas


def pre_emit_check(
    record: dict,
    *,
    strict: bool = True,
    cache: Optional[DiskCache] = None,
) -> tuple[bool, str]:
    """Verify every CVE / GHSA claim inside ``record`` BEFORE the miner writes
    it to ``audit/corpus_tags/tags/``.

    Behaviour:

    * If the record contains no CVE/GHSA references at all, returns
      ``(True, "no-claims")`` - the gate is a no-op for non-CVE-anchored
      records. Note: the BURDEN of asserting "this record claims CVE-X" lies
      with the miner; if the miner intends a CVE attribution it MUST include
      the ID somewhere reachable from the record (typical: a top-level
      ``source_audit_ref``, ``attacker_action_sequence``, or
      ``cross_language_analogues[].pattern_translation`` string).
    * If the record contains a ``target_repo`` and at least one CVE/GHSA, the
      gate fetches each advisory (live or cache), runs
      :func:`attribution_matches_repo`, and aggregates worst-case across all
      claims. Verdicts roll up:

      - any ``not-found`` -> ``(False, "not-found:<id>")``
      - any ``network-error``/``blocked-offline`` -> ``(False, "blocked:<id>")``
        unless ALL OTHER claims are clean matches, in which case the caller
        can still emit but must record ``verification_method="manual"`` and
        a quarantine shape_tag.
      - any ``no-token-overlap`` -> ``(False, "mismatched:<id>")``
      - any ``weak-match-only`` -> ``(False, "weak-match:<id>")``
      - else ``(True, "verified:<n-claims>")``

    * If ``strict=True`` and the verdict is False, raises ``ValueError``
      (helpful default for miners; convert to a quarantine route by catching
      the exception or passing ``strict=False``).

    The caller is expected to apply the returned verdict by:

    * On success: setting ``verification_method`` to one of ``nvd-live`` /
      ``ghsa-live`` / ``nvd-cache`` / ``ghsa-cache`` / ``manual`` on the
      record before writing it to canonical tags.
    * On failure: routing the record to
      ``audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/`` and ADDING one
      of :data:`UNVERIFIED_SHAPE_TAGS` to ``function_shape.shape_tags`` (and
      optionally setting ``attribution_verdict`` if the miner uses that
      out-of-schema sidecar field).
    """
    cves, ghsas = _extract_ids_from_record(record)
    if not cves and not ghsas:
        return True, "no-claims"

    target_repo = ""
    if isinstance(record, dict):
        tr = record.get("target_repo")
        if isinstance(tr, str):
            target_repo = tr

    reasons: list[str] = []
    sources_used: set[str] = set()
    any_blocked = False

    def _judge(advisory: dict, kind_label: str, rid: str) -> Optional[str]:
        env = advisory.get("__verification__") or {}
        status = env.get("status")
        src = env.get("source")
        if src:
            sources_used.add(src)
        if status in ("not-found", "cache-tombstone"):
            return f"not-found:{rid}"
        if status in ("network-error", "blocked-offline", "invalid-id"):
            nonlocal_marker.append(True)
            return f"blocked:{rid}({status})"
        # status == hit | cache-hit -> run attribution match
        matched, reason = attribution_matches_repo(advisory, target_repo)
        if matched:
            return None
        if reason == "empty-target-repo":
            return f"missing-target-repo:{rid}"
        if reason.startswith("weak-match-only"):
            return f"weak-match:{rid}:{reason}"
        return f"mismatched:{rid}:{reason}"

    # Trick to mutate 'any_blocked' from inner closure
    nonlocal_marker: list = []

    for cid in cves:
        advisory = verify_cve_id(cid, cache=cache)
        r = _judge(advisory, "CVE", cid)
        if r:
            reasons.append(r)
    for gid in ghsas:
        advisory = verify_ghsa_id(gid, cache=cache)
        r = _judge(advisory, "GHSA", gid)
        if r:
            reasons.append(r)

    any_blocked = bool(nonlocal_marker)

    if reasons:
        agg = ";".join(reasons)
        ok = False
        if strict:
            raise ValueError(f"pre_emit_check failed: {agg}")
        return ok, agg

    method = None
    if sources_used <= {"nvd-cache", "ghsa-cache"}:
        method = "cache"
    elif "nvd-live" in sources_used and "ghsa-live" in sources_used:
        method = "nvd-live+ghsa-live"
    elif "nvd-live" in sources_used:
        method = "nvd-live"
    elif "ghsa-live" in sources_used:
        method = "ghsa-live"
    else:
        method = "manual"
    return True, f"verified:{len(cves) + len(ghsas)} via {method}"


# -----------------------------------------------------------------------------
# CLI (debug)
# -----------------------------------------------------------------------------


def _main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Hackerman CVE/GHSA pre-emit verifier")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("verify-cve", help="Look up a CVE ID")
    pc.add_argument("cve_id")
    pc.add_argument("--force-refresh", action="store_true")

    pg = sub.add_parser("verify-ghsa", help="Look up a GHSA ID")
    pg.add_argument("ghsa_id")
    pg.add_argument("--force-refresh", action="store_true")

    pp = sub.add_parser("check", help="Run pre_emit_check on a record JSON file")
    pp.add_argument("record_path")
    pp.add_argument("--strict", action="store_true")

    pr = sub.add_parser("prune-cache", help="Prune disk cache of stale rows")

    args = p.parse_args(argv)

    if args.cmd == "verify-cve":
        rec = verify_cve_id(args.cve_id, force_refresh=args.force_refresh)
        json.dump(rec.get("__verification__", {}), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.cmd == "verify-ghsa":
        rec = verify_ghsa_id(args.ghsa_id, force_refresh=args.force_refresh)
        json.dump(rec.get("__verification__", {}), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.cmd == "check":
        with open(args.record_path, "r", encoding="utf-8") as fp:
            record = json.load(fp)
        try:
            ok, reason = pre_emit_check(record, strict=args.strict)
        except ValueError as exc:
            print(f"FAIL strict: {exc}", file=sys.stderr)
            return 1
        print(f"{'OK' if ok else 'FAIL'}: {reason}")
        return 0 if ok else 1
    if args.cmd == "prune-cache":
        n = get_shared_cache().prune()
        print(f"cache kept rows: {n}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(_main())
