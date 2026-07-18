"""Shared cache/fetch/rate-limit primitives for Wave-2 hackerman web miners.

W2.7.a (see ``docs/WAVE2_W27A_IMMUNEFI_DASHBOARD_SPEC_2026-05-16.md`` §3.3).

Both ``tools/hackerman-etl-from-immunefi-dashboard.py`` and
``tools/hackerman-etl-from-immunefi-medium.py`` reuse this module so that
caching, hashing, rate-limit semantics, and robots.txt handling stay
identical across the family.

Design rules (hard, do not violate):

* Pure-stdlib (urllib + gzip + hashlib + json). No third-party imports
  at module import time so the test harness can load this without
  network availability.
* Network I/O happens ONLY when ``WebCache.fetch(...)`` is called. All
  other helpers (hashing, on-disk layout, robots-decision logic) are
  pure-function.
* Hermetic test discipline: the test suite injects a cached
  ``(url -> bytes)`` mapping via ``WebCache(prefetched=...)`` and the
  miners never reach the network during ``unittest``.
* SHA256 hash evidence is recorded per page (raw HTML bytes hashed),
  written to a sidecar ``.meta.json`` next to the gzipped HTML.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple


__all__ = [
    "WebCache",
    "url_to_sha256",
    "compute_payload_sha256",
    "now_utc_iso",
    "robots_decision",
    "FetchResult",
]


USER_AGENT = "auditooor-hackerman-etl/1.0 (+https://github.com/Vuk97/auditooor)"
DEFAULT_RATE_LIMIT_MS = 1500
DEFAULT_TIMEOUT_S = 20
ROBOTS_TTL_S = 24 * 60 * 60  # 24h


def now_utc_iso() -> str:
    """Return current UTC time as ISO-8601 with trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def url_to_sha256(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def compute_payload_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def robots_decision(
    robots_txt: str,
    *,
    url: str,
    user_agent: str = USER_AGENT,
) -> Dict[str, Any]:
    """Apply a robots.txt body to a URL; return a structured decision.

    Returns a dict with keys ``allowed`` (bool), ``rule`` (matched rule
    or empty), and ``reason`` (short human-readable string).
    """
    if not robots_txt:
        return {"allowed": True, "rule": "", "reason": "no-robots-txt-fetched"}
    parser = urllib.robotparser.RobotFileParser()
    parser.parse(robots_txt.splitlines())
    allowed = parser.can_fetch(user_agent, url)
    return {
        "allowed": bool(allowed),
        "rule": "robotparser:can_fetch",
        "reason": "allowed-by-robots" if allowed else "disallowed-by-robots",
    }


@dataclass
class FetchResult:
    url: str
    payload: bytes
    http_status: int
    content_type: str
    fetched_at_utc: str
    payload_sha256: str
    from_cache: bool
    robots_decision: Dict[str, Any] = field(default_factory=dict)


class WebCache:
    """Disk-backed cache + rate-limited fetcher.

    Parameters
    ----------
    cache_dir:
        Where ``pages/<sha256>.html.gz`` + ``pages/<sha256>.meta.json`` live.
    rate_limit_ms:
        Minimum delay between two outbound HTTP fetches (per cache
        instance). Cached hits do NOT count toward the rate-limit.
    respect_robots:
        If True (default), refuse to fetch any URL disallowed by the
        site's ``robots.txt``. The host's robots.txt is fetched on
        first request and cached for ``ROBOTS_TTL_S``.
    prefetched:
        Hermetic-test injection point. A mapping ``{url: bytes}``; if a
        request matches a key, the bytes are returned immediately
        without touching the network or the disk cache. Used by the
        unittest suite.
    fetcher:
        Optional override for the actual urlopen call. Receives
        ``(url, timeout)`` and must return a tuple ``(bytes, status,
        content_type)``. Default is ``_default_fetcher`` which uses
        ``urllib.request``. Tests pass a stub here when they want to
        simulate 429 / 404 / etc.
    """

    def __init__(
        self,
        cache_dir: Path,
        *,
        rate_limit_ms: int = DEFAULT_RATE_LIMIT_MS,
        respect_robots: bool = True,
        i_acknowledge_tos: bool = False,
        prefetched: Optional[Mapping[str, bytes]] = None,
        fetcher: Optional[Callable[[str, int], Tuple[bytes, int, str]]] = None,
        sleep: Optional[Callable[[float], None]] = None,
        offline: bool = False,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.offline = bool(offline)
        self.pages_dir = self.cache_dir / "pages"
        self.runs_dir = self.cache_dir / "runs"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.pages_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_ms = int(max(0, rate_limit_ms))
        self.respect_robots = bool(respect_robots)
        self.i_acknowledge_tos = bool(i_acknowledge_tos)
        self.prefetched: Dict[str, bytes] = dict(prefetched or {})
        self._fetcher = fetcher or _default_fetcher
        self._sleep = sleep or time.sleep
        self._last_fetch_at: float = 0.0
        self._robots_cache: Dict[str, Tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # On-disk layout
    # ------------------------------------------------------------------
    def cached_paths(self, url: str) -> Tuple[Path, Path]:
        digest = url_to_sha256(url)
        return (self.pages_dir / f"{digest}.html.gz", self.pages_dir / f"{digest}.meta.json")

    def has_cached(self, url: str) -> bool:
        page, meta = self.cached_paths(url)
        return page.exists() and meta.exists()

    def load_cached(self, url: str) -> Optional[FetchResult]:
        page, meta = self.cached_paths(url)
        if not (page.exists() and meta.exists()):
            return None
        with gzip.open(page, "rb") as fh:
            payload = fh.read()
        try:
            metadata = json.loads(meta.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        return FetchResult(
            url=url,
            payload=payload,
            http_status=int(metadata.get("http_status", 200)),
            content_type=str(metadata.get("content_type", "")),
            fetched_at_utc=str(metadata.get("fetched_at_utc", now_utc_iso())),
            payload_sha256=str(metadata.get("payload_sha256", compute_payload_sha256(payload))),
            from_cache=True,
            robots_decision=dict(metadata.get("robots_decision", {})),
        )

    def _write_cache(self, result: FetchResult) -> None:
        page, meta = self.cached_paths(result.url)
        with gzip.open(page, "wb") as fh:
            fh.write(result.payload)
        meta.write_text(
            json.dumps(
                {
                    "url": result.url,
                    "fetched_at_utc": result.fetched_at_utc,
                    "sha256_payload": result.payload_sha256,
                    "payload_sha256": result.payload_sha256,
                    "http_status": result.http_status,
                    "content_type": result.content_type,
                    "robots_decision": result.robots_decision,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Robots.txt
    # ------------------------------------------------------------------
    def _robots_for(self, url: str) -> Dict[str, Any]:
        if not self.respect_robots:
            if not self.i_acknowledge_tos:
                # Soft-error contract per §3.1 of the spec: either alone
                # is invalid. Callers must pass both to bypass.
                return {
                    "allowed": False,
                    "rule": "policy",
                    "reason": "respect_robots=false requires --i-acknowledge-tos",
                }
            return {"allowed": True, "rule": "policy", "reason": "operator-acknowledged-tos"}
        parsed = urllib.parse.urlparse(url)
        host = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = f"{host}/robots.txt"
        now = time.time()
        cached = self._robots_cache.get(host)
        if cached is not None and (now - cached[1]) < ROBOTS_TTL_S:
            return robots_decision(cached[0], url=url)
        # Try prefetched (test injection) first, then network.
        body = ""
        if robots_url in self.prefetched:
            try:
                body = self.prefetched[robots_url].decode("utf-8", errors="replace")
            except Exception:
                body = ""
        else:
            try:
                payload, status, _ctype = self._fetcher(robots_url, DEFAULT_TIMEOUT_S)
                if status == 200:
                    body = payload.decode("utf-8", errors="replace")
            except Exception:
                body = ""
        self._robots_cache[host] = (body, now)
        return robots_decision(body, url=url)

    # ------------------------------------------------------------------
    # Fetch (cache-then-network)
    # ------------------------------------------------------------------
    def fetch(self, url: str, *, force: bool = False) -> FetchResult:
        if not force:
            cached = self.load_cached(url)
            if cached is not None:
                return cached
        # Prefetched-bytes path (tests + offline fixtures).
        if url in self.prefetched:
            payload = self.prefetched[url]
            result = FetchResult(
                url=url,
                payload=payload,
                http_status=200,
                content_type="text/html; charset=utf-8",
                fetched_at_utc=now_utc_iso(),
                payload_sha256=compute_payload_sha256(payload),
                from_cache=False,
                robots_decision={"allowed": True, "rule": "prefetched", "reason": "test-injection"},
            )
            self._write_cache(result)
            return result
        if self.offline:
            raise OfflineCacheMissError(url)
        # Robots check.
        decision = self._robots_for(url)
        if not decision.get("allowed", True):
            raise RobotsDisallowedError(url, decision)
        # Rate-limit between live fetches.
        now = time.time() * 1000.0
        elapsed_ms = now - (self._last_fetch_at * 1000.0)
        if self._last_fetch_at and elapsed_ms < self.rate_limit_ms:
            wait_s = (self.rate_limit_ms - elapsed_ms) / 1000.0
            if wait_s > 0:
                self._sleep(wait_s)
        try:
            payload, status, ctype = self._fetcher(url, DEFAULT_TIMEOUT_S)
        finally:
            self._last_fetch_at = time.time()
        result = FetchResult(
            url=url,
            payload=payload,
            http_status=status,
            content_type=ctype,
            fetched_at_utc=now_utc_iso(),
            payload_sha256=compute_payload_sha256(payload),
            from_cache=False,
            robots_decision=decision,
        )
        if status == 200 and payload:
            self._write_cache(result)
        return result

    # ------------------------------------------------------------------
    # Walk cache
    # ------------------------------------------------------------------
    def iter_cached(self) -> Iterable[FetchResult]:
        for meta_path in sorted(self.pages_dir.glob("*.meta.json")):
            try:
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            url = metadata.get("url")
            if not url:
                continue
            result = self.load_cached(url)
            if result is not None:
                yield result


class RobotsDisallowedError(RuntimeError):
    def __init__(self, url: str, decision: Mapping[str, Any]) -> None:
        super().__init__(f"robots.txt disallows {url}: {decision.get('reason', 'unknown')}")
        self.url = url
        self.decision = dict(decision)


class OfflineCacheMissError(RuntimeError):
    def __init__(self, url: str) -> None:
        super().__init__(f"offline mode and url not in cache/prefetched: {url}")
        self.url = url


def _default_fetcher(url: str, timeout: int) -> Tuple[bytes, int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            status = int(getattr(resp, "status", 200))
            ctype = str(resp.headers.get("Content-Type", ""))
            return payload, status, ctype
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read() or b""
        except Exception:
            body = b""
        return body, int(exc.code), str(exc.headers.get("Content-Type", "") if exc.headers else "")
