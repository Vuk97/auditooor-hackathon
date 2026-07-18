#!/usr/bin/env python3
"""Rule 77 external-dependency-behavior-must-be-source-verified gate.

A HIGH+ load-bearing / amplification / attack-delivery argument that makes a
BEHAVIORAL claim about a THIRD-PARTY dependency's runtime behavior (how a named
external library/crate/package PROCESSES input on the attack path:
concurrency/parallelism, batching, async scheduling, thread-pool, connection
handling, parsing/serialization limits) MUST cite the dependency's ACTUAL source
(a file path under a package cache - ~/.cargo/registry, vendor/, node_modules,
go/pkg/mod, site-packages, gems - with a quoted snippet/line ref) OR an executed
test transcript against the real dependency. Otherwise the behavior was ASSUMED.

Empirical anchor (zebra batch over-claim, 2026-06-02): a HIGH zebra finding
claimed "one HTTP JSON-RPC batch launches K concurrent scans" - an amplification
mechanism resting on jsonrpsee-server-0.24.10 batch behavior. That behavior was
ASSUMED, not read. The real crate source
(~/.cargo/registry/.../jsonrpsee-server-0.24.10/src/server.rs:1318) processes a
batch SEQUENTIALLY (`for call in batch { rpc_service.call(req).await }`). The
over-claim survived every gate (R76 only checks WORKSPACE source-existence, not
external-dependency BEHAVIOR). A reviewer caught it manually; the finding was
corrected HIGH -> MEDIUM.

This is the EXTERNAL-dependency-behavior sibling of R76 (R76 = workspace
source-existence of a cited code_excerpt; R77 = third-party dependency runtime
BEHAVIOR on the load-bearing path).

Verdict vocabulary:
  pass-out-of-scope                          severity below HIGH (or missing)
  pass-no-external-dep-behavior-claim        HIGH+ but no third-party behavioral
                                             claim on the load-bearing path
  pass-external-dep-behavior-source-cited    behavioral claim cites the dep's
                                             real source path + snippet, OR an
                                             executed test transcript against it
  ok-rebuttal                                <!-- r77-rebuttal: <reason> -->
  fail-external-dep-behavior-assumed         HIGH+ load-bearing behavioral claim
                                             about an external dep with no source
                                             citation and no executed test
  error                                      input error

Env extension hooks (newline-separated regex lists appended to defaults):
  AUDITOOOR_R77_DEP_NAME_PATTERNS       extra external-dependency name regexes
  AUDITOOOR_R77_BEHAVIOR_VERB_PATTERNS  extra behavioral-verb regexes
  AUDITOOOR_R77_DEP_CACHE_PATTERNS      extra package-cache path regexes

CLI: <draft.md> [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}] [--strict] [--json]

Exit codes: 0 = pass / out-of-scope / accepted rebuttal, 1 = violation, 2 = error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r77_external_dependency_behavior.v1"
GATE = "R77-EXTERNAL-DEP-BEHAVIOR"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Low-FP trigger detection.
#
# The gate fires ONLY when, on the SAME load-bearing/amplification line, BOTH:
#   (1) a named EXTERNAL dependency is present, AND
#   (2) a BEHAVIORAL verb about how that dependency PROCESSES input is present.
# This co-occurrence requirement is what keeps the false-positive rate low: a
# draft that cites its own workspace source, or names a dependency without a
# behavioral claim, or makes a behavioral claim about its own code, does not
# fire.
# ---------------------------------------------------------------------------

# Load-bearing / amplification framing: the gate only inspects lines that carry
# amplification or attack-delivery weight. A behavioral mention buried in a
# background paragraph is not load-bearing.
LOAD_BEARING_RE = re.compile(
    r"\b(?:"
    r"amplif\w+|fan[- ]?out|multiplic\w+|each\s+\w+\s+(?:launch|spawn|trigger)|"
    r"one\s+\w+\s+(?:launch|spawn|trigger|cause)|"
    r"per[- ]request|per[- ]batch|per[- ]connection|"
    r"attack\s+(?:path|delivery|vector|surface)|"
    r"load[- ]bearing|blow[- ]?up|"
    r"K\s+concurrent|N\s+concurrent|\d+x\b|\d+\s*[x×]\b|"
    r"resource\s+exhaust\w+|exhaust\w+\s+(?:cpu|memory|thread|connection|worker)|"
    r"unbounded\s+(?:concurren\w+|paralleli\w+|spawn\w+|fan)"
    r")\b",
    re.IGNORECASE,
)

# Behavioral verbs about how a dependency PROCESSES input.
BEHAVIOR_VERB_DEFAULTS = (
    # concurrency / parallelism
    r"concurrent(?:ly)?", r"in\s+parallel", r"paralleli[sz]e\w*", r"fan[- ]?out",
    r"simultaneous(?:ly)?",
    # batching / pipelining
    r"batch(?:es|ed|ing)?", r"pipelin\w+",
    # async scheduling
    r"spawn(?:s|ed|ing)?", r"await\w*", r"executor", r"runtime\s+(?:schedul|spawn)",
    r"FuturesUnordered", r"join_all", r"tokio::spawn", r"async\s+task",
    r"event\s+loop", r"reactor",
    # thread-pool
    r"thread[- ]?pool", r"blocking\s+pool", r"worker\s+threads?", r"rayon",
    # connection handling
    r"max_connections?", r"keep[- ]?alive", r"connection\s+pool",
    r"per[- ]connection\s+task",
    # parsing / serialization limits
    r"deseriali[sz]e\w*\s+(?:without|unbounded|recursi\w+)",
    r"parse(?:s|d)?\s+(?:without|unbounded|recursi\w+)",
    r"recursion\s+limit", r"depth\s+limit", r"no\s+size\s+limit",
    # generic processing verbs that imply runtime behavior
    r"process(?:es|ed)?\s+(?:concurrent|in\s+parallel|sequential\w*|each|every)",
    r"handle(?:s)?\s+(?:concurrent|in\s+parallel|each|every)",
    r"dispatch(?:es|ed)?\s+(?:concurrent|in\s+parallel|each|every)",
)

# Named external dependencies. Two families:
#   (a) a curated set of common crate/package names, AND
#   (b) a structural signal: a path under a package cache (always external).
DEP_NAME_DEFAULTS = (
    # rust crates
    r"jsonrpsee", r"tokio", r"hyper", r"axum", r"tower", r"reqwest", r"serde",
    r"serde_json", r"rayon", r"futures", r"async-std", r"actix", r"warp",
    r"rocket", r"tonic", r"prost", r"sqlx", r"diesel", r"rocksdb", r"libp2p",
    r"ethers", r"alloy", r"web3",
    # go libs
    r"grpc-go", r"net/http", r"gorilla/\w+", r"gin-gonic", r"fasthttp",
    r"cosmos-sdk", r"cometbft", r"tendermint",
    # js/ts
    r"express", r"fastify", r"ws\b", r"socket\.io", r"undici", r"node-fetch",
    r"bullmq", r"ioredis",
    # python
    r"asyncio", r"aiohttp", r"uvicorn", r"gunicorn", r"celery", r"fastapi",
    r"starlette",
    # solidity libs
    r"openzeppelin", r"solmate", r"solady",
)

# Package-cache path fragments. A path under any of these is DEFINITIVELY an
# external dependency, regardless of the curated name list.
DEP_CACHE_DEFAULTS = (
    r"\.cargo/registry", r"\.cargo/git", r"/vendor/", r"node_modules",
    r"/pkg/mod/", r"go/pkg/mod", r"site-packages", r"\.venv/", r"/gems/",
    r"\.m2/repository", r"\.gradle/caches",
)

# An external-dependency name appearing right next to a scoped @scope/pkg form.
SCOPED_PKG_RE = re.compile(r"@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*", re.IGNORECASE)

# Source-citation signals: a path under a package cache (with optional :line) OR
# an explicit executed-test transcript marker.
SOURCE_CITE_RE = re.compile(
    r"(?:"
    # path under a package cache, e.g. .cargo/registry/.../server.rs:1318
    r"(?:\.cargo/registry|\.cargo/git|/vendor/|node_modules|go/pkg/mod|/pkg/mod/|"
    r"site-packages|\.venv/|/gems/|\.m2/repository)"
    r"[^\s`)]*\.[A-Za-z0-9_]+(?::\d+)?"
    r")",
    re.IGNORECASE,
)

# Executed-test transcript markers proving the behavior was observed, not assumed.
EXECUTED_TEST_RE = re.compile(
    r"\b(?:"
    r"---\s*PASS:|test\s+result:\s*ok|Suite\s+result:\s*ok|running\s+\d+\s+tests?|"
    r"cargo\s+test|go\s+test\b|forge\s+test|pytest\b|npm\s+test|"
    r"executed\s+(?:test|harness)\s+against\s+(?:the\s+)?(?:real|actual)\s+"
    r"(?:dep|dependency|crate|library|package)"
    r")",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r77-rebuttal:\s*(.{1,200}?)\s*-->", re.IGNORECASE | re.DOTALL)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not\s+claimed|no\s+claim|does\s+not\s+claim|not\s+relying\s+on|"
    r"hypothetically|for\s+example\b|e\.g\.,?\s+if)\b",
    re.IGNORECASE,
)


def _env_patterns(var: str) -> list[str]:
    raw = os.environ.get(var, "")
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def _compile_alt(defaults: tuple[str, ...], env_var: str) -> re.Pattern[str]:
    pats = list(defaults) + _env_patterns(env_var)
    return re.compile(r"\b(?:" + "|".join(pats) + r")\b", re.IGNORECASE)


def _behavior_re() -> re.Pattern[str]:
    pats = list(BEHAVIOR_VERB_DEFAULTS) + _env_patterns("AUDITOOOR_R77_BEHAVIOR_VERB_PATTERNS")
    return re.compile(r"(?:" + "|".join(pats) + r")", re.IGNORECASE)


def _dep_name_re() -> re.Pattern[str]:
    return _compile_alt(DEP_NAME_DEFAULTS, "AUDITOOOR_R77_DEP_NAME_PATTERNS")


def _dep_cache_re() -> re.Pattern[str]:
    pats = list(DEP_CACHE_DEFAULTS) + _env_patterns("AUDITOOOR_R77_DEP_CACHE_PATTERNS")
    return re.compile(r"(?:" + "|".join(pats) + r")", re.IGNORECASE)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    sev = r"\**\s*(Critical|High|Medium|Low)\b\**"
    for pattern, source in (
        (rf"(?im)^\s*\**\s*Severity\s*:\**\s*{sev}", "severity-header"),
        (rf"(?im)^\s*severity_implied\s*:\s*{sev}", "program-impact-mapping"),
        (rf"(?im)^\s*severity_tier\s*:\s*{sev}", "impact-contract"),
        (rf"(?im)^\s*selected_severity\s*:\s*{sev}", "selected-severity"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _has_dep_on_line(line: str, dep_name_re: re.Pattern[str],
                     dep_cache_re: re.Pattern[str]) -> str | None:
    """Return the matched dependency token if the line names an external dep."""
    m = dep_cache_re.search(line)
    if m:
        return m.group(0)
    m = dep_name_re.search(line)
    if m:
        return m.group(0)
    m = SCOPED_PKG_RE.search(line)
    if m:
        return m.group(0)
    return None


def run(draft: Path, *, severity_override: str | None = None,
        strict: bool = False) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION, "gate": GATE, "file": str(draft),
            "verdict": "error", "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "gate": GATE, "file": str(draft),
        "severity": severity, "severity_source": severity_source, "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Cite the dependency's ACTUAL source: a path under .cargo/registry / "
            "vendor / node_modules / go/pkg/mod / site-packages with a quoted "
            "snippet or :line ref proving the claimed behavior.",
            "OR include an executed test transcript run against the real "
            "dependency (--- PASS: / test result: ok) proving the behavior.",
            "OR escalate-first then measure: if the behavior is not what you "
            "assumed, walk the severity back to the measured class (R34/R40).",
            "Use <!-- r77-rebuttal: reason --> only for a bounded, source-backed "
            "exception (e.g. behavior is documented in a cited public spec).",
        ],
    }

    # Below HIGH -> out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = REBUTTAL_RE.search(text)
    if rebuttal and rebuttal.group(1).strip():
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = f"r77-rebuttal accepted: {rebuttal.group(1).strip()[:200]}"
        return 0, payload

    behavior_re = _behavior_re()
    dep_name_re = _dep_name_re()
    dep_cache_re = _dep_cache_re()

    # Find load-bearing lines that ALSO name an external dep AND make a
    # behavioral claim. All three must co-occur (low-FP requirement).
    trigger_hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if NEGATIVE_SCOPE_RE.search(line):
            continue
        if not LOAD_BEARING_RE.search(line):
            continue
        dep = _has_dep_on_line(line, dep_name_re, dep_cache_re)
        if not dep:
            continue
        bm = behavior_re.search(line)
        if not bm:
            continue
        trigger_hits.append({
            "line": idx, "dependency": dep, "behavior_verb": bm.group(0),
            "text": line.strip()[:240],
        })
        if len(trigger_hits) >= 16:
            break

    if not trigger_hits:
        payload["verdict"] = "pass-no-external-dep-behavior-claim"
        payload["reason"] = ("HIGH+ but no third-party behavioral claim on the "
                             "load-bearing / amplification path")
        return 0, payload

    payload["evidence"]["trigger_hits"] = trigger_hits

    # A behavioral claim exists. Is it source-cited (dep cache path + line) OR
    # backed by an executed test transcript against the real dependency?
    source_cites = [m.group(0) for m in SOURCE_CITE_RE.finditer(text)]
    executed = bool(EXECUTED_TEST_RE.search(text))
    payload["evidence"]["source_citations"] = source_cites[:16]
    payload["evidence"]["executed_test_transcript"] = executed

    if source_cites or executed:
        payload["verdict"] = "pass-external-dep-behavior-source-cited"
        payload["reason"] = (
            "behavioral claim is backed by a dependency source citation"
            + (" + executed test transcript" if executed and source_cites
               else " (executed test transcript)" if executed
               else " (package-cache source path)")
        )
        return 0, payload

    payload["verdict"] = "fail-external-dep-behavior-assumed"
    payload["reason"] = (
        "HIGH+ load-bearing argument makes a behavioral claim about external "
        f"dependency '{trigger_hits[0]['dependency']}' "
        f"('{trigger_hits[0]['behavior_verb']}') without citing the dependency's "
        "actual source (package-cache path + snippet) or an executed test "
        "transcript - the behavior is ASSUMED, not verified"
    )
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default="auto",
                        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                                 "low", "medium", "high", "critical"])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity_override=args.severity, strict=args.strict)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[R77] {payload['verdict']}: {payload.get('reason', payload.get('error', ''))}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
