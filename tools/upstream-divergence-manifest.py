#!/usr/bin/env python3
"""upstream-divergence-manifest.py - known-upstream-fork semantic deviation gate.

WHY THIS EXISTS (the false-green it closes)
-------------------------------------------
The existing ``fork-divergence`` signal (audit-completeness-check.py signal (k),
``check_fork_divergence`` @ line 4298) fires on GIT PINS (Cargo ``rev=``,
go.mod ``replace``/pseudo-version, vendored trees) and only proves "the
fork-divergence PROBER ran". It does NOT check for KNOWN UPSTREAM PROTOCOL
identity (liquity / threshold-usd / uniswap / compound / aave / solady / morpho /
openzeppelin forks), and the artifact it accepts is a prober-ran receipt - not a
SEMANTIC DEVIATION LIST. This is EXTEND-not-rebuild: the new signal is
complementary, not a duplicate (tool-duplication preflight clean: grep confirmed
no ``.auditooor/upstream_divergence.json`` convention exists in the codebase).

TWO-STAGE DESIGN
-----------------
Stage 1 - DETECT: does this workspace audit a KNOWN-UPSTREAM PROTOCOL fork?
  Grep in order (stops at first positive hit):
  (a) <ws>/fork_target.json  - explicit operator-declared fork target
  (b) package.json dependencies / devDependencies for known upstream names
  (c) go.mod require / module lines
  (d) Cargo.toml [dependencies] / [workspace.dependencies]
  (e) docs/SCOPE.md, SCOPE.md, README.md for upstream name keywords

Stage 2 - GATE: if a fork is detected, REQUIRE a POPULATED deviation list.
  <ws>/.auditooor/upstream_divergence.json must exist AND pass content checks:
    schema: "auditooor.upstream_divergence_manifest.v1"
    upstream: <non-empty string>
    deviations: <non-empty list of {file, kind, summary}>
  Mere presence of an empty / stub file is NOT credit (content-checked, not
  presence-checked). If no fork is detected, the gate passes with n/a-pass.

SIGNAL KEY: ``fork-divergence-content``
FAIL VERDICT: ``fail-upstream-fork-divergence-manifest-missing``
L37-REBUTTAL: operator line ``fork-divergence-content: <reason>`` in
  <ws>/.auditooor/audit_completeness_rebuttal.txt flips to ``ok-rebuttal``
  via the existing _rebuttal_for path in audit-completeness-check.py (the
  evaluate() wrapper owns the rebuttal check; this tool never self-greens).

VERDICT VOCABULARY
------------------
- ``pass-fork-divergence-populated``       fork detected + manifest is non-empty.
- ``pass-no-fork-detected``                no upstream fork markers found (n/a).
- ``pass-no-source``                       no in-scope source found at all.
- ``fail-upstream-fork-divergence-manifest-missing``  fork detected but manifest
                                           absent or empty (content check failed).
- ``error``                                unreadable workspace / internal error.

MANIFEST SCHEMA (upstream_divergence.json)
------------------------------------------
{
  "schema": "auditooor.upstream_divergence_manifest.v1",
  "upstream": "<upstream project name or URL>",
  "deviations": [
    {
      "file": "<ws-relative source path>",
      "kind": "<added|removed|modified|renamed>",
      "summary": "<one-line human description of the deviation>"
    }
  ]
}
Minimum requirement: non-empty deviations list with >=1 entry where each entry
has non-empty "file", "kind", and "summary" strings.

KNOWN UPSTREAM MARKERS (curated set, case-insensitive)
-------------------------------------------------------
liquity, threshold-usd, thresholdusd, uniswap, compound, aave, solady,
morpho, openzeppelin, oz-contracts, @openzeppelin, balancer, curve-fi,
curvefi, frax-finance, fraxfinance, maker-dao, makerdao, synthetix,
yearn-finance, yearnfinance, rocketpool, rocket-pool, lido-finance,
lidofinance, gmx-io, gmxio, pendle-finance, pendlefinance, euler-finance,
eulerfinance, radiant-capital, radiantcapital, silo-finance, silofinance,
notional-finance, notionalfinance, vesta-finance, vestafinance, angle-protocol,
angleprotocol, sparklend, spark-protocol, venus-protocol, venusprotocol.

False-green-safe: a false-PASS here means the gate missed a fork (a miss we
log but never silently tolerate in the tooling). A false-FAIL is always
rebuttable via the standard l37-rebuttal operator line.

Dependency-free: stdlib only, offline-safe, never executes target code.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SCHEMA_OUT = "auditooor.upstream_divergence_manifest.v1"
MANIFEST_SCHEMA_KEY = "auditooor.upstream_divergence_manifest.v1"
GATE = "UPSTREAM-DIVERGENCE-MANIFEST"

# Relative path for the manifest artifact.
_MANIFEST_REL = (".auditooor", "upstream_divergence.json")

# Explicit fork target declaration file.
_FORK_TARGET_REL = "fork_target.json"

# Source extensions we treat as in-scope for the no-source guard
# (mirrors core-coverage-completeness.py).
_SRC_EXTS = (".sol", ".vy", ".rs", ".go", ".move", ".cairo")
_SKIP_DIRS = {
    ".git", "node_modules", "lib", "out", "artifacts", "cache", "target",
    "vendor", "third_party", ".audit_logs", ".auditooor", "submissions",
    "prior_audits", "reports", "docs", "test", "tests", "mocks",
}

# Known upstream protocol names (lower-case; matched as substrings in dep
# names / module paths / doc prose).
_KNOWN_UPSTREAMS: list[str] = [
    "liquity",
    "threshold-usd", "thresholdusd",
    "uniswap",
    "compound",
    "aave",
    "solady",
    "morpho",
    "openzeppelin", "oz-contracts", "@openzeppelin",
    "balancer",
    "curve-fi", "curvefi",
    "frax-finance", "fraxfinance",
    "maker-dao", "makerdao",
    "synthetix",
    "yearn-finance", "yearnfinance",
    "rocketpool", "rocket-pool",
    "lido-finance", "lidofinance",
    "gmx-io", "gmxio",
    "pendle-finance", "pendlefinance",
    "euler-finance", "eulerfinance",
    "radiant-capital", "radiantcapital",
    "silo-finance", "silofinance",
    "notional-finance", "notionalfinance",
    "vesta-finance", "vestafinance",
    "angle-protocol", "angleprotocol",
    "sparklend", "spark-protocol",
    "venus-protocol", "venusprotocol",
]

# Build a single compiled regex for fast text matching.
_UPSTREAM_RE = re.compile(
    "|".join(re.escape(u) for u in _KNOWN_UPSTREAMS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(p: Path) -> str | None:
    try:
        if p.is_file() and p.stat().st_size > 0:
            return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _read_json(p: Path):
    txt = _read_text(p)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except (ValueError, TypeError):
        return None


def _has_in_scope_source(ws: Path) -> bool:
    try:
        for p in ws.rglob("*"):
            if not p.is_file() or p.suffix not in _SRC_EXTS:
                continue
            if set(p.parts) & _SKIP_DIRS:
                continue
            return True
    except OSError:
        pass
    return False


_FORK_CONTEXT_RE = re.compile(
    r"\b(fork(?:ed|s)?|forking|based\s+on|derived\s+from|"
    r"built\s+on\s+top\s+of|adapted\s+from)\b",
    re.IGNORECASE,
)


def _prose_fork_context(txt: str, match_start: int) -> bool:
    """True iff a fork-indicator keyword sits on the SAME line as the upstream name.

    Distinguishes "this protocol is a fork of Aave V3" (a fork) from a bare name in
    a prior-audit-firm / dependency list ("OpenZeppelin, Sherlock, Cantina collected
    into prior_audits/") where no fork verb is adjacent. Line-scoped so a stray
    "hardfork"/"mainnet fork" elsewhere in the doc cannot manufacture a false fork.
    """
    line_start = txt.rfind("\n", 0, match_start) + 1
    line_end = txt.find("\n", match_start)
    if line_end == -1:
        line_end = len(txt)
    return _FORK_CONTEXT_RE.search(txt[line_start:line_end]) is not None


def _upstream_has_in_scope_source(ws: Path, token: str) -> bool:
    """True iff an in-scope source file's path bears the upstream ``token``.

    The prose surfaces (SCOPE.md / README.md) are the WEAKEST fork signal: a bare
    name in a doc is routinely NOT a fork - e.g. optimism's SCOPE.md lists
    "OpenZeppelin" as a prior-audit FIRM ("OpenZeppelin, Sherlock, Cantina ...
    collected into prior_audits/"), and many workspaces name a VENDORED OOS lib in
    an exclusions note. A genuine fork instead ships the upstream's source AS
    in-scope audit surface. We corroborate the prose hit by requiring at least one
    non-skipped (not lib/ vendor/ test/ ...) source file whose path contains the
    token; when the only matches live under _SKIP_DIRS (i.e. a vendored OOS
    dependency such as contracts-bedrock/lib/openzeppelin-contracts/), this returns
    False and the prose mention is correctly NOT treated as a fork.
    """
    tok = token.lower().lstrip("@").strip()
    if not tok:
        return False
    try:
        for p in ws.rglob("*"):
            if not p.is_file() or p.suffix not in _SRC_EXTS:
                continue
            if set(p.parts) & _SKIP_DIRS:
                continue
            if tok in str(p).lower():
                return True
    except OSError:
        pass
    return False


# ---------------------------------------------------------------------------
# Stage 1: DETECT a known upstream fork
# ---------------------------------------------------------------------------

def _detect_upstream_fork(ws: Path) -> tuple[bool, str, str]:
    """Return (is_fork, upstream_name, detection_source).

    Stops at first positive hit across the detection surfaces (in priority
    order). Non-fork returns (False, "", "").
    """
    # (a) Explicit operator-declared fork_target.json
    ft_path = ws / _FORK_TARGET_REL
    ft = _read_json(ft_path)
    if isinstance(ft, dict):
        upstream = str(ft.get("upstream") or ft.get("fork_of") or "").strip()
        if upstream:
            return True, upstream, "fork_target.json"
        # file exists but upstream field missing -> still a fork declaration
        return True, "(declared)", "fork_target.json (no upstream field)"
    # Also support the .auditooor/ sub-path used by existing detect logic.
    ft2_path = ws / ".auditooor" / "fork_target.json"
    ft2 = _read_json(ft2_path)
    if isinstance(ft2, dict):
        upstream = str(ft2.get("upstream") or ft2.get("fork_of") or "").strip()
        return True, upstream or "(declared)", ".auditooor/fork_target.json"

    # (b) package.json
    pj = _read_json(ws / "package.json")
    if isinstance(pj, dict):
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = pj.get(section) or {}
            if isinstance(deps, dict):
                for dep_name in deps:
                    m = _UPSTREAM_RE.search(str(dep_name))
                    if m:
                        return True, m.group(0).lower(), f"package.json[{section}]"

    # (c) go.mod
    gomod_txt = _read_text(ws / "go.mod") or ""
    if gomod_txt:
        for line in gomod_txt.splitlines():
            m = _UPSTREAM_RE.search(line)
            if m and (line.strip().startswith("require") or
                      line.strip().startswith("module") or
                      "//" not in line.split(m.group(0))[0].strip()):
                return True, m.group(0).lower(), "go.mod"

    # (d) Cargo.toml
    cargo_txt = _read_text(ws / "Cargo.toml") or ""
    if cargo_txt:
        for line in cargo_txt.splitlines():
            m = _UPSTREAM_RE.search(line)
            if m:
                return True, m.group(0).lower(), "Cargo.toml"

    # (e) SCOPE.md / docs/SCOPE.md / README.md prose - WEAKEST signal.
    # A bare upstream name in a doc is routinely NOT a fork: optimism's SCOPE.md
    # lists "OpenZeppelin" as a prior-audit FIRM ("OpenZeppelin, Sherlock, Cantina
    # ... collected into prior_audits/"), and many workspaces name a vendored OOS
    # lib in an exclusions note. Treat a prose mention as a fork ONLY when it is
    # corroborated by either (1) fork CONTEXT - a fork-indicator keyword on the same
    # line as the name ("fork of Aave V3", "forked from ...") - or (2) the upstream's
    # source actually shipped IN-SCOPE (not just under lib/ vendor/). Either signal
    # alone is enough; a bare name with neither must not trip the gate.
    for prose_rel in ("SCOPE.md", "docs/SCOPE.md", "README.md"):
        txt = _read_text(ws / prose_rel) or ""
        for m in _UPSTREAM_RE.finditer(txt):
            if _prose_fork_context(txt, m.start()) or \
               _upstream_has_in_scope_source(ws, m.group(0)):
                return True, m.group(0).lower(), prose_rel

    return False, "", ""


# ---------------------------------------------------------------------------
# Stage 2: GATE - content-check the manifest
# ---------------------------------------------------------------------------

def _manifest_path(ws: Path) -> Path:
    return ws / _MANIFEST_REL[0] / _MANIFEST_REL[1]


def _check_manifest_content(ws: Path) -> tuple[bool, str]:
    """Return (content_ok: bool, reason: str).

    Content requirements:
    - File exists and is non-empty JSON.
    - "upstream" is a non-empty string.
    - "deviations" is a non-empty list.
    - At least one deviation entry has non-empty "file", "kind", and "summary".
    """
    p = _manifest_path(ws)
    obj = _read_json(p)
    if obj is None:
        return False, "manifest absent or unreadable"
    if not isinstance(obj, dict):
        return False, "manifest is not a JSON object"
    # ----------------------------------------------------------------------
    # Explicit NO-FORK attestation escape (false-FAIL fix).
    # The detect surface tags ANY in-scope source whose name matches a known-
    # upstream keyword (e.g. "morpho", "openzeppelin") as a "fork", even when
    # the workspace IS the canonical first-party upstream (morpho-org's own
    # morpho-blue / metamorpho / vault-v2 repos are not forks of anyone). For
    # those targets there is NO deviation list to author - demanding one would
    # force fabrication. Accept an operator-authored attestation that the target
    # is first-party / not a fork:  {"fork": false, "reason": "<why>"} (also
    # is_fork:false / no_fork_attestation:true). It is false-GREEN-safe: the
    # boolean is non-default and must be explicitly set by a human/agent for
    # THIS workspace, plus a non-empty reason; it does not auto-pass any real
    # fork target (a fork still needs deviations). The caller maps this to a
    # distinct verdict (pass-no-fork-attested) so the report stays honest.
    no_fork = None
    if isinstance(obj.get("fork"), bool):
        no_fork = obj.get("fork") is False
    elif isinstance(obj.get("is_fork"), bool):
        no_fork = obj.get("is_fork") is False
    elif obj.get("no_fork_attestation") is True:
        no_fork = True
    if no_fork is True:
        reason = str(obj.get("reason") or obj.get("attestation") or "").strip()
        if not reason:
            return False, (
                'no-fork attestation present (fork:false) but missing a '
                'non-empty "reason" explaining why the target is first-party / '
                'not a fork of any upstream'
            )
        return True, f"NO-FORK-ATTESTED: {reason}"
    upstream = str(obj.get("upstream") or "").strip()
    if not upstream:
        return False, 'manifest missing non-empty "upstream" field'
    deviations = obj.get("deviations")
    if not isinstance(deviations, list) or len(deviations) == 0:
        return False, 'manifest "deviations" is absent or empty list'
    # Require at least one fully-populated entry.
    valid_entries = 0
    for entry in deviations:
        if not isinstance(entry, dict):
            continue
        f = str(entry.get("file") or "").strip()
        k = str(entry.get("kind") or "").strip()
        s = str(entry.get("summary") or "").strip()
        if f and k and s:
            valid_entries += 1
    if valid_entries == 0:
        return False, (
            'manifest "deviations" has no fully-populated entry '
            '(each entry needs non-empty "file", "kind", and "summary")'
        )
    return True, (
        f'{valid_entries} deviation(s) listed for upstream "{upstream}"'
    )


# ---------------------------------------------------------------------------
# evaluate()
# ---------------------------------------------------------------------------

def evaluate(ws) -> dict:
    """Gate entry-point. Returns a dict with "verdict" and supporting fields.

    signal key: "fork-divergence-content"
    """
    ws = Path(ws)
    base: dict = {"schema": SCHEMA_OUT, "gate": GATE,
                  "signal": "fork-divergence-content"}

    if not ws.is_dir():
        return {**base, "verdict": "error",
                "reason": f"workspace not found: {ws}",
                "fork_detected": False, "upstream": ""}

    if not _has_in_scope_source(ws):
        return {**base, "verdict": "pass-no-source",
                "reason": "no in-scope source found",
                "fork_detected": False, "upstream": ""}

    is_fork, upstream_name, detection_source = _detect_upstream_fork(ws)

    if not is_fork:
        return {**base, "verdict": "pass-no-fork-detected",
                "reason": "no known upstream fork markers found in manifests or docs",
                "fork_detected": False, "upstream": ""}

    # Fork detected - gate on populated manifest.
    content_ok, content_reason = _check_manifest_content(ws)
    manifest_p = _manifest_path(ws)

    if content_ok:
        # Distinguish an explicit no-fork attestation (first-party canonical
        # source) from a real populated deviation list, so the report is honest.
        attested = content_reason.startswith("NO-FORK-ATTESTED:")
        verdict = "pass-no-fork-attested" if attested else "pass-fork-divergence-populated"
        reason = (
            (f"detect tagged '{upstream_name}' via {detection_source}, but "
             f"operator attests target is first-party / not a fork: "
             f"{content_reason[len('NO-FORK-ATTESTED:'):].strip()}")
            if attested else
            (f"fork of '{upstream_name}' detected via {detection_source}; "
             f"manifest populated: {content_reason}")
        )
        return {**base, "verdict": verdict,
                "reason": reason,
                "fork_detected": (not attested) and True, "upstream": upstream_name,
                "detection_source": detection_source,
                "manifest_path": str(manifest_p)}

    return {**base, "verdict": "fail-upstream-fork-divergence-manifest-missing",
            "reason": (
                f"fork of '{upstream_name}' detected via {detection_source}, "
                f"but upstream_divergence.json content check failed: {content_reason}. "
                f"Create or populate {manifest_p} with schema "
                f'"{MANIFEST_SCHEMA_KEY}", a non-empty "upstream" field, and a '
                f'non-empty "deviations" list (each entry: file, kind, summary). '
                f"OR add an operator l37-rebuttal line "
                f'"fork-divergence-content: <reason>" in '
                f"<ws>/.auditooor/audit_completeness_rebuttal.txt."
            ),
            "fork_detected": True, "upstream": upstream_name,
            "detection_source": detection_source,
            "manifest_path": str(manifest_p),
            "fix": (
                f"populate {manifest_p} - see tool docstring for schema"
            )}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Upstream-divergence-manifest gate: "
                    "fork detected => require populated deviation list.")
    ap.add_argument("--workspace", "-w", required=True,
                    help="workspace root path")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on fail-upstream-fork-divergence-manifest-missing")
    ap.add_argument("--json", action="store_true",
                    help="print full result as JSON")
    args = ap.parse_args(argv)

    res = evaluate(Path(args.workspace))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(
            f"[{GATE}] verdict={res['verdict']} "
            f"fork_detected={res.get('fork_detected', False)} "
            f"upstream={res.get('upstream', '')} -- {res['reason']}"
        )

    if res["verdict"] == "error":
        return 2
    if args.check and res["verdict"] == "fail-upstream-fork-divergence-manifest-missing":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
