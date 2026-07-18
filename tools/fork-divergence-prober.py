#!/usr/bin/env python3
"""fork-divergence-prober.py — HACKERMAN_V3 Lane G2.

Deployment / fork-divergence prober. Upgrades the existing fork-ancestry and
upstream-equivalent tooling into a *structured loop* that turns a lagging
dependency pin into a queued lead with a concrete replay command:

    upstream security fix / deployment assumption differs
        -> fork-missing status
        -> reachable in-scope code path
        -> local replay / harness task (a real command)
        -> exact rubric impact gate

Empirical anchors
-----------------
  - dYdX cantina-018: the cometbft fork at audit-pin SHA `904204b11c9e` lagged
    the v0.38.22 silently-shipped blocksync hardening series
    (PRs #5757 / #5753 / #5711 / #5629 / #5718). A pinned fork fell behind an
    upstream security-fix series -> Critical-class lead.
  - Hyperbridge ibc-go: a dependency pin was *version-vulnerable* against a
    published GHSA but the vulnerable code path was an UNUSED indirect
    dependency - the vault's in-scope code never reached it. That is NOT a
    finding. The reachability gate below exists to mark exactly that case.

Why this is not a duplicate of existing tooling
-----------------------------------------------
  - tools/gomod-fork-ancestry-check.py / tools/cargo-fork-ancestry-check.py:
    discover *which* forked pins diverge from upstream (ancestry math). They
    stop at "diverged candidate". They do not check in-scope reachability,
    do not attach a replay command, and do not gate on the rubric.
  - tools/upstream-equivalent-gate.py: a *promotion* gate for an already-
    drafted candidate (5-check protocol). It walks back over-claims; it does
    not *discover* lagging pins or emit leads.
  - tools/fork-divergence-template.py: generates a Markdown *filing skeleton*
    once a finding already exists. Prose, not a queued lead.
  - tools/hackerman-cve-ghsa-delta-watcher.py: polls live NVD/GHSA into the
    corpus. Corpus ETL, not a per-workspace prober.

This tool *consumes* those (it can read a fork-ancestry JSON report) and adds
the missing three stages: reachability, replay task, rubric gate. It composes,
it does not re-implement ancestry math.

Offline-safe
------------
The prober runs entirely from local data: pinned-dependency manifests
(go.mod / Cargo.toml / Cargo.lock / package.json / submodule pins),
optional `scope.json`, an optional fork-ancestry JSON report, and an optional
local advisory cache (JSON). It NEVER requires a live network call. A live
GHSA/CVE lookup is a pluggable step (`--advisory-fetcher`) that defaults to
the offline cache; with no cache and no fetcher the tool still runs and emits
`advisory_lookup: offline-no-cache` on every pin.

CLI
---
    --workspace PATH           workspace root (contains manifests / scope.json)
    --advisory-cache PATH      local JSON advisory cache (offline source)
    --ancestry-report PATH     optional fork-ancestry-check JSON to seed pins
    --scope PATH               optional scope.json (else <ws>/scope.json)
    --out PATH                 write the prober plan JSON here
    --json                     print the plan JSON to stdout
    --strict                   exit 2 when >=1 actionable lead is queued

Exit codes
----------
    0  no actionable leads queued (or advisory mode without --strict)
    1  harness error (missing workspace, bad JSON)
    2  >=1 actionable lead queued AND --strict

Lead row schema (auditooor.fork_divergence_prober.v1)
-----------------------------------------------------
Each lead is a 5-stage row:
    upstream_fix_or_advisory      stage 1 - the upstream fix / advisory / HEAD
    fork_missing_status           stage 2 - lagging | current | unknown
    reachable_in_scope_code_path  stage 3 - reachable | not-reachable | unknown
    local_replay_or_harness_task  stage 4 - a concrete command string
    rubric_impact_gate            stage 5 - the impact gate to clear before filing
Plus: pin identity, classification, and an `actionable` boolean.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Optional

SCHEMA = "auditooor.fork_divergence_prober.v1"
TOOL_NAME = "fork-divergence-prober"

# Manifest file -> ecosystem
MANIFESTS = {
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "package.json": "npm",
}

# Directories never treated as in-scope source for reachability scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "target", "vendor",
    "artifacts", "cache", "out", "broadcast", "dist", "build",
    "__pycache__", ".auditooor", "test", "tests", "testdata",
}

SOURCE_EXT = {".go", ".rs", ".sol", ".ts", ".js", ".py"}


# ---------------------------------------------------------------------------
# Pin discovery
# ---------------------------------------------------------------------------
_GO_REPLACE_RE = re.compile(
    r"^\s*replace\s+(?P<orig>\S+)\s+=>\s+(?P<repl>\S+)\s+(?P<ver>\S+)\s*$"
)
_GO_REQUIRE_RE = re.compile(r"^\s*(?P<mod>[\w./\-]+)\s+(?P<ver>v\S+)\s*$")
_GO_PSEUDO_RE = re.compile(r"-(?P<sha>[0-9a-f]{12})$")
_CARGO_GIT_RE = re.compile(
    r'(?P<name>[\w\-]+)\s*=\s*\{[^}]*git\s*=\s*"(?P<url>[^"]+)"[^}]*\}'
)
_CARGO_LOCK_SRC_RE = re.compile(
    r'source\s*=\s*"git\+(?P<url>[^?#"]+)(?:\?[^#"]*)?#(?P<sha>[0-9a-f]{7,40})"'
)


def _norm_repo(url: str) -> str:
    """github.com/org/repo from a git URL or module path."""
    u = url.strip().rstrip("/")
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"\.git$", "", u)
    u = re.sub(r"^git\+", "", u)
    return u


def discover_pins(ws: Path) -> list[dict[str, Any]]:
    """Discover pinned / forked dependencies from local manifests only."""
    pins: list[dict[str, Any]] = []
    seen: set[str] = set()

    gomod = ws / "go.mod"
    if gomod.is_file():
        for line in gomod.read_text(errors="replace").splitlines():
            m = _GO_REPLACE_RE.match(line)
            if m:
                repo = _norm_repo(m.group("repl"))
                ver = m.group("ver")
                sha_m = _GO_PSEUDO_RE.search(ver)
                key = f"go:{repo}"
                if key in seen:
                    continue
                seen.add(key)
                pins.append({
                    "ecosystem": "go",
                    "kind": "fork-replace",
                    "module": m.group("orig"),
                    "fork_repo": repo,
                    "pin_version": ver,
                    "pin_sha": sha_m.group("sha") if sha_m else None,
                })

    cargo_toml = ws / "Cargo.toml"
    if cargo_toml.is_file():
        txt = cargo_toml.read_text(errors="replace")
        for m in _CARGO_GIT_RE.finditer(txt):
            repo = _norm_repo(m.group("url"))
            key = f"cargo:{repo}"
            if key in seen:
                continue
            seen.add(key)
            pins.append({
                "ecosystem": "cargo",
                "kind": "git-dep",
                "module": m.group("name"),
                "fork_repo": repo,
                "pin_version": None,
                "pin_sha": None,
            })

    cargo_lock = ws / "Cargo.lock"
    if cargo_lock.is_file():
        for m in _CARGO_LOCK_SRC_RE.finditer(cargo_lock.read_text(errors="replace")):
            repo = _norm_repo(m.group("url"))
            key = f"cargo:{repo}"
            if key in seen:
                # enrich existing pin with the resolved SHA
                for p in pins:
                    if p["ecosystem"] == "cargo" and p["fork_repo"] == repo:
                        p["pin_sha"] = m.group("sha")
                continue
            seen.add(key)
            pins.append({
                "ecosystem": "cargo",
                "kind": "git-dep",
                "module": repo.rsplit("/", 1)[-1],
                "fork_repo": repo,
                "pin_version": None,
                "pin_sha": m.group("sha"),
            })

    pkg = ws / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except json.JSONDecodeError:
            data = {}
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if not isinstance(spec, str):
                    continue
                # only git-pinned / forked specs are pins of interest
                if not re.search(r"(github\.com|git\+|#[0-9a-f]{7,40})", spec):
                    continue
                key = f"npm:{name}"
                if key in seen:
                    continue
                seen.add(key)
                repo_m = re.search(r"github\.com[:/]([\w\-./]+?)(?:\.git)?(?:#|$)", spec)
                sha_m = re.search(r"#([0-9a-f]{7,40})$", spec)
                pins.append({
                    "ecosystem": "npm",
                    "kind": "git-dep",
                    "module": name,
                    "fork_repo": _norm_repo(repo_m.group(1)) if repo_m else None,
                    "pin_version": spec,
                    "pin_sha": sha_m.group(1) if sha_m else None,
                })

    # .gitmodules submodule pins
    gm = ws / ".gitmodules"
    if gm.is_file():
        url = None
        for line in gm.read_text(errors="replace").splitlines():
            um = re.match(r'\s*url\s*=\s*(\S+)', line)
            if um:
                url = um.group(1)
                repo = _norm_repo(url)
                key = f"submodule:{repo}"
                if key not in seen:
                    seen.add(key)
                    pins.append({
                        "ecosystem": "submodule",
                        "kind": "submodule-pin",
                        "module": repo.rsplit("/", 1)[-1],
                        "fork_repo": repo,
                        "pin_version": None,
                        "pin_sha": None,
                    })
    return pins


def seed_pins_from_ancestry(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Seed pins from a gomod/cargo-fork-ancestry-check JSON report.

    Those tools already computed lagging status; consume it instead of
    re-deriving ancestry. Tolerant of several report shapes.
    """
    pins: list[dict[str, Any]] = []
    rows = report.get("forks") or report.get("dependencies") or report.get("results") or []
    if isinstance(rows, dict):
        rows = list(rows.values())
    for r in rows:
        if not isinstance(r, dict):
            continue
        repo = r.get("fork_repo") or r.get("repo") or r.get("fork_url") or r.get("name")
        if not repo:
            continue
        diverged = r.get("not_in_fork") or r.get("candidate_commits") or r.get("behind")
        pins.append({
            "ecosystem": r.get("ecosystem", "unknown"),
            "kind": "ancestry-seeded",
            "module": r.get("module") or r.get("name") or _norm_repo(str(repo)),
            "fork_repo": _norm_repo(str(repo)),
            "pin_version": r.get("pin_version") or r.get("base_version"),
            "pin_sha": r.get("pin_sha") or r.get("audit_pin"),
            "ancestry_lagging": bool(diverged),
            "ancestry_detail": diverged if isinstance(diverged, list) else None,
        })
    return pins


# ---------------------------------------------------------------------------
# Advisory lookup (pluggable, offline-default)
# ---------------------------------------------------------------------------
def offline_advisory_lookup(cache: dict[str, Any]) -> Callable[[dict], list[dict]]:
    """Return a fetcher closure backed purely by a local advisory cache.

    Cache shape:
        {"<repo or module>": [{"advisory_id","fixed_in","fixed_sha",
                                "vulnerable_paths":[...],"summary"}], ...}
    """
    norm = {_norm_repo(k): v for k, v in (cache or {}).items()}

    def _fetch(pin: dict[str, Any]) -> list[dict[str, Any]]:
        repo = pin.get("fork_repo") or ""
        mod = pin.get("module") or ""
        hits = norm.get(_norm_repo(repo), []) or norm.get(_norm_repo(mod), [])
        return list(hits)

    return _fetch


# ---------------------------------------------------------------------------
# Reachability gate
# ---------------------------------------------------------------------------
def _iter_source_files(ws: Path):
    for p in ws.rglob("*"):
        if not p.is_file() or p.suffix not in SOURCE_EXT:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def reachability_gate(
    ws: Path,
    pin: dict[str, Any],
    advisories: list[dict[str, Any]],
    in_scope_files: Optional[set[str]],
) -> dict[str, Any]:
    """Decide whether the vulnerable path is reachable from in-scope source.

    This is the gate that prevents version-vulnerable-but-unreachable false
    leads (the Hyperbridge ibc-go indirect-dep anchor): a pin can lag a
    published advisory yet never be called by the workspace's in-scope code.

    Returns {status, evidence, scanned_files}.
      status: "reachable" | "not-reachable" | "unknown"
    """
    module = pin.get("module") or ""
    repo = pin.get("fork_repo") or ""
    # import tokens to grep for: module path tail + advisory-named symbols.
    tokens: set[str] = set()
    if module:
        tokens.add(module)
        tokens.add(module.rsplit("/", 1)[-1])
    if repo:
        tokens.add(repo.rsplit("/", 1)[-1])
    for adv in advisories:
        for vp in adv.get("vulnerable_paths", []) or []:
            tail = str(vp).rsplit("/", 1)[-1]
            for t in (vp, tail):
                t = str(t).strip()
                if len(t) >= 4:
                    tokens.add(t)
    tokens = {t for t in tokens if t and len(t) >= 4}
    if not tokens:
        return {"status": "unknown", "evidence": [],
                "reason": "no import token derivable from pin/advisory"}

    evidence: list[str] = []
    scanned = 0
    for p in _iter_source_files(ws):
        rel = str(p.relative_to(ws))
        if in_scope_files is not None and rel not in in_scope_files:
            continue
        scanned += 1
        try:
            txt = p.read_text(errors="replace")
        except OSError:
            continue
        for tok in tokens:
            if tok in txt:
                for ln, line in enumerate(txt.splitlines(), 1):
                    if tok in line:
                        evidence.append(f"{rel}:{ln}: {line.strip()[:120]}")
                        break
                break
        if len(evidence) >= 8:
            break

    if scanned == 0:
        return {"status": "unknown", "evidence": [],
                "reason": "no in-scope source files scanned", "scanned_files": 0}
    if evidence:
        return {"status": "reachable", "evidence": evidence, "scanned_files": scanned}
    return {"status": "not-reachable", "evidence": [],
            "reason": "no in-scope source references the pinned module / "
                      "vulnerable symbol (version-vulnerable but unreachable)",
            "scanned_files": scanned}


# ---------------------------------------------------------------------------
# Replay task + rubric gate synthesis
# ---------------------------------------------------------------------------
def synth_replay_task(pin: dict[str, Any], adv: Optional[dict[str, Any]]) -> str:
    """Produce a concrete local replay / harness command for this pin."""
    repo = pin.get("fork_repo") or "<fork-repo>"
    pin_sha = pin.get("pin_sha") or pin.get("pin_version") or "<pin>"
    fixed = (adv or {}).get("fixed_sha") or (adv or {}).get("fixed_in") or "<upstream-fix-ref>"
    eco = pin.get("ecosystem")
    if eco == "go":
        return (
            f"git clone https://{repo} /tmp/fdp-{pin['module'].replace('/', '_')} && "
            f"cd /tmp/fdp-{pin['module'].replace('/', '_')} && "
            f"git merge-base --is-ancestor {fixed} {pin_sha} "
            f"&& echo PIN_HAS_FIX || echo PIN_LAGS_FIX; "
            f"# then: fork-replay-cosmos-go.py to diff fork vs {fixed} behaviour"
        )
    if eco == "cargo":
        return (
            f"git clone https://{repo} /tmp/fdp-{pin['module']} && "
            f"cd /tmp/fdp-{pin['module']} && "
            f"git merge-base --is-ancestor {fixed} {pin_sha} "
            f"&& echo PIN_HAS_FIX || echo PIN_LAGS_FIX; "
            f"# then: fork-replay-assert.py to assert divergent behaviour"
        )
    return (
        f"git clone https://{repo} /tmp/fdp-{(pin.get('module') or 'dep')} && "
        f"cd /tmp/fdp-* && git log --oneline {pin_sha}..{fixed} "
        f"# enumerate commits the pin is missing, then build a differential harness"
    )


def synth_rubric_gate(pin: dict[str, Any], adv: Optional[dict[str, Any]],
                       reach: dict[str, Any]) -> str:
    """The impact gate that must be cleared before this lead becomes a finding."""
    if reach["status"] == "not-reachable":
        return ("NOT-A-FINDING: pin is version-vulnerable but the vulnerable "
                "path is not reachable from in-scope code (indirect/unused dep). "
                "Do not file. Anchor: Hyperbridge ibc-go indirect-dep.")
    if reach["status"] == "unknown":
        return ("BLOCKED: reachability could not be determined - resolve "
                "scope.json / in-scope source before assigning a rubric tier.")
    summary = (adv or {}).get("summary", "")
    return ("Prove the upstream fix closes a path the fork still exposes AND "
            "that path lands a rubric-verbatim impact (loss/freeze/halt/"
            "consensus-divergence). Map to the workspace SEVERITY.md row before "
            f"filing. Upstream advisory context: {summary[:160] or 'n/a'}")


# ---------------------------------------------------------------------------
# Core prober loop
# ---------------------------------------------------------------------------
def probe(
    ws: Path,
    advisory_cache: dict[str, Any],
    ancestry_report: Optional[dict[str, Any]],
    advisory_fetcher: Optional[Callable[[dict], list[dict]]] = None,
    in_scope_files: Optional[set[str]] = None,
) -> dict[str, Any]:
    pins = discover_pins(ws)
    if ancestry_report:
        # merge ancestry-seeded lagging status onto discovered pins
        seeded = {p["fork_repo"]: p for p in seed_pins_from_ancestry(ancestry_report)}
        for p in pins:
            s = seeded.get(p["fork_repo"])
            if s and "ancestry_lagging" in s:
                p["ancestry_lagging"] = s["ancestry_lagging"]
                p["ancestry_detail"] = s.get("ancestry_detail")
        for repo, s in seeded.items():
            if not any(p["fork_repo"] == repo for p in pins):
                pins.append(s)

    fetcher = advisory_fetcher or offline_advisory_lookup(advisory_cache)
    advisory_mode = "live-fetcher" if advisory_fetcher else (
        "offline-cache" if advisory_cache else "offline-no-cache")

    leads: list[dict[str, Any]] = []
    for pin in pins:
        advisories = fetcher(pin) if fetcher else []
        # Stage 2: fork-missing status.
        if advisories:
            fork_missing = "lagging"
        elif pin.get("ancestry_lagging"):
            fork_missing = "lagging"
        elif advisory_mode == "offline-no-cache":
            fork_missing = "unknown"
        else:
            fork_missing = "current"

        primary = advisories[0] if advisories else None
        # Stage 3: reachability gate (only meaningful when something lags).
        if fork_missing == "lagging":
            reach = reachability_gate(ws, pin, advisories, in_scope_files)
        else:
            reach = {"status": "unknown", "evidence": [],
                     "reason": "pin not lagging - reachability not evaluated",
                     "scanned_files": 0}

        # Stage 1: upstream fix / advisory.
        if primary:
            stage1 = (f"{primary.get('advisory_id', 'ADVISORY')} "
                      f"fixed_in={primary.get('fixed_in', '?')} "
                      f"fixed_sha={primary.get('fixed_sha', '?')}")
        elif pin.get("ancestry_lagging"):
            det = pin.get("ancestry_detail")
            stage1 = (f"fork-ancestry: pin is behind upstream "
                      f"({len(det) if isinstance(det, list) else 'N'} missing commits)")
        else:
            stage1 = "no upstream advisory in local cache (offline)"

        actionable = (fork_missing == "lagging" and reach["status"] == "reachable")
        classification = (
            "actionable-lead" if actionable
            else "not-a-finding" if reach["status"] == "not-reachable"
            else "current-pin" if fork_missing == "current"
            else "blocked-needs-input"
        )

        lead = {
            "pin": {
                "ecosystem": pin.get("ecosystem"),
                "kind": pin.get("kind"),
                "module": pin.get("module"),
                "fork_repo": pin.get("fork_repo"),
                "pin_version": pin.get("pin_version"),
                "pin_sha": pin.get("pin_sha"),
            },
            "classification": classification,
            "actionable": actionable,
            # 5-stage lead row:
            "upstream_fix_or_advisory": stage1,
            "fork_missing_status": fork_missing,
            "reachable_in_scope_code_path": reach["status"],
            "reachability_evidence": reach.get("evidence", []),
            "reachability_reason": reach.get("reason"),
            "local_replay_or_harness_task": synth_replay_task(pin, primary),
            "rubric_impact_gate": synth_rubric_gate(pin, primary, reach),
            "advisory_lookup": advisory_mode,
        }
        leads.append(lead)

    actionable_n = sum(1 for l in leads if l["actionable"])
    not_finding_n = sum(1 for l in leads if l["classification"] == "not-a-finding")
    body = {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "workspace": str(ws),
        "advisory_mode": advisory_mode,
        "pins_discovered": len(pins),
        "leads": leads,
        "summary": {
            "total_pins": len(pins),
            "actionable_leads": actionable_n,
            "not_a_finding": not_finding_n,
            "current_pins": sum(1 for l in leads if l["classification"] == "current-pin"),
            "blocked": sum(1 for l in leads if l["classification"] == "blocked-needs-input"),
        },
    }
    body["plan_id"] = hashlib.sha256(
        json.dumps(body["leads"], sort_keys=True).encode()
    ).hexdigest()[:16]
    return body


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_json(path: Optional[Path]) -> Optional[dict[str, Any]]:
    if not path:
        return None
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    return json.loads(path.read_text(errors="replace"))


def load_scope_files(ws: Path, scope_path: Optional[Path]) -> Optional[set[str]]:
    """Return a set of in-scope relative paths from scope.json, or None.

    None means 'no scope filter' - the reachability scan considers all source.
    """
    sp = scope_path or (ws / "scope.json")
    if not sp.is_file():
        return None
    try:
        data = json.loads(sp.read_text(errors="replace"))
    except json.JSONDecodeError:
        return None
    files: set[str] = set()
    candidates = data.get("in_scope") or data.get("files") or data.get("scope") or []
    if isinstance(candidates, dict):
        candidates = candidates.get("files", [])
    for entry in candidates:
        if isinstance(entry, str):
            files.add(entry)
        elif isinstance(entry, dict) and entry.get("path"):
            files.add(entry["path"])
    return files or None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="HACKERMAN_V3 Lane G2 fork-divergence prober")
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--advisory-cache", type=Path,
                    help="local JSON advisory cache (offline source)")
    ap.add_argument("--ancestry-report", type=Path,
                    help="optional fork-ancestry-check JSON to seed pins")
    ap.add_argument("--scope", type=Path, help="optional scope.json")
    ap.add_argument("--out", type=Path, help="write the prober plan JSON here")
    ap.add_argument("--json", action="store_true", help="print plan JSON to stdout")
    ap.add_argument("--strict", action="store_true",
                    help="exit 2 when >=1 actionable lead is queued")
    args = ap.parse_args(argv)

    ws = args.workspace
    if not ws.is_dir():
        print(f"error: workspace not found: {ws}", file=sys.stderr)
        return 1
    try:
        advisory_cache = _load_json(args.advisory_cache) or {}
        ancestry_report = _load_json(args.ancestry_report)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    in_scope = load_scope_files(ws, args.scope)
    plan = probe(ws, advisory_cache, ancestry_report, in_scope_files=in_scope)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(plan, indent=2) + "\n")
    if args.json or not args.out:
        print(json.dumps(plan, indent=2))

    s = plan["summary"]
    print(
        f"[{TOOL_NAME}] pins={s['total_pins']} actionable={s['actionable_leads']} "
        f"not-a-finding={s['not_a_finding']} current={s['current_pins']} "
        f"blocked={s['blocked']} mode={plan['advisory_mode']}",
        file=sys.stderr,
    )
    if args.strict and s["actionable_leads"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
