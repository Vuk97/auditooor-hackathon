#!/usr/bin/env python3
"""workspace-advisory-corpus-scan.py - generic L37 advisory-corpus producer.

The L37 audit-completeness `advisory-corpus` signal requires a
`.auditooor/advisory_corpus_parity.json` ledger declaring published_advisory_count
vs corpus_advisory_record_count (so the audit can confirm the target's published
advisories are all represented in the hunt corpus - the "Zebra N-of-M false-clean"
guard). No pipeline stage produced it, so the gate hard-failed on every workspace.
This tool is the missing producer.

Genuine work (no fake-green):
  1. Enumerate the target's packages + ecosystem from the in-scope source tree
     (Cargo.toml -> crates.io, package.json -> npm, go.mod -> Go, pyproject/
     setup.py -> PyPI).
  2. Query the OSV.dev advisory database (free, no-auth) for each package - a REAL
     published-advisory lookup.
  3. Count how many returned advisory IDs are represented in the local corpus
     (prior_audits/ text + any .auditooor advisory cache). published==0 trivially
     has full parity.
  4. Emit advisory_corpus_parity.json with real counts + scan evidence
     (scan_method, source_files_used, generated_at_utc, advisory_ids).

Honesty contract:
  - We ONLY write a parity ledger when OSV actually responded (an empty vuln list
    is a valid response = 0 published). If OSV is UNREACHABLE we do NOT fabricate a
    0/0 ledger - we exit non-zero and write nothing, so the gate stays honestly
    failed ("advisory scan could not run").
  - When published>0 but corpus<published, we emit the ledger with the true gap so
    the gate fails (telling the operator to mine those advisories). We never pad
    the corpus count.

Generic + target-agnostic. Network-using (OSV). Degrades honestly offline.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.advisory_corpus_parity.v1"
OSV_URL = "https://api.osv.dev/v1/query"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def enumerate_packages(ws: Path) -> list[dict]:
    """Return [{name, ecosystem}] for the in-scope source tree. De-duplicated."""
    src = ws / "src"
    roots = [src] if src.is_dir() else [ws]
    pkgs: dict[tuple[str, str], dict] = {}

    def add(name: str, eco: str):
        name = (name or "").strip().strip('"').strip("'")
        if name and (name, eco) not in pkgs:
            pkgs[(name, eco)] = {"name": name, "ecosystem": eco}

    # r36-rebuttal: bugfix-inventory-claude-20260610
    # Sort key: shallower paths (closer to the repo root) first, then deprioritize
    # test/vendor/mock/example subdirectories, then lexically for determinism.
    # This ensures the real audited package manifests at the root are never pushed
    # out of the [:N] cap by deeply-nested vendor/ or test-fixture trees.
    _NOISE_DIRS = ("test", "vendor", "mock", "example", "fixture", "third_party", "extern")

    # VENDORED dependency directories: a manifest under one of these is a
    # third-party copy pulled in to build, NOT the audit target's own published
    # package. Enumerating them makes the advisory-corpus parity gate demand that
    # every dependency's CVEs (OpenZeppelin / Optimism / Arbitrum / Chainlink /
    # Uniswap ...) be in OUR corpus - a scope-leak false-red (hyperlane: 57 of 60
    # enumerated packages were soldeer deps under dependencies/ + lib/). HARD-skip
    # them (sorting alone still lets them in under the [:N] cap). Generic across
    # every ecosystem: soldeer/foundry `dependencies/` + `lib/`, npm
    # `node_modules/`, cargo `target/`, go `vendor/`, generic build dirs.
    _VENDORED_SEGMENTS = (
        "/dependencies/", "/lib/", "/node_modules/", "/vendor/", "/target/",
        "/out/", "/cache/", "/third_party/", "/.git/",
    )

    def _is_vendored_manifest(p: Path) -> bool:
        s = str(p).replace("\\", "/").lower()
        return any(seg in s for seg in _VENDORED_SEGMENTS)

    def _manifest_sort_key(p: Path) -> tuple:
        s = str(p).lower()
        depth = s.count("/")
        is_noise = any(f"/{nd}/" in s or s.endswith(f"/{nd}") for nd in _NOISE_DIRS)
        return (depth, is_noise, str(p))

    for root in roots:
        for cargo in sorted(root.rglob("Cargo.toml"), key=_manifest_sort_key)[:200]:
            if _is_vendored_manifest(cargo):
                continue
            txt = _read(cargo)
            # only [package] name (skip workspace/deps name= lines heuristically)
            m = re.search(r'(?ms)^\[package\][^\[]*?^\s*name\s*=\s*"([^"]+)"', txt)
            if m:
                add(m.group(1), "crates.io")
        for pj in sorted(root.rglob("package.json"), key=_manifest_sort_key)[:100]:
            if _is_vendored_manifest(pj):
                continue
            obj = json.loads(_read(pj) or "{}") if _read(pj).strip().startswith("{") else {}
            if isinstance(obj, dict) and obj.get("name"):
                add(str(obj["name"]), "npm")
        for gomod in sorted(root.rglob("go.mod"), key=_manifest_sort_key)[:100]:
            if _is_vendored_manifest(gomod):
                continue
            m = re.search(r'^module\s+(\S+)', _read(gomod), re.M)
            if m:
                add(m.group(1), "Go")
        for py in sorted(root.rglob("pyproject.toml"), key=_manifest_sort_key)[:100]:
            if _is_vendored_manifest(py):
                continue
            m = re.search(r'(?ms)^\[project\][^\[]*?^\s*name\s*=\s*"([^"]+)"', _read(py))
            if m:
                add(m.group(1), "PyPI")
    return list(pkgs.values())


def osv_query(name: str, ecosystem: str, timeout: int) -> tuple[list[str], str | None]:
    """Return (advisory_ids, error). error is None on success (even empty)."""
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(OSV_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
        ids = [v.get("id") for v in d.get("vulns", []) if isinstance(v, dict) and v.get("id")]
        return (sorted(set(ids)), None)
    except Exception as e:  # noqa: BLE001
        return ([], f"{type(e).__name__}: {str(e)[:80]}")


def corpus_match_count(ws: Path, advisory_ids: list[str]) -> tuple[int, list[str]]:
    """Count how many advisory IDs appear in the local corpus (prior_audits text +
    .auditooor advisory cache files)."""
    if not advisory_ids:
        return (0, [])
    blobs: list[str] = []
    pa = ws / "prior_audits"
    if pa.is_dir():
        for f in list(pa.rglob("*.txt")) + list(pa.rglob("*.md")):
            blobs.append(_read(f))
    a = ws / ".auditooor"
    if a.is_dir():
        for f in list(a.glob("*advisor*.json")) + list(a.glob("*corpus*advisor*.json")):
            blobs.append(_read(f))
    hay = "\n".join(blobs).upper()
    matched = [aid for aid in advisory_ids if aid.upper() in hay]
    return (len(matched), matched)



_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
_RUSTSEC_RE = re.compile(r"RUSTSEC-\d{4}-\d{4}", re.I)
_DERIVED_ROOT = Path(__file__).resolve().parent.parent / "audit" / "corpus_tags" / "derived"


def _target_repo(ws: Path) -> str | None:
    """owner/repo from the workspace targets.tsv first data row."""
    tt = ws / "targets.tsv"
    if not tt.is_file():
        return None
    for ln in tt.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        url = ln.split("\t")[0].strip()
        m = re.search(r"github\.com[:/]+([^/]+/[^/\s]+?)(?:\.git)?(?:\s|$|/)", url)
        if m:
            return m.group(1)
    return None


def github_repo_advisories(repo: str, timeout: int) -> tuple[list[str], str | None]:
    """Per-REPOSITORY GitHub Security Advisory feed - the authoritative published
    set that OSV's per-PACKAGE crates.io view misses (the zebra 13-vs-26 gap)."""
    if not repo:
        return ([], "no-repo")
    try:
        proc = subprocess.run(
            ["gh", "api", f"repos/{repo}/security-advisories?per_page=100&state=published"],
            capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return ([], type(e).__name__)
    if proc.returncode != 0:
        return ([], f"gh-api-rc{proc.returncode}")
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return ([], "json-decode")
    ids = sorted({a.get("ghsa_id") for a in data if isinstance(a, dict) and a.get("ghsa_id")})
    return ([i for i in ids if i], None)


def mined_corpus_advisory_ids(ws_name: str) -> list[str]:
    """Advisory IDs already MINED into the corpus for this target (the producer
    hackerman-etl-from-*-advisories.py emits *_<ws>_advisories.jsonl + an
    invariant_library_extended/<ws>-advisories-*/ tree). These count as published
    (officially-disclosed, tier-1) so the parity denominator is not undercounted
    when OSV's package view is a strict subset."""
    if not _DERIVED_ROOT.is_dir():
        return []
    ids: set[str] = set()
    patterns = [f"*{ws_name}*advisor*.jsonl",
                f"invariant_library_extended/{ws_name}-advisories-*/*.yaml",
                f"invariant_library_extended/*{ws_name}*advisor*/*.yaml"]
    for pat in patterns:
        for f in _DERIVED_ROOT.glob(pat):
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            ids.update(m.group(0).upper() for m in _GHSA_RE.finditer(txt))
            ids.update(m.group(0).upper() for m in _RUSTSEC_RE.finditer(txt))
    return sorted(ids)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Workspace advisory-corpus parity producer (L37).")
    ap.add_argument("workspace")
    ap.add_argument("--out", default=None)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[advisory-corpus-scan] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    out = Path(args.out).expanduser() if args.out else (ws / ".auditooor" / "advisory_corpus_parity.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    pkgs = enumerate_packages(ws)
    if not pkgs:
        print("[advisory-corpus-scan] no enumerable packages (Cargo.toml/package.json/go.mod/pyproject); "
              "writing nothing (gate stays honestly unsatisfied)", file=sys.stderr)
        return 1

    all_ids: list[str] = []
    queried: list[str] = []
    errors: list[dict] = []
    reachable = False
    for p in pkgs:
        ids, err = osv_query(p["name"], p["ecosystem"], args.timeout)
        queried.append(f"{p['ecosystem']}:{p['name']}")
        if err is None:
            reachable = True
            all_ids += ids
        else:
            errors.append({"package": p["name"], "ecosystem": p["ecosystem"], "error": err})

    if not reachable:
        # OSV never responded for ANY package -> we cannot honestly claim 0
        # published. Refuse to write a passing 0/0 ledger.
        print("[advisory-corpus-scan] OSV unreachable for all packages; NOT writing a 0/0 ledger "
              f"(honest: scan could not run). errors={errors[:2]}", file=sys.stderr)
        return 1

    osv_ids = sorted(set(all_ids))
    # UNION with the authoritative per-repo GitHub advisory feed + the already-
    # mined corpus advisories, so repo-level (non-package) advisories OSV cannot
    # see are still counted as published (the zebra 13-vs-26 false-PARITY fix).
    repo = _target_repo(ws)
    gh_ids, gh_err = github_repo_advisories(repo, args.timeout) if repo else ([], "no-repo")
    mined_ids = mined_corpus_advisory_ids(ws.name)
    all_ids = sorted({i.upper() for i in (osv_ids + gh_ids + mined_ids)})
    published = len(all_ids)
    corpus, matched = corpus_match_count(ws, all_ids)
    source_counts = {"osv": len(osv_ids), "github_repo_feed": len(gh_ids),
                     "mined_corpus": len(mined_ids), "union": published,
                     "github_repo": repo, "github_error": gh_err}

    payload = {
        "schema": SCHEMA,
        "kind": "advisory_corpus_parity",
        "workspace": str(ws),
        "ws_name": ws.name,
        "published_advisory_count": published,
        "corpus_advisory_record_count": corpus,
        "scan_method": "union(osv.dev per-package, github repo security-advisory feed, mined-corpus advisories)",
        "advisory_source_counts": source_counts,
        "source_files_used": queried,
        "generated_at_utc": _now(),
        "advisory_ids": all_ids,
        "matched_in_corpus": matched,
        "unmatched_published": [a for a in all_ids if a not in matched],
        "osv_errors": errors,
        "packages_enumerated": pkgs,
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    parity = "PARITY" if corpus >= published else f"GAP ({corpus}/{published} in corpus)"
    print(f"[advisory-corpus-scan] {ws.name}: {len(pkgs)} package(s) queried via OSV; "
          f"published={published} corpus={corpus} -> {parity}; wrote {out}")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
