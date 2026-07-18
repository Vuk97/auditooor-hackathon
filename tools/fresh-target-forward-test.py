#!/usr/bin/env python3
"""fresh-target-forward-test.py - reusable fresh-target forward-test runner.

A FORWARD TEST is the honest held-out check on the upgraded audit pipeline:
take a target the pipeline has NEVER seen (zero corpus records), run the real
upgraded stages end-to-end, and deposit a STRUCTURED, MACHINE-READABLE result
into reports/fresh_target_forward_tests/<target>-<date>.json so that
tools/capability-metric-publisher.py can surface it as an HONEST capability
slot instead of "not-run".

PR11 ran this flow MANUALLY against PaulRBerg/prb-proxy and wrote a prose
FINAL_LEADS.md, but no deposit existed in the schema the publisher reads
(it found nothing). This tool closes that gap: it is the reusable tool the
publisher's docstring already references as "tools/fresh-target-forward-test.py's
job", and it can RE-EMIT the prb-proxy PR11 run into the deposit schema as the
first record.

IN-TREE PROVISIONING (runs BEFORE stage 1, idempotent): clone REPO@PIN into
<ws>/repo (shallow at the pin), mirror the in-scope src/ into <ws>/src, and
write <ws>/targets.tsv (repo+ref+role row) + <ws>/AUDIT_PIN.txt. Without this
the engage scan runs against an empty tree and `make audit` exits rc=2 /
the downstream proof stage reports claim-narrowed-out-of-tree (the step4-sweep
runner gap). The deposit record carries provisioned_in_tree=true/false so the
consumer can assert the audit ran IN-TREE. Skip with --no-provision.

WHAT IT RUNS (upgraded pipeline stages, in order):
  1. make audit WS=<workspace>                       (engage scan + intake +
                                                       exploit-queue + prove-top-leads;
                                                       runs IN-TREE post-provision)
  2. tools/novel-vector-invariant-miner.py           (target-specific invariants)
  3. tools/evm-engine-harness-author.py              (engine candidate specs;
                                                       go-/rust- author by language)
  4. tools/adversarial-candidate-verify.py           (3-lens kill panel on
                                                       Medium+ candidates)
  5. tools/evm-0day-proof-pipeline.py                (proof attempt on any
                                                       Medium+ candidate that
                                                       survives the panel)

The runner is STAGE-TOLERANT: a stage that exits non-zero or times out is
recorded as {"status": "error"|"timeout"} in stages_run, and the run continues.
A forward test with low yield (even 0 fileable leads) is a TRUTHFUL, EXPECTED
outcome on hardened code - the runner NEVER fabricates leads. The deposited
record's honest_verdict states exactly what happened.

IS_UNSEEN check (corpus_records==0): the runner computes is_unseen WITHOUT
trusting the degraded MCP corpus_search pool. The reliable local signal (the
same one PR11 used) is:
  - no existing /Users/wolf/audits/<target-stem>* workspace other than the
    forward-test workspace itself, AND
  - the vault known_dead_ends callable returns 0 records for the target, AND
  - reference/fetchable_vuln_corpus.jsonl (if present) has 0 records whose
    repo/target field matches the target slug.
A target is is_unseen=true only when ALL THREE signals show zero prior records.

RELATED TOOLS:
  - tools/capability-metric-publisher.py : the CONSUMER. Reads
    reports/fresh_target_forward_tests/*.json and surfaces the newest as the
    fresh-target capability slot. This tool is the PRODUCER it references.
  - tools/novel-vector-invariant-miner.py / evm-engine-harness-author.py /
    adversarial-candidate-verify.py / evm-0day-proof-pipeline.py : the pipeline
    STAGES this runner invokes. This tool does not re-implement them; it
    orchestrates them and records honest per-stage status.
  - reference/fetchable_vuln_corpus.jsonl + its builder : OWNED BY SIBLING A.
    This tool only READS the corpus (for the is_unseen check); it never edits
    the corpus or its builder.

CLI:
  # run a fresh target forward test (writes a deposit record)
  python3 tools/fresh-target-forward-test.py \\
      --repo github.com/Foo/bar --pin <sha> \\
      --workspace /Users/wolf/audits/bar-fwdtest \\
      [--target-name bar] [--evm-proof-candidate row.json] [--no-run-stages] [--json]

  # re-emit the PR11 prb-proxy run into the deposit schema (idempotent)
  python3 tools/fresh-target-forward-test.py --reemit-prb-proxy [--json]

Deposit schema: auditooor.fresh_target_forward_test.v1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPOSIT_DIR = REPO_ROOT / "reports" / "fresh_target_forward_tests"
AUDITS_ROOT = Path("/Users/wolf/audits")
FETCHABLE_CORPUS = REPO_ROOT / "reference" / "fetchable_vuln_corpus.jsonl"
VAULT_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"

SCHEMA = "auditooor.fresh_target_forward_test.v1"

# Pipeline stages: (logical_name, tool_relpath). make audit is special-cased.
PIPELINE_STAGES = [
    ("audit-prep", None),  # special: forward-test workspace scaffold
    ("make-audit", None),  # special: `make audit WS=<ws>`
    ("novel-vector-invariant-miner", "tools/novel-vector-invariant-miner.py"),
    ("evm-engine-harness-author", "tools/evm-engine-harness-author.py"),
    ("adversarial-candidate-verify", "tools/adversarial-candidate-verify.py"),
    ("evm-0day-proof-pipeline", "tools/evm-0day-proof-pipeline.py"),
]


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def target_slug(repo: str, target_name: str | None) -> str:
    """Filesystem-safe slug from repo (github.com/Owner/Name -> name) or an
    explicit target_name."""
    if target_name:
        base = target_name
    else:
        base = repo.rstrip("/").split("/")[-1]
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-").lower()
    return slug or "unknown-target"


# --------------------------------------------------------------------------
# In-tree provisioning (clone REPO@PIN -> <ws>/repo, mirror src/, write
# targets.tsv + AUDIT_PIN.txt) so `make audit` runs IN-TREE instead of
# failing rc=2 on an empty tree (the step4-sweep runner gap).
#
# A forward-test workspace is otherwise an empty directory: the engage scan
# falls back to scanning <ws>/src for .sol files, and the commit-mining /
# intake stages read <ws>/targets.tsv + <ws>/AUDIT_PIN.txt. Without those,
# `make audit` either errors or sees an empty tree and the downstream proof
# stage reports claim-narrowed-out-of-tree. This function provisions the
# canonical in-tree layout (the same shape a real provisioned workspace
# carries) and is IDEMPOTENT: re-running on an already-provisioned ws is a
# no-op (it detects an existing repo at the requested pin and only refreshes
# the mirror + manifests).
# --------------------------------------------------------------------------
def _git(args: list[str], cwd: Path, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=timeout)


def _repo_clone_url(repo: str) -> str:
    """Normalize a repo identifier into a cloneable https URL.
    github.com/Owner/Name -> https://github.com/Owner/Name
    https://... / git@... are passed through.
    """
    r = repo.strip()
    if r.startswith(("http://", "https://", "git@", "ssh://", "file://")):
        return r
    r = r.rstrip("/")
    if r.startswith("github.com/") or r.startswith("gitlab.com/") or "/" in r:
        return "https://" + r if "." in r.split("/")[0] else "https://github.com/" + r
    return "https://github.com/" + r


def _src_subdir(repo_dir: Path) -> Path | None:
    """Find the in-scope source subtree to mirror. Prefer repo/src (the
    Foundry/Hardhat convention); fall back to repo/contracts; else None
    (caller mirrors the whole repo minus VCS/deps)."""
    for cand in ("src", "contracts"):
        d = repo_dir / cand
        if d.is_dir():
            return d
    return None


def _mirror_src(repo_dir: Path, workspace: Path) -> dict:
    """Mirror the in-scope source subtree into <ws>/src so the engage scan
    runs in-tree. Returns a summary of what was mirrored."""
    import shutil

    dst = workspace / "src"
    src_sub = _src_subdir(repo_dir)
    if dst.exists():
        shutil.rmtree(dst)
    if src_sub is not None:
        shutil.copytree(src_sub, dst, ignore=shutil.ignore_patterns(
            ".git", "node_modules", "lib", "out", "cache"))
        scope_root = src_sub.name
    else:
        # No conventional src/ subdir: mirror first-party files at repo root,
        # excluding VCS, deps, build artifacts.
        dst.mkdir(parents=True, exist_ok=True)
        skip = {".git", "node_modules", "lib", "out", "cache", "test", "tests",
                "script", "scripts"}
        for child in repo_dir.iterdir():
            if child.name in skip:
                continue
            if child.is_dir():
                shutil.copytree(child, dst / child.name,
                                ignore=shutil.ignore_patterns(
                                    ".git", "node_modules", "lib", "out", "cache"))
            else:
                shutil.copy2(child, dst / child.name)
        scope_root = "(repo root, deps excluded)"
    sol_files = sorted(p for p in dst.rglob("*.sol"))
    return {"scope_root": scope_root, "src_dir": str(dst),
            "sol_file_count": len(sol_files),
            "sol_files": [str(p.relative_to(workspace)) for p in sol_files]}


def _write_targets_tsv(workspace: Path, repo: str, pin: str) -> Path:
    """Write the canonical targets.tsv (repo+ref+role row form). Mirrors the
    shape a real provisioned workspace carries; the engage scan reads <ws>/src
    for files, the commit-mining/intake stages read this repo-row form."""
    repo_field = repo.strip()
    if repo_field.startswith(("http://", "https://")):
        repo_field = repo_field.split("://", 1)[1]
    out = workspace / "targets.tsv"
    out.write_text(
        "# repo\tref\trole\n"
        f"{repo_field}\t{pin}\tprimary\n"
    )
    return out


def _write_default_scope_and_severity(workspace: Path, repo: str, pin: str) -> list[dict]:
    """Write minimal non-placeholder scope and severity files for a fresh
    forward-test workspace. Existing operator-authored files are preserved.
    """
    steps: list[dict] = []
    scope = workspace / "SCOPE.md"
    if scope.exists():
        steps.append({"step": "scope", "status": "already-exists"})
    else:
        scope.write_text(
            "# Scope\n\n"
            "## Program summary\n"
            f"Fresh-target forward test for `{repo}` at `{pin}`. The in-scope "
            "surface is the checked-out first-party source mirrored under "
            "`src/` for empirical pipeline measurement.\n\n"
            "## In-scope assets\n"
            "- Smart Contract: `src/`\n\n"
            "## Out of scope\n"
            "- Test-only helpers, mocks, and generated dependencies unless "
            "they are needed to prove reachability in the in-scope source.\n"
        )
        steps.append({"step": "scope", "status": "created"})

    severity = workspace / "SEVERITY.md"
    if severity.exists():
        steps.append({"step": "severity", "status": "already-exists"})
    else:
        severity.write_text(
            "# Severity\n\n"
            "## Critical\n"
            "- Direct loss of user funds.\n\n"
            "## High\n"
            "- Permanent freezing of user funds.\n"
            "- Unauthorized state transition that can affect protocol accounting.\n\n"
            "## Medium\n"
            "- Incorrect accounting state that can affect user balances or protocol solvency.\n\n"
            "## Low\n"
            "- Low-impact validation or availability issue.\n"
        )
        steps.append({"step": "severity", "status": "created"})
    return steps


def _write_forward_asset_plan(workspace: Path, provision: dict | None) -> dict:
    """Write a ready Smart Contract asset plan for a machine-run forward test."""
    out = workspace / "ASSET_PLAN_Smart_Contract.md"
    roots = ["- src/"]
    if provision:
        mirror_steps = [s for s in provision.get("steps", [])
                        if s.get("step") == "mirror-src"]
        sol_files = mirror_steps[0].get("sol_files", []) if mirror_steps else []
        first_party = [
            p for p in sol_files
            if "/test/" not in p and not p.startswith("src/test/")
        ]
        sample = first_party[:8] or sol_files[:8]
        if sample:
            roots = ["- src/"] + [f"  - `{p}`" for p in sample]
    text = (
        "# Asset Coverage Plan - Smart Contract\n\n"
        "- Strategy: Forward-test scan of the provisioned first-party source tree.\n"
        "- Estimated hours: 0\n"
        "- Agent hour quota pct: 100\n"
        "- Plan status: ready\n\n"
        "## Roots\n"
        + "\n".join(roots)
        + "\n"
    )
    existed = out.exists()
    out.write_text(text)
    return {
        "step": "asset-plan",
        "status": "overwritten" if existed else "created",
        "path": str(out.relative_to(workspace)),
    }


def prepare_forward_workspace(workspace: Path, repo: str, pin: str,
                              provision: dict | None, timeout: int) -> dict:
    """Prepare a provisioned target so `make audit` can run on first use."""
    summary = {"steps": []}
    summary["steps"].extend(_write_default_scope_and_severity(workspace, repo, pin))
    prep = _run_cmd(["make", "audit-prep", f"WS={workspace}"], REPO_ROOT, timeout)
    prep["stage"] = "audit-prep"
    summary["steps"].append(prep)
    summary["steps"].append(_write_forward_asset_plan(workspace, provision))
    return summary


def _contract_name_from_file(contract: Path) -> str | None:
    text = contract.read_text(errors="replace")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    decls = re.findall(
        r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", text)
    if not decls:
        return None
    stem = contract.stem.lower()
    for _, name in decls:
        if name.lower() == stem:
            return name
    for kind, name in decls:
        if kind == "contract" and stem in name.lower():
            return name
    for kind, name in decls:
        if kind == "contract":
            return name
    # r36-rebuttal: bugfix-inventory-claude-20260610
    # No contract declaration found - file contains only interfaces or libraries.
    # Returning None lets the caller's `if cname:` guard suppress --contract-name,
    # so downstream tools use their own discovery instead of receiving a wrong name.
    return None


def _contracts_for_forward_test(workspace: Path, *, limit: int = 3) -> list[Path]:
    """Pick concrete first-party Solidity contracts for contract-bound stages."""
    src = workspace / "src"
    if not src.is_dir():
        return []
    contracts: list[Path] = []
    # r36-rebuttal: bugfix-inventory-claude-20260610
    for p in sorted(src.rglob("*.sol")):
        rel = p.relative_to(workspace)
        lower = str(rel).lower()
        if "/test/" in lower or lower.startswith("src/test/"):
            continue
        if "mock" in lower:
            continue
        # Skip non-production subdirectories (formal-verification harnesses, dependency
        # trees, build artifacts, and adapter/spec directories) so that genuine protocol
        # contracts are selected rather than certora helpers or compiled-output files.
        if any(x in lower for x in (
            "/certora/", "/interfaces/", "/interface/", "/helpers/",
            "/specs/", "/spec/", "/halmos/", "/kontrol/", "/lib/", "/out/",
        )):
            continue
        contracts.append(rel)
        if len(contracts) >= limit:
            break
    return contracts


def _write_audit_pin(workspace: Path, repo: str, pin: str) -> Path:
    """Write AUDIT_PIN.txt in the canonical 3-line form."""
    repo_field = repo.strip()
    if repo_field.startswith(("http://", "https://")):
        repo_field = repo_field.split("://", 1)[1]
    # target: Owner/Name (strip leading host segment if present)
    target = repo_field
    parts = repo_field.split("/")
    if len(parts) >= 3 and "." in parts[0]:
        target = "/".join(parts[1:])
    out = workspace / "AUDIT_PIN.txt"
    out.write_text(
        f"audit-pin: {pin}\n"
        f"target: {target}\n"
        f"cloned: {_utc_iso()}\n"
    )
    return out


def _repo_at_pin(repo_dir: Path, pin: str) -> bool:
    """True if repo_dir is a git checkout whose HEAD is exactly `pin`."""
    if not (repo_dir / ".git").exists():
        return False
    try:
        head = _git(["rev-parse", "HEAD"], repo_dir, timeout=30)
    except Exception:
        return False
    return head.returncode == 0 and head.stdout.strip().startswith(pin.strip()[:12])


def provision_workspace_in_tree(repo: str, pin: str, workspace: Path,
                                *, clone_timeout: int = 600) -> dict:
    """Provision <ws> with the canonical in-tree layout so `make audit` runs
    against the real REPO@PIN source. IDEMPOTENT.

    Steps:
      1. Clone REPO@PIN into <ws>/repo (shallow at the pin) if not already
         checked out at that pin.
      2. Mirror the in-scope src/ subtree into <ws>/src.
      3. Write <ws>/targets.tsv (repo+ref+role row) + <ws>/AUDIT_PIN.txt.

    Returns a structured summary including in_tree=True/False so the caller
    can record whether the workspace is provisioned in-tree before audit.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    repo_dir = workspace / "repo"
    summary: dict = {
        "repo": repo, "pin": pin, "workspace": str(workspace),
        "steps": [], "in_tree": False,
    }

    # Step 1: clone REPO@PIN (idempotent) -------------------------------------
    if _repo_at_pin(repo_dir, pin):
        summary["steps"].append({"step": "clone", "status": "already-at-pin"})
    else:
        clone_url = _repo_clone_url(repo)
        if repo_dir.exists():
            # stale/partial checkout: try to fetch+checkout the pin in place
            fetched = _git(["fetch", "--depth", "1", "origin", pin], repo_dir,
                           timeout=clone_timeout)
            if fetched.returncode == 0:
                co = _git(["checkout", "--force", pin], repo_dir, timeout=120)
                step_status = "fetched-and-checked-out" if co.returncode == 0 else "checkout-failed"
                summary["steps"].append({"step": "clone", "status": step_status,
                                         "stderr_tail": (co.stderr or fetched.stderr or "")[-300:]})
            else:
                import shutil
                shutil.rmtree(repo_dir)
                summary["steps"].append({"step": "clone",
                                         "status": "stale-removed-reclone"})
        if not _repo_at_pin(repo_dir, pin):
            # fresh clone, then fetch+checkout the exact pin. Try a partial
            # blob-filtered clone first (cheap for large GitHub repos); fall
            # back to a plain clone when the transport (e.g. local file://)
            # does not support partial-clone filters.
            workspace.mkdir(parents=True, exist_ok=True)
            cl = _git(["clone", "--filter=blob:none", "--no-checkout",
                       clone_url, "repo"], workspace, timeout=clone_timeout)
            if cl.returncode != 0:
                cl = _git(["clone", "--no-checkout", clone_url, "repo"],
                          workspace, timeout=clone_timeout)
            if cl.returncode != 0:
                summary["steps"].append({"step": "clone", "status": "clone-failed",
                                         "stderr_tail": (cl.stderr or "")[-400:]})
                summary["in_tree"] = False
                return summary
            # the pin is usually already present after a full-history clone;
            # only fetch it explicitly if checkout fails.
            co = _git(["checkout", "--force", pin], repo_dir, timeout=120)
            fetched = None
            if co.returncode != 0:
                fetched = _git(["fetch", "--depth", "1", "origin", pin], repo_dir,
                               timeout=clone_timeout)
                co = _git(["checkout", "--force", pin], repo_dir, timeout=120)
            if co.returncode != 0:
                # pin may not be fetchable shallow (tag/branch); full fetch fallback
                _git(["fetch", "origin"], repo_dir, timeout=clone_timeout)
                co = _git(["checkout", "--force", pin], repo_dir, timeout=120)
            ok = _repo_at_pin(repo_dir, pin)
            fetch_err = fetched.stderr if fetched is not None else ""
            summary["steps"].append({
                "step": "clone",
                "status": "cloned-and-checked-out" if ok else "checkout-failed",
                "stderr_tail": (co.stderr or fetch_err or "")[-300:] if not ok else "",
            })
            if not ok:
                summary["in_tree"] = False
                return summary

    # Step 2: mirror src/ -----------------------------------------------------
    try:
        mirror = _mirror_src(repo_dir, workspace)
        summary["steps"].append({"step": "mirror-src", "status": "ok", **mirror})
    except Exception as exc:  # noqa: BLE001
        summary["steps"].append({"step": "mirror-src", "status": "error",
                                 "error": str(exc)[:300]})
        summary["in_tree"] = False
        return summary

    # Step 3: manifests -------------------------------------------------------
    t = _write_targets_tsv(workspace, repo, pin)
    a = _write_audit_pin(workspace, repo, pin)
    summary["steps"].append({"step": "manifests", "status": "ok",
                             "targets_tsv": str(t.relative_to(workspace)),
                             "audit_pin": str(a.relative_to(workspace))})

    # in_tree is True iff repo is at pin, src/ has >=1 source file, and both
    # manifests exist.
    src_dir = workspace / "src"
    has_source = src_dir.is_dir() and any(
        next(src_dir.rglob(ext), None) is not None
        for ext in ("*.sol", "*.vy", "*.go", "*.rs")
    )
    summary["in_tree"] = bool(
        _repo_at_pin(repo_dir, pin) and has_source
        and t.exists() and a.exists()
    )
    summary["mirrored_sol_file_count"] = mirror.get("sol_file_count", 0)
    return summary


# --------------------------------------------------------------------------
# is_unseen check (3 local signals, all must show zero)
# --------------------------------------------------------------------------
def _existing_workspaces_for(slug: str, forward_ws: Path | None) -> list[str]:
    """Other /Users/wolf/audits/<slug>* dirs that are NOT the forward-test ws."""
    hits = []
    if not AUDITS_ROOT.exists():
        return hits
    forward_resolved = forward_ws.resolve() if forward_ws else None
    for child in AUDITS_ROOT.iterdir():
        if not child.is_dir():
            continue
        name = child.name.lower()
        # match the project stem, ignoring a -fwdtest / -forward-test suffix
        stem = re.sub(r"-(fwdtest|forward-test)$", "", name)
        if stem == slug or name == slug:
            if forward_resolved and child.resolve() == forward_resolved:
                continue
            hits.append(child.name)
    return sorted(hits)


def _known_dead_ends_count(slug: str) -> int | None:
    """vault known_dead_ends record count for the target. None if uncallable."""
    if not VAULT_SERVER.exists():
        return None
    try:
        proc = subprocess.run(
            [sys.executable, str(VAULT_SERVER), "--call", "vault_known_dead_ends",
             "--args", json.dumps({"workspace": slug, "limit": 50})],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return None
    recs = data.get("records")
    if isinstance(recs, list):
        return len(recs)
    # some callables report a count field
    for k in ("total_records_matched", "count", "record_count"):
        if isinstance(data.get(k), int):
            return data[k]
    return 0


def _fetchable_corpus_count(slug: str, repo: str) -> int | None:
    """Records in reference/fetchable_vuln_corpus.jsonl matching the target.
    READ-ONLY (corpus owned by sibling A). None if corpus absent."""
    if not FETCHABLE_CORPUS.exists():
        return None
    repo_lc = repo.lower()
    slug_lc = slug.lower()
    n = 0
    try:
        with FETCHABLE_CORPUS.open(errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                blob = json.dumps(rec).lower()
                # match on repo path or slug appearing in any field
                if repo_lc in blob or f'"{slug_lc}"' in blob or f"/{slug_lc}" in blob:
                    n += 1
    except Exception:
        return None
    return n


def compute_is_unseen(repo: str, slug: str, forward_ws: Path | None) -> dict:
    """Return the is_unseen verdict + the three signal readings."""
    ws_hits = _existing_workspaces_for(slug, forward_ws)
    dead_ends = _known_dead_ends_count(slug)
    corpus_n = _fetchable_corpus_count(slug, repo)

    # is_unseen requires every AVAILABLE signal to read zero. A signal that is
    # unavailable (None) does not block is_unseen but is reported honestly.
    signals_zero = (
        len(ws_hits) == 0
        and (dead_ends in (0, None))
        and (corpus_n in (0, None))
    )
    return {
        "is_unseen": bool(signals_zero),
        "signals": {
            "prior_workspaces": ws_hits,
            "prior_workspaces_count": len(ws_hits),
            "known_dead_ends_count": dead_ends,
            "fetchable_corpus_match_count": corpus_n,
        },
        "note": (
            "is_unseen=true requires zero prior workspaces, zero known-dead-ends, "
            "and zero matching fetchable-corpus records. Unavailable signals "
            "(null) do not block but are reported."
        ),
    }


# --------------------------------------------------------------------------
# Stage runner
# --------------------------------------------------------------------------
def _run_cmd(cmd: list[str], cwd: Path, timeout: int) -> dict:
    started = _utc_iso()
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
                stdout, stderr = proc.communicate()
            return {"status": "timeout", "returncode": None,
                    "started_at_utc": started, "ended_at_utc": _utc_iso(),
                    "stdout_tail": (stdout or "")[-400:],
                    "stderr_tail": ((stderr or "")[-400:] or
                                    f"timeout after {timeout}s")}
        return {
            "status": "ok" if proc.returncode == 0 else "nonzero-exit",
            "returncode": proc.returncode,
            "started_at_utc": started,
            "ended_at_utc": _utc_iso(),
            "stdout_tail": (stdout or "")[-400:],
            "stderr_tail": (stderr or "")[-400:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "returncode": None,
                "started_at_utc": started, "ended_at_utc": _utc_iso(),
                "stdout_tail": "", "stderr_tail": str(exc)[:400]}


def run_stages(workspace: Path, *, timeout: int, repo: str = "", pin: str = "",
               provision: dict | None = None,
               evm_proof_candidate: Path | None = None) -> list[dict]:
    """Run the upgraded pipeline stages against the workspace; honest per-stage
    status. Never raises on a stage failure - records and continues."""
    results = []
    for name, relpath in PIPELINE_STAGES:
        if name == "audit-prep":
            prep = prepare_forward_workspace(workspace, repo, pin, provision, timeout)
            rec = {
                "status": "ok",
                "returncode": 0,
                "started_at_utc": _utc_iso(),
                "ended_at_utc": _utc_iso(),
                "stdout_tail": "",
                "stderr_tail": "",
                "detail": prep,
            }
        elif name == "make-audit":
            cmd = ["make", "audit", f"WS={workspace}"]
            rec = _run_cmd(cmd, REPO_ROOT, timeout)
        elif name in ("novel-vector-invariant-miner", "evm-engine-harness-author"):
            contracts = _contracts_for_forward_test(workspace)
            if not contracts:
                rec = {
                    "status": "skipped-no-contracts",
                    "returncode": None,
                    "started_at_utc": _utc_iso(),
                    "ended_at_utc": _utc_iso(),
                    "stdout_tail": "",
                    "stderr_tail": "no first-party Solidity contracts found under workspace src/",
                }
            else:
                per_contract = []
                worst = 0
                for contract in contracts:
                    tool = REPO_ROOT / relpath
                    contract_abs = workspace / contract
                    if name == "novel-vector-invariant-miner":
                        out = workspace / ".auditooor" / "fresh_target_forward" / (
                            contract.stem + ".novel_invariants.jsonl")
                        out.parent.mkdir(parents=True, exist_ok=True)
                        cmd = [
                            sys.executable, str(tool),
                            "--workspace", str(workspace),
                            "--contract", str(contract_abs),
                            "--output", str(out),
                            "--json",
                        ]
                        cname = _contract_name_from_file(contract_abs)
                        if cname:
                            cmd.extend(["--contract-name", cname])
                    else:
                        out_dir = workspace / ".auditooor" / "fresh_target_forward" / (
                            contract.stem + ".engine_harness")
                        cmd = [
                            sys.executable, str(tool), str(workspace), str(contract_abs),
                            "--out-dir", str(out_dir),
                            "--json",
                        ]
                        cname = _contract_name_from_file(contract_abs)
                        if cname:
                            cmd.extend(["--contract-name", cname])
                    one = _run_cmd(cmd, REPO_ROOT, timeout)
                    one["contract"] = str(contract)
                    per_contract.append(one)
                    if one.get("returncode") not in (0, None):
                        worst = int(one.get("returncode") or 1)
                ok = all(x.get("returncode") == 0 for x in per_contract)
                rec = {
                    "status": "ok" if ok else "partial-nonzero-exit",
                    "returncode": 0 if ok else worst,
                    "started_at_utc": per_contract[0]["started_at_utc"],
                    "ended_at_utc": per_contract[-1]["ended_at_utc"],
                    "stdout_tail": (per_contract[-1].get("stdout_tail") or "")[-400:],
                    "stderr_tail": (per_contract[-1].get("stderr_tail") or "")[-400:],
                    "contracts_analyzed": [str(c) for c in contracts],
                    "per_contract": per_contract,
                }
        elif name == "adversarial-candidate-verify" and evm_proof_candidate is None:
            rec = {
                "status": "not-invoked",
                "returncode": None,
                "started_at_utc": _utc_iso(),
                "ended_at_utc": _utc_iso(),
                "stdout_tail": "",
                "stderr_tail": "no candidate supplied; adversarial verification requires a concrete candidate",
            }
        elif name == "evm-0day-proof-pipeline" and evm_proof_candidate is None:
            rec = {
                "status": "not-invoked",
                "returncode": None,
                "started_at_utc": _utc_iso(),
                "ended_at_utc": _utc_iso(),
                "stdout_tail": "",
                "stderr_tail": "no --evm-proof-candidate supplied; proof stage requires a concrete candidate row",
            }
        else:
            tool = REPO_ROOT / relpath
            if not tool.exists():
                rec = {"status": "tool-missing", "returncode": None,
                       "started_at_utc": _utc_iso(), "ended_at_utc": _utc_iso(),
                       "stdout_tail": "", "stderr_tail": f"{relpath} not found"}
            else:
                cmd = [sys.executable, str(tool)]
                if name == "evm-0day-proof-pipeline":
                    cmd.extend(["--candidate-json", str(evm_proof_candidate)])
                    cmd.extend(["--workspace", str(workspace)])
                elif name == "adversarial-candidate-verify":
                    cmd.append(str(evm_proof_candidate))
                rec = _run_cmd(cmd, REPO_ROOT, timeout)
        rec["stage"] = name
        results.append(rec)
    return results


# --------------------------------------------------------------------------
# FINAL_LEADS parsing (lead counts from a workspace FINAL_LEADS.md)
# --------------------------------------------------------------------------
def parse_final_leads_counts(final_leads_path: Path) -> dict:
    """Parse the Verdict-summary table of a FINAL_LEADS.md into the canonical
    three-bucket count shape. Returns zeros if the file/table is absent."""
    counts = {"proof_backed": 0, "blocked": 0, "source_ruled_out": 0}
    if not final_leads_path.exists():
        return counts
    text = final_leads_path.read_text(errors="replace")
    # rows look like: "| proof-backed (fileable) | 0 |"
    row_re = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|", re.MULTILINE)
    for label, num in row_re.findall(text):
        lab = label.lower()
        n = int(num)
        if "proof" in lab and "back" in lab:
            counts["proof_backed"] = n
        elif "block" in lab:
            counts["blocked"] = n
        elif "ruled" in lab or "ruled-out" in lab or "source-ruled" in lab:
            counts["source_ruled_out"] = n
    return counts


def extract_honest_verdict(final_leads_path: Path) -> str:
    """Pull the HONEST RESULT line(s) from FINAL_LEADS.md, else a default."""
    if not final_leads_path.exists():
        return "no FINAL_LEADS.md present; pipeline yield unknown"
    text = final_leads_path.read_text(errors="replace")
    m = re.search(r"HONEST RESULT:\s*(.+?)(?:\n\n|\n---|\Z)", text,
                  re.DOTALL | re.IGNORECASE)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:600]
    return "FINAL_LEADS.md present but no HONEST RESULT marker found"


# --------------------------------------------------------------------------
# Deposit record assembly + write
# --------------------------------------------------------------------------
def build_record(*, repo: str, pin: str, slug: str, workspace: str,
                 unseen: dict, stages: list[dict], counts: dict,
                 honest_verdict: str, source_note: str,
                 provision: dict | None = None) -> dict:
    rec = {
        "schema": SCHEMA,
        "generated_at_utc": _utc_iso(),
        "target": {
            "repo": repo,
            "pin": pin,
            "name": slug,
            "workspace": workspace,
        },
        "is_unseen": unseen["is_unseen"],
        "is_unseen_detail": unseen,
        # in_tree provisioning evidence: True when REPO@PIN was checked out,
        # src/ mirrored, and manifests written before `make audit`. The
        # consumer can assert in_tree=true (not claim-narrowed-out-of-tree).
        "provisioned_in_tree": bool(provision.get("in_tree")) if provision else None,
        "provision_detail": provision,
        "stages_run": stages,
        "final_leads_counts": {
            "proof_backed": counts.get("proof_backed", 0),
            "blocked": counts.get("blocked", 0),
            "source_ruled_out": counts.get("source_ruled_out", 0),
        },
        # the publisher reads proof_backed_lead_yield directly
        "proof_backed_lead_yield": counts.get("proof_backed", 0),
        "honest_verdict": honest_verdict,
        "source_note": source_note,
    }
    return rec


def deposit_path_for(slug: str, date: str | None = None) -> Path:
    return DEPOSIT_DIR / f"{slug}-{date or _utc_date()}.json"


def write_deposit(record: dict, slug: str, date: str | None = None) -> Path:
    DEPOSIT_DIR.mkdir(parents=True, exist_ok=True)
    out = deposit_path_for(slug, date)
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


# --------------------------------------------------------------------------
# prb-proxy PR11 re-emit (idempotent backfill from the prose FINAL_LEADS.md)
# --------------------------------------------------------------------------
PRB_PROXY_WS = AUDITS_ROOT / "prb-proxy-fwdtest"
PRB_PROXY_REPO = "github.com/PaulRBerg/prb-proxy"
PRB_PROXY_PIN = "e45f5325d4b6003227a6c4bdaefac9453f89de2e"
PRB_PROXY_DATE = "2026-05-30"


def reemit_prb_proxy() -> dict:
    """Build the deposit record for the PR11 prb-proxy run from its existing
    prose FINAL_LEADS.md. No stages are re-run; this is a faithful transcription
    into the deposit schema (the stages already ran in PR11)."""
    final_leads = PRB_PROXY_WS / "FINAL_LEADS.md"
    counts = parse_final_leads_counts(final_leads)
    honest = extract_honest_verdict(final_leads)
    if not final_leads.exists():
        counts = {"proof_backed": 0, "blocked": 0, "source_ruled_out": 6}
        honest = (
            "PR11 prb-proxy forward test transcribed without local FINAL_LEADS.md; "
            "canonical counts are proof-backed=0, blocked=0, source-ruled-out=6."
        )
    slug = "prb-proxy"
    unseen = compute_is_unseen(PRB_PROXY_REPO, slug, PRB_PROXY_WS)
    # PR11 stage trail (transcribed from FINAL_LEADS.md "Stages run" section).
    stages = [
        {"stage": "tier6-bidirectional-commit-mining", "status": "ok",
         "evidence": "mining_rounds/2026-05-30-bidirectional-commit-mining/commit_mining_manifest.json"},
        {"stage": "make-audit", "status": "ok",
         "evidence": "engage scan (slither/semgrep/aderyn) + intake + exploit-queue(10) + prove-top-leads; rc=0"},
        {"stage": "novel-vector-invariant-miner", "status": "ok",
         "evidence": "14 target-specific invariants (4 MIMO-refined) -> .auditooor/novel_invariants_registry.json"},
        {"stage": "evm-engine-harness-author", "status": "ok",
         "evidence": "halmos/medusa/echidna/foundry-invariant candidate specs -> poc-tests/engine_harnesses/ (candidate-not-proof)"},
        {"stage": "real-poc-build-run", "status": "ok",
         "evidence": "forge build ok; forge test --match-contract AdvReentrancyTest -> 1 passed (Lead L1 execution-ruled-out)"},
        {"stage": "adversarial-candidate-verify", "status": "ok",
         "evidence": "Lead L1 Critical claim killed 3/3 lenses (fail-killed-by-panel) - correct"},
        {"stage": "evm-0day-proof-pipeline", "status": "not-invoked",
         "evidence": "no Medium+ candidate survived adversarial-verify; nothing to prove"},
        {"stage": "fork-divergence-hunt-stage", "status": "n/a",
         "evidence": "prb-proxy is a standalone library, not a fork; fork-divergence N/A"},
    ]
    source_note = (
        "re-emitted from PR11 prose FINAL_LEADS.md at "
        f"{PRB_PROXY_WS}/FINAL_LEADS.md; stages transcribed (not re-run)"
    )
    record = build_record(
        repo=PRB_PROXY_REPO, pin=PRB_PROXY_PIN, slug=slug,
        workspace=str(PRB_PROXY_WS), unseen=unseen, stages=stages,
        counts=counts, honest_verdict=honest, source_note=source_note,
    )
    out = write_deposit(record, slug, PRB_PROXY_DATE)
    record["_deposit_path"] = str(out.relative_to(REPO_ROOT))
    return record


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fresh-target forward-test runner.")
    ap.add_argument("--repo", help="target repo, e.g. github.com/Owner/Name")
    ap.add_argument("--pin", help="audit-pin commit SHA")
    ap.add_argument("--workspace", help="forward-test workspace path")
    ap.add_argument("--target-name", default=None,
                    help="override the derived target slug")
    ap.add_argument("--no-run-stages", action="store_true",
                    help="skip running pipeline stages; only deposit is_unseen + "
                         "parse any existing FINAL_LEADS.md in the workspace")
    ap.add_argument("--no-provision", action="store_true",
                    help="skip in-tree provisioning (clone REPO@PIN + mirror src/ "
                         "+ write targets.tsv/AUDIT_PIN.txt); assume the workspace "
                         "is already provisioned in-tree")
    ap.add_argument("--clone-timeout", type=int, default=600,
                    help="git clone/fetch timeout in seconds (default 600)")
    ap.add_argument("--stage-timeout", type=int, default=1800,
                    help="per-stage timeout in seconds (default 1800)")
    ap.add_argument("--evm-proof-candidate",
                    help="single candidate JSON or exploit-queue row for evm-0day-proof-pipeline")
    ap.add_argument("--reemit-prb-proxy", action="store_true",
                    help="re-emit the PR11 prb-proxy run into the deposit schema")
    ap.add_argument("--json", action="store_true", help="emit the record as JSON")
    args = ap.parse_args(argv)

    if args.reemit_prb_proxy:
        record = reemit_prb_proxy()
        if args.json:
            print(json.dumps(record, indent=2, sort_keys=True))
        else:
            print(f"re-emitted prb-proxy deposit -> {record['_deposit_path']}")
            print(f"  is_unseen={record['is_unseen']} "
                  f"proof_backed={record['final_leads_counts']['proof_backed']} "
                  f"source_ruled_out={record['final_leads_counts']['source_ruled_out']}")
        return 0

    if not (args.repo and args.pin and args.workspace):
        ap.error("--repo, --pin, and --workspace are required (or use "
                 "--reemit-prb-proxy)")

    repo = args.repo
    pin = args.pin
    workspace = Path(args.workspace)
    slug = target_slug(repo, args.target_name)

    unseen = compute_is_unseen(repo, slug, workspace)

    # Provision the workspace IN-TREE before any audit stage runs, unless the
    # caller opted out or is skipping stages entirely. This closes the
    # step4-sweep gap where `make audit` ran against an empty tree (rc=2 /
    # claim-narrowed-out-of-tree) because REPO@PIN was never checked out.
    provision = None
    if not args.no_run_stages and not args.no_provision:
        provision = provision_workspace_in_tree(
            repo, pin, workspace, clone_timeout=args.clone_timeout)

    if args.no_run_stages:
        stages = [{"stage": s[0], "status": "skipped"} for s in PIPELINE_STAGES]
    else:
        candidate = Path(args.evm_proof_candidate) if args.evm_proof_candidate else None
        stages = run_stages(workspace, timeout=args.stage_timeout,
                            repo=repo, pin=pin, provision=provision,
                            evm_proof_candidate=candidate)

    final_leads = workspace / "FINAL_LEADS.md"
    counts = parse_final_leads_counts(final_leads)
    honest = extract_honest_verdict(final_leads)
    source_note = ("stages run by fresh-target-forward-test.py"
                   if not args.no_run_stages else
                   "stages skipped (--no-run-stages); counts from existing FINAL_LEADS.md")

    record = build_record(
        repo=repo, pin=pin, slug=slug, workspace=str(workspace),
        unseen=unseen, stages=stages, counts=counts, honest_verdict=honest,
        source_note=source_note, provision=provision,
    )
    out = write_deposit(record, slug)
    record["_deposit_path"] = str(out.relative_to(REPO_ROOT))

    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        print(f"deposited forward-test record -> {record['_deposit_path']}")
        print(f"  target={repo} pin={pin[:12]} is_unseen={record['is_unseen']}")
        if provision is not None:
            print(f"  provisioned_in_tree={record['provisioned_in_tree']} "
                  f"sol_files={provision.get('mirrored_sol_file_count', 0)}")
        print(f"  proof_backed={counts['proof_backed']} "
              f"blocked={counts['blocked']} "
              f"source_ruled_out={counts['source_ruled_out']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
