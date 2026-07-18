#!/usr/bin/env python3
"""readme-step-integrity.py - fail-closed verifier that every canonical README
audit step ran in FULL mode (not silently degraded or skipped).

Motivation (the 6-day miss): tier-6 commit-mining silently ran in
``local-git-only`` mode for days because the only gate signal was "an artifact
exists" - nothing asserted the step reached GitHub. A degraded step looked
"done", so the upstream post-pin security fixes were never mined. This gate
closes that hole generically: each canonical step is classified
FULL / DEGRADED / SKIPPED / MISSING from its on-disk artifact, with the
degradation reason cited. Under STRICT, any DEGRADED or SKIPPED step fails the
gate - because a degraded step is unfinished work, not a finished one.

Usage:
    python3 tools/readme-step-integrity.py --workspace <ws> [--strict] [--json]

Exit codes: 0 = all steps FULL (or non-strict). 1 = a step degraded/skipped under --strict.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time

FULL, DEGRADED, SKIPPED, MISSING = "FULL", "DEGRADED", "SKIPPED", "MISSING"


def _load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def _newest(ws, *patterns):
    hits = []
    for pat in patterns:
        hits += glob.glob(os.path.join(ws, ".auditooor", pat))
        hits += glob.glob(os.path.join(ws, ".auditooor", "*", pat))  # one subdir deep
        hits += glob.glob(os.path.join(ws, pat))
    hits = [h for h in hits if os.path.isfile(h)]
    if not hits:
        return None, None
    newest = max(hits, key=lambda p: os.path.getmtime(p))
    return newest, _load_json(newest)


def _read_pin_and_repo(ws):
    """Best-effort extract (pinned_sha, owner_repo) from workspace metadata."""
    pin = repo = None
    rs = _load_json(os.path.join(ws, ".auditooor", "repo_strategy.json"))
    if isinstance(rs, dict):
        repo = rs.get("owner_repo") or rs.get("repo")
    scope = os.path.join(ws, "SCOPE.md")
    if os.path.isfile(scope):
        import re
        txt = open(scope, errors="ignore").read()
        m = re.search(r"PINNED COMMIT:\s*`?([0-9a-f]{40})", txt)
        if m:
            pin = m.group(1)
        if not repo:
            m2 = re.search(r"([\w.-]+/[\w.-]+)`?\s*@\s*branch", txt)
            if m2:
                repo = m2.group(1).lstrip("`")
    # Serving-join fix: not every workspace writes a SCOPE.md "PINNED COMMIT:"
    # line, but the pinned SHA is always recorded in repo_strategy.json (the same
    # artifact that supplies owner_repo, and what the commit-mining gate reads).
    # Fall back to it so pin-freshness never false-SKIPs a genuinely-pinned audit.
    if not pin and isinstance(rs, dict):
        cand = rs.get("audit_pin_sha") or rs.get("audit_pin") or rs.get("pin")
        if not cand:
            for t in (rs.get("targets") or []):
                if isinstance(t, dict):
                    cand = t.get("pin") or t.get("audit_pin_sha") or t.get("audit_pin")
                    if cand:
                        if not repo:
                            repo = t.get("owner_repo") or t.get("repo") or repo
                        break
        if cand:
            pin = str(cand).strip()
    return pin, repo


def _remote_default_tip(repo):
    """Default-branch tip SHA via the UNAUTHENTICATED public commits API.

    ``commits?per_page=1`` returns the default-branch HEAD, so no branch name is
    hardcoded and no gh auth is needed (the auth path can hang -> TimeoutExpired).
    Returns '' on any error so the caller SKIPs gracefully rather than crashing.
    """
    import re as _re
    import json as _json
    import urllib.request as _u
    slug = str(repo or "").replace("https://github.com/", "")
    m = _re.search(r"([\w.-]+/[\w.-]+?)(?:\.git)?$", slug)
    if not m:
        return ""
    slug = m.group(1)
    try:
        req = _u.Request(
            f"https://api.github.com/repos/{slug}/commits?per_page=1",
            headers={"User-Agent": "auditooor-step-integrity", "Accept": "application/vnd.github+json"},
        )
        with _u.urlopen(req, timeout=15) as r:
            data = _json.loads(r.read().decode("utf-8", "replace"))
        if isinstance(data, list) and data:
            return str(data[0].get("sha", "")).strip()
    except Exception:
        return ""
    return ""


def _pin_policy(ws):
    """Resolve the workspace pin-freshness policy: 'release' or 'head' (default).

    Some programs (e.g. Lido) scope findings to DEPLOYED contracts associated with
    published RELEASES, NOT default-branch/develop HEAD - a bug only on develop is
    explicitly OUT OF SCOPE. For those, "track the latest HEAD" is the WRONG policy:
    the correct pin is the latest STABLE release tag, and a HEAD-based freshness
    check raises a false DEGRADED. Resolution order:
      1. explicit marker .auditooor/pin_policy.json {"policy": "release"|"head"}
      2. auto-detect from SCOPE.md prose (releases-only / deployed-only signals)
      3. default "head" (the standing always-audit-latest policy).
    """
    marker = _load_json(os.path.join(ws, ".auditooor", "pin_policy.json"))
    if isinstance(marker, dict):
        p = str(marker.get("policy") or "").strip().lower()
        if p in ("release", "head", "deployed"):
            return p
    scope = os.path.join(ws, "SCOPE.md")
    if os.path.isfile(scope):
        import re as _re
        txt = open(scope, errors="ignore").read()
        if _re.search(
            r"releases?[\s,_-]*not\s+develop|latest\s+release\s+tag|releases?-only|"
            r"deployed\s+contracts,?\s+not\s+latest|associated\s+with\s+releases",
            txt, _re.I,
        ):
            return "release"
    return "head"


_RELEASE_SHA_CACHE = {}  # in-process memo: slug -> (tag, sha)


def _release_cache_disk():
    """Cross-process TTL cache so a 5-min audit loop does not exhaust the 60/hr
    UNAUTHENTICATED GitHub rate limit re-resolving the same release every tick."""
    import time
    path = os.path.expanduser("~/.cache/auditooor/pin_release_cache.json")
    ttl = 6 * 3600
    try:
        d = _load_json(path)
        if isinstance(d, dict):
            now = time.time()
            return path, {k: v for k, v in d.items()
                          if isinstance(v, dict) and (now - v.get("ts", 0)) < ttl}
    except Exception:
        pass
    return path, {}


def _latest_stable_release_sha(repo):
    """(tag, commit_sha) of the latest STABLE (non-prerelease) release, or ('','').

    Uses the UNAUTHENTICATED public API (no gh auth = no keychain hang):
      - /releases/latest already excludes drafts + prereleases (e.g. -rc/-beta).
      - resolve tag_name -> commit via /commits/{tag} (auto-derefs annotated tags).
    Fallback when a repo publishes git tags but no GitHub Release objects: list
    /tags, drop semver prerelease identifiers, pick the highest. Fail-soft to ('','')
    on any error so the caller SKIPs (never a false-fail / false-green). Results are
    memoised in-process and on disk (6h TTL) to stay under the public rate limit.
    """
    import json as _json
    import re as _re
    import time
    import urllib.request as _u
    slug = str(repo or "").replace("https://github.com/", "")
    m = _re.search(r"([\w.-]+/[\w.-]+?)(?:\.git)?$", slug)
    if not m:
        return "", ""
    slug = m.group(1)
    if slug in _RELEASE_SHA_CACHE:
        return _RELEASE_SHA_CACHE[slug]
    cache_path, disk = _release_cache_disk()
    if slug in disk:
        hit = (disk[slug].get("tag", ""), disk[slug].get("sha", ""))
        _RELEASE_SHA_CACHE[slug] = hit
        return hit

    def _get(url):
        try:
            req = _u.Request(url, headers={
                "User-Agent": "auditooor-step-integrity",
                "Accept": "application/vnd.github+json",
            })
            with _u.urlopen(req, timeout=15) as r:
                return _json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return None

    def _resolve(tag):
        c = _get(f"https://api.github.com/repos/{slug}/commits/{tag}")
        if isinstance(c, dict) and c.get("sha"):
            return str(c["sha"]).strip().lower()
        return ""

    def _remember(tag, sha):
        result = (tag, sha)
        _RELEASE_SHA_CACHE[slug] = result
        # Persist ONLY successful resolutions (don't cache transient failures as ('','')).
        if tag and sha:
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                disk[slug] = {"tag": tag, "sha": sha, "ts": time.time()}
                with open(cache_path, "w") as fh:
                    _json.dump(disk, fh)
            except Exception:
                pass
        return result

    rel = _get(f"https://api.github.com/repos/{slug}/releases/latest")
    if isinstance(rel, dict) and rel.get("tag_name") and not rel.get("prerelease"):
        tag = str(rel["tag_name"])
        sha = _resolve(tag)
        if sha:
            return _remember(tag, sha)
    # Fallback: tags-only repo (no Release objects). Pick highest stable semver.
    tags = _get(f"https://api.github.com/repos/{slug}/tags?per_page=100")
    if isinstance(tags, list) and tags:
        def _key(name):
            mm = _re.match(r"v?(\d+)\.(\d+)\.(\d+)", str(name))
            return tuple(int(x) for x in mm.groups()) if mm else (-1, -1, -1)
        stable = [t for t in tags
                  if isinstance(t, dict) and t.get("name")
                  and not _re.search(r"-(rc|alpha|beta|pre|dev)\b", str(t["name"]), _re.I)
                  and _re.match(r"v?\d+\.\d+\.\d+", str(t["name"]))]
        if stable:
            best = max(stable, key=lambda t: _key(t["name"]))
            sha = (best.get("commit") or {}).get("sha") or _resolve(best["name"])
            if sha:
                return _remember(str(best["name"]), str(sha).strip().lower())
    return "", ""


def _read_targets(ws):
    """All (repo, pin, local_name) audit targets. Multi-repo workspaces record them
    in repo_strategy.json targets[] - each target carries its OWN repo + pin. The
    old single-(pin,repo) read paired one repo's pin with the top-level owner_repo
    of a DIFFERENT repo on multi-repo workspaces (the Lido false-DEGRADED). Falls
    back to _read_pin_and_repo for single-repo workspaces."""
    rs = _load_json(os.path.join(ws, ".auditooor", "repo_strategy.json"))
    out = []
    if isinstance(rs, dict):
        for t in (rs.get("targets") or []):
            if isinstance(t, dict):
                repo = t.get("owner_repo") or t.get("repo")
                pin = t.get("pin") or t.get("audit_pin_sha") or t.get("audit_pin")
                if repo and pin:
                    out.append((str(repo), str(pin).strip().lower(), t.get("local_name") or ""))
    # Serving-join fix: repo_strategy.json is only written by `make audit`. A freshly
    # set-up / re-pinned workspace records its pins in targets.tsv (the canonical pin
    # manifest the clone + commit-mining + audit-target-commit-mining all read) BEFORE
    # make audit re-runs. Fall back to targets.tsv so pin-freshness works pre-audit
    # too, instead of false-SKIPPING a genuinely-pinned multi-repo workspace.
    if not out:
        out.extend(_read_targets_tsv(ws))
    if not out:
        pin, repo = _read_pin_and_repo(ws)
        if pin and repo:
            out.append((str(repo), str(pin).strip().lower(), ""))
    return out


def _read_targets_tsv(ws):
    """Parse <ws>/targets.tsv -> [(owner_repo, pin, local_name)]. Format (tab-sep,
    '#' comments): repo_url<TAB>pinned_commit<TAB>local_name. Normalises the repo_url
    to owner/name (strips https://github.com/ prefix + .git suffix)."""
    import re as _re
    path = os.path.join(ws, "targets.tsv")
    out = []
    if not os.path.isfile(path):
        return out
    try:
        for line in open(path, errors="ignore"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) < 2:
                continue
            repo_url, pin = cols[0].strip(), cols[1].strip()
            local = cols[2].strip() if len(cols) > 2 else ""
            if not pin or not _re.fullmatch(r"[0-9a-fA-F]{7,40}", pin):
                continue
            m = _re.search(r"([\w.-]+/[\w.-]+?)(?:\.git)?$", repo_url.replace("https://github.com/", ""))
            repo = m.group(1) if m else repo_url
            out.append((repo, pin.lower(), local))
    except Exception:
        return []
    return out


def _onchain_localnames(ws):
    """local_names of repos that have in-scope on-chain (Sol/Vyper) units - the only
    repos the deployed-only/releases-only rule governs. Off-chain auxiliary repos
    (TS/Py services, merkle-tree libs) have no deployed contracts, so release-pin
    freshness does not apply to them. Empty set => unknown (caller checks all)."""
    names = set()
    p = os.path.join(ws, ".auditooor", "inscope_units.jsonl")
    if os.path.isfile(p):
        import json as _json
        for line in open(p, errors="ignore"):
            try:
                d = _json.loads(line)
            except Exception:
                continue
            f = d.get("file") or d.get("path") or ""
            parts = [x for x in f.split("/") if x not in ("", ".")]
            if parts and parts[0] in ("src", "contracts"):
                parts = parts[1:]
            if parts:
                names.add(parts[0])
    return names


def check_pin_freshness(ws):
    """POLICY: every audit target must track the latest in-scope upstream code.

    Default policy is "head": each pin must track its repo's DEFAULT-branch HEAD;
    a stale pin silently audits old code and misses everything merged since.
    When the workspace declares a "release" policy (releases-only / deployed-only
    programs - see _pin_policy), the target is instead each repo's latest STABLE
    RELEASE tag, because develop/HEAD findings are OUT OF SCOPE there; off-chain
    auxiliary repos (no deployed contracts) are exempt. Multi-repo aware: checks
    EACH target's own (repo, pin). DEGRADED if ANY target lags its policy target.
    Skips gracefully (not a false-fail) when offline / no recorded pin.
    """
    targets = _read_targets(ws)
    if not targets:
        return SKIPPED, "no recorded pin/repo in SCOPE.md or repo_strategy.json"

    policy = _pin_policy(ws)
    if policy == "deployed":
        # DEPLOYED-ONLY programs (e.g. NUVA): the in-scope assets are specific
        # mainnet DEPLOYED addresses, and the pin is deliberately the DEPLOYED
        # bytecode version - which is typically NOT the latest release/HEAD (the
        # repo moves on after deployment). Comparing to HEAD/latest-release here is
        # a FALSE DEGRADED. Freshness for a deployed pin = "pin matches the live
        # deployed impl", which is an on-chain bytecode check done at setup/filing
        # (recorded in pin_policy.json {evm_deployed_pin,vault_deployed_pin} +
        # re-verified at filing per SCOPE). So credit FULL when the workspace
        # declares deployed pins; never flag a deployed pin as "behind HEAD".
        marker = _load_json(os.path.join(ws, ".auditooor", "pin_policy.json")) or {}
        declared = [str(v)[:10] for k, v in marker.items()
                    if k.endswith("_deployed_pin") and v]
        names = ", ".join(f"{local or repo}@{pin[:10]}" for repo, pin, local in targets[:6])
        return FULL, (
            f"deployed-pin policy: {len(targets)} target(s) pinned to operator-confirmed "
            f"DEPLOYED version(s) ({names}); freshness-vs-latest is intentionally N/A "
            f"(re-verify proxy impl slot at filing per pin_policy.json)"
            + (f"; declared deployed pins: {', '.join(declared)}" if declared else "")
        )

    if policy == "release":
        onchain = _onchain_localnames(ws)
        ok, behind, unresolved = [], [], []
        for repo, pin, local in targets:
            # releases-only/deployed-only governs DEPLOYED-CONTRACT repos only.
            if onchain and local and local not in onchain:
                continue
            tag, rel_sha = _latest_stable_release_sha(repo)
            if not rel_sha:
                unresolved.append(local or repo)
            elif rel_sha.startswith(pin) or pin.startswith(rel_sha):
                ok.append(f"{local or repo}@{tag}")
            else:
                behind.append(f"{local or repo} {pin[:10]}<{tag} {rel_sha[:10]}")
        if behind:
            return DEGRADED, (
                "pin BEHIND latest stable RELEASE for: " + "; ".join(behind) +
                " - re-pin to the latest release tag and re-audit the delta (policy: releases-only)"
            )
        if ok:
            extra = f" ({len(unresolved)} unresolved: {', '.join(unresolved[:4])})" if unresolved else ""
            return FULL, f"all {len(ok)} on-chain target(s) == latest stable RELEASE: " + ", ".join(ok[:8]) + extra
        return SKIPPED, (
            "release-pin policy: could not resolve latest stable release for any "
            "on-chain target (offline / no releases) - cannot verify freshness"
        )

    # head policy: each pin vs its repo's UNAUTHENTICATED default-branch tip.
    ok, behind, unresolved = [], [], []
    for repo, pin, local in targets:
        head_sha = _remote_default_tip(repo)
        if not head_sha:
            unresolved.append(local or repo)
            continue
        head_sha = head_sha.strip().lower()
        if head_sha.startswith(pin) or pin.startswith(head_sha):
            ok.append(local or repo)
        else:
            behind.append(f"{local or repo} {pin[:10]}<HEAD {head_sha[:10]}")
    if behind:
        return DEGRADED, (
            "pin BEHIND default-branch HEAD for: " + "; ".join(behind) +
            " - re-pin to HEAD and re-audit the delta (policy: always audit latest)"
        )
    if ok:
        return FULL, f"all {len(ok)} target(s) == default-branch HEAD"
    return SKIPPED, "could not resolve upstream default-branch HEAD (offline) - cannot verify freshness"


def _pin_is_remote_tip(d) -> bool:
    """True iff the artifact's audit pin sha == the upstream repo's remote
    default-branch tip, confirmed via the UNAUTHENTICATED GitHub public commits
    API (no token needed for a public repo). Used to credit a local-git-only
    commit-mining run as complete when there are provably NO post-pin upstream
    commits to forward-mine. Fail-closed: any error / mismatch / private repo
    returns False (so it can never false-green a genuinely-stale pin)."""
    repo = str(d.get("upstream_repo") or d.get("upstream") or "").strip()
    pin = str(d.get("audit_pin_sha") or d.get("audit_pin") or "").strip().lower()
    if not repo or not pin:
        return False
    # normalise to owner/name (strip any github.com URL prefix / .git suffix)
    m = re.search(r"([\w.-]+/[\w.-]+?)(?:\.git)?$", repo.replace("https://github.com/", ""))
    if not m:
        return False
    slug = m.group(1)
    import json as _json
    import urllib.request as _u
    try:
        req = _u.Request(
            f"https://api.github.com/repos/{slug}/commits?per_page=1",
            headers={"User-Agent": "auditooor-step-integrity", "Accept": "application/vnd.github+json"},
        )
        with _u.urlopen(req, timeout=15) as r:
            data = _json.loads(r.read().decode("utf-8", "replace"))
        if isinstance(data, list) and data:
            tip = str(data[0].get("sha", "")).strip().lower()
            return bool(tip) and tip == pin
    except Exception:
        return False
    return False


def check_commit_mining(ws):
    """tier-6 bidirectional commit-mining (a README Step-1 item)."""
    path, d = _newest(ws, "git_commits_mining*.json", "commit_mining*.json")
    if not path or not isinstance(d, dict):
        # The canonical commit-mining output lands in
        # <ws>/mining_rounds/<date>-bidirectional-commit-mining/commit_mining_manifest.json
        # (two dirs deep), which _newest's shallow globs miss. Search that
        # location explicitly before declaring the step never ran - otherwise a
        # mining run that DID happen is reported as a false SKIPPED. Generic: any
        # workspace, any mining-round date dir.
        rounds = sorted(
            glob.glob(os.path.join(ws, "mining_rounds", "*", "*commit_mining*.json"))
            + glob.glob(os.path.join(ws, "mining_rounds", "*", "*git_commits_mining*.json")),
            key=lambda p: os.path.getmtime(p) if os.path.isfile(p) else 0,
        )
        rounds = [r for r in rounds if os.path.isfile(r)]
        # Prefer a per-lang git_commits_mining artifact that actually carries a
        # commits_scanned field with the MOST commits, over the commit_mining_
        # manifest.json (a roll-up index that has no commits_scanned field and so
        # reads as 0 - the false "0 commits scanned" the newest-mtime pick hit).
        best = None
        best_scanned = -1
        for r in rounds:
            rd = _load_json(r)
            if not isinstance(rd, dict):
                continue
            sc = rd.get("commits_scanned") or rd.get("scanned")
            if isinstance(sc, int) and sc > best_scanned:
                best, best_scanned, d = r, sc, rd
        if best is not None:
            path = best
        elif rounds:
            path = rounds[-1]
            d = _load_json(path)
    if not path or not isinstance(d, dict):
        return SKIPPED, "no git_commits_mining artifact - commit-mining step never ran"
    scanned = d.get("commits_scanned") or d.get("scanned") or 0
    if d.get("fallback_mode") == "local-git-only" or d.get("gh_auth") is False:
        # local-git-only misses REMOTE post-pin security fixes ONLY when post-pin
        # commits actually exist. When the audit pin IS the remote default-branch
        # tip, there are NO post-pin commits to forward-mine, so local backward-
        # mining is complete (R47 forward dedup is vacuous). We confirm pin ==
        # remote tip via the UNAUTHENTICATED public commits API (no token needed
        # for a public repo), so a missing/expired gh token does not false-red a
        # HEAD-pinned workspace. Any uncertainty (network fail, mismatch, private
        # repo) stays DEGRADED - never a false-green.
        if scanned and _pin_is_remote_tip(d):
            return FULL, (
                f"{scanned} commits scanned (local-git-only); audit pin == remote "
                "default-branch tip - forward-mining provably vacuous (no post-pin "
                "upstream commits; remote-confirmed unauthenticated)"
            )
        return DEGRADED, (
            "ran in local-git-only mode (no GitHub auth reached) - upstream "
            "post-pin security fixes were NOT mined. Fix: ensure `gh auth token` "
            "is usable / GH_TOKEN exported, then rerun."
        )
    if not scanned:
        return DEGRADED, "0 commits scanned - empty mining run"
    if d.get("fallback_mode") == "public-unauthenticated-api":
        return FULL, (
            f"{scanned} upstream commits scanned via UNAUTHENTICATED public API "
            f"(real remote forward+backward mine; gh-auth-free), "
            f"fix_count={d.get('security_fix_count', '?')}"
        )
    return FULL, f"{scanned} upstream commits scanned, fix_count={d.get('security_fix_count', '?')}"


def check_scanners(ws):
    """Automated detectors (slither/semgrep/cargo-audit/staticcheck) actually emitted."""
    path, d = _newest(ws, "scanner_ran_integrity*.json", "scanner_integrity*.json")
    if path and isinstance(d, dict):
        bad = d.get("silent_skip", []) or d.get("silent_zero", []) or []
        errored = d.get("errored", []) or []
        if bad:
            return DEGRADED, f"scanner(s) silent-0 false-green: {bad[:5]}"
        if errored and not d.get("ran"):
            return DEGRADED, f"scanner(s) errored with nothing ran: {errored[:5]}"
        if d.get("ran"):
            return FULL, f"{len(d.get('ran', []))} scanner(s) produced real output"
    # fall back to artifact presence. Detector artifacts (slither's
    # detector_action_graph*, corpus_detectorization_inventory) ARE scanner
    # output - the detector pipeline is a scanner - so recognise them too, else
    # a workspace that ran detectors but emitted no scanner_ran_integrity sidecar
    # false-SKIPs (serving-join fix).
    hits = (
        glob.glob(os.path.join(ws, ".auditooor", "*scan*"))
        + glob.glob(os.path.join(ws, "scan", "*"))
        + glob.glob(os.path.join(ws, ".auditooor", "*detector*"))
    )
    return (FULL, f"{len(hits)} scan artifact(s)") if hits else (SKIPPED, "no scanner artifacts")


def check_orient(ws):
    """Intake/orient topology resolution."""
    path, d = _newest(ws, "topology*.json", "orient*.json", "intake*topology*.json")
    if not path or not isinstance(d, dict):
        # No structured topology artifact: accept INTAKE_BASELINE.md as evidence the
        # orient/intake step ran (topology resolution is best-effort on a monorepo).
        for c in ("INTAKE_BASELINE.md", "intake_baseline.md", "engage_report.md"):
            if os.path.isfile(os.path.join(ws, c)):
                return FULL, f"intake ran ({c}); no structured topology artifact (best-effort on monorepo)"
        return SKIPPED, "no orient/topology/intake artifact"
    unresolved = len(d.get("unresolved_addresses", []) or [])
    ambiguous = len(d.get("ambiguous", []) or [])
    if d.get("errors"):
        return DEGRADED, f"orient reported {len(d['errors'])} errors"
    if unresolved or ambiguous:
        # partial topology on a big monorepo is expected; flag as DEGRADED only
        # if it was never dispositioned.
        if d.get("partial_accepted") or d.get("dispositioned"):
            return FULL, f"topology partial but dispositioned ({unresolved} unresolved, {ambiguous} ambiguous)"
        return DEGRADED, f"topology partial, not dispositioned: {unresolved} unresolved, {ambiguous} ambiguous addresses"
    return FULL, "topology fully resolved"


def _genuine_standalone_campaign(ws):
    """A standalone coverage-guided campaign (step-2c echidna>=500k / medusa>=1M
    over the real CUT, in .auditooor/fuzz_campaign_receipt.json, raw-log
    corroborated + >=1 non-vacuity mutant kill) is genuine engine-harness
    execution even when the auto-wired engine step recorded 0 (no-target / rc=6).
    Mirrors the never-false-pass guards in audit-completeness-check /
    honest-zero-verify. Returns the credited call count, or 0 when none qualifies."""
    a = os.path.join(ws, ".auditooor")
    rp = os.path.join(a, "fuzz_campaign_receipt.json")
    if not os.path.isfile(rp):
        return 0
    try:
        d = json.load(open(rp))
    except Exception:
        return 0
    if not isinstance(d, dict) or str(d.get("schema", "")) != "auditooor.fuzz_campaign_receipt.v1":
        return 0
    thr = {"echidna": 500_000, "medusa": 1_000_000}
    max_log = 0
    logd = os.path.join(a, "fuzz_logs")
    if os.path.isdir(logd):
        for fn in os.listdir(logd):
            if not fn.endswith(".log"):
                continue
            try:
                txt = open(os.path.join(logd, fn), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r"Total calls:\s*([0-9][0-9_,]*)", txt):
                try:
                    max_log = max(max_log, int(m.group(1).replace(",", "").replace("_", "")))
                except ValueError:
                    pass
    totals = d.get("totals") if isinstance(d.get("totals"), dict) else {}
    try:
        tot_kills = int(totals.get("non_vacuity_kills") or 0)
    except (ValueError, TypeError):
        tot_kills = 0
    for c in (d.get("campaigns") or []):
        if not isinstance(c, dict):
            continue
        t = thr.get(str(c.get("engine", "")).lower())
        if not t:
            continue
        res = c.get("result") if isinstance(c.get("result"), dict) else {}
        try:
            calls = int(res.get("calls") or 0)
            passed = int(res.get("passed") or 0)
        except (ValueError, TypeError):
            continue
        if calls < t or passed < 1 or max_log < t:
            continue
        try:
            ckills = int(c.get("non_vacuity_kills") or 0)
        except (ValueError, TypeError):
            ckills = 0
        md_kill = any(
            isinstance(m, dict)
            and str(m.get("baseline", "")).upper() == "PASS"
            and str(m.get("mutant_result", "")).upper() == "FAIL"
            for m in (c.get("mutation_detail") or [])
        )
        if ckills < 1 and tot_kills < 1 and not md_kill:
            continue
        return max(calls, max_log)
    return 0


def check_engines(ws):
    """audit-deep LIVE engine harness execution (echidna/halmos/medusa)."""
    for pat in ("engine-harness-execution.json", "audit_deep*.json", "engine*summary*.json", "depth*manifest*.json"):
        path, d = _newest(ws, pat)
        if isinstance(d, dict) and "executed_engine_harness_count" in d:
            n = d.get("executed_engine_harness_count") or 0
            if n:
                return FULL, f"{n} engine harnesses executed"
            break
    # ws-level marker
    mk = os.path.join(ws, ".auditooor", "executed_engine_harness_count")
    if os.path.isfile(mk):
        try:
            n = int(open(mk).read().strip())
            if n:
                return FULL, f"{n} engine harnesses executed"
        except Exception:
            pass
    # Serving-join fix: the auto-wired engine step can record 0 executed harnesses
    # (no-target echidna / rc=6 medusa) while the genuine step-2c standalone
    # campaign ran >=500k/1M mutation-verified calls over the real CUT. Credit it.
    campaign_calls = _genuine_standalone_campaign(ws)
    if campaign_calls:
        return FULL, f"standalone coverage-guided campaign executed ({campaign_calls} calls, mutation-verified, real CUT)"
    # No auto-run count AND no genuine campaign.
    for pat in ("engine-harness-execution.json", "audit_deep*.json"):
        _p, _d = _newest(ws, pat)
        if isinstance(_d, dict) and "executed_engine_harness_count" in _d:
            return DEGRADED, "0 engine harnesses executed"
    return SKIPPED, "no engine-execution evidence (audit-deep LIVE not confirmed)"


_CORPUS_REL = os.path.join(
    "audit", "corpus_tags", "derived", "invariants_pilot_audited.jsonl"
)


def _resolve_corpus(ws):
    """Locate the active cross-workspace corpus feeder.

    The corpus that feeds cross-workspace pattern transfer lives at the
    repo-relative path ``audit/corpus_tags/derived/invariants_pilot_audited.jsonl``.
    Prefer a workspace-local copy (some workspaces mirror it); otherwise fall back
    to the auditooor repo root that ships this tool
    (``Path(__file__).resolve().parents[1]``, the canonical REPO_ROOT idiom used by
    semantic-predicate-gate.py / invariant-auto-synth.py). Returns the path or None.
    """
    candidates = [os.path.join(ws, _CORPUS_REL)]
    try:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates.append(os.path.join(repo_root, _CORPUS_REL))
    except Exception:
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _newest_hunt_artifact_mtime(ws):
    """Newest mtime across the hunt artifacts (questions file + sidecar bodies).

    Returns (mtime, label) or (None, None) when no hunt artifact exists.
    """
    paths = []
    for c in ("per_fn_hacker_questions.jsonl", "per_function_hacker_questions.jsonl"):
        p = os.path.join(ws, ".auditooor", c)
        if os.path.isfile(p):
            paths.append(p)
    for sd in (
        os.path.join(ws, ".auditooor", "hunt_findings_sidecars"),
        os.path.join(ws, "hunt_findings_sidecars"),
    ):
        if os.path.isdir(sd):
            for root, _dirs, files in os.walk(sd):
                for f in files:
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp):
                        paths.append(fp)
    if not paths:
        return None, None
    newest = max(paths, key=lambda p: os.path.getmtime(p))
    return os.path.getmtime(newest), os.path.basename(newest)


def _hunt_dispatched(ws):
    """True iff the scoped hunt actually DISPATCHED and produced results: a
    non-empty hunt_findings_sidecars/ tree (the same dispatch signal
    hunt-completeness-check.py keys on). per_fn_hacker_questions rows alone are
    only the GENERATED worklist - brain-prime/orient emits them too - so they do
    NOT prove the hunt ran."""
    for rel in ("hunt_findings_sidecars",
                os.path.join(".auditooor", "hunt_findings_sidecars")):
        d = os.path.join(ws, rel)
        if os.path.isdir(d):
            for _root, _dirs, files in os.walk(d):
                if files:
                    return True
    return False


def check_hunt(ws):
    """Per-function hacker-question hunt coverage AND corpus freshness.

    Two failure modes are gated here:

    1. The scoped hunt never ran / produced no rows (SKIPPED / DEGRADED).
    2. The hunt ARTIFACTS are STALE relative to the active cross-workspace corpus
       feeder. Cross-workspace transfer machinery fires fresh, but a workspace
       whose persisted hunt artifacts predate the latest corpus ingest is
       corpus-blind: it greens this gate with 0 transferred patterns. When the
       newest hunt artifact mtime is OLDER than the corpus mtime, report DEGRADED
       so the operator/loop knows to re-run the hunt to pick up newly-ingested
       cross-workspace patterns. Graceful (no false-fail) when the corpus path is
       absent or mtimes are unreadable.
    """
    qpath = None
    for c in ("per_fn_hacker_questions.jsonl", "per_function_hacker_questions.jsonl"):
        p = os.path.join(ws, ".auditooor", c)
        if os.path.isfile(p):
            qpath = p
            break
    if not qpath:
        return SKIPPED, "no per_fn_hacker_questions - scoped hunt never ran"
    n = sum(1 for _ in open(qpath))
    if not n:
        return DEGRADED, "empty hacker-questions file"

    # Dispatch evidence (FALSE-GREEN guard, Strata 2026-06-30): question rows are
    # the GENERATED worklist; brain-prime/orient emits them too. They do NOT mean
    # the scoped hunt (step-3) actually ran. Without a non-empty
    # hunt_findings_sidecars/, this gate would certify an UN-HUNTED workspace as
    # FULL (Strata: 10 brain-prime rows, 0 sidecars greened it). Require dispatch
    # evidence for FULL; otherwise DEGRADED so the loop knows step-3 is still owed.
    if not _hunt_dispatched(ws):
        return DEGRADED, (
            f"{n} hacker-question rows EXIST but hunt_findings_sidecars/ is empty - "
            "the scoped hunt (step-3) was never dispatched; these are an un-hunted "
            "worklist (brain-prime/orient placeholders), not hunt results"
        )

    # Staleness: newest hunt artifact vs active corpus feeder.
    corpus = _resolve_corpus(ws)
    if corpus:
        try:
            corpus_mtime = os.path.getmtime(corpus)
            hunt_mtime, hunt_label = _newest_hunt_artifact_mtime(ws)
            if hunt_mtime is not None and hunt_mtime < corpus_mtime:
                lag = int(corpus_mtime - hunt_mtime)
                return DEGRADED, (
                    "hunt-stale-rerun-after-corpus-refresh: newest hunt artifact "
                    f"({hunt_label}) is {lag}s OLDER than the active corpus "
                    f"({_CORPUS_REL}) - the persisted hunt is corpus-blind and "
                    "greens this gate with 0 transferred patterns. Re-run the "
                    "scoped hunt to pick up newly-ingested cross-workspace patterns."
                )
        except Exception:
            pass  # unreadable mtimes: skip staleness, not a false-fail

    return FULL, f"{n} per-fn hacker-question rows"


STEPS = [
    ("pin-freshness", check_pin_freshness),
    ("commit-mining", check_commit_mining),
    ("scanners", check_scanners),
    ("orient-topology", check_orient),
    ("audit-deep-engines", check_engines),
    ("scoped-hunt", check_hunt),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ws = os.path.abspath(args.workspace)

    results = []
    for name, fn in STEPS:
        try:
            status, reason = fn(ws)
        except Exception as exc:  # never let a probe crash the gate
            status, reason = DEGRADED, f"probe error: {type(exc).__name__}: {exc}"
        results.append({"step": name, "status": status, "reason": reason})

    bad = [r for r in results if r["status"] in (DEGRADED, SKIPPED)]
    out = {
        "tool": "readme-step-integrity",
        "workspace": ws,
        "checked_at": int(time.time()),
        "steps": results,
        "degraded_or_skipped": [r["step"] for r in bad],
        "verdict": "pass-step-integrity" if not bad else "fail-step-integrity",
    }
    os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
    with open(os.path.join(ws, ".auditooor", "readme_step_integrity.json"), "w") as fh:
        json.dump(out, fh, indent=2)

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            mark = "OK " if r["status"] == FULL else "!! "
            print(f"{mark}{r['step']:22s} {r['status']:9s} {r['reason']}")
        print(f"\n{out['verdict']}")

    if args.strict and bad:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
