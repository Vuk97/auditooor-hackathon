#!/usr/bin/env python3
"""audit-pin-monitor.py - roll the audit pin forward and re-verify open findings.

On a rolling-main bug bounty, the audit pin we capture is a SNAPSHOT, but the
program pays for the CURRENT repository. If we file weeks after capture, upstream
may have (a) added new code = new attack surface, or (b) FIXED our open finding in
a later commit (e.g. Hyperbridge PR #917 patched the Pharos apex-offset forgery 7
days after our pin -> the filed Critical got NA'd "already fixed"). This tool treats
every upstream upgrade past the captured pin as the NEW pin, and surfaces both
consequences BEFORE a stale finding is filed.

For each in-scope asset (parsed from <ws>/SCOPE.md: `Repository:` + `Audit pin ...`)
with a local git clone, it:

  1. computes the commit delta  captured-pin .. upstream-HEAD  (new commits + PR ids),
  2. FINDING RE-VERIFICATION: for every open finding under
     submissions/{paste_ready,staging,filed}/**, extracts the source file:line
     citations + guard/error idents the finding leans on, and flags any new commit
     that TOUCHES those files (and especially one that adds guard-ish lines) as a
     "possible upstream fix -> re-verify before filing / your dispute may be stale",
  3. NEW ATTACK SURFACE: lists files added / heavily changed since the pin (new code
     to audit at the advanced pin),
  4. proposes the pin advance (upstream HEAD); `--apply` rewrites the SCOPE.md pin
     line and records the bump in <ws>/.auditooor/audit_pin_monitor.json.

RELATED TOOLS (checked before building, per tool-dedup discipline):
  - tools/workspace-staleness-check.py : WARNS that upstream has new commits (freshness
    only); does NOT re-verify findings or advance the pin. This tool is the action layer.
  - tools/mcp-pin-drift-check.py : drift of the MCP server mirror, unrelated to workspace pins.
  - tools/post-audit-deployed-contract-detector.py : deployed-vs-pin contract diff, not commit/finding aware.

Offline-safe: if `git fetch` fails (no network), it uses the local clone's current
HEAD as the upstream reference and says so.

Usage:
  audit-pin-monitor.py --workspace <ws> [--apply] [--no-fetch] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.audit_pin_monitor.v1"

_SRC_EXT = ("rs", "sol", "go", "move", "vy", "cairo", "ts")
# file:line citation inside a finding md (generic across languages)
_CITE_RE = re.compile(r"\b([\w./-]+\.(?:" + "|".join(_SRC_EXT) + r"))(?::(\d+))?\b")
# guard / error idents the finding may lean on (CamelCase errors, snake guards)
_IDENT_RE = re.compile(r"\b([A-Z][A-Za-z0-9]{4,}|[a-z][a-z0-9_]{4,}(?:_offset|_check|_guard|_mismatch|_proof|_verify))\b")
_GUARD_LINE_RE = re.compile(
    r"\b(reject|require|ensure|assert|invalid|mismatch|return\s+Err|revert|"
    r"!=|<=|>=|bound|verify|check|guard|Error::)\b", re.I)
_PR_RE = re.compile(r"\(#(\d+)\)\s*$")
_OPEN_DIRS = ("paste_ready", "staging", "filed")


def _git(repo: Path, *args, timeout=60):
    try:
        r = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return 1, "", str(e)


def _parse_scope(scope_md: Path) -> list[dict]:
    """Each in-scope asset: {repo_url, pin, local_path_hint}."""
    if not scope_md.is_file():
        return []
    assets, cur = [], {}
    for ln in scope_md.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        m = re.search(r"Repository:\s*(\S+)", s)
        if m:
            if cur.get("repo_url") or cur.get("pin"):
                assets.append(cur); cur = {}
            cur["repo_url"] = m.group(1)
        m = re.search(r"Audit pin[^:`]*[:`]\s*`?([0-9a-f]{7,40})`?", s, re.I)
        if m:
            cur["pin"] = m.group(1)
        m = re.search(r"Local path[^:]*:\s*`?([\w./-]+)`?", s)
        if m:
            cur["local_path_hint"] = m.group(1)
    if cur.get("repo_url") or cur.get("pin"):
        assets.append(cur)
    return [a for a in assets if a.get("pin")]


def _resolve_repo(ws: Path, hint: str | None) -> Path | None:
    cands = []
    if hint:
        cands.append(ws / hint)
    cands += [ws / "src", ws]
    for c in cands:
        if (c / ".git").is_dir():
            return c
    # search one level for a clone matching the hint basename
    base = Path(hint).name if hint else None
    for sub in (ws / "src").glob("*"):
        if (sub / ".git").is_dir() and (base is None or sub.name == base):
            return sub
    for sub in (ws / "src").rglob(".git"):
        return sub.parent
    return None


def _open_findings(ws: Path) -> list[Path]:
    out = []
    subs = ws / "submissions"
    for d in _OPEN_DIRS:
        base = subs / d
        if base.is_dir():
            out += [p for p in base.rglob("*.md")
                    if p.stem == p.parent.name or base in p.parents and p.suffix == ".md"]
    # de-dup, prefer the finding md (stem == folder)
    seen, res = set(), []
    for p in out:
        if p in seen:
            continue
        seen.add(p); res.append(p)
    return res


# bare basenames that collide across the whole repo - never match on these alone
_GENERIC_BASENAMES = {"lib.rs", "mod.rs", "main.rs", "types.rs", "error.rs",
                      "index.ts", "utils.rs", "lib.sol", "mod.sol"}


def _finding_anchors(md: Path, slug: str) -> dict:
    txt = md.read_text(encoding="utf-8", errors="replace")
    files, idents = set(), set()
    for m in _CITE_RE.finditer(txt):
        f = m.group(1)
        # require a directory component AND >=2 path segments, and not a bare generic basename
        if "/" in f and len(Path(f).parts) >= 2 and Path(f).name not in _GENERIC_BASENAMES:
            files.add(f)
    for m in _IDENT_RE.finditer(txt):
        idents.add(m.group(1))
    idents = {i for i in idents if re.search(r"[A-Z]", i) or re.search(r"_(offset|check|guard|mismatch|proof|verify)$", i)}
    # slug tokens (e.g. pharos, optimism, l2oracle) drive the confidence boost
    slug_tokens = {t for t in re.split(r"[-_]", slug.lower()) if len(t) >= 4
                   and t not in ("hyperbridge", "spv", "high", "medium", "critical", "low",
                                 "finding", "output", "v2", "unbound")}
    return {"files": sorted(files), "idents": sorted(idents), "slug_tokens": sorted(slug_tokens)}


def _new_commits(repo: Path, pin: str, head: str) -> list[dict]:
    rc, out, _ = _git(repo, "rev-list", "--reverse", "--format=%H%x1f%ci%x1f%s",
                      f"{pin}..{head}")
    commits = []
    if rc != 0:
        return commits
    for blk in out.split("\n"):
        if blk.startswith("commit "):
            continue
        parts = blk.split("\x1f")
        if len(parts) == 3:
            sha, date, subj = parts
            pr = _PR_RE.search(subj)
            commits.append({"sha": sha[:12], "date": date.split()[0],
                            "subject": subj, "pr": (pr.group(1) if pr else None)})
    return commits


def _commit_files(repo: Path, sha: str) -> list[str]:
    rc, out, _ = _git(repo, "show", "--name-only", "--format=", sha)
    return [l for l in out.splitlines() if l.strip()] if rc == 0 else []


def _commit_adds_guard_near(repo: Path, sha: str, finding_files: set[str], idents: set[str]) -> bool:
    rc, out, _ = _git(repo, "show", sha)
    if rc != 0:
        return False
    added = [l for l in out.splitlines() if l.startswith("+") and not l.startswith("+++")]
    blob = "\n".join(added)
    if any(i in blob for i in idents):
        return True
    return bool(_GUARD_LINE_RE.search(blob))


def monitor(ws: Path, apply: bool, no_fetch: bool) -> dict:
    scope_md = ws / "SCOPE.md"
    assets = _parse_scope(scope_md)
    findings = _open_findings(ws)
    finding_anchor = {str(p): _finding_anchors(p, p.stem) for p in findings}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    report = {"schema": SCHEMA, "workspace": str(ws), "generated_at": now,
              "open_findings": len(findings), "assets": [], "verdict": "clean"}

    any_new, any_possible_fix = False, False

    for a in assets:
        repo = _resolve_repo(ws, a.get("local_path_hint"))
        entry = {"repo_url": a.get("repo_url"), "captured_pin": a["pin"],
                 "local_repo": str(repo) if repo else None}
        if not repo:
            entry["status"] = "no-local-clone"
            report["assets"].append(entry); continue

        fetched = False
        if not no_fetch:
            rc, _, _ = _git(repo, "fetch", "--quiet", "--all", timeout=120)
            fetched = rc == 0
        # upstream ref: prefer origin/HEAD default branch, else local HEAD
        head = None
        for ref in ("origin/main", "origin/master", "origin/HEAD", "HEAD"):
            rc, out, _ = _git(repo, "rev-parse", ref)
            if rc == 0 and out:
                head = out.strip(); head_ref = ref; break
        entry["fetched"] = fetched
        entry["upstream_ref"] = head_ref if head else None
        entry["upstream_head"] = head[:12] if head else None

        # pin reachable?
        rc, _, _ = _git(repo, "cat-file", "-e", a["pin"] + "^{commit}")
        if rc != 0:
            entry["status"] = "pin-unresolvable-in-clone"
            report["assets"].append(entry); continue
        if not head:
            entry["status"] = "no-upstream-ref"
            report["assets"].append(entry); continue

        rc, ahead, _ = _git(repo, "rev-list", "--count", f"{a['pin']}..{head}")
        n_new = int(ahead) if rc == 0 and ahead.isdigit() else 0
        entry["commits_since_pin"] = n_new
        if n_new == 0:
            entry["status"] = "pin-current"
            report["assets"].append(entry); continue

        any_new = True
        commits = _new_commits(repo, a["pin"], head)
        entry["new_commits"] = commits[:200]
        entry["new_prs"] = sorted({c["pr"] for c in commits if c["pr"]}, key=lambda x: int(x))

        # FINDING RE-VERIFICATION
        fix_flags = []
        for fpath, anc in finding_anchor.items():
            ffiles = set(anc["files"]); fidents = set(anc["idents"])
            slug_tokens = set(anc["slug_tokens"])
            if not ffiles:
                continue
            for c in commits:
                touched = _commit_files(repo, c["sha"])
                # full-path suffix match only (no bare-basename collision)
                hit = [tf for tf in touched
                       if any(tf == ff or tf.endswith("/" + ff) or ff.endswith("/" + tf)
                              for ff in ffiles)]
                if not hit:
                    continue
                guardy = _commit_adds_guard_near(repo, c["sha"], ffiles, fidents)
                subj_l = c["subject"].lower()
                slug_match = any(t in subj_l for t in slug_tokens)
                if slug_match and guardy:
                    conf = "high"
                elif slug_match or guardy:
                    conf = "medium"
                else:
                    conf = "low"
                fix_flags.append({
                    "finding": Path(fpath).name, "commit": c["sha"], "pr": c["pr"],
                    "date": c["date"], "subject": c["subject"],
                    "touched_finding_files": hit[:8],
                    "adds_guard_or_ident": guardy, "slug_match": slug_match,
                    "confidence": conf,
                })
        # rank high -> medium -> low; surface the strongest signal first
        fix_flags.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}[f["confidence"]])
        if fix_flags:
            any_possible_fix = True
        entry["possible_upstream_fixes"] = fix_flags

        # NEW ATTACK SURFACE (added / heavily-changed in-scope source files)
        rc, stat, _ = _git(repo, "diff", "--numstat", f"{a['pin']}..{head}")
        surface = []
        if rc == 0:
            for ln in stat.splitlines():
                parts = ln.split("\t")
                if len(parts) == 3:
                    add, dele, path = parts
                    if path.split(".")[-1] in _SRC_EXT and add.isdigit() and int(add) >= 40:
                        surface.append({"file": path, "added": int(add),
                                        "deleted": int(dele) if dele.isdigit() else 0})
        surface.sort(key=lambda x: -x["added"])
        entry["new_attack_surface"] = surface[:40]
        entry["proposed_new_pin"] = head[:40] if head else None
        entry["status"] = "upstream-ahead"

        if apply and head:
            # rewrite the SCOPE.md pin line for this asset's pin
            txt = scope_md.read_text(encoding="utf-8")
            new_txt = txt.replace(a["pin"], head[:40], 1)
            if new_txt != txt:
                scope_md.write_text(new_txt)
                entry["pin_applied"] = head[:40]

        report["assets"].append(entry)

    report["verdict"] = ("possible-stale-finding" if any_possible_fix
                         else "upstream-ahead" if any_new else "clean")

    out_path = ws / ".auditooor" / "audit_pin_monitor.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    report["_out"] = str(out_path)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "-w", required=True, type=Path)
    ap.add_argument("--apply", action="store_true",
                    help="rewrite the SCOPE.md pin line to the upstream HEAD (advance the pin)")
    ap.add_argument("--no-fetch", action="store_true", help="skip git fetch (offline; use local HEAD)")
    ap.add_argument("--show-all", action="store_true",
                    help="print medium/low confidence fix-flags too (default: high only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[audit-pin-monitor] no such workspace: {ws}"); return 2
    rep = monitor(ws, args.apply, args.no_fetch)

    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True)); return 0

    print(f"[audit-pin-monitor] {ws.name}: verdict={rep['verdict']} "
          f"({rep['open_findings']} open findings)")
    for e in rep["assets"]:
        url = (e.get("repo_url") or "?").split("/")[-1]
        st = e.get("status")
        line = f"  - {url}: {st}"
        if e.get("commits_since_pin"):
            line += f" (+{e['commits_since_pin']} commits since pin"
            if e.get("new_prs"):
                line += f", PRs {', '.join('#'+p for p in e['new_prs'][:8])}"
            line += ")"
        print(line)
        flags = e.get("possible_upstream_fixes", [])
        shown = flags if args.show_all else [f for f in flags if f["confidence"] == "high"]
        n_hidden = len(flags) - len(shown)
        for f in shown:
            print(f"      !! POSSIBLE FIX of {f['finding']} -> {f['commit']}"
                  f"{(' (#'+f['pr']+')') if f['pr'] else ''} [{f['confidence']}] "
                  f"{f['subject'][:60]}")
        if n_hidden and not args.show_all:
            print(f"      ({n_hidden} more medium/low-confidence flags hidden; --show-all to see)")
        if e.get("proposed_new_pin") and not e.get("pin_applied"):
            print(f"      proposed new pin: {e['proposed_new_pin'][:12]}  (use --apply to advance)")
        if e.get("pin_applied"):
            print(f"      PIN ADVANCED -> {e['pin_applied'][:12]}")
        if e.get("new_attack_surface"):
            print(f"      new attack surface: {len(e['new_attack_surface'])} changed src files "
                  f"(top: {e['new_attack_surface'][0]['file']} +{e['new_attack_surface'][0]['added']})")
    print(f"  -> {rep['_out']}")
    return 1 if rep["verdict"] == "possible-stale-finding" else 0


if __name__ == "__main__":
    raise SystemExit(main())
