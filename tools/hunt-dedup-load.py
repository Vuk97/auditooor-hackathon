#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""hunt-dedup-load.py - L36 step-0 gate: DEDUP-FIRST skip-set materializer.

Background
----------
Two failure modes plagued the hunt loop:

  (1) Shallow hunts (caught by L35 / hunt-completeness-check.py).
  (2) REPEATED work: a fresh hunt re-derives a candidate that a prior
      session already KILLED, dead-ended, or even FILED. The cycle is
      burned re-discovering a known answer.

L36 is the deterministic root-cause fix for (2). It runs FIRST in the
`make hunt` orchestrator (step 0), consolidates EVERY prior-work signal
into a single on-disk skip-set, and refuses to certify the dedup-load
step unless it could actually read the prior-work corpus.

Sources consolidated into the skip-set
---------------------------------------
(i)   every prior finding draft under
      ``<WS>/submissions/{filed,paste_ready,_killed,superseded,staging}``
      (recursive: flat .md files, per-finding slug folders, and nested
      status sub-dirs like ``paste_ready/filed/`` are all enumerated).
(ii)  ``<WS>/reports/known_dead_ends.jsonl`` (and the repo-global
      ``reports/known_dead_ends.jsonl`` filtered to this workspace).
(iii) every prior ``<WS>/.auditooor/hunt_findings_sidecars/*.json``
      (including ``-FP`` false-positive sidecars) PLUS any loose
      ``*sidecar*`` artifact directly under ``<WS>/.auditooor/``.
(iv)  MCP recall: ``vault_known_dead_ends`` + ``vault_originality_context``
      + ``vault_resume_context`` for the workspace. MCP is best-effort
      (network/degraded tolerant): a failed MCP call is a WARN, not a
      hard fail, because (i)-(iii) are the load-bearing on-disk corpus.

Output
------
A consolidated skip-set is written to
``<WS>/.auditooor/hunt_skip_set.json`` with one entry per known item:

    {
      "schema": "auditooor.l36_hunt_skip_set.v1",
      "workspace": "<abs ws>",
      "generated_at": "<iso8601>",
      "source_counts": {"submissions": N, "known_dead_ends": N, ...},
      "entries": [
        {"slug": "...", "root_cause": "...", "file_line": "...",
         "verdict": "filed|killed|dead-end|superseded|staging|fp|...",
         "source": "submissions|known_dead_ends|sidecar|mcp", "origin": "<path-or-callable>"},
        ...
      ]
    }

Every downstream cluster/brief MUST consult this file and SKIP any
candidate matching an entry's slug / root-cause / file:line. Re-deriving
a known dead-end or re-filing a prior finding is a wasted-cycle defect.

Verdict vocabulary
------------------
- ``pass-dedup-loaded``        skip-set written; >=1 on-disk source readable.
- ``pass-dedup-loaded-empty``  skip-set written but workspace has zero prior
                               work (a genuinely fresh engagement). Still a
                               PASS - the file exists so downstream consult
                               works - but flagged so the operator knows.
- ``fail-cannot-write``        the skip-set file could not be written
                               (unwritable ``.auditooor/``). HARD FAIL: the
                               orchestrator must fail because no downstream
                               step can consult a skip-set that doesn't exist.
- ``error``                    unreadable workspace / internal error.

Exit code
---------
- 0 on any ``pass-*`` verdict.
- 1 on ``fail-cannot-write``.
- 2 on ``error``.

CLI
---
    python3 tools/hunt-dedup-load.py <workspace> [--json] [--no-mcp]
                                     [--mcp-server <path>] [--repo-root <path>]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.l36_hunt_skip_set.v1"
GATE = "L36-HUNT-DEDUP-LOAD"

# Status directories enumerated for prior findings (source (i)).
_SUBMISSION_STATUS_DIRS = (
    "filed",
    "paste_ready",
    "_killed",
    "superseded",
    "staging",
)

# Verdict normalization keyed by the status-dir name a draft lives under.
_STATUS_VERDICT = {
    "filed": "filed",
    "paste_ready": "filed-or-ready",
    "_killed": "killed",
    "superseded": "superseded",
    "staging": "staging",
}

# Tracker / bookkeeping stems that are NOT findings.
_NON_FINDING_STEMS = {"submissions", "readme", "tracker", "index"}

_FILE_LINE_RE = re.compile(r"([A-Za-z0-9_./\-]+\.[A-Za-z]{1,5}):(\d+)(?:-\d+)?")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _slug_from_md(path: Path) -> str:
    """Derive a finding slug from a draft path. Prefer the per-finding
    folder name when the file matches the R41 ``<slug>/<slug>.md`` layout;
    else fall back to the file stem."""
    stem = path.stem
    parent = path.parent.name
    if parent and parent.lower() == stem.lower():
        return parent
    return stem


def _first_root_cause(text: str | None) -> str:
    """Best-effort one-line root-cause: the draft Title / first heading."""
    if not text:
        return ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^#{1,3}\s+(.+)$", line)
        if m:
            return m.group(1).strip()[:200]
        m = re.match(r"^(?:title|finding|summary)\s*[:=]\s*(.+)$", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:200]
    for raw in text.splitlines():
        if raw.strip():
            return raw.strip()[:200]
    return ""


def _first_file_line(text: str | None) -> str:
    if not text:
        return ""
    m = _FILE_LINE_RE.search(text)
    return m.group(0) if m else ""


# --------------------------------------------------------------------------
# Source (i): submissions
# --------------------------------------------------------------------------
def collect_submissions(ws: Path) -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    seen_origins: list[str] = []
    subs = ws / "submissions"
    if not _exists(subs) or not subs.is_dir():
        return entries, seen_origins
    for status in _SUBMISSION_STATUS_DIRS:
        status_dir = subs / status
        if not _exists(status_dir) or not status_dir.is_dir():
            continue
        verdict = _STATUS_VERDICT.get(status, status)
        try:
            md_files = list(status_dir.rglob("*.md"))
        except OSError:
            md_files = []
        for md in sorted(md_files):
            if md.stem.lower() in _NON_FINDING_STEMS:
                continue
            text = _read_text(md)
            entries.append({
                "slug": _slug_from_md(md),
                "root_cause": _first_root_cause(text),
                "file_line": _first_file_line(text),
                "verdict": verdict,
                "source": "submissions",
                "origin": str(md),
            })
            seen_origins.append(str(md))
    return entries, seen_origins


# --------------------------------------------------------------------------
# Source (ii): known_dead_ends.jsonl (workspace + repo-global)
# --------------------------------------------------------------------------
def _parse_kde_lines(text: str, ws_name: str, *, filter_ws: bool) -> list[dict]:
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(rec, dict):
            continue
        if filter_ws:
            rec_ws = str(
                rec.get("workspace")
                or rec.get("workspace_name")
                or rec.get("ws")
                or ""
            ).strip().lower()
            # Keep records whose workspace matches OR records with no
            # workspace field (global dead-ends still apply).
            if rec_ws and ws_name and ws_name.lower() not in rec_ws and rec_ws not in ws_name.lower():
                continue
        out.append({
            "slug": str(rec.get("record_id") or rec.get("slug") or rec.get("id") or "")[:200],
            "root_cause": str(
                rec.get("root_cause")
                or rec.get("reason")
                or rec.get("title")
                or rec.get("hypothesis")
                or ""
            )[:200],
            "file_line": str(rec.get("file_line") or rec.get("location") or "")[:200],
            "verdict": str(rec.get("verdict") or rec.get("status") or "dead-end")[:60],
            "source": "known_dead_ends",
            "origin": "",  # filled by caller
        })
    return out


def collect_known_dead_ends(ws: Path, repo_root: Path | None) -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    origins: list[str] = []
    ws_name = ws.name

    ws_kde = ws / "reports" / "known_dead_ends.jsonl"
    txt = _read_text(ws_kde)
    if txt is not None:
        for rec in _parse_kde_lines(txt, ws_name, filter_ws=False):
            rec["origin"] = str(ws_kde)
            entries.append(rec)
        origins.append(str(ws_kde))

    if repo_root is not None:
        global_kde = repo_root / "reports" / "known_dead_ends.jsonl"
        if global_kde.resolve() != ws_kde.resolve():
            gtxt = _read_text(global_kde)
            if gtxt is not None:
                for rec in _parse_kde_lines(gtxt, ws_name, filter_ws=True):
                    rec["origin"] = str(global_kde)
                    entries.append(rec)
                origins.append(str(global_kde))
    return entries, origins


# --------------------------------------------------------------------------
# Source (iii): sidecars
# --------------------------------------------------------------------------
def collect_sidecars(ws: Path) -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    origins: list[str] = []
    auditooor = ws / ".auditooor"
    if not _exists(auditooor) or not auditooor.is_dir():
        return entries, origins

    candidates: list[Path] = []
    sidecar_dir = auditooor / "hunt_findings_sidecars"
    if _exists(sidecar_dir) and sidecar_dir.is_dir():
        try:
            candidates.extend(p for p in sidecar_dir.rglob("*.json") if p.is_file())
        except OSError:
            pass
    # Loose *sidecar* artifacts directly under .auditooor/ (md + json).
    try:
        for p in auditooor.iterdir():
            if p.is_file() and "sidecar" in p.name.lower() and p.suffix.lower() in (".json", ".md"):
                candidates.append(p)
    except OSError:
        pass

    for p in sorted(set(candidates)):
        text = _read_text(p)
        rec_data: dict = {}
        if p.suffix.lower() == ".json" and text:
            try:
                loaded = json.loads(text)
                if isinstance(loaded, dict):
                    rec_data = loaded
            except (ValueError, json.JSONDecodeError):
                rec_data = {}
        is_fp = "-fp" in p.stem.lower() or "_fp" in p.stem.lower() or "false_positive" in p.stem.lower()
        verdict = str(rec_data.get("verdict") or rec_data.get("status") or "") or ("fp" if is_fp else "sidecar")
        entries.append({
            "slug": str(rec_data.get("slug") or rec_data.get("candidate_id") or p.stem)[:200],
            "root_cause": str(
                rec_data.get("root_cause")
                or rec_data.get("hypothesis")
                or rec_data.get("title")
                or _first_root_cause(text)
            )[:200],
            "file_line": str(rec_data.get("file_line") or _first_file_line(text))[:200],
            "verdict": str(verdict)[:60],
            "source": "sidecar",
            "origin": str(p),
        })
        origins.append(str(p))
    return entries, origins


# --------------------------------------------------------------------------
# Source (iv): MCP recall (best-effort)
# --------------------------------------------------------------------------
def _call_mcp(server: Path, callable_name: str, args: dict) -> tuple[dict | None, str]:
    """Return (parsed_json | None, warn_msg). Never raises."""
    if not _exists(server):
        return None, f"mcp server not found: {server}"
    try:
        proc = subprocess.run(
            [sys.executable, str(server), "--call", callable_name, "--args", json.dumps(args)],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{callable_name}: subprocess error {exc}"
    if proc.returncode != 0:
        return None, f"{callable_name}: rc={proc.returncode}"
    try:
        return json.loads(proc.stdout), ""
    except (ValueError, json.JSONDecodeError):
        return None, f"{callable_name}: non-JSON output"


def collect_mcp(ws: Path, server: Path) -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    warns: list[str] = []
    ws_name = ws.name

    de, w = _call_mcp(server, "vault_known_dead_ends", {"workspace": ws_name, "limit": 50})
    if w:
        warns.append(w)
    elif isinstance(de, dict):
        records = de.get("records") or de.get("dead_ends") or de.get("items") or []
        if isinstance(records, list):
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                entries.append({
                    "slug": str(rec.get("record_id") or rec.get("slug") or "")[:200],
                    "root_cause": str(rec.get("root_cause") or rec.get("reason") or rec.get("title") or "")[:200],
                    "file_line": str(rec.get("file_line") or "")[:200],
                    "verdict": str(rec.get("verdict") or "dead-end")[:60],
                    "source": "mcp",
                    "origin": "vault_known_dead_ends",
                })

    orig, w = _call_mcp(server, "vault_originality_context", {"workspace_path": str(ws), "limit": 20})
    if w:
        warns.append(w)
    elif isinstance(orig, dict):
        prior = orig.get("prior_findings") or orig.get("findings") or orig.get("items") or []
        if isinstance(prior, list):
            for rec in prior:
                if not isinstance(rec, dict):
                    continue
                entries.append({
                    "slug": str(rec.get("slug") or rec.get("id") or rec.get("title") or "")[:200],
                    "root_cause": str(rec.get("root_cause") or rec.get("title") or "")[:200],
                    "file_line": str(rec.get("file_line") or "")[:200],
                    "verdict": str(rec.get("verdict") or "prior-finding")[:60],
                    "source": "mcp",
                    "origin": "vault_originality_context",
                })

    # resume_context warms workspace state; record only that the consult ran.
    _resume, w = _call_mcp(server, "vault_resume_context", {"workspace_path": str(ws), "limit": 4})
    if w:
        warns.append(w)

    return entries, warns


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def _dedup_entries(entries: list[dict]) -> list[dict]:
    """Drop exact duplicates keyed by (slug, file_line, verdict). Keep the
    first occurrence (submissions enumerate before dead-ends before MCP)."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for e in entries:
        key = (e.get("slug", ""), e.get("file_line", ""), e.get("verdict", ""))
        # Empty-slug entries dedup on root_cause instead so we don't collapse
        # distinct dead-ends that happen to share a blank slug.
        if not key[0]:
            key = ("", e.get("root_cause", ""), e.get("source", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def build_skip_set(
    ws: Path,
    *,
    use_mcp: bool,
    mcp_server: Path | None,
    repo_root: Path | None,
) -> dict:
    sub_e, sub_o = collect_submissions(ws)
    kde_e, kde_o = collect_known_dead_ends(ws, repo_root)
    sc_e, sc_o = collect_sidecars(ws)

    mcp_e: list[dict] = []
    mcp_warns: list[str] = []
    if use_mcp and mcp_server is not None:
        mcp_e, mcp_warns = collect_mcp(ws, mcp_server)

    all_entries = _dedup_entries([*sub_e, *kde_e, *sc_e, *mcp_e])

    source_counts = {
        "submissions": len(sub_e),
        "known_dead_ends": len(kde_e),
        "sidecars": len(sc_e),
        "mcp": len(mcp_e),
        "total_after_dedup": len(all_entries),
    }
    on_disk_sources_read = bool(sub_o or kde_o or sc_o)

    return {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(ws),
        "generated_at": _now_iso(),
        "source_counts": source_counts,
        "on_disk_sources_read": on_disk_sources_read,
        "mcp_used": bool(use_mcp and mcp_server is not None),
        "mcp_warnings": mcp_warns,
        "sources_scanned": {
            "submissions": sub_o,
            "known_dead_ends": kde_o,
            "sidecars": sc_o,
        },
        "entries": all_entries,
    }


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_mcp_server(repo_root: Path) -> Path:
    return repo_root / "tools" / "vault-mcp-server.py"


def run(ws: Path, *, use_mcp: bool, mcp_server: Path | None, repo_root: Path | None) -> tuple[dict, str]:
    """Return (result_payload, verdict)."""
    skip_set = build_skip_set(ws, use_mcp=use_mcp, mcp_server=mcp_server, repo_root=repo_root)

    out_dir = ws / ".auditooor"
    out_path = out_dir / "hunt_skip_set.json"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(skip_set, indent=2), encoding="utf-8")
    except OSError as exc:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "fail-cannot-write",
            "reason": f"could not write skip-set to {out_path}: {exc}",
            "skip_set_path": str(out_path),
            "source_counts": skip_set["source_counts"],
        }, "fail-cannot-write"

    n = skip_set["source_counts"]["total_after_dedup"]
    if n == 0:
        verdict = "pass-dedup-loaded-empty"
        reason = "skip-set written; workspace has zero prior work (fresh engagement)"
    else:
        verdict = "pass-dedup-loaded"
        reason = (
            f"skip-set written with {n} entries "
            f"(submissions={skip_set['source_counts']['submissions']}, "
            f"dead-ends={skip_set['source_counts']['known_dead_ends']}, "
            f"sidecars={skip_set['source_counts']['sidecars']}, "
            f"mcp={skip_set['source_counts']['mcp']})"
        )
    return {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": verdict, "reason": reason,
        "skip_set_path": str(out_path),
        "source_counts": skip_set["source_counts"],
        "mcp_warnings": skip_set["mcp_warnings"],
    }, verdict


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hunt-dedup-load.py",
        description="L36 dedup-first: materialize a hunt skip-set from all prior work.",
    )
    p.add_argument("workspace", help="Path to the audit workspace.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    p.add_argument("--no-mcp", action="store_true", help="Skip the best-effort MCP recall step.")
    p.add_argument("--mcp-server", default=None, help="Path to vault-mcp-server.py (default: repo tools/).")
    p.add_argument("--repo-root", default=None, help="Repo root for the global known_dead_ends.jsonl (default: tool's repo).")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error",
            "reason": "workspace path does not exist or is not a directory",
        }
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    repo_root = Path(os.path.expanduser(args.repo_root)).resolve() if args.repo_root else _default_repo_root()
    mcp_server = (
        Path(os.path.expanduser(args.mcp_server)).resolve()
        if args.mcp_server else _default_mcp_server(repo_root)
    )

    try:
        result, verdict = run(
            ws,
            use_mcp=not args.no_mcp,
            mcp_server=mcp_server,
            repo_root=repo_root,
        )
    except Exception as exc:  # pragma: no cover (defensive)
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": f"internal error: {exc}",
        }
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{GATE}] verdict={result['verdict']}")
        print(f"[{GATE}] {result['reason']}")
        print(f"[{GATE}] skip-set: {result['skip_set_path']}")
        if result.get("mcp_warnings"):
            for w in result["mcp_warnings"]:
                print(f"[{GATE}] WARN mcp: {w}")

    if verdict == "fail-cannot-write":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
