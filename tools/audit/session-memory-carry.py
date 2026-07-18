#!/usr/bin/env python3
"""session-memory-carry.py — carry an audit session's learnings forward.

Background
----------
Every audit session re-derives context. The MCP vault has recall callables
(``vault_resume_context``) but there is no clean "carry forward what THIS
session learned" path. Concretely, a session produces several kinds of
delta that the next session needs but cannot reliably recover:

  * NEGATIVE verdicts        — lanes hunted, found nothing; the next session
                               must NOT re-hunt them.
  * Dropped-lane reasons     — lanes deferred / dropped (DOS-class, OOS,
                               structural-blocker) with the reason.
  * Harness deltas           — fixes / new tools / new gates landed this
                               session.
  * Lane-cooldown state      — which lanes are on cooldown and until when.

These live scattered across ``agent_outputs/*verdict*.md``,
``.auditooor/deferred_l17_lanes.json``, ``.auditooor/gate-status/*DROPPED*``,
``.auditooor/commit_lifecycle_ledger.json`` — none of which is a structured,
resume-pack-readable artifact. The next session's ``vault_resume_context``
reads ``INDEX_active.md`` / ``NEXT_LOOP.md`` / ``goals/current.md`` /
``session-memory/*.md`` — so a session's learnings leak unless they are
consolidated into one of those.

What this tool does
-------------------
At session end, scan the workspace for the four delta classes above, build a
structured ``auditooor.session_memory_carry.v1`` artifact, and route it into
the vault-sync path so the NEXT session's ``vault_resume_context`` picks it up.

Two outputs (both reuse existing registration points — no parallel path):

  1. ``<workspace>/.auditooor/session_memory_carry.json``
     The canonical structured artifact. Registered in
     ``obsidian-vault-sync.py`` ``SECTION_SOURCES["session-memory"]`` so an
     incremental sync detects it as stale and re-emits.

  2. ``<vault>/session-memory/<workspace-slug>.md``
     A vault note. ``vault_resume_context`` default paths now include
     ``session-memory/<slug>.md`` patterns, so the next resume pack reads it.

Usage
-----
    python3 tools/audit/session-memory-carry.py --workspace ~/audits/dydx
    python3 tools/audit/session-memory-carry.py --workspace ~/audits/dydx \\
        --vault-dir obsidian-vault --json
    python3 tools/audit/session-memory-carry.py --workspace ~/audits/dydx \\
        --dry-run

Design notes
------------
- stdlib-only, offline-safe, never calls a live LLM or the network.
- Idempotent: re-running on an unchanged workspace produces a byte-identical
  artifact (timestamps excluded from the content hash).
- Read-only against the workspace except for the single
  ``.auditooor/session_memory_carry.json`` write and the vault note.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.session_memory_carry.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"

# Bounds — keep the carried artifact small enough for a resume pack.
MAX_NEGATIVE = 40
MAX_DROPPED = 40
MAX_HARNESS = 30
MAX_COOLDOWN = 30
MAX_TEXT = 320


def _now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "workspace"


def _clip(text: str, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --- delta collectors -------------------------------------------------------

# Markdown files whose name signals a NEGATIVE / dropped verdict.
_NEGATIVE_NAME_RE = re.compile(
    r"(negative|drop(ped)?|verdict|cooldown|oos)", re.IGNORECASE
)
_DROP_BODY_RE = re.compile(
    r"\b(DROP(PED)?(-[A-Z-]+)?|NEGATIVE|OOS|DUPLICATE|SUPERSEDED)\b"
)
_COOLDOWN_RE = re.compile(r"cooldown", re.IGNORECASE)


def _first_match_line(text: str, pattern: re.Pattern) -> str:
    """Return the first text line containing a pattern match (clipped)."""
    for line in text.splitlines():
        if pattern.search(line):
            stripped = line.strip().lstrip("#-* ").strip()
            if stripped:
                return _clip(stripped)
    return ""


def collect_negative_verdicts(ws: Path) -> list[dict]:
    """NEGATIVE-verdict lanes — lanes hunted that found nothing.

    Sources: agent_outputs/*verdict*.md, scope_review/*review*.md whose body
    carries a DROP/NEGATIVE marker.
    """
    out: list[dict] = []
    seen: set[str] = set()
    candidate_dirs = [ws / "agent_outputs", ws / "scope_review"]
    for d in candidate_dirs:
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*.md")):
            name = md.name
            body = _read_text(md)
            name_hit = _NEGATIVE_NAME_RE.search(name)
            body_hit = _DROP_BODY_RE.search(body)
            if not (name_hit and body_hit):
                continue
            if name in seen:
                continue
            seen.add(name)
            out.append(
                {
                    "lane": _clip(md.stem, 120),
                    "verdict_marker": _clip(body_hit.group(0), 60),
                    "reason": _first_match_line(body, _DROP_BODY_RE),
                    "source_ref": f"workspace://{md.relative_to(ws).as_posix()}",
                }
            )
            if len(out) >= MAX_NEGATIVE:
                break
    return out[:MAX_NEGATIVE]


def collect_dropped_lanes(ws: Path) -> list[dict]:
    """Dropped / deferred lanes with their reasons.

    Sources: .auditooor/deferred_l17_lanes.json, .auditooor/gate-status/*DROPPED*
    """
    out: list[dict] = []
    deferred = ws / ".auditooor" / "deferred_l17_lanes.json"
    payload = _read_json(deferred)
    if isinstance(payload, dict):
        lanes = payload.get("lanes")
        if isinstance(lanes, list):
            for lane in lanes:
                if not isinstance(lane, dict):
                    continue
                out.append(
                    {
                        "lane_id": _clip(str(lane.get("lane_id", "")), 120),
                        "status": _clip(str(lane.get("status", "")), 160),
                        "source_ref": "workspace://.auditooor/deferred_l17_lanes.json",
                    }
                )
                if len(out) >= MAX_DROPPED:
                    return out
    gate_dir = ws / ".auditooor" / "gate-status"
    if gate_dir.is_dir():
        for gs in sorted(gate_dir.glob("*DROPPED*")):
            out.append(
                {
                    "lane_id": _clip(gs.stem, 120),
                    "status": "gate-status:DROPPED",
                    "source_ref": (
                        f"workspace://.auditooor/gate-status/{gs.name}"
                    ),
                }
            )
            if len(out) >= MAX_DROPPED:
                break
    return out[:MAX_DROPPED]


def collect_harness_deltas(ws: Path) -> list[dict]:
    """Harness fixes / new tooling landed during this session.

    Sources: the engagement's commit_lifecycle_ledger.json (entries tagged as
    harness/tooling), plus any docs/next-loop note in the workspace.
    """
    out: list[dict] = []
    ledger = ws / ".auditooor" / "commit_lifecycle_ledger.json"
    payload = _read_json(ledger)
    rows: list = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("commits", "entries", "harness_deltas", "items"):
            v = payload.get(key)
            if isinstance(v, list):
                rows = v
                break
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or row.get("type") or "").lower()
        title = row.get("title") or row.get("summary") or row.get("message") or ""
        if "harness" in kind or "tool" in kind or "gate" in kind:
            out.append(
                {
                    "summary": _clip(str(title)),
                    "sha": _clip(str(row.get("sha", "")), 40),
                    "source_ref": (
                        "workspace://.auditooor/commit_lifecycle_ledger.json"
                    ),
                }
            )
            if len(out) >= MAX_HARNESS:
                return out
    return out[:MAX_HARNESS]


def collect_lane_cooldowns(ws: Path) -> list[dict]:
    """Lane-cooldown state — lanes recently DROPPED that should be skipped.

    Sources: any .auditooor/*.json carrying a cooldown structure, and the
    dropped-lane set itself (a DROPPED lane is implicitly on cooldown).
    """
    out: list[dict] = []
    seen: set[str] = set()
    audit_dir = ws / ".auditooor"
    if audit_dir.is_dir():
        for jf in sorted(audit_dir.glob("*.json")):
            if not _COOLDOWN_RE.search(jf.name) and "cooldown" not in _read_text(
                jf
            ).lower():
                continue
            payload = _read_json(jf)
            if not isinstance(payload, dict):
                continue
            cd = payload.get("cooldowns") or payload.get("lane_cooldowns")
            if isinstance(cd, list):
                for entry in cd:
                    if not isinstance(entry, dict):
                        continue
                    lane = str(entry.get("lane_id") or entry.get("lane", ""))
                    if not lane or lane in seen:
                        continue
                    seen.add(lane)
                    out.append(
                        {
                            "lane_id": _clip(lane, 120),
                            "cooldown_until": _clip(
                                str(
                                    entry.get("cooldown_until")
                                    or entry.get("until", "")
                                ),
                                40,
                            ),
                            "source_ref": (
                                f"workspace://.auditooor/{jf.name}"
                            ),
                        }
                    )
                    if len(out) >= MAX_COOLDOWN:
                        return out
    return out[:MAX_COOLDOWN]


# --- artifact build ---------------------------------------------------------


def build_artifact(ws: Path, session_id: str | None = None) -> dict:
    negative = collect_negative_verdicts(ws)
    dropped = collect_dropped_lanes(ws)
    harness = collect_harness_deltas(ws)
    cooldowns = collect_lane_cooldowns(ws)

    content = {
        "schema": SCHEMA,
        "workspace": ws.name,
        "negative_verdicts": negative,
        "dropped_lanes": dropped,
        "harness_deltas": harness,
        "lane_cooldowns": cooldowns,
        "summary": {
            "negative_verdicts": len(negative),
            "dropped_lanes": len(dropped),
            "harness_deltas": len(harness),
            "lane_cooldowns": len(cooldowns),
        },
    }
    # Content hash excludes generated/session-id so re-runs on an unchanged
    # workspace are idempotent.
    digest = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    artifact = dict(content)
    artifact["generated"] = _now()
    artifact["session_id"] = session_id or f"session:{digest[:16]}"
    artifact["content_hash"] = digest
    return artifact


# --- vault note rendering ---------------------------------------------------


def render_vault_note(artifact: dict) -> str:
    ws = artifact["workspace"]
    s = artifact["summary"]
    fm = [
        "---",
        f"title: Session Memory Carry — {ws}",
        f"generated: {artifact['generated']}",
        f"schema: {SCHEMA}",
        f"session_id: {artifact['session_id']}",
        f"content_hash: {artifact['content_hash']}",
        "status: active",
        "tags: [session-memory/carry, resume/context]",
        "---",
        "",
    ]
    body = [
        f"# Session Memory Carry — {ws}",
        "",
        f"_Generated: {artifact['generated']}_ — carry-forward artifact for "
        "the next `vault_resume_context`.",
        "",
        "## Carry Summary",
        "",
        "| Delta class | Count |",
        "|-------------|-------|",
        f"| NEGATIVE verdicts (do NOT re-hunt) | {s['negative_verdicts']} |",
        f"| Dropped / deferred lanes | {s['dropped_lanes']} |",
        f"| Harness deltas this session | {s['harness_deltas']} |",
        f"| Lanes on cooldown | {s['lane_cooldowns']} |",
        "",
    ]
    if artifact["negative_verdicts"]:
        body += ["## NEGATIVE Verdicts — do NOT re-hunt", ""]
        for n in artifact["negative_verdicts"]:
            reason = f" — {n['reason']}" if n.get("reason") else ""
            body.append(f"- **{n['lane']}** [{n['verdict_marker']}]{reason}")
        body.append("")
    if artifact["dropped_lanes"]:
        body += ["## Dropped / Deferred Lanes", ""]
        for d in artifact["dropped_lanes"]:
            body.append(f"- **{d['lane_id']}** — {d['status']}")
        body.append("")
    if artifact["harness_deltas"]:
        body += ["## Harness Deltas (landed this session)", ""]
        for h in artifact["harness_deltas"]:
            sha = f" `{h['sha']}`" if h.get("sha") else ""
            body.append(f"- {h['summary']}{sha}")
        body.append("")
    if artifact["lane_cooldowns"]:
        body += ["## Lane Cooldowns — skip until expiry", ""]
        for c in artifact["lane_cooldowns"]:
            until = f" (until {c['cooldown_until']})" if c.get("cooldown_until") else ""
            body.append(f"- **{c['lane_id']}**{until}")
        body.append("")
    body += [
        "## Resume Discipline",
        "",
        "- Treat every NEGATIVE-verdict lane above as closed; re-hunting it "
        "is wasted budget unless its trigger-state changed.",
        "- Dropped/deferred lanes carry their reason — re-open only if the "
        "named structural blocker is resolved.",
        "- Lanes on cooldown must be skipped until the listed expiry "
        "(Rule A1 cooldown discipline).",
        "",
    ]
    return "\n".join(fm + body) + "\n"


# --- write path -------------------------------------------------------------


def write_outputs(
    artifact: dict, ws: Path, vault: Path, dry_run: bool
) -> dict:
    """Write the workspace artifact + the vault note. Returns paths written."""
    written: dict[str, str] = {}

    artifact_path = ws / ".auditooor" / "session_memory_carry.json"
    note_rel = f"session-memory/{_slug(artifact['workspace'])}.md"
    note_path = vault / note_rel

    if not dry_run:
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(render_vault_note(artifact), encoding="utf-8")

    written["workspace_artifact"] = str(artifact_path)
    written["vault_note"] = str(note_path)
    written["vault_note_relpath"] = note_rel
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Carry an audit session's learnings forward into the "
        "vault so the next vault_resume_context picks them up."
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Audit workspace (e.g. ~/audits/dydx)",
    )
    parser.add_argument(
        "--sync-all-workspaces",
        action="store_true",
        help="Refresh the session-memory note for every ~/audits/<ws> that "
        "already has a .auditooor/session_memory_carry.json (vault-sync path)",
    )
    parser.add_argument(
        "--vault-dir",
        type=Path,
        default=VAULT_DEFAULT,
        help="Vault directory (default: obsidian-vault/ in repo root)",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Optional explicit session id (default: derived from content hash)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the artifact as JSON on stdout",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the artifact but write nothing",
    )
    args = parser.parse_args(argv)

    vault = args.vault_dir.expanduser().resolve()

    # --sync-all-workspaces: vault-sync batch path. Refresh every workspace
    # that already carried a session — used by obsidian-vault-sync.py.
    if args.sync_all_workspaces:
        audits_root = Path.home() / "audits"
        refreshed = 0
        for carry in sorted(audits_root.glob("*/.auditooor/session_memory_carry.json")):
            ws_dir = carry.parents[1]
            art = build_artifact(ws_dir, session_id=args.session_id)
            write_outputs(art, ws_dir, vault, args.dry_run)
            refreshed += 1
        print(f"[session-memory-carry] sync-all: {refreshed} workspace note(s) refreshed")
        # Emit a count line obsidian-vault-sync.py's regex can parse.
        print(f"TOTAL notes: {refreshed}")
        return 0

    if args.workspace is None:
        print(
            "[session-memory-carry] ERR --workspace required "
            "(or use --sync-all-workspaces)",
            file=sys.stderr,
        )
        return 2

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[session-memory-carry] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    artifact = build_artifact(ws, session_id=args.session_id)
    written = write_outputs(artifact, ws, vault, args.dry_run)

    if args.json:
        print(json.dumps({"artifact": artifact, "written": written}, indent=2))
    else:
        s = artifact["summary"]
        print("[session-memory-carry]")
        print(f"  workspace:        {ws.name}")
        print(f"  session_id:       {artifact['session_id']}")
        print(f"  content_hash:     {artifact['content_hash'][:16]}")
        print(f"  negative verdicts: {s['negative_verdicts']}")
        print(f"  dropped lanes:     {s['dropped_lanes']}")
        print(f"  harness deltas:    {s['harness_deltas']}")
        print(f"  lane cooldowns:    {s['lane_cooldowns']}")
        if args.dry_run:
            print("  (--dry-run: nothing written)")
        else:
            print(f"  artifact:         {written['workspace_artifact']}")
            print(f"  vault note:       {written['vault_note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
