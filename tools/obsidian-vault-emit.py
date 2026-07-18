#!/usr/bin/env python3
"""obsidian-vault-emit.py — Build the Obsidian shared-memory vault for auditooor.

Reads all canonical sources (read-only) and emits structured Markdown notes
into obsidian-vault/ with Dataview-compatible YAML frontmatter + wikilinks.

Usage:
    python3 tools/obsidian-vault-emit.py [--vault-dir <path>] [--limit <n>]
    python3 tools/obsidian-vault-emit.py --dry-run          # stats only, no writes
    python3 tools/obsidian-vault-emit.py --section patterns # only one section

Sources read:
  - detectors/_tier_registry.yaml
  - reference/patterns.dsl/*.yaml + r{73-94}_* rounds
  - reference/corpus_mined/*.md
  - reference/contest_cache/
  - ~/audits/<ws>/submissions/ + .auditooor/
  - docs/KNOWN_LIMITATIONS.md + KNOWN_LIMITATIONS_BURNDOWN_MAP.json
  - docs/CONTINUATION_PLAN.md
  - ~/.claude/.../memory/MEMORY.md
  - /private/tmp/auditooor-inventory/ (mining progress)

Output layout:
  obsidian-vault/
    INDEX.md
    patterns/<id>.md
    detectors/<wave>/<id>.md
    findings/<ws>/<id>.md
    workspaces/<ws>.md
    goals/current.md
    mining/<source>.md
    limitations/<id>.md
    tasks/<status>/<id>.md
    agent-memory/<file>.md
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Repo layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
AUDITS_ROOT = Path.home() / "audits"
MEMORY_PATH = (
    Path.home()
    / ".claude"
    / "projects"
    / "-Users-wolf-Downloads-GTO-WEBSITE-proper-installation-polymarket-clob2"
    / "memory"
    / "MEMORY.md"
)
INVENTORY_DIR = Path("/private/tmp/auditooor-inventory")

KNOWN_WORKSPACES = [
    "base-azul",
    "centrifuge-v3",
    "morpho",
    "polymarket",
    "k2",
    "kiln-v1",
    "monetrix",
    "revert-stableswap-hooks",
    "snowbridge",
    "thegraph",
]

# ---------------------------------------------------------------------------
# Byte cap (10MB guard)
# ---------------------------------------------------------------------------
TOTAL_BYTE_CAP = 18 * 1024 * 1024  # raised for deep ingestors
_bytes_written = 0

SECRET_PATTERNS = [
    re.compile(r"(?i)(private[_\s]?key|mnemonic|seed[_\s]?phrase|clob[_\s]?cred|api[_\s]?secret)[^\n]*"),
    re.compile(r"\b(?:sk|xai|ak)[_-][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b0x[0-9a-fA-F]{64,}\b"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    """Convert arbitrary text to a filesystem-safe slug."""
    text = re.sub(r"[^\w\s-]", "", text.lower())
    text = re.sub(r"[\s_]+", "-", text)
    text = text.strip("-")
    return text[:100]


def _now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _read_yaml(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            data = yaml.safe_load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _highest_pr_number_from_docs(docs_dir: Path) -> int:
    highest = 0
    pr_ref = re.compile(r"\b(?:PR|pull request)\s*#(\d{3,4})\b", re.IGNORECASE)
    for doc in docs_dir.rglob("*.md"):
        text = _read_text(doc)
        for n in pr_ref.findall(text):
            highest = max(highest, int(n))
    return highest


def _highest_merged_pr_number() -> int:
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", "--pretty=%s%n%b", "-n", "200"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return 0
    if proc.returncode != 0:
        return 0
    highest = 0
    for n in re.findall(r"\b(?:Merge pull request|Merged PR)\s+#(\d{3,})\b", proc.stdout):
        highest = max(highest, int(n))
    return highest


def _truncate_on_line_boundary(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text.rstrip()
    clipped = text[:max_chars]
    clipped = clipped.rsplit("\n", 1)[0].rstrip()
    if not clipped:
        clipped = text[:max_chars].rstrip()
    return f"{clipped}\n\n_(truncated)_"


def _redact_text(text: str) -> tuple[str, int]:
    count = 0
    for pattern in SECRET_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            count += len(matches)
            text = pattern.sub("[REDACTED]", text)
    return text, count


def _write_note(vault: Path, rel: str, content: str, dry_run: bool = False) -> bool:
    """Write a note, enforcing the total byte cap. Returns True if written."""
    global _bytes_written
    encoded = content.encode("utf-8")
    if _bytes_written + len(encoded) > TOTAL_BYTE_CAP:
        return False
    if not dry_run:
        dest = vault / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(encoded)
    _bytes_written += len(encoded)
    return True


def _fm(**kwargs: Any) -> str:
    """Build YAML frontmatter block."""
    lines = ["---"]
    for k, v in kwargs.items():
        if v is None:
            continue
        if isinstance(v, list):
            if v:
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  - {item}")
        elif isinstance(v, bool):
            lines.append(f"{k}: {str(v).lower()}")
        else:
            safe = str(v).replace('"', '\\"')
            lines.append(f'{k}: "{safe}"')
    lines.append("---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1. Patterns
# ---------------------------------------------------------------------------

def _find_all_dsl_dirs() -> list[Path]:
    ref = REPO_ROOT / "reference"
    dirs = [ref / "patterns.dsl"]
    for d in sorted(ref.iterdir()):
        if d.is_dir() and d.name.startswith("patterns.dsl.") and not d.name.endswith(".PROMOTED"):
            dirs.append(d)
    return dirs


def _load_all_patterns(limit: int | None) -> list[dict]:
    """Load YAML pattern files from all DSL directories."""
    patterns = []
    seen_ids: set[str] = set()
    dirs = _find_all_dsl_dirs()
    for dsl_dir in dirs:
        round_name = dsl_dir.name.replace("patterns.dsl.", "").replace("patterns.dsl", "main")
        for yaml_path in sorted(dsl_dir.glob("*.yaml")):
            raw = _read_yaml(yaml_path)
            if raw is None:
                continue
            pid = raw.get("pattern") or _slug(yaml_path.stem)
            if not pid:
                pid = _slug(yaml_path.stem)
            # deduplicate by id — first occurrence wins
            key = pid
            if key in seen_ids:
                continue
            seen_ids.add(key)
            raw["_id"] = pid
            raw["_source_file"] = str(yaml_path.relative_to(REPO_ROOT))
            raw["_round"] = round_name
            patterns.append(raw)
            if limit and len(patterns) >= limit:
                return patterns
    return patterns


def emit_patterns(vault: Path, limit: int | None, dry_run: bool) -> tuple[int, list[str]]:
    patterns = _load_all_patterns(limit)
    count = 0
    sample_links: list[str] = []
    for p in patterns:
        pid = p["_id"]
        note_slug = _slug(pid)
        severity = str(p.get("severity", "unknown")).lower()
        confidence = str(p.get("confidence", "unknown")).lower()
        engine = str(p.get("engine", "unknown")).lower()
        source = str(p.get("source", ""))
        round_name = p.get("_round", "unknown")
        src_file = p.get("_source_file", "")

        # Build tags
        tags = [
            f"severity/{severity}",
            f"engine/{engine}",
            f"round/{_slug(round_name)}",
        ]
        # pattern class from id heuristic
        for kw in ["reentrancy", "oracle", "sig-replay", "access-control", "overflow", "liquidation",
                   "flashloan", "mev", "bridge", "staking", "vault", "proxy", "zk", "token"]:
            if kw in pid.lower():
                tags.append(f"pattern-class/{kw}")
                break

        fm = _fm(
            id=pid,
            title=p.get("wiki_title") or pid,
            severity=severity,
            confidence=confidence,
            engine=engine,
            source=source,
            round=round_name,
            src_file=src_file,
            tags=tags,
            needs_metadata="true" if not p.get("wiki_description") else None,
        )

        body_parts = [fm, "", f"# {p.get('wiki_title') or pid}", ""]
        desc = p.get("wiki_description", "")
        if desc:
            body_parts += [f"{desc}", ""]
        exploit = p.get("wiki_exploit_scenario", "")
        if exploit:
            body_parts += ["## Exploit Scenario", "", exploit, ""]
        rec = p.get("wiki_recommendation", "")
        if rec:
            body_parts += ["## Recommendation", "", rec, ""]
        if source:
            body_parts += [f"**Source:** {source}", ""]
        body_parts += [f"**Source file:** `{src_file}`", ""]

        # Match predicates
        match_preds = p.get("match", [])
        if match_preds:
            body_parts += ["## Match Predicates", ""]
            for pred in match_preds:
                if isinstance(pred, dict):
                    for k, v in pred.items():
                        body_parts.append(f"- `{k}: {v}`")
                else:
                    body_parts.append(f"- `{pred}`")
            body_parts.append("")

        content = "\n".join(body_parts)
        rel = f"patterns/{note_slug}.md"
        if _write_note(vault, rel, content, dry_run):
            count += 1
            if len(sample_links) < 3:
                sample_links.append(f"[[{note_slug}]]")
    return count, sample_links


# ---------------------------------------------------------------------------
# 2. Detectors
# ---------------------------------------------------------------------------

def _load_tier_registry() -> dict:
    reg_path = REPO_ROOT / "detectors" / "_tier_registry.yaml"
    raw = _read_yaml(reg_path)
    if raw and "tiers" in raw:
        return raw["tiers"]
    return {}


def emit_detectors(vault: Path, limit: int | None, dry_run: bool) -> tuple[int, list[str]]:
    tiers = _load_tier_registry()
    count = 0
    sample_links: list[str] = []
    items = list(tiers.items())
    if limit:
        items = items[:limit]
    for det_id, info in items:
        if not isinstance(info, dict):
            continue
        tier = info.get("tier", "?")
        waves = info.get("waves", [])
        wave_label = waves[0] if waves else "unknown"
        engine = info.get("engine", "unknown")
        verified = info.get("verified", False)
        argument = info.get("argument", det_id)
        first_added = info.get("first_added", "")
        last_promoted = info.get("last_promoted", "")
        reason = info.get("reason", "")
        fixture_pair = info.get("fixture_pair", "")

        tags = [
            f"tier/{tier.lower()}",
            f"wave/{_slug(wave_label)}",
            f"engine/{_slug(engine)}",
            "verified/true" if verified else "verified/false",
        ]

        fm = _fm(
            id=det_id,
            tier=tier,
            engine=engine,
            verified=verified,
            argument=argument,
            wave=wave_label,
            first_added=str(first_added),
            last_promoted=str(last_promoted),
            tags=tags,
        )

        body_parts = [fm, "", f"# Detector: {det_id}", "", f"**Tier:** {tier}", ""]
        if engine != "unknown":
            body_parts += [f"**Engine:** {engine}", ""]
        if argument and argument != det_id:
            body_parts += [f"**Argument:** `{argument}`", ""]
        if waves:
            body_parts += [f"**Waves:** {', '.join(str(w) for w in waves)}", ""]
        if reason:
            body_parts += ["## Promotion Reason", "", reason, ""]
        if fixture_pair:
            body_parts += [f"**Fixture pair:** `{fixture_pair}`", ""]
        if first_added:
            body_parts += [f"**First added:** {first_added}", ""]
        if last_promoted:
            body_parts += [f"**Last promoted:** {last_promoted}", ""]

        content = "\n".join(body_parts)
        wave_slug = _slug(wave_label)
        note_slug = _slug(det_id)
        rel = f"detectors/{wave_slug}/{note_slug}.md"
        if _write_note(vault, rel, content, dry_run):
            count += 1
            if len(sample_links) < 3:
                sample_links.append(f"[[{wave_slug}/{note_slug}]]")
    return count, sample_links


# ---------------------------------------------------------------------------
# 3. Findings (submissions)
# ---------------------------------------------------------------------------

def _list_finding_files(ws_path: Path) -> list[Path]:
    files = []
    for sub_dir in ["submissions", "submissions/ready", "submissions/staging",
                     "submissions/final_dispositions", "submissions/paste_ready"]:
        d = ws_path / sub_dir
        if d.is_dir():
            files.extend(sorted(d.glob("*.md")))
    # deduplicate
    seen: set[Path] = set()
    unique = []
    for f in files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def emit_findings(vault: Path, limit: int | None, dry_run: bool) -> tuple[int, list[str]]:
    count = 0
    sample_links: list[str] = []
    for ws_name in KNOWN_WORKSPACES:
        ws_path = AUDITS_ROOT / ws_name
        if not ws_path.is_dir():
            continue
        finding_files = _list_finding_files(ws_path)
        for fpath in finding_files:
            text = _read_text(fpath)
            # Extract severity from text
            sev_match = re.search(r"(?:severity|Severity)[:\s]+([A-Za-z]+)", text)
            severity = sev_match.group(1).lower() if sev_match else "unknown"
            # Extract title from H1
            title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else fpath.stem
            finding_id = _slug(fpath.stem)

            tags = [
                f"workspace/{_slug(ws_name)}",
                f"severity/{severity}",
                "#status/filed",
            ]
            fm = _fm(
                id=finding_id,
                title=title,
                workspace=ws_name,
                severity=severity,
                src_file=str(fpath),
                tags=tags,
            )
            body_parts = [fm, "", f"# {title}", "", f"**Workspace:** [[workspaces/{_slug(ws_name)}]]", ""]
            # Include first 50 lines of finding body
            lines = text.splitlines()[:50]
            body_parts += lines[:50] + ["", "_(truncated - see source file)_", ""]
            content = "\n".join(body_parts)
            ws_slug = _slug(ws_name)
            rel = f"findings/{ws_slug}/{finding_id}.md"
            if _write_note(vault, rel, content, dry_run):
                count += 1
                if len(sample_links) < 3:
                    sample_links.append(f"[[findings/{ws_slug}/{finding_id}]]")
            if limit and count >= limit:
                return count, sample_links
    return count, sample_links


# ---------------------------------------------------------------------------
# 4. Workspaces
# ---------------------------------------------------------------------------

def emit_workspaces(vault: Path, dry_run: bool) -> int:
    count = 0
    for ws_name in KNOWN_WORKSPACES:
        ws_path = AUDITS_ROOT / ws_name
        exists = ws_path.is_dir()
        finding_files = _list_finding_files(ws_path) if exists else []
        auditooor_dir = ws_path / ".auditooor"
        has_state = auditooor_dir.is_dir() if exists else False

        ws_slug = _slug(ws_name)
        tags = [f"workspace/{ws_slug}"]
        if not exists:
            tags.append("status/missing")
        elif finding_files:
            tags.append("status/active")
        else:
            tags.append("status/empty")

        fm = _fm(
            id=ws_slug,
            name=ws_name,
            path=str(ws_path),
            exists=exists,
            finding_count=len(finding_files),
            has_auditooor_state=has_state,
            tags=tags,
        )
        body = [fm, "", f"# Workspace: {ws_name}", ""]
        body += [f"**Path:** `{ws_path}`", f"**Findings found:** {len(finding_files)}", ""]
        if finding_files:
            body += ["## Findings", ""]
            for ff in finding_files[:20]:
                body.append(f"- [[findings/{ws_slug}/{_slug(ff.stem)}]]")
            if len(finding_files) > 20:
                body.append(f"- _(and {len(finding_files)-20} more)_")
            body.append("")
        if has_state:
            state_files = sorted(auditooor_dir.glob("*.json"))[:10]
            if state_files:
                body += ["## State Artifacts", ""]
                for sf in state_files:
                    body.append(f"- `{sf.name}`")
                body.append("")
        if not exists:
            body += ["> [!warning] Workspace directory not found on this machine.", ""]

        content = "\n".join(body)
        if _write_note(vault, f"workspaces/{ws_slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 4b. Goals
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def emit_goals(vault: Path, dry_run: bool) -> int:
    """Emit the active perpetual-loop goal state into the vault."""
    report_path = REPO_ROOT / "reports" / "goal_loop_status_2026-05-05.json"
    doc_path = REPO_ROOT / "docs" / "GOAL_LOOP_STATUS_2026-05-05.md"
    status = _read_json(report_path) or {}
    doc_text = _read_text(doc_path)
    if not status and not doc_text:
        return 0

    policy = status.get("goal_policy") if isinstance(status.get("goal_policy"), dict) else {}
    goal_status = str(policy.get("status") or "active_continuous_loop")
    loop_back_phase = str(policy.get("loop_back_phase") or "recall_memory")
    terminal_allowed = bool(policy.get("terminal_completion_allowed", False))
    next_action = str(
        status.get("next_operational_rule")
        or "Choose bounded queue items, verify locally, write back memory, and loop back to recall memory."
    )
    objective = (
        "Keep auditooor's memory, harness, known-limitations, detector, and audit workflows "
        "in a continuous self-improvement loop while bounded findings and PR slices close independently."
    )

    fm = _fm(
        id="current",
        title="Current Perpetual Goal",
        status=goal_status,
        objective=objective,
        next_action=next_action,
        terminal_condition="never",
        completion_scope="iterations_only",
        loop="perpetual",
        loop_back_phase=loop_back_phase,
        terminal_completion_allowed=terminal_allowed,
        source_report="reports/goal_loop_status_2026-05-05.json",
        source_doc="docs/GOAL_LOOP_STATUS_2026-05-05.md",
        tags=["goal/current", "memory/goal-loop"],
    )
    body = [
        fm,
        "",
        "# Current Perpetual Goal",
        "",
        "This note is the vault-facing current goal state. The global auditooor objective stays open by design; only bounded iterations, findings, PRs, and handoff packets can close.",
        "",
        "## Policy",
        "",
        f"- Goal status: `{goal_status}`",
        f"- Terminal completion allowed: `{terminal_allowed}`",
        "- Terminal condition: `never`",
        "- Completion scope: `iterations_only`",
        f"- Loop-back phase: `{loop_back_phase}`",
        "",
        "## Next Action",
        "",
        next_action,
        "",
    ]
    if doc_text:
        body += ["## Source Summary", "", doc_text[:3000], ""]
        if len(doc_text) > 3000:
            body += ["_(truncated)_", ""]

    return 1 if _write_note(vault, "goals/current.md", "\n".join(body), dry_run) else 0


# ---------------------------------------------------------------------------
# 5. Mining sources
# ---------------------------------------------------------------------------

def _describe_dsl_dir(d: Path) -> dict:
    yaml_files = list(d.glob("*.yaml"))
    return {"count": len(yaml_files), "name": d.name}


def emit_mining(vault: Path, dry_run: bool) -> int:
    sources = []
    # DSL rounds
    ref = REPO_ROOT / "reference"
    for d in sorted(ref.iterdir()):
        if d.is_dir() and d.name.startswith("patterns.dsl.") and not d.name.endswith(".PROMOTED"):
            info = _describe_dsl_dir(d)
            sources.append(("round", d.name, info))
    # Contest cache
    cc = ref / "contest_cache"
    if cc.is_dir():
        for platform in ["cantina", "immunefi"]:
            pd = cc / platform
            if pd.is_dir():
                files = list(pd.glob("*.json"))
                sources.append(("contest", platform, {"count": len(files)}))
    # Corpus mined
    cm = ref / "corpus_mined"
    if cm.is_dir():
        mds = list(cm.glob("*.md"))
        sources.append(("corpus", "corpus_mined", {"count": len(mds)}))
    # Overnight inventory
    if INVENTORY_DIR.is_dir():
        for item in sorted(INVENTORY_DIR.iterdir())[:20]:
            sources.append(("inventory", item.name, {"path": str(item)}))

    count = 0
    for source_type, name, info in sources:
        s_slug = _slug(name)
        tags = [f"mining/{source_type}", f"mining-source/{s_slug}"]
        pat_count = info.get("count", 0)
        fm = _fm(
            id=s_slug,
            source_type=source_type,
            name=name,
            pattern_count=pat_count,
            tags=tags,
        )
        body = [fm, "", f"# Mining Source: {name}", ""]
        body += [f"**Type:** {source_type}", f"**Patterns/files:** {pat_count}", ""]
        if source_type == "round":
            body += [f"**Round directory:** `reference/{name}`", ""]
        elif source_type == "contest":
            body += [f"**Platform:** {name}", ""]
        elif source_type == "corpus":
            body += ["**Corpus directory:** `reference/corpus_mined/`", ""]
        elif source_type == "inventory":
            body += [f"**Path:** `{info.get('path', '')}`", ""]
        if pat_count == 0:
            body += ["> [!note] needs-metadata: No patterns found in this source.", ""]
        content = "\n".join(body)
        if _write_note(vault, f"mining/{s_slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 6. Known Limitations
# ---------------------------------------------------------------------------

def emit_limitations(vault: Path, dry_run: bool) -> int:
    lim_path = REPO_ROOT / "docs" / "KNOWN_LIMITATIONS.md"
    burndown_path = REPO_ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    text = _read_text(lim_path)
    burndown = {}
    if burndown_path.exists():
        try:
            raw = json.loads(burndown_path.read_text())
            if isinstance(raw, dict):
                burndown = raw
        except Exception:
            pass

    # Extract section headings as limitation IDs
    sections = re.split(r"\n## ", text)
    count = 0
    for i, section in enumerate(sections[1:], 1):  # skip preamble
        lines = section.strip().splitlines()
        if not lines:
            continue
        title = lines[0].strip()
        body_text = "\n".join(lines[1:]).strip()
        lim_id = f"lim-{i:03d}"
        lim_slug = _slug(title)

        tags = ["limitation/known"]
        fm = _fm(
            id=lim_id,
            title=title,
            slug=lim_slug,
            has_burndown=bool(burndown),
            tags=tags,
        )
        body = [fm, "", f"# Limitation: {title}", ""]
        body += [body_text[:1000], ""]
        if len(body_text) > 1000:
            body += ["_(truncated - see `docs/KNOWN_LIMITATIONS.md`)_", ""]
        content = "\n".join(body)
        if _write_note(vault, f"limitations/{lim_slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 7. Tasks (from CONTINUATION_PLAN.md)
# ---------------------------------------------------------------------------

def emit_tasks(vault: Path, dry_run: bool) -> int:
    plan_path = REPO_ROOT / "docs" / "CONTINUATION_PLAN.md"
    text = _read_text(plan_path)
    count = 0

    # Emit a stub index note regardless of whether the plan file exists
    index_fm = _fm(
        title="Active Tasks Index",
        source_file=str(plan_path),
        tags=["task/index"],
        needs_metadata="true" if not text else None,
    )
    stub_note = [
        index_fm, "",
        "# Active Tasks Index", "",
        f"_Source: `docs/CONTINUATION_PLAN.md`_", "",
    ]
    if not text:
        stub_note += [
            "> [!note] needs-metadata: `docs/CONTINUATION_PLAN.md` not found on this branch.",
            "> Tasks are tracked in the `continuation-plan` git branch.",
            "",
        ]
    else:
        stub_note += ["_See individual task notes below._", ""]
    if _write_note(vault, "tasks/active/index.md", "\n".join(stub_note), dry_run):
        count += 1

    # Extract markdown table rows — look for table under "ACTIVE WORK"
    active_section = re.search(r"## ACTIVE WORK.*?(?=\n## |\Z)", text, re.DOTALL)
    if not active_section:
        return count
    section_text = active_section.group()

    # Table rows: | # | Task | Deliverable | Agent | Status |
    row_pattern = re.compile(
        r"\|\s*(\d+|ACT-\d+)\s*\|\s*\*\*([^|*]+)\*\*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|"
    )
    for m in row_pattern.finditer(section_text):
        act_id = m.group(1).strip()
        task_name = m.group(2).strip()
        _deliverable = (m.group(3) + m.group(4)).strip()
        deliverable = m.group(4).strip()
        agent = m.group(5).strip()
        status = m.group(6).strip()

        task_slug = _slug(f"act-{act_id}-{task_name}")
        status_slug = _slug(status) if status else "active"
        tags = [f"task/{status_slug}", "task/active"]

        fm = _fm(
            id=task_slug,
            act_id=act_id,
            title=task_name,
            agent=agent,
            status=status,
            tags=tags,
        )
        body = [fm, "", f"# Task: {task_name}", ""]
        body += [f"**ID:** {act_id}", f"**Agent:** {agent}", f"**Status:** {status}", ""]
        if deliverable:
            body += [f"**Deliverable:** {deliverable}", ""]
        body += [f"**Source:** [[tasks/active/index]] (CONTINUATION_PLAN.md)", ""]
        content = "\n".join(body)
        status_dir = "active" if "dispatch" in status.lower() else "completed"
        if _write_note(vault, f"tasks/{status_dir}/{task_slug}.md", content, dry_run):
            count += 1

    return count


# ---------------------------------------------------------------------------
# 8. Agent Memory
# ---------------------------------------------------------------------------

def emit_agent_memory(vault: Path, dry_run: bool) -> int:
    count = 0
    if not MEMORY_PATH.exists():
        return 0
    memory_text, redacted_count = _redact_text(_read_text(MEMORY_PATH))

    # Parse bullet list entries linking to sub-files
    entry_pattern = re.compile(
        r"- \[([^\]]+)\]\(([^)]+)\)\s*[—-]\s*(.+)"
    )
    entries = entry_pattern.findall(memory_text)

    for title, fname, desc in entries:
        slug = _slug(fname.replace(".md", ""))
        tags = ["agent-memory/feedback"]
        fm = _fm(
            id=slug,
            title=title,
            source_file=fname,
            tags=tags,
        )
        body = [fm, "", f"# Agent Memory: {title}", ""]
        body += [f"**Description:** {desc}", ""]
        body += [f"**Source file:** `{fname}` (in memory directory)", ""]

        # Try to read the actual memory sub-file
        mem_sub = MEMORY_PATH.parent / fname
        if mem_sub.exists():
            sub_text, sub_redactions = _redact_text(_read_text(mem_sub))
            redacted_count += sub_redactions
            body += ["## Content", "", sub_text[:2000], ""]
            if len(sub_text) > 2000:
                body += ["_(truncated)_", ""]

        content = "\n".join(body)
        if _write_note(vault, f"agent-memory/{slug}.md", content, dry_run):
            count += 1

    # Mirror the main MEMORY.md index
    main_fm = _fm(title="Agent Memory Index", tags=["agent-memory/index"])
    main_body = [main_fm, "", "# Agent Memory Index", "", memory_text[:3000]]
    if len(memory_text) > 3000:
        main_body += ["", "_(truncated - see source)_"]
    main_content = "\n".join(main_body)
    if _write_note(vault, "agent-memory/INDEX.md", main_content, dry_run):
        count += 1
    if redacted_count:
        print(f"  agent-memory redacted: {redacted_count}")
    return count


# ---------------------------------------------------------------------------
# 9. Harness phases (from docs)
# ---------------------------------------------------------------------------

def emit_harness_phases(vault: Path, dry_run: bool) -> int:
    """Emit notes for each documented capability iteration."""
    docs_dir = REPO_ROOT / "docs"
    count = 0
    # Gather CAPABILITY_V3_ITER_*.md and similar
    phase_files = sorted(docs_dir.glob("CAPABILITY_V3_ITER_*_RESULTS.md"))
    for pf in phase_files:
        text = _read_text(pf)
        # Extract date from content
        date_match = re.search(r"202\d-\d\d-\d\d", text)
        date_str = date_match.group() if date_match else pf.stem[-8:]
        note_slug = _slug(pf.stem)
        tags = ["harness-phase/capability"]
        fm = _fm(
            id=note_slug,
            title=pf.stem,
            date=date_str,
            tags=tags,
        )
        body = [fm, "", f"# {pf.stem}", ""]
        body += [text[:2000], ""]
        if len(text) > 2000:
            body += ["_(truncated)_", ""]
        content = "\n".join(body)
        if _write_note(vault, f"harness-phase/{note_slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 10. INDEX.md
# ---------------------------------------------------------------------------

def emit_index(vault: Path, stats: dict[str, int], dry_run: bool) -> None:
    total = sum(stats.values())
    fm = _fm(
        title="Auditooor Obsidian Vault Index",
        generated=_now(),
        total_notes=total,
        tags=["index"],
    )
    body = [
        fm, "",
        "# Auditooor Obsidian Vault",
        "",
        f"_Generated: {_now()}_",
        "",
        "## Note Counts",
        "",
        "| Category | Count |",
        "|----------|-------|",
    ]
    for cat, n in sorted(stats.items()):
        body.append(f"| {cat} | {n} |")
    body += [
        f"| **TOTAL** | **{total}** |",
        "",
        "## Quick Navigation",
        "",
        "- [[patterns/INDEX]] - All detector patterns",
        "- [[detectors/INDEX]] - All verified detectors by wave",
        "- [[findings/INDEX]] - Per-workspace findings",
        "- [[workspaces/INDEX]] - Workspace status",
        "- [[goals/current]] - Current perpetual-loop goal state",
        "- [[mining/INDEX]] - Mining source status",
        "- [[limitations/INDEX]] - Known limitations burndown",
        "- [[tasks/active/index]] - Active auditooor tasks",
        "- [[agent-memory/INDEX]] - Agent memory mirror",
        "",
        "## Useful Dataview Queries",
        "",
        "Patterns recurring in ≥2 workspaces:",
        "```dataview",
        'TABLE title, severity, engine',
        'FROM "patterns"',
        'WHERE length(filter(tags, (t) => startswith(t, "workspace/"))) >= 2',
        'SORT severity ASC',
        "```",
        "",
        "All verified Tier-B+ detectors:",
        "```dataview",
        'TABLE id, engine, wave',
        'FROM "detectors"',
        'WHERE verified = "true" AND (contains(tags, "tier/b") OR contains(tags, "tier/a") OR contains(tags, "tier/s"))',
        'SORT id ASC',
        "```",
        "",
        "Active tasks not yet completed:",
        "```dataview",
        'TABLE title, agent, status',
        'FROM "tasks/active"',
        'WHERE contains(tags, "task/active")',
        "```",
        "",
        "Critical / High findings:",
        "```dataview",
        'TABLE title, workspace',
        'FROM "findings"',
        'WHERE contains(tags, "severity/critical") OR contains(tags, "severity/high")',
        "```",
        "",
        "## Repository",
        "",
        f"`{REPO_ROOT}`",
    ]
    content = "\n".join(body)
    _write_note(vault, "INDEX.md", content, dry_run)


# ---------------------------------------------------------------------------
# Sub-indexes
# ---------------------------------------------------------------------------

def emit_sub_indexes(vault: Path, dry_run: bool) -> None:
    """Emit INDEX.md stub for each top-level section."""
    sections = {
        "patterns": "All mined DSL patterns across all R-rounds",
        "detectors": "All detector registry entries from _tier_registry.yaml",
        "findings": "Per-workspace submitted findings",
        "workspaces": "Workspace status and artifact indexes",
        "goals": "Current perpetual-loop goal state",
        "mining": "Mining source status, progress, and output dirs",
        "limitations": "Known limitations from KNOWN_LIMITATIONS.md + deep burndown",
        "tasks": "Task tracking from CONTINUATION_PLAN.md",
        "agent-memory": "Mirror of ~/.claude/.../memory/MEMORY.md",
        "harness-phase": "Capability loop result logs",
        "agent-runs": "Agent output directory metadata (--deep)",
        "r-rounds": "DSL pattern mining round index (--deep)",
    }
    for section, desc in sections.items():
        fm = _fm(title=f"{section.title()} Index", tags=[f"{section}/index"])
        body = [fm, "", f"# {section.title()}", "", desc, ""]
        content = "\n".join(body)
        _write_note(vault, f"{section}/INDEX.md", content, dry_run)




# ---------------------------------------------------------------------------
# 11. Mining Progress (--deep)
# ---------------------------------------------------------------------------

def emit_mining_progress(vault: Path, dry_run: bool) -> int:
    if not INVENTORY_DIR.is_dir():
        return 0
    prog_files = sorted(INVENTORY_DIR.glob("*.progress.json"))
    count = 0
    for pf in prog_files:
        try:
            raw = json.loads(pf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        loop_id = pf.stem.replace(".progress", "")
        slug = _slug(loop_id)
        total = int(raw.get("total", 0))
        done = int(raw.get("done", 0))
        failed = int(raw.get("failed", 0))
        skipped = int(raw.get("skipped", 0))
        ts = raw.get("ts", "")
        in_backoff = bool(raw.get("in_backoff", False))
        current_task = str(raw.get("current_task", ""))[:120]
        pct = round(done / total * 100, 1) if total > 0 else 0.0
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        status = "in-progress" if done < total else "complete"
        if failed > 0:
            status = "has-failures"
        tags = ["mining/progress", f"status/{status}"]
        fm = _fm(
            id=slug, loop_id=loop_id, total=total, done=done,
            skipped=skipped, failed=failed, pct_done=pct,
            status=status, last_run=str(ts), tags=tags,
        )
        output_dir_name = loop_id.replace("_queue", "_outputs").replace("-queue", "-outputs")
        has_outputs = (INVENTORY_DIR / output_dir_name).is_dir()
        output_dir_slug = _slug(output_dir_name)
        outputs_link = f"[[mining/outputs/{output_dir_slug}]]" if has_outputs else "_none_"
        body = [
            fm, "",
            f"# Mining Loop: {loop_id}", "",
            f"**Progress:** `[{bar}]` {pct}%",
            f"**Done:** {done} / {total}   **Failed:** {failed}   **Skipped:** {skipped}",
            f"**Status:** {status}",
            f"**Last run:** {ts}",
        ]
        if in_backoff:
            body.append("**In backoff:** yes")
        if current_task:
            body.append(f"**Current task:** `{current_task}`")
        body += ["", f"**Outputs:** {outputs_link}", "", f"**Source file:** `{pf}`"]
        content = "\n".join(body)
        if _write_note(vault, f"mining/progress/{slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 12. Mining Outputs (--deep)
# ---------------------------------------------------------------------------

def emit_mining_outputs(vault: Path, dry_run: bool) -> int:
    if not INVENTORY_DIR.is_dir():
        return 0
    count = 0
    for d in sorted(INVENTORY_DIR.iterdir()):
        if not d.is_dir():
            continue
        if not (d.name.endswith("_outputs") or d.name.endswith("-outputs")):
            continue
        slug = _slug(d.name)
        files = sorted(d.iterdir())
        file_count = len(files)
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        total_size_kb = round(total_size / 1024, 1)
        oldest_ts = newest_ts = ""
        mtimes = [f.stat().st_mtime for f in files if f.is_file()]
        if mtimes:
            oldest_ts = _dt.datetime.fromtimestamp(
                min(mtimes), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
            newest_ts = _dt.datetime.fromtimestamp(
                max(mtimes), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
        sample_files = [f.name for f in files[:8] if f.is_file()]
        tags = ["mining/outputs"]
        fm = _fm(
            id=slug, dir_name=d.name, file_count=file_count,
            total_size_kb=total_size_kb, oldest_mtime=oldest_ts,
            newest_mtime=newest_ts, tags=tags,
        )
        body = [
            fm, "",
            f"# Mining Output Dir: {d.name}", "",
            f"**File count:** {file_count}",
            f"**Total size:** {total_size_kb} KB",
            f"**Oldest file:** {oldest_ts}",
            f"**Newest file:** {newest_ts}",
            "", "**Sample files:**",
        ]
        for sf in sample_files:
            body.append(f"- `{sf}`")
        if file_count > 8:
            body.append(f"- _(and {file_count - 8} more)_")
        body += ["", f"**Path:** `{d}`"]
        content = "\n".join(body)
        if _write_note(vault, f"mining/outputs/{slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 13. Known Limitations Deep (--deep)
# ---------------------------------------------------------------------------

def emit_limitations_deep(vault: Path, dry_run: bool) -> int:
    burndown_path = REPO_ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    if not burndown_path.exists():
        return 0
    try:
        raw = json.loads(burndown_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    rows = raw.get("rows", [])
    if not rows:
        return 0
    count = 0
    for row in rows:
        lim_id = str(row.get("limitation_id", ""))
        title = str(row.get("title", ""))
        priority_group = str(row.get("priority_group", ""))
        stop_condition = str(row.get("stop_condition", ""))
        stop_met = bool(row.get("stop_condition_met", False))
        terminal_state = str(row.get("terminal_state", ""))
        current_status = str(row.get("current_status_before", ""))
        target_status = str(row.get("target_status_after", ""))
        remaining = str(row.get("remaining_after_560", ""))
        next_command = str(row.get("next_command", ""))
        evidence = row.get("evidence", [])
        status = "closed" if stop_met else "open"
        slug = _slug(f"{priority_group}-{title}")
        tags = [
            "limitation/deep",
            f"limitation/priority-{_slug(priority_group)}",
            f"status/{status}",
        ]
        fm = _fm(
            id=slug, limitation_id=lim_id, title=title,
            priority_group=priority_group, stop_condition_met=stop_met,
            terminal_state=terminal_state, status=status, tags=tags,
        )
        body = [
            fm, "",
            f"# Limitation: {title}", "",
            f"**Limitation ID:** {lim_id}",
            f"**Priority group:** {priority_group}",
            f"**Status:** {status}",
            f"**Stop condition met:** {stop_met}",
            f"**Terminal state:** {terminal_state}",
            "",
            "## Stop Condition", "", stop_condition, "",
            "## Current Status", "", current_status, "",
            "## Remaining After #560", "", remaining, "",
            "## Target Status", "", target_status, "",
        ]
        if next_command:
            body += ["## Next Command", "", f"```\n{next_command}\n```", ""]
        if evidence:
            body += ["## Evidence", ""]
            for ev in evidence[:10]:
                body.append(f"- {ev}")
            if len(evidence) > 10:
                body.append(f"- _(and {len(evidence) - 10} more)_")
            body.append("")
        body += [f"**Source:** `docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json`"]
        content = "\n".join(body)
        if _write_note(vault, f"limitations/deep/{slug}.md", content, dry_run):
            count += 1
    return count


# ---------------------------------------------------------------------------
# 14. Agent Outputs (--deep, metadata-only, cap=200)
# ---------------------------------------------------------------------------

AGENT_OUTPUTS_CAP = 200


def emit_agent_outputs(vault: Path, dry_run: bool) -> int:
    ao_root = REPO_ROOT / "agent_outputs"
    if not ao_root.is_dir():
        return 0
    count = 0
    index_rows: list[str] = []
    subdirs = sorted(d for d in ao_root.iterdir() if d.is_dir())
    for d in subdirs[:AGENT_OUTPUTS_CAP]:
        slug = _slug(d.name)
        files = sorted(d.iterdir())
        file_count = len(files)
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        total_size_kb = round(total_size / 1024, 1)
        mtimes = [f.stat().st_mtime for f in files if f.is_file()]
        oldest_ts = newest_ts = ""
        if mtimes:
            oldest_ts = _dt.datetime.fromtimestamp(
                min(mtimes), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
            newest_ts = _dt.datetime.fromtimestamp(
                max(mtimes), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
        recent_files = [
            f.name for f in sorted(
                files, key=lambda x: x.stat().st_mtime, reverse=True
            )[:8] if f.is_file()
        ]
        tags = ["agent-runs/subdir"]
        fm = _fm(
            id=slug, dir_name=d.name, file_count=file_count,
            total_size_kb=total_size_kb, oldest_mtime=oldest_ts,
            newest_mtime=newest_ts, tags=tags,
        )
        body = [
            fm, "",
            f"# Agent Output Dir: {d.name}", "",
            f"**Files:** {file_count}   **Size:** {total_size_kb} KB",
            f"**Oldest:** {oldest_ts}   **Newest:** {newest_ts}",
            "", "**Most recent files:**",
        ]
        for rf in recent_files:
            body.append(f"- `{rf}`")
        if file_count > 8:
            body.append(f"- _(and {file_count - 8} more)_")
        body += ["", f"**Path:** `{d}`", "", "_Content not indexed - metadata only._"]
        content = "\n".join(body)
        if _write_note(vault, f"agent-runs/{slug}.md", content, dry_run):
            count += 1
            index_rows.append(
                f"| [[agent-runs/{slug}|{d.name}]] | {file_count} | {newest_ts} |"
            )
    top_mds = sorted(f for f in ao_root.iterdir() if f.is_file() and f.suffix == ".md")
    for md in top_mds[:20]:
        slug = _slug(md.stem)
        size_kb = round(md.stat().st_size / 1024, 1)
        mtime = _dt.datetime.fromtimestamp(
            md.stat().st_mtime, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
        tags = ["agent-runs/top-level"]
        fm = _fm(id=slug, filename=md.name, size_kb=size_kb, mtime=mtime, tags=tags)
        text_preview = md.read_text(encoding="utf-8", errors="replace")[:500]
        body = [
            fm, "",
            f"# Agent Output: {md.name}", "",
            f"**Modified:** {mtime}   **Size:** {size_kb} KB", "",
            "## Preview", "", text_preview, "",
            "_(truncated - see source file)_",
            "", f"**Path:** `{md}`",
        ]
        content = "\n".join(body)
        if _write_note(vault, f"agent-runs/{slug}.md", content, dry_run):
            count += 1
            index_rows.append(
                f"| [[agent-runs/{slug}|{md.name}]] | 1 | {mtime} |"
            )
    index_fm = _fm(title="Agent Runs Index", tags=["agent-runs/index"])
    index_body = [
        index_fm, "",
        "# Agent Runs Index", "",
        "_Source: `agent_outputs/` (metadata only; content not indexed)_", "",
        "| Dir/File | Files | Newest |",
        "|----------|-------|--------|",
    ] + index_rows + [""]
    if _write_note(vault, "agent-runs/INDEX.md", "\n".join(index_body), dry_run):
        count += 1
    return count


# ---------------------------------------------------------------------------
# 15. INDEX_active synthesis (--deep)
# ---------------------------------------------------------------------------

def emit_index_active(vault: Path, dry_run: bool) -> int:
    docs_dir = REPO_ROOT / "docs"
    pr_count = _highest_merged_pr_number() or _highest_pr_number_from_docs(docs_dir)
    tiers = _load_tier_registry()
    verified_count = sum(
        1 for v in tiers.values() if isinstance(v, dict) and v.get("verified")
    )
    loops: list[dict] = []
    if INVENTORY_DIR.is_dir():
        for pf in sorted(INVENTORY_DIR.glob("*.progress.json")):
            try:
                raw = json.loads(pf.read_text())
            except Exception:
                continue
            if not isinstance(raw, dict):
                continue
            total = int(raw.get("total", 0))
            done = int(raw.get("done", 0))
            failed = int(raw.get("failed", 0))
            pct = round(done / total * 100, 1) if total > 0 else 0.0
            loop_slug = _slug(pf.stem.replace(".progress", ""))
            loops.append({
                "id": pf.stem.replace(".progress", ""),
                "slug": loop_slug,
                "total": total, "done": done, "pct": pct, "failed": failed,
            })
    plan_path = docs_dir / "AUDITOOOR_CONTROL_PLANE_PLAN.md"
    plan_text = _read_text(plan_path)
    phase_snippet = ""
    phase_match = re.search(
        r"\|\s*Phase.*?\n(\|[-|]+\|\n)?(.+?)(?=\n##|\Z)", plan_text, re.DOTALL
    )
    if phase_match:
        phase_snippet = _truncate_on_line_boundary(phase_match.group(0), 1500)
    fm = _fm(
        title="Index Active - Control Plane Snapshot",
        generated=_now(), pr_count=pr_count,
        verified_detectors=verified_count, loops_in_flight=len(loops),
        tags=["index/active", "control-plane/snapshot"],
    )
    body = [
        fm, "",
        "# Index Active - Control Plane Snapshot", "",
        f"_Generated: {_now()}_", "",
        "## Quick Numbers", "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Highest merged PR | #{pr_count} |",
        f"| Verified detectors | {verified_count} |",
        f"| Overnight loops tracked | {len(loops)} |",
        "",
        "## In-Flight Overnight Loops", "",
        "| Loop | Done | Total | % | Failed |",
        "|------|------|-------|---|--------|",
    ]
    for lp in loops:
        row = (
            f"| [[mining/progress/{lp['slug']}|{lp['id']}]] "
            f"| {lp['done']} | {lp['total']} | {lp['pct']}% | {lp['failed']} |"
        )
        body.append(row)
    body += [""]
    if phase_snippet:
        body += ["## Control Plane Phase Status", "", phase_snippet, ""]
    body += [
        "## Navigation", "",
        "- [[INDEX]] - Vault root",
        "- [[patterns/INDEX]] - All patterns",
        "- [[detectors/INDEX]] - All detectors",
        "- [[r-rounds/INDEX]] - DSL R-round index",
        "- [[limitations/INDEX]] - Known limitations",
        "- [[agent-runs/INDEX]] - Agent output dirs",
        "",
    ]
    content = "\n".join(body)
    return 1 if _write_note(vault, "INDEX_active.md", content, dry_run) else 0


# ---------------------------------------------------------------------------
# 16. R-Rounds (--deep)
# ---------------------------------------------------------------------------

def emit_r_rounds(vault: Path, dry_run: bool) -> int:
    ref = REPO_ROOT / "reference"
    count = 0
    round_dirs = sorted(
        d for d in ref.iterdir()
        if d.is_dir()
        and d.name.startswith("patterns.dsl.r")
        and not d.name.endswith(".PROMOTED")
    )
    index_rows: list[str] = []
    for d in round_dirs:
        name = d.name
        m = re.match(r"patterns\.dsl\.r(\d+)_?(.*)", name)
        round_num = int(m.group(1)) if m else 0
        class_part = m.group(2) if m else name
        yaml_files = sorted(d.glob("*.yaml"))
        yaml_count = len(yaml_files)
        mining_source = "unknown"
        cp = class_part.lower()
        if "c4" in cp or "code4rena" in cp:
            mining_source = "code4rena"
        elif "mined" in cp or "solodit" in cp:
            mining_source = "solodit"
        elif "cantina" in cp:
            mining_source = "cantina"
        elif "chain" in cp:
            mining_source = "on-chain"
        elif "eip" in cp:
            mining_source = "eip-spec"
        elif "perps" in cp:
            mining_source = "perps-protocols"
        elif "oz" in cp:
            mining_source = "openzeppelin"
        elif "cs" in cp:
            mining_source = "code-scan"
        elif "crosslang" in cp:
            mining_source = "cross-language"
        slug = _slug(f"r{round_num}-{class_part}")
        tags = [f"r-round/r{round_num}", f"mining-source/{_slug(mining_source)}"]
        fm = _fm(
            id=slug, round_num=round_num, class_part=class_part,
            dir_name=name, yaml_count=yaml_count, mining_source=mining_source,
            tags=tags,
        )
        sample_patterns = yaml_files[:10]
        body = [
            fm, "",
            f"# R-Round: r{round_num} {class_part}", "",
            f"**Directory:** `reference/{name}`",
            f"**Patterns:** {yaml_count}",
            f"**Mining source:** {mining_source}",
            "", "## Sample Patterns", "",
        ]
        for yf in sample_patterns:
            pat_id = _slug(yf.stem)
            body.append(f"- [[patterns/{pat_id}]]")
        if yaml_count > 10:
            body.append(f"- _(and {yaml_count - 10} more)_")
        body += ["", f"**Source dir:** `{d.relative_to(REPO_ROOT)}`"]
        content = "\n".join(body)
        if _write_note(vault, f"r-rounds/{slug}.md", content, dry_run):
            count += 1
            index_rows.append(
                f"| [[r-rounds/{slug}|r{round_num} {class_part}]] | {yaml_count} | {mining_source} |"
            )
    index_fm = _fm(
        title="R-Rounds Index", total_rounds=len(round_dirs), tags=["r-rounds/index"]
    )
    index_body = [
        index_fm, "",
        "# R-Rounds Index", "",
        f"_Total rounds: {len(round_dirs)}_", "",
        "| Round | Patterns | Source |",
        "|-------|----------|--------|",
    ] + index_rows + [""]
    if _write_note(vault, "r-rounds/INDEX.md", "\n".join(index_body), dry_run):
        count += 1
    return count


# ---------------------------------------------------------------------------
# 17. Cross-link: pattern notes back-link to detectors
# ---------------------------------------------------------------------------

def _backlink_patterns_to_detectors(vault: Path, dry_run: bool) -> int:
    tiers = _load_tier_registry()
    pat_to_dets: dict[str, list[str]] = {}
    for det_id, info in tiers.items():
        if not isinstance(info, dict):
            continue
        arg = str(info.get("argument", "")).lower()
        wave_label = (info.get("waves") or ["unknown"])[0]
        wave_slug = _slug(str(wave_label))
        det_slug = _slug(det_id)
        det_link = f"[[detectors/{wave_slug}/{det_slug}]]"
        for kw in [arg, _slug(arg), det_id, _slug(det_id)]:
            if not kw:
                continue
            pat_to_dets.setdefault(kw, [])
            if det_link not in pat_to_dets[kw]:
                pat_to_dets[kw].append(det_link)
    if dry_run:
        return len(pat_to_dets)
    updated = 0
    patterns_dir = vault / "patterns"
    if not patterns_dir.is_dir():
        return 0
    for note_path in patterns_dir.glob("*.md"):
        note_id = note_path.stem
        matches = pat_to_dets.get(note_id, [])
        if not matches:
            continue
        try:
            existing = note_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "## Used By Detectors" in existing:
            continue
        backlink_section = (
            "\n## Used By Detectors\n\n"
            + "\n".join(f"- {lnk}" for lnk in matches)
            + "\n"
        )
        note_path.write_text(existing + backlink_section, encoding="utf-8")
        updated += 1
    return updated


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Emit Obsidian vault from auditooor canonical sources."
    )
    parser.add_argument("--vault-dir", type=Path, default=VAULT_DEFAULT,
        help="Output directory for vault (default: obsidian-vault/ in repo root)")
    parser.add_argument("--limit", type=int, default=None,
        help="Cap notes per section (for testing; omit for full run)")
    parser.add_argument("--dry-run", action="store_true",
        help="Print stats without writing any files")
    parser.add_argument(
        "--section",
        choices=[
            "patterns", "detectors", "findings", "workspaces", "mining",
            "goals", "limitations", "tasks", "agent-memory", "harness-phases",
            "mining-progress", "mining-outputs", "limitations-deep",
            "agent-outputs", "index-active", "r-rounds", "all",
        ],
        default="all",
        help="Emit only one section",
    )
    parser.add_argument("--deep", action="store_true",
        help="Run all sections + 6 deep ingestors + cross-link pass")
    args = parser.parse_args()

    vault = args.vault_dir.resolve()
    if not args.dry_run:
        vault.mkdir(parents=True, exist_ok=True)

    print(f"[obsidian-vault-emit] vault={vault} limit={args.limit} "
          f"dry_run={args.dry_run} deep={args.deep}")

    stats: dict[str, int] = {}
    all_sample_links: list[str] = []
    do_all = args.section == "all" or args.deep

    if do_all or args.section == "patterns":
        n, links = emit_patterns(vault, args.limit, args.dry_run)
        stats["patterns"] = n; all_sample_links.extend(links)
        print(f"  patterns:          {n}")

    if do_all or args.section == "detectors":
        n, links = emit_detectors(vault, args.limit, args.dry_run)
        stats["detectors"] = n; all_sample_links.extend(links)
        print(f"  detectors:         {n}")

    if do_all or args.section == "findings":
        n, links = emit_findings(vault, args.limit, args.dry_run)
        stats["findings"] = n; all_sample_links.extend(links)
        print(f"  findings:          {n}")

    if do_all or args.section == "workspaces":
        n = emit_workspaces(vault, args.dry_run)
        stats["workspaces"] = n
        print(f"  workspaces:        {n}")

    if do_all or args.section == "goals":
        n = emit_goals(vault, args.dry_run)
        stats["goals"] = n
        print(f"  goals:             {n}")

    if do_all or args.section == "mining":
        n = emit_mining(vault, args.dry_run)
        stats["mining"] = n
        print(f"  mining:            {n}")

    if do_all or args.section == "limitations":
        n = emit_limitations(vault, args.dry_run)
        stats["limitations"] = n
        print(f"  limitations:       {n}")

    if do_all or args.section == "tasks":
        n = emit_tasks(vault, args.dry_run)
        stats["tasks"] = n
        print(f"  tasks:             {n}")

    if do_all or args.section == "agent-memory":
        n = emit_agent_memory(vault, args.dry_run)
        stats["agent-memory"] = n
        print(f"  agent-memory:      {n}")

    if do_all or args.section == "harness-phases":
        n = emit_harness_phases(vault, args.dry_run)
        stats["harness-phases"] = n
        print(f"  harness-phases:    {n}")

    if args.deep or args.section == "mining-progress":
        n = emit_mining_progress(vault, args.dry_run)
        stats["mining-progress"] = n
        print(f"  mining-progress:   {n}")

    if args.deep or args.section == "mining-outputs":
        n = emit_mining_outputs(vault, args.dry_run)
        stats["mining-outputs"] = n
        print(f"  mining-outputs:    {n}")

    if args.deep or args.section == "limitations-deep":
        n = emit_limitations_deep(vault, args.dry_run)
        stats["limitations-deep"] = n
        print(f"  limitations-deep:  {n}")

    if args.deep or args.section == "agent-outputs":
        n = emit_agent_outputs(vault, args.dry_run)
        stats["agent-outputs"] = n
        print(f"  agent-outputs:     {n}")

    if args.deep or args.section == "index-active":
        n = emit_index_active(vault, args.dry_run)
        stats["index-active"] = n
        print(f"  index-active:      {n}")

    if args.deep or args.section == "r-rounds":
        n = emit_r_rounds(vault, args.dry_run)
        stats["r-rounds"] = n
        print(f"  r-rounds:          {n}")

    if do_all:
        emit_sub_indexes(vault, args.dry_run)
        emit_index(vault, stats, args.dry_run)

    if args.deep and not args.dry_run:
        backlinks = _backlink_patterns_to_detectors(vault, args.dry_run)
        print(f"  backlinks added:   {backlinks}")

    total = sum(stats.values())
    bytes_mb = _bytes_written / (1024 * 1024)
    print(f"\n  TOTAL notes:     {total}")
    print(f"  Bytes written:   {bytes_mb:.2f} MB")

    if all_sample_links:
        print("\n  Sample wikilinks:")
        for link in all_sample_links[:6]:
            print(f"    {link}")

    if not args.dry_run:
        stamp = {
            "generated": _now(),
            "total_notes": total,
            "bytes_written": _bytes_written,
            "stats": stats,
        }
        (vault / ".last_sync.json").write_text(json.dumps(stamp, indent=2))
        print(f"\n  Stamp written to {vault}/.last_sync.json")


if __name__ == "__main__":
    main()
