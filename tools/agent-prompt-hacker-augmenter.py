#!/usr/bin/env python3
"""
agent-prompt-hacker-augmenter.py — Hacker-Mindset Brief Augmenter (W2-A).

Generates a scope-filtered "Hacker Mindset Injection" Markdown brief for a
hunt-loop lane.  The brief is structured as Sections 0 / 0.5 / 0.7 / 0.9 /
1-14 (in that order) and is intended to be prepended to a worker's prompt by
SKILL.md Step 4.5 / Step 5.

Sources consumed (REUSE — never re-implement):
  - adversarial-copilot.py:build_counter_brief()   (Section 1)
  - relevant-rules-for-draft.py --frames-only --json  (Section 12)
  - vault_engage_report_context / <ws>/engage_report.md fallback (Section 5)
  - docs/KILL_RUBRIC_LIBRARY.md                    (Section 6)
  - reference/triager_patterns.md                  (Section 7)
  - reference/REJECTION_CAUSES.md + DUPE_CAUSES.md (Section 8)
  - reference/originality_keywords.md              (Section 9)
  - <ws>/OOS_CHECKLIST.md + <ws>/SCOPE.md          (Section 10)
  - <ws>/.auditooor/spark_hunt_loop_state.json     (Sections 0.7, 0.9)
  - <ws>/external/*/                               (Section 0.5)
  - vault_resume_context                           (Sections 2, 3, 4)
  - vault_exploit_context                          (Section 11)
  - tools/attack-class-ranker.py                   (Section 13 advisory questions)

Usage:
    python3 tools/agent-prompt-hacker-augmenter.py \\
        --workspace ~/audits/spark \\
        --lane-id H1-coop-exit \\
        --files spark/coopexit.go,spark/watcher.go \\
        [--contract-type-hint frost-signer] \\
        [--out /tmp/brief.md] \\
        [--max-tokens 8000] \\
        [--json-out]

Exit codes:
  0  — brief written successfully
  1  — error (workspace invalid, FILE_CAP exceeded, secret detected)
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO = pathlib.Path(__file__).resolve().parent.parent
_FILE_CAP = 2000          # abort if workspace has > this many in-scope files
_MAX_TOKENS_DEFAULT = 8000
_MAX_ITEMS_DEFAULT = 8
_SEC3_MAX_PREDICATES_PER_STEP = 4
_SEC3_MAX_HIT_REFS_PER_PREDICATE = 3
_SEC13_MAX_SEQ_PREDICATE_QUESTIONS = 8
_SEC13_MAX_PRIOR_OUTCOME_QUESTIONS = 4
_SEC13_MAX_OOS_QUESTIONS = 4
_SEC13_MAX_ATTACK_CLASS_QUESTIONS = 3

# Secret patterns to block from output (matches AWS-style keys, PEM headers, etc.)
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"[0-9a-f]{64}"),   # 64-char hex (private key candidate)
    re.compile(r"sk-[A-Za-z0-9]{32,}"),  # OpenAI-style
]

# Section headers for the 19 sections (0, 0.5, 0.7, 0.9, 1-5, 5.5, 6-14)
_SECTION_KEYS = [
    "sec0_l17_verdict_contract",
    "sec08_impact_mechanism_plane",
    "sec05_clones_inventory",
    "sec07_queued_leads",
    "sec09_cooldown_states",
    "sec1_counter_brief",
    "sec2_case_study_logic",
    "sec3_big_loss_sequences",
    "sec4_defihacklabs",
    "sec5_engage_report_fires",
    "sec55_go_yaml_fallback",
    "sec6_kill_rubric",
    "sec7_triager_patterns",
    "sec8_prior_dupes",
    "sec9_originality_keywords",
    "sec10_oos_clauses",
    "sec11_exploit_angles",
    "sec12_amf_frames",
    "sec13_question_list",
    "sec14_reply_shape",
    "sec15_hard_rules_digest",
    "sec_function_mindset",
]

# Handler-like name heuristic used by the function-mindset section.
# Filters to exported functions matching naming conventions likely to be
# security-relevant (message handlers, state writers, coordinator methods).
_HANDLER_HEURISTIC = re.compile(
    r"(?i)(handle|process|server|register|update|set|exec|create|withdraw|deposit)",
    re.IGNORECASE,
)
_HANDLER_RECEIVER_FAMILIES = {"msg-server-family", "hook-family"}

# Performance budget comment (documented in the tool).
# With ~10 in-scope files × 20 functions × ~10ms ranker call ≈ 2 seconds.
# Measured and acceptable — documented here per Deliverable 4.
_FUNCTION_MINDSET_BUDGET_NOTE = (
    "Budget: ~10 files × 20 functions × ~10ms ranker call ≈ 2 seconds expected."
)

_VAULT_CONTEXT_CACHE: Dict[Tuple[str, str, str], Optional[Dict[str, Any]]] = {}

# Path to YAML text-pattern fallback directory for Go (W2 plan §L5)
_GO_YAML_PATTERN_DIR = "reference/patterns.dsl.r94_solodit_go"
# Path to compiled Go detector dir; if it has any detector module, the fallback
# is skipped (compiled detectors are richer than text patterns).
_GO_COMPILED_DETECTOR_DIR = "go_wave1"

_ABS_PATH_RE = re.compile(r"(?<![:\w>~])(?!//)/[^\s\"'<>`]+")
_GENERATED_LINE_RE = re.compile(r"^\*\*Generated:?\*\*:?\s+.*$", re.MULTILINE)

# ---------------------------------------------------------------------------
# Secret guard
# ---------------------------------------------------------------------------

def _has_secret(text: str) -> bool:
    """Return True if text matches any known secret pattern."""
    for pat in _SECRET_PATTERNS:
        if pat.search(text):
            return True
    return False


def _sanitize(text: str) -> str:
    """Replace matched secrets with [REDACTED]."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def _sanitize_json_value(value: Any, workspace: pathlib.Path, key: str = "") -> Any:
    """Sanitize JSON sidecar values with the same privacy guard as Markdown."""
    if isinstance(value, str):
        if key == "content_hash":
            return value
        return _sanitize(_strip_absolute_paths(value, workspace))
    if isinstance(value, list):
        return [_sanitize_json_value(item, workspace, key) for item in value]
    if isinstance(value, dict):
        return {str(k): _sanitize_json_value(v, workspace, str(k)) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# Absolute-path guard
# ---------------------------------------------------------------------------

def _strip_absolute_paths(text: str, workspace: pathlib.Path) -> str:
    """Replace absolute paths with workspace-relative equivalents where possible."""
    ws_str = str(workspace)
    repo_str = str(REPO)
    home_str = str(pathlib.Path.home())

    ws_aliases = [ws_str]
    if ws_str.startswith("/private/var/"):
        ws_aliases.append(ws_str.replace("/private/var/", "/var/", 1))
    elif ws_str.startswith("/var/"):
        ws_aliases.append(ws_str.replace("/var/", "/private/var/", 1))

    repo_aliases = [repo_str]
    if repo_str.startswith("/private/var/"):
        repo_aliases.append(repo_str.replace("/private/var/", "/var/", 1))
    elif repo_str.startswith("/var/"):
        repo_aliases.append(repo_str.replace("/var/", "/private/var/", 1))

    for ws_alias in sorted(set(ws_aliases), key=len, reverse=True):
        text = text.replace(ws_alias, "<workspace>")
    for repo_alias in sorted(set(repo_aliases), key=len, reverse=True):
        text = text.replace(repo_alias, "<repo>")
    text = text.replace(home_str, "~")

    def _replace_match(match: re.Match[str]) -> str:
        path = match.group(0)
        if path.startswith("/private/tmp/"):
            return "<tmp>/" + pathlib.Path(path).name
        if path == "/private/tmp":
            return "<tmp>"
        if path.startswith("/tmp/"):
            return "<tmp>/" + pathlib.Path(path).name
        if path == "/tmp":
            return "<tmp>"
        if path.startswith("/private/var/folders/") or path.startswith("/var/folders/"):
            return "<tmp>/" + pathlib.Path(path).name
        if path.startswith("/Users/"):
            parts = pathlib.PurePosixPath(path).parts
            if len(parts) >= 3:
                return "<user>/" + "/".join(parts[3:])
            return "<user>"
        if path.startswith("/home/"):
            parts = pathlib.PurePosixPath(path).parts
            if len(parts) >= 3:
                return "<user>/" + "/".join(parts[3:])
            return "<user>"
        return "<external>/" + pathlib.Path(path).name

    text = _ABS_PATH_RE.sub(_replace_match, text)
    return text


# ---------------------------------------------------------------------------
# Relevance scoring
# ---------------------------------------------------------------------------

def _relevance_score(item: Dict[str, Any], files: List[str], hint: Optional[str]) -> float:
    """Score a corpus item against files and contract_type_hint.

    +5 per file-basename substring match in item.source_refs / item.path
    +3 per token from file basename found in item title/help/wiki_description
    +10 if hint matches item.bug_class / class / tags
    severity multiplier: CRIT=1.5, HIGH=1.2
    """
    score = 0.0

    file_basenames = [pathlib.Path(f).stem.lower() for f in files if f]

    # Path-match bonus
    source_refs = item.get("source_refs", [])
    if isinstance(source_refs, str):
        source_refs = [source_refs]
    item_paths = source_refs + [str(item.get("path", "")), str(item.get("file", ""))]
    for bn in file_basenames:
        if not bn:
            continue
        for ref in item_paths:
            if bn in str(ref).lower():
                score += 5.0
                break

    # Token-match bonus in descriptive text
    text = " ".join([
        str(item.get("title", "")),
        str(item.get("help", "")),
        str(item.get("wiki_description", "")),
        str(item.get("description", "")),
        str(item.get("name", "")),
    ]).lower()
    for bn in file_basenames:
        for tok in re.split(r"[^a-z0-9]+", bn):
            if len(tok) >= 4 and tok in text:
                score += 3.0

    # Contract-type hint bonus
    if hint:
        h = hint.lower()
        for k in ("bug_class", "class", "tags", "applicable_workspace_classes", "category"):
            v = item.get(k, "")
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            if h and h in str(v).lower():
                score += 10.0
                break

    # Severity multiplier
    sev = str(item.get("severity") or item.get("severity_class") or "").upper()
    if "CRIT" in sev:
        score *= 1.5
    elif "HIGH" in sev:
        score *= 1.2

    return score


# ---------------------------------------------------------------------------
# Section 0 — L17 verdict-shape contract (STATIC text from 12 §A)
# ---------------------------------------------------------------------------

_SEC0_TEXT = """\
## Section 0 — L17 verdict-shape contract (3-axis)

For every claim you produce in your reply, choose ONE of:

  - VERDICT CONTESTED: <reason> + <file:line> the primary missed
  - VERDICT HOLDS: invariant <X> at <file:line> (cite the invariant; no unqualified "agree")
  - NEEDS BUILD: <missing-evidence-class> + <acquisition-step>

The third axis is the L17 build-is-default rule. If your verdict is HOLDS or NEEDS-BUILD,
list at least one specific acquisition step (clone <repo>, extract <pin>, build <harness>,
instrument <test-environment>) that, if executed, would close the evidence gap.

DROP-only verdicts are accepted ONLY when one of these conditions is named verbatim:
  (a) "Evidence path structurally impossible: <reason>"
  (b) "Bug class definitionally cannot land on mainnet user: <reason>"
  (c) "Duplicate-clear filing already exists: <id>"
"""


def _build_sec0() -> Tuple[str, Dict]:
    return _SEC0_TEXT, {"items_count": 1, "items": [{"text": _SEC0_TEXT}]}


# ---------------------------------------------------------------------------
# Section 0.5 — Workspace-local clones inventory
# ---------------------------------------------------------------------------

def _build_sec05(workspace: pathlib.Path) -> Tuple[str, Dict]:
    """Walk <ws>/external/* and gather git HEAD SHAs."""
    ext_dir = workspace / "external"
    rows: List[Dict] = []

    if ext_dir.is_dir():
        for repo_dir in sorted(ext_dir.iterdir()):
            if not repo_dir.is_dir():
                continue
            head_sha = "(no .git)"
            try:
                proc = subprocess.run(
                    ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=10
                )
                if proc.returncode == 0:
                    head_sha = proc.stdout.strip()[:12]
            except Exception:
                pass

            # Check if it's a known audit-pin repo
            is_pin = "spark" in repo_dir.name.lower()
            refresh = "(unknown)"
            try:
                proc2 = subprocess.run(
                    ["git", "-C", str(repo_dir), "log", "-1", "--format=%ci"],
                    capture_output=True, text=True, timeout=10
                )
                if proc2.returncode == 0:
                    refresh = proc2.stdout.strip()[:10]
            except Exception:
                pass

            rows.append({
                "repo": repo_dir.name,
                "local_path": f"<workspace>/external/{repo_dir.name}",
                "head_sha": head_sha,
                "last_refresh": refresh,
                "audit_pin": "YES" if is_pin else "—",
            })

    lines = ["## Section 0.5 — Workspace-local clones inventory", ""]
    if rows:
        lines.append("| Repo | Local path | HEAD SHA | Last refresh | Audit-pin? |")
        lines.append("|---|---|---|---|---|")
        for r in rows:
            lines.append(
                f"| {r['repo']} | {r['local_path']} | `{r['head_sha']}` "
                f"| {r['last_refresh']} | {r['audit_pin']} |"
            )
    else:
        lines.append("_(no external clones found at `<workspace>/external/`)_")
    lines.append("")
    lines.append(
        "If your verdict relies on \"no callers anywhere,\" CHECK every clone above first.\n"
        "If a relevant repo is NOT cloned, your verdict MUST be NEEDS-BUILD with "
        "acquisition step \"clone <missing-repo>\"."
    )
    lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(rows), "items": rows}


# ---------------------------------------------------------------------------
# Section 0.7 — Queued leads not yet built
# ---------------------------------------------------------------------------

def _build_sec07(workspace: pathlib.Path, files: List[str]) -> Tuple[str, Dict]:
    """Read queued_leads from state file, filter by files overlap."""
    state_path = workspace / ".auditooor" / "spark_hunt_loop_state.json"
    queued: List[Dict] = []
    matched: List[Dict] = []
    state_available = state_path.is_file()

    if state_available:
        try:
            state = json.loads(state_path.read_text())
            queued = state.get("queued_leads", [])
            if not isinstance(queued, list):
                queued = []
        except Exception:
            queued = []

    file_basenames = {pathlib.Path(f).stem.lower() for f in files if f}
    file_set = {f.lower() for f in files if f}
    # Also collect path segments (directory components) from each file path
    file_path_segments: set = set()
    for f in files:
        if f:
            parts = pathlib.Path(f).parts
            for part in parts:
                if len(part) >= 6:  # ignore very short segments like "src", "lib"
                    file_path_segments.add(part.lower())

    for lead in queued:
        lead_paths = lead.get("paths", [])
        overlap = False
        for lp in lead_paths:
            lp_lower = lp.lower()
            if any(fb and len(fb) >= 6 and fb in lp_lower for fb in file_basenames):
                overlap = True
                break
            if any(f in lp_lower for f in file_set):
                overlap = True
                break
            if any(seg and seg in lp_lower for seg in file_path_segments):
                overlap = True
                break
        matched.append({**lead, "_scope_overlap": overlap})

    # Surface all queued leads — flagged if overlapping scope
    scope_matched = [m for m in matched if m["_scope_overlap"]]

    lines = ["## Section 0.7 — Queued leads not yet built", ""]
    if matched:
        lines.append("| Lane ID | Discovered iter | Hypothesis | L17 path | Rubric target | In-scope? |")
        lines.append("|---|---|---|---|---|---|")
        for m in matched:
            in_scope = "YES" if m["_scope_overlap"] else "—"
            hypothesis = str(m.get("shape", m.get("hypothesis", "(none)")))[:80]
            lines.append(
                f"| {m.get('lane_id', '?')} | {m.get('discovered_in', '?')} "
                f"| {hypothesis} | {m.get('l17_path', '?')} "
                f"| {m.get('rubric_target', '?')[:40]} | {in_scope} |"
            )
        lines.append("")
        if scope_matched:
            lines.append(
                "**SCOPE OVERLAP DETECTED** — the leads marked YES above intersect "
                "your file scope. Prepend those leads to your investigation. "
                "Don't re-derive what's already queued."
            )
    elif not state_available:
        lines.append(
            "_(queued-lead state unavailable: no workspace loop-state file found; "
            "do not infer there are no queued leads)_"
        )
    else:
        lines.append("_(no queued leads in state file)_")
    lines.append("")

    text = "\n".join(lines)
    return text, {
        "items_count": len(matched),
        "items": matched,
        "scope_matched": len(scope_matched),
        "state_available": state_available,
    }


# ---------------------------------------------------------------------------
# Section 0.9 — Lane-cooldown trigger states
# ---------------------------------------------------------------------------

def _build_sec09(workspace: pathlib.Path, lane_id: str) -> Tuple[str, Dict]:
    """Read lane_cooldowns, filter by lane_id family overlap."""
    state_path = workspace / ".auditooor" / "spark_hunt_loop_state.json"
    cooldowns: Dict = {}
    matched: List[Dict] = []
    state_available = state_path.is_file()

    if state_available:
        try:
            state = json.loads(state_path.read_text())
            cooldowns = state.get("lane_cooldowns", {})
            if not isinstance(cooldowns, dict):
                cooldowns = {}
        except Exception:
            cooldowns = {}

    # Match by lane_id prefix family overlap (H1 matches H1-*, W2 matches W2-*, etc.)
    lane_prefix = lane_id.split("-")[0] if "-" in lane_id else lane_id
    for cid, cdata in cooldowns.items():
        cid_prefix = cid.split("-")[0] if "-" in cid else cid
        if (
            lane_id.lower() in cid.lower()
            or cid.lower() in lane_id.lower()
            or cid_prefix == lane_prefix
        ):
            matched.append({
                "lane_id": cid,
                "since_iter": cdata.get("since_iter", "?"),
                "reason": cdata.get("reason", "?"),
                "trigger_state": cdata.get("trigger_state", {}),
            })

    lines = ["## Section 0.9 — Lane-cooldown trigger states (read-only)", ""]
    if matched:
        lines.append("| Lane ID | Since iter | Cooldown reason | Trigger-state |")
        lines.append("|---|---|---|---|")
        for m in matched:
            ts_str = json.dumps(m["trigger_state"])[:60] if m["trigger_state"] else "(none)"
            reason_short = str(m["reason"])[:80]
            lines.append(
                f"| {m['lane_id']} | {m['since_iter']} | {reason_short} | `{ts_str}` |"
            )
        lines.append("")
        lines.append(
            "If a cooldown's trigger_state HAS changed (audit-pin advanced, new clones "
            "landed, new corpus mined), the cooldown is expired — flag this in your reply."
        )
    elif not state_available:
        lines.append(
            "_(lane-cooldown state unavailable: no workspace loop-state file found; "
            "do not infer this lane has no cooldown history)_"
        )
    else:
        lines.append(
            "_(no cooldowns overlap with this lane's scope — no family match for "
            f"`{lane_id}`)_"
        )
    lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(matched), "items": matched, "state_available": state_available}


# ---------------------------------------------------------------------------
# Section 1 — Adversarial counter-brief shape
# ---------------------------------------------------------------------------

def _build_sec1() -> Tuple[str, Dict]:
    """Reuse adversarial-copilot.build_counter_brief() unchanged."""
    copilot_path = REPO / "tools" / "adversarial-copilot.py"

    try:
        spec = importlib.util.spec_from_file_location("adversarial_copilot", copilot_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            brief_text = mod.build_counter_brief(
                source=pathlib.Path("(hacker-brief-augmenter-generated)"),
                verdicts=[
                    "VERDICT CONTESTED: <reason> — the primary agent missed a path.",
                    "VERDICT HOLDS: invariant <X> at <file:line>",
                    "NEEDS BUILD: <missing-evidence-class> + <acquisition-step>",
                ],
            )
        else:
            raise ImportError("spec load failed")
    except Exception as e:
        brief_text = (
            "_(adversarial-copilot.py unavailable — counter-brief skipped; "
            f"error: {e})_"
        )

    lines = ["## Section 1 — Adversarial counter-brief shape (verdict-shape contract)", ""]
    lines.append(brief_text)
    text = "\n".join(lines)
    return text, {"items_count": 1, "items": [{"brief": brief_text}]}


# ---------------------------------------------------------------------------
# Vault MCP helpers
# ---------------------------------------------------------------------------

def _parse_json_stdout(stdout: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from tool stdout while tolerating bracketed log lines."""
    body = "\n".join(
        line for line in stdout.splitlines()
        if not line.startswith("[vault-mcp-server]")
    ).strip()
    if not body:
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _load_vault_context(
    workspace: pathlib.Path,
    call: str,
    args: Dict[str, Any],
    *,
    timeout: int = 30,
) -> Optional[Dict[str, Any]]:
    """Load a bounded Vault MCP context pack via the local CLI."""
    mcp_tool = REPO / "tools" / "vault-mcp-server.py"
    if not mcp_tool.is_file():
        return None
    normalized_args = json.dumps(args, sort_keys=True)
    cache_key = (str(workspace), call, normalized_args)
    if cache_key in _VAULT_CONTEXT_CACHE:
        return _VAULT_CONTEXT_CACHE[cache_key]
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(mcp_tool),
                "--call",
                call,
                "--args",
                normalized_args,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        _VAULT_CONTEXT_CACHE[cache_key] = None
        return None
    if proc.returncode != 0:
        _VAULT_CONTEXT_CACHE[cache_key] = None
        return None
    payload = _parse_json_stdout(proc.stdout)
    _VAULT_CONTEXT_CACHE[cache_key] = payload
    return payload


def _load_resume_context(workspace: pathlib.Path, max_items: int) -> Dict[str, Any]:
    return _load_vault_context(
        workspace,
        "vault_resume_context",
        {"workspace_path": str(workspace), "limit": max_items},
    ) or {}


def _load_exploit_context(workspace: pathlib.Path, max_items: int) -> Dict[str, Any]:
    return _load_vault_context(
        workspace,
        "vault_exploit_context",
        {"workspace_path": str(workspace), "limit": max_items},
    ) or {}


def _source_note(payload: Dict[str, Any], tool: str) -> str:
    pack_id = str(payload.get("context_pack_id") or "")
    if pack_id:
        return f"_Source: `{tool}` (`{pack_id}`)._"
    return f"_Source: `{tool}`._"


def _short(value: Any, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _normalize_worklist_predicates(
    raw_predicates: Any,
    *,
    max_predicates: int = _SEC3_MAX_PREDICATES_PER_STEP,
    max_hit_refs: int = _SEC3_MAX_HIT_REFS_PER_PREDICATE,
) -> List[Dict[str, Any]]:
    """Return bounded/safe advisory predicates from a step verdict."""
    if not isinstance(raw_predicates, list):
        return []
    rows: List[Dict[str, Any]] = []
    for raw in raw_predicates:
        if not isinstance(raw, dict):
            continue
        predicate_id = _short(raw.get("predicate_id"), 120)
        if not predicate_id:
            continue
        status = _short(raw.get("status"), 40) or "needs_evidence"
        advisory_only = bool(raw.get("advisory_only"))
        refs: List[str] = []
        for ref in (raw.get("hit_refs") if isinstance(raw.get("hit_refs"), list) else [])[:max_hit_refs]:
            ref_s = _short(ref, 220)
            if ref_s:
                refs.append(ref_s)
        rows.append(
            {
                "predicate_id": predicate_id,
                "status": status,
                "advisory_only": advisory_only,
                "hit_refs": refs,
            }
        )
        if len(rows) >= max_predicates:
            break
    return rows


def _collect_seq_worklist_predicates(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect unique advisory predicates from template-level + per-step fields."""
    seen: set[str] = set()
    rows: List[Dict[str, Any]] = []

    template_level = _normalize_worklist_predicates(item.get("worklist_predicates"), max_predicates=12)
    for pred in template_level:
        pid = pred.get("predicate_id", "")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        rows.append(pred)

    for step in (item.get("actor_sequence_verdicts") if isinstance(item.get("actor_sequence_verdicts"), list) else []):
        if not isinstance(step, dict):
            continue
        for pred in _normalize_worklist_predicates(step.get("worklist_predicates")):
            pid = pred.get("predicate_id", "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            rows.append(pred)
            if len(rows) >= 12:
                return rows
    return rows


def _rank_context_items(
    items: List[Dict[str, Any]],
    files: List[str],
    hint: Optional[str],
    max_items: int,
) -> List[Dict[str, Any]]:
    scored: List[Tuple[float, int, Dict[str, Any]]] = []
    for idx, item in enumerate(items):
        relevance = _relevance_score(item, files=files, hint=hint)
        score = relevance
        if relevance > 0:
            try:
                score += float(item.get("score") or 0)
            except (TypeError, ValueError):
                pass
        if item.get("workspace_scope_match") is True:
            score += 5.0
        if item.get("is_candidate") is True:
            score += 3.0
        try:
            if int(item.get("total_hits") or 0) > 0:
                score += 2.0
        except (TypeError, ValueError):
            pass
        if score > 0:
            scored.append((score, idx, item))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [item for _, _, item in scored[:max_items]]


# ---------------------------------------------------------------------------
# Section 2 — Case-study LOGIC
# ---------------------------------------------------------------------------

def _build_sec2(
    files: List[str],
    hint: Optional[str],
    max_items: int,
    resume_context: Dict[str, Any],
) -> Tuple[str, Dict]:
    raw_items = [row for row in resume_context.get("case_study_logic", []) if isinstance(row, dict)]
    items = _rank_context_items(raw_items, files, hint, max_items)
    lines = ["## Section 2 — Matched case-study LOGIC (top N=8)", ""]
    if resume_context:
        lines.extend([_source_note(resume_context, "vault_resume_context"), ""])
    if not items:
        lines.append("_(no case-study LOGIC matched this workspace/scope)_")
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "source": "vault_resume_context"}

    normalized: List[Dict[str, Any]] = []
    for item in items:
        case_id = str(item.get("case_id") or item.get("id") or "case-study")
        title = str(item.get("mechanism") or item.get("title") or case_id)
        normalized_item = {
            **item,
            "id": case_id,
            "title": title,
        }
        normalized.append(normalized_item)
        lines.append(f"### CS-{_slug(case_id)}: {title}")
        if item.get("class"):
            lines.append(f"- **Class**: `{_short(item.get('class'), 120)}`")
        if item.get("severity_class"):
            lines.append(f"- **Severity class**: `{_short(item.get('severity_class'), 80)}`")
        if item.get("extracted_lesson"):
            lines.append(f"- **Lesson**: {_short(item.get('extracted_lesson'), 360)}")
        if item.get("grep_predicates"):
            preds = item.get("grep_predicates") or []
            lines.append("- **Grep predicates**:")
            for pred in preds[:4]:
                lines.append(f"  - `{_short(pred, 180)}`")
        if item.get("runtime_predicates"):
            preds = item.get("runtime_predicates") or []
            lines.append("- **Runtime predicates**:")
            for pred in preds[:4]:
                lines.append(f"  - `{_short(pred, 180)}`")
        if item.get("source_file"):
            lines.append(f"- **Source**: `{_short(item.get('source_file'), 220)}`")
        lines.append("")
    return "\n".join(lines), {
        "items_count": len(normalized),
        "items": normalized,
        "source": "vault_resume_context.case_study_logic",
        "context_pack_id": resume_context.get("context_pack_id"),
    }


# ---------------------------------------------------------------------------
# Section 3 — Big-loss template actor sequences
# ---------------------------------------------------------------------------

def _build_sec3(
    files: List[str],
    hint: Optional[str],
    max_items: int,
    resume_context: Dict[str, Any],
) -> Tuple[str, Dict]:
    raw_items = [
        row for row in resume_context.get("big_loss_template_actor_sequences", [])
        if isinstance(row, dict)
    ]
    items = _rank_context_items(raw_items, files, hint, max_items)
    lines = ["## Section 3 — Big-loss template actor sequences (filtered)", ""]
    if resume_context:
        lines.extend([_source_note(resume_context, "vault_resume_context"), ""])
    if not items:
        lines.append("_(no big-loss actor sequence matched this workspace/scope)_")
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "source": "vault_resume_context"}

    normalized: List[Dict[str, Any]] = []
    for item in items:
        template_id = str(item.get("template_id") or item.get("id") or "template")
        title = str(item.get("title") or template_id)
        steps = [row for row in (item.get("actor_sequence_verdicts") or []) if isinstance(row, dict)]
        advisory_predicates = _collect_seq_worklist_predicates(item)
        normalized_item = {
            **item,
            "id": template_id,
            "title": title,
            "worklist_predicates": advisory_predicates,
        }
        normalized.append(normalized_item)
        lines.append(f"### SEQ-{_slug(template_id)}: {title}")
        lines.append(f"- **Workspace scope match**: `{str(item.get('workspace_scope_match') is True).lower()}`")
        for step in steps[:6]:
            step_no = step.get("step", "?")
            actor = _short(step.get("actor"), 80)
            action = _short(step.get("action"), 120)
            applicable = step.get("applicable")
            lines.append(f"- **Step {step_no}** `{actor}` -> `{action}`")
            if applicable is not None:
                lines.append(f"  - applicable: `{str(applicable).lower()}`")
            if step.get("evidence_required"):
                lines.append(f"  - evidence_required: {_short(step.get('evidence_required'), 240)}")
            if step.get("target"):
                lines.append(f"  - target: `{_short(step.get('target'), 180)}`")
            step_preds = _normalize_worklist_predicates(step.get("worklist_predicates"))
            if step_preds:
                lines.append("  - advisory_worklist_predicates:")
                for pred in step_preds:
                    refs = ", ".join(f"`{_short(ref, 120)}`" for ref in pred.get("hit_refs", [])) or "_(no hit refs)_"
                    lines.append(
                        "    - "
                        f"`{_short(pred.get('predicate_id'), 120)}` "
                        f"(status=`{_short(pred.get('status'), 40)}`, advisory_only=`{str(pred.get('advisory_only') is True).lower()}`)"
                    )
                    lines.append(f"      - hit_refs: {refs}")
        if advisory_predicates:
            lines.append("- **Advisory sequence predicates (for Section 13 worklist questions)**:")
            for pred in advisory_predicates[:8]:
                refs = ", ".join(f"`{_short(ref, 120)}`" for ref in pred.get("hit_refs", [])) or "_(no hit refs)_"
                lines.append(f"  - `{_short(pred.get('predicate_id'), 120)}` -> {refs}")
        lines.append("")
    return "\n".join(lines), {
        "items_count": len(normalized),
        "items": normalized,
        "source": "vault_resume_context.big_loss_template_actor_sequences",
        "context_pack_id": resume_context.get("context_pack_id"),
    }


# ---------------------------------------------------------------------------
# Section 4 — DeFiHackLabs class matches
# ---------------------------------------------------------------------------

def _build_sec4(
    files: List[str],
    hint: Optional[str],
    max_items: int,
    resume_context: Dict[str, Any],
) -> Tuple[str, Dict]:
    raw_items = [row for row in resume_context.get("defihack_class_matches", []) if isinstance(row, dict)]
    items = _rank_context_items(raw_items, files, hint, max_items)
    lines = ["## Section 4 — DeFiHackLabs class matches", ""]
    if resume_context:
        lines.extend([_source_note(resume_context, "vault_resume_context"), ""])
    if not items:
        lines.append("_(no DeFiHackLabs class match fired for this workspace/scope)_")
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "source": "vault_resume_context"}

    normalized: List[Dict[str, Any]] = []
    for item in items:
        row_id = str(item.get("id") or item.get("attack_class") or "defihack")
        attack_class = str(item.get("attack_class") or row_id)
        normalized_item = {
            **item,
            "id": row_id,
            "title": attack_class,
        }
        normalized.append(normalized_item)
        lines.append(f"### DH-{_slug(row_id)}: {attack_class}")
        if item.get("mechanism"):
            lines.append(f"- **Mechanism**: {_short(item.get('mechanism'), 360)}")
        if item.get("detector_status"):
            lines.append(f"- **Detector status**: `{_short(item.get('detector_status'), 120)}`")
        lines.append(f"- **Predicates with hits**: `{item.get('predicates_with_hits', 0)}`")
        lines.append(f"- **Total hits**: `{item.get('total_hits', 0)}`")
        lines.append(f"- **Candidate**: `{str(item.get('is_candidate') is True).lower()}`")
        if item.get("grep_predicates"):
            lines.append("- **Grep predicates**:")
            for pred in (item.get("grep_predicates") or [])[:4]:
                lines.append(f"  - `{_short(pred, 180)}`")
        if item.get("matched_predicates"):
            lines.append("- **Matched predicate refs**:")
            for pred in (item.get("matched_predicates") or [])[:4]:
                predicate = _short(pred.get("predicate"), 160)
                refs = ", ".join(
                    f"`{_short(ref, 120)}`" for ref in (pred.get("hit_refs") or [])[:3]
                ) or "_(no hit refs)_"
                lines.append(f"  - `{predicate}` -> {refs}")
        lines.append("")
    return "\n".join(lines), {
        "items_count": len(normalized),
        "items": normalized,
        "source": "vault_resume_context.defihack_class_matches",
        "context_pack_id": resume_context.get("context_pack_id"),
    }


# ---------------------------------------------------------------------------
# Section 5 — Engage-report detector fires (filtered by --files)
# ---------------------------------------------------------------------------

def _normalize_scope_path(path: str, workspace: Optional[pathlib.Path] = None) -> str:
    """Normalize a report/user path for exact path/basename overlap checks."""
    raw = str(path or "").strip().strip("`'\"")
    if not raw:
        return ""
    raw = raw.replace("\\", "/")
    raw = re.sub(r"^(workspace|file)[:/]+", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"[:#]\d+(?::\d+)?$", "", raw).strip()

    if workspace is not None:
        try:
            abs_candidate = pathlib.Path(raw).expanduser()
            if abs_candidate.is_absolute():
                raw = abs_candidate.resolve().relative_to(workspace.resolve()).as_posix()
        except (OSError, ValueError):
            pass

    parts = [part for part in pathlib.PurePosixPath(raw).parts if part not in ("", ".")]
    return "/".join(parts).lower()


def _paths_overlap_by_scope(
    selected_files: List[str],
    candidate_path: str,
    workspace: Optional[pathlib.Path] = None,
) -> bool:
    """Return true for exact normalized path, basename, or stem equality only."""
    candidate_norm = _normalize_scope_path(candidate_path, workspace)
    if not candidate_norm:
        return False
    candidate_name = pathlib.PurePosixPath(candidate_norm).name
    candidate_stem = pathlib.PurePosixPath(candidate_name).stem

    for selected in selected_files:
        selected_norm = _normalize_scope_path(selected, workspace)
        if not selected_norm:
            continue
        selected_name = pathlib.PurePosixPath(selected_norm).name
        selected_stem = pathlib.PurePosixPath(selected_name).stem
        if candidate_norm == selected_norm or candidate_name == selected_name:
            return True
        if selected_stem and candidate_stem and candidate_stem == selected_stem:
            return True
        if "/" in selected_norm and candidate_norm.endswith(f"/{selected_norm}"):
            return True
    return False


def _load_engage_report_context(workspace: pathlib.Path, max_items: int) -> Optional[Dict[str, Any]]:
    """Load detector clusters through Vault MCP; return None on graceful fallback."""
    return _load_vault_context(
        workspace,
        "vault_engage_report_context",
        {"workspace_path": str(workspace), "limit": max_items},
    )


def _filter_mcp_engage_items(
    payload: Dict[str, Any],
    files: List[str],
    max_items: int,
    workspace: Optional[pathlib.Path] = None,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for cluster in payload.get("clusters") or []:
        if not isinstance(cluster, dict):
            continue
        cluster_hits = cluster.get("hits")
        if not isinstance(cluster_hits, list):
            cluster_hits = cluster.get("fires") or cluster.get("items") or []
        fires: List[str] = []
        for hit in cluster_hits:
            if not isinstance(hit, dict):
                continue
            file_path = str(
                hit.get("file_path")
                or hit.get("path")
                or hit.get("file")
                or hit.get("location")
                or hit.get("loc")
                or ""
            )
            if not file_path:
                source_refs = hit.get("source_refs") or []
                if isinstance(source_refs, list):
                    file_path = str(source_refs[0]) if source_refs else ""
                elif isinstance(source_refs, str):
                    file_path = source_refs
            if files and not _paths_overlap_by_scope(files, file_path, workspace):
                continue
            sev = str(hit.get("severity") or hit.get("severity_class") or hit.get("sev") or "UNKNOWN")
            snippet = str(
                hit.get("snippet")
                or hit.get("message")
                or hit.get("excerpt")
                or hit.get("text")
                or ""
            )
            fire = f"[{sev}] {file_path}"
            if snippet:
                fire += f" — {snippet[:160]}"
            fires.append(fire)
        if fires:
            items.append(
                {
                    "detector": str(
                        cluster.get("detector_slug")
                        or cluster.get("detector")
                        or cluster.get("name")
                        or "(unknown)"
                    ),
                    "fires": fires[:5],
                    "count": len(fires),
                }
            )
        if len(items) >= max_items:
            break
    return items


def _build_sec5_from_items(items: List[Dict[str, Any]], source_note: str = "") -> str:
    lines = [
        "## Section 5 — Engage-report detector fires clustered by detector",
        "   (filtered to your --files only)",
        "",
    ]
    if source_note:
        lines.append(source_note)
        lines.append("")
    if items:
        for item in items:
            lines.append(f"### DET-{_slug(item['detector'])}: {item['detector']}")
            lines.append(f"- **Fires in your scope**: {item['count']}")
            for fire in item["fires"][:5]:
                lines.append(f"  - `{fire}`")
            lines.append("")
    else:
        lines.append("_(no engage_report.md fires overlap with the specified --files)_")
        lines.append("")
    return "\n".join(lines)


def _build_sec5_raw(workspace: pathlib.Path, files: List[str], max_items: int) -> Tuple[str, Dict]:
    """Fallback raw parser for legacy reports or unavailable MCP."""
    report_path = workspace / "engage_report.md"
    items: List[Dict] = []

    if not report_path.is_file():
        text = (
            "## Section 5 — Engage-report detector fires clustered by detector\n"
            "   (filtered to your --files only)\n\n"
            "_(engage_report.md not found — run `make audit WS=<workspace>` to generate)_\n"
        )
        return text, {"items_count": 0, "items": [], "missing": True}

    content = report_path.read_text(errors="replace")

    # Parse detector clusters: look for lines matching "file:line" patterns
    # engage_report.md format: lines like "  - path/to/file.go:123: <message>"
    current_detector: Optional[str] = None
    current_fires: List[str] = []

    for line in content.splitlines():
        # Detect section headers (detector names)
        hdr_match = re.match(r"^#+\s+(.+)", line)
        if hdr_match:
            if current_detector and current_fires:
                items.append({
                    "detector": current_detector,
                    "fires": current_fires[:],
                    "count": len(current_fires),
                })
            current_detector = hdr_match.group(1).strip()
            current_fires = []
            continue

        # Match fire lines: look for file:line patterns that intersect scope
        fire_match = re.search(r"([^\s:]+\.(go|sol|rs|ts|js|py))\s*:\s*(\d+)", line)
        if fire_match and current_detector:
            fired_file = fire_match.group(1)
            if _paths_overlap_by_scope(files, fired_file, workspace):
                current_fires.append(line.strip())

    # Flush last
    if current_detector and current_fires:
        items.append({
            "detector": current_detector,
            "fires": current_fires[:],
            "count": len(current_fires),
        })

    # Filter to only items with fires, then cap
    items = [i for i in items if i["fires"]]
    items_capped = items[:max_items]

    text = _build_sec5_from_items(items_capped, "_Source: raw `engage_report.md` fallback._")
    return text, {"items_count": len(items_capped), "items": items_capped, "source": "raw_fallback"}


def _build_sec5(workspace: pathlib.Path, files: List[str], max_items: int) -> Tuple[str, Dict]:
    """Load detector fires from Vault MCP, falling back to raw engage_report parsing."""
    payload = _load_engage_report_context(workspace, max_items)
    if payload and payload.get("report_found"):
        items = _filter_mcp_engage_items(payload, files, max_items, workspace)
        pack_id = str(payload.get("context_pack_id") or "")
        source_note = "_Source: `vault_engage_report_context`"
        if pack_id:
            source_note += f" (`{pack_id}`)"
        source_note += "._"
        text = _build_sec5_from_items(items, source_note)
        return text, {
            "items_count": len(items),
            "items": items,
            "source": "vault_engage_report_context",
            "context_pack_id": payload.get("context_pack_id"),
            "context_pack_hash": payload.get("context_pack_hash"),
        }

    return _build_sec5_raw(workspace, files, max_items)


# ---------------------------------------------------------------------------
# Section 5.5 — Go YAML pattern fallback (W2 plan §L5)
#
# When the worker's --files list includes Go files AND no compiled Go detector
# exists in `go_wave1/`, surface the YAML text-pattern catalog at
# `reference/patterns.dsl.r94_solodit_go/`. This is the documented fallback
# from the W2 mega plan §L5 — Go has 0 standalone detector modules in
# go_wave1/ as of 2026-05-10 despite N solodit Go patterns.
# ---------------------------------------------------------------------------


def _has_compiled_go_detector(repo: pathlib.Path = REPO) -> bool:
    """Return True iff any compiled Go detector module exists in go_wave1/."""
    det_dir = repo / _GO_COMPILED_DETECTOR_DIR
    if not det_dir.is_dir():
        return False
    for entry in det_dir.iterdir():
        # A compiled detector is a .py module (or a package dir with __init__.py)
        if entry.is_file() and entry.suffix == ".py" and entry.name != "__init__.py":
            return True
        if entry.is_dir() and (entry / "__init__.py").is_file():
            return True
    return False


def _load_go_yaml_patterns(
    repo: pathlib.Path = REPO,
    pattern_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load and parse all *.yaml files from the Go YAML pattern directory.

    Returns a list of dicts with stable keys: pattern_id, title, severity,
    bug_class, indicators, source_url, raw. Files that fail to parse are
    skipped silently (best-effort fallback).
    """
    pdir = repo / (pattern_dir or _GO_YAML_PATTERN_DIR)
    if not pdir.is_dir():
        return []

    try:
        import yaml  # type: ignore
    except ImportError:
        return []

    patterns: List[Dict[str, Any]] = []
    for yfile in sorted(pdir.glob("*.yaml")):
        try:
            data = yaml.safe_load(yfile.read_text(errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        indicators = data.get("indicators") or []
        if isinstance(indicators, str):
            indicators = [indicators]
        # Pull the first text-pattern indicator as the human-readable predicate
        first_indicator = ""
        for ind in indicators:
            if isinstance(ind, str):
                first_indicator = ind
                break
        patterns.append({
            "pattern_id": str(data.get("id", yfile.stem)),
            "title": str(data.get("title", "")).strip().replace("\n", " "),
            "severity": str(data.get("severity", "")),
            "bug_class": str(data.get("bug_class", "")),
            "indicator": first_indicator,
            "source_url": str(data.get("source_url", "")),
            "yaml_file": yfile.name,
        })
    return patterns


def _build_sec55(files: List[str], repo: pathlib.Path = REPO) -> Tuple[str, Dict]:
    """Emit the Go YAML pattern fallback section.

    Triggers IFF:
      - At least one path in `files` ends with `.go` (or contains a `.go` segment)
      - No compiled Go detector exists in `go_wave1/`
    Otherwise emits a "skipped" stub explaining why.
    """
    has_go = any(f for f in files if f and f.lower().endswith(".go"))
    compiled_present = _has_compiled_go_detector(repo)

    lines = [
        "## Section 5.5 — Go YAML pattern fallback "
        "(no compiled detectors in scope)",
        "",
    ]

    if not has_go:
        lines.append(
            "_(skipped — no `.go` files in scope; fallback only emits for Go workers)_"
        )
        lines.append("")
        return "\n".join(lines), {
            "items_count": 0,
            "items": [],
            "trigger": "skipped_no_go_files",
        }

    if compiled_present:
        lines.append(
            "_(skipped — `go_wave1/` contains compiled Go detector modules; "
            "compiled detector hits already surfaced via Section 5)_"
        )
        lines.append("")
        return "\n".join(lines), {
            "items_count": 0,
            "items": [],
            "trigger": "skipped_compiled_detectors_present",
        }

    patterns = _load_go_yaml_patterns(repo)
    if not patterns:
        lines.append(
            f"_(YAML fallback dir `{_GO_YAML_PATTERN_DIR}` is empty or unreadable)_"
        )
        lines.append("")
        return "\n".join(lines), {
            "items_count": 0,
            "items": [],
            "trigger": "yaml_dir_empty",
        }

    lines.append(
        "Compiled detectors are absent for Go scope; surfacing solodit-mined "
        "YAML text patterns. Use these as hunt seeds, not as detector hits."
    )
    lines.append("")
    lines.append("| Pattern ID | Description | Severity | Bug class | Indicator |")
    lines.append("|---|---|---|---|---|")
    for p in patterns:
        title = p["title"][:60].replace("|", "\\|")
        sev = p["severity"][:10] or "—"
        bclass = p["bug_class"][:24] or "—"
        ind = (p["indicator"] or "—")[:60].replace("|", "\\|")
        lines.append(
            f"| `{p['pattern_id']}` | {title} | {sev} | {bclass} | {ind} |"
        )
    lines.append("")
    lines.append(
        f"_Patterns loaded from `{_GO_YAML_PATTERN_DIR}/` (text-pattern "
        f"fallback for Go worker scope; no `{_GO_COMPILED_DETECTOR_DIR}/` "
        "compiled detectors exist as of 2026-05-10)._"
    )
    lines.append("")

    text = "\n".join(lines)
    return text, {
        "items_count": len(patterns),
        "items": patterns,
        "trigger": "fallback_emitted",
    }


# ---------------------------------------------------------------------------
# Section 6 — KILL_RUBRIC checklist
# ---------------------------------------------------------------------------

def _build_sec6(hint: Optional[str], max_items: int) -> Tuple[str, Dict]:
    """Read docs/KILL_RUBRIC_LIBRARY.md and match section by contract-type hint."""
    rubric_path = REPO / "docs" / "KILL_RUBRIC_LIBRARY.md"
    items: List[Dict] = []

    if not rubric_path.is_file():
        text = (
            "## Section 6 — KILL_RUBRIC checklist (matched to contract-type hint)\n\n"
            "_(KILL_RUBRIC_LIBRARY.md not found at docs/)_\n"
        )
        return text, {"items_count": 0, "items": [], "missing": True}

    content = rubric_path.read_text(errors="replace")

    # Parse real rubric sections and their checklist items. Do not treat the
    # document's top-level cross-reference metadata as a rubric.
    sections: Dict[str, List[str]] = {}
    current_section: Optional[str] = None
    in_rubric_checklist = False

    for line in content.splitlines():
        hdr = re.match(r"^(#+)\s+(.+)", line)
        if hdr:
            level = len(hdr.group(1))
            title = hdr.group(2).strip()
            if level == 2:
                current_section = title
                in_rubric_checklist = False
                sections.setdefault(current_section, [])
            elif level > 2:
                in_rubric_checklist = title.lower().startswith("rubric checklist")
            continue
        stripped = line.strip()
        if (
            current_section
            and in_rubric_checklist
            and (stripped.startswith("- [") or stripped.startswith("* ["))
        ):
            sections[current_section].append(line.strip())

    # Match section by hint
    matched_section: Optional[str] = None
    matched_items: List[str] = []

    if hint:
        h = hint.lower()
        for sec_name, sec_items in sections.items():
            if h in sec_name.lower() or any(h in it.lower() for it in sec_items[:3]):
                matched_section = sec_name
                matched_items = sec_items[:max_items]
                break

    lines = [
        "## Section 6 — KILL_RUBRIC checklist (matched to contract-type hint)",
        "",
    ]
    if matched_section:
        lines.append(f"**Matched section**: `{matched_section}`")
        lines.append("")
        for it in matched_items:
            lines.append(it)
        items = [{"section": matched_section, "item": it} for it in matched_items]
    else:
        if hint:
            lines.append("_(no match for contract-type hint in KILL_RUBRIC_LIBRARY.md)_")
        else:
            lines.append("_(no contract-type hint supplied; rubric checklist not selected)_")
    lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(items) if matched_section else 0, "items": items}


# ---------------------------------------------------------------------------
# Section 7 — Triager rejection patterns
# ---------------------------------------------------------------------------

def _build_sec7(files: List[str], hint: Optional[str], max_items: int) -> Tuple[str, Dict]:
    """Read reference/triager_patterns.md and filter by keyword overlap."""
    pat_path = REPO / "reference" / "triager_patterns.md"
    items: List[Dict] = []

    if not pat_path.is_file():
        text = (
            "## Section 7 — Triager rejection patterns to AVOID (filtered)\n\n"
            "_(triager_patterns.md not found)_\n"
        )
        return text, {"items_count": 0, "items": [], "missing": True}

    content = pat_path.read_text(errors="replace")
    file_basenames = [pathlib.Path(f).stem.lower() for f in files if f]
    hint_lower = (hint or "").lower()
    keywords = file_basenames + ([hint_lower] if hint_lower else [])

    # Parse R<N>-named pattern blocks
    pattern_blocks = re.split(r"\n(?=#+\s+R\d+|^R\d+)", content, flags=re.MULTILINE)
    for block in pattern_blocks:
        block = block.strip()
        if not block:
            continue
        hdr = re.search(r"R(\d+)[:\s]+(.+)", block)
        if not hdr:
            continue
        rid = f"R{hdr.group(1)}"
        title = hdr.group(2).strip()
        if any(kw and kw in block.lower() for kw in keywords):
            items.append({
                "id": rid,
                "title": title,
                "text": block[:400],
            })

    items = items[:max_items]

    lines = [
        "## Section 7 — Triager rejection patterns to AVOID (filtered)",
        "",
    ]
    if items:
        for it in items:
            lines.append(f"### {it['id']}: {it['title']}")
            for ln in it["text"].splitlines()[1:5]:
                lines.append(ln)
            lines.append("")
    else:
        lines.append("_(no matches in this category)_")
        lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Section 8 — Prior dupes / rejections
# ---------------------------------------------------------------------------

def _build_sec8(workspace: pathlib.Path, max_items: int) -> Tuple[str, Dict]:
    """Read REJECTION_CAUSES.md + DUPE_CAUSES.md from reference/."""
    ref_dir = REPO / "reference"
    items: List[Dict] = []

    for fname in ("REJECTION_CAUSES.md", "DUPE_CAUSES.md"):
        fpath = ref_dir / fname
        if not fpath.is_file():
            continue
        content = fpath.read_text(errors="replace")
        # Extract numbered items
        for m in re.finditer(r"(REJ-\w+|DUPE-\w+|^\d+\.\s+.+)", content, re.MULTILINE):
            items.append({"source": fname, "text": m.group(0)[:200]})
        if not items:
            # Fallback: first N non-empty lines
            for ln in content.splitlines():
                if ln.strip() and not ln.startswith("#"):
                    items.append({"source": fname, "text": ln.strip()[:200]})

    items = items[:max_items]

    lines = [
        "## Section 8 — Prior dupes / rejections in this domain",
        "",
    ]
    if items:
        for it in items:
            lines.append(f"- **[{it['source']}]** {it['text']}")
        lines.append("")
    else:
        lines.append("_(no matches in this category)_")
        lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Section 9 — Originality keywords
# ---------------------------------------------------------------------------

def _build_sec9(files: List[str], hint: Optional[str], max_items: int) -> Tuple[str, Dict]:
    """Read reference/originality_keywords.md and filter by bug class."""
    kw_path = REPO / "reference" / "originality_keywords.md"
    items: List[Dict] = []

    if not kw_path.is_file():
        text = (
            "## Section 9 — Originality keywords for this bug class\n\n"
            "_(originality_keywords.md not found)_\n"
        )
        return text, {"items_count": 0, "items": [], "missing": True}

    content = kw_path.read_text(errors="replace")
    file_basenames = [pathlib.Path(f).stem.lower() for f in files if f]
    hint_lower = (hint or "").lower()
    keywords = file_basenames + ([hint_lower] if hint_lower else [])

    # Emit lines that match scope
    matched_lines: List[str] = []
    in_match_section = False
    for line in content.splitlines():
        line_lower = line.lower()
        if any(kw and kw in line_lower for kw in keywords):
            matched_lines.append(line)
            in_match_section = True
        elif in_match_section and line.strip().startswith("-"):
            matched_lines.append(line)
        else:
            in_match_section = False

    matched_lines = matched_lines[:max_items * 4]

    lines = [
        "## Section 9 — Originality keywords for this bug class",
        "",
    ]
    if matched_lines:
        lines.extend(matched_lines)
        items = [{"text": ln} for ln in matched_lines]
    else:
        lines.append("_(no matches in this category)_")
    lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(matched_lines), "items": items}


# ---------------------------------------------------------------------------
# Section 10 — OOS clauses intersecting scope
# ---------------------------------------------------------------------------

def _build_sec10(workspace: pathlib.Path, files: List[str]) -> Tuple[str, Dict]:
    """Filter OOS_CHECKLIST.md + SCOPE.md to bullets mentioning --files basenames."""
    file_basenames = [pathlib.Path(f).stem.lower() for f in files if f]
    items: List[Dict] = []

    for fname in ("OOS_CHECKLIST.md", "SCOPE.md"):
        fpath = workspace / fname
        if not fpath.is_file():
            continue
        for line in fpath.read_text(errors="replace").splitlines():
            line_lower = line.lower()
            if any(bn and bn in line_lower for bn in file_basenames):
                items.append({"source": fname, "text": line.strip()})

    lines = [
        "## Section 10 — OOS clauses that intersect your scope",
        "",
    ]
    if items:
        for it in items:
            lines.append(f"- **[{it['source']}]** {it['text']}")
        lines.append("")
    else:
        lines.append("_(no OOS clauses intersect the specified --files basenames)_")
        lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Section 11 — Exploit-brief angles
# ---------------------------------------------------------------------------

def _build_sec11(
    files: List[str],
    hint: Optional[str],
    max_items: int,
    exploit_context: Dict[str, Any],
    workspace: Optional[pathlib.Path] = None,
) -> Tuple[str, Dict]:
    raw_items = [row for row in exploit_context.get("angles", []) if isinstance(row, dict)]
    items = _rank_context_items(raw_items, files, hint, max_items)
    lines = ["## Section 11 — Exploit-brief angles already considered", ""]
    if exploit_context:
        lines.extend([_source_note(exploit_context, "vault_exploit_context"), ""])
    if not items:
        lines.append("_(no exploit-context angles matched this workspace/scope)_")
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "source": "vault_exploit_context"}

    normalized: List[Dict[str, Any]] = []
    for item in items:
        angle_id = str(item.get("angle_id") or item.get("id") or "angle")
        title = str(item.get("title") or item.get("bug_class_id") or angle_id)
        normalized_item = {
            **item,
            "id": angle_id,
            "title": title,
        }
        normalized.append(normalized_item)
        lines.append(f"### ANG-{_slug(angle_id)}: {title}")
        if item.get("bug_class_id"):
            lines.append(f"- **Bug class**: `{_short(item.get('bug_class_id'), 120)}`")
        if item.get("confidence"):
            lines.append(f"- **Confidence**: `{_short(item.get('confidence'), 80)}`")
        if item.get("recommendation_status"):
            lines.append(f"- **Recommendation status**: `{_short(item.get('recommendation_status'), 120)}`")
        source_refs = [ref for ref in (item.get("source_refs") or []) if isinstance(ref, str)]
        if source_refs:
            lines.append("- **Source refs**:")
            for ref in source_refs[:5]:
                lines.append(f"  - `{_short(ref, 220)}`")
        proof_reqs = [
            row for row in (item.get("proof_prerequisites") or [])
            if isinstance(row, dict) and not _is_cross_workspace_noise(row, workspace)
        ]
        if proof_reqs:
            lines.append("- **Proof prerequisites**:")
            for req in proof_reqs[:4]:
                artifact = _short(req.get("artifact"), 160)
                status = _short(req.get("status"), 80)
                summary = _short(req.get("summary"), 220)
                lines.append(f"  - `{status}` `{artifact}` — {summary}")
        blockers = [
            str(row) for row in (item.get("not_submit_ready_until") or [])
            if row and not _is_cross_workspace_noise(row, workspace)
        ]
        normalized_item["proof_prerequisites"] = proof_reqs
        normalized_item["not_submit_ready_until"] = blockers
        if blockers:
            lines.append("- **Not submit-ready until**:")
            for blocker in blockers[:5]:
                lines.append(f"  - {_short(blocker, 220)}")
        lines.append("")
    return "\n".join(lines), {
        "items_count": len(normalized),
        "items": normalized,
        "source": "vault_exploit_context.angles",
        "context_pack_id": exploit_context.get("context_pack_id"),
    }


# ---------------------------------------------------------------------------
# Section 12 — Matched attacker frames (AMF-*)
# ---------------------------------------------------------------------------

def _build_sec12(files: List[str], hint: Optional[str], max_items: int) -> Tuple[str, Dict]:
    """Call relevant-rules-for-draft.py --frames-only --json via subprocess."""
    rr_path = REPO / "tools" / "relevant-rules-for-draft.py"
    items: List[Dict] = []

    if not rr_path.is_file():
        text = (
            "## Section 12 — Matched attacker frames (AMF-*)\n\n"
            "_(relevant-rules-for-draft.py not found)_\n"
        )
        return text, {"items_count": 0, "items": [], "missing": True}

    # Build a synthetic prompt seeded with files + hint for the subprocess call
    synthetic_prompt = " ".join(
        [pathlib.Path(f).name for f in files]
        + ([hint] if hint else [])
    )

    try:
        proc = subprocess.run(
            [sys.executable, str(rr_path), "--frames-only", "--json", "-"],
            input=synthetic_prompt,
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = json.loads(proc.stdout)
            frames = parsed.get("frames", [])
            if isinstance(frames, list):
                items = frames[:max_items]
        # Graceful: empty/malformed output → empty items
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass

    lines = [
        "## Section 12 — Matched attacker frames (AMF-*)",
        "",
    ]
    if items:
        for i, frame in enumerate(items):
            name = frame.get("name", frame.get("id", f"AMF-{i}"))
            lines.append(f"### {name}")
            for k in ("attacker_question", "mental_steps", "existing_corpus_anchors", "proven_yields"):
                if k in frame:
                    lines.append(f"- **{k}**: {frame[k]}")
            lines.append("")
    else:
        lines.append("_(no matches in this category)_")
        lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Section 15 — Codified rules applicable to this lane (R-rule digest)
# ---------------------------------------------------------------------------

# Lane-type to rule-id applicability map.
# Each lane type receives rules from the "all" bucket plus its own bucket.
_SEC15_LANE_RULE_MAP: Dict[str, List[str]] = {
    "all": ["R28", "R29", "R30", "R35", "R36", "R37", "R38", "R39", "R40", "R41"],
    "filing": ["R21", "R23", "R24", "R25", "R26", "R30", "R40", "R41", "R42", "R43", "R44", "R45"],
    "hunt": ["R24", "R25", "R40", "R42", "R43", "R44", "R45"],
    "miner": ["R36", "R37", "R38", "R39"],
    "detector": ["R38", "R39"],
    "dispute": ["R43", "R44", "R45"],
    "mediation": ["R43", "R44", "R45"],
    "triager-response": ["R43", "R44", "R45"],
}

_SEC15_DIGEST_PATH = "reference/codified_rules_digest.json"


def _build_sec15_hard_rules_digest(
    lane_type: str = "filing",
    repo: pathlib.Path = REPO,
) -> Tuple[str, Dict]:
    """Build Section 15: codified rules applicable to this lane subtype.

    Legacy fallback used when both MCP callables (vault_codified_rules_digest
    and vault_lane_skeleton_filler) are unavailable.

    1. Reads reference/codified_rules_digest.json if it exists.
    2. Filters by lane_type using _SEC15_LANE_RULE_MAP.
    3. Emits a markdown block prefixed with "## Codified rules applicable to this lane".
    4. Falls back gracefully if the digest is absent (warn-only, no block).

    Rule 37: this section emits documentation, not corpus records; no verification
    tier applies. The digest itself is kept authoritative by `make rule-sync`.
    """
    digest_path = repo / _SEC15_DIGEST_PATH

    lines = [
        "## Section 15 — Codified rules applicable to this lane",
        "",
        f"_Lane type: `{lane_type}`. Full digest: `{_SEC15_DIGEST_PATH}`._",
        "",
    ]

    if not digest_path.is_file():
        lines.append(
            f"_(warn: `{_SEC15_DIGEST_PATH}` not found - run `make rule-sync` to generate; "
            "section degraded gracefully)_"
        )
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "missing": True}

    try:
        digest = json.loads(digest_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        lines.append(
            f"_(warn: failed to parse `{_SEC15_DIGEST_PATH}`: {exc}; "
            "section degraded gracefully)_"
        )
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "parse_error": str(exc)}

    all_rules: List[Dict[str, Any]] = digest.get("rules", [])
    if not isinstance(all_rules, list):
        all_rules = []

    # Collect applicable rule IDs for this lane type
    applicable_ids: set = set(_SEC15_LANE_RULE_MAP.get("all", []))
    norm_lane = lane_type.lower().replace("_", "-")
    for key, ids in _SEC15_LANE_RULE_MAP.items():
        if key == "all":
            continue
        if key in norm_lane or norm_lane in key:
            applicable_ids.update(ids)

    # Filter and emit
    matched: List[Dict[str, Any]] = [
        r for r in all_rules
        if isinstance(r, dict) and r.get("rule_id") in applicable_ids
    ]

    if not matched:
        lines.append(
            f"_(no rules in digest match lane type `{lane_type}`; "
            "if this is wrong run `make rule-sync`)_"
        )
        lines.append("")
        return "\n".join(lines), {"items_count": 0, "items": [], "lane_type": lane_type}

    lines.append("| Rule | Name | Gate | Override |")
    lines.append("|------|------|------|----------|")
    items: List[Dict[str, Any]] = []
    for r in matched:
        rid = str(r.get("rule_id", "?"))
        name = str(r.get("name", ""))[:60]
        gate = str(r.get("mechanical_gate", "(none)"))[:80]
        override = str(r.get("override_marker", ""))[:40] or "(none)"
        lines.append(f"| **{rid}** | {name} | `{gate}` | `{override}` |")
        items.append(r)
    lines.append("")
    lines.append(
        "Cite each applicable rule by ID in your reply OR include the override marker. "
        "Override markers without operator approval are rejected by the orchestrator. "
        "Non-zero pre-submit-check.sh exit = NOT paste-ready."
    )
    lines.append("")

    text = "\n".join(lines)
    return text, {
        "items_count": len(items),
        "items": items,
        "lane_type": lane_type,
        "applicable_rule_ids": sorted(applicable_ids),
    }


def _build_sec15a_lane_rules_to_address(
    lane_type: str,
    severity: str,
    workspace_path: Optional[pathlib.Path],
) -> Tuple[str, Dict]:
    """Section 15a: lane-relevant rule list via vault_codified_rules_digest.

    Calls vault_codified_rules_digest with lane + severity filter and emits a
    compact list of must-address rule IDs + one-line description each.

    Falls back to the legacy digest-table Section 15 (warn-only) if the MCP
    callable is unavailable.
    """
    lines = [
        "## Section 15a — Lane-specific rules you MUST address",
        "",
        f"_Lane type: `{lane_type}`. Severity: `{severity}`._",
        "",
    ]

    ws = workspace_path or REPO
    payload = _load_vault_context(
        ws,
        "vault_codified_rules_digest",
        {
            "workspace_path": str(ws),
            "lane": lane_type,
            "severity": severity,
        },
        timeout=30,
    )

    if payload is None:
        lines.append(
            "_(warn: vault_codified_rules_digest unavailable - "
            "MCP callable not reachable; falling back to legacy digest table)_"
        )
        lines.append("")
        # Fall back: return the legacy section with a warn prefix
        legacy_text, legacy_meta = _build_sec15_hard_rules_digest(
            lane_type=lane_type,
            repo=REPO,
        )
        return lines[0] + "\n\n" + legacy_text, {
            **legacy_meta,
            "source": "legacy_fallback",
            "mcp_unavailable": True,
        }

    digest: List[Dict[str, Any]] = payload.get("digest") or []
    must_address: List[str] = payload.get("lane_specific_must_address") or []
    warnings: List[Dict[str, Any]] = payload.get("routine_violation_warnings") or []
    pack_id = str(payload.get("context_pack_id") or "")

    if pack_id:
        lines.append(f"_Source: `vault_codified_rules_digest` | pack `{pack_id}`_")
        lines.append("")

    if must_address:
        lines.append(f"**Lane-mandated rules** ({len(must_address)} must be addressed):")
        lines.append("")
        # Build a quick lookup from the digest list
        rule_lookup: Dict[str, Dict] = {
            str(r.get("rule_id", "")): r
            for r in digest
            if isinstance(r, dict)
        }
        for rid in must_address:
            rule = rule_lookup.get(str(rid), {})
            name = str(rule.get("name", ""))[:80] or "(no name in digest)"
            override = str(rule.get("override_marker", "") or "(none)")[:40]
            lines.append(f"- **{rid}**: {name} | override: `{override}`")
        lines.append("")

    if not digest and not must_address:
        lines.append(
            f"_(no rules returned for lane `{lane_type}` severity `{severity}`; "
            "run `make rule-sync` if this seems wrong)_"
        )
        lines.append("")

    if warnings:
        lines.append("**Top routine-violation warnings** (highest failure rate):")
        lines.append("")
        for w in warnings[:5]:
            wid = str(w.get("rule_id", "?"))
            remediation = str(w.get("one_line_remediation", ""))[:120]
            lines.append(f"- **{wid}**: {remediation}")
        lines.append("")

    lines.append(
        "Cite each rule by ID in your reply OR include the override marker. "
        "Non-zero pre-submit-check.sh exit = NOT paste-ready."
    )
    lines.append("")

    text = "\n".join(lines)
    return text, {
        "items_count": len(digest),
        "items": digest,
        "must_address": must_address,
        "lane_type": lane_type,
        "severity": severity,
        "source": "vault_codified_rules_digest",
        "context_pack_id": pack_id,
        "mcp_unavailable": False,
    }


def _build_sec15b_lane_skeleton_templates(
    lane_type: str,
    severity: str,
    workspace_path: Optional[pathlib.Path],
    target_finding_class: str = "",
) -> Tuple[str, Dict]:
    """Section 15b: fill-in-blank skeleton templates via vault_lane_skeleton_filler.

    Calls vault_lane_skeleton_filler and emits full skeleton templates inline
    with <<placeholder>> markers visible so the agent knows what to fill in.

    Falls back gracefully (warn-only, no block) if the callable is unavailable
    or if no skeletons exist for the given lane type.
    """
    lines = [
        "## Section 15b — Rule-section skeleton templates (fill in <<placeholders>>)",
        "",
        f"_Lane type: `{lane_type}`. Severity: `{severity}`._",
        "",
    ]

    ws = workspace_path or REPO
    mcp_args: Dict[str, Any] = {
        "lane_type": lane_type,
        "severity": severity,
    }
    if target_finding_class:
        mcp_args["target_finding_class"] = target_finding_class
    if workspace_path is not None:
        mcp_args["workspace_path"] = str(workspace_path)

    payload = _load_vault_context(
        ws,
        "vault_lane_skeleton_filler",
        mcp_args,
        timeout=30,
    )

    if payload is None:
        lines.append(
            "_(warn: vault_lane_skeleton_filler unavailable - "
            "MCP callable not reachable; no skeleton templates injected)_"
        )
        lines.append("")
        text = "\n".join(lines)
        return text, {
            "items_count": 0,
            "items": [],
            "source": "vault_lane_skeleton_filler",
            "mcp_unavailable": True,
        }

    # Check for error response (unknown lane_type)
    if payload.get("error"):
        err = str(payload.get("error", ""))
        valid = payload.get("valid_lane_types", [])
        lines.append(
            f"_(warn: vault_lane_skeleton_filler returned error `{err}`; "
            f"valid lane types: {valid}; no skeleton templates injected)_"
        )
        lines.append("")
        text = "\n".join(lines)
        return text, {
            "items_count": 0,
            "items": [],
            "source": "vault_lane_skeleton_filler",
            "error": err,
            "mcp_unavailable": False,
        }

    pack_id = str(payload.get("context_pack_id") or "")
    applicable_rules: List[str] = payload.get("applicable_rules") or []
    skeleton_sections: Dict[str, str] = payload.get("skeleton_sections") or {}
    placeholders: Dict[str, List[str]] = payload.get("placeholders_to_resolve") or {}
    workspace_anchors: Dict[str, str] = payload.get("workspace_anchors") or {}
    usage_note = str(payload.get("usage_note") or "")

    if pack_id:
        lines.append(f"_Source: `vault_lane_skeleton_filler` | pack `{pack_id}`_")
        lines.append("")

    if not skeleton_sections:
        lines.append(
            f"_(no skeleton templates for lane `{lane_type}` at severity `{severity}`; "
            "this is expected for hunt lanes which have no .tmpl files)_"
        )
        lines.append("")
        text = "\n".join(lines)
        return text, {
            "items_count": 0,
            "items": applicable_rules,
            "applicable_rules": applicable_rules,
            "source": "vault_lane_skeleton_filler",
            "context_pack_id": pack_id,
            "mcp_unavailable": False,
            "no_templates": True,
        }

    if applicable_rules:
        lines.append(f"**Applicable rules for this lane** ({len(applicable_rules)}): "
                     + ", ".join(f"`{r}`" for r in applicable_rules))
        lines.append("")

    if usage_note:
        lines.append(f"_{usage_note}_")
        lines.append("")

    # Emit each skeleton with its placeholders
    for rid, skeleton_text in skeleton_sections.items():
        lines.append(f"### Skeleton for {rid}")
        lines.append("")
        lines.append("```")
        lines.append(skeleton_text)
        lines.append("```")
        lines.append("")
        phs = placeholders.get(rid, [])
        if phs:
            lines.append(f"**Placeholders to resolve** ({len(phs)}):")
            for ph in phs:
                lines.append(f"- `{ph}`")
            lines.append("")
        # Workspace anchors for this rule
        anchor = workspace_anchors.get(rid, "")
        if anchor:
            lines.append(f"_Workspace anchor_: `{anchor}`")
            lines.append("")

    text = "\n".join(lines)
    return text, {
        "items_count": len(skeleton_sections),
        "items": list(skeleton_sections.keys()),
        "applicable_rules": applicable_rules,
        "skeleton_rule_ids": list(skeleton_sections.keys()),
        "source": "vault_lane_skeleton_filler",
        "context_pack_id": pack_id,
        "mcp_unavailable": False,
    }


# ---------------------------------------------------------------------------
# Cross-workspace noise guard
# ---------------------------------------------------------------------------

def _is_cross_workspace_noise(value: Any, workspace: Optional[pathlib.Path]) -> bool:
    """Filter known workspace-specific blockers when rendering another workspace."""
    if workspace is None:
        return False
    workspace_name = workspace.name.lower()
    text = json.dumps(value, sort_keys=True).lower() if isinstance(value, dict) else str(value).lower()
    if "spark" in workspace_name:
        return False
    return any(
        marker in text
        for marker in (
            "spark-",
            "spark-go-poc-toolchain-absent",
            "docs/spark",
            "spark-engagement",
            "/spark/",
        )
    )


# ---------------------------------------------------------------------------
# Section 13 — Question list
# ---------------------------------------------------------------------------

def _load_attack_class_ranker_module() -> Optional[Any]:
    """Load the local attack-class ranker without making it a package import."""
    ranker_path = REPO / "tools" / "attack-class-ranker.py"
    if not ranker_path.is_file():
        return None
    try:
        module_name = "_auditooor_attack_class_ranker"
        spec = importlib.util.spec_from_file_location(module_name, ranker_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod
    except Exception:
        return None


def _attack_class_ranker_query_text(
    sec5_data: Dict[str, Any],
    scoped_files: Optional[List[str]],
    hint: Optional[str],
) -> str:
    parts: List[str] = []
    if hint:
        parts.append(str(hint))
    for file_path in scoped_files or []:
        file_text = str(file_path).strip()
        if file_text:
            parts.append(file_text)
    for item in sec5_data.get("items", []):
        if not isinstance(item, dict):
            continue
        detector = str(item.get("detector") or "").strip()
        if detector:
            parts.append(detector)
        for fire in (item.get("fires") if isinstance(item.get("fires"), list) else [])[:5]:
            fire_text = str(fire).strip()
            if fire_text:
                parts.append(fire_text)
    return " ".join(parts)


def _attack_class_ranker_questions(
    sec5_data: Dict[str, Any],
    scoped_files: Optional[List[str]] = None,
    hint: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return bounded advisory Q-AC-* questions from local ranker output."""
    query_text = _attack_class_ranker_query_text(sec5_data, scoped_files, hint)
    if not query_text.strip():
        return []
    ranker = _load_attack_class_ranker_module()
    if ranker is None:
        return []

    try:
        repo_root = getattr(ranker, "REPO_ROOT", REPO)
        if hasattr(ranker, "run"):
            payload = ranker.run(
                [
                    "--repo-root",
                    str(repo_root),
                    "--context",
                    query_text,
                    "--top-n",
                    str(_SEC13_MAX_ATTACK_CLASS_QUESTIONS),
                ]
            )
            ranked = payload.get("ranked_attack_classes", []) if isinstance(payload, dict) else []
        else:
            patterns_dir = getattr(ranker, "DEFAULT_PATTERNS_DIR", REPO / "reference" / "patterns.dsl")
            defihack_catalog = getattr(
                ranker,
                "DEFAULT_DEFIHACK_CATALOG",
                REPO / "defihacklabs" / "catalog.yaml",
            )
            items = ranker.load_patterns(patterns_dir, repo_root) + ranker.load_defihack(
                defihack_catalog,
                repo_root,
            )
            ranked = ranker.rank_attack_classes(
                query_text=query_text,
                items=items,
                top_n=_SEC13_MAX_ATTACK_CLASS_QUESTIONS,
            )
    except Exception:
        return []

    questions: List[Dict[str, Any]] = []
    for row in ranked[:_SEC13_MAX_ATTACK_CLASS_QUESTIONS]:
        if not isinstance(row, dict):
            continue
        attack_class = str(row.get("attack_class") or "").strip()
        if not attack_class:
            continue
        evidence_refs: List[str] = []
        analogue_evidence: List[Dict[str, Any]] = []
        for ref_group in ("analogue_refs", "evidence_refs"):
            for ref in (row.get(ref_group) if isinstance(row.get(ref_group), list) else []):
                if not isinstance(ref, dict):
                    continue
                ref_text = str(ref.get("source_ref") or ref.get("item_id") or "").strip()
                if ref_text and ref_text not in evidence_refs:
                    evidence_refs.append(ref_text)
                if ref_group != "analogue_refs":
                    continue
                grep_predicates = [
                    str(pred).strip()
                    for pred in (ref.get("grep_predicates") if isinstance(ref.get("grep_predicates"), list) else [])
                    if str(pred).strip()
                ][:3]
                runtime_predicates = [
                    str(pred).strip()
                    for pred in (
                        ref.get("runtime_predicates") if isinstance(ref.get("runtime_predicates"), list) else []
                    )
                    if str(pred).strip()
                ][:3]
                mechanism = str(ref.get("mechanism") or "").strip()
                if ref_text and (mechanism or grep_predicates or runtime_predicates):
                    analogue_evidence.append(
                        {
                            "source_ref": ref_text,
                            "source_kind": str(ref.get("source_kind") or "").strip(),
                            "mechanism": mechanism,
                            "grep_predicates": grep_predicates,
                            "runtime_predicates": runtime_predicates,
                        }
                    )
        matched_terms = [
            str(term)
            for term in (row.get("matched_terms") if isinstance(row.get("matched_terms"), list) else [])
            if str(term).strip()
        ][:6]
        evidence_ref_text = ", ".join(f"`{_short(ref, 120)}`" for ref in evidence_refs[:3])
        if not evidence_ref_text:
            evidence_ref_text = "ranker-local corpus refs"
        predicate_bits: List[str] = []
        for ref in analogue_evidence[:2]:
            bits: List[str] = []
            mechanism = str(ref.get("mechanism") or "").strip()
            if mechanism:
                bits.append(f"mechanism `{_short(mechanism, 100)}`")
            grep_preds = ref.get("grep_predicates") if isinstance(ref.get("grep_predicates"), list) else []
            runtime_preds = ref.get("runtime_predicates") if isinstance(ref.get("runtime_predicates"), list) else []
            if grep_preds:
                bits.append("grep " + ", ".join(f"`{_short(str(pred), 60)}`" for pred in grep_preds[:2]))
            if runtime_preds:
                bits.append("runtime " + ", ".join(f"`{_short(str(pred), 70)}`" for pred in runtime_preds[:2]))
            if bits:
                predicate_bits.append(f"{_short(str(ref.get('source_ref') or ''), 80)}: " + "; ".join(bits))
        predicate_text = ""
        if predicate_bits:
            predicate_text = " Analogue predicates to prove/kill: " + " | ".join(predicate_bits) + "."
        questions.append(
            {
                "id": f"Q-AC-{_slug(attack_class)}",
                "text": (
                    f"Advisory attack-class check: for ranked hypothesis `{attack_class}`, "
                    "which source-level preconditions hold or fail in this scoped lane?"
                ),
                "evidence": (
                    f"Ranker refs: {evidence_ref_text}; confirm/refute with source anchors "
                    "and control/data-flow evidence only (not proof-of-exploit, not severity assignment)."
                    f"{predicate_text}"
                ),
                "advisory_only": True,
                "source_section": "sec13_attack_class_ranker",
                "attack_class": attack_class,
                "rank": row.get("rank"),
                "confidence": row.get("confidence"),
                "claim_scope": row.get("claim_scope") or "hypothesis_prioritization_only",
                "matched_terms": matched_terms,
                "evidence_refs": evidence_refs[:3],
                "analogue_evidence": analogue_evidence[:3],
            }
        )
    return questions


def _build_sec13(
    sec2_data: Dict,
    sec3_data: Dict,
    sec4_data: Dict,
    sec6_data: Dict,
    sec11_data: Dict,
    sec5_data: Dict,
    sec55_data: Dict,
    sec12_data: Dict,
    sec8_data: Optional[Dict] = None,
    sec10_data: Optional[Dict] = None,
    scoped_files: Optional[List[str]] = None,
    hint: Optional[str] = None,
) -> Tuple[str, Dict]:
    """Derive Q-* questions deterministically from preceding sections."""
    questions: List[Dict] = []
    seen_ids: set[str] = set()

    def _append_question(row: Dict[str, Any]) -> None:
        qid = str(row.get("id") or "").strip()
        if not qid or qid in seen_ids:
            return
        seen_ids.add(qid)
        questions.append(row)

    # Q-CS-* from case-study items (sec2)
    for i, item in enumerate(sec2_data.get("items", []), 1):
        title = item.get("title", item.get("id", f"item-{i}"))
        q = {
            "id": f"Q-CS-{i:03d}",
            "text": f"Does the code violate the predicate in case-study `{title}`?",
            "evidence": "Source-anchor or runtime check",
        }
        _append_question(q)

    # Q-SEQ-* from big-loss actor sequences (sec3)
    for i, item in enumerate(sec3_data.get("items", []), 1):
        title = item.get("title", item.get("template_id", f"sequence-{i}"))
        seq_id = item.get("template_id", item.get("id", f"sequence-{i}"))
        q = {
            "id": f"Q-SEQ-{_slug(str(seq_id))}",
            "text": f"Can attacker execute big-loss actor sequence `{title}` against this scope?",
            "evidence": "Step-by-step actor evidence or explicit broken prerequisite",
        }
        _append_question(q)

        seq_preds = _collect_seq_worklist_predicates(item)
        for pred in seq_preds[:_SEC13_MAX_SEQ_PREDICATE_QUESTIONS]:
            predicate_id = str(pred.get("predicate_id") or "").strip()
            if not predicate_id:
                continue
            hit_refs = [str(ref) for ref in (pred.get("hit_refs") or []) if str(ref).strip()]
            refs_text = ", ".join(f"`{_short(ref, 120)}`" for ref in hit_refs[:3]) or "_(no hit refs)_"
            q_pred = {
                "id": f"Q-SEQ-{_slug(str(seq_id))}-{_slug(predicate_id)}",
                "text": (
                    f"Advisory worklist: does predicate `{predicate_id}` hold for sequence `{title}` "
                    f"given observed refs: {refs_text}?"
                ),
                "evidence": (
                    "Confirm/refute with source anchors; advisory signal only "
                    "(not proof-of-exploit, not severity assignment)."
                ),
                "advisory_only": True,
                "predicate_id": predicate_id,
                "hit_refs": hit_refs[:3],
            }
            _append_question(q_pred)

    # Q-DH-* from DeFiHackLabs class matches (sec4)
    for i, item in enumerate(sec4_data.get("items", []), 1):
        title = item.get("title", item.get("attack_class", f"defihack-{i}"))
        row_id = item.get("id", item.get("attack_class", f"defihack-{i}"))
        q = {
            "id": f"Q-DH-{_slug(str(row_id))}",
            "text": f"Does DeFiHackLabs class `{title}` produce a concrete candidate path here?",
            "evidence": "Matched DefiHack predicate refs plus exploitability check",
        }
        _append_question(q)

    # Q-RUB-* from kill-rubric items (sec6)
    for i, item in enumerate(sec6_data.get("items", []), 1):
        chk = item.get("item", item.get("section", f"rubric-{i}"))
        q = {
            "id": f"Q-RUB-{i}",
            "text": f"Does the contract pass kill-rubric: `{chk[:80]}`?",
            "evidence": "Checklist verification against source",
        }
        _append_question(q)

    # Q-ANG-* from exploit angles (sec11)
    for i, item in enumerate(sec11_data.get("items", []), 1):
        title = item.get("title", f"angle-{i}")
        q = {
            "id": f"Q-ANG-{i}",
            "text": f"Was exploit angle `{title}` investigated end-to-end?",
            "evidence": "Proof-requirement + PoC attempt",
        }
        _append_question(q)

    # Q-DET-* from engage-report fires (sec5)
    for i, item in enumerate(sec5_data.get("items", []), 1):
        det = item.get("detector", f"det-{i}")
        q = {
            "id": f"Q-DET-{_slug(det)}",
            "text": f"Was detector fire `{det}` investigated end-to-end?",
            "evidence": "File:line confirmed or ruled out",
        }
        _append_question(q)

    # Q-AC-* from local attack-class ranker hypotheses.
    for q in _attack_class_ranker_questions(sec5_data, scoped_files, hint):
        _append_question(q)

    # Q-PAT-* from Go YAML pattern predicates (sec5.5 fallback)
    for i, item in enumerate(sec55_data.get("items", []), 1):
        pattern_id = str(item.get("pattern_id") or f"go-pattern-{i}")
        indicator = str(item.get("indicator") or item.get("title") or pattern_id)
        q = {
            "id": f"Q-PAT-{_slug(pattern_id)}",
            "text": (
                f"Does in-scope code satisfy fallback predicate `{indicator[:120]}` "
                f"from `{pattern_id}`?"
            ),
            "evidence": "Source-anchor + data/control-flow confirmation",
        }
        _append_question(q)

    # Q-PRIOR-* from prior dupe/rejection cause rows (sec8)
    for i, item in enumerate((sec8_data or {}).get("items", []), 1):
        if i > _SEC13_MAX_PRIOR_OUTCOME_QUESTIONS:
            break
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "prior-outcome")
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        q = {
            "id": f"Q-PRIOR-{_slug(source)}-{i}",
            "text": (
                f"Advisory prior-outcome check: does Section 8 `{source}` row "
                f"`{_short(text, 140)}` match this lane closely enough to require "
                "duplicate/rejection handling?"
            ),
            "evidence": (
                "Compare candidate mechanics, affected paths, and prior outcome refs; "
                "advisory triage signal only (not proof-of-exploit, not severity assignment)."
            ),
            "advisory_only": True,
            "source_section": "sec8_prior_dupes",
            "source": source,
        }
        _append_question(q)

    # Q-OOS-* from in-scope OOS clauses (sec10)
    for i, item in enumerate((sec10_data or {}).get("items", []), 1):
        if i > _SEC13_MAX_OOS_QUESTIONS:
            break
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "oos-clause")
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        q = {
            "id": f"Q-OOS-{_slug(source)}-{i}",
            "text": (
                f"Advisory OOS check: what direct proof would defeat likely out-of-scope "
                f"rejection for Section 10 `{source}` clause `{_short(text, 140)}`?"
            ),
            "evidence": (
                "Show the affected in-scope path, impacted asset/accounting surface, or "
                "explicit scope language that keeps the candidate in-bounds; advisory "
                "triage signal only (not proof-of-exploit, not severity assignment)."
            ),
            "advisory_only": True,
            "source_section": "sec10_oos_clauses",
            "source": source,
        }
        _append_question(q)

    # Q-RULE-* from structured attacker-frame questions (sec12)
    sec12_structured_rules = 0
    for i, item in enumerate(sec12_data.get("items", []), 1):
        if not isinstance(item, dict):
            continue
        frame_name = str(item.get("name") or item.get("id") or f"frame-{i}")
        frame_question = str(item.get("attacker_question") or "").strip()
        if not frame_question:
            continue
        sec12_structured_rules += 1
        q = {
            "id": f"Q-RULE-{_slug(frame_name)}",
            "text": (
                f"Advisory rule-check: does this lane violate or clear Section 12 attacker-frame "
                f"question `{frame_question}` (frame `{frame_name}`)?"
            ),
            "evidence": (
                "Source anchors and control/data-flow checks only; advisory signal "
                "(not proof-of-exploit, not severity assignment)."
            ),
            "advisory_only": True,
            "source_section": "sec12_amf_frames",
            "frame_name": frame_name,
        }
        _append_question(q)

    # Always include the L31 dupe question
    _append_question({
        "id": "Q-DUPE",
        "text": "Does this candidate pass L31 Q1+Q2 against any prior filing in this workspace?",
        "evidence": "tools/duplicate-preflight-check.py output",
    })

    lines = [
        "## Section 13 — Question-list to answer with PASS/FAIL/UNKNOWN+evidence",
        "                 (parsed by audit-question-burndown.py — W2-G)",
        "",
    ]
    for i, q in enumerate(questions, 1):
        lines.append(f"{i}. **{q['id']}**: {q['text']}")
        lines.append(f"   Evidence: {q['evidence']}")
    if sec12_data.get("items") and sec12_structured_rules == 0:
        lines.append("")
        lines.append(
            "_Section 12 frames lacked structured `attacker_question` fields; "
            "no `Q-RULE-*` items emitted._"
        )
    lines.append("")

    text = "\n".join(lines)
    return text, {"items_count": len(questions), "items": questions}


# ---------------------------------------------------------------------------
# Section: Function-Mindset Cheat Sheet (D-1 — inject-function-mindset)
# ---------------------------------------------------------------------------

def _is_handler_like(rec: Dict[str, Any]) -> bool:
    """Return True if the function is a plausible security-relevant handler.

    Heuristics (OR-logic):
      - Name matches _HANDLER_HEURISTIC (handle/process/register/update/set/
        exec/create/withdraw/deposit)
      - Receiver type is in msg-server-family or hook-family
    """
    name = rec.get("function_name") or ""
    recv_family = rec.get("receiver_family", "")
    if _HANDLER_HEURISTIC.search(name):
        return True
    if recv_family in _HANDLER_RECEIVER_FAMILIES:
        return True
    return False


def _compute_receiver_family_for_rec(rec: Dict[str, Any]) -> str:
    """Return receiver_family for a function record.

    Uses the same RECEIVER_FAMILY_RULES as shape-hash.py but avoids
    importlib to prevent module isolation issues under Python 3.14.
    """
    recv = (rec.get("receiver_type") or "").lstrip("*").strip()
    if recv and "." in recv:
        recv = recv.split(".")[-1]
    for family, needles in [
        ("msg-server-family", ["msgServer", "MsgServer", "Keeper", "GovKeeper"]),
        ("ibc-module", ["IBCModule", "IBCMiddleware"]),
        ("hook-family", ["Hook", "IPostHook", "Hooks"]),
        ("amm-pool-family", ["Vault", "Pool", "Pair", "AMM"]),
        ("token-family", ["ERC20", "ERC4626", "Bank", "Token"]),
    ]:
        for needle in needles:
            if needle in recv:
                return family
    return "misc-family"


def _extract_functions_for_file(
    file_path: str,
    workspace: Optional[pathlib.Path] = None,
) -> List[Dict[str, Any]]:
    """Extract Go function signatures from a single file using function-signature-extractor.

    Runs the extractor as a subprocess (avoids importlib module isolation
    issues under Python 3.14) and returns parsed JSONL records.
    File must end in .go; other languages silently return [].

    Resolution order for the source file:
      1. workspace / file_path (workspace-relative)
      2. file_path as absolute path
    If neither resolves to an existing file, returns [].
    """
    if not file_path.lower().endswith(".go"):
        return []

    # Resolve: try workspace-relative, then treat as absolute/direct
    resolved: Optional[pathlib.Path] = None
    if workspace is not None:
        candidate = workspace / file_path
        if candidate.is_file():
            resolved = candidate
    if resolved is None:
        p = pathlib.Path(file_path)
        if p.is_file():
            resolved = p
    if resolved is None:
        return []

    extractor_path = REPO / "tools" / "function-signature-extractor.py"
    if not extractor_path.is_file():
        return []

    try:
        # The extractor walks a repo root; for a single file we pass its
        # parent directory and filter to only the target file.
        parent_dir = resolved.parent
        proc = subprocess.run(
            [
                sys.executable,
                str(extractor_path),
                str(parent_dir),
                "--language", "go",
                "--filter-test-files",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        recs: List[Dict[str, Any]] = []
        target_basename = pathlib.Path(file_path).name
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Only keep records from our target file (extractor walks the dir)
            rec_fp = rec.get("file_path", "")
            if pathlib.Path(rec_fp).name == target_basename:
                # Re-annotate file_path with the original relative path so
                # ranker lookup can match against sig_extracts JSONL.
                rec["file_path"] = file_path
                recs.append(rec)
        return recs
    except (subprocess.TimeoutExpired, Exception):
        return []


################################################################################
# Ranker invocation — in-process (Wave-7 perf upgrade)                        #
################################################################################
# Wave-6 Phase D-1 used subprocess-per-function due to Python 3.14's stricter
# dataclass.__module__ validation: dynamically-loaded modules via
# importlib.util.module_from_spec() have __module__ == <the name string>, but
# dataclasses._is_type() does sys.modules.get(cls.__module__).__dict__ which
# returned None because the module wasn't pre-registered in sys.modules.
#
# Fix (Wave-7): pre-register the module in sys.modules BEFORE calling
# spec.loader.exec_module(). Speedup: subprocess startup overhead (~50-100ms)
# eliminated; 4 functions 1.32s → ~0.29s (4.5x), 30 functions 3.10s → ~1.0s.
# Subprocess fallback retained for backward compat.
#
# context_pack_id: auditooor.vault_context_pack.v1:resume:0f215322f432e859
# context_pack_hash: 0f215322f432e85958d7066d789a969fde5a36155a57b8d5f3d2bc5d62a677ea

_RANKER_MOD_AUGMENTER = None  # cached in-process module; loaded once per process


def _load_ranker_module_augmenter():
    """Load tools/ranker.py in-process, caching the result.

    Uses sys.modules pre-registration to satisfy Python 3.14's dataclass
    __module__ validation. Returns the module or None (caller falls back
    to subprocess).
    """
    global _RANKER_MOD_AUGMENTER
    if _RANKER_MOD_AUGMENTER is not None:
        return _RANKER_MOD_AUGMENTER
    ranker_path = REPO / "tools" / "ranker.py"
    if not ranker_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_auditooor_ranker_aug", str(ranker_path))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        # Pre-register BEFORE exec_module — required for Python 3.14 dataclass
        # __module__ validation (dataclasses._is_type checks sys.modules).
        sys.modules["_auditooor_ranker_aug"] = mod
        spec.loader.exec_module(mod)
        _RANKER_MOD_AUGMENTER = mod
        return mod
    except Exception:
        return None


def _rank_function(
    target_repo: str,
    file_path: str,
    function_signature: str,
    top_n: int = 5,
    min_confidence: float = 0.4,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Call ranker — in-process when possible, subprocess as fallback.

    Wave-7 perf upgrade: uses importlib in-process import with sys.modules
    pre-registration to fix Python 3.14 dataclass.__module__ issue. Falls
    back to subprocess when in-process load fails (backward compat).
    Returns (ranked_attack_classes, shape_info).
    On any error returns ([], {}).
    """
    ranker_path = REPO / "tools" / "ranker.py"
    if not ranker_path.is_file():
        return [], {}

    # --- in-process path (preferred) ---
    mod = _load_ranker_module_augmenter()
    if mod is not None:
        try:
            result = mod.rank(
                target_repo=target_repo,
                file_path=file_path,
                function_signature=function_signature,
                top_n=top_n,
                min_confidence=min_confidence,
            )
            # RankResult.target is a plain dict; ranked_attack_classes is
            # List[Dict] (same structure as the subprocess JSON path).
            target_dict = result.target if isinstance(result.target, dict) else {}
            shape_info = {
                "shape_hash": target_dict.get("shape_hash", ""),
                "shape_hash_fine": target_dict.get("shape_hash_fine", ""),
            }
            return list(result.ranked_attack_classes), shape_info
        except Exception:
            pass  # fall through to subprocess

    # --- subprocess fallback (backward compat) ---
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(ranker_path),
                "--target-repo", target_repo,
                "--file-path", file_path,
                "--function-signature", function_signature,
                "--top-n", str(top_n),
                "--min-confidence", str(min_confidence),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return [], {}
        data = json.loads(proc.stdout)
        shape_info = {
            "shape_hash": data.get("target", {}).get("shape_hash", ""),
            "shape_hash_fine": data.get("target", {}).get("shape_hash_fine", ""),
        }
        return data.get("ranked_attack_classes", []), shape_info
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return [], {}


def _build_sec_function_mindset(
    workspace: pathlib.Path,
    files: List[str],
    target_repo: str,
    max_functions_per_file: int = 20,
    min_confidence: float = 0.4,
    top_n: int = 5,
) -> Tuple[str, Dict]:
    """Build the Function-Mindset Cheat Sheet section (D-1).

    For each in-scope .go file:
      1. Extract function signatures via function-signature-extractor.py
      2. Filter to exported + handler-like functions (capped at
         max_functions_per_file)
      3. Call ranker.rank() inline for each function
      4. Emit a Markdown subsection with top attack hypotheses

    Performance budget: ~10 files × 20 functions × ~10ms ranker call ≈ 2s.
    Non-Go files are silently skipped (no fallback for Solidity/Rust yet).

    Returns (markdown_text, metadata_dict).
    """
    lines = [
        "## Function-Mindset Cheat Sheet (auto-populated by vault_function_mindset)",
        "",
        "_Performance budget: ~10 files x 20 functions x ~10ms ranker call = ~2s._",
        "_Non-Go files skipped (Go only in Phase-A)._",
        "",
    ]

    file_sections: List[Dict[str, Any]] = []
    total_functions = 0
    total_ranked = 0

    for file_path in files:
        if not file_path.lower().endswith(".go"):
            continue

        recs = _extract_functions_for_file(file_path, workspace)
        if not recs:
            continue

        # Annotate receiver_family so handler filter works
        for rec in recs:
            if "receiver_family" not in rec:
                rec["receiver_family"] = _compute_receiver_family_for_rec(rec)

        # Filter to exported + handler-like
        handler_recs = [r for r in recs if r.get("visibility") == "exported" and _is_handler_like(r)]
        # If no handler-like exported, fall back to all exported (capped)
        if not handler_recs:
            handler_recs = [r for r in recs if r.get("visibility") == "exported"]
        # Cap per-file
        handler_recs = handler_recs[:max_functions_per_file]

        if not handler_recs:
            continue

        lines.append(f"### File: `{file_path}`")
        lines.append("")

        fn_entries: List[Dict[str, Any]] = []
        for rec in handler_recs:
            name = rec.get("function_name", "?")
            line_start = rec.get("line_start", "?")
            sig = rec.get("function_signature", name)
            recv = rec.get("receiver_type")

            # Call ranker inline — also returns shape hashes from ranker's target payload
            attack_classes, shape_info = _rank_function(
                target_repo=target_repo,
                file_path=file_path,
                function_signature=sig,
                top_n=top_n,
                min_confidence=min_confidence,
            )
            # Shape hashes: prefer ranker's lookup (uses sig_extracts JSONL);
            # fall back to extractor's pre-computed values if any.
            shape_hash = shape_info.get("shape_hash") or rec.get("shape_hash", "")
            shape_hash_fine = shape_info.get("shape_hash_fine") or rec.get("shape_hash_fine", "")

            # Format subsection
            recv_label = f" (receiver: {recv})" if recv else ""
            lines.append(f"#### `{name}` (line {line_start}){recv_label}")
            if shape_hash:
                lines.append(f"shape_hash: `{shape_hash}` / fine: `{shape_hash_fine}`")
            guards = rec.get("guards_detected") or []
            if guards:
                lines.append(f"guards_detected: {', '.join(guards)}")

            if attack_classes:
                lines.append("Top attack hypotheses (ranker output):")
                for rank_entry in attack_classes:
                    ac = rank_entry.get("attack_class", "?")
                    conf = rank_entry.get("confidence", 0.0)
                    rank_num = rank_entry.get("rank", "?")
                    evidence = rank_entry.get("evidence", [])
                    evidence_refs = []
                    for ev in evidence[:2]:
                        vid = ev.get("verdict_id")
                        rid = ev.get("rule_id")
                        scorer = ev.get("scorer", "")
                        if vid:
                            evidence_refs.append(f"{vid} ({scorer})")
                        elif rid:
                            evidence_refs.append(f"{rid} ({scorer})")
                    ev_str = "; ".join(evidence_refs) if evidence_refs else "—"
                    lines.append(
                        f"  {rank_num}. {ac} (conf {conf:.2f}) — see {ev_str}"
                    )
                total_ranked += len(attack_classes)
            else:
                lines.append(
                    f"_(no attack classes above min_confidence={min_confidence})_"
                )
            lines.append("")

            fn_entries.append({
                "function_name": name,
                "line_start": line_start,
                "shape_hash": shape_hash,
                "shape_hash_fine": shape_hash_fine,
                "guards_detected": guards,
                "attack_classes": attack_classes,
            })
            total_functions += 1

        file_sections.append({
            "file_path": file_path,
            "functions": fn_entries,
        })

    if not file_sections:
        lines.append(
            "_(no Go files in scope or no exportable functions extracted — "
            "function-mindset section empty)_"
        )
        lines.append("")

    lines.extend([
        "",
        "**WARNING**: Do not skip rubric-verbatim check per SEVERITY.md.",
        "**WARNING**: Run pre-submit-check.sh #48 + #49 (L30 / L31) before filing.",
        "",
    ])

    text = "\n".join(lines)
    metadata = {
        "items_count": total_functions,
        "items": file_sections,
        "total_ranked": total_ranked,
        "target_repo": target_repo,
        "min_confidence": min_confidence,
        "max_functions_per_file": max_functions_per_file,
    }
    return text, metadata


# ---------------------------------------------------------------------------
# Section 14 — Required reply shape
# ---------------------------------------------------------------------------

_SEC14_PREFIX = """\
## Section 14 — Required reply shape (verdict contract)

The worker's reply MUST contain ONE of these for the candidate it investigates:

- `KEY FINDING: <pattern_class> at <file:line> — <one-line impact> — <severity>`
- `VERDICT CONTESTED: <prior_finding_id> — <missed path>`
- `VERDICT HOLDS: invariant <X> at <file:line>` (must cite file:line)
- `NEEDS BUILD: <missing-evidence-class> + <acquisition-step>`
- `BLOCKED: <one-line reason>`
- `NEGATIVE: <bug_class_attempted> — <why ruled out, with evidence>`

Plus the audit-question answer block:

```
## Audit-Question Answers
"""

_SEC14_SUFFIX = """\
```

Free-form replies WITHOUT a recognized verb in {KEY FINDING, VERDICT CONTESTED,
VERDICT HOLDS, NEEDS BUILD, BLOCKED, NEGATIVE} are REJECTED at Step 6
(orchestrator declines to integrate; treat as `skipped`, requeue lane next loop).

DROP-only verdicts require ONE of:
  (a) "Evidence path structurally impossible: <reason>"
  (b) "Bug class definitionally cannot land on mainnet user: <reason>"
  (c) "Duplicate-clear filing already exists: <id>"
"""


def _sec14_question_is_advisory(row: Dict[str, Any]) -> bool:
    qid = str(row.get("id") or "").strip()
    return bool(row.get("advisory_only")) or qid.startswith(("Q-AC-", "Q-PRIOR-", "Q-OOS-", "Q-RULE-"))


def _build_sec14(sec13_data: Optional[Dict] = None) -> Tuple[str, Dict]:
    questions = [
        {
            "question_id": str(row.get("id") or "").strip(),
            "advisory_only": _sec14_question_is_advisory(row),
        }
        for row in (sec13_data or {}).get("items", [])
        if isinstance(row, dict) and str(row.get("id") or "").strip()
    ]
    if not questions:
        questions = [{"question_id": "Q-DUPE", "advisory_only": False}]
    answer_lines: List[str] = []
    for row in questions:
        qid = row["question_id"]
        if row["advisory_only"]:
            answer_lines.append(
                f"- {qid}: ADVISORY_PASS|ADVISORY_FAIL|UNKNOWN — "
                "<analogue/scope comparison only; not exploit proof, not severity assignment>"
            )
        else:
            answer_lines.append(f"- {qid}: PASS|FAIL|UNKNOWN — <one-line evidence>")
    text = _SEC14_PREFIX + "\n".join(answer_lines) + "\n" + _SEC14_SUFFIX
    return text, {
        "items_count": len(questions),
        "items": questions,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", s).strip("-").lower() or "unknown"


def _compute_content_hash(content: str) -> str:
    content = _GENERATED_LINE_RE.sub("**Generated**: <generated-at>", content)
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Section 0.8 — Impact x Mechanism completeness plane (primacy-of-impact)
#
# Wires the completeness-matrix mechanism axis INTO the hunter's brief so the
# AGENT enumerates the impact x mechanism plane and clears every cell by
# source-reading + adversarial reasoning. The mechanism DETECTORS are a
# backstop/accelerant, NOT the finder: a cell with no detector ("unscanned") is
# an explicit agent obligation here, not a silent WARN. This is the durable
# generalization of the NUVA false-green miss (an unbounded consensus-hook
# chain-halt that passed 36/36 symbol/function gates because no gate modelled
# the impact->mechanism plane). Language-filtered, all-workspace, all-language.
# ---------------------------------------------------------------------------

def _load_mechanism_axis_for_brief(workspace: pathlib.Path) -> Optional[Dict[str, Any]]:
    """Import completeness-matrix-build by path (REUSE, never re-implement the
    mechanism library / scan / disposition loaders - R47 tool-dedup) and return
    its mechanism-axis dict, or None if unavailable (degrade gracefully)."""
    try:
        import importlib.util
        tool = pathlib.Path(__file__).resolve().parent / "completeness-matrix-build.py"
        if not tool.is_file():
            return None
        spec = importlib.util.spec_from_file_location("_cmb_for_brief", str(tool))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        inscope = mod._load_inscope(workspace)
        return mod._build_mechanism_axis(workspace, inscope, set())
    except Exception:
        return None


def _build_sec08_impact_mechanism_plane(workspace: pathlib.Path) -> Tuple[str, Dict]:
    """Emit the impact x mechanism completeness plane as an agent obligation.

    For EVERY in-scope impact (chain-halt/liveness, permanent-freeze, insolvency,
    direct-theft, temp-freeze/griefing, governance-manip, yield/gas/MEV-theft),
    every mechanism that can produce it (filtered to this ws's languages) is a
    cell the hunter MUST adversarially clear by reading the real in-scope source
    - EVEN when no detector exists for it. A detector firing is a lead to verify;
    a detector's silence (or absence) is NOT a clearance."""
    header = "## Section 0.8 - Impact x Mechanism completeness plane (PRIMACY-OF-IMPACT - clear every cell)"
    axis = _load_mechanism_axis_for_brief(workspace)
    if not axis or not axis.get("present") or not axis.get("cells"):
        body = (
            f"{header}\n\n"
            "_(mechanism axis unavailable for this workspace - completeness-matrix "
            "not importable or no in-scope units yet. STILL your obligation: for "
            "every in-scope IMPACT, enumerate every MECHANISM that can produce it "
            "in the real source and clear each by reasoning.)_\n"
        )
        return body, {"present": False, "cells": 0, "open": 0, "unscanned": 0}

    cells = axis["cells"]
    langs = ", ".join(axis.get("ws_languages") or []) or "(unknown)"
    open_cells = [c for c in cells if c["status"] == "not-enumerated-open-finding"]
    unscanned = [c for c in cells if c["status"] == "not-enumerated-unscanned"]
    clean = [c for c in cells if c["status"] == "enumerated-scanned-clean"]
    disp = [c for c in cells if c["status"] == "enumerated-findings-dispositioned"]

    lines = [
        header,
        "",
        "**The pipeline enumerates by symbol/function; a real Critical hides in the "
        "impact->mechanism plane no per-function gate models.** For EVERY in-scope "
        "impact below, every mechanism that can produce it is a cell YOU must clear "
        "by reading the real in-scope source and reasoning adversarially. A mechanism "
        "detector is a BACKSTOP, not the finder: **an unscanned cell (no detector) is "
        "YOUR obligation to clear, not a pass.** Close each cell with a finding OR a "
        "source-cited refutation (why this mechanism cannot produce this impact in the "
        "in-scope code).",
        "",
        f"- Workspace languages: **{langs}**  |  cells: {len(cells)} "
        f"(open-finding: {len(open_cells)}, unscanned: {len(unscanned)}, "
        f"scanned-clean: {len(clean)}, dispositioned: {len(disp)})",
        "",
    ]

    if open_cells:
        lines.append("### TOP PRIORITY - OPEN mechanism findings (a detector already FIRED here; verify -> paste-ready OR refute -> mechanism_dispositions.jsonl)")
        lines.append("")
        lines.append("| impact | mechanism | detector | open |")
        lines.append("|---|---|---|---|")
        for c in open_cells:
            lines.append(f"| {c['impact']} | {c['mechanism']} | {c.get('detector') or '-'} | {c.get('open_findings', 0)} |")
        lines.append("")

    if unscanned:
        lines.append("### UNSCANNED cells - NO detector exists; clear each by adversarial source-reading (impact->mechanism enumeration is YOUR job)")
        lines.append("")
        lines.append("| impact | mechanism | detector |")
        lines.append("|---|---|---|")
        for c in unscanned:
            lines.append(f"| {c['impact']} | {c['mechanism']} | (none - reason from source) |")
        lines.append("")

    lines.append(
        "**How to clear a cell (per README impact x mechanism step) - the loop is CLOSED, "
        "your verdict is recorded and gated:** (1) read the real in-scope code paths that "
        "could realize `impact` via `mechanism`; (2) if an unprivileged reachable path "
        "exists -> that is a finding (verify -> paste-ready); (3) else write a source-cited "
        "refutation. Do NOT treat a green/absent detector as a cleared cell."
    )
    lines.append("")
    lines.append(
        "**WRITE your per-cell verdict** to `.auditooor/agent_mechanism_verdicts/<name>.json` "
        "(a JSON array of rows) so the completeness gate credits your REASONING (not just a "
        "detector). Each row: `{\"schema\":\"auditooor.agent_mechanism_verdict.v1\", "
        "\"impact\":\"<impact>\", \"mechanism\":\"<mechanism>\", \"verdict\":\"cleared|finding\", "
        "\"source_refs\":[\"file.go:123\", ...], \"reasoning\":\"...\"}`. FAIL-CLOSED: a "
        "`cleared` verdict credits the cell ONLY with >=1 concrete `source_refs` (file:line) "
        "AND substantive `reasoning` (>=40 chars) - closing a cell is a claim of ABSENCE and "
        "must be as hard as raising a finding; a bare `cleared` is ignored. A `finding` "
        "verdict OPENS the cell (must then be filed or dispositioned). Report each cell's "
        "verdict in your reply too."
    )
    body = "\n".join(lines)
    return body, {
        "present": True,
        "cells": len(cells),
        "open": len(open_cells),
        "unscanned": len(unscanned),
        "ws_languages": axis.get("ws_languages") or [],
    }


# ---------------------------------------------------------------------------
# Main brief builder
# ---------------------------------------------------------------------------

def build_brief(
    workspace: pathlib.Path,
    lane_id: str,
    files: List[str],
    hint: Optional[str],
    max_items: int,
    inject_function_mindset: bool = True,
    max_functions_per_file: int = 20,
    min_confidence: float = 0.4,
    target_repo: str = "unknown/unknown",
    lane_type: str = "filing",
    severity: str = "HIGH",
    target_finding_class: str = "",
) -> Tuple[str, Dict]:
    """Build the complete hacker brief. Returns (markdown_text, sections_dict).

    When ``inject_function_mindset=True`` (default as of TIER A Lift 1), a
    "Function-Mindset Cheat Sheet" section is appended after Section 14.
    This requires Phase-B ranker infrastructure (ranker.py + shape-hash.py +
    sig_extracts/); the section degrades gracefully when those are missing.

    Legacy Wave-3 callers can opt back into the disabled stub by passing
    ``inject_function_mindset=False`` (CLI: ``--no-inject-function-mindset``).
    """
    ts = datetime.now(timezone.utc).isoformat()

    # Header
    header_lines = [
        f"# Hacker Mindset Injection — lane {lane_id}",
        "",
        f"**Generated**: {ts}",
        f"**Workspace**: <workspace>",
        f"**Files in scope** ({len(files)}): {', '.join(pathlib.Path(f).name for f in files)}",
        f"**Contract-type hint**: {hint or '(none)'}",
        f"**Filter cap**: {max_items}/section",
        f"**Function-mindset injection**: {'ENABLED (default; pass --no-inject-function-mindset to opt out)' if inject_function_mindset else 'DISABLED (legacy Wave-3 opt-out via --no-inject-function-mindset)'}",
        "**Source provenance**: case_study_logic, big_loss_template_actor_sequences, defihack_class_matches,",
        "  engage_report fires, kill_rubric, triager_patterns, rejection_causes, dupe_causes,",
        "  originality_keywords, oos_checklist, exploit_context angles, AMF frames, counter-brief shape",
        "",
    ]
    header = "\n".join(header_lines)

    sections: Dict[str, Dict] = {}

    # Build each section
    resume_context = _load_resume_context(workspace, max_items)
    exploit_context = _load_exploit_context(workspace, max_items)

    sec0_text, sections["sec0_l17_verdict_contract"] = _build_sec0()
    # Section 0.8 — impact x mechanism completeness plane (primacy-of-impact).
    # High salience: placed right after the verdict contract so the hunter
    # enumerates the impact->mechanism plane BEFORE diving into per-function work.
    sec08_text, sections["sec08_impact_mechanism_plane"] = _build_sec08_impact_mechanism_plane(workspace)
    sec05_text, sections["sec05_clones_inventory"] = _build_sec05(workspace)
    sec07_text, sections["sec07_queued_leads"] = _build_sec07(workspace, files)
    sec09_text, sections["sec09_cooldown_states"] = _build_sec09(workspace, lane_id)
    sec1_text, sections["sec1_counter_brief"] = _build_sec1()
    sec2_text, sections["sec2_case_study_logic"] = _build_sec2(files, hint, max_items, resume_context)
    sec3_text, sections["sec3_big_loss_sequences"] = _build_sec3(files, hint, max_items, resume_context)
    sec4_text, sections["sec4_defihacklabs"] = _build_sec4(files, hint, max_items, resume_context)
    sec5_text, sections["sec5_engage_report_fires"] = _build_sec5(workspace, files, max_items)
    sec55_text, sections["sec55_go_yaml_fallback"] = _build_sec55(files)
    sec6_text, sections["sec6_kill_rubric"] = _build_sec6(hint, max_items)
    sec7_text, sections["sec7_triager_patterns"] = _build_sec7(files, hint, max_items)
    sec8_text, sections["sec8_prior_dupes"] = _build_sec8(workspace, max_items)
    sec9_text, sections["sec9_originality_keywords"] = _build_sec9(files, hint, max_items)
    sec10_text, sections["sec10_oos_clauses"] = _build_sec10(workspace, files)
    sec11_text, sections["sec11_exploit_angles"] = _build_sec11(
        files, hint, max_items, exploit_context, workspace
    )
    sec12_text, sections["sec12_amf_frames"] = _build_sec12(files, hint, max_items)
    # Section 15a+15b: META-1 activation — lane-specific rules + skeleton templates
    # injected AFTER sec12, BEFORE sec13.
    # 15a calls vault_codified_rules_digest (lane-filtered rule list).
    # 15b calls vault_lane_skeleton_filler (fill-in-blank templates).
    # Both fall back gracefully (warn-only) if MCP callables are unavailable.
    sec15a_text, sections["sec15a_lane_rules"] = _build_sec15a_lane_rules_to_address(
        lane_type=lane_type,
        severity=severity,
        workspace_path=workspace,
    )
    sec15b_text, sections["sec15b_skeleton_templates"] = _build_sec15b_lane_skeleton_templates(
        lane_type=lane_type,
        severity=severity,
        workspace_path=workspace,
        target_finding_class=target_finding_class,
    )
    # Compose a combined sec15_text for backward-compat callers that read sections["sec15_hard_rules_digest"]
    sec15_text = sec15a_text + "\n" + sec15b_text
    sections["sec15_hard_rules_digest"] = {
        **sections["sec15a_lane_rules"],
        "sec15b": sections["sec15b_skeleton_templates"],
    }
    sec13_text, sections["sec13_question_list"] = _build_sec13(
        sections["sec2_case_study_logic"],
        sections["sec3_big_loss_sequences"],
        sections["sec4_defihacklabs"],
        sections["sec6_kill_rubric"],
        sections["sec11_exploit_angles"],
        sections["sec5_engage_report_fires"],
        sections["sec55_go_yaml_fallback"],
        sections["sec12_amf_frames"],
        sections["sec8_prior_dupes"],
        sections["sec10_oos_clauses"],
        scoped_files=files,
        hint=hint,
    )
    sec14_text, sections["sec14_reply_shape"] = _build_sec14(sections["sec13_question_list"])

    # Function-mindset injection (D-1) — only when flag is set
    if inject_function_mindset:
        sec_fm_text, sections["sec_function_mindset"] = _build_sec_function_mindset(
            workspace=workspace,
            files=files,
            target_repo=target_repo,
            max_functions_per_file=max_functions_per_file,
            min_confidence=min_confidence,
        )
    else:
        sec_fm_text = (
            "## Function-Mindset Cheat Sheet (auto-populated by vault_function_mindset)\n\n"
            "_(disabled via legacy opt-out `--no-inject-function-mindset`; "
            "default behavior is ENABLED)_\n"
        )
        sections["sec_function_mindset"] = {"items_count": 0, "items": [], "disabled": True}

    # Assemble full Markdown
    all_sections = [
        header,
        sec0_text,
        sec08_text,
        sec05_text,
        sec07_text,
        sec09_text,
        sec1_text,
        sec2_text,
        sec3_text,
        sec4_text,
        sec5_text,
        sec55_text,
        sec6_text,
        sec7_text,
        sec8_text,
        sec9_text,
        sec10_text,
        sec11_text,
        sec12_text,
        sec15_text,
        sec13_text,
        sec14_text,
        sec_fm_text,
    ]
    markdown = "\n".join(all_sections)

    # Privacy guards
    markdown = _strip_absolute_paths(markdown, workspace)
    markdown = _sanitize(markdown)

    return markdown, sections


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a scope-filtered Hacker Mindset Injection brief (W2-A)."
    )
    parser.add_argument(
        "--workspace", "-w",
        required=True,
        help="Absolute path to workspace root (must contain .auditooor/).",
    )
    parser.add_argument(
        "--lane-id", "--lane",
        required=True,
        help="Hunt-loop lane ID (e.g. H1-coop-exit, W2-B-2).",
    )
    parser.add_argument(
        "--files",
        required=True,
        help="Comma-separated list of in-scope file paths.",
    )
    parser.add_argument(
        "--contract-type-hint",
        default=None,
        help="Optional bug-class hint (e.g. amm-pool, frost-signer).",
    )
    parser.add_argument(
        "--out", "--output",
        default=None,
        dest="out",
        help="Output path. Default: <ws>/.auditooor/hacker_brief_<lane>_<ts>.md",
    )
    parser.add_argument(
        "--severity",
        default="HIGH",
        help=(
            "Severity filter for Section 15a/15b (vault_codified_rules_digest + "
            "vault_lane_skeleton_filler). One of: LOW, MEDIUM, HIGH, CRITICAL, all. "
            "Default: HIGH."
        ),
    )
    parser.add_argument(
        "--target-finding-class",
        default="",
        help=(
            "Optional finding-class hint for Section 15b skeleton workspace anchors "
            "(e.g. cooperative-exit, verifier-acceptance, oracle-trust, bridge-payout)."
        ),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=_MAX_TOKENS_DEFAULT,
        help=f"Token budget cap (default {_MAX_TOKENS_DEFAULT}).",
    )
    parser.add_argument(
        "--max-items-per-section",
        type=int,
        default=_MAX_ITEMS_DEFAULT,
        help=f"Max items per section (default {_MAX_ITEMS_DEFAULT}).",
    )
    parser.add_argument(
        "--json-out",
        action="store_true",
        help="Also emit a JSON sidecar at <out>.json.",
    )
    parser.add_argument(
        "--inject-function-mindset",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Inject per-function hacker-mindset attack hypotheses (D-1). "
            "Default ENABLED as of TIER A Lift 1 (Hackerman Capability Master Plan): "
            "all lane briefs ship per-function attack-class mindset by default. "
            "Pass --no-inject-function-mindset to opt back into legacy Wave-3 "
            "behavior (disabled stub). Requires ranker.py + shape-hash.py + "
            "audit/sig_extracts/ to be populated; degrades gracefully when those "
            "are missing."
        ),
    )
    parser.add_argument(
        "--max-functions-per-file",
        type=int,
        default=20,
        help=(
            "Maximum exported handler-like functions to rank per in-scope file "
            "(default 20). Only active when --inject-function-mindset is set."
        ),
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.4,
        help=(
            "Minimum ranker confidence threshold to include an attack class "
            "in the Function-Mindset section (default 0.4). "
            "Only active when --inject-function-mindset is set."
        ),
    )
    parser.add_argument(
        "--target-repo",
        default="unknown/unknown",
        help=(
            "Target repo slug (e.g. dydxprotocol/v4-chain) for ranker lookup. "
            "Only active when --inject-function-mindset is set."
        ),
    )
    parser.add_argument(
        "--lane-type",
        default="filing",
        help=(
            "Lane subtype for Section 15 codified-rules filtering. "
            "One of: miner, hunt, detector, filing, dispute, mediation, triager-response. "
            "Default: filing (most permissive rule set)."
        ),
    )

    args = parser.parse_args(argv)

    workspace = pathlib.Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[augmenter] ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 1

    auditooor_dir = workspace / ".auditooor"
    if not auditooor_dir.is_dir():
        print(
            f"[augmenter] ERROR: workspace must contain .auditooor/ dir: {workspace}",
            file=sys.stderr,
        )
        return 1

    # Validate file count (FILE_CAP)
    files_raw = [f.strip() for f in args.files.split(",") if f.strip()]
    if len(files_raw) > _FILE_CAP:
        print(
            f"[augmenter] ERROR: FILE_CAP exceeded ({len(files_raw)} > {_FILE_CAP}). "
            "Narrow the --files list.",
            file=sys.stderr,
        )
        return 1

    lane_id = args.lane_id.strip()
    hint = args.contract_type_hint
    max_items = args.max_items_per_section

    # Build brief
    try:
        markdown, sections = build_brief(
            workspace,
            lane_id,
            files_raw,
            hint,
            max_items,
            inject_function_mindset=args.inject_function_mindset,
            max_functions_per_file=args.max_functions_per_file,
            min_confidence=args.min_confidence,
            target_repo=args.target_repo,
            lane_type=args.lane_type,
            severity=args.severity,
            target_finding_class=getattr(args, "target_finding_class", ""),
        )
    except Exception as e:
        print(f"[augmenter] ERROR during brief build: {e}", file=sys.stderr)
        return 1

    # Secret sanity check on output
    if _has_secret(markdown):
        print("[augmenter] ERROR: output triggered secret blocklist. Aborting.", file=sys.stderr)
        return 1

    # Determine output path
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out:
        out_path = pathlib.Path(args.out).expanduser().resolve()
    else:
        out_path = auditooor_dir / f"hacker_brief_{_slug(lane_id)}_{ts_str}.md"

    # Ensure output dir exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write Markdown
    out_path.write_text(markdown, encoding="utf-8")

    # Write JSON sidecar if requested
    if args.json_out:
        content_hash = _compute_content_hash(markdown)
        sidecar = {
            "schema": "auditooor.hacker_brief_augmenter.v1",
            "lane_id": lane_id,
            "workspace": "<workspace>",
            "files": files_raw,
            "hint": hint,
            "max_items": max_items,
            "generated_at": ts_str,
            "content_hash": content_hash,
            "markdown_path": _strip_absolute_paths(str(out_path), workspace),
            "inject_function_mindset": args.inject_function_mindset,
            "max_functions_per_file": args.max_functions_per_file,
            "min_confidence": args.min_confidence,
            "target_repo": args.target_repo,
            "sections": {k: v for k, v in sections.items()},
            "sections_implemented": [
                "0", "0.5", "0.7", "0.9", "1", "2", "3", "4", "5",
                "5.5", "6", "7", "8", "9", "10", "11", "12", "15", "13", "14",
                "function_mindset",
            ],
            "sections_stubbed": [],
            "dependencies_deferred": [],
        }
        sidecar = _sanitize_json_value(sidecar, workspace)
        json_path = pathlib.Path(str(out_path) + ".json")
        json_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

    # Print output path to stdout (consumed by SKILL.md Step 4.5)
    print(str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
