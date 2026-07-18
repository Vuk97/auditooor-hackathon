#!/usr/bin/env python3
"""relevant-rules-for-draft.py — auto-inject relevant L-rules + attacker frames.

Lane 4 + Lane 10 of MCP harness review (PR #658) commit 4. Single tool, two
plug-in points (per Worker B's anti-collision recommendation).

When invoked on a draft / brief / dispatch text, scans for trigger keywords
and emits matching L-rule excerpts + attacker-frame bodies. Designed to be
invoked from:
  - dispatch-brief.sh (worker prompt construction)
  - PostToolUse Write hook (when agent edits paste_ready/staging drafts)
  - manual operator query (`tools/relevant-rules-for-draft.py path/to/draft.md`)

Usage:
    tools/relevant-rules-for-draft.py <path-or-stdin>      # default: emit relevant context
    tools/relevant-rules-for-draft.py - < text             # read from stdin
    tools/relevant-rules-for-draft.py --frames-only <p>    # only emit frames
    tools/relevant-rules-for-draft.py --rules-only <p>     # only emit L-rules
    tools/relevant-rules-for-draft.py --max-frames 3 <p>   # cap frame injection (default 3)
    tools/relevant-rules-for-draft.py --max-rules 5 <p>    # cap rule injection (default 5)
    tools/relevant-rules-for-draft.py --json <p>           # emit structured JSON
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent
FRAMES_DIR = REPO / "reference" / "attacker_frames"
RULES_DOC = REPO / "docs" / "CODIFIED_DISCIPLINE_RULES_2026-05-08.md"
DIGEST_PATH = REPO / "reference" / "codified_rules_digest.json"
DEFAULT_MAX_FRAMES = 3
DEFAULT_MAX_RULES = 5

# Token-budget cap for total injection
MAX_INJECTION_TOKENS = 1500  # ~6000 chars

# L-rule trigger keywords mapping (Lane 4) — hard-coded fallback / base entries.
# At runtime this is MERGED with dynamically-derived triggers from
# reference/codified_rules_digest.json (see _build_rule_triggers()).
_RULE_TRIGGERS_HARDCODED: dict[str, list[str]] = {
    "L17": ["rubric-match", "rubric-verbatim", "build-or-drop", "operator-decides", "severity-claim"],
    "L25": ["mcp-first", "harness-output", "engage-report", "manual-read"],
    "L26": ["worker-claim", "worker-reply", "trust-but-verify", "sub-agent-output"],
    "L27": ["cantina-paste", "paste-ready-template", "submission-template", "form-fields"],
    "L28-E": ["fork-lag", "upstream-divergence", "go.mod", "replace-directive", "cherry-pick"],
    "L29-Disc-3": ["oos-disclosure", "documentation-cited", "by-design", "acknowledged"],
    "L29-Disc-4": ["post-pin", "partial-patch", "anchor", "sibling-pattern", "regression"],
    "L29-Disc-5": ["case-study-recall", "known-pattern", "pre-source-read"],
    "L29-Disc-6": ["e2e-poc", "cross-boundary", "funds-loss", "end-to-end"],
    "L30": ["missing-guard", "enumerate-all-callsites", "asymmetric-path", "missing-modifier"],
    "L31": ["dupe-preflight", "duplicate", "Q1+Q2", "platform-rules", "report-N+1"],
    "L32": ["panic", "nil-pointer", "validator-crash", "halts-block-production", "production-path-recovery", "defer-recover", "try-catch"],
    # R-rules that predate the digest or are referenced by other rules
    "R18": ["in-process", "node-level", "production-grade"],
    "R19": ["state-machine", "apphash", "block-execution", "commit-pipeline"],
    "R20": ["checktx", "fault-injection", "rpc-pressure"],
    "R24": ["non-self-impact", "self-harm", "non-attacker", "victim-funds"],
    "R25": ["defense-in-depth", "traversal", "downstream-impact"],
    "R26": ["ante-handler", "decorator-chain", "validatenestedmsg"],
}


def _derive_triggers_from_rule_record(record: dict) -> list[str]:
    """Derive keyword triggers from a codified_rules_digest.json rule record.

    Strategy:
      1. Add the rule_id itself as a literal trigger (e.g. "R43").
      2. Split the `name` field on hyphens/underscores -> individual tokens
         that are >=4 chars (avoids noise from short connecting words).
      3. Extract up to 3 meaningful multi-word phrases from `trigger_phrase`
         that appear to be code-identifiers or domain terms.
    """
    triggers: list[str] = []

    rule_id: str = record.get("rule_id", "")
    if rule_id:
        triggers.append(rule_id.lower())  # e.g. "r43"
        triggers.append(rule_id)          # e.g. "R43" (case-insensitive match anyway)

    name: str = record.get("name", "")
    if name:
        # Split on hyphens and underscores, keep tokens >= 4 chars
        tokens = re.split(r"[-_]", name)
        for tok in tokens:
            tok = tok.strip().lower()
            if len(tok) >= 4:
                triggers.append(tok)
        # Also add the full name as a trigger (with hyphens)
        triggers.append(name.lower())

    # Extract domain keywords from trigger_phrase (first 300 chars)
    trigger_phrase: str = (record.get("trigger_phrase") or "")[:300]
    # Pull quoted identifiers and camelCase / snake_case tokens
    phrase_matches = re.findall(r"`([^`]{3,40})`", trigger_phrase)
    for m in phrase_matches[:4]:
        triggers.append(m.lower())

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for kw in triggers:
        if kw and kw not in seen:
            seen.add(kw)
            result.append(kw)
    return result


def _build_rule_triggers() -> dict[str, list[str]]:
    """Build the merged RULE_TRIGGERS dict.

    Loads reference/codified_rules_digest.json and derives triggers for each
    rule, then merges with _RULE_TRIGGERS_HARDCODED (hard-coded entries WIN
    over digest-derived entries when the rule_id is already present, so the
    hard-coded set remains authoritative and digest adds new rules).

    Falls back silently to _RULE_TRIGGERS_HARDCODED if the digest is missing
    or unparseable (warns to stderr).
    """
    merged: dict[str, list[str]] = dict(_RULE_TRIGGERS_HARDCODED)

    if not DIGEST_PATH.is_file():
        sys.stderr.write(
            f"[relevant-rules] digest not found at {DIGEST_PATH}; "
            "using hard-coded RULE_TRIGGERS only\n"
        )
        return merged

    try:
        digest = json.loads(DIGEST_PATH.read_text(encoding="utf-8"))
        rules: list[dict] = digest.get("rules", [])
        added = 0
        for rec in rules:
            rid = rec.get("rule_id", "")
            if not rid:
                continue
            derived = _derive_triggers_from_rule_record(rec)
            if rid in merged:
                # Hard-coded entry exists — extend with digest-derived keywords
                # that aren't already in the list
                existing = set(merged[rid])
                merged[rid] = merged[rid] + [kw for kw in derived if kw not in existing]
            else:
                # New rule from digest — use derived triggers
                merged[rid] = derived
                added += 1
        if added:
            sys.stderr.write(
                f"[relevant-rules] digest loaded: +{added} new rules from {DIGEST_PATH.name}\n"
            )
    except Exception as exc:
        sys.stderr.write(
            f"[relevant-rules] digest parse error ({exc}); "
            "using hard-coded RULE_TRIGGERS only\n"
        )

    return merged


# Module-level merged dict — built once at import time
RULE_TRIGGERS = _build_rule_triggers()

# Frame trigger map is loaded from frame YAML files


def _read_input(path_or_dash):
    if path_or_dash == "-":
        return sys.stdin.read()
    p = pathlib.Path(path_or_dash)
    if not p.is_file():
        raise SystemExit(f"[relevant-rules] file not found: {p}")
    return p.read_text(encoding="utf-8")


def _load_frames():
    """Load all AMF-*.yaml frames. Returns list of dicts.

    Uses PyYAML if available (preferred); falls back to lite parser.
    """
    frames = []
    if not FRAMES_DIR.is_dir():
        return frames
    try:
        import yaml
        use_pyyaml = True
    except ImportError:
        use_pyyaml = False
    for path in sorted(FRAMES_DIR.glob("AMF-*.yaml")):
        try:
            content = path.read_text(encoding="utf-8")
            if use_pyyaml:
                frame = yaml.safe_load(content)
            else:
                frame = _parse_yaml_lite(content)
            if not isinstance(frame, dict):
                continue
            frame["_path"] = str(path)
            frames.append(frame)
        except Exception as exc:
            sys.stderr.write(f"[relevant-rules] parse error on {path}: {exc}\n")
    return frames


def _parse_yaml_lite(text):
    """Minimal YAML parser for frame files (no deps required).

    Handles: scalars, lists (- item), nested objects in mental_steps,
    | (literal block scalar), # comments.
    """
    result = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line or line.lstrip().startswith("#"):
            i += 1
            continue
        # Skip if line is indented (handled by parent context)
        if line.startswith(" "):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val == "":
            # Multi-line value: list or block
            sub = []
            i += 1
            while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("-") or not lines[i].strip()):
                sub.append(lines[i])
                i += 1
            result[key] = _parse_block(sub)
        elif val == "|":
            # Literal block
            i += 1
            block_lines = []
            while i < len(lines) and (lines[i].startswith(" ") or not lines[i].strip()):
                block_lines.append(lines[i].lstrip(" "))
                i += 1
            result[key] = "\n".join(block_lines).strip()
        else:
            # Scalar
            result[key] = _strip_scalar(val)
            i += 1
    return result


def _parse_block(sub_lines):
    """Parses an indented block as either list or dict."""
    if not sub_lines:
        return []
    first = next((l for l in sub_lines if l.strip()), "")
    stripped = first.lstrip()
    if stripped.startswith("- "):
        # List
        items = []
        current_item = None
        for line in sub_lines:
            s = line.strip()
            if not s:
                continue
            if line.lstrip().startswith("- "):
                if current_item is not None:
                    items.append(current_item)
                # Start new item
                content = line.lstrip()[2:].strip()
                if ":" in content and not content.startswith('"'):
                    # Object-list-item
                    k, _, v = content.partition(":")
                    current_item = {k.strip(): _strip_scalar(v.strip())}
                else:
                    current_item = _strip_scalar(content)
            elif isinstance(current_item, dict) and ":" in line:
                k, _, v = line.strip().partition(":")
                current_item[k.strip()] = _strip_scalar(v.strip())
        if current_item is not None:
            items.append(current_item)
        return items
    return _strip_scalar(first)


def _strip_scalar(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1]
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    try:
        return int(s)
    except ValueError:
        pass
    return s


def find_relevant_rules(text, *, max_rules=DEFAULT_MAX_RULES):
    """Returns list of (rule_id, matched_keywords) tuples, ranked by match count."""
    text_lower = text.lower()
    matches = []
    for rule_id, keywords in RULE_TRIGGERS.items():
        matched_kw = [kw for kw in keywords if kw.lower() in text_lower]
        if matched_kw:
            matches.append((rule_id, matched_kw, len(matched_kw)))
    matches.sort(key=lambda x: -x[2])
    return matches[:max_rules]


def find_relevant_frames(text, frames, *, max_frames=DEFAULT_MAX_FRAMES):
    """Returns list of (frame_dict, matched_keywords, score) tuples."""
    text_lower = text.lower()
    matches = []
    for frame in frames:
        triggers = frame.get("trigger_keywords", []) or []
        if isinstance(triggers, str):
            triggers = [triggers]
        matched_kw = [kw for kw in triggers if kw.lower() in text_lower]
        if matched_kw:
            yields = frame.get("proven_yields") or {}
            paid = yields.get("paid", 0) if isinstance(yields, dict) else 0
            score = len(matched_kw) * (paid + 1)
            matches.append((frame, matched_kw, score))
    matches.sort(key=lambda x: -x[2])
    return matches[:max_frames]


def extract_rule_excerpt(rule_id, full_doc):
    """Pulls the section for `rule_id` from CODIFIED_DISCIPLINE_RULES."""
    # Match e.g. "## L32" or "## L29-Disc-6" or "## Rule 1"
    pattern = rf"^##+ +{re.escape(rule_id)}\b.*?$"
    m = re.search(pattern, full_doc, re.MULTILINE)
    if not m:
        return None
    start = m.start()
    # Find next ## heading
    next_m = re.search(r"^##+ +(?!Disc-)\S", full_doc[m.end():], re.MULTILINE)
    end = m.end() + next_m.start() if next_m else len(full_doc)
    excerpt = full_doc[start:end].strip()
    # Truncate to ~30 lines
    lines = excerpt.split("\n")
    if len(lines) > 30:
        excerpt = "\n".join(lines[:30]) + "\n\n[... rule body truncated; see docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md ...]"
    return excerpt


def render_rules(matches, full_doc):
    if not matches:
        return ""
    out = ["## Relevant L-rules (auto-injected)\n"]
    for rule_id, matched_kw, count in matches:
        out.append(f"### {rule_id}  _(triggered by: {', '.join(matched_kw)})_\n")
        excerpt = extract_rule_excerpt(rule_id, full_doc)
        if excerpt:
            out.append(excerpt)
        else:
            out.append(f"_(rule body not extractable; see docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md#{rule_id})_")
        out.append("")
    return "\n".join(out)


def render_frames(matches):
    if not matches:
        return ""
    out = ["## Relevant attacker mental frames (auto-injected)\n"]
    for frame, matched_kw, score in matches:
        out.append(f"### {frame.get('frame_id')} — {frame.get('title')}  _(triggered by: {', '.join(matched_kw)})_\n")
        if frame.get("attacker_question"):
            out.append("**Attacker question:**")
            aq = frame['attacker_question']
            if isinstance(aq, list):
                aq = " ".join(str(x) for x in aq)
            out.append(str(aq))
            out.append("")
        steps = frame.get("mental_steps", [])
        if steps and isinstance(steps, list):
            out.append("**Mental steps:**")
            for step in steps[:5]:
                if isinstance(step, dict):
                    out.append(f"  {step.get('id', '?')}. {step.get('do', '')}")
                else:
                    out.append(f"  - {step}")
            out.append("")
        counter = frame.get("counter_examples", [])
        if counter and isinstance(counter, list):
            out.append("**⚠️ Counter-examples (address-or-rebut at draft time):**")
            for ce in counter[:3]:
                out.append(f"  - {ce}")
            out.append("")
        anchors = frame.get("existing_corpus_anchors", [])
        if anchors and isinstance(anchors, list):
            out.append(f"**Corpus anchors:** {', '.join(str(a) for a in anchors[:3])}")
            out.append("")
        out.append(f"_(full frame: {frame.get('_path', '?')})_\n")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("path", help="path to draft / brief, or '-' for stdin")
    parser.add_argument("--frames-only", action="store_true")
    parser.add_argument("--rules-only", action="store_true")
    parser.add_argument("--max-frames", type=int, default=DEFAULT_MAX_FRAMES)
    parser.add_argument("--max-rules", type=int, default=DEFAULT_MAX_RULES)
    parser.add_argument("--json", action="store_true", help="emit structured JSON instead of markdown")
    parser.add_argument("--quiet", action="store_true", help="emit nothing if no matches (vs banner)")
    args = parser.parse_args()

    text = _read_input(args.path)
    rules_doc = RULES_DOC.read_text(encoding="utf-8") if RULES_DOC.is_file() else ""
    frames = _load_frames()

    rule_matches = [] if args.frames_only else find_relevant_rules(text, max_rules=args.max_rules)
    frame_matches = [] if args.rules_only else find_relevant_frames(text, frames, max_frames=args.max_frames)

    if args.json:
        payload = {
            "schema": "auditooor.relevant_rules_for_draft.v1",
            "rules_matched": [{"rule_id": rid, "keywords": kw, "score": s} for rid, kw, s in rule_matches],
            "frames_matched": [{"frame_id": f.get("frame_id"), "title": f.get("title"), "keywords": kw, "score": s} for f, kw, s in frame_matches],
        }
        print(json.dumps(payload, indent=2))
        return 0

    rendered_rules = render_rules(rule_matches, rules_doc)
    rendered_frames = render_frames(frame_matches)

    if not rendered_rules and not rendered_frames:
        if not args.quiet:
            sys.stderr.write("[relevant-rules] no rule/frame triggers matched\n")
        return 0

    print(rendered_rules)
    print(rendered_frames)
    return 0


if __name__ == "__main__":
    sys.exit(main())
