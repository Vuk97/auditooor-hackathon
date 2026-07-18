#!/usr/bin/env python3
"""Shared mining-brief proof-context lookup for dispatch and swarm flows."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


def brief_dir(workspace: Path) -> Path:
    return workspace / "swarm" / "mining_briefs"


def load_brief_text(path: Path) -> str:
    return path.read_text(errors="replace")


def score_contract_match(path: Path, text: str, contract: str) -> int:
    target_lc = contract.lower()
    score = 0
    if target_lc in path.stem.lower():
        score += 4
    if re.search(rf"^\*\*Target:\*\*\s*`?{re.escape(contract)}`?\b", text, re.MULTILINE):
        score += 6
    if re.search(rf"^# .*\b{re.escape(contract)}\b", text, re.MULTILINE):
        score += 2
    return score


def extract_angle_id(path: Path, text: str) -> str | None:
    match = re.search(r"\b(A-[A-Z0-9-]+)\b", path.stem)
    if match:
        return match.group(1)
    match = re.search(r"^\*\*Angle:\*\*\s*(A-[A-Z0-9-]+)\b", text, re.MULTILINE)
    if match:
        return match.group(1)
    match = re.search(r"^# .*?\b(A-[A-Z0-9-]+)\b", text, re.MULTILINE)
    if match:
        return match.group(1)
    return None


def extract_angle_title(text: str) -> str | None:
    match = re.search(r"^\*\*Angle:\*\*\s*(.+)$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    match = re.search(r"^# .*?—\s+(A-[A-Z0-9-]+)\s*$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def extract_target_contract(text: str) -> str | None:
    match = re.search(r"^\*\*Target:\*\*\s*`?([A-Za-z_][A-Za-z0-9_]*)`?", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def context_payload(workspace: Path, brief: Path | None) -> dict[str, Any]:
    if brief is None:
        return {
            "matched_brief": None,
            "has_context": False,
            "proof_poor": None,
            "live_section": "",
            "pair_section": "",
            "message": f"(no matching mining brief with proof context found under {workspace}/swarm/mining_briefs)",
        }

    text = load_brief_text(brief)
    proof_poor = next((line for line in text.splitlines() if "PROOF-POOR" in line), None)
    live_section = extract_markdown_section(brief, "Live Check Evidence")
    pair_section = extract_markdown_section(brief, "Expected Paired Live Proof")
    exploit_goal_section = extract_markdown_section(brief, "Exploit Goal")
    has_context = bool(proof_poor or live_section or pair_section or exploit_goal_section)
    message = None
    if not has_context:
        message = "(matched mining brief has no live-proof context sections yet)"
    return {
        "matched_brief": str(brief),
        "has_context": has_context,
        "proof_poor": proof_poor,
        "live_section": live_section,
        "pair_section": pair_section,
        "exploit_goal_section": exploit_goal_section,
        "message": message,
    }


def find_matching_mining_brief(workspace: Path, contract: str) -> Path | None:
    """Match one contract to the most relevant mining brief without leakage."""
    mining_briefs = brief_dir(workspace)
    if not mining_briefs.is_dir():
        return None

    best: Path | None = None
    best_score = -1
    for path in sorted(mining_briefs.glob("*.md")):
        text = load_brief_text(path)
        contract_score = score_contract_match(path, text, contract)
        if contract_score <= 0:
            continue
        score = contract_score
        if "## Expected Paired Live Proof" in text:
            score += 2
        if "PROOF-POOR" in text:
            score += 1
        if score > best_score:
            best = path
            best_score = score
    if best_score <= 0:
        return None
    return best


def extract_markdown_section(path: Path, heading: str) -> str:
    text = load_brief_text(path)
    capture = False
    lines: list[str] = []
    for line in text.splitlines():
        if re.match(rf"^##\s+{re.escape(heading)}\s*$", line):
            capture = True
            lines.append(line)
            continue
        if capture and line.startswith("## "):
            break
        if capture:
            lines.append(line)
    return "\n".join(lines).strip()


def get_proof_context(workspace: Path, contract: str) -> dict[str, Any]:
    """Load matched mining-brief proof context for one contract."""
    brief = find_matching_mining_brief(workspace, contract)
    return context_payload(workspace, brief)


def angle_specs_from_surfaces(surfaces: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for surface in surfaces:
        angle_id = str(surface.get("id") or "").strip()
        title = str(surface.get("title") or "").strip()
        if not angle_id.startswith("A-"):
            continue
        key = (angle_id, title)
        if key in seen:
            continue
        seen.add(key)
        specs.append({"id": angle_id, "title": title})
    return specs


def find_matching_mining_brief_for_angle(
    workspace: Path,
    contract: str,
    angle_id: str,
    angle_title: str = "",
) -> tuple[Path | None, list[Path]]:
    mining_briefs = brief_dir(workspace)
    if not mining_briefs.is_dir():
        return None, []

    best: Path | None = None
    best_score = -1
    tied: list[Path] = []
    for path in sorted(mining_briefs.glob("*.md")):
        text = load_brief_text(path)
        contract_score = score_contract_match(path, text, contract)
        if contract_score <= 0:
            continue
        brief_angle = extract_angle_id(path, text)
        if brief_angle != angle_id:
            continue
        brief_title = extract_angle_title(text) or ""
        if angle_title and brief_title and brief_title != angle_title:
            continue
        score = contract_score + 8
        if angle_title and brief_title == angle_title:
            score += 6
        if "## Expected Paired Live Proof" in text:
            score += 2
        if "PROOF-POOR" in text:
            score += 1
        if score > best_score:
            best = path
            best_score = score
            tied = [path]
        elif score == best_score and best_score > 0:
            tied.append(path)
    if len(tied) > 1:
        return None, tied
    return best, []


def get_group_proof_context(workspace: Path, contract: str, surfaces: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Load angle-aware mining-brief proof context for one swarm contract group."""
    angle_specs = angle_specs_from_surfaces(surfaces)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for angle_spec in angle_specs:
        angle_id = angle_spec["id"]
        angle_title = angle_spec["title"]
        brief, ambiguous_matches = find_matching_mining_brief_for_angle(workspace, contract, angle_id, angle_title)
        payload = context_payload(workspace, brief)
        payload["angle_id"] = angle_id
        payload["angle_title"] = angle_title
        payload["match_mode"] = "angle+contract"
        if ambiguous_matches:
            rels = ", ".join(
                f"`{path.relative_to(workspace)}`"
                for path in ambiguous_matches[:3]
            )
            payload["message"] = (
                f"(multiple mining briefs match {angle_id} / {angle_title or '?'} for {contract}; failing closed. "
                f"Candidates: {rels})"
            )
        if payload["matched_brief"] is not None:
            seen.add(str(payload["matched_brief"]))
        entries.append(payload)

    fallback = None
    if not angle_specs and not any(entry.get("has_context") for entry in entries):
        fallback = get_proof_context(workspace, contract)
        fallback["angle_id"] = None
        fallback["angle_title"] = None
        fallback["match_mode"] = "contract-fallback"
        if fallback["matched_brief"] is not None and str(fallback["matched_brief"]) not in seen:
            entries.append(fallback)

    has_context = any(entry.get("has_context") for entry in entries)
    missing_angles = [entry["angle_id"] for entry in entries if entry.get("angle_id") and not entry.get("has_context")]
    matched_briefs = [entry["matched_brief"] for entry in entries if entry.get("matched_brief")]
    return {
        "has_context": has_context,
        "entries": entries,
        "missing_angles": missing_angles,
        "matched_briefs": matched_briefs,
        "message": None if has_context else f"(no matching mining brief with proof context found under {workspace}/swarm/mining_briefs)",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve mining-brief proof context for a contract")
    parser.add_argument("workspace", help="Workspace root")
    parser.add_argument("contract", help="Contract name to match")
    parser.add_argument("--json", action="store_true", help="Print proof context as JSON")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    payload = get_proof_context(workspace, args.contract)
    if args.json:
        print(json.dumps(payload))
        return
    matched = payload.get("matched_brief")
    if matched:
        print(matched)
    elif payload.get("message"):
        print(payload["message"])


if __name__ == "__main__":
    main()
