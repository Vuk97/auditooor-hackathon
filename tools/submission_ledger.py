#!/usr/bin/env python3
"""Helpers for parsing real workspace submission ledgers."""

from __future__ import annotations

import re
from pathlib import Path


def strip_markdown(value: str) -> str:
    """Remove lightweight markdown formatting from a table/block cell."""
    cleaned = value.strip()
    cleaned = re.sub(r"`([^`]*)`", r"\1", cleaned)
    cleaned = re.sub(r"\*\*([^*]+)\*\*", r"\1", cleaned)
    cleaned = re.sub(r"\*([^*]+)\*", r"\1", cleaned)
    return " ".join(cleaned.split())


def is_prior_submission_status(status: str) -> bool:
    """Return True when a tracker status represents already-filed history."""
    normalized = strip_markdown(status).lower()
    if not normalized:
        return False
    excluded_prefixes = ("draft", "ready", "withdrawn", "superseded")
    return not any(normalized.startswith(prefix) for prefix in excluded_prefixes)


def parse_table_submissions(text: str) -> list[dict[str, str]]:
    """Parse markdown status tables from a tracker."""
    subs: list[dict[str, str]] = []
    lines = text.splitlines()
    in_table = False
    headers: list[str] = []

    for line in lines:
        if line.startswith("|") and "Status" in line and ("Title" in line or "Finding" in line):
            headers = [strip_markdown(h).lower() for h in line.split("|") if h.strip()]
            in_table = True
            continue
        if in_table and line.startswith("|") and "---" not in line:
            cells = [strip_markdown(c) for c in line.split("|")]
            while cells and not cells[0]:
                cells.pop(0)
            while cells and not cells[-1]:
                cells.pop()
            while len(cells) < len(headers):
                cells.append("")
            row = dict(zip(headers, cells))
            status = row.get("status", "")
            title = row.get("title") or row.get("finding") or ""
            if title and is_prior_submission_status(status):
                raw_id = row.get("cantina #") or row.get("cantina id") or row.get("id") or ""
                finding_id = raw_id.lstrip("#")
                subs.append({
                    "id": finding_id,
                    "title": title,
                    "status": status,
                    "severity": row.get("severity", ""),
                    "date": row.get("date", ""),
                    "text": f"{title} {status}",
                    "source_format": "table",
                })
        elif in_table and not line.startswith("|"):
            in_table = False
    return subs


def extract_block_field(section: str, label: str) -> str:
    """Extract a markdown bullet field from a narrative tracker block."""
    pattern = rf"- \*\*{re.escape(label)}\*\*\s*(?:\n\s*|\s*:?\s*)(.+)"
    match = re.search(pattern, section)
    return strip_markdown(match.group(1)) if match else ""


def clean_block_title(raw_title: str) -> str:
    """Drop tracker numbering prefixes from a heading title."""
    title = strip_markdown(raw_title)
    return re.sub(r"^(?:#\d+|S-\d+)\s+[—-]\s*", "", title).strip()


def parse_marker_block_submissions(text: str) -> list[dict[str, str]]:
    """Parse legacy/root tracker blocks wrapped in CANTINA-ID comments."""
    subs: list[dict[str, str]] = []
    pattern = re.compile(
        r"<!-- CANTINA-ID:(?P<id>\d+) -->\s*(?P<section>.*?)<!-- /CANTINA-ID:\1 -->",
        re.S,
    )
    for match in pattern.finditer(text):
        finding_id = match.group("id")
        section = match.group("section")
        heading = re.search(r"^(##+)\s+(.+)$", section, re.M)
        title = clean_block_title(heading.group(2)) if heading else f"#{finding_id}"
        status = extract_block_field(section, "Status")
        if not is_prior_submission_status(status):
            continue
        subs.append({
            "id": finding_id,
            "title": title,
            "status": status,
            "severity": extract_block_field(section, "Severity"),
            "date": extract_block_field(section, "Submitted at"),
            "outcome": extract_block_field(section, "Outcome"),
            "text": section,
            "source_format": "marker-block",
        })
    return subs


def parse_heading_block_submissions(text: str) -> list[dict[str, str]]:
    """Parse narrative tracker sections containing an explicit Status block."""
    subs: list[dict[str, str]] = []
    matches = list(re.finditer(r"^(##+)\s+(.+)$", text, re.M))
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        section = text[start:end]
        status = extract_block_field(section, "Status")
        if not is_prior_submission_status(status):
            continue
        raw_title = strip_markdown(match.group(2))
        id_match = re.search(r"#(\d+)", raw_title)
        title = clean_block_title(raw_title)
        subs.append({
            "id": id_match.group(1) if id_match else "",
            "title": title,
            "status": status,
            "severity": extract_block_field(section, "Severity"),
            "date": extract_block_field(section, "Submitted at"),
            "outcome": extract_block_field(section, "Outcome"),
            "text": section,
            "source_format": "heading-block",
        })
    return subs


def load_submission_entries_from_text(text: str) -> list[dict[str, str]]:
    """Load prior-submission entries from a tracker body."""
    subs = parse_table_submissions(text)
    if subs:
        return subs
    subs = parse_marker_block_submissions(text)
    if subs:
        return subs
    return parse_heading_block_submissions(text)


def load_submission_entries(path: Path) -> list[dict[str, str]]:
    """Load prior-submission entries from a tracker file."""
    return load_submission_entries_from_text(path.read_text())
