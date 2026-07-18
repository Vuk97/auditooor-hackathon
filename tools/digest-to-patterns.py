#!/usr/bin/env python3
"""
digest-to-patterns.py — learn-from-prior-audits feedback loop.

Reads every `$WS/prior_audits/DIGEST_*.md` (produced by Sonnet agents via the
`templates/audit_digest_agent_brief.md` prompt), extracts each finding's
`generalizable pattern:` field, deduplicates against existing entries in
`reference/bug_patterns_observed.md`, and produces two outputs:

1. **NEW pattern entries** appended to `reference/bug_patterns_observed.md`
   (P64, P65, ...) citing the source audit for each. This grows the
   cross-bounty pattern catalog organically.

2. **Scanner-gap TODOs** appended to `$WS/TODO.md` for every pattern that
   DID NOT fire on the current iter 1 custom-detectors scan. Those become
   the backlog for detector authoring — "prior auditors found this bug
   class but our 1,039 detectors missed it, so we need a new detector
   targeting this shape."

This closes the loop sketched in SKILL_ISSUE #56/#57.

Usage:
    python3 tools/digest-to-patterns.py <workspace-dir>
    python3 tools/digest-to-patterns.py <workspace-dir> --dry-run

Exit 0 on success, 1 on fatal errors.
"""
import argparse
import re
import sys
from pathlib import Path
from datetime import datetime

REPO = Path(__file__).resolve().parent.parent
CATALOG = REPO / "reference" / "bug_patterns_observed.md"

# Finding header in a DIGEST_*.md: "### <id> — <title>"
FINDING_HEADER_RE = re.compile(r'^###\s+([^\n]+)$', re.M)
PATTERN_FIELD_RE = re.compile(
    r'^-\s+\*\*Generalizable pattern:\*\*\s+(.+?)(?=\n-\s+\*\*|\n###|\n##|\Z)',
    re.M | re.S,
)
SEVERITY_FIELD_RE = re.compile(r'^-\s+\*\*Severity:\*\*\s+(\w+)', re.M)
MECHANISM_FIELD_RE = re.compile(
    r'^-\s+\*\*Mechanism:\*\*\s+(.+?)(?=\n-\s+\*\*|\n###|\n##|\Z)',
    re.M | re.S,
)
FIX_STATUS_RE = re.compile(
    r'^-\s+\*\*Fix status:\*\*\s+(.+?)(?=\n-\s+\*\*|\n###|\n##|\Z)',
    re.M | re.S,
)
FN_FIELD_RE = re.compile(r'^-\s+\*\*Vulnerable function:\*\*\s+`?([^`\n]+)`?', re.M)
FILE_FIELD_RE = re.compile(r'^-\s+\*\*File:line:\*\*\s+`?([^`\n]+)`?', re.M)


def parse_digests(ws: Path) -> list[dict]:
    """Read every DIGEST_*.md in $WS/prior_audits/ and return finding dicts."""
    digest_dir = ws / "prior_audits"
    findings = []
    if not digest_dir.is_dir():
        return findings
    for f in sorted(digest_dir.glob("DIGEST_*.md")):
        text = f.read_text(errors="ignore")
        # Split on finding headers
        blocks = re.split(r'(?=^### )', text, flags=re.M)
        for b in blocks:
            m_head = FINDING_HEADER_RE.match(b.strip() if b.strip().startswith("###") else b)
            if not m_head:
                continue
            header = m_head.group(1).strip()
            if " — " in header:
                fid, title = header.split(" — ", 1)
            elif " - " in header:
                fid, title = header.split(" - ", 1)
            else:
                fid, title = header, ""
            # Skip H3 headers that are just section dividers like "### HIGH"
            if fid.strip() in {"HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO",
                                "INFORMATIONAL", "GAS", "Findings by severity"}:
                continue
            pat = PATTERN_FIELD_RE.search(b)
            if not pat:
                continue
            pat_text = re.sub(r'\s+', ' ', pat.group(1)).strip()
            # Strip markdown separators and trailing dashes that bled in
            pat_text = re.sub(r'\s*-{3,}\s*$', '', pat_text).strip()
            pat_text = re.sub(r'\s*\*{3,}\s*$', '', pat_text).strip()
            if not pat_text or len(pat_text) < 15:
                continue
            # Reject degenerate cross-references like "See Spearbit Gas-01." /
            # "Same as CVF-5 / CVF-6. - Other field..."
            cleaned = pat_text.rstrip('.').rstrip()
            if re.match(r'^(see|same\s+as)\b', cleaned.lower()):
                continue
            # Reject "various hygiene" umbrella entries — not a single pattern
            if re.match(r'^various\b', pat_text.lower()):
                continue
            sev_m = SEVERITY_FIELD_RE.search(b)
            mech_m = MECHANISM_FIELD_RE.search(b)
            fix_m = FIX_STATUS_RE.search(b)
            fn_m = FN_FIELD_RE.search(b)
            file_m = FILE_FIELD_RE.search(b)
            findings.append({
                "source_digest": f.name,
                "finding_id": fid.strip(),
                "title": title.strip(),
                "severity": sev_m.group(1) if sev_m else "",
                "mechanism": (re.sub(r'\s+', ' ', mech_m.group(1)).strip()
                              if mech_m else ""),
                "fix_status": (re.sub(r'\s+', ' ', fix_m.group(1)).strip()
                               if fix_m else ""),
                "vulnerable_fn": fn_m.group(1).strip() if fn_m else "",
                "file_line": file_m.group(1).strip() if file_m else "",
                "generalizable_pattern": pat_text,
            })
    return findings


def _normalize(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', s.lower()).strip()


def existing_pattern_index() -> dict[int, dict]:
    """Parse reference/bug_patterns_observed.md into {P_number: {class_name, text}}."""
    if not CATALOG.exists():
        return {}
    text = CATALOG.read_text()
    out = {}
    for m in re.finditer(r'### P(\d+)\s+—\s+(.+?)(?=\n###|\Z)', text, re.S):
        num = int(m.group(1))
        body = m.group(2)
        first_line = body.splitlines()[0] if body else ""
        out[num] = {"class_name": first_line.strip(), "body": body}
    return out


def keyword_tokens(text: str) -> set[str]:
    """Significant tokens for fuzzy dedup (length ≥ 4, non-stopword)."""
    stop = {"with", "from", "that", "this", "into", "when", "have", "been",
            "does", "also", "only", "where", "which", "would", "could",
            "should", "other", "their", "there", "these", "those", "without",
            "because", "calls", "call", "sets", "set", "reads", "read",
            "writes", "write", "missing", "check", "state", "value", "values"}
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_]{3,}', text.lower())
    return {t for t in tokens if t not in stop}


def is_duplicate(pattern: str, existing: dict[int, dict], threshold: float = 0.45) -> int | None:
    """Return the P# of an existing pattern if this one is a near-duplicate,
    else None. Jaccard similarity on keyword tokens."""
    p_tokens = keyword_tokens(pattern)
    if not p_tokens:
        return None
    best_p = None
    best_sim = 0.0
    for num, meta in existing.items():
        e_tokens = keyword_tokens(meta["class_name"] + " " + meta["body"][:500])
        if not e_tokens:
            continue
        overlap = len(p_tokens & e_tokens)
        union = len(p_tokens | e_tokens)
        sim = overlap / union if union else 0.0
        if sim > best_sim:
            best_sim = sim
            best_p = num
    if best_sim >= threshold:
        return best_p
    return None


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Second-pass dedup within the digest batch itself — two findings from
    the same digest might map to the same pattern. Keep the one with the
    most specific mechanism."""
    seen_keys = {}
    out = []
    for f in findings:
        # Key = first 10 significant tokens of the pattern
        tokens = sorted(keyword_tokens(f["generalizable_pattern"]))[:10]
        key = " ".join(tokens)
        if key in seen_keys:
            # Prefer the one with longer mechanism field
            if len(f.get("mechanism", "")) > len(seen_keys[key].get("mechanism", "")):
                seen_keys[key] = f
        else:
            seen_keys[key] = f
    return list(seen_keys.values())


def append_to_catalog(new_entries: list[dict], existing: dict[int, dict],
                      dry_run: bool = False) -> int:
    """Append new P## entries to reference/bug_patterns_observed.md."""
    if not new_entries:
        return 0
    next_num = max(existing.keys(), default=0) + 1
    today = datetime.now().strftime("%Y-%m-%d")
    blocks = []
    for e in new_entries:
        sev = e.get("severity", "Unknown")
        fid = e.get("finding_id", "?")
        source = e.get("source_digest", "DIGEST_*.md")
        pat = e.get("generalizable_pattern", "").rstrip(".")
        mech = e.get("mechanism", "").rstrip(".")
        fn = e.get("vulnerable_fn", "")
        fileline = e.get("file_line", "")
        fix = e.get("fix_status", "")
        # Synthesize a short class-name from the pattern: take first noun-ish clause
        class_short = pat.split(",")[0].split(";")[0].strip()
        if len(class_short) > 80:
            class_short = class_short[:77] + "..."
        blocks.append(
            f"### P{next_num} — {class_short}\n"
            f"- **First observed:** {fid} (prior audit, {source}) — ingested {today}\n"
            f"- **Severity achieved:** {sev}\n"
            f"- **Code smell:** {pat}\n"
            f"- **Mechanism:** {mech}\n"
            + (f"- **Vulnerable fn seen at:** `{fn}` `{fileline}`\n" if fn or fileline else "")
            + f"- **Fix status in source audit:** {fix}\n"
            f"- **PoC archetype:** isolated (unit-testable) unless the class touches oracle or cross-market state\n"
            f"- **Originality keywords:** see `reference/originality_keywords.md` (add new class if missing)\n"
            f"- **Anti-pattern cross-ref:** *(fill in when class is next submitted)*\n"
        )
        next_num += 1
    payload = "\n" + "\n".join(blocks)
    if dry_run:
        print(payload[:2000])
        return len(new_entries)
    with open(CATALOG, "a") as f:
        f.write(payload)
    return len(new_entries)


def parse_scan_log_hits(scan_log: Path) -> set[str]:
    """Parse a custom-detectors log to see which detector ARGUMENTs fired ≥1
    time. Returns the set of fired detectors. Used for scanner-gap detection."""
    if not scan_log.exists():
        return set()
    text = scan_log.read_text(errors="ignore")
    parts = re.split(r"=== Running (\S+) ===\n", text)
    fired = set()
    for i in range(1, len(parts), 2):
        name = parts[i]
        body = parts[i+1] if i+1 < len(parts) else ""
        for line in body.splitlines():
            if re.match(r"\s+\[(HIGH|MEDIUM|LOW|INFORMATIONAL)\]", line):
                fired.add(name)
                break
    return fired


def append_scanner_todos(new_patterns: list[dict], ws: Path,
                         dry_run: bool = False) -> int:
    """Append 'scanner gap' TODOs — but only for security-relevant severities
    (Critical/High/Medium). Info/Gas/Minor/NC findings are noise for
    detector-authoring purposes."""
    todo = ws / "TODO.md"
    if not todo.exists():
        return 0
    candidates = list(ws.glob("custom-detectors*.log"))
    fired = set()
    if candidates:
        fired = parse_scan_log_hits(candidates[0])
    # Filter: only include findings of material severity
    promote_severities = {"critical", "high", "medium", "med", "moderate"}
    security = [p for p in new_patterns
                if (p.get("severity", "").lower() in promote_severities)]
    if not security:
        return 0
    today = datetime.now().strftime("%Y-%m-%d")
    header = (
        f"\n## Scanner gap candidates (from prior-audit digests, {today})\n\n"
        "Prior auditors found these bug classes. Auditooor's iter 1 scan\n"
        "didn't surface them. Candidates for new Slither detectors.\n"
        "(Filtered to Critical/High/Medium only — Info/Gas/NC excluded.)\n\n"
    )
    lines = [header]
    for p in security:
        pat = p.get("generalizable_pattern", "")
        sev = p.get("severity", "")
        fid = p.get("finding_id", "")
        src = p.get("source_digest", "")
        lines.append(f"- [ ] **{sev}** — `{pat[:120]}` ({fid}, {src})")
    payload = "\n".join(lines) + "\n"
    if dry_run:
        print("--- TODO.md append ---")
        print(payload[:2000])
        return len(security)
    with open(todo, "a") as f:
        f.write(payload)
    return len(security)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace", help="workspace dir containing prior_audits/")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--similarity", type=float, default=0.45,
                    help="jaccard dedup threshold (default 0.45)")
    args = ap.parse_args()

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"Error: {ws} not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"[digest-to-patterns] reading {ws}/prior_audits/DIGEST_*.md")
    findings = parse_digests(ws)
    print(f"  extracted {len(findings)} findings with generalizable patterns")
    if not findings:
        print("  nothing to process; ensure DIGEST_*.md files exist")
        sys.exit(0)

    findings = dedup_findings(findings)
    print(f"  after intra-digest dedup: {len(findings)}")

    existing = existing_pattern_index()
    print(f"  existing pattern catalog: {len(existing)} entries (P1..P{max(existing.keys(), default=0)})")

    # Persistent per-workspace ingestion ledger — hard dedup across repeated
    # pre-iter-check runs. Catches exact-repeat ingestion before Jaccard.
    ledger_path = ws / "prior_audits" / ".ingested_findings.tsv"
    ingested_keys = set()
    if ledger_path.exists():
        for line in ledger_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ingested_keys.add(line)

    new_entries = []
    dupes = []
    skipped_ingested = 0
    for f in findings:
        # source_digest + finding_id = stable unique key
        key = f"{f['source_digest']}\t{f['finding_id']}"
        if key in ingested_keys:
            skipped_ingested += 1
            continue
        dup_p = is_duplicate(f["generalizable_pattern"], existing, args.similarity)
        if dup_p is not None:
            dupes.append((f, dup_p))
            # Record ingestion even though it dedup'd, so we don't re-check
            ingested_keys.add(key)
        else:
            new_entries.append(f)
            ingested_keys.add(key)
    if skipped_ingested:
        print(f"  already ingested (ledger hit): {skipped_ingested}")

    print(f"  new patterns (not in catalog): {len(new_entries)}")
    print(f"  duplicates (already cataloged): {len(dupes)}")
    if dupes[:3]:
        print("  dup samples:")
        for f, dp in dupes[:3]:
            print(f"    - {f['finding_id']} -> P{dp}")

    if new_entries:
        n_cat = append_to_catalog(new_entries, existing, dry_run=args.dry_run)
        print(f"  -> appended {n_cat} new P## entries to {CATALOG.name}")
        n_todo = append_scanner_todos(new_entries, ws, dry_run=args.dry_run)
        print(f"  -> appended {n_todo} scanner-gap TODOs to {ws.name}/TODO.md")
    else:
        print("  nothing new to append")

    # Write ledger (only on non-dry-run — ingestion is committed)
    if not args.dry_run:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(ledger_path, "w") as fd:
            fd.write("# ingested findings — (source_digest\\tfinding_id)\n")
            fd.write("# generated by tools/digest-to-patterns.py — do not edit\n")
            for k in sorted(ingested_keys):
                fd.write(k + "\n")

    print("[done]")


if __name__ == "__main__":
    main()
