#!/usr/bin/env python3
"""mine-audit-to-patterns.py — text-based audit-report → stub pattern YAML.

Generalization of `audit-text-to-specs.py` for non-EVM corpora. The original
hard-filters out Rust/Soroban/Move/etc. via `_is_non_evm_filename`; this tool
inverts that filter so a Stellar/Soroban or Sui-Move audit text can seed
Rust/non-EVM detector specs.

Usage:
    python3 tools/mine-audit-to-patterns.py \\
        --text-file /Users/wolf/audits/k2/prior_audits/halborn.txt \\
        --source halborn-2025-09 \\
        --language rust \\
        --platform soroban \\
        --out-dir detectors/_specs/drafts_halborn_k2

For batch use, see `tools/mine-audit-to-patterns.sh`.

Emits one YAML per discovered finding section with these fields:
    id, title, severity, language, platform, source, source_id,
    bug_class (heuristic), indicators (extracted regex hints),
    real_world_example (excerpt), suggested_remediation (excerpt or empty)

Output is STUB-quality — Agent-led extraction (e.g. Agent 2 in R-K2-1) produces
higher-fidelity YAMLs. Use this tool for fast first-pass corpus seeding on a
new non-EVM engagement, then iterate.
"""
import argparse
import re
import sys
from pathlib import Path

# Heuristic finding-section delimiters we've seen in the wild
FINDING_PATTERNS = [
    # Halborn: "7.1 SYSTEMIC LACK OF AUTHENTICATION..."
    re.compile(r"^([0-9]+\.[0-9]+)\s+([A-Z][A-Z0-9 ,'/&\u2013\u2014\u2019\(\)\.-]{8,200})$", re.MULTILINE),
    # Common: "## H-01 Title", "### M-3 Title"
    re.compile(r"^#{1,4}\s+([HMLCQI]-?[0-9]+\.?[0-9]*)\s*[:\u2014\u2013-]\s*(.+)$", re.MULTILINE),
    # V12: "# Title\n#XXXXX\n- Severity: ..."
    re.compile(r"^#\s+(.+?)\n\*\*#([0-9]+)\*\*", re.MULTILINE),
    # WatchPug-style: "## Critical / High / Medium" headers without IDs (handled separately)
]

SEVERITY_RE = re.compile(
    r"\b(Critical|High|Medium|Low|Informational|Info|QA)\b", re.IGNORECASE
)

INVALID_REASON_RE = re.compile(r"Invalid Reason", re.IGNORECASE)

# V12-H2 / Zellic: a standalone "Invalid" line right after the severity label
# indicates V12 self-invalidated the finding during review. Format is always:
#   <Critical|High|Medium|Low> risk
#
#   Invalid
#
V12_H2_INVALID_RE = re.compile(
    r"^(?:Critical|High|Medium|Low|Informational)\s+risk\s*\n+Invalid\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _kebab(name: str, max_len: int = 70) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    if s and s[0].isdigit():
        s = "f-" + s
    return s[:max_len]


def _classify_bug_class(blob: str) -> str:
    blob_low = blob.lower()
    if any(k in blob_low for k in ("require_auth", "missing auth", "unauthorized", "access control", "privileged", "admin role")):
        return "authorization"
    if any(k in blob_low for k in ("ttl", "archive", "expire", "persistent storage", "instance storage")):
        return "ttl-archival"
    if any(k in blob_low for k in ("oracle", "price", "feed", "reflector", "twap", "circuit breaker")):
        return "oracle-cascade"
    if any(k in blob_low for k in ("rounding", "precision", "truncat", "div before mul", "decimals")):
        return "precision-loss"
    if any(k in blob_low for k in ("liquidat", "health factor", "collateral", "bad debt")):
        return "liquidation"
    if any(k in blob_low for k in ("unwrap", "panic", "expect", "error handling")):
        return "error-handling"
    if any(k in blob_low for k in ("reward", "incentive", "emission", "claim")):
        return "reward-accounting"
    if any(k in blob_low for k in ("validate", "missing check", "input", "zero address", "bound")):
        return "input-validation"
    if any(k in blob_low for k in ("flash loan", "atomicity", "premium")):
        return "flash-loan"
    if any(k in blob_low for k in ("abi", "cross-contract", "invoke_contract", "client signature")):
        return "abi-mismatch"
    if any(k in blob_low for k in ("bitmap", "reserve id", "off-by-one")):
        return "bitmap-bounds"
    return "miscellaneous"


def _norm_severity(raw: str) -> str:
    s = raw.strip().lower()
    if s in ("critical", "c"):
        return "Critical"
    if s in ("high", "h"):
        return "High"
    if s in ("medium", "med", "m"):
        return "Medium"
    if s in ("low", "l", "qa"):
        return "Low"
    if s in ("info", "informational", "i"):
        return "Info"
    return "Unknown"


def _extract_findings(text: str, source_kind: str):
    """Return list of (source_id, title, body) tuples."""
    findings = []
    if source_kind in ("halborn", "spearbit", "zellic"):
        # Halborn/Spearbit/Zellic: TOC followed by per-section detail.
        # Section IDs are 2-level (X.Y) or 3-level (X.Y.Z), possibly
        # followed by a DOT (Zellic format: `3.1.   Title`).
        # Spearbit findings live exclusively at X.Y.Z — Halborn/Zellic use X.Y.
        # Zellic also allows leading whitespace (indented TOC-style body).
        if source_kind == "zellic":
            # Allow leading whitespace + optional trailing dot after the id
            sec = re.compile(
                r"^[ \t]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.?[ \t]+([A-Za-z][A-Za-z0-9 ,'/&\u2013\u2014\u2019\(\)\.\"\-_]{6,250})$",
                re.MULTILINE,
            )
        else:
            sec = re.compile(
                r"^([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s+([A-Za-z][A-Za-z0-9 ,'/&\u2013\u2014\u2019\(\)\.\"\-_]{6,250})$",
                re.MULTILINE,
            )
        matches = list(sec.finditer(text))
        # Per id, keep ALL occurrences but only emit the one with the longest
        # body (typically the detail section, not the TOC).
        by_id = {}
        for m in matches:
            by_id.setdefault(m.group(1), []).append(m)
        def _id_sort_key(s):
            return tuple(int(p) for p in s.split("."))
        for sid in sorted(by_id.keys(), key=_id_sort_key):
            # Spearbit: skip X.Y section headers (severity groups like
            # "Medium Risk") — findings live at X.Y.Z only. Halborn keeps both.
            if source_kind == "spearbit" and sid.count(".") < 2:
                continue
            occurrences = by_id[sid]
            # Compute body for each, pick longest
            best_match, best_body = None, ""
            for m in occurrences:
                start = m.end()
                # Body extends to next X.Y or X.Y.Z header with a strictly
                # greater or equal depth (prevents 5.1 gobbling 5.1.1's body).
                next_start = len(text)
                for m2 in matches:
                    if m2.start() > m.start() and m2.start() < next_start:
                        # Only stop at a sibling OR a shallower section.
                        m2_depth = m2.group(1).count(".")
                        m_depth = m.group(1).count(".")
                        if m2_depth <= m_depth or m2.group(1).startswith(sid + "."):
                            # Include direct children for halborn, break on
                            # siblings/shallower. For spearbit X.Y.Z, break on
                            # any next X.Y.Z sibling too.
                            if m2_depth == m_depth:
                                next_start = m2.start()
                                break
                            elif m2_depth < m_depth:
                                next_start = m2.start()
                                break
                body = text[start:next_start]
                if len(body) > len(best_body):
                    best_body = body
                    best_match = m
            if best_match is None or len(best_body.strip()) < 80:
                continue
            # Filter: dot-leader TOC lines (e.g. "5.1.1 Title . . . . . 4")
            title_str = best_match.group(2).strip()
            if ". . . . ." in title_str or title_str.endswith("."):
                # Try to salvage by stripping trailing dot-leader + page num
                title_str = re.sub(r"\s*\.(?:\s*\.)+.*$", "", title_str).strip()
                if len(title_str) < 8:
                    continue
            findings.append((sid, title_str, best_body))
    elif source_kind == "v12":
        # V12: "# Title\n**#NNNNN**\n- Severity: X\n## Targets..."
        # Section lasts until next '# ' at column 0
        v12_re = re.compile(
            r"^#\s+(?P<title>.+?)\n\*\*#(?P<id>[0-9]+)\*\*\n",
            re.MULTILINE,
        )
        matches = list(v12_re.finditer(text))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[m.end():end]
            findings.append((m.group("id"), m.group("title"), body))
    elif source_kind == "v12-h2":
        # V12 / Zellic H2-anchor format:
        #   ## [Title of finding](#finding-NNNNN)
        #   <body text>
        #   ### Impact
        #   ...
        #   ### Remediation
        #   ...
        #   Critical risk       <- severity line (optional)
        #   Invalid             <- self-invalidation marker (optional)
        #   F-NNNNN             <- next finding's id prefix
        v12h2_re = re.compile(
            r"^##\s+\[(?P<title>[^\]]+)\]\(#finding-(?P<id>\d+)\)\s*$",
            re.MULTILINE,
        )
        matches = list(v12h2_re.finditer(text))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[m.end():end]
            findings.append((m.group("id"), m.group("title").strip(), body))
    elif source_kind == "generic":
        # Try '## H-01 ...' / '### M-2 ...' etc.
        gen_re = re.compile(
            r"^#{1,4}\s+(?P<id>[HMLCQI]-?[0-9]+(?:\.[0-9]+)?)\s*[:\u2014\u2013-]\s*(?P<title>.+)$",
            re.MULTILINE,
        )
        matches = list(gen_re.finditer(text))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[m.end():end]
            findings.append((m.group("id"), m.group("title").strip(), body))
    return findings


def _emit_yaml(out_dir: Path, source: str, language: str, platform: str,
               sid: str, title: str, body: str) -> Path:
    # Severity may appear at the head (Halborn, generic) or tail (V12-H2 puts
    # "Critical risk" as the very last line before the next finding).
    sev_match = SEVERITY_RE.search(body[:400]) or SEVERITY_RE.search(body[-600:])
    severity = _norm_severity(sev_match.group(1)) if sev_match else "Unknown"
    bug_class = _classify_bug_class(title + "\n" + body[:600])
    invalid = bool(INVALID_REASON_RE.search(body))

    if invalid:
        # V12 self-invalidated; skip emission, caller can collect for OOS list
        return None

    slug = _kebab(title) or _kebab(sid)
    if not slug:
        return None
    yaml_path = out_dir / f"{slug}.yaml"
    if yaml_path.exists():
        # Disambiguate
        yaml_path = out_dir / f"{slug}-{_kebab(sid)}.yaml"

    # Excerpt: first paragraph, max 600 chars
    para = body.strip().split("\n\n")[0].strip().replace("\n", " ")
    excerpt = para[:600] + ("..." if len(para) > 600 else "")
    excerpt = excerpt.replace('"', "'")

    indicators = []
    # Backtick code identifiers as hint indicators
    for ident in re.findall(r"`([A-Za-z_][A-Za-z0-9_]{2,40}(?:\([^)]*\))?)`", body[:2000])[:8]:
        indicators.append(f"references {ident!r}")
    if not indicators:
        indicators.append(f"text-pattern: {slug.replace('-', ' ')[:60]}")

    yaml_text = f"""id: {slug}
title: |
  {title.strip()[:120]}
severity: {severity}
language: {language}
platform: {platform}
source: {source}
source_id: "{sid}"
bug_class: {bug_class}
indicators:
"""
    for ind in indicators[:8]:
        yaml_text += f"  - {ind!r}\n"
    yaml_text += f"""victim: tbd
exploit_precondition: tbd
real_world_example: |
  {excerpt}
suggested_remediation: |
  See source report {sid} ({source}).
cross_refs: []
"""

    yaml_path.write_text(yaml_text)
    return yaml_path


def _detect_source_kind(text: str) -> str:
    head = text[:5000]
    # Zellic / V12 H2-anchor format: "## [Title](#finding-NNNNN)"
    if re.search(r"^##\s+\[[^\]]+\]\(#finding-\d+\)", text[:20000], re.MULTILINE):
        return "v12-h2"
    if "Spearbit" in head[:2000] or "spearbit.com" in head[:3000]:
        return "spearbit"
    if "Halborn" in head or re.search(r"^\s*7\.[0-9]+\s+[A-Z]", head, re.MULTILINE):
        return "halborn"
    if re.search(r"#\s*[0-9]{5}\s*$", head, re.MULTILINE) or "V12" in head[:200] or "Audited by" in head:
        return "v12"
    return "generic"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--text-file", required=True, type=Path,
                    help="Path to audit report text (output of pdftotext)")
    ap.add_argument("--source", required=True,
                    help="Source slug, e.g. halborn-2025-09")
    ap.add_argument("--language", default="rust",
                    help="Language tag (default: rust)")
    ap.add_argument("--platform", default="soroban",
                    help="Platform/chain tag (default: soroban)")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="Output dir for YAMLs (created if missing)")
    ap.add_argument("--source-kind", default="auto",
                    choices=("auto", "halborn", "spearbit", "zellic", "v12", "v12-h2", "generic"))
    args = ap.parse_args()

    if not args.text_file.is_file():
        print(f"[err] not a file: {args.text_file}", file=sys.stderr)
        sys.exit(2)

    text = args.text_file.read_text(errors="replace")
    kind = args.source_kind
    if kind == "auto":
        kind = _detect_source_kind(text)
    print(f"[setup] source_kind={kind} text-len={len(text)} chars")

    findings = _extract_findings(text, kind)
    print(f"[setup] discovered {len(findings)} candidate findings")

    args.out_dir.mkdir(parents=True, exist_ok=True)

    emitted = 0
    skipped_invalid = 0
    for sid, title, body in findings:
        # V12 "Invalid Reason" subsection anywhere in body ⇒ self-invalidated
        if INVALID_REASON_RE.search(body):
            skipped_invalid += 1
            continue
        # V12-H2 / Zellic: standalone "Invalid" line after severity, in the
        # last 500 chars of body ⇒ reviewed-and-rejected marker.
        if V12_H2_INVALID_RE.search(body[-500:]):
            skipped_invalid += 1
            continue
        path = _emit_yaml(args.out_dir, args.source, args.language,
                          args.platform, sid, title, body)
        if path:
            emitted += 1

    print(f"[done] emitted {emitted} YAMLs to {args.out_dir}")
    print(f"[done] skipped {skipped_invalid} self-invalidated findings")


if __name__ == "__main__":
    main()
