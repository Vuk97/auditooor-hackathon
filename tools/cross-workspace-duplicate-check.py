#!/usr/bin/env python3
"""
cross-workspace-duplicate-check.py — Mandatory dedup gate before filing

Reads a paste-ready markdown file, extracts a bug-class fingerprint
(title-token bag + first-paragraph TF-IDF approximation), and cross-references
against every other workspace's filed/staged paste-ready files.

If similarity > 0.7, emits BLOCKED_<fingerprint>.md and exits non-zero.

This is wired into pre-submit-check.sh as Check 40.

Usage:
    python3 tools/cross-workspace-duplicate-check.py <paste-ready.md>
        [--workspace <ws-name>]
        [--audits-dir ~/audits]
        [--threshold 0.7]
        [--out-dir /tmp]
        [--quiet]

Exit codes:
    0  No duplicate found — safe to proceed
    1  Duplicate found (blocked) — BLOCKED_<id>.md written
    2  Usage / input error
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_THRESHOLD = 0.70
AUDITOOOR_DIR = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------

def extract_title(text: str) -> str:
    """Extract the canonical finding title from a paste-ready markdown."""
    # Pattern 1: ``` block containing a title (common in polymarket submissions)
    m = re.search(r"```\s*\n([^\n]{10,120})\n```", text)
    if m:
        return m.group(1).strip()
    # Pattern 2: ## Finding Title line
    m = re.search(r"(?:^|\n)#{1,4}\s*(?:Finding\s+)?Title[^\n]*\n+([^\n]{10,120})", text)
    if m:
        return m.group(1).strip()
    # Pattern 3: First H1/H2 section title
    m = re.search(r"(?:^|\n)#{1,2}\s+([^\n]{10,120})", text)
    if m:
        cand = m.group(1).strip()
        # Skip "Legend", "Summary", structural headers
        skip = re.compile(r"^(legend|summary|severity|target|finding|submission|submitted|draft)", re.I)
        if not skip.match(cand):
            return cand
    return text[:120].strip()


def extract_first_paragraph(text: str) -> str:
    """Extract the first substantive paragraph (the summary / main claim)."""
    # Look for ## Summary section
    m = re.search(r"(?:^|\n)#{1,4}\s*Summary\s*\n+(.+?)(?:\n#{1,4}|\n\n\n)", text, re.DOTALL)
    if m:
        return m.group(1).strip()[:1000]
    # Fallback: first paragraph after first header
    m = re.search(r"(?:^|\n)#{1,3}[^\n]+\n+([^\n#`|]{80,})", text)
    if m:
        return m.group(1).strip()[:1000]
    # Last resort: raw first 800 chars
    return text[:800]


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphabetic tokens, >=3 chars."""
    return [t for t in re.findall(r"[a-zA-Z][a-zA-Z0-9]+", text.lower()) if len(t) >= 3]


# ---------------------------------------------------------------------------
# Fingerprint computation
# ---------------------------------------------------------------------------

# Stop words to skip for TF-IDF
STOP_WORDS = {
    "the", "and", "for", "that", "this", "with", "are", "from", "not", "has",
    "can", "all", "any", "via", "per", "its", "but", "let", "when", "then",
    "call", "each", "get", "set", "use", "used", "also", "into", "will",
    "which", "have", "more", "than", "only", "been", "was", "where",
}

# High-weight security vocabulary — tokens in this set are weighted 3×
SECURITY_VOCAB = {
    "reentrancy", "overflow", "underflow", "unauthorized", "steal", "theft",
    "drain", "exploit", "vulnerability", "attack", "bypass", "arbitrary",
    "missing", "guard", "locked", "permanent", "reverts", "reward", "refund",
    "manipulation", "oracle", "price", "collision", "frontrun", "flash",
    "signature", "permit", "approve", "delegate", "proxy", "upgrade",
    "reentr", "nonreentrant", "callback", "bricks", "stranding", "race",
    "truncation", "inflation", "donation", "griefing", "bricking",
}


def compute_fingerprint(title: str, body: str) -> Dict[str, Any]:
    """
    Compute a bug-class fingerprint from title + body.
    Returns a dict with token_bag, tfidf_approx, and a hex digest.
    """
    title_tokens = tokenize(title)
    body_tokens = tokenize(body)

    # Title tokens get 5× weight
    all_tokens = title_tokens * 5 + body_tokens

    # Remove stop words
    filtered = [t for t in all_tokens if t not in STOP_WORDS]

    # Token frequency
    freq = Counter(filtered)

    # Apply security vocab weight
    for token, count in list(freq.items()):
        if token in SECURITY_VOCAB:
            freq[token] = count * 3

    # Top-50 tokens form the fingerprint bag
    top_tokens = sorted(freq.items(), key=lambda x: -x[1])[:50]
    token_bag = {t: c for t, c in top_tokens}

    # Compute a short hex digest for filename uniqueness
    canonical = " ".join(sorted(token_bag.keys()))
    digest = hashlib.sha1(canonical.encode()).hexdigest()[:12]

    return {
        "title": title,
        "title_tokens": title_tokens,
        "token_bag": token_bag,
        "digest": digest,
    }


def cosine_similarity(bag_a: Dict[str, int], bag_b: Dict[str, int]) -> float:
    """Cosine similarity between two token-frequency bags."""
    if not bag_a or not bag_b:
        return 0.0
    common = set(bag_a) & set(bag_b)
    if not common:
        return 0.0
    dot = sum(bag_a[t] * bag_b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in bag_a.values()))
    norm_b = math.sqrt(sum(v * v for v in bag_b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Workspace discovery
# ---------------------------------------------------------------------------

def discover_paste_ready_files(
    audits_dir: Path,
    exclude_workspace: Optional[str] = None,
) -> List[Tuple[str, Path]]:
    """
    Find all paste-ready markdown files in every workspace's submissions/.
    Returns [(workspace_name, path)].
    """
    results: List[Tuple[str, Path]] = []
    if not audits_dir.exists():
        return results
    for ws_dir in sorted(audits_dir.iterdir()):
        if not ws_dir.is_dir() or ws_dir.name.startswith("."):
            continue
        if ws_dir.name in ("auditooor", "test-dogfood-r48"):
            continue
        if exclude_workspace and ws_dir.name == exclude_workspace:
            continue
        # Search in submissions/, submissions/staging/, and root SUBMISSIONS.md
        search_dirs = [
            ws_dir / "submissions",
            ws_dir / "submissions" / "staging",
        ]
        for d in search_dirs:
            if d.is_dir():
                for f in sorted(d.glob("*.md")):
                    if f.name.startswith("BLOCKED_"):
                        continue
                    if f.stat().st_size > 200:  # skip tiny stubs
                        results.append((ws_dir.name, f))
        # Also check root SUBMISSIONS.md as a corpus reference
        root_sub = ws_dir / "SUBMISSIONS.md"
        if root_sub.exists() and root_sub.stat().st_size > 200:
            results.append((ws_dir.name, root_sub))
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paste_ready",
        help="Path to the paste-ready markdown file to check",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Name of the current workspace to exclude from comparison",
    )
    parser.add_argument(
        "--audits-dir",
        default=os.environ.get("AUDITS_DIR", str(Path.home() / "audits")),
        help="Root directory containing audit workspaces (default: ~/audits)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Similarity threshold for blocking (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--out-dir",
        default="/tmp",
        help="Directory to write BLOCKED_*.md files (default: /tmp)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit machine-readable JSON result to stdout",
    )
    args = parser.parse_args()

    paste_path = Path(args.paste_ready).expanduser()
    if not paste_path.exists():
        print(f"[dedup-check] ERROR: paste-ready file not found: {paste_path}", file=sys.stderr)
        sys.exit(2)

    audits_dir = Path(args.audits_dir).expanduser()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Fingerprint the candidate
    candidate_text = paste_path.read_text(errors="replace")
    title = extract_title(candidate_text)
    body = extract_first_paragraph(candidate_text)
    candidate_fp = compute_fingerprint(title, body)

    if not args.quiet:
        print(f"[dedup-check] candidate: '{title[:80]}...' (digest={candidate_fp['digest']})")

    # 2. Gather comparison corpus
    corpus_files = discover_paste_ready_files(audits_dir, exclude_workspace=args.workspace)
    # Also add the SUBMISSIONS.md files in the audits root
    submissions_root = audits_dir / "SUBMISSION_TRACKER.md"
    if submissions_root.exists():
        corpus_files.append(("_root", submissions_root))

    if not args.quiet:
        print(f"[dedup-check] comparing against {len(corpus_files)} corpus files "
              f"across workspaces: {sorted({ws for ws, _ in corpus_files})}")

    # 3. Compare
    matches: List[Dict[str, Any]] = []
    for ws_name, corp_path in corpus_files:
        # Skip comparing file to itself
        if corp_path.resolve() == paste_path.resolve():
            continue
        try:
            corp_text = corp_path.read_text(errors="replace")
        except Exception:
            continue
        corp_title = extract_title(corp_text)
        corp_body = extract_first_paragraph(corp_text)
        corp_fp = compute_fingerprint(corp_title, corp_body)

        sim = cosine_similarity(candidate_fp["token_bag"], corp_fp["token_bag"])
        if sim >= args.threshold:
            matches.append({
                "workspace": ws_name,
                "path": str(corp_path),
                "title": corp_title[:120],
                "similarity": round(sim, 4),
                "digest": corp_fp["digest"],
            })

    # 4. Sort by similarity descending
    matches.sort(key=lambda x: -x["similarity"])

    now = datetime.now(timezone.utc).isoformat()
    result = {
        "checked_at": now,
        "candidate_path": str(paste_path),
        "candidate_title": title,
        "candidate_digest": candidate_fp["digest"],
        "threshold": args.threshold,
        "blocked": len(matches) > 0,
        "matches": matches,
    }

    if args.json_out:
        print(json.dumps(result, indent=2))

    if not matches:
        if not args.quiet:
            print("[dedup-check] OK — no duplicate found above threshold")
        if not args.json_out:
            print("PASS")
        sys.exit(0)

    # 5. Blocked — write BLOCKED file and report
    blocked_name = f"BLOCKED_{candidate_fp['digest']}.md"
    blocked_path = out_dir / blocked_name

    best = matches[0]
    blocked_lines = [
        f"# BLOCKED — Duplicate Risk Detected",
        f"",
        f"**Checked:** {now}",
        f"**Candidate:** `{paste_path}`",
        f"**Candidate title:** {title}",
        f"**Threshold:** {args.threshold}",
        f"",
        f"## Top match ({best['similarity']:.1%} similar)",
        f"",
        f"- **Workspace:** `{best['workspace']}`",
        f"- **File:** `{best['path']}`",
        f"- **Title:** {best['title']}",
        f"- **Similarity:** {best['similarity']:.4f}",
        f"",
        f"## All matches above threshold",
        f"",
    ]
    for m in matches:
        blocked_lines.append(
            f"| {m['workspace']} | {m['similarity']:.4f} | {m['title'][:80]} |"
        )
    blocked_lines += [
        f"",
        f"## Action required",
        f"",
        f"Review the matched prior submission before filing. If this is a genuinely",
        f"different bug in a different codebase, add `--threshold 0.5` to override.",
        f"If it is the same bug class in a different protocol, consider whether the",
        f"finding adds novel value or if a cross-reference note suffices.",
        f"",
        f"Re-run with `--threshold <lower>` to override if confirmed novel.",
    ]
    blocked_path.write_text("\n".join(blocked_lines))

    print(f"[dedup-check] BLOCKED — similarity {best['similarity']:.1%} >= threshold {args.threshold}")
    print(f"  Best match: [{best['workspace']}] {best['title'][:80]}")
    print(f"  Details: {blocked_path}")
    print(f"FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
