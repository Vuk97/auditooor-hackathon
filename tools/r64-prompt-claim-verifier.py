#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared 10 files via tools/agent-pathspec-register.py at lane start
"""r64-prompt-claim-verifier.py - Standalone R64 enforcement.

Extracts factual claims from an orchestrator's Agent-dispatch prompt
and verifies each against the canonical inventory snapshot. R64 catches
hallucinated claims BEFORE the worker is dispatched - L25/L26 trust-
but-verify only fires AFTER the worker reads source files; R64 fires
at dispatch time.

Claim classes detected:
    - tool-path     : "tools/foo.py", "./tools/bar.sh"
    - mcp-callable  : "vault_some_name"
    - check         : "Check #42", "Check#42"
    - r-rule        : "R52", "L34", "R-52", "Rule 52"
    - schema        : "auditooor.foo.v1"
    - makefile      : "make audit-fast", "make hunt"
    - record-count  : "10K Cantina rationales", "5,000 findings"  (heuristic)
    - record-source : "prior_audits/" / "findings_*.jsonl"

Output schema (auditooor.r64_prompt_claim_verifier.v1):

    {
      "schema": "...",
      "prompt_path": str,
      "claims": [
        {
          "claim": str,
          "kind": str,
          "verified": bool,
          "context_line": str (truncated),
          "evidence": ...
        }
      ],
      "total_claims": int,
      "verified_count": int,
      "unverified_count": int,
      "overall_verdict": "pass-all-verified" |
                         "pass-no-claims" |
                         "ok-rebuttal" |
                         "fail-prompt-contains-unverified-claim"
    }

CLI:

    # Read a prompt file
    python3 tools/r64-prompt-claim-verifier.py <prompt-file>

    # From stdin
    cat prompt.md | python3 tools/r64-prompt-claim-verifier.py -

    # JSON output
    python3 tools/r64-prompt-claim-verifier.py prompt.md --json

    # Strict mode (exit non-zero on unverified claims)
    python3 tools/r64-prompt-claim-verifier.py prompt.md --strict

Override marker (any of):
    <!-- r64-rebuttal: <reason up to 200 chars> -->
    r64-rebuttal: <reason up to 200 chars>

Empirical anchor (2026-05-26): orchestrator emitted TOK-A subagent
prompt with the claim "mine 10K Cantina rationales". Canonical
inventory shows reference/findings_*.jsonl contains 181 records
total. The claim was unverifiable but went unchecked. R64 would have
flagged it pre-dispatch.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Import the inventory module for direct invocation.
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))

try:
    # Import via canonical-inventory module file name
    import importlib.util
    inv_path = _THIS_DIR / "canonical-inventory.py"
    spec = importlib.util.spec_from_file_location("canonical_inventory", inv_path)
    canonical_inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(canonical_inventory)
except Exception as exc:
    print(f"FATAL: cannot import canonical-inventory module: {exc!r}",
          file=sys.stderr)
    sys.exit(1)

SCHEMA = "auditooor.r64_prompt_claim_verifier.v1"

# ---------------------------------------------------------------------------
# Claim-extraction regex matrix
# ---------------------------------------------------------------------------
#
# Each pattern captures the literal claim string. The Verifier then routes
# each claim to canonical_inventory.verify_claim() for the actual lookup.

# Tool paths: tools/foo.py, ./tools/foo.sh, tools/hooks/bar.py
_TOOL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?:\./)?tools/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.(?:py|sh)"
    r"(?![A-Za-z0-9_])"
)

# MCP callable names: vault_<something>
_MCP_CALLABLE_RE = re.compile(
    r"(?<![A-Za-z0-9_])vault_[a-z][a-z0-9_]+(?![A-Za-z0-9_])"
)

# Pre-submit check references: Check #42, Check#42, "Check #N"
_CHECK_RE = re.compile(
    r"\bCheck\s*#\s*(\d+)\b"
)

# R-rule / L-rule references: R52, L34, "Rule 52", "Rule R52", R-52
_R_RULE_RE = re.compile(
    r"\b(?:Rule\s+)?([RL])[\s_-]?(\d+[A-Z]?)\b"
)

# Schema names: auditooor.<name>.v<N>
_SCHEMA_RE = re.compile(
    r"auditooor\.[a-z0-9_]+\.v\d+"
)

# Makefile targets: "make foo", "make foo-bar"
_MAKE_TARGET_RE = re.compile(
    r"\bmake\s+([a-zA-Z][a-zA-Z0-9_-]*)\b"
)

# Record-count claims (heuristic): "10K Cantina rationales", "5,000 findings",
# "200 prior audits", "3000 records"
_RECORD_COUNT_RE = re.compile(
    r"(?P<count>\d{1,3}(?:[,.]\d{3})+|\d+[Kk]?)\s+"
    r"(?P<noun>cantina|solodit|immunefi|sherlock|code4rena|hackenproof|"
    r"finding|findings|rationale|rationales|prior[\s-]audit[s]?|"
    r"record|records|verdict|verdicts|triager[\s-]closure[s]?)"
    r"\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Rebuttal detection
# ---------------------------------------------------------------------------

_R64_REBUTTAL_HTMLCOMMENT_RE = re.compile(
    r"<!--\s*r64-rebuttal:\s*(.{1,200}?)\s*-->",
    re.IGNORECASE,
)
_R64_REBUTTAL_VISIBLE_RE = re.compile(
    r"^\s*r64-rebuttal:\s*(.{1,200})$",
    re.MULTILINE | re.IGNORECASE,
)
_R64_REBUTTAL_INLINE_RE = re.compile(
    r"r64-rebuttal:\s*(.{1,200})",
    re.IGNORECASE,
)


# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared in agent_pathspec.json via tools/agent-pathspec-register.py
def detect_rebuttal(prompt_text: str) -> str:
    """Return the rebuttal reason if a valid r64-rebuttal marker is
    present in the prompt, else "".

    Accepts (in order):
    1. <!-- r64-rebuttal: <reason> -->
    2. visible line `r64-rebuttal: <reason>`
    3. any inline `r64-rebuttal: <reason>` (last fallback)

    Empty reasons (only whitespace, or only the closing `-->` token)
    are treated as missing and return "".
    """
    for pat in (_R64_REBUTTAL_HTMLCOMMENT_RE,
                _R64_REBUTTAL_VISIBLE_RE,
                _R64_REBUTTAL_INLINE_RE):
        m = pat.search(prompt_text)
        if m:
            reason = m.group(1).strip()
            # Strip a trailing "-->" if the visible/inline pattern caught it.
            if reason.endswith("-->"):
                reason = reason[:-3].rstrip()
            if reason and len(reason) <= 200:
                return reason
    return ""


# ---------------------------------------------------------------------------
# Claim extraction
# ---------------------------------------------------------------------------

def _line_for_offset(text: str, offset: int) -> str:
    """Return the line containing `offset`, truncated to 200 chars."""
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    line = text[start:end]
    if len(line) > 200:
        line = line[:200] + "..."
    return line.strip()


def extract_claims(text: str) -> list[dict[str, Any]]:
    """Return a list of {claim, kind, context_line, span} extracted
    from the prompt body. Each claim is deduplicated by (kind, claim)
    but each first occurrence is kept for context-line reporting."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _emit(claim: str, kind: str, span: tuple[int, int]):
        key = (kind, claim)
        if key in seen:
            return
        seen.add(key)
        ctx = _line_for_offset(text, span[0])
        out.append({
            "claim": claim,
            "kind_hint": kind,
            "context_line": ctx,
            "offset": span[0],
        })

    # Tool paths
    for m in _TOOL_PATH_RE.finditer(text):
        _emit(m.group(0), "tool-path", m.span())

    # MCP callables
    for m in _MCP_CALLABLE_RE.finditer(text):
        _emit(m.group(0), "mcp-callable", m.span())

    # Check #N
    for m in _CHECK_RE.finditer(text):
        normalised = f"Check #{m.group(1)}"
        _emit(normalised, "check", m.span())

    # R-rules
    for m in _R_RULE_RE.finditer(text):
        prefix = m.group(1).upper()
        suffix = m.group(2)
        # Skip ambiguous matches that look like license/version like R2018
        # by requiring suffix length <= 3.
        if len(suffix) > 3:
            continue
        normalised = f"{prefix}{suffix}"
        _emit(normalised, "r-rule", m.span())

    # Schemas
    for m in _SCHEMA_RE.finditer(text):
        _emit(m.group(0), "schema", m.span())

    # Make targets
    for m in _MAKE_TARGET_RE.finditer(text):
        normalised = f"make {m.group(1)}"
        _emit(normalised, "makefile", m.span())

    # Record-count claims (kept as record-count kind; verify against
    # canonical inventory record_counts_per_source totals).
    for m in _RECORD_COUNT_RE.finditer(text):
        count_raw = m.group("count")
        noun = m.group("noun")
        _emit(f"{count_raw} {noun}", "record-count", m.span())

    return out


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _parse_count_claim(claim: str) -> int | None:
    """Parse '10K cantina rationales' -> 10000.
    '5,000 findings' -> 5000. 'two hundred prior_audits' -> None."""
    m = re.match(r"(?P<num>\d{1,3}(?:[,.]\d{3})+|\d+)(?P<suffix>[Kk]?)", claim)
    if not m:
        return None
    num_str = m.group("num").replace(",", "").replace(".", "")
    try:
        n = int(num_str)
    except ValueError:
        return None
    if m.group("suffix"):
        n *= 1000
    return n


def verify_record_count_claim(snap: dict[str, Any], claim: str) -> dict[str, Any]:
    """Verify a record-count claim against the snapshot.

    A record-count claim is verifiable when the claimed quantity is
    within 25% of an actual canonical source's record count, OR the
    sum of records across the relevant noun-category sources covers
    the claim. Otherwise unverified.
    """
    claimed = _parse_count_claim(claim)
    if claimed is None:
        return {
            "claim": claim,
            "kind": "record-count",
            "verified": False,
            "evidence": {"reason": "could-not-parse-numeric-quantity"},
        }
    sources = snap.get("record_counts_per_source", {}) or {}
    # Sum all counts (the broadest possible canonical pool).
    total = sum(v for v in sources.values() if isinstance(v, int))

    # If claimed is much larger than total, the claim is hallucinated.
    # We use a 2x tolerance: claim must be <= 2 * total to even be
    # plausible. The classifier is then SOFT: a verified claim is one
    # within 25% of an actual source; otherwise we return false with
    # the tot as evidence so the operator can see the discrepancy.
    closest = None
    closest_delta = None
    for src, cnt in sources.items():
        if not isinstance(cnt, int):
            continue
        delta = abs(cnt - claimed) / max(claimed, 1)
        if closest_delta is None or delta < closest_delta:
            closest = src
            closest_delta = delta

    if claimed > total * 2 and total > 0:
        return {
            "claim": claim,
            "kind": "record-count",
            "verified": False,
            "evidence": {
                "claimed": claimed,
                "canonical_total": total,
                "closest_source": closest,
                "closest_count": sources.get(closest) if closest else None,
                "reason": "claim-exceeds-2x-canonical-total",
            },
        }
    if closest_delta is not None and closest_delta <= 0.25:
        return {
            "claim": claim,
            "kind": "record-count",
            "verified": True,
            "evidence": {
                "claimed": claimed,
                "matched_source": closest,
                "matched_count": sources.get(closest),
                "delta_pct": round(closest_delta * 100, 1),
            },
        }
    return {
        "claim": claim,
        "kind": "record-count",
        "verified": False,
        "evidence": {
            "claimed": claimed,
            "canonical_total": total,
            "closest_source": closest,
            "closest_count": sources.get(closest) if closest else None,
            "reason": "no-source-within-25pct-of-claim",
        },
    }


def verify_prompt(prompt_text: str,
                  snap: dict[str, Any]) -> dict[str, Any]:
    """Run claim extraction + verification on a prompt body.

    Returns the schema'd payload (see module docstring)."""
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "claims": [],
        "total_claims": 0,
        "verified_count": 0,
        "unverified_count": 0,
        "overall_verdict": "pass-no-claims",
    }

    rebuttal = detect_rebuttal(prompt_text)
    if rebuttal:
        result["rebuttal_reason"] = rebuttal

    raw_claims = extract_claims(prompt_text)
    result["total_claims"] = len(raw_claims)

    for entry in raw_claims:
        claim = entry["claim"]
        kind_hint = entry["kind_hint"]
        if kind_hint == "record-count":
            v = verify_record_count_claim(snap, claim)
        elif kind_hint == "check":
            v = canonical_inventory.verify_claim(snap, claim)
        else:
            v = canonical_inventory.verify_claim(snap, claim)
        v["context_line"] = entry["context_line"]
        v["offset"] = entry["offset"]
        result["claims"].append(v)
        if v.get("verified"):
            result["verified_count"] += 1
        else:
            result["unverified_count"] += 1

    if result["total_claims"] == 0:
        result["overall_verdict"] = "pass-no-claims"
    elif result["unverified_count"] == 0:
        result["overall_verdict"] = "pass-all-verified"
    elif rebuttal:
        result["overall_verdict"] = "ok-rebuttal"
    else:
        result["overall_verdict"] = "fail-prompt-contains-unverified-claim"
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="R64 prompt-claim verification against canonical inventory."
    )
    parser.add_argument("prompt", nargs="?", default="-",
                        help="Prompt file path (or '-' for stdin).")
    parser.add_argument("--json", action="store_true",
                        help="JSON output (default: human-readable).")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 on unverified claims.")
    parser.add_argument("--workspace", default=None,
                        help="Repo root override.")
    parser.add_argument("--snapshot-path", default=None,
                        help="Snapshot path override.")
    parser.add_argument("--audits-root", default=None,
                        help="Audits root override.")
    parser.add_argument("--refresh", action="store_true",
                        help="Force snapshot refresh.")
    args = parser.parse_args(argv)

    if args.prompt == "-":
        prompt_text = sys.stdin.read()
        prompt_path = "<stdin>"
    else:
        p = Path(args.prompt)
        if not p.is_file():
            print(f"ERROR: prompt file not found: {p}", file=sys.stderr)
            return 1
        prompt_text = p.read_text(encoding="utf-8", errors="replace")
        prompt_path = str(p)

    if args.workspace:
        repo_root = Path(args.workspace).resolve()
    else:
        repo_root = canonical_inventory._find_repo_root(Path.cwd())

    kwargs: dict[str, Any] = {}
    if args.snapshot_path:
        kwargs["snapshot_path"] = Path(args.snapshot_path)
    if args.audits_root:
        kwargs["audits_root"] = Path(args.audits_root)
    snap = canonical_inventory.load_or_refresh(
        repo_root,
        refresh=args.refresh,
        **kwargs,
    )

    result = verify_prompt(prompt_text, snap)
    result["prompt_path"] = prompt_path

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"R64 verdict: {result['overall_verdict']}")
        print(f"  prompt:     {prompt_path}")
        print(f"  total:      {result['total_claims']} claims extracted")
        print(f"  verified:   {result['verified_count']}")
        print(f"  unverified: {result['unverified_count']}")
        rb = result.get("rebuttal_reason", "")
        if rb:
            print(f"  rebuttal:   {rb[:80]}")
        if result["unverified_count"] > 0:
            print("\n  Unverified claims:")
            for c in result["claims"]:
                if c.get("verified"):
                    continue
                print(f"    - [{c.get('kind', '?')}] {c.get('claim', '?')}")
                ev = c.get("evidence")
                if ev:
                    ev_str = json.dumps(ev)
                    if len(ev_str) > 140:
                        ev_str = ev_str[:140] + "..."
                    print(f"      evidence: {ev_str}")

    if args.strict and result["overall_verdict"].startswith("fail-"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
