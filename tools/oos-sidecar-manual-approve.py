#!/usr/bin/env python3
"""oos-sidecar-manual-approve.py — codify operator manual override of the
per-finding OOS heuristic sidecar.

Background
----------
``tools/per-finding-oos-check.py`` writes a JSON sidecar at
``<workspace>/.auditooor/oos_check_<finding_sha256>.json``. Its default
heuristic mode is a token-overlap test that fires on ANY mention of OOS-class
vocabulary (governance, admin, compromised key, etc.) — even when those tokens
appear inside the finding's *rebuttal prose* explaining why a clause does NOT
apply. This causes false-positive ``matches-oos`` verdicts that block Check
#29 in ``pre-submit-check.sh``.

The contract: when a finding embeds clause-anchored rebuttals (markdown
``**Cn ...**`` headers walking through each matched OOS clause), the operator
may flip the sidecar verdict to ``in-scope`` after manual review. This tool
codifies that override path — gated on per-clause rebuttal evidence so the
flag cannot be applied to a draft that lacks structured rebuttals for the
specific clause IDs being approved.

Usage
-----
    oos-sidecar-manual-approve.py
        --workspace <ws>
        --finding   <draft.md>
        [--all-clauses-ok | --clause-ids c1,c2,c3]
        [--rationale "<text>"]
        [--dry-run]

Exit codes
----------
    0 — sidecar updated (or, with --dry-run, override would be applied)
    1 — sidecar / finding missing, or insufficient clause-specific rebuttals
    2 — usage error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

# Match clause-anchored rebuttals in the markdown body. We accept both
# ``**Cn**`` (strict spec form) and ``**Cn — text**`` (the form the rebuttal
# section actually uses, where the bold span wraps the whole clause heading).
_CLAUSE_ANCHOR_RE = re.compile(r"\*\*(C\d+)\b")
_CLAUSE_REBUTTAL_RE = re.compile(
    r"(?m)^"
    r"[ \t]*(?:[-*+][ \t]+)?"
    r"\*\*(?P<cid>C\d+)\b(?P<heading>[^*\n]*)\*\*"
    r"(?P<tail>[^\n]*)"
    r"(?P<body>"
    r"(?:\n"
    r"(?![ \t]*(?:[-*+][ \t]+)?\*\*C\d+\b)"
    r"(?![ \t]{0,3}#{1,6}[ \t]+)"
    r".*"
    r")*"
    r")",
)
_REBUTTAL_CUE_RE = re.compile(
    r"\b("
    r"rebuttal|not\s+(?:a\s+)?match|does\s+not\s+apply|do\s+not\s+apply|"
    r"not\s+applicable|not\s+oos|in[-\s]?scope|because|root\s+cause|"
    r"attack\s+path|production\s+path|permissionless|public\s+(?:path|entry)"
    r")\b",
    re.IGNORECASE,
)
_MIN_REBUTTAL_WORDS = 8
_OVERRIDE_MODE = "heuristic+manual-rebuttal"


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _normalize_clause_ids(raw: str) -> list[str]:
    out: list[str] = []
    for tok in raw.replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        m = re.match(r"^[Cc](\d+)$", tok)
        if not m:
            print(
                f"[oos-sidecar-manual-approve] bad clause id {tok!r}; "
                "expected form C7 or c7",
                file=sys.stderr,
            )
            return []
        out.append(f"C{m.group(1)}")
    return out


def _meaningful_words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9][A-Za-z0-9_\-']+", text)


def _clause_rebuttals(finding_text: str) -> dict[str, list[str]]:
    """Return substantive rebuttal snippets keyed by clause ID.

    The manual approval command is intentionally conservative: a bare
    ``**C7**`` anchor is not enough. The clause entry must carry rebuttal prose
    on the same bullet/paragraph, and that prose must include a rebuttal cue.
    """
    out: dict[str, list[str]] = {}
    for m in _CLAUSE_REBUTTAL_RE.finditer(finding_text):
        cid = m.group("cid")
        snippet = " ".join(
            part.strip()
            for part in (
                m.group("heading") or "",
                m.group("tail") or "",
                m.group("body") or "",
            )
            if part and part.strip()
        )
        snippet = re.sub(r"\s+", " ", snippet).strip(" :-\t")
        if (
            len(_meaningful_words(snippet)) >= _MIN_REBUTTAL_WORDS
            and _REBUTTAL_CUE_RE.search(snippet)
        ):
            out.setdefault(cid, []).append(snippet)
    return out


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oos-sidecar-manual-approve.py",
        description="Operator manual override of per-finding OOS heuristic sidecar.",
    )
    parser.add_argument("--workspace", required=True, help="Workspace root.")
    parser.add_argument("--finding", required=True, help="Path to draft finding (Markdown).")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "--all-clauses-ok",
        action="store_true",
        help="Approve every clause in the sidecar.",
    )
    grp.add_argument(
        "--clause-ids",
        default=None,
        help="Comma-separated subset (e.g. C5,C12,C27).",
    )
    parser.add_argument(
        "--rationale",
        default="",
        help="Operator rationale recorded in the sidecar.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print intended diff without writing.",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    finding = Path(args.finding).expanduser().resolve()
    if not ws.is_dir():
        _eprint(f"workspace not found: {ws}")
        return 1
    if not finding.is_file():
        _eprint(f"finding not found: {finding}")
        return 1

    sha = _sha256_file(finding)
    sidecar = ws / ".auditooor" / f"oos_check_{sha}.json"
    if not sidecar.is_file():
        _eprint(f"sidecar not found: {sidecar}")
        _eprint(
            "Run tools/per-finding-oos-check.py first to generate the heuristic sidecar."
        )
        return 1

    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    sidecar_clauses = [c.get("id", "") for c in payload.get("clauses_checked", [])]
    if not sidecar_clauses:
        _eprint("sidecar has no clauses_checked entries to approve")
        return 1

    if args.all_clauses_ok:
        approved = list(sidecar_clauses)
    else:
        approved = _normalize_clause_ids(args.clause_ids or "")
        if not approved:
            return 2
        unknown = [c for c in approved if c not in sidecar_clauses]
        if unknown:
            _eprint(f"clause-ids not present in sidecar: {unknown}")
            return 1

    finding_text = finding.read_text(encoding="utf-8", errors="replace")
    anchors = _CLAUSE_ANCHOR_RE.findall(finding_text)
    rebuttals = _clause_rebuttals(finding_text)
    missing = [cid for cid in approved if cid not in rebuttals]
    if missing:
        _eprint(
            "manual approval refused: missing meaningful clause-specific "
            f"rebuttals for {','.join(missing)}"
        )
        _eprint(
            "Add a markdown entry such as "
            "`- **C7 — <clause summary>**: Rebuttal: <why this finding is "
            "not covered by C7>` for each approved clause, then rerun."
        )
        _eprint(
            f"detected clause anchors: {','.join(sorted(set(anchors))) or 'none'}; "
            f"detected substantive rebuttals: "
            f"{','.join(sorted(rebuttals)) or 'none'}"
        )
        return 1

    prior_verdict = payload.get("verdict")
    prior_mode = payload.get("mode")

    payload["verdict"] = "in-scope"
    payload["mode"] = _OVERRIDE_MODE
    payload["manual_approval_at"] = _utc_now_iso()
    payload["manual_approval_rationale"] = args.rationale
    payload["manual_approved_clauses"] = approved
    payload["manual_approval_anchor_count"] = len(anchors)
    payload["manual_approval_rebuttals"] = {
        cid: rebuttals[cid][0] for cid in approved
    }

    print(f"[oos-sidecar-manual-approve] sidecar: {sidecar}")
    print(f"  prior verdict: {prior_verdict}  mode: {prior_mode}")
    print(f"  new   verdict: in-scope         mode: {_OVERRIDE_MODE}")
    print(f"  approved clauses ({len(approved)}): {','.join(approved)}")
    print(f"  rebuttal anchors found: {len(anchors)}")
    print(f"  clause-specific rebuttals accepted: {','.join(approved)}")
    if args.dry_run:
        print("  [dry-run] not writing")
        return 0
    _atomic_write(sidecar, payload)
    print("  written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
