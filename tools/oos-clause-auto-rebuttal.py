#!/usr/bin/env python3
"""oos-clause-auto-rebuttal.py — generate clause-ID-anchored rebuttal patches.

Wave V-04 follow-up. Per-finding-oos-check uses a heuristic token-overlap
classifier; when a clause matches the finding via shared OOS-class
tokens (often produced by the rebuttal prose itself, not by an attack
precondition), the gate fires until the operator embeds an explicit,
clause-ID-anchored ``**Cn**`` rebuttal in the draft. Existing
free-form rebuttals (e.g. *"Reports relying on an invalid TEE or ZK
proof"*) are not anchored to ``Cn`` IDs, so the gate cannot credit them.

This tool is **advisory-only**. It never modifies the finding files
(filing freeze, PR603 § 0.4). It:

1. Reads the per-finding OOS-check sidecar
   (``<workspace>/.auditooor/oos_check_<sha>.json``).
2. Extracts every clause whose verdict is ``MATCH``.
3. Reads the workspace's ``OOS_PASTED.md`` manifest for canonical
   clause text.
4. Detects which matched clause IDs the draft already anchors
   (``**C6**`` / ``**C6 (...)**`` / ``- **Cn**`` near a rebuttal block).
5. For every matched-but-unaddressed clause emits a one-paragraph
   anchored rebuttal stub. Stubs default to a generic in-scope
   justification but flag ``<TODO_OPERATOR_FILL_REBUTTAL>`` when no
   pattern fits.
6. Appends the suggested patch (or writes a fresh patch file) under
   ``<workspace>/submissions/paste_ready/current/`` as advisory.

Usage::

    oos-clause-auto-rebuttal.py \
        --workspace /Users/wolf/audits/base-azul \
        --finding   .../FN3_HIGH_FINAL_PASTE.md \
        --finding   .../FN6_HIGH_FINAL_PASTE.md \
        --out       .../V04_OOS_REBUTTAL_PATCHES.md

Exit codes
----------
    0 — wrote advisory (or printed when ``--dry-run``)
    1 — workspace / sidecar / manifest missing
    2 — usage error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.oos_clause_auto_rebuttal.v1"

# Per-clause boilerplate rebuttals. Operator can edit before applying.
# Keys are exact clause IDs as they appear in OOS_PASTED.md.
_CANNED_REBUTTALS: dict[str, str] = {
    "C6": (
        "No 51% / economic-majority assumption. The exploit fires from a "
        "single permissionless action (no validator-set capture, no "
        "stake threshold, no governance vote). Token 'governance'/'admin' "
        "appears in the rebuttal prose only; the attack precondition "
        "does not require any privileged or majority actor."
    ),
    "C10": (
        "No Base-operated infrastructure compromise. The bug is "
        "discoverable via on-chain code review (`AggregateVerifier` source "
        "+ Foundry PoC) and triggered through public, permissionless "
        "entry points. Token 'compromis' appears only in the negative "
        "rebuttal phrasing of this draft, not in the attack precondition."
    ),
    "C11": (
        "Atomic exploit; no Base-inaction assumption. The state mutation "
        "completes within a single transaction (`nullify()` / equivalent), "
        "so reactive blacklist/dispute/retire is downstream and cannot "
        "prevent the impact. The 'will not / does not' tokens are in "
        "denial prose, not in the trigger preconditions."
    ),
    "C12": (
        "No invalid TEE or ZK proof relied upon. Every proof in the chain "
        "is genuinely computed by the attacker against their own legitimate "
        "input; the bug is a structural collision / preimage confusion / "
        "permissionless cascade in the on-chain verifier, not a soundness "
        "break or attestation forgery."
    ),
    "C13": (
        "Recovery requires a contract upgrade (e.g. constructor guard or "
        "verifier redeploy), not a service restart with different "
        "configuration. The exploit does not assume any particular off-chain "
        "operator behaviour or restart pattern."
    ),
    "C15": (
        "No Security-Council action assumed in the attack. The exploit "
        "completes without any multisig approval; the only place the "
        "Council enters is *after* impact, in remediation. Council "
        "redeploy is the remediation path, not a precondition. "
        "Token 'governance'/'admin' is rebuttal prose only."
    ),
    "C21": (
        "No leaked keys, no stolen credentials. The attacker uses their "
        "own legitimately-generated credentials and proofs throughout. "
        "Token 'compromis' / 'leaked key' appears only in the negative "
        "rebuttal phrasing."
    ),
    "C22": (
        "Permissionless attacker; no privileged-address access required. "
        "Every entry point used in the exploit (`create`, `nullify`, "
        "`challenge`, `resolve`, `claimCredit`, …) is callable by any "
        "external account that posts the public bond. No role grant, "
        "whitelist, multisig approval, or modification to attributed "
        "privileges is required."
    ),
    "C27": (
        "The bug is in production source under `src/` (e.g. "
        "`src/multiproof/AggregateVerifier.sol`), not in test fixtures or "
        "configuration files. PoC files under `test/` only *demonstrate* "
        "the production bug; the impact lives in the in-scope production "
        "tree."
    ),
}


def _utc_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_oos_manifest(workspace: Path) -> dict[str, Any] | None:
    """Reuse the per-finding-oos-check fence parser semantics (lightweight copy)."""
    pasted = workspace / "OOS_PASTED.md"
    if not pasted.is_file():
        return None
    text = pasted.read_text(encoding="utf-8", errors="replace")
    OPEN = "<!-- OOS_PASTED_MANIFEST_BEGIN"
    CLOSE = "OOS_PASTED_MANIFEST_END -->"
    if OPEN in text and CLOSE in text:
        try:
            block = text.split(OPEN, 1)[1].split(CLOSE, 1)[0].strip()
            return json.loads(block)
        except (IndexError, json.JSONDecodeError):
            pass
    # Legacy fallback: `- **Cn** / OOS-n: text` lines.
    legacy_re = re.compile(
        r"^-\s+(?:\*\*)?(C\d+|OOS-\d+)(?:\*\*)?\s*(?:/\s*OOS-\d+)?\s*:\s*(.+)$",
        re.MULTILINE,
    )
    seen: set[str] = set()
    clauses: list[dict[str, str]] = []
    for m in legacy_re.finditer(text):
        raw = m.group(1)
        cid = "C" + raw.split("-", 1)[1] if raw.startswith("OOS-") else raw
        if cid in seen:
            continue
        seen.add(cid)
        clauses.append({"id": cid, "text": m.group(2).strip()})
    return {"clauses": clauses} if clauses else None


def _load_sidecar(workspace: Path, finding_path: Path) -> dict[str, Any] | None:
    text = finding_path.read_text(encoding="utf-8", errors="replace")
    sha = _sha256_text(text)
    sidecar = workspace / ".auditooor" / f"oos_check_{sha}.json"
    if not sidecar.is_file():
        _eprint(f"[oos-rebuttal] sidecar not found: {sidecar}")
        return None
    return json.loads(sidecar.read_text(encoding="utf-8", errors="replace"))


def _detect_anchored_clauses(finding_text: str) -> set[str]:
    """Detect clause IDs the draft already anchors as `**Cn**` / `Cn (...)` / `Cn.`."""
    found: set[str] = set()
    # Matches **C6**, **C6 (foo)**, "C6 (Council)", "- **C6.**" — the patterns
    # the gate's V04 advisory recommends.
    for m in re.finditer(r"\*\*(C\d+)(?:[\s\(\.\:\,\)\-\*]|$)", finding_text):
        found.add(m.group(1))
    for m in re.finditer(r"(?<![A-Za-z0-9])(C\d+)\s*\(", finding_text):
        found.add(m.group(1))
    return found


def _summarize_clause(text: str, max_words: int = 8) -> str:
    """One-line summary used as the bold header tag."""
    text = re.sub(r"\s+", " ", text.strip().rstrip("."))
    parts = text.split(" ")
    if len(parts) <= max_words:
        return text
    return " ".join(parts[:max_words]) + "…"


def build_rebuttal_block(
    *,
    finding_path: Path,
    sidecar: dict[str, Any],
    manifest_clauses: dict[str, str],
    already_anchored: set[str],
) -> tuple[str, list[str], list[str]]:
    """Return (markdown_block, matched_ids, unaddressed_ids)."""
    matched: list[str] = [
        c["id"] for c in sidecar.get("clauses_checked", [])
        if c.get("verdict") == "MATCH"
    ]
    unaddressed = [cid for cid in matched if cid not in already_anchored]

    lines: list[str] = []
    lines.append(f"### {finding_path.name}")
    lines.append("")
    lines.append(f"- finding_sha256: `{sidecar.get('finding_sha256', '')}`")
    lines.append(f"- matched clauses (sidecar): {', '.join(matched) or '—'}")
    lines.append(
        f"- already anchored in draft: "
        f"{', '.join(sorted(already_anchored)) or '—'}"
    )
    lines.append(
        f"- **unaddressed** (need anchored rebuttal): "
        f"{', '.join(unaddressed) or '— (all clauses already anchored)'}"
    )
    lines.append("")

    if not unaddressed:
        lines.append(
            "_Nothing to patch. Every matched clause is already explicitly "
            "anchored in the draft._"
        )
        lines.append("")
        return "\n".join(lines), matched, unaddressed

    lines.append("Suggested append to `## Out-of-scope clause rebuttal`:")
    lines.append("")
    lines.append("```markdown")
    for cid in unaddressed:
        clause_text = manifest_clauses.get(cid, "")
        if not clause_text:
            lines.append(f"- **{cid}**: <TODO_OPERATOR_FILL_REBUTTAL>")
            continue
        summary = _summarize_clause(clause_text)
        rebuttal = _CANNED_REBUTTALS.get(
            cid, "<TODO_OPERATOR_FILL_REBUTTAL>"
        )
        lines.append(
            f"- **{cid} — {summary}**: \"{clause_text}\" Rebuttal: {rebuttal}"
        )
    lines.append("```")
    lines.append("")
    return "\n".join(lines), matched, unaddressed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="oos-clause-auto-rebuttal.py",
        description=__doc__.splitlines()[0] if __doc__ else "",
    )
    ap.add_argument("--workspace", required=True)
    ap.add_argument(
        "--finding", action="append", required=True,
        help="One or more finding paste-ready files",
    )
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).expanduser()
    if not workspace.is_dir():
        _eprint(f"[oos-rebuttal] workspace missing: {workspace}")
        return 1

    manifest = _load_oos_manifest(workspace)
    if manifest is None:
        _eprint(f"[oos-rebuttal] OOS_PASTED.md missing or unparseable in {workspace}")
        return 1
    manifest_text = {c["id"]: c.get("text", "") for c in manifest.get("clauses", [])}

    sections: list[str] = []
    summary_rows: list[tuple[str, list[str], list[str]]] = []
    for f in args.finding:
        fp = Path(f).expanduser()
        if not fp.is_file():
            _eprint(f"[oos-rebuttal] finding missing: {fp}")
            return 1
        sidecar = _load_sidecar(workspace, fp)
        if sidecar is None:
            return 1
        finding_text = fp.read_text(encoding="utf-8", errors="replace")
        anchored = _detect_anchored_clauses(finding_text)
        block, matched, unaddressed = build_rebuttal_block(
            finding_path=fp,
            sidecar=sidecar,
            manifest_clauses=manifest_text,
            already_anchored=anchored,
        )
        sections.append(block)
        summary_rows.append((fp.name, matched, unaddressed))

    header = [
        f"# OOS Clause Auto-Rebuttal Advisory (V04 follow-up)",
        "",
        f"- generated: {_utc_now()}",
        f"- schema: `{SCHEMA}`",
        f"- workspace: `{workspace}`",
        "",
        "**Status:** ADVISORY ONLY. PR603 § 0.4 filing freeze — do NOT "
        "apply, do NOT file. Operator reviews each suggested rebuttal "
        "and either edits the canned text or fills the "
        "`<TODO_OPERATOR_FILL_REBUTTAL>` markers before lifting HOLD.",
        "",
        "## Summary",
        "",
        "| Finding | Matched | Unaddressed |",
        "|---|---|---|",
    ]
    for name, matched, unaddressed in summary_rows:
        header.append(
            f"| {name} | {', '.join(matched) or '—'} | "
            f"{', '.join(unaddressed) or '—'} |"
        )
    header.append("")
    header.append("## Per-finding patches")
    header.append("")

    rendered = "\n".join(header) + "\n".join(sections)

    if args.dry_run or not args.out:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        existing = out_path.read_text(encoding="utf-8", errors="replace")
        with out_path.open("w", encoding="utf-8") as f:
            f.write(existing.rstrip() + "\n\n---\n\n" + rendered)
    else:
        out_path.write_text(rendered, encoding="utf-8")
    print(f"[oos-rebuttal] wrote advisory: {out_path}")
    print(
        f"[oos-rebuttal] findings={len(summary_rows)} "
        f"sections={len(sections)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
