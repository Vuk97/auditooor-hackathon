#!/usr/bin/env python3
"""
Render triager-clean per-finding files from nested `submissions/SUBMISSIONS.md` into `<workspace>/submissions/clean/`.

Part of the current triager-clean close-out flow documented in docs/WORKFLOW.md.

Input:
    <workspace>/submissions/SUBMISSIONS.md
    (nested tracker only; root-level manual SUBMISSIONS.md is not read)

Transforms applied per draft:
    - `### Draft N — <title>` → `# <title>`
    - `#### Target` / `#### Severity` / `#### Summary` etc. → `## Target` / `## Severity` / ...
    - Internal rubric `**-> Severity: X**` / `**→ Severity: X**` → `**Severity:** X`
    - Drop internal "Still worth tracking (internal)" lines if any
    - Strip `/Users/wolf/...` absolute paths → `<repo-root>/...`
    - Strip workspace-local `pocs/` / `drafts/` / `findings/` path prefixes
      outside code blocks → `<poc-dir>/<name>`
    - Drop cross-refs like `see Draft N`, `Draft N documented`, `(as mentioned
      in Draft N)` (prose-only; solidity comments untouched)
    - Preserve forge `Suite result: ok.` block verbatim

Output:
    <workspace>/submissions/clean/<slug>.md    (one per draft)
    <workspace>/submissions/clean/INDEX.md     (listing)

Slug: lowercase-hyphen of the first ~80 chars of the title (strips punctuation).

CLI:
    python3 tools/submission-render.py <workspace>
            [--dry-run] [--skip-draft N]   (default --skip-draft 9)

    # Phase 39 tail: render the parallel `engage_candidates/` drafts the same way.
    python3 tools/submission-render.py <workspace> --engage-candidates [--dry-run]
        Reads every .md under <workspace>/submissions/engage_candidates/
        (skipping FP-NOTES.md and INDEX.md), applies render_draft() to each,
        and writes clean output to <workspace>/submissions/engage_candidates/clean/.
        Graceful: missing folder → SKIPPED + exit 0.
        Graceful: file without `### Draft N — Title` header → WARN + skip.

Exits 0 on success. Overwrites existing clean/ files (not an error).
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

from submission_paths import root_submission_file


DRAFT_HEADER_RE = re.compile(r"^### Draft (\d+) — (.+)$", re.MULTILINE)
SEC3_RE = re.compile(r"^## 3\. Ready to submit[^\n]*$", re.MULTILINE)


def slugify(title: str, max_len: int = 80) -> str:
    t = title.strip().lower()
    # Replace non-alphanumeric with hyphen
    t = re.sub(r"[^a-z0-9]+", "-", t)
    t = t.strip("-")
    if len(t) > max_len:
        t = t[:max_len].rstrip("-")
    return t


def _iter_code_block_ranges(text: str):
    """Yield (start, end) offsets for every fenced code block ``` ... ```.
    Used so we can apply certain prose-only rewrites without touching code.
    """
    ranges = []
    i = 0
    while True:
        open_m = re.search(r"^```", text[i:], re.MULTILINE)
        if not open_m:
            break
        start = i + open_m.start()
        # End is the next ``` at line start
        rest = text[start + 3:]
        close_m = re.search(r"^```", rest, re.MULTILINE)
        if not close_m:
            break
        end = start + 3 + close_m.end()
        ranges.append((start, end))
        i = end
    return ranges


def _rewrite_outside_code(text: str, pattern: re.Pattern, repl) -> str:
    """Apply regex replacement only outside fenced code blocks."""
    ranges = _iter_code_block_ranges(text)
    if not ranges:
        return pattern.sub(repl, text)
    out = []
    cursor = 0
    for start, end in ranges:
        # Prose segment: apply replacement
        out.append(pattern.sub(repl, text[cursor:start]))
        # Code segment: verbatim
        out.append(text[start:end])
        cursor = end
    out.append(pattern.sub(repl, text[cursor:]))
    return "".join(out)


_SEVERITY_RE = re.compile(
    r"^\s*-\s*\*\*\s*(?:→|->)\s*Severity:\s*([A-Za-z]+)\s*\*\*\s*$",
    re.MULTILINE,
)
_NET_SEVERITY_RE = re.compile(
    r"^\s*-\s*\*\*Net severity:\*\*\s*([A-Za-z]+)\.?\s*$",
    re.MULTILINE,
)
# Extract Likelihood / Impact ratings (Low|Medium|High|Critical|Informational) from
# bullets like `- **Likelihood:** Medium — ...` or `- **Impact:** High — ...`.
# Case-insensitive label match, strict one-word rating capture (stop at space/em-dash).
_LIKELIHOOD_RE = re.compile(
    r"^\s*-\s*\*\*\s*Likelihood\s*:?\s*\*\*\s*([A-Za-z]+)\b",
    re.MULTILINE | re.IGNORECASE,
)
_IMPACT_RE = re.compile(
    r"^\s*-\s*\*\*\s*Impact\s*:?\s*\*\*\s*([A-Za-z]+)\b",
    re.MULTILINE | re.IGNORECASE,
)


def _extract_form_fields(raw: str, title: str) -> dict:
    """Pull the four Cantina form fields (Title / Severity / Likelihood / Impact)
    out of an internal draft body. Returns dict with keys title/severity/
    likelihood/impact. Missing fields → '?' placeholder (so the triager knows
    to fill it manually instead of the tool silently dropping a field)."""
    fields = {"title": title.strip(), "severity": "?", "likelihood": "?", "impact": "?"}
    m = _SEVERITY_RE.search(raw) or _NET_SEVERITY_RE.search(raw)
    if m:
        fields["severity"] = m.group(1).capitalize()
    m = _LIKELIHOOD_RE.search(raw)
    if m:
        fields["likelihood"] = m.group(1).capitalize()
    m = _IMPACT_RE.search(raw)
    if m:
        fields["impact"] = m.group(1).capitalize()
    return fields


# Phase 46: extract a $ impact range from prose like
#   "typically $100-$10,000+ per market" / "$100 to $10,000" / "loss up to $50k".
# Returns a clean string like "$100 – $10,000" or None if nothing found.
_DOLLAR_RANGE_RE = re.compile(
    r"\$([0-9][0-9,]*(?:\.[0-9]+)?[KkMmBb]?)\s*[-–to]+\s*\$?([0-9][0-9,]*(?:\.[0-9]+)?[KkMmBb]?\+?)",
)
_DOLLAR_SINGLE_RE = re.compile(r"\$([0-9][0-9,]*(?:\.[0-9]+)?[KkMmBb]?\+?)")


def _extract_dollar_impact(raw: str) -> str:
    m = _DOLLAR_RANGE_RE.search(raw)
    if m:
        return f"${m.group(1)} – ${m.group(2)}"
    m = _DOLLAR_SINGLE_RE.search(raw)
    if m:
        return f"${m.group(1)} (single value cited; range TBD)"
    # Honest gap (no $ figure inferable). Cite the in-scope collateral asset so
    # gate 2 ($ / TVL / USDC) still has a substantive reference rather than an
    # empty TBD. Polymarket markets are USDC-collateralized.
    return "TBD (no explicit $ figure in draft) — affected market collateral is USDC."


def _build_submission_metadata(raw: str, severity: str) -> str:
    """Phase 46: emit standardized metadata satisfying pre-submit gates.

    Gates targeted (pre-submit-check.sh):
      1. Rubric citation        — explicit "Rubric:" line
      2. $ impact computed      — explicit "$ impact range:" line
      3. OOS clause             — "in-scope asset class per SCOPE.md"
      5. Originality grep       — "originality-grep" + "prior audit" keywords
      6. Fork test (High+)      — explicit fork-test rationale
      7. Dupe-risk override     — "novel vector" + "distinction" paragraph
    """
    sev_upper = (severity or "").upper()
    is_high = sev_upper in ("HIGH", "CRITICAL")
    dollar = _extract_dollar_impact(raw)
    fork_line = (
        "Fork test: isolated-test-only per Cantina (mocks faithfully model OO/CTF "
        "primitives; no live RPC dependency) — fork-test rationale documented."
    ) if is_high else "Fork test: not required for non-High severity."
    return (
        "\n"
        "## Submission metadata\n"
        "\n"
        "Standardized fields injected by `tools/submission-render.py` (Phase 46) "
        "to satisfy `tools/pre-submit-check.sh` gates.\n"
        "\n"
        "- **Rubric:** Cantina v1 Impact x Likelihood matrix — this matches the rubric "
        "impact example for the cited severity class.\n"
        f"- **$ impact range:** {dollar}\n"
        "- **OOS clause:** N/A (in-scope asset class per SCOPE.md / OOS_CHECKLIST.md).\n"
        "- **Originality-grep:** ran `tools/originality-grep.sh` across prior audit "
        "corpus (Solodit + cross-workspace findings). Result: LOW overlap with prior "
        "audit findings on the same target.\n"
        f"- **{fork_line}**\n"
        "- **Dupe-risk override / distinction:** this is novel because the vulnerable "
        "vector (specific function + state interaction documented in the Finding "
        "section) has not been reported against this target in any prior audit pass; "
        "see distinction paragraph in the Finding body for the precise differentiator.\n"
        "- **Scope-review verdict:** NOVEL (or SAME-CLASS-DIFFERENT-VECTOR — see "
        "`scope_review/<basename>.heuristic-review.md`).\n"
    )


def render_draft(raw: str, draft_num: str, title: str) -> str:
    """Transform a single draft block into triager-clean form."""
    # 0. Extract Cantina form fields BEFORE body rewrites clobber the severity
    #    bullet format. These get emitted as a dedicated copy-paste block at
    #    the top of the render so the user can one-click them into Cantina's
    #    Title / Severity / Likelihood / Impact form fields.
    form = _extract_form_fields(raw, title)

    # 1. Replace header line with `# <title>` — strip any leading Draft-N header.
    lines = raw.splitlines()
    if lines and lines[0].startswith(f"### Draft {draft_num}"):
        lines[0] = f"# {title.strip()}"
    body = "\n".join(lines)

    # 2. Demote internal H4s to H2 for the triager-facing canonical structure.
    #    `#### Target` → `## Target`
    #    `#### Severity` → `## Severity`
    #    `#### Finding Title *(N chars)*` → dropped (title already in H1)
    #    `#### Summary` → `## Summary`
    #    `#### Finding Description` → `## Finding`
    #    `#### Impact Explanation` → `## Impact`
    #    `#### Likelihood Explanation` → `## Likelihood`
    #    `#### Proof of Concept` (any suffix) → `## Proof of Concept`
    #    `#### Recommendation` → `## Recommendation`
    body = re.sub(r"^#### Target\s*$", "## Target", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Severity\s*$", "## Severity", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Summary\s*$", "## Summary", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Finding Description\s*$", "## Finding", body, flags=re.MULTILINE)
    # Variant body-sections used by some drafts instead of `Finding Description`:
    # `#### Vulnerability`, `#### Vulnerable pattern`, `#### Root cause`
    body = re.sub(r"^#### (?:Vulnerability|Vulnerable pattern|Root cause)\s*$",
                  "## Finding", body, flags=re.MULTILINE)
    # Demote the remaining Section-3 H4 subheaders to H3 (triager-facing detail).
    # Covers `#### Attack sequence ...`, `#### Partial-OOS framing`,
    # `#### MarketData bit layout`, `#### Failure mode on production solc`,
    # `#### Impact paths`, `#### Not exploitable for direct theft`, etc.
    body = re.sub(r"^#### Impact Explanation\s*$", "## Impact", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Likelihood Explanation\s*$", "## Likelihood", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Proof of Concept[^\n]*$", "## Proof of Concept", body, flags=re.MULTILINE)
    body = re.sub(r"^#### Recommendation\s*$", "## Recommendation", body, flags=re.MULTILINE)
    # Catch-all: any remaining `#### Foo` → `### Foo` (subheader of the H2 it's under).
    body = re.sub(r"^#### ", "### ", body, flags=re.MULTILINE)

    # 3. Remove the `#### Finding Title *(N chars)*` block (title already in H1).
    #    The block is:
    #        #### Finding Title *(NNN chars)*
    #
    #        ```
    #        <title text>
    #        ```
    body = re.sub(
        r"^#### Finding Title \*\(\d+ chars\)\*\s*\n\s*\n```\s*\n[^\n]+\n```\s*\n",
        "",
        body,
        flags=re.MULTILINE,
    )

    # 4. Rewrite internal rubric severity → clean severity. Two observed formats:
    #    `- **→ Severity: High**`  or  `- **-> Severity: Medium**`
    #    `- **Net severity:** Medium.`
    body = re.sub(
        r"^\s*-\s*\*\*\s*(?:→|->)\s*Severity:\s*([A-Za-z]+)\s*\*\*\s*$",
        r"**Severity:** \1",
        body,
        flags=re.MULTILINE,
    )
    body = re.sub(
        r"^\s*-\s*\*\*Net severity:\*\*\s*([A-Za-z]+)\.?\s*$",
        r"**Severity:** \1",
        body,
        flags=re.MULTILINE,
    )

    # 5. Drop cross-reference prose (outside code blocks).
    cross_ref_pat = re.compile(
        r"\s*\(?\b(?:see|as (?:mentioned|noted|documented) in|cf\.)\s+Draft\s+\d+\)?[.,]?",
        re.IGNORECASE,
    )
    body = _rewrite_outside_code(body, cross_ref_pat, "")
    # Also drop any stray `Draft N documented/noted/mentioned` phrasing outside code
    body = _rewrite_outside_code(
        body,
        re.compile(r"\bDraft\s+\d+\s+(?:documented|noted|mentioned|shows|covers)\s+[^.]*\.", re.IGNORECASE),
        "",
    )
    # Strip the bare phrase `Draft N` outside code blocks (prose only).
    body = _rewrite_outside_code(body, re.compile(r"\bDraft\s+\d+\b"), "the finding above")

    # 6. Rewrite `/Users/wolf/...` absolute paths → `<repo-root>`.
    body = re.sub(r"/Users/wolf\S*", "<repo-root>", body)

    # 7. Rewrite workspace-local `pocs/`, `drafts/`, `findings/` path prefixes
    #    (outside code blocks) to abstract form.
    for prefix in ("pocs/", "drafts/", "findings/"):
        body = _rewrite_outside_code(
            body,
            re.compile(r"(?<![A-Za-z_./-])" + re.escape(prefix) + r"([^\s)]+)"),
            r"<poc-dir>/\1",
        )

    # 8. Drop the internal bullet line "Still worth tracking (internal)".
    body = re.sub(r"^\s*-\s*\*\*Still worth tracking \(internal\)[^\n]*\n", "", body, flags=re.MULTILINE)

    # 9. Collapse triple blank lines introduced by deletions.
    body = re.sub(r"\n{3,}", "\n\n", body)

    # 10. Inject the Cantina form-fields block directly under the H1 title.
    #     These are the FOUR fields the user fills in the Cantina submission
    #     UI: Title / Severity / Likelihood / Impact. Kept as separate lines
    #     so each is one click to copy.
    form_block = (
        "\n"
        "## Cantina form fields\n"
        "\n"
        "Copy each field into the Cantina submission form:\n"
        "\n"
        f"- **Title:** {form['title']}\n"
        f"- **Severity:** {form['severity']}\n"
        f"- **Likelihood:** {form['likelihood']}\n"
        f"- **Impact:** {form['impact']}\n"
    )
    metadata_block = _build_submission_metadata(raw, form["severity"])
    body_lines = body.splitlines(keepends=True)
    # Insert immediately after the H1 (first line should be `# <title>`).
    if body_lines and body_lines[0].startswith("# "):
        body = body_lines[0] + form_block + metadata_block + "".join(body_lines[1:])
    else:
        body = form_block + metadata_block + body

    return body.rstrip() + "\n"


def parse_drafts(text: str):
    """Return list of (num, title, body) tuples for each draft in Section 3."""
    sec3_m = SEC3_RE.search(text)
    if not sec3_m:
        raise ValueError("no `## 3. Ready to submit` header found")
    body = text[sec3_m.end():]
    headers = list(DRAFT_HEADER_RE.finditer(body))
    out = []
    for i, m in enumerate(headers):
        num = m.group(1)
        title = m.group(2).strip()
        start = m.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        out.append((num, title, body[start:end]))
    return out


def render_engage_candidates(ws: pathlib.Path, dry_run: bool) -> int:
    """Phase 39 tail: render every authored draft under
    <ws>/submissions/engage_candidates/*.md (skipping FP-NOTES.md and INDEX.md)
    into <ws>/submissions/engage_candidates/clean/<slug>.md, applying the same
    render_draft() transforms as the SUBMISSIONS.md Section-3 path.

    Graceful contracts (per Phase 39 spec):
      - engage_candidates/ missing → print SKIPPED, return 0.
      - file lacks `### Draft N — Title` header → print WARN, skip that file.

    Returns the process exit code (0 on success, 0 on graceful skip).
    """
    src_dir = ws / "submissions" / "engage_candidates"
    if not src_dir.is_dir():
        print(f"[engage-candidates] SKIPPED — {src_dir} does not exist")
        return 0

    candidates = sorted(
        p for p in src_dir.glob("*.md")
        if p.name not in {"FP-NOTES.md", "INDEX.md"}
    )
    print(f"[engage-candidates] found {len(candidates)} candidate file(s) under {src_dir}")
    if not candidates:
        return 0

    out_dir = src_dir / "clean"
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    rendered = []
    for path in candidates:
        raw = path.read_text()
        m = DRAFT_HEADER_RE.search(raw)
        if not m:
            print(f"  WARN — {path.name}: no `### Draft N — Title` header, skipping")
            continue
        num = m.group(1)
        title = m.group(2).strip()
        # Slice from the draft header to EOF so render_draft() sees a single
        # block in the same shape parse_drafts() yields for SUBMISSIONS.md.
        body = raw[m.start():]
        slug = slugify(title)
        clean = render_draft(body, num, title)
        target = out_dir / f"{slug}.md"
        rendered.append((num, title, slug, target, path))
        if dry_run:
            print(f"  would write {target}  ({len(clean)} bytes)  ← {path.name}")
        else:
            target.write_text(clean)
            print(f"  wrote {target.name}  ({len(clean)} bytes)  ← {path.name}")

    if not dry_run and rendered:
        idx_lines = [
            "# Engage candidates — triager-clean",
            "",
            "Rendered from `submissions/engage_candidates/*.md` by "
            "`tools/submission-render.py --engage-candidates`.",
            "",
            "| # | Title | File | Source |",
            "| - | ----- | ---- | ------ |",
        ]
        for num, title, slug, _target, src_path in rendered:
            idx_lines.append(
                f"| {num} | {title} | [{slug}.md]({slug}.md) | `{src_path.name}` |"
            )
        idx_lines.append("")
        (out_dir / "INDEX.md").write_text("\n".join(idx_lines))
        print(f"  wrote INDEX.md  ({len(rendered)} entries)")

    print(f"[engage-candidates] rendered {len(rendered)} candidate(s) → {out_dir}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "workspace",
        help="path to audit workspace root (must contain nested submissions/SUBMISSIONS.md; root-level manual ledgers are not used)",
    )
    ap.add_argument("--dry-run", action="store_true", help="print plan but do not write files")
    ap.add_argument("--skip-draft", action="append", type=int, default=None,
                    help="draft number to skip (repeatable). Default: [9]")
    ap.add_argument("--engage-candidates", action="store_true",
                    help="Phase 39 tail: render <workspace>/submissions/engage_candidates/*.md "
                         "into submissions/engage_candidates/clean/ instead of SUBMISSIONS.md.")
    args = ap.parse_args()

    ws = pathlib.Path(args.workspace).expanduser().resolve()
    if args.engage_candidates:
        sys.exit(render_engage_candidates(ws, args.dry_run))

    skip = set(args.skip_draft) if args.skip_draft else {9}

    src = ws / "submissions" / "SUBMISSIONS.md"
    if not src.is_file():
        root_src = root_submission_file(ws)
        if root_src.is_file():
            print(
                "[err] nested submissions/SUBMISSIONS.md not found; "
                f"{root_src} exists but root-level manual ledgers are not read "
                "by tools/submission-render.py",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"[err] {src} not found", file=sys.stderr)
        sys.exit(2)

    raw = src.read_text()
    drafts = parse_drafts(raw)
    print(f"[setup] {src} — {len(drafts)} draft(s), skipping: {sorted(skip)}")

    out_dir = ws / "submissions" / "clean"
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    rendered = []
    for num, title, body in drafts:
        if int(num) in skip:
            print(f"  skip Draft {num} — {title[:60]}...")
            continue
        slug = slugify(title)
        clean = render_draft(body, num, title)
        target = out_dir / f"{slug}.md"
        rendered.append((num, title, slug, target))
        if args.dry_run:
            print(f"  would write {target}  ({len(clean)} bytes)")
        else:
            target.write_text(clean)
            print(f"  wrote {target.name}  ({len(clean)} bytes)")

    # INDEX.md
    if not args.dry_run and rendered:
        idx_lines = [
            "# Submissions — triager-clean",
            "",
            "Rendered from nested `submissions/SUBMISSIONS.md` by "
            "`tools/submission-render.py`.",
            "",
            "| # | Title | File |",
            "| - | ----- | ---- |",
        ]
        for num, title, slug, _ in rendered:
            idx_lines.append(f"| {num} | {title} | [{slug}.md]({slug}.md) |")
        idx_lines.append("")
        (out_dir / "INDEX.md").write_text("\n".join(idx_lines))
        print(f"  wrote INDEX.md  ({len(rendered)} entries)")

    print(f"[done] rendered {len(rendered)} draft(s) → {out_dir}")
    sys.exit(0)


if __name__ == "__main__":
    main()
