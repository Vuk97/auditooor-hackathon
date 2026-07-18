#!/usr/bin/env python3
"""
Lint internal `SUBMISSIONS.md` drafts and triager-clean files under `submissions/clean/` or `submissions/engage_candidates/clean/`.

Phase 36 upgrade: 25 checks total (was 21). New blocks (triager-only):
    22. No `### Draft N` leakage (bug title must be the H1 heading)
    23. No internal arrow-rubric severity (`**-> Severity:` / `**→ Severity:`)
    24. No bare "Draft N" mentions anywhere in the rendered output
    25. No internal tier/classification words outside code blocks
        (tier/Tier, `_internal` detector markers, "internal rubric", etc.)

The 4 new checks are CONDITIONAL: they only run when invoked with
`--triager-clean`, or when the input path contains `/clean/`. This keeps the
lint backwards-compatible with the internal authoring doc (which legitimately
carries Draft-N headers and internal commentary).

Usage:
    # Audit internal SUBMISSIONS.md (21 checks)
    python3 tools/submissions-lint.py <workspace>

    # Audit rendered clean/*.md files (25 checks each)
    python3 tools/submissions-lint.py <workspace>/submissions/clean/<slug>.md --triager-clean

    # Batch audit all rendered files in a workspace
    # (submissions/clean/ + submissions/engage_candidates/clean/)
    python3 tools/submissions-lint.py <workspace> --triager-clean --clean-glob

Exit 0 if every audited file/draft scores max-possible. Exit 1 on any fail
when `--strict` is set.
"""
import argparse
import pathlib
import re
import sys


REQUIRED_SUBS = [
    "Target",
    "Severity",
    "Finding Title",
    "Summary",
    "Finding Description",
    "Impact Explanation",
    "Likelihood Explanation",
    "Proof of Concept",
    "Recommendation",
]

# Triager-clean canonical H2 subsection set (post-render).
REQUIRED_SUBS_CLEAN = [
    "Target",
    "Severity",
    "Summary",
    "Finding",
    "Proof of Concept",
    "Recommendation",
]

REJECT_PATTERNS = [
    ("no `see Draft N` cross-ref", r"see Draft \d+"),
    ("no `Matrix: ` rating commentary", r"Matrix: \*\*Impact"),
    ("no `_internal ` placeholders", r"_internal (detector|draft|cold)"),
    ("no `pocs/` workspace paths", r"\bpocs/"),
    ("no `/Users/wolf` absolute paths", r"/Users/wolf"),
    ("no dangling `./_XFixture.sol` import", r'from\s*"\./_\w+Fixture\.sol"'),
]

# Phase 36 — new triager-clean reject patterns (4 checks).
TRIAGER_REJECT_PATTERNS = [
    ("no `### Draft N` header leakage", r"^###\s+Draft\s+\d+", re.MULTILINE),
    ("no `**-> Severity:` internal rubric arrow",
     r"\*\*\s*(?:->|→)\s*Severity\s*:", 0),
    # Bare "Draft N" anywhere — strict in clean output.
    ("no bare `Draft N` mentions", r"\bDraft\s+\d+\b", 0),
    # tier/Tier/_internal leakage outside code blocks — checked via helper.
    ("no `tier` / `_internal` classification leakage", None, 0),
]


def _iter_code_block_ranges(text: str):
    ranges = []
    i = 0
    while True:
        open_m = re.search(r"^```", text[i:], re.MULTILINE)
        if not open_m:
            break
        start = i + open_m.start()
        rest = text[start + 3:]
        close_m = re.search(r"^```", rest, re.MULTILINE)
        if not close_m:
            break
        end = start + 3 + close_m.end()
        ranges.append((start, end))
        i = end
    return ranges


def _find_outside_code(text: str, pattern: re.Pattern):
    """Return list of match-strings for `pattern` occurring outside fenced
    code blocks."""
    ranges = _iter_code_block_ranges(text)
    hits = []
    cursor = 0
    segments = []
    for start, end in ranges:
        segments.append(text[cursor:start])
        cursor = end
    segments.append(text[cursor:])
    for seg in segments:
        hits.extend(pattern.findall(seg))
    return hits


def audit_draft(draft_text: str, draft_num: str, draft_title: str,
                in_scope_addrs: set, triager_clean: bool = False):
    checks = {}

    # Heading hierarchy
    strays = re.findall(r"^## [^#]", draft_text, re.MULTILINE)
    if not triager_clean:
        # In internal SUBMISSIONS.md, H2s inside a draft are unusual.
        # In triager-clean output, `## Target` etc. are expected H2s — skip this check.
        checks["no `## ` strays inside draft"] = (
            len(strays) == 0,
            f"{len(strays)} stray H2 lines",
        )

    # Required subsections
    if triager_clean:
        for sub in REQUIRED_SUBS_CLEAN:
            present = re.search(rf"^##\s+{re.escape(sub)}\s*$", draft_text, re.MULTILINE) is not None
            checks[f"has `## {sub}`"] = (present, "ok" if present else "MISSING")
    else:
        for sub in REQUIRED_SUBS:
            present = f"#### {sub}" in draft_text
            checks[f"has `#### {sub}`"] = (present, "ok" if present else "MISSING")

    # Target address
    addr_m = re.search(r"`(0x[a-fA-F0-9]{40})`", draft_text)
    if addr_m:
        addr = addr_m.group(1).lower()
        in_scope = addr in {a.lower() for a in in_scope_addrs} if in_scope_addrs else True
        checks["target in SCOPE"] = (
            in_scope,
            f"{addr_m.group(1)}{' OK' if in_scope else ' NOT IN SCOPE'}",
        )
    else:
        checks["target in SCOPE"] = (False, "no 0x-address in body")

    # Finding title char count — only in internal mode. Triager-clean moves
    # the title to the H1 heading, so this internal-rubric block is gone.
    if not triager_clean:
        title_m = re.search(
            r"#### Finding Title \*\((\d+) chars\)\*\s*\n\s*\n\s*```\s*\n([^\n]+)\n\s*```",
            draft_text,
        )
        if title_m:
            claimed = int(title_m.group(1))
            actual = len(title_m.group(2).strip())
            ok = claimed == actual and actual <= 120
            checks["title char-count accurate <=120"] = (ok, f"claims {claimed}, actual {actual}")
        else:
            checks["title char-count accurate <=120"] = (False, "missing or malformed")
    else:
        # Triager-clean: H1 title must be <= 120 chars.
        h1_m = re.search(r"^# (.+)$", draft_text, re.MULTILINE)
        if h1_m:
            actual = len(h1_m.group(1).strip())
            checks["H1 title <=120 chars"] = (actual <= 120, f"{actual} chars")
        else:
            checks["H1 title <=120 chars"] = (False, "no H1")

    # Forge PASS block
    forge_ok = "Suite result: ok" in draft_text and "```text" in draft_text
    checks["forge `Suite result: ok.` block"] = (forge_ok, "present" if forge_ok else "MISSING")

    # Reject patterns — base set (checks 16-21)
    for name, pat in REJECT_PATTERNS:
        hits = re.findall(pat, draft_text)
        checks[name] = (len(hits) == 0, f"{len(hits)} hit(s)" if hits else "clean")

    # Phase 36 — triager-clean stricter checks (lifts total to 25)
    if triager_clean:
        # 22. No `### Draft N` header leakage
        pat22 = re.compile(r"^###\s+Draft\s+\d+", re.MULTILINE)
        hits22 = pat22.findall(draft_text)
        checks["no `### Draft N` header leakage"] = (
            len(hits22) == 0, f"{len(hits22)} hit(s)" if hits22 else "clean",
        )

        # 23. No `**-> Severity:` / `**→ Severity:` arrow-rubric
        pat23 = re.compile(r"\*\*\s*(?:->|→)\s*Severity\s*:")
        hits23 = pat23.findall(draft_text)
        checks["no `**-> Severity:` arrow-rubric"] = (
            len(hits23) == 0, f"{len(hits23)} hit(s)" if hits23 else "clean",
        )

        # 24. No bare `Draft N` anywhere in rendered PROSE (code comments ok).
        pat24 = re.compile(r"\bDraft\s+\d+\b")
        hits24 = _find_outside_code(draft_text, pat24)
        checks["no bare `Draft N` mentions in prose"] = (
            len(hits24) == 0, f"{len(hits24)} hit(s)" if hits24 else "clean",
        )

        # 25. No tier/_internal classification words outside code blocks.
        classification_pat = re.compile(
            r"(?:\b[Tt]ier\b|\b_internal\s+(?:detector|draft|cold)\b|"
            r"\binternal (?:rubric|commentary|note|classification)\b|"
            r"Still worth tracking \(internal\))"
        )
        hits25 = _find_outside_code(draft_text, classification_pat)
        checks["no tier/_internal classification leakage"] = (
            len(hits25) == 0, f"{len(hits25)} hit(s)" if hits25 else "clean",
        )

        # 26. Exactly one H1 (the bug title).
        h1_count = len(re.findall(r"^# [^#\n]", draft_text, re.MULTILINE))
        checks["exactly one H1 heading"] = (h1_count == 1, f"{h1_count} H1(s)")

        # 27-29. Exactly one each of the required singleton H2s.
        for name in ("Target", "Severity", "Recommendation"):
            c = len(re.findall(rf"^##\s+{re.escape(name)}\s*$", draft_text, re.MULTILINE))
            checks[f"exactly one `## {name}`"] = (c == 1, f"{c}")

        # 30. No stray H4 (`#### ...`) — render should demote everything to H3 or higher.
        h4_count = len(re.findall(r"^#### ", draft_text, re.MULTILINE))
        checks["no stray `#### ` H4 headings"] = (h4_count == 0, f"{h4_count}")

        # 31. `## Severity` section names one of {Critical, High, Medium, Low, Informational}.
        sev_m = re.search(r"^## Severity\s*\n(.*?)(?=^## |\Z)", draft_text, re.MULTILINE | re.DOTALL)
        sev_ok = bool(sev_m and re.search(
            r"\*\*Severity:\*\*\s*(Critical|High|Medium|Low|Informational)",
            sev_m.group(1),
        ))
        checks["Severity names a recognized level"] = (
            sev_ok, "ok" if sev_ok else "missing `**Severity:** <level>`",
        )

    passed = sum(1 for v in checks.values() if v[0])
    total = len(checks)
    return passed, total, checks


def _load_scope_addrs(workspace: pathlib.Path) -> set:
    scope = workspace / "SCOPE.md"
    if not scope.is_file():
        return set()
    return set(re.findall(r"0x[a-fA-F0-9]{40}", scope.read_text()))


def _audit_clean_file(path: pathlib.Path, in_scope: set):
    text = path.read_text()
    # Use the H1 title as pseudo-draft-title, draft_num unknown (use filename).
    h1 = re.search(r"^# (.+)$", text, re.MULTILINE)
    title = h1.group(1).strip() if h1 else path.stem
    passed, total, checks = audit_draft(text, path.stem, title, in_scope, triager_clean=True)
    return title, passed, total, checks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="workspace path, OR a triager-clean .md file path (with --triager-clean)")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any draft scores < max")
    ap.add_argument("--draft", type=int, help="audit only the specified draft number (internal mode)")
    ap.add_argument("--triager-clean", action="store_true",
                    help="run the stricter 25-check audit on rendered clean/*.md file(s)")
    ap.add_argument("--clean-glob", action="store_true",
                    help="with --triager-clean + a workspace path: audit every submissions/clean/*.md and submissions/engage_candidates/clean/*.md")
    args = ap.parse_args()

    target = pathlib.Path(args.target).expanduser().resolve()

    # Auto-enable --triager-clean if the path contains /clean/
    if not args.triager_clean and "/clean/" in str(target):
        args.triager_clean = True

    # Mode A: audit a single triager-clean file directly.
    if args.triager_clean and target.is_file():
        # Find workspace from path: .../<workspace>/submissions/clean/<slug>.md
        parts = target.parts
        ws = None
        for i in range(len(parts) - 1, -1, -1):
            if parts[i] == "submissions" and i > 0:
                ws = pathlib.Path(*parts[:i])
                break
        in_scope = _load_scope_addrs(ws) if ws else set()
        title, passed, total, checks = _audit_clean_file(target, in_scope)
        print(f"[setup] single-file mode — {target}")
        print(f"\n{'File':<50} {'Score':<10}")
        print("=" * 70)
        mark = "PASS" if passed == total else "FAIL"
        print(f"{target.name:<50} {passed}/{total} {mark}")
        if passed < total:
            print("\n--- FAILED CHECKS ---\n")
            print(f"{target.name} — {title[:80]}")
            for k, (ok, reason) in checks.items():
                if not ok:
                    print(f"    [FAIL] {k}: {reason}")
            if args.strict:
                sys.exit(1)
        sys.exit(0)

    # Mode B: workspace path (either internal SUBMISSIONS.md or --clean-glob).
    ws = target
    if not ws.is_dir():
        print(f"[err] {ws} is not a directory (and not a .md with --triager-clean)", file=sys.stderr)
        sys.exit(2)

    in_scope = _load_scope_addrs(ws)
    print(f"[setup] {len(in_scope)} in-scope addresses loaded from SCOPE.md")

    if args.triager_clean and args.clean_glob:
        # Phase 39 tail: scan BOTH submissions/clean/ AND
        # submissions/engage_candidates/clean/ so engage-candidate renders are
        # held to the same 25-check bar as the SUBMISSIONS.md drafts.
        clean_dir = ws / "submissions" / "clean"
        ec_clean_dir = ws / "submissions" / "engage_candidates" / "clean"
        if not clean_dir.is_dir() and not ec_clean_dir.is_dir():
            print(
                "[err] neither rendered clean directory exists. Run "
                "`make clean-submissions WORKSPACE=<path>` from a workspace "
                "with an up-to-date nested submissions/SUBMISSIONS.md ledger, "
                "or `make clean-engage-candidates WORKSPACE=<path>` for "
                "engage-candidate renders.",
                file=sys.stderr,
            )
            sys.exit(2)
        files = []
        for d in (clean_dir, ec_clean_dir):
            if d.is_dir():
                files.extend(p for p in d.glob("*.md") if p.name != "INDEX.md")
        files = sorted(files)
        print(f"[setup] {len(files)} triager-clean file(s) found "
              f"(submissions/clean + engage_candidates/clean)\n")

        print(f"{'File':<60} {'Score':<10}")
        print("=" * 90)
        any_fail = False
        all_results = []
        for f in files:
            title, passed, total, checks = _audit_clean_file(f, in_scope)
            all_results.append((f, title, passed, total, checks))
            mark = "PASS" if passed == total else "FAIL"
            print(f"{f.name:<60} {passed}/{total} {mark}")
            if passed < total:
                any_fail = True

        if any_fail:
            print("\n--- FAILED CHECKS ---\n")
            for f, title, passed, total, checks in all_results:
                fails = [(k, v[1]) for k, v in checks.items() if not v[0]]
                if fails:
                    print(f"{f.name} — {title[:70]}")
                    for k, reason in fails:
                        print(f"    [FAIL] {k}: {reason}")
                    print()
        if args.strict and any_fail:
            sys.exit(1)
        sys.exit(0)

    # Mode C: legacy internal SUBMISSIONS.md audit.
    sub = ws / "submissions" / "SUBMISSIONS.md"
    scope = ws / "SCOPE.md"
    if not sub.is_file():
        print(f"[err] {sub} not found", file=sys.stderr); sys.exit(2)
    if not scope.is_file():
        print(f"[err] {scope} not found", file=sys.stderr); sys.exit(2)

    text = sub.read_text()

    # R89 fix G1: accept three layouts.
    sec3_m = re.search(r"^## 3\. Ready to submit[^\n]*$", text, re.MULTILINE)
    if sec3_m:
        body = text[sec3_m.end():]
        draft_pattern = r"^### Draft (\d+) — (.+)$"
        fmt = "R83-canonical (Section 3)"
    else:
        legacy_m = re.search(r"^#{1,3}\s*(?:.*?)?Submission\s+\d+\s+—\s+#", text, re.MULTILINE)
        if legacy_m:
            body = text
            draft_pattern = r"^#{1,3}\s*(?:.*?)?Submission (\d+)\s+—\s+#?([^—\n]+?)\s+—\s+([^\n]+)$"
            fmt = "legacy (Submission N — #ID — Severity)"
        else:
            print(f"[err] no draft headers found in SUBMISSIONS.md", file=sys.stderr)
            sys.exit(2)
    draft_hdrs = list(re.finditer(draft_pattern, body, re.MULTILINE))
    print(f"[setup] {len(draft_hdrs)} drafts found ({fmt})\n")

    results = []
    for i, m in enumerate(draft_hdrs):
        n = m.group(1)
        if len(m.groups()) >= 3:
            t = f"#{m.group(2).strip()} — {m.group(3).strip()}"
        else:
            t = m.group(2)
        if args.draft is not None and int(n) != args.draft:
            continue
        start = m.start()
        end = draft_hdrs[i + 1].start() if i + 1 < len(draft_hdrs) else len(body)
        draft = body[start:end]
        passed, total, checks = audit_draft(draft, n, t, in_scope, triager_clean=False)
        results.append((n, t, passed, total, checks))

    print(f"{'Draft':<6} {'Title':<58} {'Score':<10}")
    print("=" * 90)
    any_fail = False
    for n, t, p, total, _ in results:
        mark = "PASS" if p == total else "FAIL"
        status = f"{p}/{total} {mark}"
        if p < total:
            any_fail = True
        title = (t[:55] + "..") if len(t) > 57 else t
        print(f"{n:<6} {title:<58} {status}")

    if any_fail:
        print("\n--- FAILED CHECKS ---\n")
        for n, t, p, total, checks in results:
            fails = [(k, v[1]) for k, v in checks.items() if not v[0]]
            if fails:
                print(f"Draft {n} — {t[:80]}")
                for k, reason in fails:
                    print(f"    [FAIL] {k}: {reason}")
                print()

    if args.strict and any_fail:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
