#!/usr/bin/env python3
"""Rule 61 Claim-Source-Anchor-Required gate (Check #108).

# Rule 61: this tool emits no corpus record.

TRIGGER: severity HIGH+ AND draft body contains structural-negation
claims about codebase behavior ("X is unreachable", "Y does not apply",
"Z never executes", "stays NULL", "stays zero", "never confirms",
"never exists", "no in-tree consumer", "0 callers", "structurally
blocked", "cannot be reached", "fails to fire", etc.).

When a HIGH+ draft asserts a structural negation about codebase
behavior, the natural triager response is "where in the source does
the code prove that?". If the assertion is made from a mental model
without an inline file:line anchor, the triager either (a) closes the
finding as "cannot verify" or (b) opens a multi-round dispute that
eventually inverts the verdict when source-verify happens.

Every structural-negation assertion MUST be paired with an inline
source anchor in the same sentence or paragraph. Accepted anchor
forms:

  - `[src: path/to/file.ext:line]` or `[src: path/to/file.ext:line-line]`
  - inline file:line citation `path/to/file.ext:NNN` where the extension
    is a recognized source extension (.rs, .go, .sol, .py, .ts, .js,
    .move, .vy, .cairo, .yul, .huff, .c, .cpp, .h, .java, .kt, .swift,
    .rb, .php, .cs)

Anchor lesson: Spark LEAD 1 dispute v1-v10 culminated in HONEST
CONCESSION (commit 9e84c4c322) because the v9 row 2 claim
"QueryBroadcastableTransferLeaves unreachable because leaf
NodeConfirmationHeight stays NULL" was structurally wrong from v1 -
asserted from mental model rather than anchored to source. Source-
verify at audit pin showed finalize_deposit_tree.go:969
SetRawTx(signedCpfpRootTx) + ent/schema/tree_node.go:325-336 +
tree/tree.go:30-36 proves leaf.RawTxid == cpfpRootTx.TxHash() so
MarkExitingNodes DOES match -> watchtower path IS reachable ->
Critical claim falsified.

If R61 had existed at v1, the unanchored claim would have been refused
pre-submit, saving 9 dispute rounds + ~3 weeks of compute + credibility
cost.

Honest dispositions PASS:
  pass-out-of-scope                       : severity below HIGH
  pass-no-structural-assertions           : HIGH+ but no structural
                                            negations found in the body
  pass-all-anchored                       : every structural-negation
                                            sentence is anchored to a
                                            file:line citation in the
                                            same sentence/paragraph
  ok-rebuttal                             : visible bounded
                                            r61-rebuttal marker

Fail-closed verdicts:
  fail-unanchored-claim                   : one or more structural-
                                            negation sentences are
                                            unanchored (no file:line
                                            citation in the same
                                            sentence/paragraph)
  error

Exit codes:
  0 - pass / ok-rebuttal / pass-out-of-scope
  1 - any fail-* verdict (always; or with --strict for warn-grade flags)
  2 - input error

Schema: auditooor.r61_claim_source_anchor_check.v1

Override marker:
  visible bounded line "r61-rebuttal: <reason>" (<=200 chars)
    OR
  HTML-comment form "<!-- r61-rebuttal: <reason> -->" (<=200 chars).
  Empty or oversized reasons are ignored; original fail verdict stands.

Env extension hooks:
  AUDITOOOR_R61_NEGATION_PATTERNS         - newline-separated regex list
                                            appended to
                                            DEFAULT_NEGATION_PATTERNS
  AUDITOOOR_R61_REQUIRED_CITATION_SHAPES  - newline-separated regex list
                                            appended to
                                            DEFAULT_CITATION_PATTERNS
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.r61_claim_source_anchor_check.v1"
GATE = "R61-CLAIM-SOURCE-ANCHOR-REQUIRED"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MIN_SEVERITY_RANK = SEVERITY_RANK["high"]

# ---------------------------------------------------------------------------
# Trigger: structural-negation prose detectors.
#
# These patterns catch claims that ASSERT THE NEGATION OF SOMETHING the
# codebase does or could do. Each pattern represents a claim that, if
# false, would invert the finding's verdict (the LEAD 1 v9 anti-pattern).
# ---------------------------------------------------------------------------

DEFAULT_NEGATION_PATTERNS = [
    # "X is unreachable" / "X is structurally unreachable"
    r"\b(?:is|are|was|were|remains|stays)\s+(?:structurally\s+|categorically\s+|provably\s+)?unreachable\b",
    r"\b(?:structurally|categorically|provably)\s+unreachable\b",
    # "cannot be reached" / "can never be reached"
    r"\b(?:cannot|can\s+never|can\s+not|will\s+never|could\s+never|won't)\s+be\s+(?:reached|hit|triggered|executed|called|invoked|fired)\b",
    # "X does not apply" / "X never applies"
    r"\b(?:does\s+not|do\s+not|doesn't|don't|did\s+not|didn't|will\s+not|won't|never)\s+(?:apply|applies|fire|fires|execute|executes|run|runs|trigger|triggers|match|matches|reach|reaches|enter|enters)\b",
    # "X never executes" / "X never fires" / "X never runs" / "X never matches"
    r"\bnever\s+(?:executes|fires|runs|matches|reaches|enters|hits|triggers|invokes|broadcasts|confirms|exists|gets\s+called|gets\s+invoked|gets\s+set|gets\s+triggered|gets\s+reached)\b",
    # "X never confirms" / "X never exists" - present in v9 line 49 + 56
    r"\bnever\s+(?:confirm|confirms|exist|exists|gets\s+set)\b",
    # "stays NULL" / "stays zero" / "remains NULL" / "remains zero"
    r"\b(?:stays|remains|stays\s+at|remains\s+at|left\s+at|kept\s+at)\s+(?:NULL|null|None|zero|0|undefined|empty|unset|unchanged|the\s+same)\b",
    # "structurally blocked" / "structurally gated"
    r"\bstructurally\s+(?:blocked|gated|rejected|prevented|prohibited|impossible)\b",
    # "no in-tree consumer" / "0 callers" / "zero callers" / "no callers"
    r"\b(?:no|zero|0)\s+(?:in[- ]tree|on[- ]chain|production|live)\s+(?:consumer|consumers|caller|callers|user|users|reader|readers)\b",
    r"\b(?:zero|0)\s+(?:callers|consumers|references|matches|hits)\b",
    r"\bno\s+(?:callers|consumers|references)\s+(?:exist|present)\b",
    # "no callsite" / "no callsites exist"
    r"\bno\s+call[- ]?sites?\s+(?:exist|exists|present)\b",
    # "fails to fire" / "fails to match" / "fails to trigger"
    r"\bfails?\s+to\s+(?:fire|match|trigger|reach|hit|invoke|execute|run|apply|broadcast|confirm)\b",
    # "Z is impossible" / "is not possible"
    r"\b(?:is|are|was|were)\s+(?:not\s+possible|impossible|infeasible|impracticable)\b",
    # "X is excluded" / "X is filtered out"
    r"\b(?:is|are|gets|get)\s+(?:excluded|filtered\s+out|filtered|rejected|skipped|short[- ]circuited)\b",
    # "is silently dropped" / "is silently skipped"
    r"\bsilently\s+(?:dropped|skipped|exits?|returns?|fails?|rejected|excluded)\b",
    # "no copy of X exists" / "X does not exist on chain"
    r"\bno\s+(?:copy|instance|trace|record)\s+of\s+\S+\s+(?:exists?|appears?|landed?)\b",
    r"\b(?:does\s+not|doesn't)\s+exist\s+(?:on\s+chain|in\s+the\s+tree|in\s+state|in\s+storage)\b",
    # "X has no capacity to ..." / "X has zero capacity"
    r"\bhas\s+(?:no|zero)\s+capacity\s+to\b",
    # "every defensive path requires" - v9-style sweeping negation
    r"\bevery\s+(?:defensive|defense|protection|protective|safe|safety)\s+(?:path|guard|check|layer|branch)\s+(?:requires|needs|depends\s+on)\b",
    # "X cannot exist" / "X will not exist"
    r"\b(?:cannot|can\s+not|will\s+not|won't|could\s+not|couldn't)\s+(?:exist|broadcast|confirm|fire|land|reach|trigger)\b",
    # "is not produced" / "is not signed" / "is never produced"
    r"\b(?:is|are|was|were)\s+(?:not|never)\s+(?:produced|signed|broadcast|broadcasted|submitted|attested|finalized|committed|emitted)\b",
    # "is short-circuited" / "is short-circuited at"
    r"\bshort[- ]circuited\b",
    # "returns early without" / "exits early without"
    r"\b(?:returns?|exits?)\s+(?:early|silently|immediately)\s+(?:without|before)\b",
]

# ---------------------------------------------------------------------------
# Source-anchor citation detectors.
#
# An anchor is one of:
#   - `[src: path/to/file.ext:NNN]` or `[src: path/to/file.ext:NNN-NNN]`
#   - inline file:line where file has a recognized source extension
# ---------------------------------------------------------------------------

# Bracketed [src: ...] form. The path may contain hyphens, dots, slashes,
# alphanumerics, and underscores. Line spec is `NNN`, `NNN-NNN`, or `NNN:NNN`.
SRC_BRACKET_RE = re.compile(
    r"\[\s*src\s*:\s*[\w./\-]+\.\w+:\d+(?:[-:]\d+)?\s*\]",
    re.IGNORECASE,
)

# Inline file:line citation form. Recognized source extensions only -
# markdown / text / log files are excluded.
INLINE_FILE_LINE_RE = re.compile(
    r"\b[\w./\-]+\.(?:rs|go|sol|py|ts|tsx|js|move|vy|cairo|yul|huff|c|cpp|h|java|kt|swift|rb|php|cs)"
    r":\d+(?:[-:]\d+)?\b",
    re.IGNORECASE,
)

DEFAULT_CITATION_PATTERNS = [
    SRC_BRACKET_RE.pattern,
    INLINE_FILE_LINE_RE.pattern,
]


# ---------------------------------------------------------------------------
# Rebuttal markers
# ---------------------------------------------------------------------------

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r61-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r61[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*(?:[-*]\s+)?\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*(?:[-*]\s+)?severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*(?:[-*]\s+)?severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*(?:[-*]\s+)?selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
        (r"(?im)^\s*(?:[-*]\s+)?\**\s*Severity\s+selector\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-selector"),
        # HTML-comment Severity marker (e.g. v10 draft uses "<!-- Severity: Medium -->")
        (r"<!--\s*Severity\s*:\s*(Critical|High|Medium|Low)\s*-->", "severity-comment"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _split_paragraphs(text: str) -> list[tuple[int, int, str]]:
    """Split text into paragraphs preserving line numbers.

    Returns list of (start_line, end_line, paragraph_text) tuples. Paragraph
    is delimited by one or more blank lines.
    """
    lines = text.splitlines()
    paragraphs: list[tuple[int, int, str]] = []
    cur_start = 1
    cur_lines: list[str] = []
    for idx, line in enumerate(lines, start=1):
        if line.strip() == "":
            if cur_lines:
                paragraphs.append((cur_start, idx - 1, "\n".join(cur_lines)))
                cur_lines = []
            cur_start = idx + 1
        else:
            if not cur_lines:
                cur_start = idx
            cur_lines.append(line)
    if cur_lines:
        paragraphs.append((cur_start, len(lines), "\n".join(cur_lines)))
    return paragraphs


# A simple sentence splitter. We split on '. ', '? ', '! ', plus end-of-line
# terminators. Markdown table rows and code-fence blocks are handled by the
# table/codefence stripping pass on the paragraph text.
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\(\[])")


def _split_sentences(paragraph: str) -> list[str]:
    # If paragraph looks like a markdown table (contains `|` in most lines),
    # treat each non-separator line as its own "sentence" - table rows do not
    # follow English-sentence punctuation. The same applies to bullet lines.
    lines = paragraph.splitlines()
    table_lines = sum(1 for ln in lines if "|" in ln)
    if lines and table_lines >= max(2, len(lines) // 2):
        # Treat each row as its own scope for anchor matching.
        return [ln for ln in lines if ln.strip()]
    # Bullet lines: each top-level bullet is a separate sentence-scope.
    if all(
        (not ln.strip())
        or ln.lstrip().startswith(("-", "*", "+"))
        or ln.lstrip().startswith(tuple(f"{n}." for n in range(0, 10)))
        for ln in lines
    ):
        return [ln for ln in lines if ln.strip()]
    # Otherwise standard sentence splitting on the whole paragraph (joined).
    joined = " ".join(ln.strip() for ln in lines if ln.strip())
    parts = SENTENCE_SPLIT_RE.split(joined)
    return [p for p in parts if p.strip()]


def _strip_quoted_negations(text: str) -> str:
    """Remove text spans that are quotes of OTHER drafts' negations.

    Specifically, content inside `\"...\"` or backticks that quotes a v9-style
    negation (typical anti-pattern: a v10 dispute response QUOTES the v9
    negation it is correcting). The quoted negation belongs to the OTHER
    draft; the current draft should not be penalized for it.
    """
    # Remove `"..."` and `'...'` quoted spans entirely - quoted text is
    # someone else's claim, not the author's.
    out = re.sub(r'"[^"\n]{1,400}"', " ", text)
    out = re.sub(r"'[^'\n]{1,400}'", " ", out)
    return out


def _is_anchored(
    scope_text: str,
    paragraph_text: str,
    *,
    neighbor_text: str = "",
) -> tuple[bool, list[str]]:
    """Check if a sentence (or row) has a source anchor in itself OR in its
    surrounding paragraph context OR in the immediately-adjacent bullet
    siblings (when the paragraph is a single-line bullet).
    """
    env_extra = _env_patterns("AUDITOOOR_R61_REQUIRED_CITATION_SHAPES")
    anchor_re = _compile_union(DEFAULT_CITATION_PATTERNS + env_extra)

    matches_in_sentence = [m.group(0) for m in anchor_re.finditer(scope_text)]
    if matches_in_sentence:
        return True, matches_in_sentence
    matches_in_paragraph = [m.group(0) for m in anchor_re.finditer(paragraph_text)]
    if matches_in_paragraph:
        return True, matches_in_paragraph
    if neighbor_text:
        matches_in_neighbor = [m.group(0) for m in anchor_re.finditer(neighbor_text)]
        if matches_in_neighbor:
            return True, matches_in_neighbor
    return False, []


def _is_single_bullet(paragraph_text: str) -> bool:
    """Detect a single-line bullet paragraph (e.g. a bullet in an R29/R42/R43
    section where each bullet has been separated by a blank line).
    """
    lines = [ln for ln in paragraph_text.splitlines() if ln.strip()]
    if len(lines) != 1:
        return False
    stripped = lines[0].lstrip()
    return stripped.startswith(("-", "*", "+"))


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "For every structural-negation claim (\"X is unreachable\", "
            "\"Y does not apply\", \"never executes\", \"stays NULL\", "
            "\"no in-tree consumer\", \"structurally blocked\", etc.) "
            "add an inline source anchor in the same sentence or paragraph. "
            "Accepted forms: `[src: path/to/file.ext:NNN]` or inline "
            "`path/to/file.ext:NNN` citation. Recognized source extensions: "
            ".rs / .go / .sol / .py / .ts / .move / .vy / .cairo / .yul / "
            ".huff / .c / .cpp / .h / .java / .kt / .swift / .rb / .php / .cs.",
            "Override: visible 'r61-rebuttal: <reason>' (<=200 chars) "
            "or '<!-- r61-rebuttal: <reason> -->' for legitimately "
            "unanchored claims (e.g., quoting prior dispute rounds).",
        ],
    }

    # Severity discipline.
    if severity is None or SEVERITY_RANK.get(severity, 0) < MIN_SEVERITY_RANK:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH; R61 not applicable"
        return 0, payload

    # Rebuttal short-circuit.
    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    # Build negation detector.
    negation_re = _compile_union(
        DEFAULT_NEGATION_PATTERNS + _env_patterns("AUDITOOOR_R61_NEGATION_PATTERNS")
    )

    # Walk paragraphs -> sentences. For each sentence containing a structural
    # negation pattern, check if the sentence or its paragraph carries a
    # source anchor.
    unanchored: list[dict[str, Any]] = []
    anchored_count = 0
    total_negation_scopes = 0

    # Rubric-row mapping context: lines that mention CRIT-1/CRIT-2/HIGH-1
    # /MEDIUM-1/LOW-1/PoI rubric-row IDs are about whether the finding
    # MATCHES A RUBRIC ROW (not about codebase behavior). Same for severity-
    # walk-back / impact-mapping contexts. These claims should not trip R61.
    RUBRIC_CONTEXT_RE = re.compile(
        r"\b(?:CRIT-\d|HIGH-\d|MEDIUM-\d|LOW-\d|Primacy\s+of\s+Impact|PoI|"
        r"rubric(?:\s+row)?|severity\s+(?:row|mapping|tier)|"
        r"impact\s+contract|impact\s+mapping)\b",
        re.IGNORECASE,
    )
    # Harness/test-coverage context: claims about what the PoC harness did or
    # didn't do are about test coverage, not codebase behavior.
    HARNESS_CONTEXT_RE = re.compile(
        r"\b(?:harness|PoC|test\s+harness|regression\s+harness|test\s+suite|"
        r"regtest|simulation|fixture|fuzz\s+harness)\b",
        re.IGNORECASE,
    )

    paragraphs = _split_paragraphs(text)
    for idx, (pstart, pend, ptext) in enumerate(paragraphs):
        # Skip code-fence paragraphs (start with ``` or are inside ```).
        # Simple heuristic: if any line begins with ```, treat the whole
        # paragraph as code and skip.
        if any(ln.lstrip().startswith("```") for ln in ptext.splitlines()):
            continue
        # Strip text that is a quote of someone else's claim (v9-style
        # quoted negations in a v10 response).
        clean_ptext = _strip_quoted_negations(ptext)
        # For single-bullet paragraphs, treat the immediately-adjacent bullets
        # as a shared semantic block (R29/R42/R43/R57 sections often have one
        # bullet per blank-line-delimited paragraph).
        neighbor_text = ""
        if _is_single_bullet(ptext):
            if idx > 0:
                _, _, prev_text = paragraphs[idx - 1]
                if _is_single_bullet(prev_text):
                    neighbor_text += prev_text + "\n"
            if idx + 1 < len(paragraphs):
                _, _, next_text = paragraphs[idx + 1]
                if _is_single_bullet(next_text):
                    neighbor_text += next_text
        sentences = _split_sentences(clean_ptext)
        for sentence in sentences:
            # Skip pure markdown headers - section titles are not claims.
            stripped = sentence.strip()
            if stripped.startswith("#"):
                continue
            if not negation_re.search(sentence):
                continue
            # Skip rubric-row-mapping sentences: "does not apply" about
            # whether a rubric row covers the finding is not a codebase
            # claim.
            if RUBRIC_CONTEXT_RE.search(sentence):
                continue
            # Skip harness/PoC-coverage sentences: "did not exercise" about
            # test-suite coverage is not a codebase claim.
            if HARNESS_CONTEXT_RE.search(sentence):
                continue
            total_negation_scopes += 1
            anchored, matches = _is_anchored(
                sentence, clean_ptext, neighbor_text=neighbor_text
            )
            if anchored:
                anchored_count += 1
            else:
                unanchored.append({
                    "paragraph_start_line": pstart,
                    "paragraph_end_line": pend,
                    "sentence_excerpt": sentence.strip()[:300],
                    "negation_token": (
                        m.group(0) if (m := negation_re.search(sentence)) else ""
                    )[:80],
                })

    payload["evidence"]["total_negation_scopes"] = total_negation_scopes
    payload["evidence"]["anchored_count"] = anchored_count
    payload["evidence"]["unanchored_count"] = len(unanchored)
    payload["evidence"]["unanchored"] = unanchored[:20]

    if total_negation_scopes == 0:
        payload["verdict"] = "pass-no-structural-assertions"
        payload["reason"] = "HIGH+ but no structural-negation claims detected"
        return 0, payload

    if not unanchored:
        payload["verdict"] = "pass-all-anchored"
        payload["reason"] = (
            f"all {total_negation_scopes} structural-negation claim(s) are "
            "anchored to a source citation in the same sentence or paragraph"
        )
        return 0, payload

    payload["verdict"] = "fail-unanchored-claim"
    payload["reason"] = (
        f"{len(unanchored)} of {total_negation_scopes} structural-negation "
        "claim(s) lack an inline source anchor (file:line citation) in the "
        "same sentence or paragraph; add `[src: path/file.ext:NNN]` or inline "
        "`path/file.ext:NNN` per offending claim or use r61-rebuttal"
    )
    return 1, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="Path to draft .md file")
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
        ],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        strict=args.strict,
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        verdict = payload.get("verdict", "error")
        reason = payload.get("reason", payload.get("error", ""))
        prefix = "[PASS]" if verdict.startswith("pass") or verdict == "ok-rebuttal" else "[FAIL]"
        print(f"{prefix} {GATE}: {verdict}")
        if reason:
            print(f"  reason: {reason}")
        ev = payload.get("evidence", {})
        if ev:
            print(f"  total negation scopes: {ev.get('total_negation_scopes', 0)}")
            print(f"  anchored: {ev.get('anchored_count', 0)}")
            print(f"  unanchored: {ev.get('unanchored_count', 0)}")
            for item in (ev.get("unanchored") or [])[:5]:
                print(
                    f"    line ~{item.get('paragraph_start_line', '?')}: "
                    f"\"{item.get('sentence_excerpt', '')[:120]}\""
                )
    return rc


if __name__ == "__main__":
    sys.exit(main())
