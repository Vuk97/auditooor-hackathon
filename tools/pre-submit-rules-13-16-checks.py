#!/usr/bin/env python3
"""pre-submit-rules-13-16-checks.py — pre-submit gates for Rules 10-16 + D13/D20.

Codified from `docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md` Rules 10-16 plus
the dydx engagement closeout (cantina-018/048/192/202/PENDING1-5). Each check
returns ``(passed, message)`` and the CLI dispatches per ``--check`` selector
(50..57). ``pre-submit-check.sh`` invokes this once per check ID.

Empirical anchors
-----------------
- Rule 10 (#50): wrong-rubric cross-engagement contamination caught when Spark
  "(fix requires hardfork)" phrasing leaked into dydx CRITICAL escalation briefs.
- Rule 11 (#51): default-vs-opt-in claim — empirical anchor goleveldb dropped
  as "opt-in" but actually default at `server/util.go:430` + `cometbft
  config/config.go:256`.
- Rule 12 (#52): L17 build-path itemization — empirical anchor
  ASA-2024-0012-CAP-HARNESS "2-4 days, out-of-90-min-session-budget".
- Rule 13 (#53): advisory-ID leak — dydx codec sub-call cap draft initially
  referenced ASA-2024-0012; scrub required before filing (operator caught).
- D13 (#54): escalation-history narrative — drafts must read as single
  consolidated run, not as "we attempted X then Y" history.
- Rule 15 (#55): but-for causation — must show that without the bug, the
  impact does not materialize.
- Rule 16 (#56): parity-precedent citation — when severity escalated by
  parity with prior filed finding, must cite the precedent.
- D20 (#57): consolidation linter — single-PoC drafts must not list multiple
  test-file paths.

Exit codes
----------
0 — passed (or soft-skip)
1 — failed closed
2 — usage error / unparseable input
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Rule 10 (#50) — wrong-rubric cross-engagement contamination
# ---------------------------------------------------------------------------

# Spark-specific severity-rubric phrases (Spark SEVERITY.md). When these appear
# in a non-Spark draft (i.e. workspace path indicates non-Spark engagement),
# fail closed.
SPARK_RUBRIC_PHRASES = [
    r"\(fix requires hardfork\)",
    r"fix requires hardfork",
    r"hardfork-required",
    r"Spark mainnet user",
    r"chain-watcher",
    r"coop-exit flow",
    r"FROST signing library",
    r"Primacy of Impact",
]

# Cantina/dydx-specific phrases that should NOT appear in Spark drafts.
CANTINA_RUBRIC_PHRASES = [
    r"\bCantina\b",
    r"v4-chain \(protocol\)",
    r"cosmos-sdk fork",
    r"\biavl\b",
    r"\bdYdX\b",
    r"\bdydx\b",
]

# Sherlock-specific.
SHERLOCK_PHRASES = [
    r"\bSherlock\b",
    r"watson",
    r"\bissue contest\b",
]

# Code4rena-specific.
C4_PHRASES = [
    r"\bCode4rena\b",
    r"\bC4\b judges",
    r"warden",
]


def _detect_workspace_engagement(path: Path) -> str:
    """Infer engagement/platform generically. Prefer the workspace SCOPE.md
    'Platform:' line (authoritative) over path tokens, so ANY program is
    detected (not just the spark/dydx path-token cases). Returns one of
    spark|dydx|cantina|immunefi|hackenproof|sherlock|code4rena|unknown."""
    # (1) SCOPE.md platform line - walk up from the draft path to find a ws root.
    for anc in [path] + list(path.parents):
        scope = anc / "SCOPE.md"
        if scope.is_file():
            try:
                head = scope.read_text(encoding="utf-8", errors="replace")[:4000].lower()
            except OSError:
                head = ""
            for plat in ("cantina", "immunefi", "hackenproof", "sherlock", "code4rena", "spark", "dydx"):
                if re.search(rf"platform[^\n]*\b{plat}\b", head) or f"\n- platform: {plat}" in head:
                    return plat
            break
    # (2) path tokens (legacy fallback).
    parts = [p.lower() for p in path.parts]
    if any("spark" in p for p in parts):
        return "spark"
    if any(p in ("dydx",) for p in parts):
        return "dydx"
    if any("cantina" in p for p in parts):
        return "cantina"
    if any("immunefi" in p for p in parts):
        return "immunefi"
    if any("hackenproof" in p for p in parts):
        return "hackenproof"
    if any("sherlock" in p for p in parts):
        return "sherlock"
    if any(p in ("c4", "code4rena") for p in parts):
        return "code4rena"
    return "unknown"


def check_50_wrong_rubric_contamination(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*r10-rebuttal:", text):
        return True, "r10-rebuttal override present"
    engagement = _detect_workspace_engagement(path)
    # NOTE: 'unknown' no longer soft-skip-PASSES (that was a fail-open submission
    # gate for every non-spark/dydx engagement - ssv/polygon/optimism/etherfi/
    # near/...). When the engagement is unknown we fail-CLOSED by scanning ALL
    # contest-platform rubric phrase sets (any of them in a draft for an
    # unidentified program is a candidate leak; add an r10-rebuttal if native).
    _ALL_FOREIGN = [
        ("Spark", SPARK_RUBRIC_PHRASES),
        ("dydx/Cantina", CANTINA_RUBRIC_PHRASES),
        ("Sherlock", SHERLOCK_PHRASES),
        ("Code4rena", C4_PHRASES),
    ]
    foreign_groups = {
        "spark": [
            ("dydx/Cantina", CANTINA_RUBRIC_PHRASES),
            ("Sherlock", SHERLOCK_PHRASES),
            ("Code4rena", C4_PHRASES),
        ],
        "dydx": [
            ("Spark", SPARK_RUBRIC_PHRASES),
            ("Sherlock", SHERLOCK_PHRASES),
            ("Code4rena", C4_PHRASES),
        ],
        "sherlock": [
            ("Spark", SPARK_RUBRIC_PHRASES),
            ("dydx/Cantina", CANTINA_RUBRIC_PHRASES),
            ("Code4rena", C4_PHRASES),
        ],
        "code4rena": [
            ("Spark", SPARK_RUBRIC_PHRASES),
            ("dydx/Cantina", CANTINA_RUBRIC_PHRASES),
            ("Sherlock", SHERLOCK_PHRASES),
        ],
        # cantina-native programs (morpho etc.): cantina phrasing is native, scan the rest.
        "cantina": [
            ("Spark", SPARK_RUBRIC_PHRASES),
            ("Sherlock", SHERLOCK_PHRASES),
            ("Code4rena", C4_PHRASES),
        ],
        # impact-based platforms: ALL contest-rubric phrasings are foreign.
        "immunefi": _ALL_FOREIGN,
        "hackenproof": _ALL_FOREIGN,
    }.get(engagement, _ALL_FOREIGN)  # unknown -> fail-closed scan of all (was soft-skip PASS)

    hits = []
    for name, phrases in foreign_groups:
        for pat in phrases:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                hits.append(f"{name}-rubric phrase '{m.group(0)}'")
    if hits:
        return False, (
            f"Rule 10 violation (engagement={engagement}): "
            + "; ".join(hits[:5])
            + " — scrub cross-engagement rubric language before filing"
        )
    return True, f"no cross-engagement rubric leak (engagement={engagement})"


# ---------------------------------------------------------------------------
# Rule 11 (#51) — default-vs-opt-in claim must cite code path
# ---------------------------------------------------------------------------

# A claim is something like "X is the default", "X is opt-in", "by default X",
# "default behavior is Y". When such a claim is made, the draft must include a
# code-path citation (file:line OR a fenced code block referencing a source
# file).
DEFAULT_CLAIM_RE = re.compile(
    r"(?i)\b("
    r"by default[, ]|default[s]? to|default[ -]?(?:on|off|enabled|disabled|value|setting)|"
    r"opt[- ]?in(?:\s|\.|,)|opt[- ]?out|"
    r"is (?:the )?default|are (?:the )?default"
    r")"
)

# A code-path citation: file path with .go/.rs/.sol/.py/.ts/.js/.c/.h/.cpp/.move
# extension, optionally with :line.
CODE_PATH_RE = re.compile(
    r"\b[\w/\-.]+\.(go|rs|sol|py|ts|js|c|h|cpp|move|sql|psql|plpgsql)(?::\d+)?\b"
)


def check_51_default_vs_opt_in_citation(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*r11-rebuttal:", text):
        return True, "r11-rebuttal override present"
    default_hits = list(DEFAULT_CLAIM_RE.finditer(text))
    if not default_hits:
        return True, "no default/opt-in claims found"
    # If there are any default claims, require at least one code-path citation
    # in the same draft.
    code_paths = list(CODE_PATH_RE.finditer(text))
    if not code_paths:
        sample = default_hits[0].group(0).strip()
        return False, (
            f"Rule 11 violation: default/opt-in claim '{sample}' found, "
            "but no file.ext[:line] code-path citation anywhere in draft. "
            "Cite the default-config code path (e.g. `server/util.go:430`)"
        )
    return True, (
        f"{len(default_hits)} default/opt-in claim(s) accompanied by "
        f"{len(code_paths)} code-path citation(s)"
    )


# ---------------------------------------------------------------------------
# Rule 12 (#52) — L17 build-path itemization
# ---------------------------------------------------------------------------

# When a draft says "to upgrade to Critical, build X", it should itemize what
# X requires: at least (1) build target / harness name (2) effort estimate
# (3) blocker class (single-process / multi-validator / regtest / mainnet).
BUILD_PATH_TRIGGER_RE = re.compile(
    r"(?i)\bwhat would upgrade to (?:critical|high)|"
    r"to (?:upgrade|escalate) to (?:critical|high)|"
    r"build-path|"
    r"path to (?:critical|high)|"
    r"deferred build|"
    r"l17 build|"
    r"build-or-drop"
)

# Itemization shape: numbered or bulleted list with ≥3 items in the build-path
# section.
ITEMIZATION_RE = re.compile(r"^\s*(?:[-*]|\d+\.)\s+\S", re.MULTILINE)


def check_52_build_path_itemization(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*r12-rebuttal:", text):
        return True, "r12-rebuttal override present"
    if not BUILD_PATH_TRIGGER_RE.search(text):
        return True, "no build-path / upgrade-to-Critical section present"
    # Find the trigger position; check that within the next 1500 chars there
    # are ≥3 list items.
    m = BUILD_PATH_TRIGGER_RE.search(text)
    window_end = min(len(text), m.start() + 1500)
    window = text[m.start():window_end]
    items = ITEMIZATION_RE.findall(window)
    if len(items) < 3:
        return False, (
            f"Rule 12 violation: build-path section near '{m.group(0)}' has "
            f"{len(items)} itemized step(s); needs ≥3 (target/harness, effort, blocker)"
        )
    return True, f"build-path itemized with {len(items)} steps"


# ---------------------------------------------------------------------------
# Rule 13 (#53) — advisory-ID OOS-leak scrub (D12)
# ---------------------------------------------------------------------------

# Advisory ID patterns that, when referenced in a filing-ready draft, may
# accidentally claim OOS coverage or scope-overlap with a known disclosure.
# Scrub all of these unless preceded by a documented "originality defense"
# section header.
ADVISORY_ID_RE = re.compile(
    r"\b("
    r"ASA-\d{4}-\d{4,5}"
    r"|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
    r"|CVE-\d{4}-\d{4,7}"
    r"|CSA-\d{4}-\d{2,4}"
    r"|ICRA-\d{4}-\d{2,4}"
    r"|(?<![A-Z-])OF-\d{3,}"
    r"|RUSTSEC-\d{4}-\d{4}"
    r")\b"
)

# Section headers that legitimately cite advisory IDs for originality defense.
ORIGINALITY_SECTION_RE = re.compile(
    r"(?im)^#{1,6}\s+(?:scope\s+and\s+)?originality|"
    r"^#{1,6}\s+prior\s+(?:art|disclosures?|reports?)|"
    r"^#{1,6}\s+upstream\s+(?:equivalent|fix|patch)|"
    r"^#{1,6}\s+recommended?\s+fix|"
    r"^#{1,6}\s+fix\s+(?:recommendation|guidance)"
)

# Context tokens that legitimize an advisory-ID citation (within ±200 chars).
OOS_CONTEXT_TOKENS_RE = re.compile(
    r"(?i)(oos_traps|out[- ]of[- ]scope|\bOOS\b|"
    r"different (?:module|bug class|finding)|"
    r"upstream cherry-pick|cherry-picked|silently[- ]shipped|"
    r"git log evidence)"
)


def check_53_advisory_id_oos_leak(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*(?:l13|r13)-rebuttal:", text):
        return True, "r13/l13-rebuttal override present"
    hits = list(ADVISORY_ID_RE.finditer(text))
    if not hits:
        return True, "no advisory ID references"
    # Check each hit individually: if it's inside or after an originality
    # section OR has an OOS-context token within ±200 chars, allow.
    section_positions = [m.start() for m in ORIGINALITY_SECTION_RE.finditer(text)]
    illegitimate = []
    for h in hits:
        hp = h.start()
        # Find the most recent section header before this hit.
        in_section = any(sp < hp for sp in section_positions)
        ctx_start = max(0, hp - 200)
        ctx_end = min(len(text), hp + 200)
        has_context = bool(OOS_CONTEXT_TOKENS_RE.search(text[ctx_start:ctx_end]))
        if not in_section and not has_context:
            illegitimate.append(h.group(0))
    if illegitimate:
        sample = ", ".join(sorted(set(illegitimate))[:3])
        return False, (
            f"Rule 13 violation: advisory ID(s) {sample} appear outside an originality / "
            "prior-art / recommended-fix section AND lack OOS-context tokens "
            "('oos_traps', 'OOS', 'out-of-scope', 'cherry-pick', etc.) within ±200 chars. "
            "Scrub, move to a legitimate section, or add `<!-- r13-rebuttal: <reason> -->`."
        )
    return True, f"{len(hits)} advisory ID(s) in legitimate context"


# ---------------------------------------------------------------------------
# D13 (#54) — escalation-history narrative scrub
# ---------------------------------------------------------------------------

# Phrases that indicate ping-pong / "we tried X then Y" narrative that should
# be scrubbed from the consolidated single-narrative draft.
ESCALATION_HISTORY_RE = re.compile(
    r"(?i)\b("
    r"we attempted|we tried|first we|then we|after that we|"
    r"initial(?:ly)? we|originally we|"
    r"iteration \d+|iter[- ]?\d+|round \d+|round-\d+|"
    r"v\d+ of (?:this )?(?:draft|finding|submission)|"
    r"previous(?:ly)? (?:draft|version|attempt)|"
    r"earlier (?:draft|version|attempt)|"
    r"escalat(?:ed|ion) history|"
    r"approach (?:a|b|c|1|2|3) (?:failed|did not|worked|succeeded)"
    r")\b"
)


def check_54_escalation_history_narrative(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*d13-rebuttal:", text):
        return True, "d13-rebuttal override present"
    hits = list(ESCALATION_HISTORY_RE.finditer(text))
    if not hits:
        return True, "no escalation-history narrative detected"
    sample = ", ".join(sorted({h.group(0) for h in hits})[:5])
    return False, (
        f"D13 violation: escalation-history phrasing detected ({len(hits)} hits): "
        f"{sample} — rewrite as single-narrative consolidated draft "
        "(team reads this as filed, not as authoring journal)"
    )


# ---------------------------------------------------------------------------
# Rule 15 (#55) — but-for causation gate (D15)
# ---------------------------------------------------------------------------

# Drafts claiming Critical / High impact must articulate but-for causation:
# "absent this bug, the impact does not occur" OR equivalent counterfactual.
SEVERITY_HIGH_PLUS_RE = re.compile(
    r"(?im)^(?:severity|## severity)\s*[:\-]?\s*(critical|high)\b"
)
BUT_FOR_RE = re.compile(
    r"(?i)\b("
    r"but[- ]for|"
    r"absent (?:the|this) bug|"
    r"without (?:the|this) bug|"
    r"if the bug were not present|"
    r"counterfactual|"
    r"without (?:the|this) vulnerability|"
    r"in the absence of (?:the|this) (?:bug|vulnerability|flaw)|"
    r"would not (?:occur|materialize|happen|trigger) (?:absent|without)"
    r")\b"
)


def check_55_but_for_causation(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*r15-rebuttal:", text):
        return True, "r15-rebuttal override present"
    sev_m = SEVERITY_HIGH_PLUS_RE.search(text)
    if not sev_m:
        return True, "soft-skip: severity not Critical/High or not parseable"
    severity = sev_m.group(1).lower()
    if not BUT_FOR_RE.search(text):
        return False, (
            f"Rule 15 violation: severity={severity} but no but-for causation "
            "statement found. Add a sentence like 'Absent this bug, the impact "
            "does not occur because X'."
        )
    return True, f"but-for causation present (severity={severity})"


# ---------------------------------------------------------------------------
# Rule 16 (#56) — parity-precedent citation (D18)
# ---------------------------------------------------------------------------

# When severity is escalated by parity with prior filed finding, the draft
# must cite the precedent: "(per parity with #N)" / "matching #N's mechanism"
# / "same mechanism as #N".
PARITY_TRIGGER_RE = re.compile(
    r"(?i)\b("
    r"parity[- ]precedent|"
    r"parity with (?:cantina-?#?\d+|prior filing|earlier finding|issue #\d+)|"
    r"by parity|"
    r"same mechanism as|"
    r"escalat(?:ed|ion) by (?:parity|precedent)|"
    r"orchestrator override"
    r")\b"
)
PRECEDENT_CITATION_RE = re.compile(
    r"(?i)\b("
    r"cantina-?#?\d+|"
    r"issue\s*#\d+|"
    r"PR\s*#\d+|"
    r"#\d{2,6}"
    r")\b"
)


def check_56_parity_precedent_citation(text: str, path: Path) -> tuple[bool, str]:
    if re.search(r"<!--\s*r16-rebuttal:", text):
        return True, "r16-rebuttal override present"
    parity_hits = list(PARITY_TRIGGER_RE.finditer(text))
    if not parity_hits:
        return True, "no parity-precedent escalation claimed"
    # Within 500 chars of each parity hit, require at least one precedent
    # citation.
    missing = []
    for m in parity_hits:
        window = text[m.start(): min(len(text), m.end() + 500)]
        if not PRECEDENT_CITATION_RE.search(window):
            missing.append(m.group(0))
    if missing:
        return False, (
            f"Rule 16 violation: parity claim(s) {missing[:3]} not accompanied by "
            "a precedent citation (cantina-#N / issue #N / PR #N) within 500 chars"
        )
    return True, f"{len(parity_hits)} parity claim(s) with precedent citation(s)"


# ---------------------------------------------------------------------------
# D20 (#57) — consolidation linter
# ---------------------------------------------------------------------------

# A single-narrative consolidated draft should reference ONE primary PoC test
# file. If it lists ≥3 distinct `*_test.go` / `*_test.rs` / `*.t.sol` paths
# in code-block fences, that's a fragmentation smell.
POC_TEST_PATH_RE = re.compile(
    r"(?m)^[ \t]*(?:[-*]\s+)?"  # optional bullet
    r"`?([\w/\-.]+_test\.(?:go|rs|py|ts|js)|"
    r"[\w/\-.]+\.t\.sol|"
    r"[\w/\-.]+\.spec\.[a-z]+)`?"
)

# Allow override comment.
D20_OVERRIDE_RE = re.compile(r"<!--\s*d20-rebuttal:")


def check_57_consolidation_linter(text: str, path: Path) -> tuple[bool, str]:
    if D20_OVERRIDE_RE.search(text):
        return True, "d20-rebuttal override present"
    paths = set()
    for m in POC_TEST_PATH_RE.finditer(text):
        paths.add(m.group(1))
    if len(paths) >= 3:
        sample = sorted(paths)[:3]
        return False, (
            f"D20 violation: {len(paths)} distinct PoC test paths cited: "
            f"{sample}… — consolidate to a single primary PoC or add "
            "`<!-- d20-rebuttal: <reason> -->`"
        )
    return True, f"{len(paths)} PoC test path(s) cited (within consolidation limit)"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

CHECKS = {
    50: ("Rule 10 wrong-rubric cross-engagement contamination", check_50_wrong_rubric_contamination),
    51: ("Rule 11 default-vs-opt-in claim cites code path", check_51_default_vs_opt_in_citation),
    52: ("Rule 12 L17 build-path itemization", check_52_build_path_itemization),
    53: ("Rule 13 advisory-ID OOS-leak scrub", check_53_advisory_id_oos_leak),
    54: ("D13 escalation-history narrative scrub", check_54_escalation_history_narrative),
    55: ("Rule 15 but-for causation gate", check_55_but_for_causation),
    56: ("Rule 16 parity-precedent citation", check_56_parity_precedent_citation),
    57: ("D20 consolidation linter (single-PoC drafts)", check_57_consolidation_linter),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("submission", help="path to draft markdown")
    ap.add_argument("--check", type=int, required=True, choices=sorted(CHECKS.keys()),
                    help="check ID 50..57")
    args = ap.parse_args()

    p = Path(args.submission)
    if not p.is_file():
        print(f"error: file not found: {p}", file=sys.stderr)
        return 2
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"error: read failed: {e}", file=sys.stderr)
        return 2

    label, fn = CHECKS[args.check]
    passed, msg = fn(text, p)
    if passed:
        print(f"{label}: {msg}")
        return 0
    print(f"{label}: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
