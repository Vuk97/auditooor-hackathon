#!/usr/bin/env python3
"""
detector-fp-shape-lint.py - Lint detector definitions for over-broad FP shapes.

Schema: auditooor.detector_fp_shape_lint.v1

Scans two detector definition sources:
  1. Bash check_pattern() calls in apply-queries.sh (grep-based detectors)
  2. YAML DSL files in reference/patterns.dsl*/ (DSL detectors)

Lint rules:
  - pure_or_with_benign_alternative: OR-regex where a benign-common token
    can fire alone (no discriminating co-term scopes it).
  - symptom_token_no_precondition: detector matches a dangerous-but-common
    symptom token with no precondition / scoping context.
  - unanchored_broad_regex: regex is very short, generic, and unanchored.

Severity levels in flag output:
  - fp_risk   : genuine over-broad flag requiring tightening.
  - advisory  : pattern is intentionally broad by design (review-tier); logged
                for visibility only and NOT actionable. These detectors feed a
                human-review pipeline and are exempt from tightening.

Detector tiers:
  - review-grep : bash grep detectors in apply-queries.sh. Their hits are
                  stamped LOW in engage_report.md and reviewed by a human agent
                  whose explicit job is "verify whether this is a real bug."
                  Mark with `# detector-tier: review-grep` annotation in the
                  script OR rely on the implicit rule: ALL bash grep detectors
                  (detector_type="bash_grep") are review-tier by default.
                  Review-tier detectors are flagged at `advisory` level, NOT
                  `fp_risk`. They are excluded from the --strict exit-1 path.
  - finding-generator : DSL YAML detectors (reference/patterns.dsl*/*.yaml).
                        These produce Slither findings that can auto-promote.
                        AND-clause composition is evaluated holistically: a
                        broad single regex clause inside a multi-clause match
                        block that includes a discriminating `name_matches` /
                        `kind` / `preconditions` is NOT flagged because the
                        AND-composition already scopes the firing condition.

AND-clause awareness for DSL patterns:
  A DSL `match` block is a logical AND of all its clauses. A broad regex on one
  clause (e.g. `function.body_contains_regex: '.*'`) is only a genuine FP risk
  when the ENTIRE match+preconditions block lacks any discriminating clause.
  A discriminating clause is any of:
    - function.name_matches / function.name_matches_regex (non-trivial pattern)
    - function.kind (external_or_public, internal, etc.)
    - a precondition whose value is not `.*` / `.`
    - 3+ match clauses total (specificity by conjunction)
  When ANY discriminating clause is present, DSL regex clauses are not flagged.

Usage:
  python3 tools/detector-fp-shape-lint.py [--dir <repo>] [--json] [--strict]
  python3 tools/detector-fp-shape-lint.py --file apply-queries.sh [--json] [--strict]

Exit codes: 0=clean, 1=fp_risk flags found (only with --strict), 2=error.
  Note: advisory flags (review-tier) never trigger exit-1 in --strict mode.
"""

import re
import sys
import json
import argparse
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Configurable token lists (can be extended via env or future config)
# ---------------------------------------------------------------------------

# Tokens that are extremely common in Solidity and alone do NOT indicate a bug.
# When a pure-OR regex includes one of these as a standalone alternative,
# it makes the entire detector fire on benign code.
BENIGN_COMMON_TOKENS = [
    r"_msgSender\s*\(",           # standard OZ Context helper
    r"msg\.sender",               # ubiquitous
    r"block\.timestamp",          # ubiquitous
    r"\.call\b",                  # every low-level call
    r"\bcall\b",                  # alone is too short
    r"\brequire\b",               # every Solidity require
    r"\btransfer\b",              # very common token transfer
    r"\btransferFrom\b",          # common ERC20
    r"\bapprove\b",               # common ERC20
    r"\bassembly\b",              # any assembly block
    r"tx\.origin",                # common in access-control patterns alone
    r"\bselfdestruct\b",          # alone (covered more narrowly by a good detector)
    r"\bsuicide\b",               # deprecated alias
    r"\bdelegate\b",              # lone word too generic
    r"\bmint\b",                  # lone word too generic
    r"\bburn\b",                  # lone word too generic
    r"\bpause\b",                 # lone word too generic
    r"\bowner\b",                 # lone word too generic
    r"\bbalanceOf\b",             # alone too generic
    r"\btotalSupply\b",           # alone too generic
    r"\binitialized\b",           # alone too generic
    r"address\(this\)",           # extremely common
    r"\bupgrade\b",               # lone word too generic
    r"\bproxy\b",                 # lone word too generic
    r"\bimplementation\b",        # lone word too generic
    r"\bsupply\b",                # lone word too generic
    r"\brevert\b",                # ubiquitous
    r"\bemit\b",                  # ubiquitous
    r"\bevent\b",                 # ubiquitous
]

# Symptom tokens that are dangerous-but-common - require a precondition/scope
SYMPTOM_TOKENS = [
    "ecrecover",
    "tx.origin",
    "selfdestruct",
    "suicide",
    "delegatecall",
    "assembly",
    "msg.sender",
    "block.timestamp",
    "latestRoundData",
    "abi.encodePacked",
]

# Regex so short and generic it will fire everywhere (threshold: len <= 10)
BROAD_REGEX_MAX_LEN = 10
# Regex with no anchoring tokens (no \s, \b, \(, named function patterns, etc.)
ANCHORING_INDICATORS = [r'\s', r'\(', r'\b', r'function\s', r'struct\s',
                        r'contract\s', r'\[', r'\?', r'\{', r'\.']

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_benign_token(alt: str) -> bool:
    """Return True if the regex alternative matches a benign common token."""
    alt = alt.strip()
    for bt in BENIGN_COMMON_TOKENS:
        try:
            # Check if the alternative regex is a sub-pattern of the benign token
            # or if it literally matches one of the benign patterns.
            if re.fullmatch(bt, alt):
                return True
            # Also check simpler literal match
            bt_literal = re.sub(r'\\s\*\\\(', '(', bt).replace(r'\b', '').replace(r'\s*', '')
            if bt_literal.strip() == alt.strip():
                return True
        except re.error:
            pass
    # Direct literal check after stripping regex metacharacters lightly
    alt_clean = re.sub(r'[\s\\]+', '', alt).lower()
    for bt in BENIGN_COMMON_TOKENS:
        bt_clean = re.sub(r'[\s\\]+', '', bt).lower()
        bt_clean = re.sub(r'[().*+?^${}|]', '', bt_clean)
        if alt_clean == bt_clean or alt_clean.startswith(bt_clean):
            return True
    return False


def _has_strong_discriminating_term(alternatives: List[str]) -> bool:
    """Return True if the OR alternatives include at least one strong discriminating term.

    A strong term is one that:
    - Is longer than 12 chars (specific enough)
    - Is NOT a benign common token
    - Includes function/struct/event patterns or named protocol tokens

    When a strong term is present alongside a benign term, the detector is
    less likely to be over-broad (though it may still have nuanced FPs).
    """
    for alt in alternatives:
        alt = alt.strip()
        if _is_benign_token(alt):
            continue
        # Must be substantive: >= 8 non-metachar chars
        clean = re.sub(r'[\\().*+?^${}\[\]|]', '', alt)
        clean = re.sub(r'\s+', '', clean)
        if len(clean) >= 8:
            return True
    return False


def _split_top_level_or(pattern: str) -> List[str]:
    """Split a regex pattern on top-level | (not inside groups).

    Handles escaped characters: \\( and \\[ do NOT increase nesting depth.
    """
    parts = []
    depth = 0
    current = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        # Skip escaped characters (they don't affect group depth)
        if ch == '\\' and i + 1 < len(pattern):
            current.append(ch)
            current.append(pattern[i + 1])
            i += 2
            continue
        if ch in '([':
            depth += 1
            current.append(ch)
        elif ch in ')]':
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == '|' and depth == 0:
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        parts.append(''.join(current))
    return parts


def _is_unanchored_broad(pattern: str) -> bool:
    """Return True if pattern is very short or has no anchoring structure."""
    # Strip common regex flags prefix like (?i)
    clean = re.sub(r'^\(\?[a-zA-Z]+\)', '', pattern).strip()
    # Strip start/end anchors
    clean2 = clean.lstrip('^').rstrip('$').strip()
    # Length check (very short = broad)
    if len(clean2) <= BROAD_REGEX_MAX_LEN:
        return True
    # Check for any anchoring indicator
    for indicator in ANCHORING_INDICATORS:
        if re.search(indicator, clean2):
            return False
    # No anchoring found and not short - but only flag if genuinely generic
    # (no letters at all, or all-wildcard)
    non_meta = re.sub(r'[\\().*+?^${}\[\]|]', '', clean2)
    non_meta = re.sub(r'\s+', '', non_meta)
    if len(non_meta) <= 3:
        return True
    return False


# ---------------------------------------------------------------------------
# Lint rule implementations
# ---------------------------------------------------------------------------

LintFlag = Dict[str, Any]


def lint_pure_or_with_benign_alternative(name: str, pattern: str,
                                          source_file: str, detector_type: str) -> Optional[LintFlag]:
    """Flag: pure OR regex where a benign token fires as a standalone alternative."""
    # Only relevant if there is a top-level |
    if '|' not in pattern:
        return None

    # Strip (?i) flag prefix
    clean_pattern = re.sub(r'^\(\?[a-zA-Z]+\)', '', pattern).strip()

    parts = _split_top_level_or(clean_pattern)
    if len(parts) < 2:
        return None

    benign_found = []
    for part in parts:
        part = part.strip()
        if _is_benign_token(part):
            benign_found.append(part)

    if not benign_found:
        return None

    # Key insight: even if there are strong discriminating terms in OTHER branches
    # of the OR, a benign alternative CAN fire entirely on its own.
    # In a grep/rg OR match, ANY branch matching is sufficient to trigger the detector.
    # So a file with only _msgSender() will fire the erc-2771 detector even if
    # 'trustedForwarder' and 'ERC2771' are other branches.
    # => We always flag when a benign-common token is a standalone OR alternative,
    #    UNLESS all benign alternatives are clearly just aliases for the same concept
    #    (e.g., selfdestruct|suicide where both are clearly the same bad thing).
    #
    # Exception: if there are strong co-occurring AND terms (not OR), the benign
    # term is scoped. But in a pure-OR detector there is no AND scoping.
    # We DO allow the selfdestruct|suicide case because both terms are the same
    # semantic concept and neither is benign in context (they just cover the alias).
    all_benign = all(_is_benign_token(p.strip()) for p in parts)
    if all_benign:
        # All alternatives are benign - definitely flag
        pass
    else:
        # Some strong terms exist. Only pass if NONE of the benign alternatives
        # are common OZ/stdlib helpers that fire on totally normal code.
        # We distinguish: "dangerous-but-specific" benign (selfdestruct) vs
        # "completely-ubiquitous" benign (_msgSender, msg.sender, etc.)
        ubiquitous_benign_patterns = [
            r'_msgSender\s*\(',
            r'msg\.sender',
            r'msg\.value',
            r'block\.timestamp',
            r'\.call\b',
            r'\.call\s*\(',
            r'\bcall\b',
            r'\brequire\b',
            r'\btransfer\b',
            r'\btransferFrom\b',
            r'\bapprove\b',
            r'address\(this\)',
            r'\bassembly\b',
        ]
        ubiquitous_found = []
        for bf in benign_found:
            for ub in ubiquitous_benign_patterns:
                try:
                    if re.fullmatch(ub, bf.strip()):
                        ubiquitous_found.append(bf)
                        break
                except re.error:
                    pass
            else:
                # Also check clean literal match
                bf_clean = re.sub(r'[\\s*\\b()]', '', bf).strip().lower()
                for ub in ubiquitous_benign_patterns:
                    ub_clean = re.sub(r'[\\().*+?^${}\[\]|\\s*\\b]', '', ub).strip().lower()
                    if bf_clean == ub_clean or ub_clean in bf_clean:
                        ubiquitous_found.append(bf)
                        break

        if not ubiquitous_found:
            # Benign tokens are "dangerous-but-specific" (e.g., selfdestruct)
            # with strong co-terms. Let the tool pass.
            return None

    offending = ', '.join(f'`{b}`' for b in benign_found)
    suggestion = (
        f"Narrow the pattern: remove `{benign_found[0]}` as a standalone OR alternative, "
        f"or add a discriminating precondition that must co-occur (e.g., require an adjacent "
        f"ERC-specific inheritance keyword in the same file)."
    )
    return {
        "rule": "pure_or_with_benign_alternative",
        "detector": name,
        "file": source_file,
        "detector_type": detector_type,
        "offending": offending,
        "pattern_snippet": pattern[:120],
        "suggestion": suggestion,
    }


def lint_symptom_token_no_precondition(name: str, pattern: str,
                                        source_file: str, detector_type: str,
                                        has_precondition: bool,
                                        has_additional_match: bool) -> Optional[LintFlag]:
    """Flag: detector matches a symptom token with no precondition and no additional match context."""
    if has_precondition or has_additional_match:
        return None

    clean_pattern = re.sub(r'^\(\?[a-zA-Z]+\)', '', pattern).strip()

    for token in SYMPTOM_TOKENS:
        # Token must appear as the ENTIRE match or be a top-level OR alternative
        parts = _split_top_level_or(clean_pattern)
        for part in parts:
            part_clean = re.sub(r'[\\s*\\b]', '', part).strip().replace(r'\s*\(', '(')
            if token.replace('\\', '') in part_clean or part_clean.rstrip(r'\s*\(').endswith(token.split('.')[-1]):
                # Check if the overall pattern is generic (not heavily qualified)
                if '\\s+' not in clean_pattern and 'function\\s' not in clean_pattern:
                    suggestion = (
                        f"Add a `preconditions` block (DSL) or a more specific regex "
                        f"co-occurrence pattern alongside `{token}` to reduce FPs "
                        f"(e.g., require a companion call, a specific contract import, or "
                        f"a function-name qualifier)."
                    )
                    return {
                        "rule": "symptom_token_no_precondition",
                        "detector": name,
                        "file": source_file,
                        "detector_type": detector_type,
                        "offending": f"`{token}` with no scoping precondition",
                        "pattern_snippet": pattern[:120],
                        "suggestion": suggestion,
                    }
    return None


def lint_unanchored_broad_regex(name: str, pattern: str,
                                  source_file: str, detector_type: str) -> Optional[LintFlag]:
    """Flag: pattern is very short/generic and has no anchoring structure."""
    if not _is_unanchored_broad(pattern):
        return None

    suggestion = (
        f"Pattern `{pattern[:60]}` is too short or unanchored. Add structural anchors "
        f"(e.g., `function\\s+`, `\\bcontract\\b`, specific parameter/return type patterns, "
        f"or a multi-term AND-style sequence) to reduce FP rate."
    )
    return {
        "rule": "unanchored_broad_regex",
        "detector": name,
        "file": source_file,
        "detector_type": detector_type,
        "offending": f"pattern length={len(pattern)}, no anchors",
        "pattern_snippet": pattern[:120],
        "suggestion": suggestion,
    }


# ---------------------------------------------------------------------------
# Parser: apply-queries.sh (bash check_pattern calls)
# ---------------------------------------------------------------------------

# Matches: check_pattern "name" "category" 'pattern'
_BASH_DETECTOR_RE = re.compile(
    r'check_pattern\s+"([^"]+)"\s+"([^"]+)"\s+\'([^\']+)\'',
    re.MULTILINE,
)


def _is_review_tier_bash(name: str, line_text: str) -> bool:
    """Return True if this bash detector is explicitly or implicitly review-tier.

    Convention:
      - Explicit: line contains `# detector-tier: review-grep` annotation.
      - Implicit: ALL bash grep detectors in apply-queries.sh are review-tier by
        default (their hits land LOW in engage_report.md behind a human-review
        gate and never auto-promote to exploit-queue rows).

    The implicit rule can be overridden per-detector with:
      `# detector-tier: finding-generator`
    to mark a bash detector as precision-required (unusual; document the reason).
    """
    if "detector-tier: finding-generator" in line_text:
        return False
    # Explicit review-grep annotation OR implicit default for all bash detectors
    return True


def parse_bash_detectors(script_path: str) -> List[Dict[str, Any]]:
    """Extract (name, category, pattern) triples from apply-queries.sh.

    All bash grep detectors are tagged `detector_tier: review-grep` by default
    (implicit rule; see module docstring AND-clause / detector tier section).
    They feed human-reviewed LOW-severity clusters in engage_report.md and are
    never auto-promoted. The lint flags them at `advisory` level only.
    """
    text = Path(script_path).read_text()
    results = []
    # Match line-by-line so we can inspect per-line annotations
    for m in _BASH_DETECTOR_RE.finditer(text):
        # Find the line containing this match for annotation inspection
        start = text.rfind('\n', 0, m.start()) + 1
        end = text.find('\n', m.end())
        line_text = text[start:end if end != -1 else len(text)]
        results.append({
            "name": m.group(1),
            "category": m.group(2),
            "pattern": m.group(3),
            "has_precondition": False,   # bash detectors have no precondition field
            "has_additional_match": False,
            "source_file": script_path,
            "detector_type": "bash_grep",
            "detector_tier": "review-grep" if _is_review_tier_bash(m.group(1), line_text) else "finding-generator",
        })
    return results


# ---------------------------------------------------------------------------
# Parser: YAML DSL detectors
# ---------------------------------------------------------------------------

def _try_import_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def _dsl_has_discriminating_clause(match_clauses: list, preconditions: list) -> bool:
    """Return True if the DSL match+preconditions block has at least one discriminating clause.

    A discriminating clause is one that narrows the firing condition sufficiently
    to prevent over-broad firing on the full corpus.  When ANY discriminating
    clause is present, individual broad regex clauses within the same match block
    are NOT flagged - the AND-composition already scopes the detector.

    Discriminating clause types:
      - function.name_matches / function.name_matches_regex with a non-trivial
        pattern (not `.*`, not `.`).
      - function.kind (restricts to external_or_public / internal / etc.).
      - A real precondition: contract.source_matches_regex or
        contract.has_state_var_matching etc. whose value is not `.*` / `.`.
      - 3+ total match clauses (specificity by conjunction depth).
    """
    # 3+ match clauses => discriminating by conjunction depth
    if len(match_clauses) >= 3:
        return True

    # Check each match clause for a name_matches or kind key
    for clause in match_clauses:
        if not isinstance(clause, dict):
            continue
        for key, val in clause.items():
            key_lower = key.lower()
            # name_matches / name_matches_regex with a non-trivial value
            if "name_matches" in key_lower:
                if isinstance(val, str) and val not in (".*", ".", ""):
                    return True
            # function.kind always discriminates (restricts to a call category)
            if key_lower in ("function.kind", "kind"):
                return True
            # has_paired_function, has_high_level_call_named, not_leaf_helper, etc.
            # - boolean structural keys that act as discriminators
            if any(disc in key_lower for disc in (
                "has_paired_function", "has_high_level_call_named", "not_leaf_helper",
                "has_modifier", "not_in_skip_list",
            )):
                return True

    # Check preconditions: any non-trivial precondition discriminates
    for pre in preconditions:
        if isinstance(pre, dict):
            for k, v in pre.items():
                if isinstance(v, str) and v not in (".*", ".*.*", ".", ""):
                    return True
                if isinstance(v, bool):
                    return True   # boolean precondition is always discriminating

    return False


def _dsl_all_regex_clauses_broadly_fired(match_clauses: list) -> bool:
    """Return True if ALL regex clauses in the match block are broad (no discriminating regex).

    Used as a secondary gate after _dsl_has_discriminating_clause returns False.
    When called, we know there are no structural discriminating clauses.
    We then check whether the regex values themselves provide any scoping.
    """
    regex_vals = []
    for clause in match_clauses:
        if not isinstance(clause, dict):
            continue
        for key, val in clause.items():
            if "regex" in key.lower() and isinstance(val, str):
                regex_vals.append(val)

    if not regex_vals:
        return False   # no regex at all, not a regex-broadness issue

    for rv in regex_vals:
        # A regex that is non-trivial (not just .* or . or empty) provides scoping
        clean = rv.strip()
        if clean not in (".*", ".", "", ".*.*"):
            # Further check: is it longer than 5 non-meta chars?
            non_meta = re.sub(r'[\\().*+?^${}\[\]|]', '', clean)
            non_meta = re.sub(r'\s+', '', non_meta)
            if len(non_meta) >= 5:
                return False   # this regex IS discriminating
    return True   # all regex clauses are trivially broad


def parse_dsl_detectors(dsl_dirs: List[str]) -> List[Dict[str, Any]]:
    """Extract detector definitions from YAML DSL files.

    AND-clause awareness (wave-17 fix):
      A DSL `match` block is a logical AND.  A broad regex on one clause is
      only a genuine FP risk when the ENTIRE match+preconditions block lacks
      any discriminating clause (see _dsl_has_discriminating_clause).
      When a discriminating clause exists, individual broad regex clauses are
      NOT emitted for lint evaluation - the detector is emitted as a single
      holistic record with `and_clause_scoped=True` and both
      `has_precondition=True` and `has_additional_match=True` set, which
      suppresses all three lint rules for that detector.
    """
    yaml = _try_import_yaml()
    if yaml is None:
        print("[WARN] PyYAML not available; skipping DSL detector scan.", file=sys.stderr)
        return []

    results = []
    for dsl_dir in dsl_dirs:
        p = Path(dsl_dir)
        if not p.is_dir():
            continue
        for yaml_file in sorted(p.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text())
                if not isinstance(data, dict):
                    continue

                name = data.get("pattern", yaml_file.stem)
                preconditions = data.get("preconditions", [])
                match_clauses = data.get("match", [])

                # Has a meaningful precondition (not just contract.source_matches_regex: '.*')
                has_real_precondition = False
                for pre in preconditions:
                    if isinstance(pre, dict):
                        val = list(pre.values())[0] if pre else ""
                        if val and val not in (".*", ".*.*", ""):
                            has_real_precondition = True
                            break

                # Has additional match clauses beyond pure regex body match
                has_additional_match = len(match_clauses) > 1

                # AND-clause awareness: check whether the whole block is discriminating
                and_clause_scoped = _dsl_has_discriminating_clause(match_clauses, preconditions)

                if and_clause_scoped:
                    # The block has at least one discriminating clause.
                    # Emit a single holistic record that suppresses all lint rules.
                    # This is the correct behaviour: a broad regex inside a well-scoped
                    # multi-clause AND block is NOT a genuine FP risk.
                    results.append({
                        "name": name,
                        "category": "dsl",
                        "pattern": "(and-clause-scoped: holistic match block is discriminating)",
                        "has_precondition": True,     # suppresses symptom_token rule
                        "has_additional_match": True,  # suppresses symptom_token rule
                        "source_file": str(yaml_file),
                        "detector_type": "dsl_yaml",
                        "and_clause_scoped": True,
                        "detector_tier": "finding-generator",
                    })
                    continue

                # Block is not discriminating by structure - emit per-regex-clause
                # so the rules can evaluate individual regex values.
                for clause in match_clauses:
                    if not isinstance(clause, dict):
                        continue
                    for key, val in clause.items():
                        if "regex" in key.lower() and isinstance(val, str):
                            results.append({
                                "name": name,
                                "category": "dsl",
                                "pattern": val,
                                "has_precondition": has_real_precondition,
                                "has_additional_match": has_additional_match,
                                "source_file": str(yaml_file),
                                "detector_type": "dsl_yaml",
                                "match_key": key,
                                "and_clause_scoped": False,
                                "detector_tier": "finding-generator",
                            })

            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_lint(detectors: List[Dict[str, Any]]) -> List[LintFlag]:
    """Run all lint rules over the detector list.

    Severity assignment:
      - review-tier detectors (detector_tier="review-grep") receive severity
        "advisory" on any flag.  Advisory flags are informational only and do
        NOT trigger --strict exit-1.
      - finding-generator detectors (DSL YAML) receive severity "fp_risk" on
        flags.  fp_risk flags DO trigger --strict exit-1.
      - and_clause_scoped=True detectors are holistic placeholders; they carry
        has_precondition=True and has_additional_match=True which already
        suppresses all three lint rules - the loop effectively skips them.
    """
    flags: List[LintFlag] = []
    seen: set = set()  # deduplicate on (detector, rule)

    for det in detectors:
        name = det["name"]
        pattern = det["pattern"]
        src = det["source_file"]
        dtype = det["detector_type"]
        has_pre = det.get("has_precondition", False)
        has_extra = det.get("has_additional_match", False)
        detector_tier = det.get("detector_tier", "finding-generator")

        # and_clause_scoped holistic records have has_precondition=True which
        # suppresses symptom_token, and pattern="(and-clause-scoped...)" which
        # won't match any lint rule.  They pass through cleanly without special-casing.

        candidates = [
            lint_pure_or_with_benign_alternative(name, pattern, src, dtype),
            lint_symptom_token_no_precondition(name, pattern, src, dtype, has_pre, has_extra),
            lint_unanchored_broad_regex(name, pattern, src, dtype),
        ]

        for flag in candidates:
            if flag is None:
                continue
            dedup_key = (flag["detector"], flag["rule"], flag["file"])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            # Assign severity based on detector tier
            flag["severity"] = "advisory" if detector_tier == "review-grep" else "fp_risk"
            flag["detector_tier"] = detector_tier
            flags.append(flag)

    return flags


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_human(flags: List[LintFlag]) -> str:
    fp_risk_flags = [f for f in flags if f.get("severity") != "advisory"]
    advisory_flags = [f for f in flags if f.get("severity") == "advisory"]
    if not flags:
        return "detector-fp-shape-lint: CLEAN (0 flags)\n"
    lines = [
        f"detector-fp-shape-lint: {len(fp_risk_flags)} fp_risk flag(s), "
        f"{len(advisory_flags)} advisory flag(s)\n"
    ]
    if fp_risk_flags:
        lines.append("  === fp_risk flags (actionable - tightening required) ===")
        for i, f in enumerate(fp_risk_flags, 1):
            lines.append(f"  [{i}] rule={f['rule']} severity=fp_risk")
            lines.append(f"      detector : {f['detector']}")
            lines.append(f"      file     : {f['file']}")
            lines.append(f"      offending: {f['offending']}")
            lines.append(f"      pattern  : {f['pattern_snippet']}")
            lines.append(f"      fix      : {f['suggestion']}")
            lines.append("")
    if advisory_flags:
        lines.append("  === advisory flags (review-tier: intentionally broad, not actionable) ===")
        for i, f in enumerate(advisory_flags, 1):
            lines.append(f"  [{i}] rule={f['rule']} severity=advisory tier={f.get('detector_tier','?')}")
            lines.append(f"      detector : {f['detector']}")
            lines.append(f"      file     : {f['file']}")
            lines.append(f"      offending: {f['offending']}")
            lines.append(f"      pattern  : {f['pattern_snippet']}")
            lines.append("")
    return "\n".join(lines)


def format_json(flags: List[LintFlag], detectors: List[Dict[str, Any]]) -> str:
    fp_risk_flags = [f for f in flags if f.get("severity") != "advisory"]
    advisory_flags = [f for f in flags if f.get("severity") == "advisory"]
    out = {
        "schema": "auditooor.detector_fp_shape_lint.v1",
        "total_detectors_scanned": len(detectors),
        "total_flags": len(flags),
        "total_fp_risk_flags": len(fp_risk_flags),
        "total_advisory_flags": len(advisory_flags),
        "flags": flags,
    }
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Lint detector definitions for over-broad FP shapes."
    )
    parser.add_argument(
        "--dir", default=".",
        help="Root of the auditooor-mcp repo (default: current dir)"
    )
    parser.add_argument(
        "--file", default=None,
        help="Scan a specific apply-queries.sh file instead of auto-discover"
    )
    parser.add_argument(
        "--dsl-dirs", default=None,
        help="Comma-separated list of DSL pattern directories (default: auto)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit JSON output (schema auditooor.detector_fp_shape_lint.v1)"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero if any flags found"
    )
    parser.add_argument(
        "--no-bash", action="store_true",
        help="Skip bash apply-queries.sh scan"
    )
    parser.add_argument(
        "--no-dsl", action="store_true",
        help="Skip DSL YAML scan"
    )
    args = parser.parse_args()

    repo_root = Path(args.dir).resolve()
    detectors: List[Dict[str, Any]] = []

    # --- Bash detector scan ---
    if not args.no_bash:
        if args.file:
            bash_path = args.file
        else:
            bash_path = str(repo_root / "tools" / "apply-queries.sh")
        if os.path.exists(bash_path):
            detectors.extend(parse_bash_detectors(bash_path))
        else:
            if not getattr(args, "json"):
                print(f"[WARN] apply-queries.sh not found at {bash_path}", file=sys.stderr)

    # --- DSL detector scan ---
    if not args.no_dsl:
        if args.dsl_dirs:
            dsl_dirs = [d.strip() for d in args.dsl_dirs.split(",")]
        else:
            ref = repo_root / "reference"
            dsl_dirs = [str(d) for d in sorted(ref.glob("patterns.dsl*"))
                        if d.is_dir() and "_quarantine" not in d.name and "_held" not in d.name]
        detectors.extend(parse_dsl_detectors(dsl_dirs))

    flags = run_lint(detectors)

    if args.json:
        print(format_json(flags, detectors))
    else:
        print(format_human(flags))

    if args.strict:
        fp_risk_flags = [f for f in flags if f.get("severity") != "advisory"]
        if fp_risk_flags:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
