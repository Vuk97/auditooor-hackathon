#!/usr/bin/env python3
"""findings-to-pattern.py — V5 Gap-24 / Gap-34.

Background
----------
``reference/patterns.dsl/`` holds ~1,300 detector specs. Verified
2026-04-26 (V5_CAPABILITY_GAPS doc): only 21 patterns cite a
workspace — the vast majority were mined from external corpora
(LISA-Bench, defimon, rekt). Years of in-house audit work
(``findings/*.md`` per workspace) is NOT being cycled back into the
library.

This tool converts a finding spec (a markdown file with structured
fields, OR a set of CLI args) into a *candidate* DSL pattern plus
two empty Solidity fixture scaffolds. The output goes through a
deliberate review gate before it can affect detector compilation:

1. The pattern YAML is written with the suffix ``.yaml.candidate`` so
   ``make compile`` (which globs ``*.yaml``) does NOT pick it up.
2. The two fixture files are written with the suffix ``.sol.todo``
   so the Rust fixture suite does NOT compile them.
3. The candidate cannot enter ``reference/patterns.dsl/`` (i.e.
   the suffix cannot be stripped) until paired vulnerable + clean
   fixtures have been hand-written for the actual bug shape.

Codex's exact spec from the V5 W3 PR-G plan (verbatim):

  "produce candidate YAML plus a checklist, not auto-promote to
  canonical detectors."

  "Every generated candidate must require vulnerable/clean fixtures
  before it can enter reference/patterns.dsl/."

The promotion gate (``--promote``) refuses to strip ``.candidate``
unless both fixtures exist with content. See :func:`promote`.

Input shapes
------------
1. CLI flags:

       findings-to-pattern.py \
         --name oracle-stale-price-no-grace-period \
         --bug-class oracle-staleness \
         --severity HIGH \
         --confidence MEDIUM \
         --citation src/Oracle.sol:42 \
         --description "Price feed used without staleness check"

   The ``--description`` field can also be ``--description-file <path>``.

2. Markdown file (passed positionally):

       findings-to-pattern.py path/to/finding.md

   The markdown is parsed for the following labelled fields (case
   insensitive, colon-terminated, one per line):

       Title:       <free text — slugified into pattern name>
       Bug class:   <token, becomes a tag>
       Severity:    <CRITICAL|HIGH|MEDIUM|LOW|INFO>
       Confidence:  <HIGH|MEDIUM|LOW>
       Citation:    <file:line>      (repeatable)
       Description: <multi-line until next labelled field or EOF>

   The first ``# H1`` heading is used as the title if no ``Title:``
   line is present. CLI args override fields parsed from the
   markdown.

Outputs
-------
For ``--name foo``:

  reference/patterns.dsl/foo.yaml.candidate
  detectors/test_fixtures/foo_vulnerable.sol.todo
  detectors/test_fixtures/foo_clean.sol.todo
  reference/patterns.dsl/foo.checklist.md   (review checklist)

The ``.todo`` fixtures contain explicit ``// TODO:`` markers AND a
``REPLACE THIS SCAFFOLD`` notice; they will fail the foot-gun #2
fixture-comment-leak check if accidentally renamed to ``.sol`` (the
preflight will reject the unprocessed scaffold). This is intentional:
foot-gun #15 pins the rule that fixtures must NEVER use the trigger
words ``// VULN``, ``// BUG``, ``// CLEAN``, ``// missing``.

Hard rules followed
-------------------
- Stdlib only.
- NEVER auto-strip ``.candidate``. The ``--promote`` flow is a
  separate manual step that asserts the fixture pair exists with
  non-trivial content.
- Output is deterministic (sorted YAML field order, deterministic
  fixture skeletons). Running twice produces byte-identical output
  unless ``--force`` is set.
- Refuses to clobber an existing ``*.yaml`` (canonical) by the same
  name — the promotion path of an earlier mining round MUST be
  honored.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import textwrap


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
FIXTURES_DIR = REPO_ROOT / "detectors" / "test_fixtures"

CANDIDATE_SUFFIX = ".yaml.candidate"
FIXTURE_SUFFIX = ".sol.todo"

VALID_SEVERITY = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
VALID_CONFIDENCE = ("HIGH", "MEDIUM", "LOW")
REPORTABLE_PATTERN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}


# ---------------------------------------------------------------------------
# Slugification
# ---------------------------------------------------------------------------

# Pattern names are kebab-case. Source: every existing
# reference/patterns.dsl/*.yaml in the repo.
_NAME_SAFE_RE = re.compile(r"[^a-z0-9-]+")


def slugify(text: str) -> str:
    """Convert a free-form title into a kebab-case pattern name."""
    if not text:
        return ""
    s = text.strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    s = _NAME_SAFE_RE.sub("", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


# ---------------------------------------------------------------------------
# Markdown finding parser
# ---------------------------------------------------------------------------

_FIELD_LINE_RE = re.compile(
    r"^\s*(?P<key>title|bug[\s_-]?class|severity|confidence|citation|description)"
    r"\s*:\s*(?P<value>.*?)\s*$",
    re.IGNORECASE,
)
_H1_RE = re.compile(r"^\s*#\s+(?P<value>.+?)\s*$")


def parse_finding_markdown(md: str) -> dict:
    """Parse a finding markdown into a dict of fields.

    Returns a dict with keys: title, bug_class, severity, confidence,
    citations (list[str]), description. Missing keys are absent (NOT
    None) so the caller can distinguish absence from explicit empty.
    """
    out: dict = {"citations": []}
    if not md:
        return out
    lines = md.splitlines()
    i = 0
    description_buf: list[str] = []
    in_description = False
    while i < len(lines):
        line = lines[i]
        if not in_description:
            m = _FIELD_LINE_RE.match(line)
            if m:
                key = m.group("key").lower().replace(" ", "_").replace("-", "_")
                if key == "bug_class":
                    out["bug_class"] = m.group("value").strip()
                elif key == "title":
                    out["title"] = m.group("value").strip()
                elif key == "severity":
                    out["severity"] = m.group("value").strip().upper()
                elif key == "confidence":
                    out["confidence"] = m.group("value").strip().upper()
                elif key == "citation":
                    cite = m.group("value").strip()
                    if cite:
                        out["citations"].append(cite)
                elif key == "description":
                    in_description = True
                    rest = m.group("value").strip()
                    if rest:
                        description_buf.append(rest)
                i += 1
                continue
            if "title" not in out:
                hm = _H1_RE.match(line)
                if hm:
                    out["title"] = hm.group("value").strip()
        else:
            # Description continues until the next labelled field line.
            if _FIELD_LINE_RE.match(line):
                in_description = False
                continue  # re-process this line as a field
            description_buf.append(line)
        i += 1
    if description_buf:
        # Strip trailing blank lines but keep internal spacing.
        while description_buf and not description_buf[-1].strip():
            description_buf.pop()
        out["description"] = "\n".join(description_buf).rstrip()
    return out


# ---------------------------------------------------------------------------
# YAML emission (stdlib-only, deterministic)
# ---------------------------------------------------------------------------


def _yaml_quote(value: str) -> str:
    """Quote a value for safe YAML emission.

    Wraps in single quotes (escaping internal single quotes by
    doubling), which is the safest stdlib-only path that works for
    every printable ASCII character including ``:`` and ``#``.
    """
    if value is None:
        return "''"
    s = str(value)
    return "'" + s.replace("'", "''") + "'"


def _yaml_block_scalar(value: str, indent: int = 2) -> str:
    """Emit a value as a literal block scalar (``|``).

    Each line is indented by ``indent`` spaces. Trailing newlines are
    normalised to a single one.
    """
    if value is None:
        value = ""
    pad = " " * indent
    body = "\n".join(pad + ln for ln in value.splitlines())
    return body


def _safe_regex_substring(citation: str) -> str:
    """Build a *neutral* anchor regex hint from a file:line citation.

    We deliberately do NOT try to derive an actual positive regex from
    the finding — that's the human's job during fixture authoring.
    The candidate carries a single placeholder regex with a TODO
    marker; the citation is preserved separately as evidence the
    reviewer should consult.
    """
    return citation.split(":", 1)[0].rsplit("/", 1)[-1]


def render_candidate_yaml(spec: dict) -> str:
    """Render a candidate DSL pattern YAML.

    The shape mirrors the canonical files under
    ``reference/patterns.dsl/`` (pattern, source, severity,
    confidence, preconditions, match, fixtures, help, wiki_*) but
    every concrete predicate is a TODO placeholder. The reviewer
    must fill these in before stripping the ``.candidate`` suffix.
    """
    name = spec["name"]
    severity = spec.get("severity", "MEDIUM")
    confidence = spec.get("confidence", "LOW")
    bug_class = spec.get("bug_class") or "TODO-bug-class"
    description = spec.get("description") or ""
    citations = spec.get("citations") or []
    source = spec.get("source") or "in-house-finding-mining"

    cite_block = ""
    if citations:
        cite_block = "\n".join(f"  - {_yaml_quote(c)}" for c in citations)
    else:
        cite_block = "  # TODO: add file:line citations from the finding"

    desc_emit = description if description else "TODO: paste finding description here"
    desc_block = _yaml_block_scalar(desc_emit, indent=2)

    body = textwrap.dedent(
        f"""\
        # CANDIDATE PATTERN — DO NOT PROMOTE WITHOUT FIXTURES.
        # Generated by tools/findings-to-pattern.py.
        # Strip the .candidate suffix only after vulnerable + clean
        # fixtures exist with non-trivial content. See tools/findings-to-pattern.py
        # --promote for the gate. V5-P0-14.

        pattern: {name}
        source: {_yaml_quote(source)}
        severity: {severity}
        confidence: {confidence}
        bug_class: {_yaml_quote(bug_class)}

        # Citations from the original finding (file:line). Kept here
        # as evidence; the reviewer should derive the positive regex
        # from the cited code, not from the finding's prose.
        citations:
        """
    )
    body += cite_block + "\n\n"
    body += "preconditions:\n"
    body += "  # TODO: pin the contract anchor (e.g. only contracts that\n"
    body += "  # touch the relevant interface). Example:\n"
    body += "  # - contract.source_matches_regex: 'TODO-anchor-regex'\n\n"
    body += "# Impact contract posture: detector candidates are impact-neutral\n"
    body += "# until a workspace-specific proof maps a hit to one exact listed\n"
    body += "# program impact sentence.\n"
    body += "impact_contract_required: true\n"
    body += "impact_contract_id: ''\n"
    body += "selected_impact: ''\n"
    body += "submission_posture: NOT_SUBMIT_READY\n"
    body += "submit_status: NOT_SUBMIT_READY\n\n"
    body += "match:\n"
    body += "  - function.kind: any\n"
    body += "  # TODO: replace this placeholder with the actual\n"
    body += "  # positive-regex anchor that fires on the bug shape\n"
    body += "  # cited above. Keep it CONSERVATIVE — false positives\n"
    body += "  # poison the calibration ledger.\n"
    body += "  - function.body_contains_regex:\n"
    body += "      regex: 'TODO-positive-regex'\n"
    body += "  # TODO: add a function.not_source_matches_regex FP-guard\n"
    body += "  # that excludes the documented safe shape.\n\n"
    body += "fixtures:\n"
    body += f"  vuln: detectors/test_fixtures/{name}_vulnerable.sol\n"
    body += f"  clean: detectors/test_fixtures/{name}_clean.sol\n\n"
    body += "help: " + _yaml_quote(f"{bug_class} — see candidate description for the bug shape.") + "\n"
    body += "wiki_title: " + _yaml_quote(spec.get("title") or name) + "\n"
    body += "wiki_description: |\n"
    body += desc_block + "\n"
    body += "wiki_exploit_scenario: |\n"
    body += "  TODO: write a single-paragraph attacker-walkthrough.\n"
    body += "wiki_recommendation: |\n"
    body += "  TODO: write a remediation paragraph.\n"
    return body


# ---------------------------------------------------------------------------
# Fixture scaffolds (TODO, neutral comments — foot-gun #15)
# ---------------------------------------------------------------------------


def render_vulnerable_fixture(name: str) -> str:
    """Return a neutral .sol.todo scaffold for the vulnerable case.

    The scaffold is *intentionally* not a compilable Solidity
    contract — the ``.todo`` suffix prevents the Rust fixture suite
    from picking it up, and the body contains an explicit "REPLACE
    THIS SCAFFOLD" instruction. We avoid the trigger words
    ``// VULN`` / ``// BUG`` / ``// CLEAN`` / ``// missing`` so
    foot-gun #2 (fixture-comment-leak) never sees them in case the
    file is renamed to ``.sol`` before content is added.
    """
    return textwrap.dedent(
        f"""\
        // SPDX-License-Identifier: UNLICENSED
        // SCAFFOLD for pattern: {name}
        // REPLACE THIS SCAFFOLD before stripping the .todo suffix.
        //
        // Authoring requirements:
        //   1. Contract must compile under solc 0.8.x.
        //   2. The vulnerable shape must be visible to the pattern's
        //      positive-regex anchor (see {name}.yaml.candidate).
        //   3. Comments must NOT include the trigger words //·VULN,
        //      //·BUG, //·CLEAN, or //·missing — see foot-gun #2.
        //   4. Keep it minimal: one function, one storage var, one
        //      external call. The smaller the fixture, the cheaper
        //      the regression suite.

        pragma solidity ^0.8.20;

        contract {_to_pascal(name)}_Scaffold_PleaseReplace {{
            // TODO: replace with the minimal vulnerable shape.
        }}
        """
    )


def render_clean_fixture(name: str) -> str:
    """Return a neutral .sol.todo scaffold for the clean (mitigated) case."""
    return textwrap.dedent(
        f"""\
        // SPDX-License-Identifier: UNLICENSED
        // SCAFFOLD for pattern: {name} — mitigated/safe case.
        // REPLACE THIS SCAFFOLD before stripping the .todo suffix.
        //
        // Authoring requirements:
        //   1. Same contract shape as the vulnerable fixture, with
        //      the documented mitigation in place.
        //   2. The pattern must NOT fire on this fixture.
        //   3. Comments must NOT include the trigger words //·VULN,
        //      //·BUG, //·CLEAN, or //·missing — see foot-gun #2.

        pragma solidity ^0.8.20;

        contract {_to_pascal(name)}_SafeScaffold_PleaseReplace {{
            // TODO: replace with the minimal mitigated shape.
        }}
        """
    )


def _to_pascal(name: str) -> str:
    return "".join(p.capitalize() for p in name.split("-") if p) or "Anon"


def render_checklist(spec: dict) -> str:
    """Reviewer checklist accompanying every candidate."""
    name = spec["name"]
    citations = spec.get("citations") or []
    cite_lines = "\n".join(f"  - {c}" for c in citations) if citations else "  - (none provided — fill in before promotion)"
    return textwrap.dedent(
        f"""\
        # Candidate review checklist — {name}

        Generated by `tools/findings-to-pattern.py`. **Do not strip
        the `.candidate` suffix until every box below is checked.**

        ## Provenance
        - [ ] Bug class confirmed: `{spec.get('bug_class', 'TODO')}`
        - [ ] Severity confirmed: `{spec.get('severity', 'TODO')}`
        - [ ] Confidence confirmed: `{spec.get('confidence', 'TODO')}`
        - [ ] Citations re-verified against current source:
        {cite_lines}

        ## Pattern hygiene
        - [ ] Positive regex tightened (no overbroad anchors)
        - [ ] FP-guard regex added (`function.not_source_matches_regex`)
        - [ ] Pattern name does not duplicate any existing pattern (run
              `tools/pattern-taxonomy-cluster.py --json` to inspect)
        - [ ] Description does NOT contain protocol-specific names
              that would prevent multi-protocol firing

        ## Fixtures (BLOCKING — promotion is refused without these)
        - [ ] `detectors/test_fixtures/{name}_vulnerable.sol` exists
              with non-trivial content (≥10 lines of real Solidity)
        - [ ] `detectors/test_fixtures/{name}_clean.sol` exists with
              non-trivial content (≥10 lines of real Solidity)
        - [ ] Neither fixture contains the trigger words `// VULN`,
              `// BUG`, `// CLEAN`, `// missing` (foot-gun #2)
        - [ ] Pattern fires on the vulnerable fixture and does NOT
              fire on the clean fixture (run `make compile` + Rust suite)

        ## Promotion
        Once every box above is checked, run:

            python3 tools/findings-to-pattern.py --promote {name}

        which atomically renames the `.candidate` to `.yaml`, asserts
        both fixture suffixes are now `.sol`, and stages the change.
        """
    )


# ---------------------------------------------------------------------------
# Output gate (write candidate + scaffolds + checklist)
# ---------------------------------------------------------------------------


class GenerateResult:
    """Container returned by :func:`generate` for programmatic use."""

    def __init__(self) -> None:
        self.pattern_path: pathlib.Path | None = None
        self.vuln_path: pathlib.Path | None = None
        self.clean_path: pathlib.Path | None = None
        self.checklist_path: pathlib.Path | None = None
        self.warnings: list[str] = []
        self.skipped: list[str] = []

    def to_dict(self) -> dict:
        return {
            "pattern": str(self.pattern_path) if self.pattern_path else None,
            "vuln_fixture": str(self.vuln_path) if self.vuln_path else None,
            "clean_fixture": str(self.clean_path) if self.clean_path else None,
            "checklist": str(self.checklist_path) if self.checklist_path else None,
            "warnings": self.warnings,
            "skipped": self.skipped,
        }


def generate(
    spec: dict,
    *,
    patterns_dir: pathlib.Path | None = None,
    fixtures_dir: pathlib.Path | None = None,
    force: bool = False,
) -> GenerateResult:
    """Write the candidate YAML + two fixture scaffolds + checklist.

    Returns a :class:`GenerateResult`. Refuses (raises ``ValueError``)
    if a canonical ``*.yaml`` (no ``.candidate`` suffix) by the same
    name already exists in ``patterns_dir`` — that name has already
    been promoted and ``findings-to-pattern.py`` is not authorised
    to overwrite an active pattern.
    """
    patterns_dir = pathlib.Path(patterns_dir) if patterns_dir else PATTERNS_DIR
    fixtures_dir = pathlib.Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR

    name = spec.get("name")
    if not name:
        raise ValueError("spec missing 'name'")
    if not re.match(r"^[a-z0-9][a-z0-9-]+[a-z0-9]$", name):
        raise ValueError(
            f"invalid pattern name {name!r}; must be kebab-case "
            "(lowercase letters/digits/hyphens, no leading/trailing hyphen)"
        )

    severity = spec.get("severity") or "MEDIUM"
    if severity not in VALID_SEVERITY:
        raise ValueError(f"severity {severity!r} not in {VALID_SEVERITY}")
    confidence = spec.get("confidence") or "LOW"
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"confidence {confidence!r} not in {VALID_CONFIDENCE}")

    canonical_yaml = patterns_dir / f"{name}.yaml"
    if canonical_yaml.exists():
        raise ValueError(
            f"refusing to overwrite already-promoted pattern at {canonical_yaml}; "
            "pick a distinct name or delete the canonical file first"
        )

    res = GenerateResult()
    patterns_dir.mkdir(parents=True, exist_ok=True)
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    cand_path = patterns_dir / f"{name}{CANDIDATE_SUFFIX}"
    vuln_path = fixtures_dir / f"{name}_vulnerable{FIXTURE_SUFFIX}"
    clean_path = fixtures_dir / f"{name}_clean{FIXTURE_SUFFIX}"
    checklist_path = patterns_dir / f"{name}.checklist.md"

    for p in (cand_path, vuln_path, clean_path, checklist_path):
        if p.exists() and not force:
            res.skipped.append(str(p))

    if cand_path.exists() and not force:
        res.warnings.append(f"candidate already exists: {cand_path} (use --force to overwrite)")
    else:
        cand_path.write_text(render_candidate_yaml(spec), encoding="utf-8")
        res.pattern_path = cand_path

    if vuln_path.exists() and not force:
        res.warnings.append(f"vuln scaffold already exists: {vuln_path}")
    else:
        vuln_path.write_text(render_vulnerable_fixture(name), encoding="utf-8")
        res.vuln_path = vuln_path

    if clean_path.exists() and not force:
        res.warnings.append(f"clean scaffold already exists: {clean_path}")
    else:
        clean_path.write_text(render_clean_fixture(name), encoding="utf-8")
        res.clean_path = clean_path

    if checklist_path.exists() and not force:
        res.warnings.append(f"checklist already exists: {checklist_path}")
    else:
        checklist_path.write_text(render_checklist(spec), encoding="utf-8")
        res.checklist_path = checklist_path

    return res


# ---------------------------------------------------------------------------
# Promotion gate (BLOCKING — fixtures must exist with non-trivial content)
# ---------------------------------------------------------------------------


MIN_FIXTURE_NONTRIVIAL_LINES = 10
SCAFFOLD_MARKER = "REPLACE THIS SCAFFOLD"


def _is_nontrivial_fixture(path: pathlib.Path) -> tuple[bool, str]:
    """Return (ok, reason) — fixture must exist, have ``.sol`` suffix
    (NOT ``.sol.todo``), have ≥ MIN_FIXTURE_NONTRIVIAL_LINES non-blank
    Solidity-ish lines, and must NOT carry the ``REPLACE THIS
    SCAFFOLD`` marker any more.
    """
    if not path.is_file():
        return False, f"missing: {path}"
    if path.name.endswith(".sol.todo"):
        return False, f"still scaffold (rename .sol.todo → .sol): {path}"
    text = path.read_text(encoding="utf-8", errors="replace")
    if SCAFFOLD_MARKER in text:
        return False, f"scaffold marker still present in {path}; replace it"
    nontrivial = [
        ln for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("//")
    ]
    if len(nontrivial) < MIN_FIXTURE_NONTRIVIAL_LINES:
        return False, (
            f"{path}: only {len(nontrivial)} non-comment lines "
            f"(need >= {MIN_FIXTURE_NONTRIVIAL_LINES})"
        )
    # foot-gun #2: trigger-word scan.
    for trigger in ("// VULN", "// CLEAN", "// BUG", "// missing"):
        if trigger in text:
            return False, (
                f"{path}: contains forbidden trigger comment {trigger!r} "
                "(foot-gun #2)"
            )
    return True, ""


CANDIDATE_TODO_MARKERS = (
    "TODO-positive-regex",
    "TODO-anchor-regex",
    "TODO-bug-class",
    "TODO: paste finding description here",
    "TODO: write a single-paragraph attacker-walkthrough",
    "TODO: write a remediation paragraph",
)


def _top_level_scalar(text: str, key: str) -> str:
    """Return a simple top-level YAML scalar without pulling in PyYAML."""
    pattern = re.compile(rf"(?m)^{re.escape(key)}\s*:\s*(.*?)\s*(?:#.*)?$")
    match = pattern.search(text)
    if not match:
        return ""
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value.strip()


def _candidate_impact_contract_blockers(text: str) -> list[str]:
    """Fail reportable detector promotion unless impact posture is explicit.

    Detector patterns are reusable scanners, not workspace findings. A
    reportable-looking pattern severity can therefore be promoted without a
    workspace-specific impact contract only when the YAML explicitly says the
    detector remains impact-neutral / NOT_SUBMIT_READY.
    """
    severity = _top_level_scalar(text, "severity").upper()
    if severity not in REPORTABLE_PATTERN_SEVERITIES:
        return []
    impact_contract_id = _top_level_scalar(text, "impact_contract_id")
    if impact_contract_id:
        return []
    required = _top_level_scalar(text, "impact_contract_required").lower() == "true"
    selected_impact = _top_level_scalar(text, "selected_impact")
    posture = _top_level_scalar(text, "submission_posture").upper()
    submit_status = _top_level_scalar(text, "submit_status").upper()
    if (
        required
        and not selected_impact
        and posture == "NOT_SUBMIT_READY"
        and submit_status == "NOT_SUBMIT_READY"
    ):
        return []
    return [
        "reportable detector severity requires impact_contract_id or explicit "
        "impact-neutral posture "
        "(impact_contract_required=true, selected_impact='', "
        "submission_posture=NOT_SUBMIT_READY, submit_status=NOT_SUBMIT_READY)"
    ]


def _candidate_has_unresolved_todos(text: str) -> list[str]:
    """Return the list of literal TODO markers still present in the YAML.

    Promotion is refused if any of the placeholder strings emitted by
    :func:`render_candidate_yaml` are still in the file — these are
    the predicate, description, and remediation slots a reviewer must
    fill in. (Kimi pre-review finding for V5 PR-G.)
    """
    return [m for m in CANDIDATE_TODO_MARKERS if m in text]


def promote(
    name: str,
    *,
    patterns_dir: pathlib.Path | None = None,
    fixtures_dir: pathlib.Path | None = None,
) -> tuple[bool, list[str]]:
    """Strip the ``.candidate`` suffix iff fixtures exist with content.

    Returns ``(ok, messages)``. On success the candidate file is
    renamed to ``<name>.yaml`` and the messages list contains a
    single confirmation line. On failure the file is *not* moved
    and the messages describe every blocker.
    """
    patterns_dir = pathlib.Path(patterns_dir) if patterns_dir else PATTERNS_DIR
    fixtures_dir = pathlib.Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR

    cand = patterns_dir / f"{name}{CANDIDATE_SUFFIX}"
    canonical = patterns_dir / f"{name}.yaml"
    vuln = fixtures_dir / f"{name}_vulnerable.sol"
    clean = fixtures_dir / f"{name}_clean.sol"

    blockers: list[str] = []
    if not cand.is_file():
        blockers.append(f"candidate not found: {cand}")
    else:
        # Refuse to promote a candidate that still has TODO placeholders.
        # Without this gate, a reviewer could rename the file and ship
        # a pattern with `regex: 'TODO-positive-regex'` that fires on
        # nothing — appearing to pass tests while doing nothing.
        candidate_text = cand.read_text(encoding="utf-8")
        leftover_todos = _candidate_has_unresolved_todos(candidate_text)
        if leftover_todos:
            blockers.append(
                f"candidate {cand} still contains TODO placeholders: "
                f"{', '.join(leftover_todos)}; replace them first"
            )
        blockers.extend(_candidate_impact_contract_blockers(candidate_text))
    if canonical.is_file():
        blockers.append(
            f"canonical {canonical} already exists; "
            "promotion would clobber an active pattern"
        )
    ok_v, why_v = _is_nontrivial_fixture(vuln)
    if not ok_v:
        blockers.append(why_v)
    ok_c, why_c = _is_nontrivial_fixture(clean)
    if not ok_c:
        blockers.append(why_c)

    if blockers:
        return False, blockers

    cand.rename(canonical)
    return True, [f"promoted: {cand} -> {canonical}"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="findings-to-pattern",
        description=(
            "Convert an audit finding into a CANDIDATE pattern + fixture "
            "scaffolds. Never auto-promotes; promotion requires paired "
            "vulnerable + clean fixtures (V5 Gap-24 / Gap-34)."
        ),
    )
    p.add_argument("finding", nargs="?", help="Path to a finding markdown file")
    p.add_argument("--name", help="Pattern name (kebab-case). Required if no finding markdown.")
    p.add_argument("--bug-class", help="Bug-class tag (e.g. oracle-staleness).")
    p.add_argument("--severity", choices=VALID_SEVERITY, help="Severity.")
    p.add_argument("--confidence", choices=VALID_CONFIDENCE, help="Confidence.")
    p.add_argument(
        "--citation",
        action="append",
        default=None,
        help="file:line citation. Repeatable.",
    )
    p.add_argument("--description", help="Inline description string.")
    p.add_argument("--description-file", help="Read description from file.")
    p.add_argument("--title", help="Free-form title (used to derive name if --name is absent).")
    p.add_argument("--source", help="source label (default: in-house-finding-mining).")
    p.add_argument("--patterns-dir", default=str(PATTERNS_DIR))
    p.add_argument("--fixtures-dir", default=str(FIXTURES_DIR))
    p.add_argument("--force", action="store_true", help="Overwrite existing scaffolds.")
    p.add_argument("--json", action="store_true", help="Emit GenerateResult as JSON to stdout.")
    p.add_argument(
        "--promote",
        metavar="NAME",
        help=(
            "Strip the .candidate suffix for pattern NAME if vuln+clean "
            "fixtures exist with non-trivial content. Refuses otherwise."
        ),
    )
    return p


def _build_spec(args: argparse.Namespace) -> dict:
    """Combine CLI args + parsed markdown into the final spec dict."""
    spec: dict = {}
    if args.finding:
        md = pathlib.Path(args.finding).expanduser().read_text(encoding="utf-8")
        spec.update(parse_finding_markdown(md))
    if args.title:
        spec["title"] = args.title
    if args.bug_class:
        spec["bug_class"] = args.bug_class
    if args.severity:
        spec["severity"] = args.severity
    if args.confidence:
        spec["confidence"] = args.confidence
    if args.citation:
        spec["citations"] = list(args.citation)
    if args.description:
        spec["description"] = args.description
    if args.description_file:
        spec["description"] = pathlib.Path(args.description_file).read_text(encoding="utf-8").rstrip()
    if args.source:
        spec["source"] = args.source

    name = args.name
    if not name:
        title = spec.get("title")
        if title:
            name = slugify(title)
    if not name:
        raise SystemExit(
            "error: cannot derive pattern name. Pass --name or include "
            "a Title: line / # H1 in the finding markdown."
        )
    spec["name"] = name
    return spec


def main(argv: list[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)

    patterns_dir = pathlib.Path(args.patterns_dir).expanduser().resolve()
    fixtures_dir = pathlib.Path(args.fixtures_dir).expanduser().resolve()

    if args.promote:
        ok, msgs = promote(
            args.promote,
            patterns_dir=patterns_dir,
            fixtures_dir=fixtures_dir,
        )
        for m in msgs:
            print(m, file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 2

    spec = _build_spec(args)
    res = generate(
        spec,
        patterns_dir=patterns_dir,
        fixtures_dir=fixtures_dir,
        force=args.force,
    )
    if args.json:
        print(json.dumps(res.to_dict(), indent=2, sort_keys=True))
    else:
        for w in res.warnings:
            print(f"[warn] {w}", file=sys.stderr)
        for s in res.skipped:
            print(f"[skip] {s}", file=sys.stderr)
        if res.pattern_path:
            print(f"candidate -> {res.pattern_path}")
        if res.vuln_path:
            print(f"vuln scaffold -> {res.vuln_path}")
        if res.clean_path:
            print(f"clean scaffold -> {res.clean_path}")
        if res.checklist_path:
            print(f"checklist -> {res.checklist_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
