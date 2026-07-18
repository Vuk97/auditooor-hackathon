#!/usr/bin/env python3
"""false-positive-batch-repair.py — queue builder for wave-14/17 FP detectors.

Reads inventory_smoke_summary.json. For each detector with status="false_positive"
(predicate fires on BOTH the vulnerable AND the clean fixture), build an LLM
task that asks the model to ENCODE THE BUG-CLASS SEMANTICS described in the
audit finding text — NOT to "distinguish the two fixtures".

Why the framing matters (root cause, 2026-05-04 incident, PR #607):
  An earlier version of this prompt asked the LLM to "refine the predicate
  so it still fires on the vulnerable fixture but not on the clean one".
  Phase-B-prime fixture synthesis (`tools/phase-b-prime-fixture-synthesis.py`)
  generates wave-14 FP fixtures from a fixed template where the only
  syntactic diff is a single `require(newVal <= 10000, "cap");` line in the
  clean fixture. Asked to distinguish that pair, the LLM correctly emitted
  the trivial predicate
       function.body_not_contains_regex: "require\\s*\\("
  on 91/91 tasks. That predicate fires on EVERY function in the world that
  has no require() at top of body, regardless of bug class. Smoke passes,
  detector is fake. The 91 fakes were quarantined in PR #607.

  This file is the upstream root-cause fix: rewrite the prompt to ask for
  bug-class semantics, not fixture-shape distinguishing. See
  `docs/PROMPT_REWRITE_FP_REPAIR_2026-05-04.md`. The complementary Layer A
  dispatch-time lint (PR #609 `tools/agent-dispatch-prompt-lint.py`) catches
  fixture-shape phrasings that slip through this rewrite.

Inputs per task:
  - The argument (kebab id) and snake form
  - The current YAML at reference/patterns.dsl/<arg>.yaml when present, else
    detectors/_specs/drafts_audit_text/<arg>.yaml (auto-mined skeleton form)
  - The audit finding text: title, description, exploit scenario, recommendation
    — pulled from the current YAML's wiki_* fields when present, with a
    backstop to the wave14/wave17 detector .py source's WIKI_* constants.
  - The vulnerable Solidity fixture (used for STRUCTURE only; explicitly
    flagged as a synthesized fixed-template stand-in, not the real bug shape)
  - The clean Solidity fixture (same caveat)

Output format follows docs/llm-codegen-format-spec.md (delimiter-based, NOT
JSON-string-encoded — per FN2-bug-lesson). Sections:
  ===BEGIN_REFINED_YAML===
  <full new YAML, conforming to reference/PATTERN_DSL.md>
  ===END_REFINED_YAML===
  ===BEGIN_BUG_CLASS===
  <one sentence describing the bug class, derived from the audit finding>
  ===END_BUG_CLASS===
  ===BEGIN_RATIONALE===
  <one paragraph: which bug-class-encoding predicates you used and why
   they capture the audit-described condition>
  ===END_RATIONALE===
  ===BEGIN_SELF_CHECK===
  <answer the self-check question from the prompt>
  ===END_SELF_CHECK===
  ===BEGIN_METADATA===
  argument: <kebab>
  ===END_METADATA===

Usage:
  python3 tools/false-positive-batch-repair.py \\
    --smoke-summary /private/tmp/auditooor-inventory/inventory_smoke_summary.json \\
    --queue-out /private/tmp/auditooor-inventory/fp_repair_queue.jsonl \\
    --prompts-dir /private/tmp/auditooor-inventory/fp_repair_prompts \\
    --outputs-dir /private/tmp/auditooor-inventory/fp_repair_outputs \\
    [--limit 50]
    [--only-args-file path.txt]   # 5-task validation sample mode

The queue is consumed by tools/overnight-llm-loop.sh in the usual way; the
operator runs it. This script does NOT run the queue.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
DRAFT_DIR = REPO / "detectors" / "_specs" / "drafts_audit_text"
WAVE14_DIR = REPO / "detectors" / "wave14"
WAVE17_DIR = REPO / "detectors" / "wave17"
PATTERN_DSL_DOC = REPO / "reference" / "PATTERN_DSL.md"

MAX_FIXTURE_BYTES = 12_000     # cap each fixture excerpt
MAX_YAML_BYTES = 6_000         # cap current YAML excerpt
MAX_DSL_DOC_BYTES = 6_000      # cap PATTERN_DSL.md excerpt
MAX_AUDIT_TEXT_BYTES = 4_000   # cap each audit-context field


def _read_capped(path: Path, cap: int) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return f"<MISSING: {path}>"
    if len(text) <= cap:
        return text
    return text[:cap] + f"\n\n... [truncated; original {len(text)} bytes]\n"


def _resolve_yaml(arg: str) -> tuple[Path | None, str]:
    """Return (path, schema_label) for the existing YAML.

    schema_label is "dsl" if it lives in reference/patterns.dsl/ (true DSL form),
    else "skeleton" if it's in _specs/drafts_audit_text/ (auto-mined skeleton form).
    """
    dsl_path = DSL_DIR / f"{arg}.yaml"
    if dsl_path.exists():
        return dsl_path, "dsl"
    draft_path = DRAFT_DIR / f"{arg}.yaml"
    if draft_path.exists():
        return draft_path, "skeleton"
    return None, "missing"


def _extract_audit_context(yaml_path: Path | None, snake: str) -> dict:
    """Pull the audit finding's title/description/scenario/recommendation
    from the YAML's wiki_* fields, falling back to the wave14/wave17
    detector .py source's WIKI_* constants if present.

    Returns a dict with keys: title, description, exploit_scenario,
    recommendation, source, found_in. Each text value is capped at
    MAX_AUDIT_TEXT_BYTES.
    """
    ctx = {
        "title": "",
        "description": "",
        "exploit_scenario": "",
        "recommendation": "",
        "source": "",
        "found_in": "<none>",
    }
    if yaml_path is not None and yaml_path.exists():
        try:
            import yaml as _yaml  # type: ignore
            data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            ctx["title"] = str(data.get("wiki_title", "") or data.get("name", "")).strip()
            ctx["description"] = str(data.get("wiki_description", "") or data.get("help", "")).strip()
            ctx["exploit_scenario"] = str(data.get("wiki_exploit_scenario", "")).strip()
            ctx["recommendation"] = str(data.get("wiki_recommendation", "")).strip()
            ctx["source"] = str(data.get("source", "")).strip()
            ctx["found_in"] = str(yaml_path.relative_to(REPO))
        except Exception:
            pass
    # Backstop: scrape WIKI_* / HELP from wave14/wave17 .py if YAML thin.
    if not ctx["description"]:
        for waved in (WAVE14_DIR, WAVE17_DIR):
            py_path = waved / f"{snake}.py"
            if py_path.exists():
                try:
                    src = py_path.read_text(encoding="utf-8", errors="replace")
                    field_keys = [
                        ("title", "WIKI_TITLE"),
                        ("description", "WIKI_DESCRIPTION"),
                        ("exploit_scenario", "WIKI_EXPLOIT_SCENARIO"),
                        ("recommendation", "WIKI_RECOMMENDATION"),
                    ]
                    for field, key in field_keys:
                        if ctx[field]:
                            continue
                        m = re.search(r'%s\s*=\s*"([^"]*)"' % key, src)
                        if m:
                            ctx[field] = m.group(1).strip()
                    if ctx["found_in"] == "<none>":
                        ctx["found_in"] = str(py_path.relative_to(REPO))
                except Exception:
                    pass
                break
    for k in ("title", "description", "exploit_scenario", "recommendation"):
        if len(ctx[k]) > MAX_AUDIT_TEXT_BYTES:
            ctx[k] = ctx[k][:MAX_AUDIT_TEXT_BYTES] + " ... [truncated]"
    return ctx


def _format_audit_context(ctx: dict) -> str:
    """Render the audit context as a readable block."""
    lines: list[str] = []
    src = ctx.get("source", "").strip()
    if src:
        lines.append(f"Source:       {src}")
    if ctx.get("title"):
        lines.append("")
        lines.append(f"Title:        {ctx['title']}")
    if ctx.get("description"):
        lines.append("")
        lines.append("Description:")
        for ln in (ctx["description"].splitlines() or [""]):
            lines.append(f"    {ln}")
    if ctx.get("exploit_scenario"):
        lines.append("")
        lines.append("Exploit scenario:")
        for ln in (ctx["exploit_scenario"].splitlines() or [""]):
            lines.append(f"    {ln}")
    if ctx.get("recommendation"):
        lines.append("")
        lines.append("Recommended fix (from audit):")
        for ln in (ctx["recommendation"].splitlines() or [""]):
            lines.append(f"    {ln}")
    if not lines:
        return ("(no audit-finding text available - fall back on the YAML's "
                "name/argument and infer the bug class from the wave-14 "
                "audit-text drafts directory if possible)")
    return "\n".join(lines)


SUPPORTED_KEYS_WHITELIST = """
ALLOWED PRECONDITION KEYS (preconditions:):
  contract.implements_any_interface, contract.inherits_any,
  contract.inherits_none_of, contract.is_erc20, contract.is_erc721,
  contract.is_erc1155, contract.is_erc4626,
  contract.has_state_var_matching, contract.has_function_matching,
  contract.has_function_body_matching, contract.has_no_function_body_matching,
  contract.has_state_declaration_matching, contract.has_no_state_declaration_matching,
  contract.source_matches_regex, contract.source_not_contains_regex,
  contract.not_source_matches_regex, contract.has_external_call_to,
  contract.has_mapping

ALLOWED FUNCTION-MATCH KEYS (match:):
  function.kind, function.is_payable, function.state_mutability,
  function.is_mutating, function.is_constructor,
  function.not_slither_synthetic, function.not_in_skip_list,
  function.not_leaf_helper, function.name_matches,
  function.has_param_of_type, function.has_param_name_matching,
  function.has_param_mapping, function.has_param_struct_named,
  function.has_external_call, function.external_call_count_gte,
  function.has_high_level_call_named, function.has_low_level_call,
  function.calls_function_matching, function.reaches_external,
  function.has_external_call_without_guard,
  function.post_external_call_mutates_state,
  function.pre_external_call_mutates_state,
  function.post_external_call_writes_gte,
  function.is_self_scoped_mapping_write,
  function.body_contains_regex, function.body_not_contains_regex,
  function.not_body_contains_regex, function.source_matches_regex,
  function.not_source_matches_regex,
  function.contract.source_matches_regex,
  function.contract.not_source_matches_regex,
  function.assembly_block_matches, function.assembly_block_not_matches,
  function.body_has_multi_dynamic_encodepacked,
  function.taints_param_to, function.has_require_mentioning,
  function.computes_keccak, function.emits_event_matching,
  function.reads_msg_sender, function.reads_tx_origin,
  function.reads_block_timestamp, function.reads_block_number,
  function.reads_storage_matching, function.writes_storage_matching,
  function.has_modifier, function.ast, function.not_ast

DO NOT USE any key not in the lists above. Specifically these are NOT
real keys: function.has_require_referencing, function.has_no_function_body_matching,
function.has_function_body_matching. Pattern-compile rejects them.
"""


def _build_prompt(
    arg: str,
    snake: str,
    yaml_text: str,
    yaml_schema: str,
    vuln_text: str,
    clean_text: str,
    pattern_dsl_doc: str,
    audit_ctx: dict,
) -> str:
    # IMPORTANT (root-cause fix, 2026-05-04):
    #
    # The previous prompt asked the LLM to "make this YAML stricter so the
    # predicate fires on vuln but not clean". Wave14/17 fixtures are
    # synthesized from a fixed template (vuln=no-require, clean=has-require),
    # so the LLM correctly distinguished them with
    #     function.body_not_contains_regex: "require\\s*\\("
    # which is a fixture-shape predicate, NOT a bug-class predicate. 91/91
    # newly-emitted YAMLs collapsed to that single trick; quarantined in
    # PR #607.
    #
    # The new prompt below:
    #   1. Treats the audit FINDING TEXT as the primary source of truth.
    #   2. Treats the synthesized fixtures as STAND-IN structure, NOT as
    #      the bug shape. The LLM is explicitly warned not to encode the
    #      fixture diff.
    #   3. Lists the regex-trick predicate FIRST in the anti-pattern list.
    #   4. Provides bug-class predicate templates so the LLM has examples
    #      of what GOOD looks like.
    #   5. Adds a self-check: "would this predicate fire on a CORRECT
    #      implementation that happens to share the fixture's surface
    #      shape? If yes, iterate."
    audit_block = _format_audit_context(audit_ctx)
    return textwrap.dedent(f"""\
        # Slither DSL Pattern - Bug-Class Encoding Task

        You are writing a Slither pattern (DSL form) for the bug class
        described in the AUDIT FINDING below. Your job is to encode the
        SEMANTIC condition that makes a function vulnerable. NOT to play
        spot-the-difference between two test fixtures.

        Read these sections in order:

          1. AUDIT FINDING (primary source of truth - what bug to detect).
          2. CRITICAL FRAMING (why fixtures are unreliable here).
          3. BUG-CLASS-ENCODING DIRECTIVE (your real task).
          4. ANTI-PATTERNS (what NOT to emit - lead with the regex trick).
          5. ALLOWED KEYS (the DSL vocabulary you must use).
          6. CURRENT YAML / FIXTURES (reference material - NOT goals).
          7. SELF-CHECK (you must answer this honestly before emitting).
          8. OUTPUT FORMAT (delimited sections, verbatim newlines).
          9. ACCEPTANCE (the wirer-side gates your output must pass).

        ============================================================
        SECTION 1 - AUDIT FINDING (PRIMARY SOURCE OF TRUTH)
        ============================================================

        Argument:    {arg}
        Found in:    {audit_ctx.get("found_in", "<none>")}

        {audit_block}

        ============================================================
        SECTION 2 - CRITICAL FRAMING (read carefully)
        ============================================================

        The fixtures shown later in this prompt are SYNTHESIZED. They were
        generated by `tools/phase-b-prime-fixture-synthesis.py` from a
        fixed template:

            // vulnerable
            function FN(uint256 newVal) external {{
                balance = newVal;
            }}

            // clean
            function FN(uint256 newVal) external {{
                require(newVal <= 10000, "cap");
                balance = newVal;
            }}

        The ONLY syntactic difference between the two fixtures is a single
        `require(newVal <= 10000, "cap");` line. THIS DIFFERENCE IS NOT
        THE BUG. The fixtures are structural stand-ins so smoke-tests can
        execute the detector at all. The actual bug class is described in
        the audit finding above.

        On 2026-05-04 (PR #607), 91 detectors collapsed to the predicate

            function.body_not_contains_regex: "require\\\\s*\\\\("

        because that is the obvious diff between the two fixtures. That
        predicate fires on EVERY function in the world that has no
        `require(` token at top of body - regardless of bug class. It is
        a fake detector. Smoke passed; production utility was zero.

        Your task is to NOT do that. See SECTION 4.

        ============================================================
        SECTION 3 - BUG-CLASS-ENCODING DIRECTIVE
        ============================================================

        From the audit finding above, identify the bug class in ONE
        sentence. Examples of good bug-class statements:

          - "external call followed by state mutation with no
             reentrancy guard"
          - "storage write that is not preceded by a sender authorization
             check"
          - "signature verification that does not include a nonce or
             chainId in the digest"
          - "ERC20 transferFrom return value not checked"
          - "use of tx.origin for authorization"
          - "loop bound is user-controlled and unbounded"

        Now encode that one-sentence statement as a CONJUNCTION of DSL
        predicates from the allowed-keys list. The predicate must:

          (a) Capture the SEMANTIC shape of the bug. If the bug class is
              "missing reentrancy guard around an external call that
              precedes a state write", your match block should look
              roughly like:

                  match:
                    - function.kind: external_or_public
                    - function.has_external_call: true
                    - function.post_external_call_mutates_state: true
                    - function.has_modifier:
                        includes: [nonReentrant]
                        negate: true
                    - function.not_in_skip_list: true
                    - function.not_slither_synthetic: true

              (Pick the keys that match YOUR audit finding - those are
              illustrative, not a copy-paste template.)

          (b) Reference the audit's recommended fix as the "negative"
              side of the predicate. If the recommendation is "add a
              nonce check", encode "function does NOT include the nonce
              check". If the recommendation is "use safe math", encode
              "function performs unchecked arithmetic".

          (c) NOT rely on a single body-regex predicate as the sole
              semantic signal (see SECTION 4).

        Bug-class predicate menu (combine 2+ of these per detector):

          missing-reentrancy-guard:
            function.has_external_call: true
            function.post_external_call_mutates_state: true
            function.has_modifier: {{includes: [nonReentrant], negate: true}}

          missing-authorization-check (ownership/role):
            function.is_mutating: true
            function.has_modifier: {{includes: [onlyOwner, onlyRole, onlyAdmin], negate: true}}
            function.body_not_contains_regex: "msg\\\\.sender\\\\s*=="

          tx-origin-auth:
            function.reads_tx_origin: true

          unchecked-low-level-call:
            function.has_low_level_call: {{op: call}}
            function.body_not_contains_regex: "(?:bool\\\\s+\\\\w+\\\\s*=|require\\\\s*\\\\()"

          unsafe-erc20-call:
            function.has_high_level_call_named: "(?:transfer|transferFrom|approve)"
            function.body_not_contains_regex: "SafeERC20"

          unbounded-loop:
            function.body_contains_regex: "for\\\\s*\\\\("
            function.body_not_contains_regex: "(?:i\\\\s*<\\\\s*\\\\d+|MAX|LIMIT)"

          signature-replay (nonce/chainId-related):
            function.computes_keccak: true
            function.body_not_contains_regex: "(?:nonce|chainId|block\\\\.chainid)"

        These are STARTERS. Pick the predicates that fit YOUR audit finding.
        If your audit doesn't fit any of the templates above, write your
        own conjunction. The shape is: {{positive bug-class signal}} AND
        {{negative absence-of-recommended-fix signal}}.

        It is BETTER to emit a slightly-too-narrow bug-class predicate
        that misses the synthesized fixture than to emit a fixture-shape
        predicate that "passes smoke" but encodes nothing real. If the
        synthesized fixture cannot exercise the real bug class
        (because the synthesis is too crude), say so in your
        BUG_CLASS section and choose the bug-class predicate anyway -
        the diversity-check guard (PR #607/#608) will accept variety
        even when individual cohorts smoke-fail. Honest accounting wins
        over fake passes; M14-trap discipline applies.

        ============================================================
        SECTION 4 - ANTI-PATTERNS (do NOT emit any of these)
        ============================================================

        4.1 [LEAD ANTI-PATTERN - the 91-task incident]

            DO NOT use as a SOLE semantic signal:

                - function.body_not_contains_regex: "require\\\\s*\\\\("

            Reason: this fires on every function without a require()
            statement, regardless of bug class. It is the regex trick
            that produced 91 fake YAMLs in the previous wave. If the
            ONLY semantic predicate in your match block is a body-regex
            for `require\\\\s*\\\\(`, your output is rejected.

        4.2 Variants of the same trick - also forbidden as a sole signal:

                - function.body_not_contains_regex: "require\\\\s*\\\\(.*newVal"
                - function.not_body_contains_regex: "require"
                - function.source_not_contains_regex: "require"
                - function.has_require_mentioning:
                    regex: ".*"
                    negate: true

            All of these are "function lacks a require()" framed
            differently. They are still fixture-shape predicates.

            (You MAY combine `body_not_contains_regex: "require\\\\s*\\\\("` with
             OTHER bug-class predicates if the audit's recommended fix is
             specifically "add a require check on parameter X" - but the
             other bug-class predicate must do the real work.)

        4.3 Hallucinated key names - pattern-compile rejects these:

                - function.has_require_referencing:    # NOT a real key
                    regex: "newVal"
                    negate: true
                - function.has_no_function_body_matching: "..."  # NOT real
                - function.has_function_body_matching: "..."     # NOT real

            Use only keys from SECTION 5.

        4.4 Function-name-only matches:

            DO NOT use `function.name_matches` as the only semantic
            signal. Function name is SCOPE; bug-class is SEMANTICS.
            Both are needed; only-scope is not enough.

        ============================================================
        SECTION 5 - ALLOWED PREDICATE KEYS (HARD WHITELIST)
        ============================================================
        {SUPPORTED_KEYS_WHITELIST}

        ============================================================
        SECTION 6 - CURRENT YAML AND FIXTURES (reference only)
        ============================================================

        Current YAML ({yaml_schema}) - REPLACE its `match:` block with a
        bug-class-encoding match block; preserve everything else
        (pattern, name, source, severity, confidence, wiki_*, fixtures):

        --- begin current yaml ---
        {yaml_text}
        --- end current yaml ---

        Vulnerable fixture (SYNTHESIZED stand-in - STRUCTURE ONLY):

        --- begin vulnerable fixture ---
        {vuln_text}
        --- end vulnerable fixture ---

        Clean fixture (SYNTHESIZED stand-in - STRUCTURE ONLY):

        --- begin clean fixture ---
        {clean_text}
        --- end clean fixture ---

        Fixtures block to use in your output (do not change paths):

            fixtures:
              vuln: detectors/test_fixtures/{snake}_vulnerable.sol
              clean: detectors/test_fixtures/{snake}_clean.sol

        ============================================================
        SECTION 7 - SELF-CHECK (you MUST answer in BEGIN_SELF_CHECK)
        ============================================================

        Before emitting, ask yourself:

          Q1. State the bug class in one sentence (from the audit
              finding, not from the fixture diff).

          Q2. List each predicate in your match block and explain WHY
              the audit finding implies it.

          Q3. Imagine a CORRECT, production-quality implementation of
              the same audit finding's recommended fix that DOES NOT
              happen to contain a `require(` at top of body (e.g. it
              uses a `if (...) revert ErrorName();` pattern, or it uses
              a modifier, or it uses `assert`). Would my predicate
              fire on that correct implementation?
                - If YES, my predicate is fixture-shape, not bug-class.
                  Iterate before emitting.
                - If NO, my predicate is bug-class. Proceed.

          Q4. Imagine a vulnerable function that DOES contain
              `require(some_unrelated_thing)` - e.g. an unrelated
              precondition check - but is still vulnerable to the
              audited bug. Would my predicate miss it?
                - If YES and the bug class genuinely allows that
                  shape, my predicate is too narrow on the require
                  axis specifically. Re-encode with bug-class
                  predicates instead of require-presence.

          Q5. If I would default to `function.body_not_contains_regex`
              for every detector, am I gaming the smoke test? Yes.
              Use the bug-class semantic predicates: `<storage-write>
              AND NOT <prior-validation>`, `<external-call> AND NOT
              <reentrancy-guard>`, etc.

        ============================================================
        SECTION 8 - OUTPUT FORMAT (STRICT)
        ============================================================

        Emit FIVE sections in this exact order, with REAL newlines and
        ZERO escapes/markdown fences inside each section.

        ===BEGIN_REFINED_YAML===
        <full new YAML, conforming to reference/PATTERN_DSL.md, with
         a bug-class-encoding match block>
        ===END_REFINED_YAML===
        ===BEGIN_BUG_CLASS===
        <one sentence describing the bug class extracted from the
         audit finding>
        ===END_BUG_CLASS===
        ===BEGIN_RATIONALE===
        <one paragraph: which whitelist keys you used, why each maps
         to the audit finding, and how the conjunction encodes the bug
         class>
        ===END_RATIONALE===
        ===BEGIN_SELF_CHECK===
        <answer Q1-Q5 from SECTION 7, in order, briefly>
        ===END_SELF_CHECK===
        ===BEGIN_METADATA===
        argument: {arg}
        ===END_METADATA===

        ============================================================
        SECTION 9 - ACCEPTANCE
        ============================================================

        ## Acceptance

        Your output is accepted iff:

          A1. Pattern-compile succeeds with --strict-unsupported-keys
              (no hallucinated keys; everything from SECTION 5).
          A2. The match block contains AT LEAST ONE non-scope-only
              predicate from SECTION 5 that is NOT a body-regex for
              `require\\\\s*\\\\(` (or close variants in SECTION 4.2).
          A3. The diversity-check guard
              (tools/wirer-output-diversity-check.py) does not flag
              your YAML's predicate cohort as exceeding --max-share.
          A4. Your BUG_CLASS / RATIONALE / SELF_CHECK sections are
              non-empty and non-trivial (they must reference the
              audit finding's specific semantics, not the fixture
              diff).

        If you emit the regex trick, you fail A2 and A3. Honest
        accounting: prefer a bug-class predicate that smoke-fails over
        a fixture-shape predicate that smoke-passes.
    """)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke-summary", required=True)
    ap.add_argument("--queue-out", required=True)
    ap.add_argument("--prompts-dir", required=True)
    ap.add_argument("--outputs-dir", required=True)
    ap.add_argument("--limit", type=int, default=0,
                    help="cap number of tasks (debug)")
    ap.add_argument("--only-args-file",
                    help="optional file with one argument per line; "
                         "only those args are queued (used for the 5-task "
                         "validation sample)")
    args = ap.parse_args()

    summary = json.loads(Path(args.smoke_summary).read_text(encoding="utf-8"))
    fps = [r for r in summary.get("results", [])
           if r.get("status") == "false_positive"]

    only_args: set[str] | None = None
    if args.only_args_file:
        only_args = set()
        for line in Path(args.only_args_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                only_args.add(line)

    prompts_dir = Path(args.prompts_dir); prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir = Path(args.outputs_dir); outputs_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(args.queue_out); queue_path.parent.mkdir(parents=True, exist_ok=True)

    pattern_dsl_doc = _read_capped(PATTERN_DSL_DOC, MAX_DSL_DOC_BYTES)

    tasks: list[dict] = []
    skipped_no_yaml = 0
    skipped_missing_fixture = 0
    skipped_filtered = 0

    for r in fps:
        arg = r["argument"]
        if only_args is not None and arg not in only_args:
            skipped_filtered += 1
            continue
        snake = arg.replace("-", "_")
        yaml_path, yaml_schema = _resolve_yaml(arg)
        if yaml_path is None:
            skipped_no_yaml += 1
            continue
        vuln_path = REPO / r["vuln_fixture"]
        clean_path = REPO / r["clean_fixture"]
        if not vuln_path.exists() or not clean_path.exists():
            skipped_missing_fixture += 1
            continue

        yaml_text = _read_capped(yaml_path, MAX_YAML_BYTES)
        vuln_text = _read_capped(vuln_path, MAX_FIXTURE_BYTES)
        clean_text = _read_capped(clean_path, MAX_FIXTURE_BYTES)
        audit_ctx = _extract_audit_context(yaml_path, snake)

        prompt = _build_prompt(
            arg=arg,
            snake=snake,
            yaml_text=yaml_text,
            yaml_schema=yaml_schema,
            vuln_text=vuln_text,
            clean_text=clean_text,
            pattern_dsl_doc=pattern_dsl_doc,
            audit_ctx=audit_ctx,
        )

        prompt_path = prompts_dir / f"fp_repair_{snake}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        out_path = outputs_dir / f"fp_repair_{snake}.txt"

        tasks.append({
            "task_id": f"fp-repair-{arg}",
            "provider": "minimax",
            "task_type": "fp-repair-yaml",
            "argument": arg,
            "snake": snake,
            "current_yaml_path": str(yaml_path.relative_to(REPO)),
            "current_yaml_schema": yaml_schema,
            "vuln_fixture": r["vuln_fixture"],
            "clean_fixture": r["clean_fixture"],
            "py_path_original": r["py_path"],
            "wave_original": r["wave"],
            "prompt_path": str(prompt_path),
            "output_path": str(out_path),
            "max_tokens": 6000,
            "audit_context_source": audit_ctx.get("found_in", "<none>"),
        })

    if args.limit:
        tasks = tasks[: args.limit]

    with queue_path.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")

    print(f"[fp-repair-builder] queue -> {queue_path}")
    print(f"  total FP detectors: {len(fps)}")
    print(f"  queued tasks:       {len(tasks)}")
    print(f"  skipped (no YAML):  {skipped_no_yaml}")
    print(f"  skipped (missing fixture): {skipped_missing_fixture}")
    if only_args is not None:
        print(f"  skipped (not in --only-args-file): {skipped_filtered}")
    print(f"  prompts -> {prompts_dir}")
    print(f"  outputs -> {outputs_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
