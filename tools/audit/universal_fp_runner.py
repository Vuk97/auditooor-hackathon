#!/usr/bin/env python3
"""Universal FP runner (Wave-4 capability uplift).

Loads universal-fingerprint YAML records from the canonical
``audit/corpus_tags/tags/dsl_pattern_universal_fp_*.yaml`` family
and fires concrete regex / structural strategies derived from
each FP's verbatim ``pattern_shape`` against a target workspace's
source tree.

Schema for the JSON output: ``auditooor.universal_fp_runner.v1``.

CLI surface:

  --workspace <ws>       Target workspace root (required).
  --fp-dir <path>        Directory holding FP YAMLs (default:
                         <repo>/audit/corpus_tags/tags).
  --fps FP-01,FP-03,...  Restrict to a comma-separated subset
                         (default: all loaded FPs).
  --target-language LANG Override auto-detect (solidity|go|rust).
  --json                 Emit JSON to stdout (default: on).
  --markdown             Also emit a human-readable markdown
                         summary of top hits per FP.
  --output <path>        Write JSON to file instead of stdout.
  --markdown-output P    Write markdown report to file.
  --strict               Exit 1 when total_hits > 0.
  --no-blacklist         Disable the default path-classification
                         blacklist (restore pre-CAP-D7 behavior;
                         every hit gets path_classification set
                         to ``unknown``).
  --blacklist-extra P    Add operator-supplied path patterns to
                         the blacklist. Comma-separated. Each
                         entry is a glob-style fragment matched
                         as a substring against the relative path.
  --include-mocks        Legacy alias for ``--no-blacklist``.

Stdlib + PyYAML only. No network. No mutation of the target
workspace. Quarantine subtrees (``_QUARANTINE_*`` / ``_archive`` /
``node_modules`` / ``.git`` / ``vendor`` / ``out`` / ``cache`` /
``forge-cache``) are skipped.

Path-classification (CAP-D7, lane added 2026-05-16):
  Each hit gains a ``path_classification`` field in
  {``production`` | ``test`` | ``mock`` | ``lib`` | ``script`` |
  ``unknown``}. By default the Markdown report buckets hits by
  classification so the PRODUCTION signal surfaces first and
  TEST / MOCK / LIB noise is relegated to reference tables. The
  JSON envelope adds ``hits_per_classification`` and
  ``hits_per_fp_by_classification`` summaries.

  The default blacklist intentionally suppresses test/mock/lib/
  script subtrees because CAP-D6 observed FP-01 on Graph fired
  396 hits with heavy test/mock noise (signal swamped). The
  ``--no-blacklist`` / ``--include-mocks`` flags restore the
  pre-CAP-D7 behavior for operators who explicitly want the
  full hit list.

Per Rule 37: this tool is a CONSUMER of tier-2 corpus records;
it does not emit corpus records, so emit-time tier discipline is
not in scope here.

Per Rule 36: invoked under explicit pathspec; the runner itself
makes no git-state changes.

Validation discipline:
  * Pattern shapes are parsed verbatim from each FP YAML's
    ``attacker_action_sequence`` text. The runner cites this
    string in every hit record so the operator can audit drift
    between the YAML's prose and this runner's implementation.
  * Synthetic-fixture detection: FPs whose ``shape_tags`` carry
    ``synthetic_fixture:true`` are tagged accordingly in the
    JSON. The 6 v1 FPs are ``synthetic_fixture:false``.
  * Honest false-positive disclosure: every hit carries a
    ``confidence`` field in {high, medium, low}. The Markdown
    report tabulates per-FP hit counts and confidence
    distribution so the operator can triage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[universal-fp-runner] PyYAML required; install via "
        "`pip install pyyaml` (got: %s)\n" % exc
    )
    sys.exit(2)


SCHEMA_VERSION = "auditooor.universal_fp_runner.v1"

QUARANTINE_DIRS = {
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE",
    "_archive",
    "_deprecated",
    "node_modules",
    ".git",
    "vendor",
    "out",
    "cache",
    "forge-cache",
    "build",
    "target",
    "dist",
    ".venv",
    "__pycache__",
}

LANGUAGE_EXTENSIONS = {
    "solidity": {".sol"},
    "go": {".go"},
    "rust": {".rs"},
}


# ---------------------------------------------------------------------------
# Path classification (CAP-D7 lane, 2026-05-16).
#
# Each entry maps a classification label to a list of substring
# fragments. A relative path that contains ANY fragment is
# classified accordingly. The first matching classification (in
# the order ``test`` -> ``mock`` -> ``lib`` -> ``script``) wins;
# otherwise the hit is ``production``.
#
# The fragments are matched against the path's slash-normalised
# relative form (``foo/test/Bar.sol``) and are case-sensitive on
# the directory components. File-extension-style suffixes like
# ``.t.sol`` are matched directly against the file name.
#
# Operators can extend via --blacklist-extra; those extras are
# always classified as ``test`` for bucketing (the operator
# already decided the path is non-production by adding it).
# ---------------------------------------------------------------------------


PATH_CLASSIFICATION_RULES = [
    (
        "test",
        [
            "/test/",
            "/tests/",
            "/spec/",
            "/specs/",
            "/_test/",
            ".t.sol",
            "/Test.sol",
        ],
    ),
    (
        "mock",
        [
            "/mock/",
            "/mocks/",
            "/_mocks/",
        ],
    ),
    (
        "lib",
        [
            "/.lib/",
            "/lib/forge-std/",
            "/node_modules/",
        ],
    ),
    (
        "script",
        [
            "/script/",
            "/scripts/",
        ],
    ),
]

# The set of classifications the blacklist suppresses by default
# when ``--no-blacklist`` is NOT passed. Hits whose classification
# is in this set are still emitted (so the operator can audit
# noise) but are bucketed separately in the markdown report.
BLACKLISTED_CLASSIFICATIONS = {"test", "mock", "lib", "script"}


def classify_path(rel_path: str, extra_fragments: list = None) -> str:
    """Return the classification label for ``rel_path``.

    ``rel_path`` is expected to be a forward-slash-normalised path
    relative to the workspace root. Returns one of:
    ``test`` / ``mock`` / ``lib`` / ``script`` / ``production``.

    Operator-supplied ``extra_fragments`` (from
    ``--blacklist-extra``) are also matched; matching extras are
    classified as ``test`` since the operator already decided the
    path is non-production.
    """
    norm = rel_path.replace("\\", "/")
    if not norm.startswith("/"):
        norm_with_slash = "/" + norm
    else:
        norm_with_slash = norm
    # Also tolerate matches against the basename (catch .t.sol
    # files that live directly under src/).
    basename = os.path.basename(norm)
    for label, fragments in PATH_CLASSIFICATION_RULES:
        for frag in fragments:
            if frag in norm_with_slash or frag in norm or frag in basename:
                return label
    if extra_fragments:
        for frag in extra_fragments:
            if not frag:
                continue
            if frag in norm_with_slash or frag in norm or frag in basename:
                return "test"
    return "production"


@dataclass
class FPDefinition:
    fp_id: str
    record_id: str
    target_language: str
    bug_class: str
    attack_class: str
    pattern_shape: str
    workspaces_observed: list
    universality: str
    synthetic_fixture: bool
    seeds: list
    source_path: str

    def applies_to_language(self, lang: str) -> bool:
        return self.target_language == lang or self.target_language == "any"


@dataclass
class Hit:
    fp_id: str
    file: str
    line: int
    function: str
    snippet: str
    confidence: str
    pattern_shape_excerpt: str = ""
    path_classification: str = "unknown"


# ---------------------------------------------------------------------------
# FP YAML loader.
# ---------------------------------------------------------------------------


_FP_ID_RE = re.compile(r"fingerprint_id:(FP-\d+)")
_UNIVERSALITY_RE = re.compile(r"universality:([\w\-]+)")
_WORKSPACE_RE = re.compile(r"^workspace:(.+)$")
_SEED_RE = re.compile(r"^seed:(.+)$")
_SYNTHETIC_RE = re.compile(r"synthetic_fixture:(true|false)")


def load_fp_definitions(fp_dir: Path) -> list:
    """Read every dsl_pattern_universal_fp_*.yaml under fp_dir.

    Returns a sorted-by-fp_id list of FPDefinition.
    """
    out = []
    if not fp_dir.is_dir():
        return out
    for path in sorted(fp_dir.glob("dsl_pattern_universal_fp_*.yaml")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            sys.stderr.write(
                "[universal-fp-runner] skip malformed %s: %s\n" % (path, exc)
            )
            continue

        shape_tags = (doc.get("function_shape") or {}).get("shape_tags") or []
        shape_tags = [str(t) for t in shape_tags]

        fp_id = ""
        universality = ""
        workspaces = []
        seeds = []
        synthetic = False
        for tag in shape_tags:
            m = _FP_ID_RE.search(tag)
            if m:
                fp_id = m.group(1)
                continue
            m = _UNIVERSALITY_RE.search(tag)
            if m:
                universality = m.group(1)
                continue
            m = _WORKSPACE_RE.match(tag)
            if m:
                workspaces.append(m.group(1))
                continue
            m = _SEED_RE.match(tag)
            if m:
                seeds.append(m.group(1))
                continue
            m = _SYNTHETIC_RE.search(tag)
            if m:
                synthetic = m.group(1) == "true"

        if not fp_id:
            sys.stderr.write(
                "[universal-fp-runner] skip %s: no fingerprint_id tag\n"
                % path.name
            )
            continue

        out.append(
            FPDefinition(
                fp_id=fp_id,
                record_id=str(doc.get("record_id") or path.stem),
                target_language=str(doc.get("target_language") or "any"),
                bug_class=str(doc.get("bug_class") or ""),
                attack_class=str(doc.get("attack_class") or ""),
                pattern_shape=str(doc.get("attacker_action_sequence") or ""),
                workspaces_observed=workspaces,
                universality=universality,
                synthetic_fixture=synthetic,
                seeds=seeds,
                source_path=str(path),
            )
        )
    out.sort(key=lambda d: d.fp_id)
    return out


# ---------------------------------------------------------------------------
# Workspace traversal.
# ---------------------------------------------------------------------------


def detect_workspace_languages(workspace: Path) -> set:
    """Auto-detect languages by file extension within workspace."""
    found = set()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        for ext in exts:
            for _ in iter_source_files(workspace, {lang: exts}):
                found.add(lang)
                break
            if lang in found:
                break
    return found


def iter_source_files(
    workspace: Path, lang_to_exts: dict
) -> Iterable:
    """Yield (path, language) for every source file under workspace.

    Skips quarantine and build directories.
    """
    flat_ext_to_lang = {}
    for lang, exts in lang_to_exts.items():
        for ext in exts:
            flat_ext_to_lang[ext] = lang

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in QUARANTINE_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1]
            lang = flat_ext_to_lang.get(ext)
            if not lang:
                continue
            yield Path(root) / name, lang


# ---------------------------------------------------------------------------
# Concrete pattern strategies per FP.
#
# Each strategy:
#   * receives the FP definition + file path + text.
#   * returns a list[Hit].
#
# The strategies derive concrete shapes from each FP's
# pattern_shape prose. The mapping is documented inline so an
# auditor can verify drift between corpus prose and runner code.
# ---------------------------------------------------------------------------


# Solidity: function definitions (top-level or nested).
_SOL_FN_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*"
    r"(?P<modifiers>[^{;]*)\{",
    re.MULTILINE,
)
# Solidity: storage-state assignment (heuristic: assignment to a
# bare identifier or `this.var =` outside a `view`/`pure` fn).
_SOL_STATE_ASSIGN_RE = re.compile(
    r"^\s*(?:(?P<lhs>[A-Za-z_]\w*(?:\[[^\]]*\])?(?:\.[A-Za-z_]\w*)?))\s*=\s*[^=]",
    re.MULTILINE,
)
_SOL_GUARD_RE = re.compile(
    r"\b(require|assert|revert|if\s*\(.*\)\s*(revert|throw))\b"
)
# Strip Solidity comments before guard scanning so a `// require`
# comment does not silence a real FP-01 hit.
_SOL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_SOL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_solidity_comments(text: str) -> str:
    text = _SOL_BLOCK_COMMENT_RE.sub("", text)
    text = _SOL_LINE_COMMENT_RE.sub("", text)
    return text
_SOL_VIEW_PURE_RE = re.compile(r"\b(view|pure)\b")
_SOL_MODIFIER_GUARD_TOKENS = {
    "onlyOwner",
    "onlyAdmin",
    "onlyRole",
    "onlyGovernor",
    "nonReentrant",
    "whenNotPaused",
    "auth",
    "restricted",
}

# ---------------------------------------------------------------------------
# FP-01 refinement predicate (lane W6-4, 2026-05-17).
#
# The W5-C2 calibration corpus measured FP-01 firing 4 false positives
# on OpenZeppelin v5.1.0 base primitives: ``_pause``, ``_unpause``,
# ``_transferOwnership``, ``_update``. All four share one structural
# shape: they are INTERNAL leading-underscore base mutators that
# deliberately delegate the caller-trust precondition to their PUBLIC
# wrapper (``pause()`` -> ``_pause()`` under ``onlyOwner``;
# ``transferOwnership()`` -> ``_transferOwnership()`` under
# ``onlyOwner``; ``transferFrom()`` -> ``_update()`` which itself runs
# ``_checkAuthorized``). FP-01's job is to flag a writer that fails to
# check a precondition - it is NOT a finding when the writer is an
# internal primitive and the precondition is checked one frame up or
# by an internal validation helper.
#
# The refinement suppresses an FP-01 hit ONLY when the function is an
# internal/private leading-underscore base primitive AND one of three
# OZ-style clean shapes holds:
#   (a) guarded by a state-guard / access-control modifier
#       (``when*Paused``, ``only*``, ``when*``);
#   (b) the body invokes an internal validation helper
#       (``_check*`` / ``_require*`` / ``_validate*`` / ``_authorize*``
#       / ``_assert*``) before/around the state write;
#   (c) the body is a trivial base setter primitive - every non-
#       assignment statement is an ``emit`` or a local-var decl, i.e.
#       it does pure bookkeeping and delegates caller-trust upward.
#
# A public/external function, or an internal function WITHOUT a
# leading underscore, or an internal underscore function that does
# none of (a)/(b)/(c), is NOT suppressed - genuine missing-validation
# shapes still fire. The TP calibration fixtures (``setX`` public no
# guard; ``setOwner`` public ``onlyOwner``) are public, so they are
# never reached by this predicate.
# ---------------------------------------------------------------------------
_SOL_INTERNAL_VIS_RE = re.compile(r"\b(internal|private)\b")
_SOL_PUBLIC_VIS_RE = re.compile(r"\b(public|external)\b")
_SOL_STATE_GUARD_MODIFIER_RE = re.compile(
    r"\b(only[A-Z]\w*|when[A-Z]\w*|nonReentrant|auth|restricted)\b"
)
_SOL_INTERNAL_VALIDATION_HELPER_RE = re.compile(
    r"\b_(check|require|validate|authorize|assert)[A-Za-z_]*\s*\("
)
# A "trivial base setter" statement is an assignment, an emit, a
# local-var declaration, an unchecked block, or an if-wrapped
# internal validation/clearing helper. If every statement in the
# body matches one of these, the function is a pure bookkeeping
# primitive that delegates caller-trust to its wrapper.
_SOL_TRIVIAL_STMT_RES = [
    re.compile(r"^emit\b"),
    re.compile(r"^return\b"),
    re.compile(r"^_[A-Za-z_]\w*\s*[\.=]"),          # private state field write
    re.compile(r"^[A-Za-z_]\w*(\[[^\]]*\])?\s*="),  # bare state assignment
    re.compile(
        r"^(uint\w*|int\w*|bool|address|bytes\w*|string|mapping)\b"
    ),  # local-var decl
    re.compile(r"^unchecked\b"),
    re.compile(r"^if\s*\("),                        # guard/clearing branch
]
# Tokens that disqualify a body from "trivial base setter": an
# external/low-level call, a loop, or a delegatecall surface.
_SOL_NONTRIVIAL_BODY_RE = re.compile(
    r"\b(for\s*\(|while\s*\(|\.call\{|\.delegatecall\(|"
    r"\.transfer\(|\.send\()"
)


def _fp01_refinement_suppresses(
    name: str, modifiers: str, body_no_comments: str
) -> str:
    """Return a non-empty reason string if FP-01 should suppress this
    hit on the W6-4 OZ-base-primitive refinement, else ''.

    The predicate fires ONLY for internal/private leading-underscore
    base mutators matching one of the three OZ-clean shapes. Anything
    public/external, or non-underscore-named, returns '' (not
    suppressed) so genuine missing-validation shapes still fire.
    """
    # Gate 1: leading-underscore name (OZ base-primitive convention).
    if not name.startswith("_"):
        return ""
    # Gate 2: internal/private visibility - a public/external function
    # owns its own caller-trust boundary and cannot delegate upward.
    if _SOL_PUBLIC_VIS_RE.search(modifiers):
        return ""
    if not _SOL_INTERNAL_VIS_RE.search(modifiers):
        # Solidity functions with no explicit visibility default to
        # internal for the function-body case the FP-01 regex picks
        # up; but a missing keyword is ambiguous. Require an explicit
        # internal/private keyword so the predicate stays narrow.
        return ""
    # (a) state-guard / access-control modifier on the primitive.
    if _SOL_STATE_GUARD_MODIFIER_RE.search(modifiers):
        return "internal-underscore primitive guarded by modifier"
    # (b) internal validation helper invoked in the body.
    if _SOL_INTERNAL_VALIDATION_HELPER_RE.search(body_no_comments):
        return "internal-underscore primitive invokes validation helper"
    # (c) trivial base setter: every statement is bookkeeping and the
    # body contains no external call / loop / value transfer.
    if _SOL_NONTRIVIAL_BODY_RE.search(body_no_comments):
        return ""
    stmts = [
        s.strip()
        for s in body_no_comments.replace("}", ";").split(";")
        if s.strip()
    ]
    if not stmts:
        return ""
    for stmt in stmts:
        if not any(rx.match(stmt) for rx in _SOL_TRIVIAL_STMT_RES):
            return ""
    return "internal-underscore trivial base-setter primitive"


def _extract_solidity_functions(text: str):
    """Yield (name, modifiers_str, body_text, start_line) per function."""
    for m in _SOL_FN_RE.finditer(text):
        start = m.end() - 1  # at the opening brace
        depth = 0
        i = start
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    body = text[start + 1 : i]
                    start_line = text.count("\n", 0, m.start()) + 1
                    yield (
                        m.group("name"),
                        m.group("modifiers") or "",
                        body,
                        start_line,
                    )
                    break
            i += 1


def strategy_fp01_solidity(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-01 solidity: function mutates state without preceding guard.

    Heuristic from pattern_shape: 'for each function F that
    mutates persistent state S ... if F-body does not contain a
    syntactic invocation of P (require / modifier guard) ...
    emit candidate'.

    Confidence:
      * high: state-mutating fn, no require/assert/revert AND no
        access-control modifier token in modifiers slot.
      * medium: state-mutating fn, no require/assert/revert but
        has access-control modifier (caller-trust gates the
        write).
      * low: never emitted by this strategy.
    """
    hits = []
    if fp.target_language != "solidity":
        return hits
    for name, modifiers, body, line in _extract_solidity_functions(text):
        if _SOL_VIEW_PURE_RE.search(modifiers):
            continue
        assign_match = _SOL_STATE_ASSIGN_RE.search(body)
        if not assign_match:
            continue
        # Skip obvious local-var decls (uint256 x = ...; address y =).
        # The regex above is anchored at line start so `uint256 x = 1;`
        # would match too. Filter via a quick lookbehind on the line.
        line_text = body[
            body.rfind("\n", 0, assign_match.start()) + 1 : assign_match.end()
        ]
        if re.match(
            r"\s*(uint\w*|int\w*|bool|address|bytes\w*|string|"
            r"mapping|struct|memory|storage|calldata)\b",
            line_text,
        ):
            continue
        prefix_no_comments = _strip_solidity_comments(
            body[: assign_match.start()]
        )
        has_guard = bool(_SOL_GUARD_RE.search(prefix_no_comments))
        if has_guard:
            continue
        modifiers_no_comments = _strip_solidity_comments(modifiers)
        # W6-4 refinement: suppress OZ-style internal-underscore base
        # primitives that delegate caller-trust to a public wrapper.
        body_no_comments = _strip_solidity_comments(body)
        refinement_reason = _fp01_refinement_suppresses(
            name, modifiers_no_comments, body_no_comments
        )
        if refinement_reason:
            continue
        confidence = "high"
        for tok in _SOL_MODIFIER_GUARD_TOKENS:
            if tok in modifiers_no_comments:
                confidence = "medium"
                break
        snippet = line_text.strip()[:200]
        hits.append(
            Hit(
                fp_id=fp.fp_id,
                file=str(path),
                line=line + body.count("\n", 0, assign_match.start()),
                function=name,
                snippet=snippet,
                confidence=confidence,
                pattern_shape_excerpt=(
                    "function F that mutates persistent state S "
                    "without checking precondition P"
                ),
            )
        )
    return hits


# Go: function definitions + state-mutating call shape.
_GO_FN_RE = re.compile(
    r"^func\s+(?:\([^)]*\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)
_GO_STATE_CALL_RE = re.compile(
    r"\.(Set[A-Z]\w*|SendCoins\w*|"
    r"Save\(ctx|SetParams|SetX|SetSubaccount|SetClobPair|"
    r"PutObject|Put\(|Update\(\)\.Save)\b"
)


def _extract_go_functions(text: str):
    """Yield (name, body_text, start_line) for each top-level func."""
    matches = list(_GO_FN_RE.finditer(text))
    for idx, m in enumerate(matches):
        # find matching opening brace after the signature.
        brace_start = text.find("{", m.end())
        if brace_start < 0:
            continue
        depth = 0
        i = brace_start
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    body = text[brace_start + 1 : i]
                    start_line = text.count("\n", 0, m.start()) + 1
                    yield m.group("name"), body, start_line
                    break
            i += 1


def strategy_fp02_go(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-02 go: function with >=2 state-mutating calls in same body.

    The corpus-required-order pairs are not yet broken out as
    machine-readable rules in the v1 YAMLs (the seeds cite
    DD-PAT-002 and SP-PAT-NEW-004 but the explicit
    Wi-before-Wj pairs live in the source SHAs). The runner
    therefore emits CANDIDATE hits for review (every Go function
    with >=2 state mutations) and the operator confirms order.

    Confidence:
      * medium: 2 state-mutating calls in same fn.
      * high: 3+ state-mutating calls in same fn (more chances
        for ordering violations).
    """
    hits = []
    if fp.target_language != "go":
        return hits
    for name, body, line in _extract_go_functions(text):
        calls = list(_GO_STATE_CALL_RE.finditer(body))
        if len(calls) < 2:
            continue
        confidence = "high" if len(calls) >= 3 else "medium"
        first_call = body[
            body.rfind("\n", 0, calls[0].start()) + 1 : calls[0].end() + 40
        ]
        snippet = first_call.strip()[:200]
        hits.append(
            Hit(
                fp_id=fp.fp_id,
                file=str(path),
                line=line + body.count("\n", 0, calls[0].start()),
                function=name,
                snippet=snippet,
                confidence=confidence,
                pattern_shape_excerpt=(
                    "function F containing >=2 state-mutating "
                    "calls with order-dependence"
                ),
            )
        )
    return hits


# Solidity admin setter heuristic.
_SOL_ADMIN_FN_NAME_RE = re.compile(
    r"^set[A-Z]\w*|^update[A-Z]\w*|^configure[A-Z]\w*|"
    r"^initialize|^__\w+_init|^reinitialize"
)
_SOL_REINIT_TOKENS = (
    "refresh",
    "invalidate",
    "reInit",
    "reinit",
    "_update",
    "sync",
    "rebalance",
    "rescue",
)


def strategy_fp03_solidity(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-03 solidity: admin setter mutates config without
    invalidating downstream consumers.

    Confidence:
      * medium: admin-shaped setter, body has a state-write
        but no refresh / invalidate / reinit / sync / update
        token elsewhere in the body.
      * low: admin-shaped setter, body has state-write, body
        does contain a refresh-style token but in a different
        statement than the mutation (heuristic noisy).
    """
    hits = []
    if fp.target_language != "solidity":
        return hits
    for name, modifiers, body, line in _extract_solidity_functions(text):
        if not _SOL_ADMIN_FN_NAME_RE.match(name):
            continue
        assign_match = _SOL_STATE_ASSIGN_RE.search(body)
        if not assign_match:
            continue
        body_no_comments = _strip_solidity_comments(body)
        body_lc = body_no_comments.lower()
        has_reinit = any(tok.lower() in body_lc for tok in _SOL_REINIT_TOKENS)
        confidence = "low" if has_reinit else "medium"
        snippet = body[assign_match.start() : assign_match.end() + 60].strip()[
            :200
        ]
        hits.append(
            Hit(
                fp_id=fp.fp_id,
                file=str(path),
                line=line + body.count("\n", 0, assign_match.start()),
                function=name,
                snippet=snippet,
                confidence=confidence,
                pattern_shape_excerpt=(
                    "handler H mutates config-state C without "
                    "invalidating / refreshing downstream consumers D"
                ),
            )
        )
    return hits


def strategy_fp04_any(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-04 git-history scan: NOT a source-tree pattern.

    The pattern_shape is 'enumerate git history (forward window)
    for commits matching subject =~ /Revert "(.*)"/' which is
    out of scope for this runner (we walk source, not git log).
    The Wave-2 corpus already ships `tools/reverted-guard-mine.py`
    for this exact lane; we surface a single 'not-applicable'
    record so the operator knows we did not silently skip it.
    """
    return []


def strategy_fp05_solidity(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-05 solidity: residual references to renamed identifiers.

    The corpus seeds cite two concrete renames:
      * TG-PAT-011: NO_ALLOCATION -> NO_ALLOCATED_TOKENS
      * DD-PAT-011: GetStakedAmount -> GetStakedBaseTokens
    We grep both directions on each source file.

    Confidence: high (renames have crisp ground truth).
    """
    hits = []
    if fp.target_language != "solidity":
        return hits
    rename_pairs = [
        ("NO_ALLOCATION", "NO_ALLOCATED_TOKENS"),
        ("GetStakedAmount", "GetStakedBaseTokens"),
    ]
    for old_name, new_name in rename_pairs:
        for m in re.finditer(r"\b" + re.escape(old_name) + r"\b", text):
            line_no = text.count("\n", 0, m.start()) + 1
            line_text = text.splitlines()[line_no - 1]
            # Skip lines that also mention the new name (likely
            # a migration comment, doc, or declaration block).
            if new_name in line_text:
                continue
            hits.append(
                Hit(
                    fp_id=fp.fp_id,
                    file=str(path),
                    line=line_no,
                    function="",
                    snippet=line_text.strip()[:200],
                    confidence="high",
                    pattern_shape_excerpt=(
                        "residual reference to renamed identifier "
                        "%s -> %s" % (old_name, new_name)
                    ),
                )
            )
    return hits


_SOL_INTERFACE_RE = re.compile(
    r"\binterface\s+(?P<name>[A-Z]\w*)\s*\{(?P<body>[^}]*)\}",
    re.DOTALL,
)
_SOL_IFACE_FN_RE = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
    r"(?:external|public|internal|private)?\s*"
    r"(?:view|pure|payable)?\s*"
    r"(?:returns\s*\([^)]*\))?\s*;"
)


def strategy_fp06_solidity(
    fp: FPDefinition, path: Path, text: str
) -> list:
    """FP-06 solidity: interface arity drift heuristic.

    For each `interface IX { function f(...) ... }` block, count
    declared param-list elements and surface as candidate. A
    cross-file diff against the implementing contract is the
    operator's manual step; this runner just enumerates
    interface fn declarations so the audit-deep markdown report
    gives the operator a starting roster.

    Confidence: low (no comparator, just inventory).
    """
    hits = []
    if fp.target_language != "solidity":
        return hits
    for iface_match in _SOL_INTERFACE_RE.finditer(text):
        iface_name = iface_match.group("name")
        body = iface_match.group("body")
        iface_line = text.count("\n", 0, iface_match.start()) + 1
        for fn_match in _SOL_IFACE_FN_RE.finditer(body):
            fn_name = fn_match.group(1)
            params = fn_match.group(2).strip()
            param_count = len([p for p in params.split(",") if p.strip()])
            snippet = (
                "interface %s.%s(%d params): %s"
                % (iface_name, fn_name, param_count, params[:120])
            )
            line_no = iface_line + body.count("\n", 0, fn_match.start())
            hits.append(
                Hit(
                    fp_id=fp.fp_id,
                    file=str(path),
                    line=line_no,
                    function="%s.%s" % (iface_name, fn_name),
                    snippet=snippet,
                    confidence="low",
                    pattern_shape_excerpt=(
                        "external-facing interface arity / "
                        "selector divergence"
                    ),
                )
            )
    return hits


STRATEGY_REGISTRY = {
    "FP-01": strategy_fp01_solidity,
    "FP-02": strategy_fp02_go,
    "FP-03": strategy_fp03_solidity,
    "FP-04": strategy_fp04_any,
    "FP-05": strategy_fp05_solidity,
    "FP-06": strategy_fp06_solidity,
}


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def fire_fps_on_workspace(
    workspace: Path,
    fps: list,
    target_languages: set,
    blacklist_enabled: bool = True,
    blacklist_extra: list = None,
) -> list:
    """For each FP applicable to a detected language, walk the
    workspace's source tree and fire the strategy.

    Returns flat list[Hit]. Every hit is tagged with a
    ``path_classification`` derived from its workspace-relative
    path (CAP-D7 lane).

    When ``blacklist_enabled`` is True (default), hits whose
    classification is in ``BLACKLISTED_CLASSIFICATIONS`` are
    STILL returned (so the operator can audit noise) but the
    Markdown / JSON consumers bucket them separately. The
    ``hits_per_classification`` summary makes the test/mock
    delta explicit.
    """
    hits = []
    lang_to_exts = {
        lang: LANGUAGE_EXTENSIONS[lang] for lang in target_languages
    }
    extra = blacklist_extra or []
    workspace_resolved = workspace.resolve()
    for file_path, lang in iter_source_files(workspace, lang_to_exts):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(file_path.resolve().relative_to(workspace_resolved))
        except ValueError:
            rel = str(file_path)
        if blacklist_enabled:
            classification = classify_path(rel, extra)
        else:
            classification = "unknown"
        for fp in fps:
            if not fp.applies_to_language(lang) and fp.target_language != "any":
                continue
            strategy = STRATEGY_REGISTRY.get(fp.fp_id)
            if strategy is None:
                continue
            for h in strategy(fp, file_path, text):
                h.path_classification = classification
                hits.append(h)
    return hits


def build_output(
    workspace: Path,
    fps_evaluated: list,
    hits: list,
    target_languages: set,
    fp_dir: Path,
    blacklist_enabled: bool = True,
    blacklist_extra: list = None,
) -> dict:
    hits_per_fp = {}
    confidence_per_fp = {}
    for fp in fps_evaluated:
        hits_per_fp[fp.fp_id] = 0
        confidence_per_fp[fp.fp_id] = {"high": 0, "medium": 0, "low": 0}
    hits_per_classification = {
        "production": 0,
        "test": 0,
        "mock": 0,
        "lib": 0,
        "script": 0,
        "unknown": 0,
    }
    hits_per_fp_by_classification = {}
    production_hit_count = 0
    for h in hits:
        hits_per_fp[h.fp_id] = hits_per_fp.get(h.fp_id, 0) + 1
        bucket = confidence_per_fp.setdefault(
            h.fp_id, {"high": 0, "medium": 0, "low": 0}
        )
        bucket[h.confidence] = bucket.get(h.confidence, 0) + 1
        cls = h.path_classification or "unknown"
        hits_per_classification[cls] = hits_per_classification.get(cls, 0) + 1
        if cls == "production":
            production_hit_count += 1
        fp_cls = hits_per_fp_by_classification.setdefault(
            h.fp_id,
            {
                "production": 0,
                "test": 0,
                "mock": 0,
                "lib": 0,
                "script": 0,
                "unknown": 0,
            },
        )
        fp_cls[cls] = fp_cls.get(cls, 0) + 1

    return {
        "schema": SCHEMA_VERSION,
        "target_workspace": str(workspace.resolve()),
        "fp_dir": str(fp_dir.resolve()),
        "target_languages": sorted(target_languages),
        "fps_evaluated": [
            {
                "fp_id": fp.fp_id,
                "record_id": fp.record_id,
                "target_language": fp.target_language,
                "bug_class": fp.bug_class,
                "attack_class": fp.attack_class,
                "universality": fp.universality,
                "workspaces_observed": fp.workspaces_observed,
                "seeds": fp.seeds,
                "synthetic_fixture": fp.synthetic_fixture,
                "strategy_available": fp.fp_id in STRATEGY_REGISTRY,
                "strategy_notes": _strategy_notes(fp.fp_id),
                "source_yaml": fp.source_path,
            }
            for fp in fps_evaluated
        ],
        "total_hits": len(hits),
        "production_hit_count": production_hit_count,
        "blacklist_enabled": blacklist_enabled,
        "blacklist_extra": list(blacklist_extra or []),
        "hits_per_fp": hits_per_fp,
        "confidence_per_fp": confidence_per_fp,
        "hits_per_classification": hits_per_classification,
        "hits_per_fp_by_classification": hits_per_fp_by_classification,
        "hits": [asdict(h) for h in hits],
    }


def _strategy_notes(fp_id: str) -> str:
    return {
        "FP-01": (
            "solidity: state-write without preceding require / "
            "assert / revert; access-control modifier walks "
            "confidence high -> medium. W6-4 refinement: internal "
            "leading-underscore base primitives that delegate "
            "caller-trust to a public wrapper (modifier-guarded, "
            "internal-validation-helper, or trivial base-setter) "
            "are suppressed - OZ _pause/_unpause/_transferOwnership/"
            "_update no longer false-positive."
        ),
        "FP-02": (
            "go: function body with >=2 state-mutating calls; "
            "Wi-before-Wj order is operator-verified"
        ),
        "FP-03": (
            "solidity: admin-named setter writes config without "
            "refresh / invalidate / reinit / sync token in body"
        ),
        "FP-04": (
            "git-history-only; use tools/reverted-guard-mine.py "
            "(source-tree runner returns 0 hits by design)"
        ),
        "FP-05": (
            "solidity: residual reference to renamed identifier "
            "(NO_ALLOCATION, GetStakedAmount)"
        ),
        "FP-06": (
            "solidity: interface fn-decl inventory; arity / "
            "selector diff is an operator review step"
        ),
    }.get(fp_id, "no strategy")


def render_markdown(output: dict, top_n: int = 10) -> str:
    lines = []
    lines.append("# universal_fp_runner report")
    lines.append("")
    lines.append("- schema: " + output["schema"])
    lines.append("- workspace: " + output["target_workspace"])
    lines.append("- fp_dir: " + output["fp_dir"])
    lines.append(
        "- target_languages: " + ", ".join(output["target_languages"])
    )
    lines.append("- total_hits: %d" % output["total_hits"])
    lines.append(
        "- production_hit_count: %d"
        % output.get("production_hit_count", 0)
    )
    lines.append(
        "- blacklist_enabled: %s"
        % str(output.get("blacklist_enabled", True))
    )
    if output.get("blacklist_extra"):
        lines.append(
            "- blacklist_extra: " + ", ".join(output["blacklist_extra"])
        )
    lines.append("")
    # Path-classification summary (CAP-D7).
    lines.append("## hits by path_classification")
    lines.append("")
    lines.append("| classification | count |")
    lines.append("| --- | ---:|")
    hpc = output.get("hits_per_classification") or {}
    for cls in ["production", "test", "mock", "lib", "script", "unknown"]:
        lines.append("| %s | %d |" % (cls, hpc.get(cls, 0)))
    lines.append("")
    lines.append("## per-FP hit counts")
    lines.append("")
    lines.append("| fp_id | bug_class | language | hits | high | medium | low |")
    lines.append("| --- | --- | --- | ---:| ---:| ---:| ---:|")
    fp_map = {fp["fp_id"]: fp for fp in output["fps_evaluated"]}
    for fp_id in sorted(output["hits_per_fp"].keys()):
        fp_info = fp_map.get(fp_id, {})
        cb = output["confidence_per_fp"].get(
            fp_id, {"high": 0, "medium": 0, "low": 0}
        )
        lines.append(
            "| %s | %s | %s | %d | %d | %d | %d |"
            % (
                fp_id,
                fp_info.get("bug_class", "?"),
                fp_info.get("target_language", "?"),
                output["hits_per_fp"].get(fp_id, 0),
                cb.get("high", 0),
                cb.get("medium", 0),
                cb.get("low", 0),
            )
        )
    lines.append("")
    # per-FP classification breakdown.
    fp_cls_map = output.get("hits_per_fp_by_classification") or {}
    if fp_cls_map:
        lines.append("## per-FP classification breakdown")
        lines.append("")
        lines.append(
            "| fp_id | production | test | mock | lib | script | unknown |"
        )
        lines.append("| --- | ---:| ---:| ---:| ---:| ---:| ---:|")
        for fp_id in sorted(fp_cls_map.keys()):
            row = fp_cls_map[fp_id]
            lines.append(
                "| %s | %d | %d | %d | %d | %d | %d |"
                % (
                    fp_id,
                    row.get("production", 0),
                    row.get("test", 0),
                    row.get("mock", 0),
                    row.get("lib", 0),
                    row.get("script", 0),
                    row.get("unknown", 0),
                )
            )
        lines.append("")
    # Bucket hits by classification then per_fp.
    by_cls = {}
    for h in output["hits"]:
        by_cls.setdefault(h.get("path_classification", "unknown"), []).append(h)
    # SIGNAL bucket first (production), then noise buckets.
    bucket_order = ["production", "unknown", "test", "mock", "lib", "script"]
    for cls in bucket_order:
        cls_hits = by_cls.get(cls)
        if not cls_hits:
            continue
        header_prefix = "## PRODUCTION (signal):" if cls == "production" else (
            "## " + cls.upper() + " (noise reference):"
        )
        if cls == "unknown":
            header_prefix = "## UNKNOWN (signal/noise mixed):"
        lines.append(header_prefix + " top %d hits per FP" % top_n)
        lines.append("")
        hits_by_fp = {}
        for h in cls_hits:
            hits_by_fp.setdefault(h["fp_id"], []).append(h)
        for fp_id in sorted(hits_by_fp.keys()):
            lines.append("### %s %s (%d hits)" % (cls, fp_id, len(hits_by_fp[fp_id])))
            lines.append("")
            for h in hits_by_fp[fp_id][:top_n]:
                lines.append(
                    "- `%s:%d` fn=`%s` confidence=%s classification=%s"
                    % (
                        h["file"],
                        h["line"],
                        h["function"],
                        h["confidence"],
                        h.get("path_classification", "unknown"),
                    )
                )
                lines.append("  - %s" % (h["snippet"] or "(no snippet)"))
            lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    # tools/audit/universal_fp_runner.py -> repo root is parents[2].
    return Path(__file__).resolve().parents[2]


def main(argv: list) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Fire universal-fingerprint YAML patterns against a "
            "target workspace's source tree."
        )
    )
    p.add_argument("--workspace", required=True, help="target workspace root")
    p.add_argument(
        "--fp-dir",
        default=str(_repo_root() / "audit" / "corpus_tags" / "tags"),
        help="directory holding dsl_pattern_universal_fp_*.yaml files",
    )
    p.add_argument(
        "--fps",
        default="",
        help="comma-separated FP IDs to restrict (default: all loaded)",
    )
    p.add_argument(
        "--target-language",
        default="",
        choices=["", "solidity", "go", "rust"],
        help="restrict scan to one language (default: auto-detect)",
    )
    p.add_argument("--json", action="store_true", default=True)
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--output", default="", help="write JSON to this file")
    p.add_argument(
        "--markdown-output", default="", help="write markdown to this file"
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when total_hits > 0",
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="markdown: top-N hits per FP (default 10)",
    )
    p.add_argument(
        "--no-blacklist",
        action="store_true",
        help=(
            "disable the CAP-D7 path-classification blacklist "
            "(restore pre-CAP-D7 behavior; test/mock/lib/script "
            "hits are no longer classified or bucketed)"
        ),
    )
    p.add_argument(
        "--include-mocks",
        action="store_true",
        help="legacy alias for --no-blacklist",
    )
    p.add_argument(
        "--blacklist-extra",
        default="",
        help=(
            "comma-separated operator-supplied path fragments to "
            "add to the blacklist; matching paths classify as 'test'"
        ),
    )
    args = p.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        sys.stderr.write(
            "[universal-fp-runner] workspace not a directory: %s\n" % workspace
        )
        return 2

    fp_dir = Path(args.fp_dir).expanduser().resolve()
    fps = load_fp_definitions(fp_dir)
    if args.fps:
        wanted = {x.strip() for x in args.fps.split(",") if x.strip()}
        fps = [fp for fp in fps if fp.fp_id in wanted]
    if not fps:
        sys.stderr.write(
            "[universal-fp-runner] no FP definitions loaded from %s\n"
            % fp_dir
        )
        # Still emit a valid envelope so audit-deep wiring does not
        # break when the YAMLs are absent (e.g. on a base branch
        # that predates the PR #729 promotion).
        out = build_output(workspace, [], [], set(), fp_dir)
        _emit(out, args)
        return 0

    if args.target_language:
        target_langs = {args.target_language}
    else:
        target_langs = detect_workspace_languages(workspace)
        if not target_langs:
            # Fallback to all known languages so we at least touch
            # the FS once; downstream the per-FP language filter
            # will produce 0 hits cleanly.
            target_langs = set(LANGUAGE_EXTENSIONS.keys())

    blacklist_enabled = not (args.no_blacklist or args.include_mocks)
    blacklist_extra = [
        x.strip() for x in args.blacklist_extra.split(",") if x.strip()
    ]
    hits = fire_fps_on_workspace(
        workspace,
        fps,
        target_langs,
        blacklist_enabled=blacklist_enabled,
        blacklist_extra=blacklist_extra,
    )
    out = build_output(
        workspace,
        fps,
        hits,
        target_langs,
        fp_dir,
        blacklist_enabled=blacklist_enabled,
        blacklist_extra=blacklist_extra,
    )
    _emit(out, args)

    if args.strict and out["total_hits"] > 0:
        return 1
    return 0


def _emit(out: dict, args):
    txt = json.dumps(out, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).expanduser().write_text(txt + "\n", encoding="utf-8")
    else:
        sys.stdout.write(txt + "\n")
    if args.markdown or args.markdown_output:
        md = render_markdown(out, top_n=args.top_n)
        if args.markdown_output:
            Path(args.markdown_output).expanduser().write_text(
                md, encoding="utf-8"
            )
        else:
            sys.stdout.write(md)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
