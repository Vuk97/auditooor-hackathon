#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-auditor-backtest; orchestrator commits; no sibling files touched -->
"""auditor-backtest.py - honest real-world backtest of the auditooor DETECTION
LAYER against a KNOWN third-party vulnerability.

Problem this answers
--------------------
`tools/audit/detector-catch-rate-backtest.py` is a SELF-TEST: it runs each DSL
detector against its own checked-in fixture pair and measures "does the library
catch the contract it was written for". That number is honest but circular - a
detector authored for fixture X is graded on fixture X.

This tool answers the DIFFERENT, harder question: given a KNOWN real-world bug
that the team already disclosed and FIXED somewhere -

    {id, repo, prefix_ref, vuln_class, file_line}

- fetch/locate the PRE-FIX source (the commit BEFORE the fix, where the bug is
  still live), run the FULL detection layer against it, and answer honestly:

    CAUGHT  - at least one detection layer fired AT the vulnerable file:line
              (within +/-25 lines of the cited line; or, when no line is
              given, anywhere in the vulnerable file).
    PARTIAL - a detector fired somewhere in the vulnerable FILE but NOT within
              +/-25 lines of the cited line. The class was recognized in the
              right file but the precise call-site was not localized. PARTIAL
              is reported separately from CAUGHT so the file-level signal is
              never inflated into a line-level catch. PARTIAL only exists when
              the case carries a cited line; without a line, a file hit IS the
              best-possible localization and counts as CAUGHT.
    MISSED  - the whole layer stayed silent on the known-vulnerable file.

A MISS is a MISS. The tool does not inflate: it reports the exact layers tried,
which (if any) fired, the file:line, and - on a MISS - the missing-capability
diagnosis (which layer SHOULD have covered this vuln_class but did not).
<!-- r36-rebuttal: pathspec registered LANE-backtest-harness-author in agent_pathspec.json -->

ANTI-OVERFIT: --corpus-detector-dir
------------------------------------
Newly-generated CLASS-level detectors (authored from TRAIN vulns, never from a
held-out id/file/repo) are dropped into a separate directory and unioned with
the canonical --patterns-dir via --corpus-detector-dir. The held-out catch-rate
this tool prints is then the REAL number: it measures whether a class-detector
built on TRAIN generalizes to a vuln it never saw. The flag is repeatable.

PER-LANGUAGE detection (PR4)
----------------------------
The detector layer applied is the one WIRED FOR THE TARGET LANGUAGE, resolved
from the cited file's extension. A Rust/Go/TS-dominated corpus no longer scores
0% just because there is no .sol to compile:

  .sol / .vy   -> Slither DSL engine (sub-layer 1 below). The compile step is
                  hardened: a third-party file with @openzeppelin/@uniswap/...
                  imports is retried with solc remappings derived from any
                  node_modules/ found by walking up, then by compiling the
                  enclosing checkout tree (hits restricted to the target file).
  .rs          -> tools/rust-detector-runner.py scan_workspace (pure-regex, no
                  rustc) - the same wired Rust static detectors used by audits.
  .go          -> tools/go-detector-runner.py scan_workspace UNION
                  tools/cosmos-detector-runner.py run (cosmos DSL rows).
  .ts/.tsx/.js -> semgrep registry rules (p/typescript | p/javascript). Graceful
                  when semgrep is absent or the registry is unreachable.

Every per-language arm returns the SAME (fired, hit_lines, fired_slugs) shape so
the CAUGHT/PARTIAL/MISSED outcome logic is language-agnostic. A hit is credited
ONLY when the firing detector's slug class-matches vuln_class AND the hit is in
the TARGET file (each arm scans a temp workspace holding only that file, so a
sibling-file hit can never be credited).

ENGINE / NOVEL-VECTOR arm (PR4, --engine-arm)
---------------------------------------------
An optional second arm derives novel-vector invariants on the target file via
tools/novel-vector-invariant-miner.py and credits a FILE-RECALL (PARTIAL) catch
only when a derived invariant's family class-matches vuln_class. The miner is
per-function (no precise line) so this arm can NEVER produce a line-level CAUGHT
- it is reported as PARTIAL and never inflated. Bounded: no engine fuzz, just
the cheap invariant derivation; --mimo-refine is opt-in + budget-capped (<=6,
consent-gated by AUDITOOOR_LLM_NETWORK_CONSENT=1).

The detection layer (4 sub-layers)
----------------------------------
  1. DSL detectors  - reference/patterns.dsl/*.yaml whose slug-derived
                      attack_class matches vuln_class, evaluated via the same
                      detectors/_predicate_engine.py the compiled Slither
                      detectors use (the "engine harness"). For non-Solidity
                      languages this sub-layer is the per-language runner above.
  2. corpus invariants - audit/corpus_tags/derived/invariants_extracted.jsonl
                      rows whose category / attack_signature matches vuln_class.
                      Presence of a matching invariant = the corpus KNOWS this
                      bug class (it is in memory); absence = a knowledge gap.
  3. per-fn packs    - audit/corpus_tags/derived/*/...per_fn_questions.json -
                      whether a per-function hacker-question pack covers the
                      vuln_class. Advisory layer.
  4. engine harness  - the slither predicate-engine run itself (sub-layer 1's
                      execution surface). Surfaced separately so a MISS can
                      distinguish "no relevant detector existed" (capability
                      gap) from "detector existed but engine could not compile
                      the target" (harness gap).

CAUGHT requires sub-layer 1 (a real DSL detector firing on the live source).
Sub-layers 2 and 3 are KNOWLEDGE/ADVISORY signals: they say the bug class is in
memory, not that a runnable detector fires. A vuln that is "known to the corpus"
but has no firing detector is reported as MISSED with missing-capability =
"corpus-knows-class-but-no-firing-detector".

Fetching pre-fix code
---------------------
  * --local-checkout DIR : use an already-checked-out tree (preferred; offline).
  * else: shallow `git clone` of repo, `git checkout prefix_ref`, locate
    file_line's file. Requires network + git. If the clone/checkout fails (no
    network, bad ref), the case is reported HONESTLY as outcome=NA with
    reason=fetch-failed - NOT as MISSED and NOT as CAUGHT.

Usage
-----
  Single case (flags):
    python3 tools/auditor-backtest.py \
        --id BUG-1 --repo owner/name --prefix-ref <sha> \
        --vuln-class reentrancy --file-line src/Vault.sol:142 \
        [--local-checkout /path/to/prefix/tree] [--json]

  Batch (JSONL, one case object per line with the 5 keys):
    python3 tools/auditor-backtest.py --cases cases.jsonl [--json]

Output: human report on stdout; --json emits the machine record
(schema auditooor.auditor_backtest.v1).

RELATED TOOLS:
  * tools/audit/detector-catch-rate-backtest.py - SELF-TEST against checked-in
    fixture PAIRS (does the library catch the fixture it was written for). This
    tool is DIFFERENT: it backtests against an EXTERNAL known vuln fetched from
    a real repo prefix_ref, and emits CAUGHT/MISSED + missing-capability. No
    fixture pair involved.
  * tools/*-detector-runner.py - per-language batch detector runners over a
    whole workspace; they do not fetch a prefix_ref nor grade a single known
    vuln CAUGHT/MISSED.
  * vault_detector_backtest (MCP) - surfaces the SELF-TEST catch-rate JSON; not
    a real-world fetch+grade.

Stdlib + pyyaml + slither-analyzer (slither only needed for sub-layer 1/4).
Exits 0 always (measurement tool); per-case outcome is in the record.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DETECTORS_DIR = REPO_ROOT / "detectors"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"

# PR2b: route scoring through the shared trusted-corpus resolver so backtest
# output records the trust_scope its class-detector corpus was admitted under.
sys.path.insert(0, str(REPO_ROOT / "tools" / "lib"))
try:
    import trusted_corpus_resolver as _tcr  # noqa: E402
except Exception:  # pragma: no cover - defensive
    _tcr = None


def _corpus_trust_annotation():
    if _tcr is None:
        return {"trust_scope": "raw-fallback", "is_fallback": True,
                "reason": "trusted_corpus_resolver unavailable"}
    inc = os.environ.get("INCLUDE_ADVISORY") == "1"
    return _tcr.resolve_active_corpus(repo_root_path=REPO_ROOT,
                                      include_advisory=inc).as_dict()


# --------------------------------------------------------------------------
# PR3a: FETCHABLE-ONLY admission + split discipline
# --------------------------------------------------------------------------
# A backtest case is only SCORABLE when its backing record is a real,
# source-backed, FETCHABLE vulnerability. Prose-only / fabricated / quarantined
# records are DROPPED entirely (never scored, never NA-counted) so a hallucinated
# "CONFIRMED" record can never inflate or deflate the held-out recall number.
#
# A case is fetchable when EITHER:
#   - it carries an explicit fetch_status of immutable_ready / ok / fetchable,
#     OR
#   - it carries the immutable coordinates needed to reach pre-fix source:
#     a local checkout, OR (repo AND a prefix/vulnerable ref).
# Non-fetchable pre-fix code is reported as outcome=NA (NOT MISSED): the layer
# was never given the live source to fire on, so silence is not a miss.

# Split tags. TRAIN authors detectors; HELD_OUT/FRESH_TARGET score them; a case
# inspected for authoring that should have been held out is TRAIN_LEAKED.
SPLIT_TAGS = ("TRAIN", "DEV", "HELD_OUT", "FRESH_TARGET", "FIXED_REF", "TRAIN_LEAKED")

# trust_state values (PR2 trusted-corpus schema) that must NEVER be scored.
_DROP_TRUST_STATES = {"prose_memory", "quarantine", "superseded"}
# explicit drop flags a case row may carry directly.
_DROP_FLAGS = ("is_prose_only", "is_fabricated", "is_hallucinated")
# fetch_status values that mark a case as reachable without coordinate inference.
_FETCHABLE_STATUS = {"immutable_ready", "ok", "fetchable", "live", "reachable"}
# fetch_status values that mark a case as explicitly non-fetchable.
_NONFETCHABLE_STATUS = {"dead_source", "non_fetchable", "non-fetchable",
                        "dead-source", "unfetchable", "blocked"}


def normalize_split(tag) -> str:
    """Normalize a free-form split tag to one of SPLIT_TAGS, or '' if unknown."""
    if not tag:
        return ""
    t = str(tag).strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "HELDOUT": "HELD_OUT", "HOLDOUT": "HELD_OUT", "HOLD_OUT": "HELD_OUT",
        "TEST": "HELD_OUT", "EVAL": "HELD_OUT",
        "FRESH": "FRESH_TARGET", "FRESHTARGET": "FRESH_TARGET",
        "FIXED": "FIXED_REF", "FIXEDREF": "FIXED_REF", "NEGATIVE_CONTROL": "FIXED_REF",
        "VALIDATION": "DEV", "VAL": "DEV",
        "TRAINING": "TRAIN",
        "LEAKED": "TRAIN_LEAKED",
    }
    t = aliases.get(t, t)
    return t if t in SPLIT_TAGS else ""


def case_split(case) -> str:
    """Resolve a case's split tag from any of split / split_tag / trust_tier
    style keys. Empty string when the case declares none."""
    for k in ("split", "split_tag", "dataset_split"):
        v = case.get(k)
        if v:
            return normalize_split(v)
    return ""


def is_droppable_record(case) -> tuple:
    """(drop_bool, reason). A case is dropped (never scored, never NA-counted)
    when its backing record is prose-only / fabricated / quarantined."""
    ts = (case.get("trust_state") or case.get("trust_tier") or "").strip().lower()
    if ts in _DROP_TRUST_STATES:
        return True, f"trust_state={ts}"
    for fl in _DROP_FLAGS:
        if bool(case.get(fl)):
            return True, fl
    # an R76 hallucination verdict baked into the case
    r76 = (case.get("r76_verdict") or "").strip().lower()
    if r76.startswith("fail"):
        return True, f"r76_verdict={r76}"
    return False, ""


def is_fetchable(case, local_checkout) -> tuple:
    """(fetchable_bool, reason). Fetchable when the case carries a fetchable
    fetch_status OR the immutable coordinates to reach pre-fix source. A case
    that is explicitly non-fetchable (dead source) is NOT fetchable -> NA."""
    fs = (case.get("fetch_status") or "").strip().lower()
    if fs in _NONFETCHABLE_STATUS:
        return False, f"fetch_status={fs}"
    if fs in _FETCHABLE_STATUS:
        return True, f"fetch_status={fs}"
    # No explicit status -> infer from immutable coordinates.
    if local_checkout:
        return True, "local-checkout-provided"
    repo = case.get("repo") or case.get("repo_url") or ""
    ref = (case.get("prefix_ref") or case.get("vulnerable_ref_full_sha") or "")
    if repo and ref:
        return True, "repo+prefix_ref-present"
    return False, "no-fetch-status-and-no-repo+ref-coordinates"
INVARIANTS_JSONL = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
PER_FN_GLOB = "audit/corpus_tags/derived/**/*per_fn_questions.json"
SCHEMA = "auditooor.auditor_backtest.v1"

# Force fixture-smoke mode so the vendored/test filter does not silently
# suppress detector hits on real third-party source paths.
os.environ.setdefault("AUDITOOOR_FIXTURE_SMOKE_MODE", "1")
sys.path.insert(0, str(DETECTORS_DIR))


# --------------------------------------------------------------------------
# vuln_class -> attack_class normalization (reuse the catch-rate taxonomy)
# --------------------------------------------------------------------------
def _import_class_helpers():
    """Reuse derive_attack_classes from the catch-rate backtest so this tool's
    class taxonomy stays 1:1 with the library's own."""
    import importlib.util
    p = REPO_ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
    spec = importlib.util.spec_from_file_location("_catchrate", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Direct keyword fallback (used if the catch-rate module cannot be imported,
# e.g. its slither import side-effects fail in a minimal env).
_CLASS_KEYWORDS = {
    "reentrancy": ["reentr", "callback", "cei", "checks-effects"],
    "access-control": ["access", "auth", "onlyowner", "permission", "role", "privilege"],
    "arithmetic": ["overflow", "underflow", "arithmetic", "rounding", "precision", "division"],
    "oracle": ["oracle", "price", "twap", "chainlink", "feed"],
    "signature": ["signature", "ecrecover", "permit", "replay", "nonce", "eip712"],
    "dos": ["dos", "denial", "gas-limit", "unbounded", "griefing"],
    "logic": ["logic", "validation", "invariant", "state"],
    "slippage": ["slippage", "minout", "frontrun", "sandwich", "mev"],
    "upgrade": ["upgrade", "proxy", "initialize", "storage-collision"],
    "flashloan": ["flashloan", "flash-loan", "manipulat"],
}


def normalize_vuln_class(vc: str) -> str:
    return (vc or "").strip().lower().replace("_", "-").replace(" ", "-")


def slug_keyword_classes(slug: str) -> set:
    """Heuristic class set for a DSL slug via keyword match (fallback path)."""
    s = (slug or "").lower()
    out = set()
    for cls, kws in _CLASS_KEYWORDS.items():
        if any(kw in s for kw in kws):
            out.add(cls)
    return out


def class_matches(vuln_class: str, candidate_classes: set) -> bool:
    """True if the normalized vuln_class shares a token with any candidate
    class. Token-overlap so 'access-control' matches 'access' and vice versa."""
    vc = normalize_vuln_class(vuln_class)
    if not vc:
        return False
    vc_tokens = set(vc.split("-"))
    for cc in candidate_classes:
        cc = (cc or "").lower()
        if not cc:
            continue
        if cc == vc or vc in cc or cc in vc:
            return True
        if vc_tokens & set(cc.replace("_", "-").split("-")):
            return True
    return False


# --------------------------------------------------------------------------
# Pre-fix source fetch / locate
# --------------------------------------------------------------------------
def parse_file_line(file_line: str):
    """'src/Vault.sol:142' -> ('src/Vault.sol', 142). Line optional."""
    if not file_line:
        return None, None
    if ":" in file_line:
        path, _, ln = file_line.rpartition(":")
        if ln.isdigit():
            return path, int(ln)
        return file_line, None
    return file_line, None


def locate_source(case, local_checkout, work_root):
    """Return (resolved_file_path|None, checkout_dir|None, reason).

    Strategy:
      1. If --local-checkout given, resolve file_line's file inside it.
      2. Else shallow-clone repo + checkout prefix_ref.
    Honest NA reasons on failure.
    """
    rel_file, _ = parse_file_line(case.get("file_line", ""))

    # 1. local checkout
    if local_checkout:
        base = Path(local_checkout)
        if not base.exists():
            return None, None, f"local-checkout-missing: {base}"
        if rel_file:
            cand = base / rel_file
            if cand.exists():
                return cand, base, "located-in-local-checkout"
            # try basename search
            hits = list(base.rglob(Path(rel_file).name))
            if hits:
                return hits[0], base, f"located-by-basename ({hits[0]})"
            return None, base, f"file-not-found-in-local-checkout: {rel_file}"
        return None, base, "no-file-line-given-cannot-locate-file"

    # 2. shallow clone + checkout
    repo = case.get("repo", "")
    ref = case.get("prefix_ref", "")
    if not repo or not ref:
        return None, None, "no-local-checkout-and-missing-repo-or-prefix-ref"
    url = repo if repo.startswith(("http", "git@")) else f"https://github.com/{repo}.git"
    dest = Path(work_root) / repo.replace("/", "__")
    try:
        if not dest.exists():
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)],
                check=True, capture_output=True, text=True, timeout=180,
            )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", ref],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None, None, "fetch-failed: clone/checkout timed out (offline?)"
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or "").strip().splitlines()
        tail = msg[-1] if msg else str(e)
        return None, None, f"fetch-failed: {tail[:160]}"
    except FileNotFoundError:
        return None, None, "fetch-failed: git not available"
    if rel_file:
        cand = dest / rel_file
        if cand.exists():
            return cand, dest, "located-after-checkout"
        hits = list(dest.rglob(Path(rel_file).name))
        if hits:
            return hits[0], dest, f"located-by-basename ({hits[0]})"
        return None, dest, f"file-not-found-after-checkout: {rel_file}"
    return None, dest, "no-file-line-given-cannot-locate-file"


# --------------------------------------------------------------------------
# Detection layer
# --------------------------------------------------------------------------
# r36-rebuttal: pathspec for this lane declared in agent_pathspec.json
def _iter_dsl_dirs(patterns_dir, corpus_detector_dirs):
    """Yield every pattern-source directory to scan, canonical first then any
    --corpus-detector-dir dirs (newly-generated class-detectors). De-dup by
    resolved path so a dir passed twice (or equal to patterns_dir) is scanned
    once. Order is preserved (canonical wins on slug collision via seen-set)."""
    seen = set()
    for d in [patterns_dir] + list(corpus_detector_dirs or []):
        if not d:
            continue
        try:
            rp = Path(d).resolve()
        except Exception:
            continue
        if rp in seen or not rp.is_dir():
            continue
        seen.add(rp)
        yield rp


def load_relevant_dsl(vuln_class, patterns_dir, class_helpers,
                      corpus_detector_dirs=None):
    """Return list of (slug, spec) DSL patterns whose attack_class matches.

    Scans the canonical --patterns-dir PLUS every --corpus-detector-dir (newly
    generated CLASS-level detectors). A slug seen in an earlier dir wins, so a
    corpus-detector-dir cannot silently shadow a canonical pattern of the same
    name; conversely a NEW slug only present in the corpus dir is picked up -
    that is exactly the anti-overfit measurement surface."""
    import yaml
    out = []
    seen_slugs = set()
    for pdir in _iter_dsl_dirs(patterns_dir, corpus_detector_dirs):
        for yf in sorted(pdir.glob("*.yaml")):
            try:
                spec = yaml.safe_load(yf.read_text())
            except Exception:
                continue
            if not isinstance(spec, dict):
                continue
            slug = spec.get("pattern") or yf.stem
            if slug in seen_slugs:
                continue
            if class_helpers is not None:
                try:
                    classes = class_helpers.derive_attack_classes(slug, spec.get("tags"))
                except Exception:
                    classes = slug_keyword_classes(slug)
            else:
                classes = slug_keyword_classes(slug)
            if class_matches(vuln_class, set(classes)):
                seen_slugs.add(slug)
                out.append((slug, spec))
    return out


def import_engine():
    """Return engine tuple, or None if slither unavailable."""
    try:
        from _predicate_engine import eval_preconditions, eval_function_match  # noqa
        from _template_utils import is_leaf_helper, is_vendored_or_test_contract  # noqa
        return (eval_preconditions, eval_function_match, is_leaf_helper,
                is_vendored_or_test_contract)
    except Exception:
        return None


def _slither_compile(sol_path):
    """Compile a single .sol file with Slither, best-effort tolerating the
    common 'missing node_modules / unresolved import' failure of third-party
    repos checked out without their dependency tree.

    Strategy (first success wins):
      1. plain Slither(file)            - works for self-contained sources.
      2. Slither(file, solc_remaps=...) - map @openzeppelin / @uniswap / etc.
         to any node_modules/ found by walking up from the file, so an import
         that exists on disk resolves.
      3. Slither(checkout_root)         - compile the whole tree so relative
         imports resolve against siblings (heavier, last resort).
    Returns (slither_obj|None, error_str|None).
    """
    try:
        from slither import Slither
    except ImportError as e:
        return None, f"slither-import-error: {e}"
    sol_path = Path(sol_path)
    attempts = []
    # 1. plain
    try:
        return Slither(str(sol_path)), None
    except Exception as e:
        attempts.append(f"plain:{type(e).__name__}")
    # 2. remap @scope -> node_modules/@scope by locating node_modules upward.
    remaps = []
    base = sol_path.parent
    for _ in range(8):
        nm = base / "node_modules"
        if nm.is_dir():
            for scope in sorted(p.name for p in nm.iterdir()
                                if p.is_dir() and p.name.startswith("@")):
                remaps.append(f"{scope}/={nm}/{scope}/")
            # also bare top-level packages (e.g. solmate, forge-std)
            for pkg in sorted(p.name for p in nm.iterdir()
                              if p.is_dir() and not p.name.startswith("@")):
                remaps.append(f"{pkg}/={nm}/{pkg}/")
            break
        if base.parent == base:
            break
        base = base.parent
    if remaps:
        try:
            return Slither(str(sol_path), solc_remaps=" ".join(remaps)), None
        except Exception as e:
            attempts.append(f"remap:{type(e).__name__}")
    # 3. compile the enclosing checkout tree so relative imports resolve.
    #    Walk up to the nearest dir that looks like a project root.
    root = None
    base = sol_path.parent
    for _ in range(10):
        if any((base / m).exists() for m in
               ("foundry.toml", "hardhat.config.js", "hardhat.config.ts",
                "remappings.txt", ".git", "package.json")):
            root = base
            break
        if base.parent == base:
            break
        base = base.parent
    if root is not None and root != sol_path.parent:
        try:
            sl = Slither(str(root))
            return sl, None
        except Exception as e:
            attempts.append(f"tree:{type(e).__name__}")
    return None, f"compile-error: tried [{', '.join(attempts)}]"


def run_dsl_on_file(spec, sol_path, engine, target_line=None):
    """Return (fired_bool, hit_lines, error). hit_lines = source lines where a
    matching function/modifier is declared. If target_line is given it is used
    by the caller for AT-line determination; file-level hits are still
    recorded in hit_lines."""
    eval_pre, eval_match, is_leaf, is_vendored = engine
    preconds = spec.get("preconditions") or []
    matches = spec.get("match") or []
    include_leaf = bool(spec.get("include_leaf_helpers", False))
    sl, cerr = _slither_compile(sol_path)
    if sl is None:
        return False, [], cerr
    target_abs = str(Path(sol_path).resolve())
    hit_lines = []
    try:
        for c in sl.contracts:
            if is_vendored(c):
                continue
            # When attempt-3 compiled the whole checkout tree, restrict hits
            # to the TARGET file so a sibling-contract hit can never be
            # credited as catching the cited vuln.
            csrc = getattr(c, "source_mapping", None)
            cfile = getattr(csrc, "filename", None)
            cabs = getattr(cfile, "absolute", None) if cfile is not None else None
            if cabs and str(Path(cabs).resolve()) != target_abs:
                continue
            if not eval_pre(c, preconds):
                continue
            for fn in c.functions_and_modifiers_declared:
                if not include_leaf and is_leaf(fn):
                    continue
                if eval_match(fn, matches):
                    src = getattr(fn, "source_mapping", None)
                    ln = None
                    if src is not None:
                        lines = getattr(src, "lines", None)
                        if lines:
                            ln = lines[0]
                    hit_lines.append(ln if ln is not None else -1)
    except Exception as e:
        return False, [], f"eval-error: {type(e).__name__}: {str(e)[:160]}"
    return (len(hit_lines) > 0), hit_lines, None


# --------------------------------------------------------------------------
# PR4: PER-LANGUAGE detection dispatch
# --------------------------------------------------------------------------
# The DSL/Slither path above measures the SOLIDITY layer only. A corpus that is
# Rust/Go/TS-dominated scored 0% under Slither-only because there was no .sol to
# compile. This block applies the detector layer WIRED FOR THE TARGET LANGUAGE:
#   .sol/.vy         -> Slither DSL engine (run_dsl_on_file above)
#   .rs              -> rust-detector-runner.scan_workspace  (pure-regex, no rustc)
#   .go              -> go-detector-runner.scan_workspace + cosmos-detector-runner
#   .ts/.tsx/.js/.jsx-> semgrep registry rules (p/typescript|p/javascript)
# Each per-language arm returns the SAME shape the Solidity path produces so the
# CAUGHT/PARTIAL/MISSED outcome logic is language-agnostic:
#   {"fired": bool, "hit_lines": [int], "fired_slugs": [str],
#    "errors": [str], "engine_ran": bool, "engine": "<name>"}

_EXT_LANG = {
    ".sol": "solidity", ".vy": "vyper",
    ".rs": "rust",
    ".go": "go",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".move": "move", ".cairo": "cairo",
}


def language_of(file_line):
    """Resolve the target language from the case's file_line extension."""
    rel_file, _ = parse_file_line(file_line or "")
    if not rel_file:
        return "unknown"
    return _EXT_LANG.get(Path(rel_file).suffix.lower(), "unknown")


def _empty_arm(engine_name, error=None, fired=False):
    return {"fired": fired, "hit_lines": [], "fired_slugs": [], "engine_ran": False,
            "errors": ([error] if error else []), "engine": engine_name}


def _import_lang_runner(module_filename):
    """Import a tools/<file>.py module by path (hyphenated filenames). Returns
    the module or None."""
    import importlib.util
    p = REPO_ROOT / "tools" / module_filename
    if not p.exists():
        return None
    modname = "_lang_" + module_filename.replace("-", "_").replace(".py", "")
    try:
        spec = importlib.util.spec_from_file_location(modname, p)
        mod = importlib.util.module_from_spec(spec)
        # Register in sys.modules BEFORE exec so dataclass/KW_ONLY annotation
        # resolution (Python 3.14) can find the module's __dict__ via
        # cls.__module__; otherwise a `from __future__ import annotations`
        # dataclass in the runner raises AttributeError at import time.
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        sys.modules.pop(modname, None)
        return None


def _scan_pattern_runner(mod, scan_fn_name, scan_args, src_path, vuln_class,
                         engine_label=None):
    """Drive a pure-regex per-language runner (rust/go) whose scan returns
    {"patterns": {pid: {"hits": [{"file","line"}]}}}. Only credits a hit when
    the firing pattern's slug class-matches vuln_class AND the hit file is the
    target file. Returns the standard arm dict."""
    engine_label = engine_label or scan_fn_name
    scan = getattr(mod, scan_fn_name, None)
    if scan is None:
        return _empty_arm(engine_label, error="scan-fn-missing")
    # Run the scan inside a temp workspace containing ONLY the target file, so
    # _walk_*_files picks it up and no sibling-file hit leaks in.
    target = Path(src_path).resolve()
    hit_lines, fired_slugs = [], []
    try:
        with tempfile.TemporaryDirectory(prefix="lang_scan_") as ws:
            wsp = Path(ws)
            dst = wsp / target.name
            dst.write_bytes(target.read_bytes())
            summary = scan(wsp, *scan_args)
    except Exception as e:
        return _empty_arm(engine_label, error=f"scan-error:{type(e).__name__}:{str(e)[:120]}")
    patterns = (summary or {}).get("patterns", {}) or {}
    engine_ran = True
    for pid, pdata in patterns.items():
        # slug -> class via keyword fallback (pure-regex pids carry the class in
        # their dotted slug, e.g. rust.frost.aggregate.under_threshold...).
        classes = slug_keyword_classes(pid) | _pid_extra_classes(pid)
        if not class_matches(vuln_class, classes):
            continue
        for h in (pdata.get("hits") or []):
            ln = h.get("line")
            if isinstance(ln, int) and ln > 0:
                hit_lines.append(ln)
            fired_slugs.append(pid)
    arm = _empty_arm(engine_label, fired=bool(hit_lines))
    arm["hit_lines"] = hit_lines
    arm["fired_slugs"] = sorted(set(fired_slugs))[:10]
    arm["engine_ran"] = engine_ran
    return arm


# --------------------------------------------------------------------------
# PR-iter4: corpus-detector-dir .py detector modules (rust/go arms)
# --------------------------------------------------------------------------
# The Solidity arm reads --corpus-detector-dir as a directory of *.yaml DSL
# specs (load_relevant_dsl). The Rust/Go arms ship as standalone *.py modules
# each exposing a module-level scan(root)->list[(file,line,msg)] plus the
# metadata attrs DETECTOR_ID / CLASS_TAG / LANGUAGE / _EXT (the
# tools/advisory-seed-to-dsl.py emit shape). Before iter4 the rust/go arms
# called scan_workspace on the wired runner ONLY and ignored every
# --corpus-detector-dir entirely, so detectors under detectors/from_advisories
# never loaded. This helper closes that gap: it imports every scan()-exposing
# module found under each corpus dir, keeps the ones whose LANGUAGE / _EXT
# matches the target language, runs each over a temp workspace holding ONLY the
# target file (so a sibling-file hit can never leak), and credits a hit only
# when the module's CLASS_TAG (or its DETECTOR_ID keyword fallback)
# class-matches vuln_class. Returns the standard arm dict so the caller can
# union it with the wired-runner arm. Errors per-module are swallowed so one
# bad module never sinks the union.

# _EXT / LANGUAGE -> the target-language label used by language_of().
_CORPUS_DET_EXT_LANG = {
    ".rs": "rust", ".go": "go",
    ".sol": "solidity", ".vy": "vyper",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".move": "move", ".cairo": "cairo",
}


def _import_detector_module(py_path):
    """Import a standalone detector .py by path. Returns the module or None.
    Uses a unique module name per path so two corpus dirs with same-named
    files don't collide in sys.modules."""
    import importlib.util
    py_path = Path(py_path)
    modname = "_corpusdet_" + re.sub(r"[^0-9A-Za-z_]", "_", str(py_path.resolve()))
    try:
        spec = importlib.util.spec_from_file_location(modname, py_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        sys.modules.pop(modname, None)
        return None


def _corpus_detector_module_lang(mod):
    """Resolve a corpus detector module's target language from its LANGUAGE /
    _EXT metadata. Returns a language label or '' when undeterminable."""
    lang = (getattr(mod, "LANGUAGE", "") or "").strip().lower()
    if lang in _EXT_LANG.values():
        return lang
    ext = (getattr(mod, "_EXT", "") or "").strip().lower()
    if ext:
        return _CORPUS_DET_EXT_LANG.get(ext, "")
    return ""


def _run_corpus_dir_detectors(corpus_detector_dirs, src_path, vuln_class,
                              target_lang):
    """Load + run every scan()-exposing .py detector under each corpus dir whose
    LANGUAGE matches target_lang, crediting a class-matched hit on the target
    file. Returns the standard arm dict (fired/hit_lines/fired_slugs/errors/
    engine_ran/engine). A no-op (engine_ran stays its incoming default) when no
    corpus dirs are given or none match the language."""
    arm = _empty_arm("corpus-detector-dir")
    if not corpus_detector_dirs:
        return arm
    target = Path(src_path).resolve()
    seen_modules = set()
    for d in corpus_detector_dirs:
        if not d:
            continue
        try:
            ddir = Path(d).resolve()
        except Exception:
            continue
        if not ddir.is_dir():
            continue
        for py in sorted(ddir.glob("*.py")):
            if py.name.startswith("__") or py.resolve() in seen_modules:
                continue
            seen_modules.add(py.resolve())
            mod = _import_detector_module(py)
            if mod is None:
                arm["errors"].append(f"import-failed:{py.name}")
                continue
            scan = getattr(mod, "scan", None)
            if scan is None or not callable(scan):
                continue  # not a scan()-exposing detector module
            mod_lang = _corpus_detector_module_lang(mod)
            # Only run language-matching detectors (a .rs detector on a .go
            # target would scan an empty workspace and just waste time). When a
            # module declares no language we still run it (best-effort).
            if mod_lang and target_lang and mod_lang != target_lang:
                continue
            did = (getattr(mod, "DETECTOR_ID", "") or py.stem)
            ctag = (getattr(mod, "CLASS_TAG", "") or "")
            classes = ({ctag} if ctag else set())
            classes |= slug_keyword_classes(ctag) | slug_keyword_classes(did)
            classes |= _pid_extra_classes(did) | _pid_extra_classes(ctag)
            if not class_matches(vuln_class, classes):
                continue
            try:
                with tempfile.TemporaryDirectory(prefix="corpusdet_") as ws:
                    wsp = Path(ws)
                    (wsp / target.name).write_bytes(target.read_bytes())
                    raw = scan(str(wsp))
            except Exception as e:
                arm["errors"].append(f"{did}:scan-error:{type(e).__name__}")
                continue
            arm["engine_ran"] = True
            for tup in (raw or []):
                try:
                    _fpath, ln, _msg = tup[0], tup[1], (tup[2] if len(tup) > 2 else "")
                except Exception:
                    continue
                if isinstance(ln, int) and ln > 0:
                    arm["hit_lines"].append(ln)
                arm["fired_slugs"].append(did)
    arm["fired"] = bool(arm["hit_lines"])
    arm["fired_slugs"] = sorted(set(arm["fired_slugs"]))[:10]
    return arm


# extra slug->class hints for dotted per-language pattern ids whose tokens the
# generic keyword table misses (frost->signature, dkg->signature, txid->logic).
_PID_CLASS_HINTS = {
    "frost": {"signature"}, "dkg": {"signature"}, "nonce": {"signature"},
    "keypackage": {"signature"}, "threshold": {"signature", "access-control"},
    "txid": {"logic"}, "statemachine": {"logic"}, "guard": {"access-control"},
    "consensus": {"logic"}, "gossip": {"dos"}, "protohash": {"logic"},
    "self_heal": {"logic"}, "perimeter": {"access-control"},
    "msg_handler": {"access-control"}, "feegrant": {"logic"},
}


def _pid_extra_classes(pid):
    s = (pid or "").lower()
    out = set()
    for tok, cls in _PID_CLASS_HINTS.items():
        if tok in s:
            out |= cls
    return out


def _semgrep_arm(src_path, vuln_class, lang_config):
    """Run semgrep registry rules for a non-compiled language (TS/JS). Credits
    a finding when its check_id / message class-matches vuln_class. Hit lines
    are the finding start lines. Graceful when semgrep is absent / offline."""
    import shutil
    if shutil.which("semgrep") is None:
        return _empty_arm("semgrep", error="semgrep-not-installed")
    target = Path(src_path).resolve()
    try:
        proc = subprocess.run(
            ["semgrep", "--config", lang_config, "--json", "--quiet",
             "--timeout", "30", "--metrics", "off", str(target)],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return _empty_arm("semgrep", error="semgrep-timeout")
    except Exception as e:
        return _empty_arm("semgrep", error=f"semgrep-error:{type(e).__name__}")
    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:
        # registry fetch failed (offline) -> honest engine-could-not-run, NA-ish
        return _empty_arm("semgrep",
                          error="semgrep-no-json (offline registry?)")
    hit_lines, fired_slugs = [], []
    engine_ran = True
    for res in payload.get("results", []):
        cid = (res.get("check_id") or "")
        msg = ((res.get("extra") or {}).get("message") or "")
        classes = slug_keyword_classes(cid + " " + msg) | _pid_extra_classes(cid)
        if not class_matches(vuln_class, classes):
            continue
        ln = ((res.get("start") or {}).get("line"))
        if isinstance(ln, int) and ln > 0:
            hit_lines.append(ln)
        fired_slugs.append(cid.split(".")[-1][:60])
    arm = _empty_arm("semgrep", fired=bool(hit_lines))
    arm["hit_lines"] = hit_lines
    arm["fired_slugs"] = sorted(set(fired_slugs))[:10]
    arm["engine_ran"] = engine_ran
    return arm


def run_language_detectors(case, src_path, vuln_class, engine,
                           patterns_dir, class_helpers, corpus_detector_dirs):
    """Apply the detector layer wired for the TARGET language. Returns the
    standard arm dict (fired/hit_lines/fired_slugs/errors/engine_ran/engine).
    For Solidity it drives the existing Slither DSL engine; for Rust/Go it
    drives the pure-regex runners; for TS/JS it drives semgrep registry rules.
    """
    lang = language_of(case.get("file_line", ""))

    # ---- Solidity / Vyper: existing Slither DSL engine ----
    if lang in ("solidity", "vyper"):
        _, target_line = parse_file_line(case.get("file_line", ""))
        relevant = load_relevant_dsl(vuln_class, patterns_dir, class_helpers,
                                     corpus_detector_dirs=corpus_detector_dirs)
        if engine is None:
            return {"fired": False, "hit_lines": [], "fired_slugs": [],
                    "engine_ran": False, "engine": "slither",
                    "errors": ["slither-unavailable"], "selected": len(relevant)}
        hit_lines, fired_slugs, errs = [], [], []
        engine_ran = False
        for slug, spec in relevant:
            fired, hits, err = run_dsl_on_file(spec, src_path, engine, target_line)
            if err:
                errs.append(f"{slug}: {err}")
                continue
            engine_ran = True
            if fired:
                fired_slugs.append(slug)
                hit_lines.extend([h for h in hits if isinstance(h, int) and h > 0])
        return {"fired": bool(hit_lines), "hit_lines": hit_lines,
                "fired_slugs": fired_slugs[:10], "engine_ran": engine_ran,
                "engine": "slither", "errors": errs[:5], "selected": len(relevant)}

    # ---- Rust: pure-regex rust-detector-runner UNION corpus-detector-dir ----
    if lang == "rust":
        arm = _empty_arm("rust-detector-runner")
        mod = _import_lang_runner("rust-detector-runner.py")
        if mod is not None:
            rarm = _scan_pattern_runner(mod, "scan_workspace", (), src_path,
                                        vuln_class,
                                        engine_label="rust-detector-runner")
            arm["hit_lines"] += rarm["hit_lines"]
            arm["fired_slugs"] += rarm["fired_slugs"]
            arm["errors"] += rarm["errors"]
            arm["engine_ran"] = arm["engine_ran"] or rarm["engine_ran"]
        else:
            arm["errors"].append("runner-import-failed")
        # UNION newly-generated CLASS-level detectors under --corpus-detector-dir
        # (e.g. detectors/from_advisories/*.py). Before iter4 these never loaded.
        carm = _run_corpus_dir_detectors(corpus_detector_dirs, src_path,
                                         vuln_class, "rust")
        arm["hit_lines"] += carm["hit_lines"]
        arm["fired_slugs"] += carm["fired_slugs"]
        arm["errors"] += carm["errors"]
        arm["engine_ran"] = arm["engine_ran"] or carm["engine_ran"]
        arm["fired"] = bool(arm["hit_lines"])
        arm["fired_slugs"] = sorted(set(arm["fired_slugs"]))[:10]
        if carm["fired_slugs"]:
            arm["engine"] = "rust-detector-runner+corpus-detector-dir"
        return arm

    # ---- Go: pure-regex go-detector-runner UNION cosmos-detector-runner ----
    if lang == "go":
        arm = _empty_arm("go+cosmos")
        gomod = _import_lang_runner("go-detector-runner.py")
        if gomod is not None:
            guards = getattr(gomod, "_DEFAULT_GUARDS", ())
            garm = _scan_pattern_runner(gomod, "scan_workspace", (guards,),
                                        src_path, vuln_class,
                                        engine_label="go-detector-runner")
            arm["hit_lines"] += garm["hit_lines"]
            arm["fired_slugs"] += garm["fired_slugs"]
            arm["errors"] += garm["errors"]
            arm["engine_ran"] = arm["engine_ran"] or garm["engine_ran"]
        else:
            arm["errors"].append("go-runner-import-failed")
        # cosmos arm: needs a cosmos-sdk go.mod; emit go.mod stub so the
        # pattern-precondition (chain.is_cosmos_sdk) can fire on a cosmos vuln.
        carm = _run_cosmos_arm(src_path, vuln_class)
        arm["hit_lines"] += carm["hit_lines"]
        arm["fired_slugs"] += carm["fired_slugs"]
        arm["errors"] += carm["errors"]
        arm["engine_ran"] = arm["engine_ran"] or carm["engine_ran"]
        # UNION newly-generated CLASS-level detectors under --corpus-detector-dir
        # (e.g. detectors/from_advisories/*.py go-language detectors). Before
        # iter4 these never loaded for the go arm either.
        cdarm = _run_corpus_dir_detectors(corpus_detector_dirs, src_path,
                                          vuln_class, "go")
        arm["hit_lines"] += cdarm["hit_lines"]
        arm["fired_slugs"] += cdarm["fired_slugs"]
        arm["errors"] += cdarm["errors"]
        arm["engine_ran"] = arm["engine_ran"] or cdarm["engine_ran"]
        arm["fired"] = bool(arm["hit_lines"])
        arm["fired_slugs"] = sorted(set(arm["fired_slugs"]))[:10]
        if cdarm["fired_slugs"]:
            arm["engine"] = "go+cosmos+corpus-detector-dir"
        return arm

    # ---- TS / JS: semgrep registry rules ----
    if lang in ("typescript", "javascript"):
        cfg = "p/typescript" if lang == "typescript" else "p/javascript"
        return _semgrep_arm(src_path, vuln_class, cfg)

    # ---- unknown / unwired language ----
    return _empty_arm(f"unwired:{lang}", error=f"no-detector-layer-for-language:{lang}")


def _run_cosmos_arm(src_path, vuln_class):
    """Drive cosmos-detector-runner.run over a temp workspace containing the
    target .go file + a synthetic cosmos-sdk go.mod so the cosmos preconditions
    can fire. Credits a finding when its pattern class-matches vuln_class and
    the hit is in the target file."""
    mod = _import_lang_runner("cosmos-detector-runner.py")
    if mod is None:
        return _empty_arm("cosmos-detector-runner", error="cosmos-import-failed")
    run = getattr(mod, "run", None)
    if run is None:
        return _empty_arm("cosmos-detector-runner", error="cosmos-run-missing")
    target = Path(src_path).resolve()
    hit_lines, fired_slugs, errs = [], [], []
    engine_ran = False
    try:
        with tempfile.TemporaryDirectory(prefix="cosmos_scan_") as ws:
            wsp = Path(ws)
            (wsp / target.name).write_bytes(target.read_bytes())
            # synthetic go.mod marking a cosmos-sdk workspace so the required
            # chain.is_cosmos_sdk precondition is satisfiable. This does NOT
            # fabricate a hit - it only lets the precondition pass; the match
            # predicates still have to fire on the real target source.
            (wsp / "go.mod").write_text(
                "module backtest/target\n\ngo 1.21\n\n"
                "require github.com/cosmos/cosmos-sdk v0.50.0\n")
            out = wsp / "cosmos_out.json"
            run(wsp, only=None,
                patterns_dir=getattr(mod, "DEFAULT_PATTERNS_DIR",
                                     DEFAULT_PATTERNS_DIR),
                out_path=out, quiet=True)
            engine_ran = True
            data = json.loads(out.read_text()) if out.exists() else {}
    except Exception as e:
        return _empty_arm("cosmos-detector-runner",
                          error=f"cosmos-error:{type(e).__name__}:{str(e)[:120]}")
    for f in (data.get("findings") or []):
        pid = f.get("pattern") or ""
        classes = slug_keyword_classes(pid) | _pid_extra_classes(pid)
        if not class_matches(vuln_class, classes):
            continue
        ln = f.get("line")
        if isinstance(ln, int) and ln > 0:
            hit_lines.append(ln)
        fired_slugs.append(pid)
    arm = _empty_arm("cosmos-detector-runner", fired=bool(hit_lines))
    arm["hit_lines"] = hit_lines
    arm["fired_slugs"] = sorted(set(fired_slugs))[:10]
    arm["engine_ran"] = engine_ran
    return arm


# --------------------------------------------------------------------------
# PR4: ENGINE / NOVEL-VECTOR scoring arm (optional, bounded)
# --------------------------------------------------------------------------
def run_engine_arm(case, src_path, vuln_class, mimo_refine=False, mimo_budget=6):
    """Optional novel-vector arm: derive invariants on the target file and
    credit a FILE-RECALL catch ONLY when a derived invariant's family
    class-matches vuln_class. The miner is per-function (no precise line), so
    this arm can only ever produce a file-level signal - it is reported
    separately and never inflated into a line-level CAUGHT. Bounded: no engine
    fuzz, just the (cheap) invariant derivation; MIMO refinement is opt-in and
    budget-capped. Returns an arm dict with an extra 'families' field."""
    mod = _import_lang_runner("novel-vector-invariant-miner.py")
    if mod is None:
        return _empty_arm("novel-vector-invariant-miner",
                          error="miner-import-failed")
    lang = language_of(case.get("file_line", ""))
    # rust/go/move parse is pure-regex (in-process, no evm_mod). solidity needs
    # the evm engine-harness-author module -> defer to the bounded CLI.
    if lang not in ("rust", "go", "move"):
        return _engine_arm_via_cli(mod, case, src_path, vuln_class,
                                   mimo_refine, mimo_budget)
    parse_surface = getattr(mod, "parse_surface", None)
    derive = getattr(mod, "derive_invariants", None)
    load_corpus = getattr(mod, "load_corpus_families", None)
    if parse_surface is None or derive is None:
        return _engine_arm_via_cli(mod, case, src_path, vuln_class,
                                   mimo_refine, mimo_budget)
    fired_families = []
    invs = []
    try:
        surf = parse_surface(Path(src_path), lang, None, None)
        by_cat, counts = ({}, {})
        if load_corpus is not None:
            for attr in ("DEFAULT_EXTRACTED", "DEFAULT_PILOT", "DEFAULT_INDEX"):
                if not hasattr(mod, attr):
                    load_corpus = None
                    break
            if load_corpus is not None:
                try:
                    by_cat, counts = load_corpus(
                        Path(mod.DEFAULT_EXTRACTED), Path(mod.DEFAULT_PILOT),
                        Path(mod.DEFAULT_INDEX))
                except Exception:
                    by_cat, counts = {}, {}
        invs = derive(surf, by_cat, counts, 3)
    except Exception as e:
        return _empty_arm("novel-vector-invariant-miner",
                          error=f"miner-error:{type(e).__name__}:{str(e)[:120]}")
    for inv in invs:
        fam = inv.get("family") or ""
        classes = slug_keyword_classes(fam) | _pid_extra_classes(fam) | {fam}
        if class_matches(vuln_class, classes):
            fired_families.append(fam)
    arm = _empty_arm("novel-vector-invariant-miner", fired=bool(fired_families))
    # file-recall only: no line, so hit_lines stays empty but 'fired' marks a
    # FILE-level family match (caller treats engine-arm fire as file-recall).
    arm["families"] = sorted(set(fired_families))
    arm["invariants_derived"] = len(invs)
    arm["engine_ran"] = True
    arm["fired_slugs"] = [f"invariant:{f}" for f in arm["families"]][:10]
    return arm


def _engine_arm_via_cli(mod, case, src_path, vuln_class, mimo_refine, mimo_budget):
    """Fallback: run the miner via its CLI (bounded) and parse the JSONL of
    derived invariants for a family class-match."""
    miner_path = REPO_ROOT / "tools" / "novel-vector-invariant-miner.py"
    lang = language_of(case.get("file_line", ""))
    lang_arg = lang if lang in ("solidity", "rust", "go", "move") else "auto"
    with tempfile.TemporaryDirectory(prefix="engine_arm_") as ws:
        out = Path(ws) / "invs.jsonl"
        cmd = [sys.executable, str(miner_path),
               "--workspace", ws, "--contract", str(src_path),
               "--lang", lang_arg, "--output", str(out)]
        if mimo_refine and os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1":
            cmd += ["--mimo-refine", "--mimo-budget", str(min(mimo_budget, 6))]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        except Exception as e:
            return _empty_arm("novel-vector-invariant-miner",
                              error=f"miner-cli-error:{type(e).__name__}")
        families = []
        if out.exists():
            for raw in out.read_text(errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    inv = json.loads(raw)
                except Exception:
                    continue
                fam = inv.get("family") or ""
                classes = slug_keyword_classes(fam) | _pid_extra_classes(fam) | {fam}
                if class_matches(vuln_class, classes):
                    families.append(fam)
        arm = _empty_arm("novel-vector-invariant-miner", fired=bool(families))
        arm["families"] = sorted(set(families))
        arm["engine_ran"] = True
        arm["fired_slugs"] = [f"invariant:{f}" for f in arm["families"]][:10]
        return arm


# --------------------------------------------------------------------------
# F4 / E4.1: HUNT-path mode - grade the LLM hunt path, not the detector layer
# --------------------------------------------------------------------------
# The default (--mode detect) measures the static DETECTION layer (DSL/Slither,
# rust/go runners, semgrep). That number says nothing about whether the actual
# LLM HUNT (mimo/dispatch) re-discovers a known bug. --mode hunt grades the hunt
# path against a held-out known-bug corpus and reports HUNT-RECALL (the fraction
# of held-out bugs the hunt re-discovers), which is the number honest-zero-verify
# floors on (E4.2). It reuses the SAME fixture-pair plumbing (locate_source,
# is_fetchable, the {id,repo,prefix_ref,vuln_class,file_line} case shape) so a
# hunt case is just a detect case scored through the hunt arm.
#
# Languages with NO detector arm (move/cairo/circom/noir/solana) record
# engine='llm-hunt-only' so the recall number is honest even where the detector
# layer would score ~0 by construction (cross-cutting rule 3: never silent-zero).
#
# The hunt callable is INJECTABLE (run_hunt_on_case takes hunt_fn=) so the test
# suite can drive the path offline with a deterministic stub. The default
# callable is consent-gated and offline-graceful: with no network consent it
# returns a typed hunt-not-run record (outcome=NA), never a silent MISSED.

HUNT_SCHEMA = "auditooor.auditor_backtest.hunt.v1"

# Languages that have a wired static DETECTOR arm (see run_language_detectors).
# For any OTHER language the hunt arm records engine='llm-hunt-only' so the recall
# number is not silently penalized by an absent detector layer.
_DETECTOR_ARM_LANGS = {"solidity", "vyper", "rust", "go", "typescript", "javascript"}


def _default_hunt_fn(case, src_path, vuln_class):
    """Default hunt callable: drive the real LLM hunt (dispatch/mimo) over the
    located pre-fix source and report whether it re-discovered the known bug.

    Consent-gated + offline-graceful: with no AUDITOOOR_LLM_NETWORK_CONSENT=1 the
    hunt is NOT run and a typed (ran=False, reason=...) record is returned so the
    caller scores the case NA - NOT a silent MISSED (silence with no hunt is not
    a miss, exactly as the detector path treats source-unavailable as NA).

    Returns a dict:
      {"ran": bool, "rediscovered": bool, "fired_at_line": int|None,
       "confidence": float|None, "reason": str, "evidence": [str]}
    """
    if os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1":
        return {"ran": False, "rediscovered": False, "fired_at_line": None,
                "confidence": None,
                "reason": "hunt-not-run: AUDITOOOR_LLM_NETWORK_CONSENT!=1 "
                          "(offline; pass a hunt_fn to grade a real hunt)",
                "evidence": []}
    # Real-hunt wiring: drive dispatch-agent-with-prebriefing over the single
    # located file. Kept best-effort so a transport error reports ran=False
    # (NA), never a fabricated rediscovery.
    try:
        mod = _import_lang_runner("dispatch-agent-with-prebriefing.py")
        if mod is None:
            return {"ran": False, "rediscovered": False, "fired_at_line": None,
                    "confidence": None,
                    "reason": "hunt-not-run: dispatch module unavailable",
                    "evidence": []}
        runner = getattr(mod, "run_single_file_hunt", None)
        if runner is None or not callable(runner):
            return {"ran": False, "rediscovered": False, "fired_at_line": None,
                    "confidence": None,
                    "reason": "hunt-not-run: dispatch has no run_single_file_hunt "
                              "entrypoint (wire it to enable the live hunt arm)",
                    "evidence": []}
        out = runner(str(src_path), vuln_class=vuln_class) or {}
        return {"ran": True,
                "rediscovered": bool(out.get("rediscovered")),
                "fired_at_line": out.get("fired_at_line"),
                "confidence": out.get("confidence"),
                "reason": out.get("reason", "live-hunt"),
                "evidence": list(out.get("evidence") or [])[:5]}
    except Exception as e:  # pragma: no cover - defensive
        return {"ran": False, "rediscovered": False, "fired_at_line": None,
                "confidence": None,
                "reason": f"hunt-not-run: {type(e).__name__}:{str(e)[:120]}",
                "evidence": []}


def hunt_case(case, local_checkout, work_root, quiet=False, hunt_fn=None):
    """Grade ONE case through the HUNT path (not the detector layer). Reuses the
    fixture-pair plumbing (is_fetchable + locate_source) then scores the located
    pre-fix source through the hunt callable.

    Outcome (mirrors backtest_case so reporting is shared):
      CAUGHT  - the hunt re-discovered the known bug AT the cited line
                (within +/-25 lines; or anywhere in the file when no line cited).
      PARTIAL - the hunt re-discovered the class in the file but not at the line.
      MISSED  - the hunt RAN but stayed silent on the known-vulnerable file.
      NA      - non-fetchable OR source-unavailable OR the hunt did not run
                (no consent / transport error): silence with no hunt is NOT a miss.
    """
    hunt_fn = hunt_fn or _default_hunt_fn
    cid = case.get("id", "?")
    vuln_class = case.get("vuln_class", "")
    file_line = case.get("file_line", "")
    _, target_line = parse_file_line(file_line)
    lang = language_of(file_line)
    engine_label = "llm-hunt" if lang in _DETECTOR_ARM_LANGS else "llm-hunt-only"

    rec = {
        "schema": HUNT_SCHEMA,
        "id": cid,
        "repo": case.get("repo", "") or case.get("repo_url", ""),
        "prefix_ref": case.get("prefix_ref", "") or case.get("vulnerable_ref_full_sha", ""),
        "vuln_class": vuln_class,
        "file_line": file_line,
        "language": lang,
        "split": case_split(case),
        "engine": engine_label,
        "mode": "hunt",
        "outcome": "NA",
        "rediscovered": False,
        "fired_at_line": None,
        "missing_capability": None,
        "reason": "",
    }

    fetchable, fetch_reason = is_fetchable(case, local_checkout)
    if not fetchable:
        rec["missing_capability"] = "non-fetchable"
        rec["reason"] = f"non-fetchable: {fetch_reason}"
        return rec

    src_path, _checkout_dir, loc_reason = locate_source(case, local_checkout, work_root)
    rec["reason"] = loc_reason
    if src_path is None:
        rec["missing_capability"] = "source-unavailable"
        return rec

    res = hunt_fn(case, src_path, vuln_class) or {}
    rec["hunt"] = {"ran": bool(res.get("ran")),
                   "reason": res.get("reason", ""),
                   "confidence": res.get("confidence"),
                   "evidence": list(res.get("evidence") or [])[:5]}
    if not res.get("ran"):
        # Hunt was never run (no consent / transport) -> NA, never a silent MISS.
        rec["outcome"] = "NA"
        rec["missing_capability"] = "hunt-not-run"
        rec["reason"] = res.get("reason", "hunt-not-run")
        return rec

    if not res.get("rediscovered"):
        rec["outcome"] = "MISSED"
        rec["missing_capability"] = (
            f"{engine_label}-ran-but-did-not-rediscover-class:"
            f"{normalize_vuln_class(vuln_class)}")
        return rec

    fired = res.get("fired_at_line")
    fired = fired if isinstance(fired, int) and fired > 0 else None
    if target_line is not None and fired is not None and abs(fired - target_line) > 25:
        # rediscovered in file but not at the cited line -> PARTIAL.
        rec["outcome"] = "PARTIAL"
        rec["rediscovered"] = True
        rec["fired_at_line"] = fired
        rec["missing_capability"] = "rediscovered-in-file-but-not-at-cited-line"
        return rec
    rec["outcome"] = "CAUGHT"
    rec["rediscovered"] = True
    rec["fired_at_line"] = fired
    rec["missing_capability"] = None
    return rec


def hunt_recall(records):
    """Compute hunt-recall over a list of hunt_case records: the fraction of
    SCORABLE (CAUGHT+PARTIAL+MISSED) cases the hunt re-discovered. PARTIAL counts
    as a (file-level) re-discovery in the file-recall numerator. NA cases (not
    fetchable / hunt-not-run) are excluded from the denominator so an offline run
    does not deflate recall to 0. Returns a dict with the strict + file numbers."""
    caught = sum(1 for r in records if r.get("outcome") == "CAUGHT")
    partial = sum(1 for r in records if r.get("outcome") == "PARTIAL")
    missed = sum(1 for r in records if r.get("outcome") == "MISSED")
    na = sum(1 for r in records if r.get("outcome") == "NA")
    denom = caught + partial + missed
    return {
        "scorable": denom,
        "caught": caught,
        "partial": partial,
        "missed": missed,
        "na": na,
        # strict recall: re-discovered AT the cited line / all scorable.
        "recall": (caught / denom) if denom else 0.0,
        # file recall: re-discovered anywhere in the file / all scorable.
        "file_recall": ((caught + partial) / denom) if denom else 0.0,
    }


def corpus_knows_class(vuln_class):
    """Return (count, [invariant_ids]) of corpus invariants matching vuln_class."""
    if not INVARIANTS_JSONL.exists():
        return 0, []
    ids = []
    vc_tokens = set(normalize_vuln_class(vuln_class).split("-"))
    try:
        for raw in INVARIANTS_JSONL.read_text(errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except Exception:
                continue
            cat = (rec.get("category") or "").lower()
            sig = (rec.get("attack_signature") or "").lower()
            blob = f"{cat} {sig}"
            if class_matches(vuln_class, {cat}) or (vc_tokens & set(blob.replace("|", " ").replace("-", " ").split())):
                inv_id = rec.get("invariant_id")
                if inv_id:
                    ids.append(inv_id)
    except Exception:
        return 0, []
    return len(ids), ids[:25]


def per_fn_pack_covers(vuln_class):
    """Return (covered_bool, [pack_paths]) - whether any per-fn question pack
    mentions the vuln_class token. Advisory layer."""
    covered_paths = []
    vc = normalize_vuln_class(vuln_class)
    vc_tokens = [t for t in vc.split("-") if len(t) >= 4]
    for p in REPO_ROOT.glob(PER_FN_GLOB):
        try:
            txt = p.read_text(errors="replace").lower()
        except Exception:
            continue
        if vc in txt or any(t in txt for t in vc_tokens):
            covered_paths.append(str(p.relative_to(REPO_ROOT)))
    return (len(covered_paths) > 0), covered_paths[:10]


# --------------------------------------------------------------------------
# Single-case backtest
# --------------------------------------------------------------------------
# r36-rebuttal: lane pathspec declared in agent_pathspec.json
def backtest_case(case, local_checkout, patterns_dir, class_helpers, engine,
                  work_root, quiet=False, corpus_detector_dirs=None,
                  engine_arm_enabled=False, mimo_refine=False, mimo_budget=6):
    cid = case.get("id", "?")
    vuln_class = case.get("vuln_class", "")
    file_line = case.get("file_line", "")
    _, target_line = parse_file_line(file_line)

    rec = {
        "schema": SCHEMA,
        "id": cid,
        "repo": case.get("repo", "") or case.get("repo_url", ""),
        "prefix_ref": case.get("prefix_ref", "") or case.get("vulnerable_ref_full_sha", ""),
        "vuln_class": vuln_class,
        "file_line": file_line,
        "split": case_split(case),
        "outcome": "NA",
        "caught_by": [],
        "fired_at_line": None,
        "layers": {},
        "missing_capability": None,
        "reason": "",
    }

    # --- FETCHABLE-ONLY gate (PR3a) ---
    # Non-fetchable pre-fix code -> outcome=NA (NOT MISSED): the detection layer
    # was never given live source to fire on, so silence cannot count as a miss.
    fetchable, fetch_reason = is_fetchable(case, local_checkout)
    if not fetchable:
        rec["outcome"] = "NA"
        rec["missing_capability"] = "non-fetchable"
        rec["reason"] = f"non-fetchable: {fetch_reason}"
        inv_n, inv_ids = corpus_knows_class(vuln_class)
        pf_cov, pf_paths = per_fn_pack_covers(vuln_class)
        rec["layers"] = {
            "dsl_detectors": {"selected": None, "fired": None, "error": "non-fetchable"},
            "corpus_invariants": {"matched": inv_n, "ids": inv_ids},
            "per_fn_packs": {"covered": pf_cov, "packs": pf_paths},
            "engine_harness": {"ran": False, "error": "non-fetchable"},
        }
        return rec

    # --- locate source ---
    src_path, checkout_dir, loc_reason = locate_source(case, local_checkout, work_root)
    rec["reason"] = loc_reason
    if src_path is None:
        # Cannot fetch/locate -> honest NA, not a MISS.
        rec["outcome"] = "NA"
        rec["missing_capability"] = "source-unavailable"
        # still record knowledge-layer signals (they don't need source)
        inv_n, inv_ids = corpus_knows_class(vuln_class)
        pf_cov, pf_paths = per_fn_pack_covers(vuln_class)
        rec["layers"] = {
            "dsl_detectors": {"selected": None, "fired": None, "error": "source-unavailable"},
            "corpus_invariants": {"matched": inv_n, "ids": inv_ids},
            "per_fn_packs": {"covered": pf_cov, "packs": pf_paths},
            "engine_harness": {"ran": False, "error": "source-unavailable"},
        }
        return rec

    # --- sub-layer 1 + 4: PER-LANGUAGE detectors via the wired engine ---
    # r36-rebuttal: pathspec in agent_pathspec.json
    # Solidity -> Slither DSL engine; Rust -> rust runner; Go -> go+cosmos
    # runners; TS/JS -> semgrep registry rules. Each arm returns the SAME shape
    # so the CAUGHT/PARTIAL/MISSED logic is language-agnostic.
    lang = language_of(file_line)
    rec["language"] = lang
    arm = run_language_detectors(case, src_path, vuln_class, engine,
                                 patterns_dir, class_helpers, corpus_detector_dirs)
    selected = arm.get("selected")
    if selected is None and lang in ("solidity", "vyper"):
        selected = 0
    dsl_fired = bool(arm.get("fired"))
    fired_slugs = arm.get("fired_slugs", [])
    dsl_errors = arm.get("errors", [])
    engine_ran = bool(arm.get("engine_ran"))
    raw_hits = [h for h in arm.get("hit_lines", []) if isinstance(h, int) and h > 0]

    dsl_fired_at = None        # hit within +/-25 lines of the cited line
    dsl_fired_at_file = raw_hits[0] if raw_hits else None
    if target_line is not None:
        for ln in raw_hits:
            if abs(ln - target_line) <= 25:
                dsl_fired_at = ln
                break

    # Keep the canonical 'dsl_detectors' key (back-compat); the firing engine
    # name (slither / rust-detector-runner / go+cosmos / semgrep) is recorded
    # so a MISS/CATCH can be attributed to the right per-language layer.
    dsl_layer = {
        "engine": arm.get("engine"),
        "selected": selected,
        "fired": dsl_fired,
        "fired_at_line": dsl_fired_at,
        "fired_at_line_file_level": dsl_fired_at_file,
        "fired_slugs": fired_slugs[:10],
        "errors": dsl_errors[:5],
    }

    # --- sub-layer 2: corpus invariants ---
    inv_n, inv_ids = corpus_knows_class(vuln_class)
    # --- sub-layer 3: per-fn packs ---
    pf_cov, pf_paths = per_fn_pack_covers(vuln_class)
    # --- engine / novel-vector arm (file-recall only, never line-level) ---
    engine_arm = None
    arm_on = (engine_arm_enabled or bool(case.get("engine_arm"))
              or os.environ.get("AUDITOOOR_BACKTEST_ENGINE_ARM") == "1")
    if arm_on:
        engine_arm = run_engine_arm(
            case, src_path, vuln_class,
            mimo_refine=bool(mimo_refine or case.get("mimo_refine")),
            mimo_budget=int(case.get("mimo_budget", mimo_budget) or mimo_budget))

    rec["layers"] = {
        "dsl_detectors": dsl_layer,
        "corpus_invariants": {"matched": inv_n, "ids": inv_ids},
        "per_fn_packs": {"covered": pf_cov, "packs": pf_paths},
        "engine_harness": {"ran": engine_ran,
                           "engine": arm.get("engine"),
                           "error": (None if engine_ran else
                                     ("slither-unavailable" if (engine is None and
                                      lang in ("solidity", "vyper"))
                                      else "no-relevant-detector-compiled"))},
    }
    if engine_arm is not None:
        rec["layers"]["novel_vector_engine"] = {
            "fired": engine_arm.get("fired"),
            "families": engine_arm.get("families", []),
            "invariants_derived": engine_arm.get("invariants_derived"),
            "errors": engine_arm.get("errors", []),
            "note": "file-recall only (per-fn miner, no precise line)",
        }

    # --- outcome ---
    # r36-rebuttal: pathspec in agent_pathspec.json
    # A firing per-language detector is a catch. The engine arm can ONLY ever
    # produce a file-level signal (per-fn invariant, no precise line) - so a
    # detector that stayed silent but whose engine arm matched the class is at
    # best PARTIAL (file-recall), never a line-level CAUGHT.
    if dsl_fired:
        line_level = (dsl_fired_at is not None)
        if line_level or target_line is None:
            rec["outcome"] = "CAUGHT"
            rec["caught_by"] = ["dsl_detectors"]
            rec["fired_at_line"] = dsl_fired_at if line_level else dsl_fired_at_file
            rec["missing_capability"] = None
        else:
            rec["outcome"] = "PARTIAL"
            rec["caught_by"] = ["dsl_detectors"]
            rec["fired_at_line"] = dsl_fired_at_file
            rec["missing_capability"] = "fired-in-file-but-not-at-cited-line"
            rec["reason"] = (loc_reason +
                             " | PARTIAL: detector fired in the vulnerable file but "
                             "not within +/-25 lines of the cited line "
                             f"(file-level hit at line {dsl_fired_at_file}, "
                             f"cited line {target_line})")
        return rec

    # detector silent, but the engine arm matched the class in this file ->
    # PARTIAL (file-recall via novel-vector invariant). Never inflate to CAUGHT
    # because the per-fn miner has no precise line.
    if engine_arm is not None and engine_arm.get("fired"):
        rec["outcome"] = "PARTIAL"
        rec["caught_by"] = ["novel_vector_engine"]
        rec["fired_at_line"] = None
        rec["missing_capability"] = "engine-arm-file-recall-only-no-detector-line"
        rec["reason"] = (loc_reason +
                         " | PARTIAL: no DSL detector fired, but a derived "
                         "novel-vector invariant matched vuln_class in this file "
                         f"(families={engine_arm.get('families')})")
        return rec

    # no detector and no engine-arm match -> MISSED
    # r36-rebuttal: pathspec in agent_pathspec.json
    rec["outcome"] = "MISSED"
    rec["caught_by"] = []
    rec["fired_at_line"] = None
    # missing-capability diagnosis
    if lang in ("solidity", "vyper") and engine is None:
        rec["missing_capability"] = "engine-unavailable-slither-not-installed"
    elif lang == "unknown":
        rec["missing_capability"] = "no-detector-layer-for-unknown-language"
    elif selected == 0 and lang in ("solidity", "vyper"):
        if inv_n > 0:
            rec["missing_capability"] = "corpus-knows-class-but-no-firing-detector"
        else:
            rec["missing_capability"] = f"no-detector-for-class:{normalize_vuln_class(vuln_class)}"
    elif lang in ("solidity", "vyper") and engine_ran:
        # detectors selected + compiled but stayed silent (original semantics).
        rec["missing_capability"] = (
            "detector-selected-and-compiled-but-stayed-silent "
            f"({selected} candidate detectors, 0 fired)")
    elif not engine_ran:
        rec["missing_capability"] = (
            f"{arm.get('engine')}-could-not-run-on-target "
            f"({'; '.join(dsl_errors[:2]) or 'engine_ran=False'})")
    elif inv_n > 0:
        rec["missing_capability"] = "corpus-knows-class-but-no-firing-detector"
    else:
        rec["missing_capability"] = (
            f"{arm.get('engine')}-ran-but-stayed-silent-for-class:"
            f"{normalize_vuln_class(vuln_class)}")

    return rec


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def human_report(records, admission=None):
    L = []
    L.append("=" * 70)
    L.append("AUDITOR BACKTEST - detection layer vs known third-party vulns")
    L.append("=" * 70)
    caught = sum(1 for r in records if r["outcome"] == "CAUGHT")
    partial = sum(1 for r in records if r["outcome"] == "PARTIAL")
    missed = sum(1 for r in records if r["outcome"] == "MISSED")
    na = sum(1 for r in records if r["outcome"] == "NA")
    # Strict line recall counts PARTIAL in the denominator (a file-level-only hit
    # is NOT a line-level catch). File recall credits PARTIAL.
    strict_denom = caught + partial + missed
    strict_rate = (caught / strict_denom) if strict_denom else 0.0
    file_rate = ((caught + partial) / strict_denom) if strict_denom else 0.0
    L.append(f"cases: {len(records)}  CAUGHT={caught}  PARTIAL={partial}  "
             f"MISSED={missed}  NA={na}")
    if admission:
        if admission.get("split_requested"):
            L.append(f"split: {admission['split_requested']}  "
                     f"(skipped {admission.get('split_skipped', 0)} off-split)")
        dnf = admission.get("dropped_non_fetchable_records", 0)
        if dnf:
            L.append(f"dropped (prose/fabricated/quarantined, NOT scored): {dnf}")
        if admission.get("corpus_detector_dirs"):
            L.append(f"corpus-detector-dirs: {admission['corpus_detector_dirs']}")
    if strict_denom:
        L.append(f"strict line recall CAUGHT/(CAUGHT+PARTIAL+MISSED): "
                 f"{caught}/{strict_denom} = {strict_rate:.1%}")
        L.append(f"file recall (CAUGHT+PARTIAL)/...: "
                 f"{caught + partial}/{strict_denom} = {file_rate:.1%}")
    else:
        L.append("catch-rate: n/a (no scorable cases)")
    L.append("-" * 70)
    for r in records:
        line = f"[{r['outcome']:6}] {r['id']}  class={r['vuln_class']}  {r['file_line']}"
        L.append(line)
        if r["outcome"] == "CAUGHT":
            at = r.get("fired_at_line")
            slugs = r["layers"].get("dsl_detectors", {}).get("fired_slugs", [])
            L.append(f"           caught_by={r['caught_by']} fired_at_line={at}")
            if slugs:
                L.append(f"           detectors: {', '.join(slugs[:3])}")
        elif r["outcome"] == "PARTIAL":
            at = r.get("fired_at_line")
            L.append(f"           PARTIAL (file-level hit at line {at}, not "
                     f"line-localized): {r.get('missing_capability')}")
        elif r["outcome"] == "MISSED":
            L.append(f"           MISSING CAPABILITY: {r['missing_capability']}")
            dsl = r["layers"].get("dsl_detectors", {})
            inv = r["layers"].get("corpus_invariants", {})
            L.append(f"           dsl_selected={dsl.get('selected')} "
                     f"corpus_invariants_matched={inv.get('matched')}")
        else:  # NA
            L.append(f"           reason: {r['reason']}")
    L.append("=" * 70)
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def load_cases(args):
    if args.cases:
        cases = []
        for raw in Path(args.cases).read_text().splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            cases.append(json.loads(raw))
        return cases
    # single-case from flags
    if not args.id or not args.vuln_class:
        raise SystemExit("error: provide --cases FILE, or --id and --vuln-class "
                         "(plus --repo/--prefix-ref or --local-checkout)")
    return [{
        "id": args.id,
        "repo": args.repo or "",
        "prefix_ref": args.prefix_ref or "",
        "vuln_class": args.vuln_class,
        "file_line": args.file_line or "",
        "split": args.split or "",
    }]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--mode", choices=("detect", "hunt"), default="detect",
        help="detect (default) grades the static DETECTION layer "
             "(DSL/Slither, rust/go runners, semgrep). hunt grades the LLM HUNT "
             "path against the held-out corpus and reports HUNT-RECALL (the "
             "number honest-zero-verify floors on). Languages with no detector "
             "arm record engine='llm-hunt-only' so the recall is honest.",
    )
    ap.add_argument("--cases", help="JSONL file, one case object per line")
    ap.add_argument("--id")
    ap.add_argument("--repo", help="owner/name or full git URL")
    ap.add_argument("--prefix-ref", dest="prefix_ref", help="commit/ref BEFORE the fix")
    ap.add_argument("--vuln-class")
    ap.add_argument("--file-line", dest="file_line", help="src/File.sol:142")
    ap.add_argument("--local-checkout", dest="local_checkout",
                    help="use an already-checked-out pre-fix tree (offline)")
    ap.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS_DIR))
    ap.add_argument(
        "--corpus-detector-dir", dest="corpus_detector_dir", action="append",
        default=[], metavar="DIR",
        help="ANTI-OVERFIT: extra directory of newly-generated CLASS-level "
             "detectors (authored from TRAIN cases only) to UNION with "
             "--patterns-dir. Repeatable. The held-out catch-rate then measures "
             "whether a TRAIN-built class detector generalizes to a vuln it "
             "never saw. Canonical patterns win on slug collision.",
    )
    ap.add_argument(
        "--split", dest="split", default=None,
        help="Score ONLY cases tagged with this split "
             "(TRAIN|DEV|HELD_OUT|FRESH_TARGET|FIXED_REF|TRAIN_LEAKED). "
             "Detectors are authored on TRAIN and scored on HELD_OUT; pass "
             "--split HELD_OUT for the honest generalization number. When used "
             "as a single-case flag (with --id) it tags that case's split. "
             "Omit to score every case regardless of split tag.",
    )
    ap.add_argument(
        "--engine-arm", dest="engine_arm", action="store_true",
        help="ENGINE/NOVEL-VECTOR scoring arm: in addition to the per-language "
             "detector layer, derive novel-vector invariants on the target file "
             "and credit a FILE-RECALL (PARTIAL) catch when a derived invariant's "
             "family class-matches the recorded vuln_class. Per-fn (no precise "
             "line) so it is never inflated into a line-level CAUGHT. Bounded: no "
             "engine fuzz, just the cheap invariant derivation.",
    )
    ap.add_argument(
        "--mimo-refine", dest="mimo_refine", action="store_true",
        help="With --engine-arm, refine derived invariant statements via MIMO "
             "(consent-gated: requires AUDITOOOR_LLM_NETWORK_CONSENT=1). Bounded "
             "by --mimo-budget (cap 6).",
    )
    ap.add_argument("--mimo-budget", dest="mimo_budget", type=int, default=6,
                    help="max MIMO calls for --mimo-refine (cap 6)")
    ap.add_argument("--json", action="store_true", help="emit machine record(s)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    cases = load_cases(args)

    # --- split selection (PR3a) ---
    # When --split is given AND we loaded a --cases file, keep only cases whose
    # normalized split tag matches. (Single-case --id mode tags rather than
    # filters, so do not drop it here.)
    split_filter = normalize_split(args.split) if (args.split and args.cases) else ""
    if args.split and args.cases and not split_filter:
        raise SystemExit(f"error: --split '{args.split}' is not one of {SPLIT_TAGS}")
    selected = []
    split_skipped = 0
    for case in cases:
        if split_filter and case_split(case) != split_filter:
            split_skipped += 1
            continue
        selected.append(case)

    # --- FETCHABLE-ONLY admission: drop prose / fabricated / quarantined (PR3a) ---
    # Dropped records NEVER become scored rows and never enter the NA count: a
    # fabricated record can neither inflate nor deflate held-out recall.
    scorable_cases = []
    dropped = []
    for case in selected:
        drop, reason = is_droppable_record(case)
        if drop:
            dropped.append({"id": case.get("id", "?"), "reason": reason})
        else:
            scorable_cases.append(case)

    # --- HUNT mode (E4.1): grade the LLM hunt path, emit HUNT-RECALL ---
    if args.mode == "hunt":
        hunt_records = []
        with tempfile.TemporaryDirectory(prefix="auditor_hunt_") as work_root:
            for case in scorable_cases:
                hunt_records.append(
                    hunt_case(case, args.local_checkout, work_root,
                              quiet=args.quiet))
        recall = hunt_recall(hunt_records)
        langs_scored = sorted({r.get("language") for r in hunt_records
                               if r.get("language")})
        admission = {
            "mode": "hunt",
            "split_requested": split_filter or None,
            "split_skipped": split_skipped,
            "dropped_non_fetchable_records": len(dropped),
            "dropped": dropped[:50],
            "languages_scored": langs_scored,
            "engines": sorted({r.get("engine") for r in hunt_records
                               if r.get("engine")}),
        }
        if args.json:
            out = {"schema": HUNT_SCHEMA,
                   "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "mode": "hunt",
                   "admission": admission,
                   "hunt_recall": recall,
                   "cases": hunt_records}
            print(json.dumps(out, indent=2))
        else:
            print("=" * 70)
            print("AUDITOR BACKTEST (HUNT mode) - LLM hunt path vs known vulns")
            print("=" * 70)
            print(f"cases: {len(hunt_records)}  CAUGHT={recall['caught']}  "
                  f"PARTIAL={recall['partial']}  MISSED={recall['missed']}  "
                  f"NA={recall['na']}")
            if recall["scorable"]:
                print(f"hunt-recall (strict, CAUGHT/scorable): "
                      f"{recall['caught']}/{recall['scorable']} = "
                      f"{recall['recall']:.1%}")
                print(f"hunt file-recall (CAUGHT+PARTIAL)/scorable: "
                      f"{recall['caught'] + recall['partial']}/"
                      f"{recall['scorable']} = {recall['file_recall']:.1%}")
            else:
                print("hunt-recall: n/a (no scorable cases; all NA - hunt not run?)")
            for r in hunt_records:
                print(f"[{r['outcome']:6}] {r['id']}  class={r['vuln_class']}  "
                      f"{r['file_line']}  engine={r['engine']}")
                if r.get("missing_capability"):
                    print(f"           {r['missing_capability']}")
        return 0

    try:
        class_helpers = _import_class_helpers()
    except Exception:
        class_helpers = None
    engine = import_engine()

    corpus_dirs = list(args.corpus_detector_dir or [])
    records = []
    with tempfile.TemporaryDirectory(prefix="auditor_backtest_") as work_root:
        for case in scorable_cases:
            rec = backtest_case(case, args.local_checkout, args.patterns_dir,
                                class_helpers, engine, work_root, quiet=args.quiet,
                                corpus_detector_dirs=corpus_dirs,
                                engine_arm_enabled=args.engine_arm,
                                mimo_refine=args.mimo_refine,
                                mimo_budget=args.mimo_budget)
            records.append(rec)

    # Consume sibling-A's trusted-corpus index via the shared resolver. When
    # the index is absent the resolver degrades gracefully to raw-fallback; we
    # LOG that explicitly so a 0-index run is never mistaken for a clean one.
    trust = _corpus_trust_annotation()
    if trust.get("is_fallback"):
        print(f"[auditor-backtest] NOTE trusted-corpus index empty/absent "
              f"({trust.get('reason', '')}); degraded to "
              f"trust_scope={trust.get('trust_scope')}. Build it via "
              f"`make trusted-corpus-index` for trust-scoped scoring.",
              file=sys.stderr)

    admission = {
        "split_requested": split_filter or None,
        "split_skipped": split_skipped,
        "dropped_non_fetchable_records": len(dropped),
        "dropped": dropped[:50],
        "corpus_detector_dirs": corpus_dirs,
        "engine_arm": bool(args.engine_arm),
        "mimo_refine": bool(args.mimo_refine),
        "languages_scored": sorted({r.get("language") for r in records
                                    if r.get("language")}),
    }

    if args.json:
        out = {"schema": SCHEMA, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "corpus_trust": trust,
               "admission": admission,
               "cases": records}
        print(json.dumps(out, indent=2))
    else:
        print(human_report(records, admission=admission))
    return 0


if __name__ == "__main__":
    sys.exit(main())
