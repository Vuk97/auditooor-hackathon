#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-R81-DEPTH-CERTIFICATE registered in .auditooor/agent_pathspec.json -->
"""depth-certificate-check.py - R81 gate: enforce "0 findings = smell, not success".

Background
----------
``make audit-deep`` now runs two depth passes alongside the per-function
invariant + exploit-queue stages:

  - the per-guard NEGATIVE-SPACE pass (``per-guard-negative-space.py``) which,
    for every in-scope guard/validation, emits a delta row {guard, checks_what,
    invariant_requires, delta, exploitation_attempt_artifact} to
    ``.auditooor/depth/negative_space.jsonl``; and

  - the SIBLING-PATH guard-diff pass (``sibling-path-guard-diff.py``) which
    auto-enumerates sibling code-path PAIRS (claim/finalize, sender/receiver,
    deposit/withdraw, mint/burn, lock/unlock, propose/execute, escrow/release,
    vote/tally) across the in-scope src tree and diffs the two paths' guards,
    emitting asymmetry rows to ``.auditooor/depth/sibling_guard_diff.jsonl``.

The two passes emit per-row JSONL evidence
(``negative_space_worklist.jsonl`` / ``negative_space_gaps.jsonl`` /
``sibling_guard_asymmetries.jsonl``). A SINGLE producer,
``tools/depth-certificate-build.py``, then ROLLS those rows up into the depth
certificate at ``<ws>/.auditooor/depth_certificate.json`` (schema
``auditooor.depth_certificate.v1``) - the passes themselves do NOT write the
cert. THIS tool is the GATE that reads the cert and decides whether the
workspace's depth layer actually RAN with evidence.

The KEY RULE this gate enforces
-------------------------------
A workspace claiming "0 findings / no-new-gap" is a SMELL, not a success,
UNLESS the cert proves the depth passes RAN WITH EVIDENCE. A missing or empty
cert is therefore ``fail-no-depth-certificate`` - never a pass. A genuine
0-findings outcome only clears the smell when BOTH depth passes ran AND every
surviving incomplete-guard delta / sibling asymmetry carries an
exploitation-attempt artifact (PoC path) or a source-cited ruled-out reason.

This tool is deterministic, stdlib-only, offline-safe, and NEVER re-runs any
depth pass - it reads the certificate the depth passes leave behind. It exposes
a reusable ``check_depth(ws) -> dict`` so the L37 completeness gate
(``audit-completeness-check.py``) and the honesty gate
(``audit-honesty-check.py``) can import it via ``importlib`` (the filename has a
hyphen).

Verdicts
--------
  pass-depth-audited            cert present, both passes ran with evidence,
                                every guard probed, every gap disposed,
                                survivors validated, and (if 0 findings) the
                                zero-findings smell is cleared.
  fail-no-depth-certificate     cert absent or unreadable / empty.
  fail-depth-pending            producer verdict is ``depth-pending`` - the
                                mechanical passes ran but the agentic probe/
                                validate is incomplete (not every guard probed /
                                not every candidate gap disposed). A cert must be
                                ``depth-audited`` to pass.
  fail-depth-not-run            producer verdict is ``depth-not-run`` - the depth
                                passes never ran (no worklist, no asymmetries).
  fail-depth-stale              the cert's mtime is OLDER than one of its depth
                                inputs (inscope_units.jsonl / negative_space_*
                                / sibling_guard_asymmetries.jsonl /
                                asymmetry_probes* / depth_probes*). The inputs
                                were regenerated (e.g. a fresh
                                depth-probe-ingest) AFTER the cert was built, so
                                the cert no longer reflects the depth evidence -
                                it must be REBUILT (``make audit-depth``) before
                                it can be certified. This is the ~537x-stale-cert
                                failure mode that kept a workspace silently at
                                depth-pending while the cert claimed otherwise.
  fail-negative-space-not-run   ``negative_space_ran`` is false (or no guards
                                examined).
  fail-sibling-diff-not-run     ``sibling_diff_ran`` is false (or no pairs
                                enumerated).
  fail-survivors-unvalidated    a surviving incomplete-guard delta or sibling
                                asymmetry lacks an exploitation-attempt
                                artifact AND a source-cited ruled-out reason.
  fail-zero-findings-smell      findings_count == 0 but the depth passes did
                                NOT run with evidence (the smell is not cleared).
  ok-rebuttal                   a bounded ``r81-rebuttal: <reason>`` is present.
  error                         malformed cert / unexpected shape.

Rebuttal
--------
Visible bounded line ``r81-rebuttal: <reason>`` (<=200 chars) OR HTML-comment
form ``<!-- r81-rebuttal: <reason> -->`` in
``<WS>/.auditooor/depth_certificate_rebuttal.txt``. Reserved for genuinely-N/A
workspaces (e.g. a target with no guard/validation surface at all). Empty or
oversized reasons are ignored; the original fail stands.

Usage
-----
    python3 tools/depth-certificate-check.py --workspace <ws> [--strict] [--json]

Exit code: 0 on a pass / ok-rebuttal verdict, 1 on any fail / error verdict.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.depth_certificate_check.v1"
CERT_SCHEMA = "auditooor.depth_certificate.v1"

_REBUTTAL_MAX = 200
_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?r81-rebuttal:\s*(?P<reason>.+?)(?:\s*-->)?\s*$"
)

# Verdicts
PASS = "pass-depth-audited"
FAIL_NO_CERT = "fail-no-depth-certificate"
FAIL_NEG_SPACE = "fail-negative-space-not-run"
FAIL_SIBLING = "fail-sibling-diff-not-run"
FAIL_SURVIVORS = "fail-survivors-unvalidated"
FAIL_ZERO_SMELL = "fail-zero-findings-smell"
# The cert producer (depth-certificate-build.py) writes a first-class honest
# ``verdict`` field. A cert whose verdict is NOT depth-audited is NOT a pass -
# depth-pending (mechanical passes ran but the agentic probe/validate is
# incomplete) and depth-not-run both fail the gate. A cert must be depth-audited
# to pass.
FAIL_DEPTH_PENDING = "fail-depth-pending"
FAIL_DEPTH_NOT_RUN = "fail-depth-not-run"
# Freshness: a cert built at T1 over inputs replaced at T2>T1 is STALE. Such a
# cert silently certifies a workspace whose real depth evidence has moved on
# (the ~537x-stale cert that kept polygon at depth-pending). The gate fails it
# and prints a "re-run make audit-depth" step.
FAIL_STALE = "fail-depth-stale"
OK_REBUTTAL = "ok-rebuttal"
ERROR = "error"
# LLM-hunt-only (Oscript) depth axis (advisory-first). A language with NO
# static/fuzz engine (is_llm_hunt_only, e.g. Obyte Oscript AAs) cannot have its
# guards enumerated by the static negative-space / sibling-diff passes, so the
# cert producer computes an `llm_hunt_only_depth` block crediting an LLM hunt
# verdict (a hunt_findings_sidecar anchored to a unit's file) as the language-
# appropriate depth evidence. For a MIXED workspace (has engine-lang units) this
# axis is PURELY ADVISORY (surfaced in detail; the engine verdict stands). For a
# workspace that is ENTIRELY LLM-hunt-only the static gate is INAPPLICABLE (no
# engine guard can exist), so a static "did-not-run" fail is a FALSE-BLOCK: the
# gate defers to this axis - fully-covered => pass, otherwise a distinct honest
# fail (never a silent pass, never a demand for a static campaign that cannot
# exist for that language).
PASS_OSCRIPT = "pass-oscript-depth-llm-hunt-credited"
FAIL_OSCRIPT_UNCOVERED = "fail-oscript-depth-uncovered"

# Honest verdicts the producer writes.
BUILD_VERDICT_AUDITED = "depth-audited"
BUILD_VERDICT_PENDING = "depth-pending"
BUILD_VERDICT_NOT_RUN = "depth-not-run"

_PASS_VERDICTS = frozenset({PASS, OK_REBUTTAL, PASS_OSCRIPT})

# The static verdicts that are INAPPLICABLE to an entirely-LLM-hunt-only
# workspace (the static passes cannot enumerate guards for such a language). When
# the workspace has zero engine-lang units, one of these is a FALSE-BLOCK and the
# gate defers to the LLM-hunt-only depth axis instead. FAIL_STALE / ERROR /
# FAIL_NO_CERT / FAIL_SURVIVORS are integrity failures we never override, and a
# rebuttal is already handled upstream.
_OSCRIPT_STATIC_OVERRIDE_VERDICTS = frozenset({
    FAIL_DEPTH_NOT_RUN, FAIL_NEG_SPACE, FAIL_SIBLING, FAIL_DEPTH_PENDING,
    FAIL_ZERO_SMELL,
})


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_rebuttal(ws: Path) -> str | None:
    """Return the bounded rebuttal reason, or None."""
    rb = ws / ".auditooor" / "depth_certificate_rebuttal.txt"
    try:
        text = rb.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        m = _REBUTTAL_RE.search(line.strip())
        if not m:
            continue
        reason = (m.group("reason") or "").strip()
        if reason and len(reason) <= _REBUTTAL_MAX:
            return reason
    return None


def _survivor_validated(row: dict) -> bool:
    """A surviving incomplete-guard delta or sibling asymmetry is validated iff
    it carries an exploitation-attempt artifact OR a source-cited ruled-out
    reason."""
    if not isinstance(row, dict):
        return False
    art = row.get("exploitation_attempt_artifact")
    if isinstance(art, str) and art.strip():
        return True
    ruled = row.get("ruled_out_reason")
    if isinstance(ruled, str) and ruled.strip():
        return True
    return False


# Depth inputs the cert is ROLLED UP FROM (must all be OLDER-than the cert for it
# to be fresh). File inputs are exact names under <ws>/.auditooor/; dir/glob
# inputs are scanned for their newest member. Kept in sync with the readers in
# depth-certificate-build.py (negative_space_*, sibling_guard_asymmetries,
# asymmetry_probes*, the asymmetry_probes/ batch dir) plus inscope_units.jsonl
# (the in-scope unit manifest the negative-space pass keys off) and any
# depth_probes*/ batch dir. Language-general (no source-tree assumptions).
_FRESHNESS_FILE_INPUTS = (
    "inscope_units.jsonl",
    "negative_space_worklist.jsonl",
    "negative_space_gaps.jsonl",
    "sibling_guard_asymmetries.jsonl",
    "asymmetry_probes.jsonl",
    "asymmetry_probes_combined.jsonl",
    # Edge 5: the cert also rolls up UNGUARDED uncovered DefUsePaths from the slice
    # as residual-smell negative-space entries; a refreshed slice must re-roll-up.
    "dataflow_paths.jsonl",
)
# Directory inputs: the cert must be newer than the NEWEST member of each.
_FRESHNESS_DIR_INPUTS = ("asymmetry_probes",)
# Glob inputs (depth-probe batch dirs occur as depth_probes/ and depth_probes_*/).
_FRESHNESS_DIR_GLOBS = ("depth_probes", "depth_probes_*")


def _newest_mtime_in_dir(d: Path) -> float | None:
    """Newest mtime among files under ``d`` (recursive), or None if empty /
    unreadable. Never raises - a directory we cannot stat contributes no signal
    (completeness-safe: we do not under-scope by silently treating it fresh)."""
    newest: float | None = None
    try:
        for p in d.rglob("*"):
            try:
                if p.is_file():
                    m = p.stat().st_mtime
                    if newest is None or m > newest:
                        newest = m
            except OSError:
                continue
    except OSError:
        return None
    return newest


def _check_freshness(ws: Path, cert_path: Path) -> dict:
    """Compare the cert mtime against every existing depth input.

    Returns a dict::

        {
          "stale": bool,             # an input is NEWER than the cert
          "newer_inputs": [str],     # inputs that post-date the cert (stale set)
          "checked_inputs": [str],   # inputs that existed and were compared
          "missing_inputs": [str],   # inputs that did not exist (reported, not fatal)
          "cert_mtime": float | None,
        }

    Completeness-safe: a missing input is REPORTED, never crashes, and never on
    its own marks the cert stale. If NO inputs exist at all, freshness cannot be
    verified - we return stale=False with an empty checked set so the caller can
    WARN rather than under-scope. Language-general."""
    try:
        cert_mtime = cert_path.stat().st_mtime
    except OSError:
        # Cannot stat the cert -> cannot judge freshness; treat as not-stale so we
        # never block on an IO hiccup (the cert-readability checks elsewhere catch
        # a truly-broken cert).
        return {
            "stale": False,
            "newer_inputs": [],
            "checked_inputs": [],
            "missing_inputs": [],
            "cert_mtime": None,
        }

    aud = ws / ".auditooor"
    newer: list[str] = []
    checked: list[str] = []
    missing: list[str] = []

    def _consider(name: str, mtime: float | None, existed: bool) -> None:
        if not existed:
            missing.append(name)
            return
        if mtime is None:
            # existed but empty/unreadable dir -> reported as checked-but-no-signal
            checked.append(name)
            return
        checked.append(name)
        # Use a strict ">" so a same-second rebuild (cert written right after the
        # input in the same audit-depth run) is NOT mis-flagged stale. Genuine
        # staleness (input replaced in a LATER run) shows a clearly-newer mtime.
        if mtime > cert_mtime:
            newer.append(name)

    for name in _FRESHNESS_FILE_INPUTS:
        p = aud / name
        if p.is_file():
            try:
                _consider(name, p.stat().st_mtime, True)
            except OSError:
                missing.append(name)
        else:
            _consider(name, None, False)

    for name in _FRESHNESS_DIR_INPUTS:
        d = aud / name
        if d.is_dir():
            _consider(name + "/", _newest_mtime_in_dir(d), True)
        else:
            _consider(name + "/", None, False)

    for pattern in _FRESHNESS_DIR_GLOBS:
        any_matched = False
        for d in sorted(aud.glob(pattern)):
            if d.is_dir():
                any_matched = True
                _consider(d.name + "/", _newest_mtime_in_dir(d), True)
        if not any_matched:
            missing.append(pattern + "/")

    return {
        "stale": bool(newer),
        "newer_inputs": newer,
        "checked_inputs": checked,
        "missing_inputs": missing,
        "cert_mtime": cert_mtime,
    }


def _load_llm_hunt_only_block(ws: Path) -> dict | None:
    """The cert's ``llm_hunt_only_depth`` block (written by the single cert
    producer for a workspace that has >=1 LLM-hunt-only in-scope unit), or None.
    None => an engine-only (Solidity/Go/Rust) workspace, whose gate behavior is
    byte-identical (the overlay is a no-op)."""
    cert = _load_json(ws / ".auditooor" / "depth_certificate.json")
    if not isinstance(cert, dict):
        return None
    block = cert.get("llm_hunt_only_depth")
    return block if isinstance(block, dict) else None


def _apply_llm_hunt_only_axis(ws: Path, result: dict) -> dict:
    """Overlay the advisory-first LLM-hunt-only (Oscript) depth axis onto a static
    gate result. No-op (byte-identical) when the cert has no llm_hunt_only_depth
    block (engine-only workspace). For a MIXED workspace the axis is advisory-only
    (surfaced in detail; the engine verdict stands). For an ENTIRELY-LLM-hunt-only
    workspace a static "did-not-run" fail is a FALSE-BLOCK, so the gate defers to
    the axis: fully-covered => pass-oscript, otherwise fail-oscript-depth-uncovered
    (never a silent pass; never demanding a static campaign that cannot exist)."""
    block = _load_llm_hunt_only_block(ws)
    if block is None:
        return result  # engine-only workspace: byte-identical, no overlay

    # Advisory: surface the axis in detail for EVERY oscript-bearing workspace.
    detail = result.get("detail")
    detail = dict(detail) if isinstance(detail, dict) else {}
    detail["llm_hunt_only_depth"] = block
    result = dict(result)
    result["detail"] = detail
    result["llm_hunt_only_depth"] = block

    def _int(name: str) -> int:
        v = block.get(name)
        return v if isinstance(v, int) and not isinstance(v, bool) else 0

    engine_units = _int("engine_units_total")
    verdict = result.get("verdict")

    # MIXED workspace (has engine-lang in-scope units): advisory only - the
    # engine-derived verdict stands (the Solidity/Go depth logic is untouched).
    if engine_units > 0:
        return result

    # ENTIRELY LLM-hunt-only: only a static "did-not-run"/"pending" fail is a
    # false-block we may override. Integrity fails (stale/error/no-cert/survivors)
    # and an already-granted rebuttal/pass are left exactly as-is.
    if verdict not in _OSCRIPT_STATIC_OVERRIDE_VERDICTS:
        return result

    langs = ", ".join(block.get("langs") or []) or "llm-hunt-only"
    units_total = _int("units_total")
    covered = _int("covered_units")
    uncovered = _int("uncovered_units")
    axis_verdict = block.get("axis_verdict")
    result["would_be_verdict_static"] = verdict
    if axis_verdict == "covered" and covered > 0 and uncovered == 0:
        result["verdict"] = PASS_OSCRIPT
        result["reason"] = (
            f"workspace is entirely LLM-hunt-only ({langs}); the static negative-"
            f"space/sibling-diff passes cannot enumerate guards for these "
            f"languages, so the depth axis is credited from LLM hunt verdicts. "
            f"All {units_total} in-scope units are depth-covered by a matching "
            f"hunt_findings_sidecar."
        )
    else:
        result["verdict"] = FAIL_OSCRIPT_UNCOVERED
        result["reason"] = (
            f"workspace is entirely LLM-hunt-only ({langs}); {uncovered} of "
            f"{units_total} in-scope units have NO matching hunt_findings_sidecar "
            f"- the LLM hunt is incomplete (an uncovered unit is a smell, not a "
            f"success). Credit is per-file: a unit is covered only when a hunt "
            f"sidecar is anchored to its file. Hunt the uncovered units, then "
            f"re-run `make audit-depth WS=<ws>`."
        )
    return result


def check_depth(ws) -> dict:
    """Reusable entrypoint. Returns a dict with at least {verdict, reason}.

    Importable by L37 / honesty gates. Never raises on a malformed cert - it
    returns an ``error`` verdict instead.

    Layers the advisory-first LLM-hunt-only (Oscript) depth axis on top of the
    static gate result: a no-op for engine-only workspaces (byte-identical),
    advisory for mixed workspaces, and the authoritative axis for a workspace
    that is entirely LLM-hunt-only (where the static gate is inapplicable)."""
    return _apply_llm_hunt_only_axis(Path(ws), _check_depth_core(ws))


def _check_depth_core(ws) -> dict:
    """The static R81 depth gate (engine-language logic). BYTE-IDENTICAL to the
    pre-Oscript behavior; the LLM-hunt-only overlay lives in ``check_depth``."""
    ws = Path(ws)
    cert_path = ws / ".auditooor" / "depth_certificate.json"

    rebuttal = _load_rebuttal(ws)

    if not cert_path.exists():
        if rebuttal:
            return {
                "schema": SCHEMA,
                "verdict": OK_REBUTTAL,
                "reason": f"no depth certificate; r81-rebuttal accepted: {rebuttal}",
                "cert_path": str(cert_path),
                "rebuttal": rebuttal,
            }
        return {
            "schema": SCHEMA,
            "verdict": FAIL_NO_CERT,
            "reason": (
                "no <ws>/.auditooor/depth_certificate.json - a missing cert is a "
                "smell, not a pass (0 findings must be PROVEN, not assumed)"
            ),
            "cert_path": str(cert_path),
        }

    cert = _load_json(cert_path)
    if not isinstance(cert, dict):
        if rebuttal:
            return {
                "schema": SCHEMA,
                "verdict": OK_REBUTTAL,
                "reason": f"unreadable cert; r81-rebuttal accepted: {rebuttal}",
                "cert_path": str(cert_path),
                "rebuttal": rebuttal,
            }
        return {
            "schema": SCHEMA,
            "verdict": FAIL_NO_CERT,
            "reason": "depth_certificate.json is unreadable / not a JSON object",
            "cert_path": str(cert_path),
        }

    # Honest sanity: if the cert declares a schema, it must be the cert schema.
    declared = cert.get("schema")
    if declared is not None and declared != CERT_SCHEMA:
        return {
            "schema": SCHEMA,
            "verdict": ERROR,
            "reason": f"cert schema mismatch: got {declared!r}, want {CERT_SCHEMA!r}",
            "cert_path": str(cert_path),
        }

    # FRESHNESS: a cert built at T1 over inputs replaced at T2>T1 is STALE - the
    # depth evidence has moved on but the cert still claims its old verdict (the
    # ~537x-stale cert that kept polygon at depth-pending). This fires BEFORE the
    # verdict short-circuit and field checks so a stale cert can NEVER pass,
    # regardless of what verdict it carries. Completeness-safe: missing inputs are
    # reported (not fatal); if NO inputs exist the gate cannot verify freshness
    # and WARNs rather than under-scoping. A bounded r81-rebuttal still applies.
    fresh = _check_freshness(ws, cert_path)
    if fresh["stale"]:
        reason = (
            "depth_certificate.json is STALE: it was built BEFORE its inputs were "
            f"last regenerated ({', '.join(fresh['newer_inputs'])} post-date the "
            "cert) - the cert no longer reflects the depth evidence. REBUILD it: "
            "re-run `make audit-depth WS=<ws>` (which re-runs "
            "depth-certificate-build after ingest)."
        )
        if rebuttal:
            return {
                "schema": SCHEMA,
                "verdict": OK_REBUTTAL,
                "reason": f"depth gate would fail ({FAIL_STALE}); r81-rebuttal accepted: {rebuttal}",
                "cert_path": str(cert_path),
                "rebuttal": rebuttal,
                "would_be_verdict": FAIL_STALE,
                "freshness": fresh,
                "remediation": "make audit-depth WS=<ws>",
            }
        return {
            "schema": SCHEMA,
            "verdict": FAIL_STALE,
            "reason": reason,
            "cert_path": str(cert_path),
            "freshness": fresh,
            "remediation": "make audit-depth WS=<ws>",
        }
    if not fresh["checked_inputs"]:
        # Loud, non-fatal WARN: no depth inputs exist on disk, so freshness could
        # not be verified. We keep-all (do not fail on freshness) but surface a
        # one-line manual step so the operator never mistakes "could not verify"
        # for "verified fresh".
        print(
            "[depth-certificate-check] WARN cannot verify cert freshness: no depth "
            "inputs found under <ws>/.auditooor/ (inscope_units.jsonl / "
            "negative_space_* / sibling_guard_asymmetries.jsonl / asymmetry_probes* "
            "/ depth_probes*). Manual step: confirm `make audit-depth WS=<ws>` "
            "actually produced these inputs before trusting this cert.",
            file=sys.stderr,
        )

    # Verdict short-circuit: the producer writes a first-class honest verdict.
    # A cert must be depth-audited to pass; depth-pending / depth-not-run fail
    # the gate so a workspace whose guards were enumerated but never probed is
    # NOT greened. Only the explicit producer verdict triggers this branch; a
    # legacy cert with no verdict field falls through to the field-based logic
    # below (backward compatible).
    # Only the producer's known build-verdict vocabulary triggers this branch.
    # A legacy cert carrying some other ``verdict`` string (or none) falls
    # through to the field-based logic below (backward compatible). We further
    # require the producer's build_schema marker so a hand-written cert that
    # happens to reuse one of these strings does not accidentally short-circuit.
    _BUILD_VERDICTS = {
        BUILD_VERDICT_AUDITED, BUILD_VERDICT_PENDING, BUILD_VERDICT_NOT_RUN,
    }
    build_verdict = cert.get("verdict")
    is_producer_cert = cert.get("build_schema") == "auditooor.depth_certificate_build.v1"
    if (
        isinstance(build_verdict, str)
        and build_verdict in _BUILD_VERDICTS
        and is_producer_cert
    ):
        if build_verdict != BUILD_VERDICT_AUDITED:
            mapped = (
                FAIL_DEPTH_NOT_RUN
                if build_verdict == BUILD_VERDICT_NOT_RUN
                else FAIL_DEPTH_PENDING
            )
            reason = (
                f"depth certificate verdict is {build_verdict!r}, not "
                f"{BUILD_VERDICT_AUDITED!r} - the depth layer is not yet fully "
                "audited (mechanical passes may have run but the agentic "
                "probe/validate is incomplete); 0 findings is a smell, not a "
                "success"
            )
            if rebuttal:
                return {
                    "schema": SCHEMA,
                    "verdict": OK_REBUTTAL,
                    "reason": f"depth gate would fail ({mapped}); r81-rebuttal accepted: {rebuttal}",
                    "cert_path": str(cert_path),
                    "rebuttal": rebuttal,
                    "would_be_verdict": mapped,
                    "build_verdict": build_verdict,
                }
            return {
                "schema": SCHEMA,
                "verdict": mapped,
                "reason": reason,
                "cert_path": str(cert_path),
                "build_verdict": build_verdict,
            }
        # build_verdict == depth-audited: fall through to the field-based checks
        # below, which independently re-verify the evidence (defense in depth -
        # the producer's verdict and the gate's field checks must agree).

    neg_ran = bool(cert.get("negative_space_ran"))
    sib_ran = bool(cert.get("sibling_diff_ran"))

    def _int(field: str) -> int:
        v = cert.get(field)
        return v if isinstance(v, int) and not isinstance(v, bool) else 0

    guards = _int("guards_enumerated")
    pairs = _int("sibling_pairs_enumerated")
    findings = _int("findings_count")

    incomplete = cert.get("incomplete_guard_deltas")
    if not isinstance(incomplete, list):
        incomplete = []
    asymmetries = cert.get("sibling_asymmetries")
    if not isinstance(asymmetries, list):
        asymmetries = []

    # Build the per-signal failure list (load-bearing order: neg-space, sibling,
    # survivors, zero-smell). The first failing signal is the top-level verdict.
    failures: list[tuple[str, str]] = []

    # Negative-space pass must have run AND examined >0 guards.
    if not neg_ran or guards <= 0:
        failures.append((
            FAIL_NEG_SPACE,
            f"negative-space pass not run with evidence (ran={neg_ran}, "
            f"guards_enumerated={guards})",
        ))

    # Sibling-diff pass must have run. Zero asymmetry rows is a valid result:
    # it means the pass ran and found no sibling candidate gaps to dispose.
    if not sib_ran:
        failures.append((
            FAIL_SIBLING,
            f"sibling-path guard-diff pass not run with evidence (ran={sib_ran})",
        ))

    # Every surviving incomplete-guard delta + sibling asymmetry must be
    # validated (exploitation attempt OR source-cited ruled-out).
    unvalidated: list[str] = []
    for row in incomplete:
        if not _survivor_validated(row):
            ident = (row.get("guard") if isinstance(row, dict) else None) or "<guard?>"
            unvalidated.append(f"guard:{ident}")
    for row in asymmetries:
        if not _survivor_validated(row):
            ident = (row.get("pair") if isinstance(row, dict) else None) or "<pair?>"
            unvalidated.append(f"sibling:{ident}")
    if unvalidated:
        failures.append((
            FAIL_SURVIVORS,
            "survivors lack an exploitation-attempt artifact OR a source-cited "
            f"ruled-out reason: {', '.join(unvalidated[:10])}"
            + (" ..." if len(unvalidated) > 10 else ""),
        ))

    # 0 findings = smell. It is cleared ONLY when both depth passes ran with
    # evidence (i.e. neg-space + sibling signals above did not already fail).
    depth_ran_with_evidence = neg_ran and guards > 0 and sib_ran
    smell_cleared = bool(cert.get("zero_findings_smell_cleared"))
    if findings == 0:
        if not depth_ran_with_evidence or not smell_cleared:
            failures.append((
                FAIL_ZERO_SMELL,
                "findings_count==0 but the depth passes did not run with evidence / "
                f"zero_findings_smell_cleared={smell_cleared} - 0 findings is a "
                "smell, not a success",
            ))

    detail = {
        "negative_space_ran": neg_ran,
        "sibling_diff_ran": sib_ran,
        "guards_enumerated": guards,
        "sibling_pairs_enumerated": pairs,
        "findings_count": findings,
        "incomplete_guard_deltas": len(incomplete),
        "sibling_asymmetries": len(asymmetries),
        "survivors_unvalidated": len(unvalidated),
        "zero_findings_smell_cleared": smell_cleared,
        "freshness": fresh,
        "depth_ran_with_evidence": depth_ran_with_evidence,
    }

    if not failures:
        return {
            "schema": SCHEMA,
            "verdict": PASS,
            "reason": (
                f"depth layer audited: {guards} guards probed, {pairs} sibling "
                f"pairs diffed, all survivors validated"
                + (", zero-findings smell cleared" if findings == 0 else "")
            ),
            "cert_path": str(cert_path),
            "detail": detail,
        }

    # A rebuttal promotes the first failing verdict to ok-rebuttal.
    if rebuttal:
        return {
            "schema": SCHEMA,
            "verdict": OK_REBUTTAL,
            "reason": f"depth gate would fail ({failures[0][0]}); r81-rebuttal accepted: {rebuttal}",
            "cert_path": str(cert_path),
            "detail": detail,
            "rebuttal": rebuttal,
            "would_be_verdict": failures[0][0],
            "failures": [{"verdict": v, "reason": r} for v, r in failures],
        }

    top_verdict, top_reason = failures[0]
    return {
        "schema": SCHEMA,
        "verdict": top_verdict,
        "reason": top_reason,
        "cert_path": str(cert_path),
        "detail": detail,
        "failures": [{"verdict": v, "reason": r} for v, r in failures],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="R81 depth-certificate gate: '0 findings = smell, not success'."
    )
    ap.add_argument("--workspace", required=True, help="workspace path")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="(reserved) treat advisory soft signals as hard fails",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    result = check_depth(args.workspace)
    # --strict is reserved for future soft-signal hardening; it never relaxes a
    # fail. Recorded in the payload so callers can see the mode.
    result["strict"] = bool(args.strict)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"verdict: {result['verdict']}")
        print(f"reason:  {result['reason']}")
        for f in result.get("failures", []):
            print(f"  - {f['verdict']}: {f['reason']}")

    return 0 if result["verdict"] in _PASS_VERDICTS else 1


if __name__ == "__main__":
    sys.exit(main())
