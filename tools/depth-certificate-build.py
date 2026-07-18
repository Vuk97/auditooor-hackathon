#!/usr/bin/env python3
"""depth-certificate-build.py - the WRITE side of the R81 depth layer.

Background
----------
The R81 depth layer has two halves:

  - a GATE (``tools/depth-certificate-check.py``) that READS
    ``<ws>/.auditooor/depth_certificate.json`` and decides whether the depth
    layer ran with evidence ("0 findings = smell, not success"); and

  - a PRODUCER - THIS tool - that ROLLS UP the artifacts the two mechanical
    depth passes already emit into that same certificate.

Before this tool existed there was NO producer: the gate read a cert that
nothing wrote, so after ``make audit-depth`` the gate could only ever fail
``fail-no-depth-certificate``. This tool closes that gap. It is the ONE writer
of the cert. There must be exactly one writer so the cert never drifts between
two producers; the mechanical passes (``guard-negative-space-analyzer.py``,
``sibling-path-guard-diff.py``) emit their per-row JSONL evidence, and this tool
folds those rows into the roll-up cert. The agentic depth re-audit workflow's
Certify phase MUST also call this same producer (one writer) rather than
hand-writing a cert.

Inputs (all under ``<ws>/.auditooor/``)
---------------------------------------
  negative_space_worklist.jsonl     guards enumerated by
                                    ``guard-negative-space-analyzer --emit-worklist``
                                    (REQUIRED for the depth passes to be "ran").
  negative_space_gaps.jsonl         agent probe verdicts, folded in by
                                    ``guard-negative-space-analyzer --ingest``
                                    (may be ABSENT if the agentic probe has not
                                    run yet - that is the depth-pending case).
  sibling_guard_asymmetries.jsonl   sibling-path guard asymmetries from
                                    ``sibling-path-guard-diff --check``.
  --survivors <json>                OPTIONAL. The validated draft/drop
                                    dispositions from the agentic validate
                                    phase. Shape (either accepted)::

                                        {"survivors": [...], "drops": [...],
                                         "findings_drafted": [...]}
                                      or a list of disposition rows each with a
                                      ``disposition`` in {draft, drop} and (for
                                      drops) a ``ruled_out_reason``/source cite.

Output
------
  ``<ws>/.auditooor/depth_certificate.json`` (schema
  ``auditooor.depth_certificate.v1``) carrying BOTH the rich gate-facing fields
  AND a first-class honest ``verdict``.

HONEST VERDICT LOGIC (the crux - this tool must NOT auto-pass)
--------------------------------------------------------------
  depth-audited   ONLY iff:
                    - negative_space_ran (worklist exists, >=1 guard), AND
                    - sibling_diff_ran (asymmetries file exists), AND
                    - EVERY enumerated guard has a probe verdict
                      (worklist guard count == adjudicated-gap count), AND
                    - EVERY candidate gap (negative-space gap + sibling
                      asymmetry) has a disposition: a drafted finding OR a
                      source-cited drop (exploitation-attempt artifact OR
                      ruled-out reason).
  depth-pending   the mechanical passes ran (worklist exists) but the agentic
                    probe/validate is incomplete (not every guard adjudicated,
                    or a candidate gap lacks a disposition). This is what
                    ``make audit-depth`` ALONE produces (mechanical-only). The
                    gate MUST treat depth-pending as NOT-yet-pass so it does not
                    green a workspace whose guards were enumerated but never
                    probed.
  depth-not-run   no worklist AND no asymmetries exist (the depth passes never
                    ran).

The producer writes the verdict it computes; it never upgrades a pending/
not-run workspace to audited. The gate is the authority on pass/fail, but the
producer's verdict is the honest summary the gate keys off.

CLI
---
    python3 tools/depth-certificate-build.py --workspace <ws> \
        [--survivors <json>] [--strict] [--json]

Exit code: 0 when a cert was written (regardless of verdict - writing a
``depth-pending`` cert is a SUCCESS for this tool; it is the GATE that decides
pass/fail). 2 on a usage/IO error.

Dependency-free: stdlib only, offline-safe, never executes target code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.source_extensions import is_llm_hunt_only, lang_of  # noqa: E402  canonical ext/lang registry

SCHEMA = "auditooor.depth_certificate_build.v1"
CERT_SCHEMA = "auditooor.depth_certificate.v1"

VERDICT_AUDITED = "depth-audited"
VERDICT_PENDING = "depth-pending"
VERDICT_NOT_RUN = "depth-not-run"

# --- anti-stub adjudication-genuineness layer -------------------------------
# A guard/asymmetry adjudication counts as GENUINE only if its ruled_out_reason
# (or exploitation-attempt artifact) is BOTH:
#   (a) SUBSTANTIVE - it references the specific guard (a file:line, a concrete
#       require/check/revert/assert/modifier code reference, a backtick code
#       excerpt, or a per-guard id), NOT a generic "guard adjudicated against
#       its protected invariant" boilerplate; AND
#   (b) NOT BULK-TEMPLATED - it is not one of a large cluster of near-identical
#       reasons. We compute, over ALL adjudication reasons, the size of the
#       largest near-identical cluster (grouped by a normalized first-~60-char
#       shingle). If a single template covers more than
#       AUDITOOOR_DEPTH_TEMPLATE_FRACTION (default 0.25) of all adjudications,
#       every row in that cluster is a bulk stub and is NOT genuine.
#
# Empirical anchor: zebra's 1240 negative-space rows all share the identical
# 60-char prefix "Probed: guard adjudicated against its protected invariant; n"
# (largest cluster fraction = 1.0) and cite no file:line / code / check keyword
# -> bulk template stubs, NOT genuine -> verdict must be depth-pending.
# morpho-midnight's 124 rows each cite a distinct guard id + file:line + the
# specific `require(...)`/`revert(...)` checked (largest normalized cluster ~27
# of 124 = 0.22 < 0.25, and every row is substantive) -> genuinely
# adjudicated -> verdict stays depth-audited. The two gates together catch the
# identical-template bulk without flagging legitimately-similar-but-distinct
# per-guard analyses.

_DEFAULT_TEMPLATE_FRACTION = 0.25
# A cluster is only "bulk" when it is BOTH over the fraction threshold AND an
# absolutely-large cluster. Without an absolute floor a tiny prose population
# (e.g. a single ruled-out reason) would trivially "dominate" its own 1-row
# population at fraction 1.0 and be mis-flagged as a template. Real bulk stubs
# are large (zebra=1240, the cluster we must catch); a handful of similar
# legitimate analyses are not. Tunable via AUDITOOOR_DEPTH_TEMPLATE_MIN_CLUSTER.
_DEFAULT_TEMPLATE_MIN_CLUSTER = 3

# A substantive reason must reference the specific guard via at least one of:
#   - a file:line citation (foo/Bar.sol:216, src/x.rs:88, pallet.go:42, ...)
#   - a per-guard id (NS-<hex>, guard ns-<hex>)
#   - a backtick-quoted code excerpt (`require(...)`)
#   - a concrete check / guard keyword (require/revert/assert/ensure/modifier/
#     onlyOwner/msg.sender/...)
_SUBSTANTIVE_FILE_LINE_RE = re.compile(
    r"[\w./-]+\.(?:sol|rs|go|move|cairo|py|ts|js|vy|fe|huff|yul):\d+", re.I
)
_SUBSTANTIVE_GUARD_ID_RE = re.compile(r"\bns-[0-9a-f]{6,}\b", re.I)
_SUBSTANTIVE_CODE_KEYWORD_RE = re.compile(
    r"\b(require|revert|assert|ensure|ensure_signed|ensure_root|modifier|"
    r"onlyowner|only[a-z]+|msg\.sender|require_keys_eq|access[_ ]?control|"
    r"reentranc|nonreentrant|whenpaused|whennotpaused|hasrole|_checkrole|"
    r"debug_assert|assert[a-z0-9_]*|ok_or|ok_or_else|return\s+err|err|"
    r"result|panic|checked_[a-z0-9_]+|(?:check|validate|verify)[a-z0-9_]*)\b",
    re.I,
)
_HONEST_NON_GUARD_RE = re.compile(
    r"(?:module import|import line|commented[- ]out).{0,120}"
    r"(?:not|does not|cannot|no).{0,80}(?:guard|invariant|runtime|execution)",
    re.I,
)
# Generic boilerplate phrases that, on their own, do NOT make a reason
# substantive. (Used only as a sanity signal; the positive substantive checks
# above are authoritative - a reason that ONLY matches boilerplate and nothing
# substantive is not genuine.)
_GENERIC_BOILERPLATE_RE = re.compile(
    r"guard adjudicated against its protected invariant", re.I
)


def _template_fraction_threshold() -> float:
    """Read AUDITOOOR_DEPTH_TEMPLATE_FRACTION (default 0.25); ignore garbage."""
    raw = os.environ.get("AUDITOOOR_DEPTH_TEMPLATE_FRACTION")
    if raw is None:
        return _DEFAULT_TEMPLATE_FRACTION
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_TEMPLATE_FRACTION
    if val <= 0.0 or val > 1.0:
        return _DEFAULT_TEMPLATE_FRACTION
    return val


def _template_min_cluster() -> int:
    """Read AUDITOOOR_DEPTH_TEMPLATE_MIN_CLUSTER (default 3); ignore garbage."""
    raw = os.environ.get("AUDITOOOR_DEPTH_TEMPLATE_MIN_CLUSTER")
    if raw is None:
        return _DEFAULT_TEMPLATE_MIN_CLUSTER
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_TEMPLATE_MIN_CLUSTER
    return val if val >= 1 else _DEFAULT_TEMPLATE_MIN_CLUSTER


def _has_artifact(row: dict) -> bool:
    """True iff the row is disposed via a real exploitation-attempt artifact
    (a PoC file path / drafted-or-attempted exploit). An artifact is genuine by
    nature - it cannot be a bulk prose stub - so artifact-backed rows are always
    counted genuine and are excluded from the template-cluster analysis."""
    if not isinstance(row, dict):
        return False
    art = row.get("exploitation_attempt_artifact")
    return isinstance(art, str) and bool(art.strip())


def _adjudication_reason(row: dict) -> str:
    """The ruled-out-reason prose we judge for substantive-ness / templating.

    Only the ruled_out_reason is judged. A row disposed via an
    exploitation-attempt artifact is handled separately (``_has_artifact``);
    artifact paths are not prose and must not be run through the substantive /
    template-cluster gates."""
    if not isinstance(row, dict):
        return ""
    ruled = row.get("ruled_out_reason")
    if isinstance(ruled, str) and ruled.strip():
        return ruled.strip()
    return ""


def _is_substantive_reason(reason: str) -> bool:
    """(a) SUBSTANTIVE: references the specific guard (file:line / per-guard id /
    backtick code excerpt / concrete check keyword), not generic boilerplate."""
    if not reason or not reason.strip():
        return False
    if _SUBSTANTIVE_FILE_LINE_RE.search(reason):
        return True
    if _SUBSTANTIVE_GUARD_ID_RE.search(reason):
        return True
    if "`" in reason and reason.count("`") >= 2:
        # backtick-quoted code excerpt citing the actual guarded statement
        return True
    if _SUBSTANTIVE_CODE_KEYWORD_RE.search(reason):
        return True
    # Guard enumeration can over-include imports and commented-out code. A
    # source-anchored explanation that explicitly rules such a row out is a
    # genuine adjudication, not an unreasoned template stub.
    if _HONEST_NON_GUARD_RE.search(reason):
        return True
    return False


# Distinctive code tokens (snake_case/CamelCase identifiers >=6 chars, backtick
# excerpts) - the part of a reason that names the SPECIFIC guarded code. Idiom /
# english stopwords are excluded so that two reasons sharing a language idiom
# (e.g. Rust `?`-propagation, Go `if err != nil`) but naming DIFFERENT functions
# land in DIFFERENT shingles, while a reason naming NO specific code collapses to
# the empty (boilerplate) shingle and is correctly clustered + rejected.
_SHINGLE_TOKEN_RE = re.compile(r"`[^`]+`|\b[a-z][a-z0-9_]{5,}\b|\b[A-Z][A-Za-z0-9]{4,}\b")
_SHINGLE_STOPWORDS = frozenset(
    """error propagation operator operators ensures ensure compilation compile
    fails failed propagate propagates propagated guard guards guarded check checks
    checked invariant invariants input inputs reachable reachables violate violates
    violated value values function functions return returns result results before
    after which cannot silently ignored enforce enforces enforced validates validate
    validated prevents prevent through within across against defense depth maintained
    construction generated condition conditions triggers trigger branch message
    pattern patterns caller callers source target offset address bounds boundary
    propagation negative positive instruction instructions compilation""".split()
)


def _template_shingle(reason: str) -> str:
    """Cluster key = the SORTED set of distinctive code tokens a reason cites.

    Position-independent (the distinguishing token may appear anywhere in the
    prose, not just the first 60 chars). A reason that names a specific guarded
    function / type / backtick code excerpt keys on those tokens -> its own
    shingle. A reason with NO distinctive code token (pure boilerplate / idiom)
    keys on the EMPTY shingle -> clusters with every other boilerplate row and is
    rejected when the cluster exceeds the template-fraction threshold. So genuine
    cite-bearing analysis of idiomatic repetitive code is no longer mistaken for
    a template, while fake bulk stubs are still caught. Generic across languages."""
    toks: set[str] = set()
    for m in _SHINGLE_TOKEN_RE.findall(reason or ""):
        t = m.strip("`").strip().lower()
        if t and not t.isdigit() and t not in _SHINGLE_STOPWORDS:
            toks.add(t[:40])
    if not toks:
        return ""  # boilerplate / pure-idiom -> single cluster -> rejected if too big
    return "|".join(sorted(toks))[:200]


def adjudication_genuineness(rows: list[dict], threshold: float | None = None) -> dict:
    """Classify each adjudicated row as genuine or a bulk/generic stub.

    A row is GENUINE iff its reason is (a) SUBSTANTIVE and (b) NOT in the
    largest near-identical template cluster when that cluster exceeds the
    template-fraction threshold.

    Returns a dict with:
      genuine_adjudicated        count of rows passing (a)+(b)
      templated_or_generic_count count of rows failing (a) and/or (b)
      largest_template_cluster   size of the biggest near-identical shingle
      largest_template_fraction  that size / total adjudicated (0.0 if none)
      template_threshold         the active threshold
      genuine_rows / stub_rows   the partitioned row lists (for callers)
    """
    if threshold is None:
        threshold = _template_fraction_threshold()

    # Rows disposed via a real exploitation-attempt artifact are genuine by
    # nature (a drafted/attempted exploit, not prose) and are not subject to the
    # substantive / template-cluster prose gates.
    artifact_rows = [r for r in rows if _has_artifact(r)]
    prose_rows = [r for r in rows if not _has_artifact(r)]

    total = len(rows)
    if total == 0:
        return {
            "genuine_adjudicated": 0,
            "templated_or_generic_count": 0,
            "largest_template_cluster": 0,
            "largest_template_fraction": 0.0,
            "template_threshold": threshold,
            "genuine_rows": [],
            "stub_rows": [],
        }

    reasons: list[tuple[dict, str]] = [(r, _adjudication_reason(r)) for r in prose_rows]
    prose_total = len(reasons)

    # (b) bulk-template detection over the PROSE adjudications. The fraction is
    # taken over prose rows (the population the template can dominate). The
    # reported largest_template_fraction is over ALL adjudications so the cert
    # reads honestly (zebra: 1240/1240 = 1.0).
    min_cluster = _template_min_cluster()
    if prose_total:
        shingles = Counter(_template_shingle(reason) for _r, reason in reasons)
        _key, largest_cluster = shingles.most_common(1)[0]
        # A shingle is bulk only when its cluster is BOTH over the fraction
        # threshold AND absolutely large (>= min_cluster). This stops a tiny
        # prose population from self-dominating while still catching the
        # zebra-class identical-1240 template.
        bulk_shingles = {
            k for k, v in shingles.items()
            if (v / prose_total) > threshold and v >= min_cluster
        }
    else:
        shingles = Counter()
        largest_cluster = 0
        bulk_shingles = set()

    largest_fraction = (largest_cluster / total) if total else 0.0

    genuine_rows: list[dict] = list(artifact_rows)
    stub_rows: list[dict] = []
    for r, reason in reasons:
        substantive = _is_substantive_reason(reason)
        in_bulk = _template_shingle(reason) in bulk_shingles
        if substantive and not in_bulk:
            genuine_rows.append(r)
        else:
            stub_rows.append(r)

    return {
        "genuine_adjudicated": len(genuine_rows),
        "templated_or_generic_count": len(stub_rows),
        "largest_template_cluster": largest_cluster,
        "largest_template_fraction": round(largest_fraction, 6),
        "template_threshold": threshold,
        "genuine_rows": genuine_rows,
        "stub_rows": stub_rows,
    }

GENERATED_AT_NOTE = (
    "written by tools/depth-certificate-build.py (the single R81 cert writer); "
    "the mechanical passes emit per-row JSONL, this tool rolls them up; the "
    "agentic Certify phase calls this same producer"
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    except OSError:
        return []
    return rows


def _read_json(p: Path):
    if not p or not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _gap_adjudicated(g: dict) -> bool:
    """A negative-space gap row counts as ADJUDICATED iff the agent actually
    probed it: it carries an exploitation-attempt artifact OR an explicit
    ruled-out reason. A bare ``gap_found`` boolean with no artifact is NOT
    enough (it has no disposition)."""
    if not isinstance(g, dict):
        return False
    art = g.get("exploitation_attempt_artifact")
    if isinstance(art, str) and art.strip():
        return True
    ruled = g.get("ruled_out_reason")
    if isinstance(ruled, str) and ruled.strip():
        return True
    return False


def _row_key(row: dict) -> str:
    """Stable row identity for reconciling worklist, probe, and candidate rows."""
    if not isinstance(row, dict):
        return ""
    for key in ("guard_id", "candidate_gap_id", "asym_id", "id"):
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    fl = row.get("file_line")
    if isinstance(fl, str) and fl.strip():
        return fl.strip()
    fls = row.get("file_lines")
    if isinstance(fls, list) and fls:
        return "|".join(str(x).strip() for x in fls if str(x).strip())
    return ""


def _asymmetry_id(row: dict) -> str:
    """Stable identity for sibling-asymmetry candidates and verdict rows."""
    key = _row_key(row)
    if key:
        return key
    fls = row.get("file_lines")
    if isinstance(fls, list) and len(fls) >= 2:
        return "ASYM-" + hashlib.sha1(
            f"{fls[0]}|{fls[1]}".encode()
        ).hexdigest()[:12]
    pa = row.get("path_a") if isinstance(row.get("path_a"), dict) else {}
    pb = row.get("path_b") if isinstance(row.get("path_b"), dict) else {}
    fa, la = pa.get("file"), pa.get("line")
    fb, lb = pb.get("file"), pb.get("line")
    if fa and fb and la and lb:
        return "ASYM-" + hashlib.sha1(
            f"{fa}:{la}|{fb}:{lb}".encode()
        ).hexdigest()[:12]
    return ""


def _disposition_reason(row: dict) -> str:
    if not isinstance(row, dict):
        return ""
    for key in ("ruled_out_reason", "why_no_gap_or_exploit", "reason"):
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _genuine_disposition_map(rows: list[dict]) -> dict[str, dict]:
    """Return disposition rows accepted by the shared anti-stub classifier."""
    projected: list[dict] = []
    ids: list[str] = []
    sources: list[dict] = []
    for row in rows:
        rid = _asymmetry_id(row)
        if not rid:
            continue
        proj = {"ruled_out_reason": _disposition_reason(row)}
        art = row.get("exploitation_attempt_artifact")
        if isinstance(art, str) and art.strip():
            proj["exploitation_attempt_artifact"] = art
        projected.append(proj)
        ids.append(rid)
        sources.append(row)
    if not projected:
        return {}
    genuine = adjudication_genuineness(projected)
    genuine_ids = {id(r) for r in genuine["genuine_rows"]}
    accepted: dict[str, dict] = {}
    for rid, source, proj in zip(ids, sources, projected):
        if id(proj) not in genuine_ids:
            continue
        accepted[rid] = source
    return accepted


def _apply_asymmetry_dispositions(asymmetries: list[dict], probes: list[dict]) -> list[dict]:
    """Merge reviewed asymmetry verdicts into current sibling candidate rows."""
    dispositions = _genuine_disposition_map(probes)
    if not dispositions:
        return asymmetries
    merged: list[dict] = []
    for row in asymmetries:
        out = dict(row)
        aid = _asymmetry_id(out)
        if aid:
            out["candidate_gap_id"] = aid
        disp = dispositions.get(aid)
        if disp:
            reason = _disposition_reason(disp)
            art = disp.get("exploitation_attempt_artifact")
            if reason:
                out["ruled_out_reason"] = reason
            if isinstance(art, str) and art.strip():
                out["exploitation_attempt_artifact"] = art.strip()
            out["gap_found"] = bool(disp.get("gap_found"))
            out["disposition"] = "candidate" if disp.get("gap_found") else "drop"
            out["probe_source"] = disp.get("probe_source") or "asymmetry-probe"
        merged.append(out)
    return merged


def _row_disposed(row: dict) -> bool:
    """A candidate gap (negative-space gap OR sibling asymmetry) is DISPOSED iff
    it carries an exploitation-attempt artifact (drafted/attempted) OR a
    source-cited ruled-out reason (dropped)."""
    return _gap_adjudicated(row)


# --- Edge 5: dataflow unguarded-path residual smells ------------------------
# An UNGUARDED multi-hop (closure-corrected) DefUsePath into a value-moving sink
# whose SINK FUNCTION has NO hunter verdict / terminal coverage is a residual
# depth gap the cert must surface (a SMELL). A genuinely-GUARDED path is NOT a gap
# (unguarded==True is already closure-corrected by dataflow_schema.new_path, so a
# require(onlyOwner)/role-check anywhere on the inter-procedural slice excludes
# it). ADDITIVE + default-off: with no slice the smell list is empty and the cert
# is byte-identical to before.

# Sink kinds that MOVE VALUE (mirrors per-function-hacker-questions
# FLOW_VALUE_MOVER_SINK_KINDS + dataflow-slice VALUE_MOVING_CALLEES). A read sink
# (state_var_read) or a non-economic write is NOT a value-mover and is not a smell.
_VALUE_MOVER_SINK_KINDS = frozenset({
    "transfer", "transferFrom", "send", "safeTransfer", "safeTransferFrom",
    "mint", "burn", "_mint", "_burn", "delegatecall", "sendValue", "call",
    "low_level_call", "staticcall", "storage-value",
})


def _read_dataflow_paths(ws: Path) -> list[dict]:
    """Read non-degraded DefUsePath records via the canonical schema reader.

    Returns [] when the slice sidecar is absent / unreadable / the reader is
    unavailable, so a no-slice workspace yields zero residual smells (default-off,
    byte-identical to before any slice existed)."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_schema",
            str(Path(__file__).resolve().parent / "dataflow_schema.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return []
    try:
        return mod.read_paths(str(ws), skip_degraded=True)
    except Exception:
        return []


def _covered_sink_fn_keys(ws: Path) -> set[str]:
    """Set of sink-function identity keys that DO carry a hunter verdict / terminal
    coverage. A sink fn is "covered" when a coverage_unit_verdict exists for it OR
    a hunt-findings sidecar names it.

    The coverage_unit_verdicts/ dir holds one JSON per analyzed unit with a
    ``unit_id`` like ``ClusterLib.sol::ebToVUnits``. We index by BOTH the full
    unit_id and its bare function-name tail (lowercased) so a sink fn recorded as a
    bare name or a fully-qualified signature can still join. Returns an empty set
    when no coverage dir exists (=> every value-flow sink is treated as uncovered,
    the honest worst case: an unhunted slice is all-smell).

    strata 2026-07-01 (loop-caught, serving-join false-red class): the canonical
    per-fn hunt evidence for most workspaces lives in
    ``.auditooor/hunt_findings_sidecars/*.json`` (the sidecar-bridge output), NOT
    ``coverage_unit_verdicts/`` - on strata that dir is EMPTY while 163 real,
    R76-verified hunt sidecars exist (e.g. Tranche.sol:267 ``_deposit`` genuinely
    hunted), so every dataflow-unguarded-path sink was treated as uncovered and
    could never be disposed. Also index the sidecar dir by its
    ``function_anchor.fn`` (same key shape ``business_flow_decompose._hunted_fnkeys``
    already uses, so both readers agree)."""
    keys: set[str] = set()
    aud = ws / ".auditooor"
    cov_dir = aud / "coverage_unit_verdicts"
    if cov_dir.is_dir():
        for p in cov_dir.glob("*.json"):
            obj = _read_json(p)
            if not isinstance(obj, dict):
                continue
            uid = obj.get("unit_id")
            if isinstance(uid, str) and uid.strip():
                keys.add(uid.strip().lower())
                tail = uid.split("::")[-1].strip().lower()
                if tail:
                    keys.add(tail)
    sidecar_dir = aud / "hunt_findings_sidecars"
    if sidecar_dir.is_dir():
        for p in sidecar_dir.glob("*.json"):
            obj = _read_json(p)
            if not isinstance(obj, dict):
                continue
            anchor = obj.get("function_anchor")
            fn = ""
            if isinstance(anchor, dict):
                fn = str(anchor.get("fn") or anchor.get("function") or "")
            if not fn:
                fn = str(obj.get("function") or "")
            fn = fn.split("(", 1)[0].strip()
            if "." in fn:
                fn = fn.rsplit(".", 1)[-1]
            if "::" in fn:
                fn = fn.rsplit("::", 1)[-1]
            if fn:
                keys.add(fn.strip().lower())
    return keys


def _sink_fn_keys(sink: dict) -> set[str]:
    """Candidate identity keys for a DefUsePath sink, to join against coverage.

    Emits the bare function name (and its solidity-signature stem before '('),
    lowercased, plus a ``<file-stem>::<fn>`` form so a coverage unit_id keyed by
    file::fn can match. Never raises."""
    out: set[str] = set()
    fn = str((sink or {}).get("fn") or "").strip()
    if not fn:
        return out
    # Drop any trailing parameter signature for the bare-name form: a slither sink
    # fn is often "Contract.foo(uint256,address)" or "foo(uint256)".
    name = fn.split("(", 1)[0].strip()
    # Go receiver-method form "(pkg.Type).Method" starts with '(' so the split above
    # yields an empty name - recover the method name after the closing ')' (NUVA
    # 2026-07-09: (github.com/provlabs/vault/keeper.msgServer).BridgeBurnShares could
    # not join a coverage verdict keyed by the bare fn name). Generic to every Go ws.
    if not name and ")" in fn:
        name = fn.rsplit(")", 1)[-1].lstrip(". ").split("(", 1)[0].strip()
    # name may be "Contract.foo" - take the dotted tail too.
    tail = name.split(".")[-1].strip()
    for cand in (fn, name, tail):
        c = cand.lower()
        if c:
            out.add(c)
    f = str((sink or {}).get("file") or "").strip()
    if f and tail:
        stem = os.path.basename(f)
        out.add(f"{stem}::{tail}".lower())
    return out


import re as _re_vendored


def _scope_authority_module():
    """Lazy-load scope_authority.py (the in-scope authority built 2026-07-01) so
    a dataflow sink outside the enumerated in-scope target set (test/mock,
    strategies/ - not one of SCOPE.md's 13 targets on strata) is never surfaced
    as a depth-cert residual smell. Reuses the SAME authority
    inscope-disposition-guard.py already uses, per the tool-duplication
    preflight - no bespoke in-scope check here."""
    try:
        import importlib.util as _il
        p = Path(__file__).resolve().parent / "scope_authority.py"
        spec = _il.spec_from_file_location("scope_authority", p)
        m = _il.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


def _is_vendored_sink_path(file_path: str) -> bool:
    """True iff a sink file lives in vendored / dependency code that is OOS for
    the audit (so it must NOT become an in-scope residual smell). Precise: matches
    npm node_modules + foundry lib-install dep roots, but PRESERVES a project's own
    ``contracts/libraries/`` (SSV's ClusterLib/OperatorLib live there). Surfaced by
    real SSV use: edge-5 folded 8 node_modules/@openzeppelin Address.sol delegatecall
    sinks into undisposed depth gaps - vendored OZ, not in-scope SSV."""
    fp = (file_path or "").replace("\\", "/")
    if "/node_modules/" in fp:
        return True
    # Go module cache (`go get` third-party deps: ~/go/pkg/mod/...) = OOS vendored Go,
    # the Go analog of node_modules/@openzeppelin. Surfaced on NUVA 2026-07-09: the
    # provenance-io/provenance x/marker msgServer.Mint/Burn sinks (in ~/go/pkg/mod/
    # github.com/provenance-io/...) folded in as false in-scope undisposed depth gaps.
    # `/pkg/mod/` is unambiguous (the Go module cache); a Go `vendor/` dep tree too.
    if "/pkg/mod/" in fp or "/vendor/" in fp:
        return True
    # foundry-installed deps: /lib/<pkg>/ for a known dependency package (NOT the
    # project's own contracts/libraries/ directory).
    if _re_vendored.search(r"(^|/)lib/(openzeppelin|forge-std|solmate|solady|@|ds-test|create3)", fp):
        return True
    return False


def _dataflow_residual_smells(ws: Path) -> list[dict]:
    """Edge 5: UNGUARDED multi-hop value-flow paths whose sink fn is UNCOVERED.

    One residual-smell row per qualifying path, tagged source=dataflow_unguarded_path
    carrying path_id + sink file:line. Default-off: empty when no slice. Vendored /
    dependency sinks (node_modules, foundry lib deps) are EXCLUDED - they are OOS and
    must not become in-scope residual gaps. So are sinks OUTSIDE the workspace's
    enumerated in-scope target set (strata 2026-07-01, loop-caught: test/Mock*.sol
    and tranches/strategies/ are not in SCOPE.md's 13 targets, yet surfaced as
    undisposable depth gaps - reuses scope_authority, the same authority
    inscope-disposition-guard.py already uses)."""
    paths = _read_dataflow_paths(ws)
    if not paths:
        return []
    covered = _covered_sink_fn_keys(ws)
    sa = _scope_authority_module()
    smells: list[dict] = []
    seen_ids: set[str] = set()
    for p in paths:
        if not isinstance(p, dict):
            continue
        if p.get("unguarded") is not True:
            continue  # genuinely-guarded path is NOT a gap (closure-corrected)
        if int(p.get("call_depth") or 0) < 1:
            continue  # multi-hop only (>=1 inter-procedural hop)
        if str(p.get("confidence") or "") == "heuristic":
            continue  # name-substring fallback is advisory (R80)
        sink = p.get("sink") or {}
        if str(sink.get("kind") or "") not in _VALUE_MOVER_SINK_KINDS:
            continue  # only value-moving sinks
        if _is_vendored_sink_path(str(sink.get("file") or "")):
            continue  # vendored / dependency sink (node_modules, foundry lib) = OOS
        sink_file = str(sink.get("file") or "")
        if sa is not None and sink_file:
            ins = sa.load_inscope(ws)
            if ins.present and not sa.is_inscope_file(ws, sink_file):
                continue  # sink file is not an enumerated in-scope target = OOS
        if _sink_fn_keys(sink) & covered:
            continue  # sink fn HAS a hunter verdict / terminal coverage
        pid = str(p.get("path_id") or "")
        if pid and pid in seen_ids:
            continue
        if pid:
            seen_ids.add(pid)
        sink_file = sink.get("file") or ""
        sink_line = sink.get("line")
        sink_fl = (
            f"{sink_file}:{sink_line}" if (sink_file and sink_line is not None)
            else (sink_file or "")
        )
        smells.append({
            "source": "dataflow_unguarded_path",
            "path_id": pid or "dfp-?",
            "sink_file_line": sink_fl,
            "sink_kind": str(sink.get("kind") or ""),
            "sink_fn": str(sink.get("fn") or ""),
            "call_depth": int(p.get("call_depth") or 0),
            "smell": "unguarded-multi-hop-value-flow-to-uncovered-sink",
            "disposition": "undisposed",
        })
    return smells


# --- LLM-hunt-only (e.g. Obyte Oscript) depth axis --------------------------
# WHY (Obyte 2026-07-09): the negative-space / sibling-diff analyzers that feed
# guards_enumerated / sibling_pairs are STATIC and only parse the engine
# languages (solidity/vyper/rust/go). For a language with NO static/fuzz engine
# - is_llm_hunt_only(lang) is True (Obyte Oscript AAs, `.oscript`/`.aa`) - those
# analyzers emit ZERO guards, so the depth cert would either silent-0-pass
# (false-green: 382 Oscript units invisible while the cert certifies over 0 of
# them) or falsely-block (an Oscript-only workspace pinned at depth-not-run
# forever because a static guard-enumeration that cannot exist for that language
# is demanded). The LANGUAGE-APPROPRIATE depth evidence for a hunt-only language
# is an LLM hunt verdict: a hunt_findings_sidecar anchored to the unit's file. An
# LLM-hunt-only unit is depth-covered iff a matching hunt sidecar exists; one
# WITHOUT stays uncovered (no over-credit). This axis is ADDITIVE and DEFAULT-OFF:
# a workspace with NO llm-hunt-only in-scope units returns None here and its cert
# is byte-identical (the Solidity/Go depth logic is untouched).

# Cert file-list fields are capped so a huge hunt-only workspace cannot bloat the
# cert; the COUNTS stay exact.
_LLM_AXIS_FILE_LIST_CAP = 200


def _rel_to_ws(f: str, ws: Path) -> str:
    """Normalize a unit/sidecar file path to a ws-relative form for exact
    per-FILE join. Strips an absolute ws prefix + leading ``./`` and normalizes
    separators. We deliberately keep the FULL relative path (never the basename):
    several Oscript files share a basename (city-aa/governance.oscript vs
    coop-aa/governance.oscript vs friend-aa/governance.oscript), so a basename
    join would over-credit an uncovered file from a covered sibling's sidecar."""
    s = str(f or "").replace("\\", "/").strip()
    wsp = str(ws).replace("\\", "/").rstrip("/") + "/"
    if s.startswith(wsp):
        s = s[len(wsp):]
    while s.startswith("./"):
        s = s[2:]
    return s


def _sidecar_anchor_file(obj: dict) -> str:
    """The source file a hunt_findings_sidecar is anchored to (function_anchor.file
    is the canonical shape; tolerate a bare top-level ``file``)."""
    if not isinstance(obj, dict):
        return ""
    anchor = obj.get("function_anchor")
    if isinstance(anchor, dict):
        f = anchor.get("file")
        if isinstance(f, str) and f.strip():
            return f.strip()
    f = obj.get("file")
    return f.strip() if isinstance(f, str) and f.strip() else ""


def _hunt_only_sidecar_covered_files(ws: Path) -> tuple[set[str], int]:
    """ws-relative set of source files that carry >=1 hunt_findings_sidecar whose
    anchor file is an LLM-hunt-only language, plus the count of such sidecars.

    Restricting to hunt-only-language anchor files keeps this axis strictly about
    the languages the static engines cannot cover - a solidity/go sidecar never
    credits an oscript unit (and by exact-path join could not anyway)."""
    covered: set[str] = set()
    n = 0
    sidecar_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    if not sidecar_dir.is_dir():
        return covered, n
    for p in sorted(sidecar_dir.glob("*.json")):
        obj = _read_json(p)
        if not isinstance(obj, dict):
            continue
        f = _sidecar_anchor_file(obj)
        if not f:
            continue
        lang = lang_of(f)
        if not (lang and is_llm_hunt_only(lang)):
            continue  # only hunt-only-language sidecars credit this axis
        n += 1
        covered.add(_rel_to_ws(f, ws))
    return covered, n


def _llm_hunt_only_depth_axis(ws: Path):
    """Depth axis for LLM-hunt-only in-scope units. Returns None (and stamps
    nothing) when the workspace has no such units, so an engine-only Solidity/Go/
    Rust workspace cert is byte-identical. Otherwise credits per-unit hunt-sidecar
    coverage (a unit is depth-covered iff a hunt sidecar is anchored to its file)."""
    units = _read_jsonl(ws / ".auditooor" / "inscope_units.jsonl")
    hunt_only_units: list[dict] = []
    engine_units_total = 0
    for u in units:
        if not isinstance(u, dict):
            continue
        lang = u.get("lang") or lang_of(str(u.get("file") or ""))
        if not lang:
            continue  # unrecognized extension: neither axis (no silent miscount)
        if is_llm_hunt_only(lang):
            hunt_only_units.append(u)
        else:
            engine_units_total += 1
    if not hunt_only_units:
        return None  # engine-only ws -> byte-identical cert (default-off)

    covered_files, sidecars_total = _hunt_only_sidecar_covered_files(ws)

    per_lang: dict[str, dict] = {}
    covered_units = 0
    covered_file_set: set[str] = set()
    uncovered_file_set: set[str] = set()
    for u in hunt_only_units:
        lang = u.get("lang") or lang_of(str(u.get("file") or "")) or "unknown"
        uf = _rel_to_ws(str(u.get("file") or ""), ws)
        d = per_lang.setdefault(lang, {"units": 0, "covered": 0})
        d["units"] += 1
        if uf and uf in covered_files:
            covered_units += 1
            d["covered"] += 1
            covered_file_set.add(uf)
        elif uf:
            uncovered_file_set.add(uf)
    units_total = len(hunt_only_units)
    uncovered_units = units_total - covered_units
    if covered_units == 0:
        axis_verdict = "uncovered"
    elif uncovered_units == 0:
        axis_verdict = "covered"
    else:
        axis_verdict = "partial"

    covered_files_sorted = sorted(covered_file_set)
    uncovered_files_sorted = sorted(uncovered_file_set)
    axis = {
        "schema": "auditooor.llm_hunt_only_depth.v1",
        "langs": sorted(per_lang.keys()),
        "units_total": units_total,
        "engine_units_total": engine_units_total,
        "covered_units": covered_units,
        "uncovered_units": uncovered_units,
        "hunt_sidecars_total": sidecars_total,
        "covered_files_count": len(covered_files_sorted),
        "uncovered_files_count": len(uncovered_files_sorted),
        "covered_files": covered_files_sorted[:_LLM_AXIS_FILE_LIST_CAP],
        "uncovered_files": uncovered_files_sorted[:_LLM_AXIS_FILE_LIST_CAP],
        "per_lang": per_lang,
        "axis_verdict": axis_verdict,
        "credit_method": (
            "per-file: an LLM-hunt-only unit is depth-covered iff a "
            "hunt_findings_sidecar is anchored to its file; a fuzz campaign / "
            "mutation-verified harness / static guard-enumeration is NOT demanded "
            "(it cannot exist for a language with no static/fuzz engine)"
        ),
    }
    if len(covered_files_sorted) > _LLM_AXIS_FILE_LIST_CAP:
        axis["covered_files_truncated"] = True
    if len(uncovered_files_sorted) > _LLM_AXIS_FILE_LIST_CAP:
        axis["uncovered_files_truncated"] = True
    return axis


def _normalize_survivors(raw) -> dict:
    """Accept either {survivors,drops,findings_drafted} or a flat list of
    disposition rows. Return a dict with those three lists plus the raw rows so
    the cert records what the agentic validate phase decided."""
    survivors: list = []
    drops: list = []
    drafted: list = []
    if isinstance(raw, dict):
        survivors = list(raw.get("survivors") or [])
        drops = list(raw.get("drops") or [])
        drafted = list(raw.get("findings_drafted") or [])
        # Also fold any flat rows under a "rows"/"dispositions" key.
        flat = raw.get("dispositions") or raw.get("rows") or []
    elif isinstance(raw, list):
        flat = raw
    else:
        flat = []
    for r in flat:
        if not isinstance(r, dict):
            continue
        disp = str(r.get("disposition") or "").strip().lower()
        if disp == "draft":
            survivors.append(r)
            drafted.append(r)
        elif disp == "drop":
            drops.append(r)
    return {"survivors": survivors, "drops": drops, "findings_drafted": drafted}


def build_certificate(ws: Path, survivors_raw=None) -> dict:
    """Roll up the depth-pass artifacts into the cert dict. Pure function:
    computes the cert but does NOT write it (so it is unit-testable)."""
    auditooor = ws / ".auditooor"

    worklist = _read_jsonl(auditooor / "negative_space_worklist.jsonl")
    gaps = _read_jsonl(auditooor / "negative_space_gaps.jsonl")
    asymmetries = _read_jsonl(auditooor / "sibling_guard_asymmetries.jsonl")
    # Drop MALFORMED asymmetry candidates: a sibling-path guard-diff needs TWO real
    # paths to compare. missing-guard-pairs-fold emits naming-pattern "matches" where
    # one side (path_a/path_b) has an empty file - that is not a real asymmetry and
    # cannot be probed, yet was counted as an undisposed gap (5051 of optimism's 5696,
    # a combinatorial naming explosion) -> false depth-pending. Keep only candidates
    # whose BOTH paths cite a real file (the 645 genuine ones the agentic probe ran).
    def _well_formed_asym(a: dict) -> bool:
        if not isinstance(a, dict):
            return False
        pa = a.get("path_a") or {}
        pb = a.get("path_b") or {}
        fa = (pa.get("file") if isinstance(pa, dict) else "") or ""
        fb = (pb.get("file") if isinstance(pb, dict) else "") or ""
        if fa.strip() and fb.strip():
            return True
        # tolerate alternative schemas that carry >=2 file_lines instead of path_a/b
        fls = [str(x) for x in (a.get("file_lines") or []) if str(x).strip()]
        return len(fls) >= 2
    _asym_before = len(asymmetries)
    asymmetries = [a for a in asymmetries if _well_formed_asym(a)]
    _asym_dropped_malformed = _asym_before - len(asymmetries)
    # The agentic probe's dispositions feed the cert. depth-probe-ingest's output
    # naming has drifted (it combines batches to asymmetry_probes_combined.jsonl
    # and/or a per-batch asymmetry_probes/ dir while leaving the canonical
    # asymmetry_probes.jsonl empty) - that stranded 644 real dispositions on
    # optimism and left a false depth-pending. Read the canonical file, then fall
    # back to the combined file, then the per-batch dir, so genuine probe results
    # are never lost to a filename mismatch.
    asymmetry_probes = _read_jsonl(auditooor / "asymmetry_probes.jsonl")
    if not asymmetry_probes:
        asymmetry_probes = _read_jsonl(auditooor / "asymmetry_probes_combined.jsonl")
    if not asymmetry_probes:
        _pdir = auditooor / "asymmetry_probes"
        if _pdir.is_dir():
            for _pf in sorted(_pdir.glob("*.jsonl")) + sorted(_pdir.glob("*.json")):
                asymmetry_probes.extend(_read_jsonl(_pf))
    asymmetries = _apply_asymmetry_dispositions(asymmetries, asymmetry_probes)

    worklist_guard_ids = {_row_key(r) for r in worklist if _row_key(r)}
    guards_analyzed = len(worklist_guard_ids)
    if guards_analyzed == 0:
        # Fall back to row count if guard_id is absent (defensive).
        guards_analyzed = len(worklist)

    sibling_pairs_diffed = len(asymmetries)

    negative_space_ran = guards_analyzed > 0
    sibling_diff_ran = (auditooor / "sibling_guard_asymmetries.jsonl").is_file()

    # Adjudication: every enumerated guard must have a probe verdict.
    adjudicated_gaps = [g for g in gaps if _gap_adjudicated(g)]
    adjudicated_ids = {_row_key(g) for g in adjudicated_gaps if _row_key(g)}
    adjudicated_count = len(adjudicated_ids) if adjudicated_ids else len(adjudicated_gaps)

    # Anti-stub layer: an adjudication counts as GENUINE only if its reason is
    # (a) SUBSTANTIVE and (b) NOT a bulk template. zebra's 1240 identical
    # boilerplate stubs collapse to genuine_adjudicated=0 here; morpho's 124
    # distinct per-guard analyses stay genuine. A workspace is fully adjudicated
    # only when EVERY enumerated guard has a GENUINE adjudication.
    genuine = adjudication_genuineness(adjudicated_gaps)
    genuine_rows = genuine["genuine_rows"]
    genuine_ids = {_row_key(g) for g in genuine_rows if _row_key(g)}
    genuine_adjudicated = len(genuine_ids) if genuine_ids else genuine["genuine_adjudicated"]
    templated_or_generic_count = genuine["templated_or_generic_count"]
    largest_template_cluster = genuine["largest_template_cluster"]
    largest_template_fraction = genuine["largest_template_fraction"]

    missing_guard_ids = sorted(worklist_guard_ids - genuine_ids) if worklist_guard_ids else []
    all_guards_adjudicated = (
        negative_space_ran
        and (
            (not worklist_guard_ids and genuine_adjudicated >= guards_analyzed)
            or (bool(worklist_guard_ids) and not missing_guard_ids)
        )
    )

    # Edge 5: UNGUARDED multi-hop value-flow paths into UNCOVERED sinks are residual
    # depth smells the cert must surface. ADDITIVE + default-off (empty when no
    # slice -> byte-identical cert). A residual smell is an undisposed candidate gap
    # by construction (it has no hunter verdict), so it keeps the verdict honestly at
    # depth-pending until probed - exactly the intent of "0 findings is a SMELL".
    dataflow_residual_smells = _dataflow_residual_smells(ws)

    # Candidate gaps = negative-space gaps that FOUND a gap + sibling asymmetries
    # + dataflow residual smells (edge 5). Each must carry a disposition.
    negspace_candidate_gaps = [g for g in gaps if g.get("gap_found")]
    candidate_gaps = (
        list(negspace_candidate_gaps)
        + list(asymmetries)
        + list(dataflow_residual_smells)
    )
    undisposed = [r for r in candidate_gaps if not _row_disposed(r)]
    all_candidates_disposed = len(undisposed) == 0

    survivors = _normalize_survivors(survivors_raw)
    findings_drafted = survivors["findings_drafted"]
    drops = survivors["drops"]

    # --- HONEST VERDICT -----------------------------------------------------
    if not negative_space_ran and not sibling_diff_ran:
        verdict = VERDICT_NOT_RUN
    elif (
        negative_space_ran
        and sibling_diff_ran
        and all_guards_adjudicated
        and all_candidates_disposed
    ):
        verdict = VERDICT_AUDITED
    else:
        verdict = VERDICT_PENDING

    findings_count = len(findings_drafted)

    # The gate's rich fields. We expose unadjudicated guards + undisposed
    # candidates as the "survivors" the gate validates: an unvalidated row makes
    # the gate fail-survivors-unvalidated, which is exactly the depth-pending
    # state. We mirror that into the gate-facing incomplete_guard_deltas /
    # sibling_asymmetries lists so a legacy gate (presence-only) still fails on
    # an unprobed workspace, AND the new verdict-aware gate fails on
    # depth-pending directly.
    incomplete_guard_deltas: list[dict] = []
    worklist_by_id = {_row_key(r): r for r in worklist if _row_key(r)}
    for gid in missing_guard_ids:
        r = worklist_by_id.get(gid, {})
        incomplete_guard_deltas.append({
            "guard": gid,
            "file_line": r.get("file_line") or "",
            "delta": "missing-genuine-adjudication",
            "exploitation_attempt_artifact": "",
            "ruled_out_reason": "",
        })
    for r in negspace_candidate_gaps:
        if not _row_disposed(r):
            incomplete_guard_deltas.append({
                "guard": r.get("guard_id") or r.get("guard") or "<guard?>",
                "file_line": r.get("file_line") or "",
                "delta": r.get("kind") or "",
                "exploitation_attempt_artifact": r.get(
                    "exploitation_attempt_artifact"
                ) or "",
                "ruled_out_reason": r.get("ruled_out_reason") or "",
            })
    # Edge 5: surface undisposed dataflow residual smells as incomplete deltas so a
    # legacy presence-only gate ALSO fails on an unhunted unguarded value flow.
    for r in dataflow_residual_smells:
        if not _row_disposed(r):
            incomplete_guard_deltas.append({
                "guard": r.get("path_id") or "<path?>",
                "file_line": r.get("sink_file_line") or "",
                "delta": r.get("smell") or "dataflow-unguarded-path",
                "source": "dataflow_unguarded_path",
                "exploitation_attempt_artifact": "",
                "ruled_out_reason": "",
            })
    sibling_asymmetries_unvalidated: list[dict] = []
    for r in asymmetries:
        if not _row_disposed(r):
            sibling_asymmetries_unvalidated.append({
                "pair": r.get("pair") or "<pair?>",
                "file_lines": r.get("file_lines") or [],
                "exploitation_attempt_artifact": r.get(
                    "exploitation_attempt_artifact"
                ) or "",
                "ruled_out_reason": r.get("ruled_out_reason") or "",
            })

    # zero-findings smell is cleared only when the depth layer is fully audited.
    zero_findings_smell_cleared = verdict == VERDICT_AUDITED

    cert = {
        "schema": CERT_SCHEMA,
        "build_schema": SCHEMA,
        "workspace": str(ws),
        "verdict": verdict,
        "method": (
            "roll-up of negative_space_worklist.jsonl + negative_space_gaps.jsonl "
            "+ sibling_guard_asymmetries.jsonl + optional survivors disposition json"
        ),
        # --- task-named roll-up fields ---
        "guards_analyzed": guards_analyzed,
        "sibling_pairs_diffed": sibling_pairs_diffed,
        "candidate_gaps": len(candidate_gaps),
        "candidate_gaps_undisposed": len(undisposed),
        "survivors": survivors["survivors"],
        "drops": drops,
        "findings_drafted": findings_drafted,
        "negative_space_ran": negative_space_ran,
        "sibling_diff_ran": sibling_diff_ran,
        # --- gate-facing rich fields (consumed by depth-certificate-check.py) ---
        "guards_enumerated": guards_analyzed,
        "guards_adjudicated": adjudicated_count,
        # --- anti-stub genuineness fields (R81 hardening) ---
        "genuine_adjudicated": genuine_adjudicated,
        "templated_or_generic_count": templated_or_generic_count,
        "largest_template_cluster": largest_template_cluster,
        "largest_template_fraction": largest_template_fraction,
        "template_threshold": genuine["template_threshold"],
        "sibling_pairs_enumerated": sibling_pairs_diffed,
        "findings_count": findings_count,
        "incomplete_guard_deltas": incomplete_guard_deltas,
        "sibling_asymmetries": sibling_asymmetries_unvalidated,
        "zero_findings_smell_cleared": zero_findings_smell_cleared,
        # --- provenance ---
        "generated_at_utc": _now(),
        "generated_at_note": GENERATED_AT_NOTE,
    }
    # --- edge 5: dataflow unguarded-path residual smells (ADDITIVE, default-off) ---
    # Only stamp the residual-smell fields when a slice produced rows, so a no-slice
    # workspace's cert is STRUCTURALLY byte-identical (modulo the always-fresh
    # generated_at_utc) to before this edge existed.
    if dataflow_residual_smells:
        cert["dataflow_residual_smells"] = dataflow_residual_smells
        cert["dataflow_residual_smells_count"] = len(dataflow_residual_smells)
    # --- LLM-hunt-only (Oscript) depth axis (ADDITIVE, default-off) ----------
    # Only stamped when the workspace has >=1 LLM-hunt-only in-scope unit, so an
    # engine-only (Solidity/Go/Rust) workspace's cert is STRUCTURALLY byte-
    # identical (modulo the always-fresh generated_at_utc). The engine-derived
    # verdict/fields above are untouched; this is a separate, advisory-first axis
    # the gate credits via hunt sidecars instead of demanding static guards.
    llm_axis = _llm_hunt_only_depth_axis(ws)
    if llm_axis is not None:
        cert["llm_hunt_only_depth"] = llm_axis
    return cert


def write_certificate(ws: Path, cert: dict) -> Path:
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "depth_certificate.json"
    out_path.write_text(
        json.dumps(cert, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build the R81 depth certificate (the single cert writer)."
    )
    ap.add_argument("--workspace", required=True, help="workspace path")
    ap.add_argument(
        "--survivors",
        help="optional JSON file of validated draft/drop dispositions from the "
        "agentic validate phase",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="(reserved) treat advisory soft signals as hard. Never relaxes the "
        "honest verdict.",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        msg = {"schema": SCHEMA, "error": f"workspace not a directory: {ws}"}
        print(json.dumps(msg) if args.json else msg["error"], file=sys.stderr)
        return 2

    survivors_raw = None
    if args.survivors:
        sp = Path(args.survivors).expanduser()
        survivors_raw = _read_json(sp)
        if survivors_raw is None:
            msg = {
                "schema": SCHEMA,
                "error": f"--survivors file not found or not JSON: {sp}",
            }
            print(json.dumps(msg) if args.json else msg["error"], file=sys.stderr)
            return 2

    cert = build_certificate(ws, survivors_raw)
    cert["strict"] = bool(args.strict)
    out_path = write_certificate(ws, cert)

    result = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "verdict": cert["verdict"],
        "guards_analyzed": cert["guards_analyzed"],
        "guards_adjudicated": cert["guards_adjudicated"],
        "genuine_adjudicated": cert["genuine_adjudicated"],
        "templated_or_generic_count": cert["templated_or_generic_count"],
        "largest_template_cluster": cert["largest_template_cluster"],
        "largest_template_fraction": cert["largest_template_fraction"],
        "sibling_pairs_diffed": cert["sibling_pairs_diffed"],
        "candidate_gaps": cert["candidate_gaps"],
        "candidate_gaps_undisposed": cert["candidate_gaps_undisposed"],
        "findings_count": cert["findings_count"],
        "cert_path": str(out_path),
    }

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"verdict:        {result['verdict']}")
        print(f"guards_analyzed:{result['guards_analyzed']} "
              f"adjudicated={result['guards_adjudicated']} "
              f"genuine={result['genuine_adjudicated']} "
              f"templated/generic={result['templated_or_generic_count']} "
              f"(largest_cluster={result['largest_template_cluster']}, "
              f"frac={result['largest_template_fraction']})")
        print(f"sibling_pairs:  {result['sibling_pairs_diffed']}")
        print(f"candidate_gaps: {result['candidate_gaps']} "
              f"(undisposed={result['candidate_gaps_undisposed']})")
        print(f"cert written:   {result['cert_path']}")

    # Writing a cert is a SUCCESS for this tool regardless of verdict; the GATE
    # decides pass/fail.
    return 0


if __name__ == "__main__":
    sys.exit(main())
