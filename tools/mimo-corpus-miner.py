#!/usr/bin/env python3
"""mimo-corpus-miner.py - mine all MIMO sidecars to update auditooor corpora.

RELATED TOOLS (read these BEFORE building anything overlapping):
  - tools/promote-mined-to-canonical.py (1153 lines): bridges mined records
    to MCP-readable paths. Operates on CANONICAL corpus, not raw MIMO sidecars.
  - tools/hackerman-etl-from-corpus-mined.py (624 lines): converts
    reference/corpus_mined/*.md to hackerman_record YAML.
  - tools/triage-kill-promoter.py: flows kills to vault_known_dead_ends.
  - tools/hacker-q-reweighter.py: per-question signal reweight (cron-style).

UNIQUE GAP this tool fills: reads RAW per-task mimo_harness_*/*.json sidecars
(MIMO output format, not canonical corpus) and emits 4 specific derived
products (per workspace x attack_class yield matrix, cross-class YES
co-occurrence chain candidates, MAYBE-survivor predicate queue,
hallucination classification by attack class). These specific outputs do
not exist anywhere else and feed vault_mimo_corpus_intelligence.

r36-rebuttal: registered lane mimo-corpus-mining-wave-2026-05-28.

Walks every audit/corpus_tags/derived/mimo_harness_*/*.json and joins
back to the question + workspace to produce derived corpora that feed
the next mining batch (closes the learning loop).

# r36-rebuttal: lane mega-learn-2026-05-28 pathspec-registered
Outputs:
  1. audit/corpus_tags/derived/mimo_observed_yield.json
     - per (attack_class, workspace) yes/no/maybe rates
     - replaces the baked-in ATTACK_CLASS_PRIOR in per-fn ranker
  2. audit/corpus_tags/derived/hacker_q_signal_scores.jsonl
     - per source_question_id signal_score + bucket
     - feeds hacker_questions_library reweight pipeline
  3. audit/corpus_tags/derived/chain_candidates_from_mimo.jsonl
     - cross-class YES co-occurrence per fn/workspace
     - populates the previously-empty chain_candidates.jsonl
  3b. audit/corpus_tags/derived/chain_candidates.jsonl (APPENDED, not rewritten)
     - canonical chain candidates file consumed by vault_hackerman_chain_candidates
     - records use schema auditooor.chain_candidate.v1 (router=mimo_observed,
       category=mimo-mined, statement=JSON of yes_classes co-occurrence)
  4. audit/corpus_tags/derived/exploit_predicates_from_mimo_maybes.jsonl
     - ALL MAYBE candidates (cap lifted 2026-05-28 per operator instruction)
     - promote to exploit_predicates_promoted on operator approval
  5. reports/yield_per_question_per_workspace.json
     - matrix for the operator: question_class x workspace = yield %
  6. audit/corpus_tags/derived/mimo_hallucination_classification.jsonl
     - per question_class, hallucination rate (file_hint empty / code_excerpt missing)
     - feeds anti-pattern catalog updates
  7. audit/corpus_tags/derived/brain_prime_priors_<workspace>.json (per-ws)
     - AUTO-BOOST / AUTO-DEPRIORITIZE cells consumable by brain-prime.py Phase E.1
     - schema auditooor.brain_prime_priors.v1
     - cells emitted when total>=5 AND (yes_rate>=0.10 boost OR no_rate>=0.95 deprioritize)

Schema: auditooor.mimo_corpus_mining.v1

USAGE:
  python3 tools/mimo-corpus-miner.py [--workspace <ws>] [--json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import importlib.util as _ilu
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mimo_corpus_mining.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
DERIVED = AUDITOOOR_ROOT / "audit/corpus_tags/derived"
REPORTS = AUDITOOOR_ROOT / "reports"

# Reuse the submissions ETL helpers (one source of truth for is_confirmed_finding +
# attack-class inference) so S7 confirmed-finding priors stay consistent with the
# own-findings corpus. Import is best-effort: a missing module degrades to mimo-only.
_SUB_PATH = AUDITOOOR_ROOT / "tools" / "hackerman-etl-from-our-submissions.py"
try:
    _s = _ilu.spec_from_file_location("hackerman_etl_submissions", _SUB_PATH)
    _sub = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_sub)
except Exception:
    _sub = None


def gather_confirmed_classes(audits_root: Path) -> dict:
    """{ws_basename: {attack_class: count}} from each workspace's CONFIRMED submissions.

    Closes the outcome->priming loop (S7): brain priming was one-directional (MIMO
    yes-rate only). A confirmed/filed finding is the strongest per-workspace signal of
    a productive attack class, so it should boost that class on the NEXT run. Reuses
    hackerman-etl-from-our-submissions (discover + build_own_record) for the same
    attack-class inference the own-findings corpus uses - no re-implementation.
    """
    out: dict = {}
    if _sub is None or not audits_root.is_dir():
        return out
    for ws in sorted(p for p in audits_root.iterdir() if p.is_dir()):
        try:
            paths = _sub.discover(ws)
        except Exception:
            continue
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            fm = _sub.FILENAME_SEV_RE.search(path.name)
            rel = path.relative_to(ws).as_posix()
            try:
                rec = _sub.build_own_record(
                    ws.name, rel, _sub.extract_title(path, text), text[:6000],
                    filename_severity=fm.group(1) if fm else "",
                    filed="filed" in rel.lower())
            except Exception:
                continue
            ac = str(rec.get("attack_class") or "").strip()
            if ac and ac.lower() not in ("", "unknown", "none"):
                out.setdefault(ws.name, collections.Counter())[ac] += 1
    return out


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_sidecar(p: Path) -> dict | None:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    # Schema 1: MIMO-API wrapper {"status":"ok","result":"```json{...}```"}.
    if d.get("status") == "ok":
        r = d.get("result", "")
        if not isinstance(r, str) or not r.strip():
            return None
        body = r.strip().strip("`").lstrip("json").strip()
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(j, dict):
            return None
        return {"meta": d, "verdict": j, "path": str(p)}
    # Schema 2: bridged hunt sidecar - FLAT verdict object at top level, e.g.
    # {"unit":..., "file_line":..., "verdict":"NEGATIVE", "analysis":[...]}.
    # These live in <ws>/.auditooor/hunt_findings_sidecars/*.json and carry no
    # MIMO-API wrapper. Mirror the schema-tolerance of
    # tools/hunt-obligation-resolve.py _sidecar_has_verdict: a top-level
    # `verdict` (with unit/file_line/analysis present) means the dict itself IS
    # the verdict object. Additive + false-green-safe (a dict with no verdict
    # signal still returns None).
    if d.get("verdict") not in (None, ""):
        # Normalize the flat `verdict` string (NEGATIVE / POSITIVE / MAYBE) into
        # the yes/no/maybe `applies_to_target` token the yield matrix keys on, so
        # a bridged sidecar produces real signal instead of an "?" cell. Only
        # set it when the flat object did not already carry applies_to_target.
        if "applies_to_target" not in d:
            vstr = str(d.get("verdict") or "").strip().lower()
            d = dict(d)
            d["applies_to_target"] = (
                "no" if vstr in ("negative", "no", "n/a", "none", "rejected")
                else "yes" if vstr in ("positive", "yes", "confirmed")
                else "maybe" if vstr in ("maybe", "uncertain", "needs_review")
                else "?")
        return {"meta": d, "verdict": d, "path": str(p)}
    return None


def _safe_ws_filename(ws: str) -> str:
    """Basename a workspace token for use inside an output FILENAME.

    `ws` may arrive as a full path (e.g. /Users/wolf/audits/mezo) from a
    sidecar's `workspace` field. Embedding that raw in
    `brain_prime_priors_{ws}.json` produces an embedded-slash filename, so the
    write resolves into a nested non-existent dir -> FileNotFoundError, which
    silently aborts the per-workspace learning step (regression 2026-06-13).
    Basename it; fall back to "unknown" for an empty/slash-only token."""
    return Path(str(ws)).name or "unknown"


def extract_workspace_from_path(p: str) -> str:
    """e.g. .../mimo_harness_hyperbridge_full/foo.json -> hyperbridge
    Also handles haiku_harness_<ws>_nNNNN/ dirs."""
    import re as _re
    parts = p.split("/")
    for x in parts:
        for prefix in ("mimo_harness_", "haiku_harness_"):
            if x.startswith(prefix):
                ws = x[len(prefix):]
                ws = ws.replace("_full", "").replace("_perfn_pilot", "")
                ws = _re.sub(r"_n\d+$", "", ws)  # strip _n40, _n2007, etc.
                return ws
    # bridged hunt sidecars live at <ws>/.auditooor/hunt_findings_sidecars/X.json;
    # the workspace basename is the dir two levels above the sidecar file.
    if "hunt_findings_sidecars" in parts:
        i = parts.index("hunt_findings_sidecars")
        if i >= 2 and parts[i - 1] == ".auditooor" and parts[i - 2]:
            return parts[i - 2]
    return "unknown"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", help="Optional: mine only one workspace")
    p.add_argument("--audits-root", default=str(Path.home() / "audits"),
                   help="root of audit workspaces; confirmed findings there feed brain_prime priors (S7)")
    p.add_argument("--max-sidecars", type=int, default=0,
                   help="Cap on sidecars processed (0=unlimited)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    # Walk all sidecars. Normalize a workspace PATH to its basename: the
    # harness dirs are named mimo_harness_<basename>_* / haiku_harness_<basename>_*,
    # but the `make mimo-corpus-mine` target and the canonical audit loops pass
    # WS=<full path> (e.g. /Users/wolf/audits/monero-oxide). Without this the
    # glob becomes mimo_harness_/Users/wolf/...* and silently scans 0 sidecars
    # (a no-op per-workspace mine on every loop). Path(...).name is a no-op for a
    # bare workspace name and strips any trailing slash.
    if args.workspace:
        ws_name = Path(args.workspace).name
        patterns = [str(DERIVED / f"mimo_harness_{ws_name}*/*.json"),
                    str(DERIVED / f"haiku_harness_{ws_name}*/*.json")]
        # ALSO mine the bridged hunt verdict sidecars that live IN the workspace
        # at <ws>/.auditooor/hunt_findings_sidecars/. The DERIVED-only globs above
        # are blind to these flat-schema verdicts (the real per-fn hunt output);
        # without this the per-workspace mine silently scans 0 of them. Resolve
        # the full ws path (handles both a bare ws name and an absolute path).
        ws_path = Path(args.workspace)
        if not ws_path.is_absolute():
            cand = Path.home() / "audits" / ws_name
            if cand.is_dir():
                ws_path = cand
        hf_dir = ws_path / ".auditooor" / "hunt_findings_sidecars"
        patterns.append(str(hf_dir / "*.json"))
        patterns.append(str(hf_dir / "*.jsonl"))
    else:
        patterns = [str(DERIVED / "mimo_harness_*/*.json"),
                    str(DERIVED / "haiku_harness_*/*.json")]

    sidecars = []
    for pat in patterns:
        sidecars.extend(glob.glob(pat))
    sidecars.sort()
    if args.max_sidecars:
        sidecars = sidecars[:args.max_sidecars]
    sys.stderr.write(f"[corpus-miner] scanning {len(sidecars)} sidecars\n")

    # Aggregate
    # by (workspace, attack_class) -> Counter(yes/no/maybe)
    yield_matrix = collections.defaultdict(lambda: collections.Counter())
    # by source_question_id -> Counter(yes/no/maybe)
    by_question = collections.defaultdict(lambda: collections.Counter())
    # by (workspace, file, fn) -> list of (class, applies)
    fn_class_results = collections.defaultdict(list)
    # candidates by status for chain mining + MAYBE surviving predicates
    maybe_records = []
    hallucination_signals = collections.Counter()  # per attack_class

    parsed_ok = 0
    for sc_path in sidecars:
        parsed = parse_sidecar(Path(sc_path))
        if not parsed:
            continue
        parsed_ok += 1
        v = parsed["verdict"]
        m = parsed["meta"]
        # r36-rebuttal: lane sidecar-backfill-2026-05-28
        # Prefer BACKFILLED root-level fields over verdict body (backfill tool
        # writes workspace/attack_class/source_question_id/function_anchor to
        # the sidecar root via mimo-sidecar-metadata-backfill.py).
        ws = m.get("workspace") or extract_workspace_from_path(sc_path)
        applies = v.get("applies_to_target", "?")
        # attack_class precedence: backfilled root > verdict body > source_question_id slug
        # probe_class (R80-safe question metadata stamped by per-fn-question-ranker)
        # is keyed BELOW a real attack_class claim but ABOVE the source_question_id
        # slug / "generic" fallback - so claim-free coverage-fold questions land in
        # their probe bucket (reentrancy / access-control / serialization / ...)
        # instead of collapsing the whole matrix to a single "generic" cell.
        # Flat hunt sidecars carry attack_classes_checked (a LIST), not a scalar
        # attack_class; surface its first element so they land in their real class
        # bucket (reentrancy / erc4626-share-inflation / ...) instead of collapsing
        # to "generic" (L7 granularity, 2026-06-30).
        _acc = v.get("attack_classes_checked") or m.get("attack_classes_checked") or []
        _acc0 = (str(_acc[0]) if isinstance(_acc, list) and _acc else "")
        klass = (m.get("attack_class")
                 or v.get("attack_class")
                 or m.get("probe_class")
                 or v.get("probe_class")
                 or _acc0
                 or m.get("source_question_id") or "generic").split(":")[-1][:60]
        klass = klass.lower() if klass else "generic"
        file_hint = str(v.get("file_path_hint") or v.get("file_line") or "")[:120]
        fn_name = ""
        # function_anchor: prefer backfilled root (file:line from prompt context)
        # over verdict-body anchor
        anchor = m.get("function_anchor") if isinstance(m.get("function_anchor"), dict) else None
        if anchor:
            fn_name = anchor.get("fn") or f"line{anchor.get('line_start', '?')}"
            if not file_hint and anchor.get("file"):
                file_hint = anchor["file"]

        yield_matrix[(ws, klass)][applies] += 1
        qid = m.get("source_question_id", "")
        if qid:
            by_question[qid][applies] += 1
        if fn_name and file_hint:
            fn_class_results[(ws, file_hint, fn_name)].append((klass, applies))

        # MAYBE candidates that have substantive metadata -> predicate candidates
        if applies == "maybe":
            falsif = v.get("falsification_attempt", "")
            if len(falsif) > 40:  # has substance
                maybe_records.append({
                    "task_id": m.get("task_id", "?"),
                    "workspace": ws,
                    "attack_class": klass,
                    # (x or "") not x.get(k, "") - the key can be PRESENT with a null
                    # value (native flat sidecars carry rubric_row_cited: null), and
                    # None[:120] raises TypeError, crashing the whole corpus-closure ETL.
                    "candidate_finding": (v.get("candidate_finding") or "")[:200],
                    "file_path_hint": file_hint,
                    "falsification_attempt": falsif[:300],
                    "rubric_row_cited": (v.get("rubric_row_cited") or "")[:120],
                    "severity_estimate": v.get("severity_estimate", "?"),
                })

        # Hallucination signal: CONFIRMED+conceptual OR file_hint empty on YES
        if applies in ("yes", "maybe"):
            r_text = str(v).lower()
            if (not file_hint) or "n/a" in file_hint.lower() or "conceptual" in r_text:
                hallucination_signals[klass] += 1

    sys.stderr.write(f"[corpus-miner] parsed_ok={parsed_ok} maybe_predicates={len(maybe_records)} "
                     f"fn_clusters={len(fn_class_results)}\n")

    # === Output 1: observed yield matrix ===
    out_yield = DERIVED / "mimo_observed_yield.json"
    yield_dict = {}
    for (ws, klass), ct in yield_matrix.items():
        total = sum(ct.values())
        if total < 3:  # noise floor
            continue
        yield_dict.setdefault(ws, {})[klass] = {
            "yes": ct.get("yes", 0),
            "no": ct.get("no", 0),
            "maybe": ct.get("maybe", 0),
            "total": total,
            "yes_rate": round(ct.get("yes", 0) / total, 4),
            "maybe_rate": round(ct.get("maybe", 0) / total, 4),
        }
    out_yield.write_text(json.dumps({
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "sidecars_scanned": parsed_ok,
        "by_workspace": yield_dict,
    }, indent=2))

    # === Output 2: hacker-q signal scores ===
    out_sig = DERIVED / "hacker_q_signal_scores.jsonl"
    sig_rows = []
    for qid, ct in by_question.items():
        total = sum(ct.values())
        if total < 2:
            continue
        yes, maybe, no = ct.get("yes", 0), ct.get("maybe", 0), ct.get("no", 0)
        score = yes * 5 + maybe * 1 - no * 0.1
        bucket = (
            "HIGH-SIGNAL" if yes > 0 else
            "MEDIUM-SIGNAL" if maybe >= 2 and maybe / total >= 0.2 else
            "LOW-SIGNAL-DEPRIORITIZE" if no / total >= 0.95 and total >= 5 else
            "INSUFFICIENT-DATA"
        )
        sig_rows.append({
            "schema_version": SCHEMA, "kind": "hacker_q_signal",
            "question_id": qid,
            "yes": yes, "maybe": maybe, "no": no, "total": total,
            "signal_score": round(score, 3),
            "signal_bucket": bucket,
            "promoted_at_utc": iso_now(),
        })
    with out_sig.open("w") as fh:
        for r in sig_rows:
            fh.write(json.dumps(r) + "\n")

    # === Output 3: chain candidates from cross-class YES co-occurrence ===
    out_chains = DERIVED / "chain_candidates_from_mimo.jsonl"
    chain_rows = []
    for (ws, file_hint, fn), results in fn_class_results.items():
        yes_classes = sorted(set(c for c, a in results if a == "yes"))
        if len(yes_classes) >= 2:  # multiple YES classes on same fn = chain candidate
            chain_rows.append({
                "schema_version": SCHEMA, "kind": "chain_candidate_from_mimo",
                "workspace": ws,
                "function_anchor": {"file": file_hint, "fn": fn},
                "yes_classes": yes_classes,
                "evidence_count": len(results),
                "promoted_at_utc": iso_now(),
            })
    with out_chains.open("w") as fh:
        for r in chain_rows:
            fh.write(json.dumps(r) + "\n")

    # === Output 4: exploit predicates from MAYBE survivors ===
    # r36-rebuttal: 500-cap lifted 2026-05-28 per operator mega-learn instruction
    out_preds = DERIVED / "exploit_predicates_from_mimo_maybes.jsonl"
    with out_preds.open("w") as fh:
        for m in maybe_records:  # ALL records — cap lifted (was [:500])
            fh.write(json.dumps({
                "schema_version": SCHEMA, "kind": "predicate_from_mimo_maybe",
                **m,
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "needs_audit": True,
                "promoted_at_utc": iso_now(),
            }) + "\n")

    # === Output 3b: APPEND to canonical chain_candidates.jsonl ===
    # Distinct from output 3 (chain_candidates_from_mimo.jsonl) which is a
    # source-specific sidecar. The canonical file is what
    # vault_hackerman_chain_candidates queries. We use idempotent append-only
    # with record_id derived from (workspace, file, fn, sorted yes_classes)
    # so re-runs don't duplicate.
    out_canonical_chains = DERIVED / "chain_candidates.jsonl"
    existing_ids = set()
    if out_canonical_chains.exists():
        for ln in out_canonical_chains.read_text().splitlines():
            try:
                d = json.loads(ln)
                existing_ids.add(d.get("record_id", ""))
            except Exception:
                pass
    appended = 0
    with out_canonical_chains.open("a") as fh:
        for (ws, file_hint, fn), results in fn_class_results.items():
            yes_classes = sorted(set(c for c, a in results if a == "yes"))
            if len(yes_classes) < 2:
                continue
            rid = f"mimo-{ws}-{file_hint[:40]}-{fn[:40]}-{'_'.join(yes_classes)[:80]}"
            rid = rid.replace("/", "_").replace(" ", "_")[:200]
            if rid in existing_ids:
                continue
            existing_ids.add(rid)
            stmt = {
                "chain_possible": "yes",
                "chain_direction": "->".join(yes_classes[:3]),
                "compound_impact": (
                    f"MIMO mining observed YES verdicts in {len(yes_classes)} "
                    f"attack classes ({', '.join(yes_classes[:5])}) on the same "
                    f"function {fn} in {ws}. Cross-class YES co-occurrence is a "
                    f"chain-candidate signal."
                ),
                "chain_likelihood_1_to_5": min(5, len(yes_classes)),
                "evidence_count": len(results),
            }
            fh.write(json.dumps({
                "schema_version": "auditooor.chain_candidate.v1",
                "record_id": rid,
                "kind": "chain_candidate",
                "router": "mimo_observed",
                "category": "mimo-mined",
                "statement": json.dumps(stmt),
                "target_lang": "unknown",
                "raw_keys": ["workspace", "function_anchor", "yes_classes"],
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_task_id": f"mimo-corpus-miner-{ws}",
                "audit_status": "needs_audit",
                "ts_utc": iso_now(),
                "workspace": ws,
                "function_anchor": {"file": file_hint, "fn": fn},
                "yes_classes": yes_classes,
            }) + "\n")
            appended += 1
    sys.stderr.write(f"[corpus-miner] appended {appended} new canonical chain candidates "
                     f"(total file: {len(existing_ids)})\n")

    # === Output 7: per-workspace brain_prime_priors ===
    # Threshold: total>=5; yes_rate>=0.10 boost (rare YES is the gold);
    # no_rate>=0.95 deprioritize (consistent NO = drop class for this ws).
    # Consumed by brain-prime.py Phase E.1 to adjust per-fn ranker scores.
    # S7: confirmed/filed findings per workspace also boost their attack class on the
    # next run (close the outcome->priming loop). Indexed by sanitized basename so it
    # matches the mimo ws token regardless of path-vs-basename form.
    confirmed_by_ws = gather_confirmed_classes(Path(os.path.expanduser(args.audits_root))) \
        if getattr(args, "audits_root", None) else {}
    confirmed_idx = {_safe_ws_filename(k): v for k, v in confirmed_by_ws.items()}

    brain_priors_emitted = 0
    # iterate mimo workspaces PLUS confirmed-only workspaces (findings but no sidecars)
    ws_tokens = list(yield_dict.keys())
    seen_bn = {_safe_ws_filename(w) for w in ws_tokens}
    for ws_name in confirmed_by_ws:
        if _safe_ws_filename(ws_name) not in seen_bn:
            ws_tokens.append(ws_name)
    for ws in ws_tokens:
        classes = yield_dict.get(ws, {})
        boost_cells = []
        deprio_cells = []
        for klass, stats in classes.items():
            total = stats["total"]
            if total < 5:
                continue
            yes_rate = stats["yes_rate"]
            no = stats.get("no", 0)
            no_rate = no / total if total else 0
            if yes_rate >= 0.10:
                boost_cells.append({
                    "attack_class": klass, "yes_rate": yes_rate, "boost_source": "mimo",
                    "total": total, "boost_score": round(yes_rate * 10, 2),
                })
            elif no_rate >= 0.95 and total >= 10:
                deprio_cells.append({
                    "attack_class": klass, "no_rate": round(no_rate, 4),
                    "total": total, "penalty_score": -3.0,
                })
        # merge confirmed-finding boost (S7): a confirmed class either upgrades an
        # existing mimo cell to mimo+confirmed or adds a new confirmed-finding cell.
        conf = confirmed_idx.get(_safe_ws_filename(ws), {})
        by_class = {c["attack_class"]: c for c in boost_cells}
        for klass, cnt in conf.items():
            if klass in by_class:
                cell = by_class[klass]
                cell["boost_source"] = "mimo+confirmed"
                cell["confirmed_count"] = int(cnt)
                cell["boost_score"] = round(cell["boost_score"] + min(int(cnt), 3) + 2.0, 2)
            else:
                boost_cells.append({
                    "attack_class": klass, "boost_source": "confirmed-finding",
                    "confirmed_count": int(cnt), "boost_score": round(min(int(cnt), 3) + 2.0, 2),
                })
        if not (boost_cells or deprio_cells):
            continue
        # ws may arrive as a full path (e.g. /Users/wolf/audits/mezo) from a
        # sidecar's workspace field; basename it so the output filename carries no
        # embedded slashes (else FileNotFoundError on a nested non-existent dir).
        safe_ws = _safe_ws_filename(ws)
        out_priors = DERIVED / f"brain_prime_priors_{safe_ws}.json"
        out_priors.write_text(json.dumps({
            "schema_version": "auditooor.brain_prime_priors.v1",
            "generated_at_utc": iso_now(),
            "workspace": ws,
            "source": "mimo-corpus-miner",
            "auto_boost_cells": sorted(boost_cells, key=lambda c: -c["boost_score"]),
            "auto_deprioritize_cells": sorted(deprio_cells, key=lambda c: c["penalty_score"]),
            "consumer": "brain-prime.py Phase E.1",
        }, indent=2))
        brain_priors_emitted += 1
    sys.stderr.write(f"[corpus-miner] emitted {brain_priors_emitted} brain_prime_priors files\n")

    # === Output 5: per-workspace x per-class matrix ===
    REPORTS.mkdir(parents=True, exist_ok=True)
    matrix_path = REPORTS / "yield_per_question_per_workspace.json"
    matrix_path.write_text(json.dumps({
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "workspaces": sorted(yield_dict.keys()),
        "classes": sorted(set(k for ws in yield_dict.values() for k in ws.keys())),
        "matrix": yield_dict,
    }, indent=2))

    # === Output 6: hallucination classification ===
    out_hallu = DERIVED / "mimo_hallucination_classification.jsonl"
    with out_hallu.open("w") as fh:
        for klass, n in hallucination_signals.most_common():
            yield_total = sum(yield_matrix[(ws, k)][a] for (ws, k), ct in yield_matrix.items()
                              for a in ("yes", "maybe") if k == klass)
            if yield_total == 0:
                rate = 0
            else:
                rate = n / yield_total
            fh.write(json.dumps({
                "schema_version": SCHEMA, "kind": "hallucination_rate",
                "attack_class": klass,
                "hallucination_signals": n,
                "yes_maybe_total": yield_total,
                "hallucination_rate": round(rate, 4),
                "promoted_at_utc": iso_now(),
            }) + "\n")

    summary = {
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "sidecars_scanned": parsed_ok,
        "outputs": {
            "observed_yield": str(out_yield.relative_to(AUDITOOOR_ROOT)),
            "hacker_q_signal_scores": str(out_sig.relative_to(AUDITOOOR_ROOT)),
            "chain_candidates_from_mimo": str(out_chains.relative_to(AUDITOOOR_ROOT)),
            "exploit_predicates_from_maybes": str(out_preds.relative_to(AUDITOOOR_ROOT)),
            "yield_matrix": str(matrix_path.relative_to(AUDITOOOR_ROOT)),
            "hallucination_classification": str(out_hallu.relative_to(AUDITOOOR_ROOT)),
        },
        # r36-rebuttal: lane mega-learn-2026-05-28 counts dict extended
        "counts": {
            "yield_cells": sum(len(v) for v in yield_dict.values()),
            "signal_rows": len(sig_rows),
            "chain_candidates": len(chain_rows),
            "canonical_chains_appended": appended,
            "maybe_predicates": len(maybe_records),
            "hallucination_classes": len(hallucination_signals),
            "brain_prime_priors_emitted": brain_priors_emitted,
        },
    }
    sys.stderr.write(f"[corpus-miner] complete: {summary['counts']}\n")
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Scanned: {parsed_ok} sidecars")
        print(f"Yield cells (ws x class): {summary['counts']['yield_cells']}")
        print(f"Signal scores (per question): {summary['counts']['signal_rows']}")
        print(f"Chain candidates: {summary['counts']['chain_candidates']}")
        print(f"MAYBE predicates promoted: {summary['counts']['maybe_predicates']}")
        print(f"Hallucination classes: {summary['counts']['hallucination_classes']}")
        for k, v in summary["outputs"].items():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
