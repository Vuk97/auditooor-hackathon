#!/usr/bin/env python3
"""novelty-gate-flywheel.py - the NOVELTY classifier + arsenal flywheel.

Stage 5 of the LOGIC ARSENAL ROADMAP NOVELTY-GENERATION LAYER
(docs/LOGIC_ARSENAL_ROADMAP.md lines 53-76). The invariant-synth /
assumption engines (value-conservation-invariant-synth.py [VCIS],
novel-vector-invariant-miner.py) DERIVE a protocol's OWN invariants FROM ITS
CODE - not from a corpus class list - and surface candidate violations. THIS
tool takes those candidates and answers the novelty question:

    A candidate that violates a DERIVED invariant but matches NO corpus class
    is the HIGHEST-value signal -> label NOVEL, dedup vs the corpus class
    taxonomy AND prior_audits, and FEED IT BACK as a NEW corpus-class record
    so the arsenal learns net-new vectors from its own hunts.

CRITICAL GUARD-RAIL (roadmap): the invariants are DERIVED FROM THE WORKSPACE
CODE, and the novelty of a violation does NOT depend on it matching a known
class. This tool NEVER decides novelty by asking "is this one of the 56
classes?" as a *gate on surfacing* - the candidate is already surfaced by the
derive engines. It only asks "does this surfaced violation ALREADY have a
corpus name?" If not, it is NOVEL (not filtered out).

WHY THIS IS NOT A DUPLICATE OF EXISTING PRIMITIVES
==================================================
It EXTENDS, does not rebuild:
  * value-conservation-invariant-synth.py / novel-vector-invariant-miner.py
    DERIVE the invariants (this tool consumes their output as candidates).
  * novel-bug-class-surfacer.py mines the BUG_CLASSES *registry* for missing
    analogical vertices (corpus-internal); it does NOT take live per-workspace
    invariant-violation candidates and route them through corpus + prior-audit
    dedup into a NOVEL label + a fed-back new-class record. That routing +
    flywheel emission is what THIS tool adds.
  * early-prior-audit-dedup-gate.py / prior-audit-dupe-gate.py dedup *findings*
    vs prior audits; this tool dedups DERIVED-INVARIANT candidates vs the
    corpus CLASS taxonomy (the 56-class vocabulary) AND prior audits, and the
    non-match branch MINTS a new class (the learning flywheel), which the dupe
    gates never do.

INPUT (candidate violations - from the derive engines, per workspace)
=====================================================================
Default source (no --candidates): the VCIS manifest
  <ws>/.auditooor/vcis/vcis_manifest.json  (verdicts[] - each a derived
  conservation/monotonicity invariant over REAL protocol symbols).
Optional additive source: novel-vector-invariant-miner JSONL via --miner.
Explicit override: --candidates <jsonl> where each line is a candidate with
  at least {statement | property_form, tokens?, target?, function?}.

OUTPUT (owned backend - this tool's own directory)
==================================================
<ws>/.auditooor/novelty/
  novelty_verdicts.jsonl   - one row per candidate: NOVEL | KNOWN(class_id)
  new_classes.jsonl        - auditooor.novel_class.v1 records (the flywheel;
                             one per NOVEL candidate, deduped by class slug).
  burndown_feed.jsonl      - LOGIC_ARSENAL_BURNDOWN feed rows (the enforcement
                             lane appends these into the 56-class vocabulary /
                             corpus_tags; this tool NEVER edits those files of
                             record directly - it EMITS a feed the owning lane
                             consumes, per the dispatch note).
  novelty_summary.json     - counts + non-vacuity attestation.

DEDUP MODEL
===========
Corpus-class match: each taxonomy class contributes a keyword/phrase set
(class_id words + name + description words + keywords[]). A candidate's text
blob (derived-invariant statement + property_form + real symbol tokens +
credit fields + function name) is scored against each class:
    score = 2*phrase_hits + word_overlap_count
A candidate is KNOWN iff best_score >= --match-threshold (default 3). NOVEL
otherwise. Prior-audit overlap is computed the same way over prior_audits
DIGEST text; a strong prior-audit hit also demotes NOVEL->KNOWN(prior-audit)
(you cannot mint a "novel" class for something a prior audit already named).

NON-VACUITY (fail-loud, never silent-green)
===========================================
- FAILS if the taxonomy loads 0 classes (corpus vocabulary missing).
- FAILS if 0 candidates are examined (nothing to classify -> not a pass).
These are hard exits so the flywheel can never vacuously "pass" on empty input.

Stdlib + pyyaml only. Does NOT commit, does NOT edit the taxonomy / burndown
files of record, does NOT touch the Makefile or exploit-queue.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import zero_day_fuel_identity as zero_day_identity

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - pyyaml is present in this repo
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAXONOMY = ROOT / "reference" / "bug_class_taxonomy.yaml"

# words that carry no discriminating signal for corpus/prior-audit matching
STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "is", "are", "be",
    "by", "for", "with", "that", "this", "it", "as", "at", "not", "no", "via",
    "must", "may", "can", "when", "if", "any", "all", "each", "value", "state",
    "code", "path", "check", "into", "over", "from", "than", "less", "more",
    "field", "fields", "call", "sum", "form", "does", "only", "which",
}

WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]+")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_ident(tok: str) -> list[str]:
    """camelCase / snake_case / path -> lowercased word list."""
    tok = re.sub(r"[./_\-:]+", " ", tok)
    tok = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tok)
    return [w.lower() for w in WORD_RE.findall(tok)]


def _words(text: str) -> set[str]:
    out: set[str] = set()
    for m in WORD_RE.findall(text):
        for w in _split_ident(m):
            if len(w) >= 3 and w not in STOPWORDS:
                out.add(w)
    return out


# ---------------------------------------------------------------------------
# corpus taxonomy loader
# ---------------------------------------------------------------------------

def load_taxonomy(path: Path) -> list[dict]:
    if yaml is None:
        raise SystemExit("FATAL: pyyaml unavailable; cannot load corpus taxonomy")
    if not path.exists():
        raise SystemExit(f"FATAL: taxonomy not found: {path}")
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, list):
        raise SystemExit(f"FATAL: taxonomy is not a list: {path}")
    classes = []
    for entry in data:
        if not isinstance(entry, dict) or "class_id" not in entry:
            continue
        if entry.get("deprecated") is True:
            continue
        cid = str(entry["class_id"])
        phrases: set[str] = set()
        blobwords: set[str] = set()
        for kw in entry.get("keywords", []) or []:
            kw = str(kw).strip().lower()
            if " " in kw and len(kw) >= 5:
                phrases.add(kw)
            blobwords |= _words(kw)
        blobwords |= _words(cid)
        blobwords |= _words(str(entry.get("name", "")))
        blobwords |= _words(str(entry.get("description", "")))
        blobwords -= STOPWORDS
        classes.append({
            "class_id": cid,
            "phrases": phrases,
            "words": blobwords,
            "severity_hint": entry.get("severity_hint", ""),
        })
    return classes


def score_against_class(blob_text: str, blob_words: set[str], klass: dict) -> int:
    phrase_hits = sum(1 for p in klass["phrases"] if p in blob_text)
    overlap = len(blob_words & klass["words"])
    return 2 * phrase_hits + overlap


# ---------------------------------------------------------------------------
# prior-audit corpus loader
# ---------------------------------------------------------------------------

# A "code symbol" is a distinctive identifier: camelCase hump, snake_case, or an
# internal digit. Prose words ("balance", "protocol", "invariant") are NOT
# symbols, so prior-audit dedup keys on genuine symbol REUSE, not common English
# overlap (a bag-of-words overlap demotes almost everything to KNOWN - the
# 76/89 over-match that the nuva proof exposed).
SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}")


def _is_symbol(tok: str) -> bool:
    if "_" in tok:
        return True
    if re.search(r"[a-z][A-Z]", tok):  # camelCase hump
        return True
    if re.search(r"[A-Za-z][0-9]", tok):  # internal digit (erc4626, sha256)
        return True
    return False


def _symbols(text: str) -> set[str]:
    out: set[str] = set()
    for m in SYMBOL_RE.findall(text):
        if _is_symbol(m) and len(m) >= 5:
            out.add(m.lower())
    return out


def load_prior_audit_symbols(ws: Path) -> set[str]:
    syms: set[str] = set()
    pa = ws / "prior_audits"
    if not pa.is_dir():
        return syms
    # prefer the human DIGEST markdowns (clean prose) over raw html dumps
    digests = sorted(pa.glob("DIGEST_*.md"))
    srcs = digests if digests else sorted(pa.glob("*.txt"))
    for f in srcs[:12]:
        try:
            syms |= _symbols(f.read_text(errors="ignore")[:400_000])
        except Exception:
            continue
    return syms


# ---------------------------------------------------------------------------
# candidate loaders (from the DERIVE engines)
# ---------------------------------------------------------------------------

def candidates_from_vcis(ws: Path) -> list[dict]:
    mf = ws / ".auditooor" / "vcis" / "vcis_manifest.json"
    if not mf.exists():
        return []
    data = json.loads(mf.read_text())
    verdicts = data.get("verdicts", []) if isinstance(data, dict) else []
    out = []
    for v in verdicts:
        pform = v.get("property_form", "")
        fn = v.get("function", "")
        toks = list(v.get("tokens", []) or []) + list(v.get("credit_fields", []) or [])
        statement = (
            f"derived {pform} invariant on {fn}: "
            f"protocol balance conserves credit-side liability "
            f"{'+'.join(v.get('credit_fields', []) or [])}"
        )
        out.append({
            "invariant_id": v.get("property_name", f"vcis-{fn}"),
            "statement": statement,
            "property_form": pform,
            "tokens": toks,
            "function": fn,
            "target": v.get("file_line", ""),
            "source_lane": "vcis",
            "violated": True,  # a derived-invariant candidate awaiting refutation
        })
    return out


def candidates_from_miner(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        out.append({
            "invariant_id": r.get("invariant_id") or r.get("id", "miner"),
            "statement": r.get("statement") or r.get("assertion_expr", ""),
            "property_form": r.get("family", ""),
            "tokens": r.get("tokens", []) or [],
            "function": r.get("function", ""),
            "target": r.get("target", ""),
            "source_lane": "novel-vector-invariant-miner",
            "violated": bool(r.get("violated", True)),
        })
    return out


def candidates_from_jsonl(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        out.append({
            "invariant_id": r.get("invariant_id", "cand"),
            "statement": r.get("statement", r.get("property_form", "")),
            "property_form": r.get("property_form", ""),
            "tokens": r.get("tokens", []) or [],
            "function": r.get("function", ""),
            "target": r.get("target", ""),
            "source_lane": r.get("source_lane", "external"),
            "violated": bool(r.get("violated", True)),
        })
    return out


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

def candidate_blob(c: dict) -> tuple[str, set[str]]:
    parts = [c.get("statement", ""), c.get("property_form", ""),
             c.get("function", ""), c.get("target", "")]
    parts += [str(t) for t in c.get("tokens", [])]
    text = " ".join(parts)
    return text.lower(), _words(text)


def mint_class_slug(c: dict) -> str:
    """FAMILY-level slug so the flywheel mints ONE new corpus class per novel
    invariant family (e.g. one 'value-conservation-solvency-floor' class), not
    one per candidate. Keying on property_form (the derive-engine's invariant
    family) collapses N near-identical conservation violations into a single
    net-new class - a clean, learnable feed row rather than 25 near-dupes."""
    fam = str(c.get("property_form") or "").strip()
    if not fam:
        fam = str(c.get("function") or c.get("invariant_id") or "derived-invariant")
    slug = re.sub(r"[^a-z0-9]+", "-", fam.lower()).strip("-")[:48]
    return f"novel-{slug or 'derived-invariant'}"


def candidate_symbols(c: dict) -> set[str]:
    """Distinctive code identifiers the candidate is about (real symbol names),
    used for prior-audit dedup so common English prose can't demote to KNOWN."""
    syms: set[str] = set()
    for t in c.get("tokens", []) or []:
        n = re.sub(r"[^A-Za-z0-9_]", "", str(t))
        if len(n) >= 5 and (_is_symbol(n) or n[0].isupper()):
            syms.add(n.lower())
    fn = re.sub(r"[^A-Za-z0-9_]", "", str(c.get("function", "")))
    if len(fn) >= 5 and _is_symbol(fn):
        syms.add(fn.lower())
    return syms


def classify(candidates, classes, prior_symbols, match_threshold, prior_threshold):
    verdicts = []
    novel_classes = {}
    burndown_feed = []
    for c in candidates:
        blob_text, blob_words = candidate_blob(c)
        best_cid, best_score = None, 0
        for k in classes:
            s = score_against_class(blob_text, blob_words, k)
            if s > best_score:
                best_score, best_cid = s, k["class_id"]
        prior_overlap = len(candidate_symbols(c) & prior_symbols)

        if best_score >= match_threshold:
            verdict = {
                "invariant_id": c["invariant_id"],
                "label": "KNOWN",
                "matched_class": best_cid,
                "match_score": best_score,
                "prior_audit_overlap": prior_overlap,
                "source_lane": c["source_lane"],
                "target": c["target"],
                "reason": f"derived-invariant already named by corpus class '{best_cid}'",
            }
        elif prior_overlap >= prior_threshold:
            verdict = {
                "invariant_id": c["invariant_id"],
                "label": "KNOWN",
                "matched_class": "prior-audit",
                "match_score": best_score,
                "prior_audit_overlap": prior_overlap,
                "source_lane": c["source_lane"],
                "target": c["target"],
                "reason": "derived-invariant already covered by a prior audit",
            }
        else:
            slug = mint_class_slug(c)
            verdict = {
                "invariant_id": c["invariant_id"],
                "label": "NOVEL",
                "matched_class": None,
                "nearest_class": best_cid,
                "nearest_score": best_score,
                "prior_audit_overlap": prior_overlap,
                "priority": "HIGHEST",
                "minted_class_id": slug,
                "source_lane": c["source_lane"],
                "target": c["target"],
                "reason": ("violates a DERIVED invariant but matches NO corpus "
                           "class and NO prior audit -> net-new vector"),
            }
            if slug not in novel_classes:
                novel_classes[slug] = {
                    "schema": "auditooor.novel_class.v1",
                    "class_id": slug,
                    "minted_at": _now(),
                    "minted_from": {
                        "invariant_id": c["invariant_id"],
                        "statement": c.get("statement", ""),
                        "property_form": c.get("property_form", ""),
                        "tokens": c.get("tokens", []),
                        "source_lane": c["source_lane"],
                        "target": c["target"],
                    },
                    "nearest_existing_class": best_cid,
                    "nearest_score": best_score,
                    "status": "candidate-unported",
                }
                burndown_feed.append({
                    "schema": "auditooor.burndown_feed.v1",
                    "action": "add-corpus-class",
                    "class_id": slug,
                    "origin": "novelty-gate-flywheel",
                    "statement": c.get("statement", ""),
                    "priority": "HIGHEST",
                    "note": ("Autonomously surfaced NOVEL vector: a derived-"
                             "invariant violation with no corpus/prior-audit "
                             "name. Enforcement lane: append to "
                             "reference/bug_class_taxonomy.yaml + corpus_tags "
                             "and to docs/LOGIC_ARSENAL_BURNDOWN.md."),
                    "fed_at": _now(),
                })
        verdicts.append(verdict)
    return verdicts, list(novel_classes.values()), burndown_feed


def emit_zero_day_fuel(candidates: list[dict], verdicts: list[dict], identity_map_path: Path | None, strict: bool) -> list[dict]:
    """Emit linked flywheel fuel only where a caller supplied an exact map."""
    if not candidates:
        return []
    if identity_map_path is None:
        if strict:
            raise zero_day_identity.FuelIdentityError("missing_identity_map_for_applicable_fuel")
        return []
    identity_index = zero_day_identity.load_identity_map(identity_map_path)
    rows: list[dict] = []
    for candidate, verdict in zip(candidates, verdicts):
        identifier = str(candidate.get("invariant_id") or "").strip()
        key = f"novelty_flywheel:{identifier}"
        payload = {
            "question": str(candidate.get("statement") or candidate.get("property_form") or "").strip(),
            "title": str(verdict.get("label") or "novelty").strip(),
            "identity_key": key,
            "novelty_label": verdict.get("label"),
        }
        try:
            rows.append(zero_day_identity.fuel_row(
                producer_step_id="step-2g-novelty-flywheel", fuel_kind="novelty_flywheel",
                identity_key=key, identity_index=identity_index, payload=payload,
            ))
        except zero_day_identity.FuelIdentityError:
            if strict:
                raise
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Novelty gate + arsenal flywheel.")
    ap.add_argument("workspace", help="workspace root")
    ap.add_argument("--taxonomy", default=str(DEFAULT_TAXONOMY))
    ap.add_argument("--candidates", help="explicit candidate-violations JSONL")
    ap.add_argument("--miner", help="additive novel-vector-invariant-miner JSONL")
    ap.add_argument("--out", help="override output dir")
    ap.add_argument("--match-threshold", type=int, default=3)
    ap.add_argument("--prior-threshold", type=int, default=2)
    ap.add_argument("--zero-day-fuel-out",
                    help="write explicitly linked auditooor.zero_day_fuel.v1 JSONL")
    ap.add_argument("--zero-day-identity-map",
                    help="JSONL map of exact current reasoner obligation/revision identities")
    ap.add_argument("--strict", action="store_true",
                    help="fail if applicable typed zero-day fuel has no unique identity link")
    ap.add_argument("--json", action="store_true", help="print summary JSON")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    classes = load_taxonomy(Path(args.taxonomy))
    if not classes:
        raise SystemExit("FATAL non-vacuity: 0 corpus classes loaded")

    candidates: list[dict] = []
    if args.candidates:
        candidates += candidates_from_jsonl(Path(args.candidates))
    else:
        candidates += candidates_from_vcis(ws)
        if args.miner:
            candidates += candidates_from_miner(Path(args.miner))
    if not candidates:
        raise SystemExit(
            "FATAL non-vacuity: 0 candidate violations examined "
            "(no VCIS manifest / --candidates). Run the derive engines first.")

    prior_symbols = load_prior_audit_symbols(ws)
    verdicts, novel_classes, burndown_feed = classify(
        candidates, classes, prior_symbols, args.match_threshold, args.prior_threshold)

    out_dir = Path(args.out) if args.out else (ws / ".auditooor" / "novelty")
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "novelty_verdicts.jsonl").write_text(
        "".join(json.dumps(v) + "\n" for v in verdicts))
    (out_dir / "new_classes.jsonl").write_text(
        "".join(json.dumps(v) + "\n" for v in novel_classes))
    (out_dir / "burndown_feed.jsonl").write_text(
        "".join(json.dumps(v) + "\n" for v in burndown_feed))

    fuel_rows: list[dict] = []
    if args.zero_day_fuel_out:
        try:
            fuel_rows = emit_zero_day_fuel(
                candidates, verdicts,
                Path(args.zero_day_identity_map) if args.zero_day_identity_map else None,
                args.strict,
            )
        except zero_day_identity.FuelIdentityError as exc:
            raise SystemExit(f"FATAL zero-day fuel: {exc}") from exc
        fuel_path = Path(args.zero_day_fuel_out)
        fuel_path.parent.mkdir(parents=True, exist_ok=True)
        fuel_path.write_text(
            "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n" for row in fuel_rows),
            encoding="utf-8",
        )

    n_novel = sum(1 for v in verdicts if v["label"] == "NOVEL")
    n_known = sum(1 for v in verdicts if v["label"] == "KNOWN")
    summary = {
        "schema": "auditooor.novelty_gate.v1",
        "tool": "novelty-gate-flywheel",
        "workspace": str(ws),
        "generated_at": _now(),
        "taxonomy_classes_loaded": len(classes),
        "candidates_examined": len(candidates),
        "known": n_known,
        "novel": n_novel,
        "new_classes_minted": len(novel_classes),
        "burndown_feed_rows": len(burndown_feed),
        "zero_day_fuel_rows": len(fuel_rows),
        "non_vacuity": {
            "classes_loaded_gt0": len(classes) > 0,
            "candidates_examined_gt0": len(candidates) > 0,
        },
        "out_dir": str(out_dir),
    }
    (out_dir / "novelty_summary.json").write_text(json.dumps(summary, indent=2))

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[novelty-gate-flywheel] classes={len(classes)} "
              f"candidates={len(candidates)} known={n_known} novel={n_novel} "
              f"minted={len(novel_classes)} -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
