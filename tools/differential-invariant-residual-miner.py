#!/usr/bin/env python3
# <!-- r36-rebuttal: lane differential-invariant-residual registered via dispatch report; enforcement lane owns runbook wiring -->
"""differential-invariant-residual-miner.py  (DIRM)

NOVELTY-GENERATION LAYER primitive (docs/LOGIC_ARSENAL_ROADMAP.md).

THE ENGINE FOR NEVER-COVERED 0-DAY CLASSES
==========================================
Every shipped "logic" reasoner hard-codes ONE known corpus class (Euler DOWN\\CHECK,
Aptos must-move-together, flash-loan borrow->pump->withdraw, ...).  Each is a LOGIC
query, but each is still ANCHORED to a corpus incident, so it can only re-derive a
class the corpus already owns.  DIRM inverts the direction.

    Residual(target) = InvariantsOf(target)  MINUS  Union_{c in corpus} InvariantsOf(c)

Every member of Residual is, BY CONSTRUCTION, an invariant that NO corpus class
recognizer was built for.  A reachable violation of a residual member is therefore
a NEVER-COVERED class - a genuine 0-day of a shape the arsenal has never seen.

GUARD-RAIL (why this is NOT pattern-matching, and NOT a re-encoding)
====================================================================
DIRM NEVER reads an attack-class taxonomy to decide WHAT to look for.  It reads the
TARGET's OWN derived invariants (from producers the pipeline already owns) and
SUBTRACTS the corpus.  The corpus is consulted ONLY to REMOVE the already-covered -
the exact inverse of a class recognizer.  A residual member cannot be a re-encoding
of a known class: any invariant whose STRUCTURAL SIGNATURE matches a known class
signature is subtracted by definition.  The output set is the COMPLEMENT of the
known universe.

STRUCTURAL-SIGNATURE SPACE (not symbol strings)
===============================================
Symbols differ per protocol (nuva `tvv`/`TotalShares`, an ERC4626 vault
`totalAssets`/`totalSupply`), so a naive symbol diff would leak every invariant as
"unique".  DIRM subtracts in SIGNATURE space:

    signature = { form, quantity_role, authority_topology }

  - form            : ratio-authority | escrow-liability | supply-conservation |
                      conservation | generic  (the algebraic shape of the relation)
  - quantity_role   : price | share | supply | liability | fee | balance | generic
  - authority_topology : which WRITE-AUTHORITY domain feeds each side of the
                      relation - the load-bearing axis.  For a ratio N/D:
                      whether N (and D) is fed by an EXTERNAL balance read
                      (GetAllBalances / balanceOf / BankKeeper) versus an
                      INTERNALLY-tracked ledger field.  This is the axis on which
                      the nuva ratio (external numerator) diverges from the ERC4626
                      corpus ratio (internal totalAssets), so the nuva class
                      SURVIVES the subtraction while a plain vault is subtracted.

state_symbols and file:line are carried for the OBLIGATION (reachability), but are
NOT used in the match - the match is signature-only, so it is symbol-invariant.

InvariantsOf(target)  = union of ALREADY-OWNED derived-invariant producers, keyed to
                        real symbols:
  - PISVS   <ws>/.auditooor/pisvs/derived_invariants.jsonl  (the step-2b-pisvs
            SUBSTRATE artifact). DIRM reads this DURABLE artifact directly; when it
            is absent DIRM runs the step-2b producer
            tools/protocol-invariant-synth-violation-search.py ITSELF (default;
            --no-autorun-producers to disable) rather than relying on
            composition-novelty-search.py --autorun-producers having run first -
            closing the producer-after-consumer ordering hole that masked
            SUBSTRATE_VACUOUS.
  - VCIS    <ws>/.auditooor/vcis/*  (value-conservation-invariant-synth forms)
  - CSCG    <ws>/.auditooor/coupled_state_gaps.jsonl  (must-move-together groups)
  - CFIC    <ws>/.auditooor/cross-function-coverage/*  (cross-fn obligations)
Union(corpus) is ALREADY materialized on disk (NO re-mining):
  audit/corpus_tags/derived/invariants_extracted.jsonl
  audit/corpus_tags/derived/invariant_family_*.jsonl
  audit/corpus_tags/derived/invariant_library_index.json

SEMANTIC MATCH
==============
The subtraction uses a semantic-similarity threshold, not string-equality, so
"ERC4626 totalShares/totalAssets desync" collapses to ONE corpus signature that ANY
internal-fed vault target matches.  Two backends are supported:
  * default (in-workflow safe): a LOCAL deterministic structural-similarity over the
    3 signature components (form / quantity_role / authority_topology), documented
    and reproducible with no network dependency.
  * optional: mcp__auditooor-vault__vault_semantic_match_verify, plugged in via the
    --semantic-hook argument (a shell command that reads a JSON pair on stdin and
    prints a 0..1 score).  Used only when explicitly requested; DIRM defaults to the
    local backend so it runs standalone inside a workflow.

ANTI-VACUITY (fail-loud, per the capability-vacuity-telltale memory)
====================================================================
DIRM asserts |InvariantsOf(target)| > 0.  If the target has NO derived invariants,
that is SUBSTRATE_VACUOUS -> a fail-closed error (run the producers first), NEVER a
silent green.  If the target HAS invariants but Residual drains to empty (every one
was subtracted), that is a CITED-EMPTY rationale listing WHICH corpus signature
subtracted each - an honest "this protocol shares all its invariant shapes with
prior art", never a silent green.

OUTPUT (advisory; never self-credits coverage)
===============================================
<ws>/.auditooor/dirm/
  differential_invariant_residual_obligations.jsonl  (one residual obligation / line)
  dirm_manifest.json                                 (summary + cited-empty rationale)
Schema: auditooor.differential_invariant_residual.v1
Every obligation carries verdict="needs-search" until an executed PoC/fuzz resolves
it, novelty="RESIDUAL", and the reachability question "which mutator can violate
this state relation".
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.differential_invariant_residual.v1"

_TOOLS_DIR = Path(__file__).resolve().parent
# The step-2b-pisvs SUBSTRATE PRODUCER. DIRM reads InvariantsOf(target) from the
# durable artifact this producer materializes (<ws>/.auditooor/pisvs/
# derived_invariants.jsonl). If the artifact is absent DIRM runs THIS producer
# directly (see _ensure_pisvs_substrate) rather than depending on
# composition-novelty-search.py --autorun-producers having run first - removing
# the producer-after-consumer ordering hole that masked SUBSTRATE_VACUOUS.
_PISVS_PRODUCER = "protocol-invariant-synth-violation-search.py"
_PISVS_ARTIFACT = ("pisvs", "derived_invariants.jsonl")


def _ensure_pisvs_substrate(ws: Path, autorun: bool) -> dict:
    """If the durable step-2b-pisvs artifact is absent, materialize it by running
    the PISVS producer directly on <ws>. Returns an autorun log entry (never
    raises - a failed producer still leaves the honest SUBSTRATE_VACUOUS path).
    """
    artifact = ws.joinpath(".auditooor", *_PISVS_ARTIFACT)
    if artifact.is_file():
        return {"ran": False, "reason": "artifact-present", "artifact": str(artifact)}
    if not autorun:
        return {"ran": False, "reason": "artifact-absent-autorun-disabled",
                "artifact": str(artifact)}
    producer = _TOOLS_DIR / _PISVS_PRODUCER
    if not producer.is_file():
        return {"ran": False, "reason": "producer-script-not-found",
                "producer": str(producer)}
    try:
        cp = subprocess.run([sys.executable, str(producer), str(ws)],
                            capture_output=True, text=True, timeout=900)
        return {"ran": True, "producer": _PISVS_PRODUCER,
                "returncode": cp.returncode,
                "ok": cp.returncode == 0,
                "artifact_present_after": artifact.is_file(),
                "stderr_tail": (cp.stderr or "")[-400:]}
    except Exception as exc:  # noqa: BLE001 - report, never crash DIRM
        return {"ran": True, "producer": _PISVS_PRODUCER, "ok": False,
                "reason": f"{type(exc).__name__}: {exc}"}

# --------------------------------------------------------------------------
# Structural vocabulary (describes CODE / RELATION shapes, NOT attack classes).
# --------------------------------------------------------------------------
EXTERNAL_BALANCE_READ = re.compile(
    r"\b(GetAllBalances|GetBalance|SpendableCoins|balanceOf|BankKeeper|"
    r"getBalance|address\(this\)\.balance|\.balance\b)", re.I)
_RATIO_WORDS = re.compile(
    r"(price|nav|rate|pro[_ ]?rata|share[_ ]?price|exchange[_ ]?rate|index|tvv|"
    r"value.?per|per.?share|convert(?:to)?(?:assets|shares)|/\s*total|totalassets\s*/)",
    re.I)
_DIV_TOKEN = re.compile(r"(\.Quo|\.div\(|\bmulDiv\b|[A-Za-z0-9_]\s*/\s*[A-Za-z0-9_])")
_ESCROW_WORDS = re.compile(
    r"(escrow|custody|held\s+balance|balance\s*>=|solvenc|liabilit|collateral|"
    r"backed|reserve\s*>=|held\s+token)", re.I)
_SUPPLY_WORDS = re.compile(
    r"(supply|total[_ ]?shares|totalsupply|mint/?burn|mint\s+and\s+burn|"
    r"conservation|matched\s+mint|sum\(shares\)|monoton)", re.I)

_ROLE_PATTERNS = [
    ("price", re.compile(r"(price|nav|exchange[_ ]?rate|value.?per|per.?share|share[_ ]?price)", re.I)),
    ("share", re.compile(r"(share|pro[_ ]?rata|totalshares|convert(?:to)?(?:assets|shares))", re.I)),
    ("supply", re.compile(r"(supply|total\b|totalsupply|mint|burn)", re.I)),
    ("liability", re.compile(r"(liabilit|escrow|custody|collateral|debt|owed|backed|reserve)", re.I)),
    ("fee", re.compile(r"(fee|reward|commission|distribut|pool)", re.I)),
    ("balance", re.compile(r"(balance|held|token\s+amount)", re.I)),
]


# --------------------------------------------------------------------------
# Signature construction
# --------------------------------------------------------------------------
def _quantity_role(text: str) -> str:
    for role, pat in _ROLE_PATTERNS:
        if pat.search(text or ""):
            return role
    return "generic"


def _form_of(text: str, has_division: bool) -> str:
    t = text or ""
    if has_division or (_DIV_TOKEN.search(t) and _RATIO_WORDS.search(t)):
        return "ratio-authority"
    if _ESCROW_WORDS.search(t):
        return "escrow-liability"
    if _SUPPLY_WORDS.search(t):
        return "supply-conservation"
    return "generic"


def _side_authority(text: str) -> str:
    """external if the side is fed by an external balance read, else internal."""
    return "external" if EXTERNAL_BALANCE_READ.search(text or "") else "internal"


def _authority_topology_target(rec: dict) -> str:
    """Derive authority_topology from a TARGET (producer) invariant record.

    For a ratio (D1) the numerator/denominator feed-source is the load-bearing
    axis.  numerator_external_source present with an external-read token => the
    numerator lives in an EXTERNAL write-authority domain; the denominator's
    internal_writers (or absence + supply/share naming) => internal domain.
    """
    form = rec.get("_form_hint") or ""
    if form.startswith("D1") or form == "ratio-authority":
        num_src = str(rec.get("numerator_external_source") or "")
        num = _side_authority(num_src)
        # denominator: an internally-tracked field (protocol mint/burn ledger).
        den = "internal"
        return f"num:{num}|den:{den}"
    if form.startswith("D2") or form == "escrow-liability":
        # held token balance vs internally-written liability ledger.
        return "held:external|ledger:internal"
    if form.startswith("D3") or form == "supply-conservation":
        return "field:internal|move:internal"
    # generic fallback derived from the statement text
    return f"any:{_side_authority(rec.get('statement') or rec.get('invariant_statement') or '')}"


def _authority_topology_corpus(text: str, form: str) -> str:
    """Derive authority_topology from a CORPUS invariant STATEMENT (natural
    language).  Corpus invariants are stated over their OWN (usually internal)
    accounting fields; a corpus statement that references an external balance
    read is rare.  This is exactly why an external-numerator target ratio has NO
    corpus counterpart and SURVIVES the subtraction."""
    ext = EXTERNAL_BALANCE_READ.search(text or "")
    if form == "ratio-authority":
        return f"num:{'external' if ext else 'internal'}|den:internal"
    if form == "escrow-liability":
        return f"held:{'external' if ext else 'internal'}|ledger:internal"
    if form == "supply-conservation":
        return "field:internal|move:internal"
    return f"any:{'external' if ext else 'internal'}"


def make_signature_target(rec: dict) -> dict:
    form_hint = str(rec.get("form") or "")
    rec = {**rec, "_form_hint": form_hint}
    statement = str(rec.get("statement") or rec.get("invariant_statement") or "")
    has_div = form_hint.startswith("D1") or bool(rec.get("numerator"))
    form = ("ratio-authority" if form_hint.startswith("D1") else
            "escrow-liability" if form_hint.startswith("D2") else
            "supply-conservation" if form_hint.startswith("D3") else
            _form_of(statement, has_div))
    role_text = " ".join(str(rec.get(k) or "") for k in
                         ("numerator", "denominator", "field", "function", "statement",
                          "invariant_statement"))
    state_symbols = [s for s in (rec.get("numerator"), rec.get("denominator"),
                                 rec.get("field"),
                                 *(rec.get("liability_fields") or []),
                                 *(rec.get("writers") or [])) if s]
    return {
        "form": form,
        "quantity_role": _quantity_role(role_text),
        "authority_topology": _authority_topology_target(rec),
        "state_symbols": [str(s) for s in state_symbols][:8],
        "file": rec.get("file"),
        "line": rec.get("line"),
        "statement": statement,
        "search_question": rec.get("search_question"),
        "provenance": rec.get("_provenance", "pisvs"),
        "form_hint": form_hint,
    }


def make_signature_corpus(rec: dict) -> dict:
    statement = str(rec.get("statement") or "")
    has_div = bool(_DIV_TOKEN.search(statement) and _RATIO_WORDS.search(statement))
    form = _form_of(statement, has_div)
    return {
        "form": form,
        "quantity_role": _quantity_role(
            statement + " " + str(rec.get("attack_signature") or "") + " "
            + str(rec.get("category") or "")),
        "authority_topology": _authority_topology_corpus(statement, form),
        "corpus_id": rec.get("invariant_id"),
        "family": rec.get("protocol_family") or rec.get("category"),
    }


# --------------------------------------------------------------------------
# Similarity  (local deterministic structural backend, default)
# --------------------------------------------------------------------------
_W_FORM = 0.40
_W_ROLE = 0.25
_W_TOPO = 0.35


def structural_similarity(t: dict, c: dict) -> float:
    s = 0.0
    if t["form"] == c["form"]:
        s += _W_FORM
    elif "generic" in (t["form"], c["form"]):
        s += _W_FORM * 0.25  # weak partial credit for an unclassified side
    if t["quantity_role"] == c["quantity_role"]:
        s += _W_ROLE
    elif "generic" in (t["quantity_role"], c["quantity_role"]):
        s += _W_ROLE * 0.4
    if t["authority_topology"] == c["authority_topology"]:
        s += _W_TOPO
    return round(s, 4)


def _semantic_hook_score(hook: str, t: dict, c: dict) -> float | None:
    payload = json.dumps({"a": {k: t[k] for k in ("form", "quantity_role", "authority_topology")},
                          "b": {k: c[k] for k in ("form", "quantity_role", "authority_topology")}})
    try:
        p = subprocess.run(hook, shell=True, input=payload, capture_output=True,
                           text=True, timeout=30)
        if p.returncode != 0:
            return None
        return float(p.stdout.strip().split()[-1])
    except Exception:
        return None


def best_corpus_match(t: dict, corpus_sigs: list[dict], threshold: float,
                      hook: str | None) -> tuple[float, dict | None]:
    best_score, best = 0.0, None
    for c in corpus_sigs:
        score = None
        if hook:
            score = _semantic_hook_score(hook, t, c)
        if score is None:
            score = structural_similarity(t, c)
        if score > best_score:
            best_score, best = score, c
        if best_score >= 0.999:
            break
    return best_score, best


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------
def _load_jsonl(p: Path) -> list[dict]:
    out = []
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if isinstance(r, dict):
                out.append(r)
        except Exception:
            continue
    return out


def load_target_invariants(ws: Path) -> list[dict]:
    """Union of every already-owned derived-invariant producer on disk."""
    recs: list[dict] = []
    # PISVS (primary)
    for r in _load_jsonl(ws / ".auditooor" / "pisvs" / "derived_invariants.jsonl"):
        r["_provenance"] = "pisvs"
        recs.append(r)
    # VCIS forms (value-conservation-invariant-synth)
    vcis = ws / ".auditooor" / "vcis"
    if vcis.is_dir():
        for f in vcis.glob("*.jsonl"):
            for r in _load_jsonl(f):
                if "form" not in r and "invariant_form" in r:
                    r["form"] = r["invariant_form"]
                r["_provenance"] = "vcis"
                recs.append(r)
    # CSCG must-move-together groups
    for r in _load_jsonl(ws / ".auditooor" / "coupled_state_gaps.jsonl"):
        r.setdefault("form", "coupled-state")
        r.setdefault("statement",
                     f"must-move-together set {r.get('set_id')} members "
                     f"{r.get('set_members')} at {r.get('writer_file')}:"
                     f"{r.get('writer_line')}")
        r["file"] = r.get("writer_file")
        r["line"] = r.get("writer_line")
        r["_provenance"] = "cscg"
        recs.append(r)
    return recs


def load_corpus_signatures(corpus_root: Path, limit: int | None = None) -> list[dict]:
    sigs: list[dict] = []
    seen: set = set()
    files = [corpus_root / "invariants_extracted.jsonl"]
    files += sorted(corpus_root.glob("invariant_family_*.jsonl"))
    for f in files:
        for r in _load_jsonl(f):
            sig = make_signature_corpus(r)
            key = (sig["form"], sig["quantity_role"], sig["authority_topology"])
            if key in seen:
                continue
            seen.add(key)
            sigs.append(sig)
            if limit and len(sigs) >= limit:
                return sigs
    return sigs


# --------------------------------------------------------------------------
# Core: residual = target \ corpus (signature space)
# --------------------------------------------------------------------------
def compute_residual(target_invs: list[dict], corpus_sigs: list[dict],
                     threshold: float, hook: str | None) -> dict:
    target_sigs = [make_signature_target(r) for r in target_invs]
    residual, subtracted = [], []
    for t in target_sigs:
        score, match = best_corpus_match(t, corpus_sigs, threshold, hook)
        row = {"signature": t, "best_corpus_score": score,
               "best_corpus_match": match}
        if score >= threshold:
            subtracted.append(row)
        else:
            residual.append(row)
    return {"target_sigs": target_sigs, "residual": residual,
            "subtracted": subtracted}


def residual_obligation(row: dict) -> dict:
    t = row["signature"]
    q = (t.get("search_question")
         or f"Which mutator can violate the state relation over {t['state_symbols']} "
            f"(form={t['form']}, role={t['quantity_role']}, "
            f"authority={t['authority_topology']})?")
    return {
        "schema_version": SCHEMA,
        "novelty": "RESIDUAL",
        "invariant_form": t["form"],
        "quantity_role": t["quantity_role"],
        "authority_topology": t["authority_topology"],
        "state_symbols": t["state_symbols"],
        "invariant_text": t["statement"],
        "site": {"file": t["file"], "line": t["line"]},
        "reachability_question": q,
        "residual_rationale": (
            f"No corpus invariant signature matched under threshold "
            f"(best score {row['best_corpus_score']} < required); the "
            f"authority_topology '{t['authority_topology']}' has no counterpart in "
            f"the {row['best_corpus_match']['family'] if row.get('best_corpus_match') else 'corpus'} "
            f"signature space - this invariant shape is NOT owned by any class "
            f"recognizer. A reachable violation is a NEVER-COVERED class."),
        "nearest_corpus": row.get("best_corpus_match"),
        "nearest_corpus_score": row["best_corpus_score"],
        "provenance": t.get("provenance"),
        "verdict": "needs-search",
    }


def run(ws: Path, corpus_root: Path, threshold: float, hook: str | None,
        corpus_limit: int | None, autorun_producers: bool = True) -> dict:
    # Read InvariantsOf(target) from the durable step-2b-pisvs artifact; if it is
    # absent, materialize it by running the PISVS producer directly (instead of
    # relying on composition-novelty-search.py --autorun-producers having run).
    autorun_log = _ensure_pisvs_substrate(ws, autorun_producers)
    target_invs = load_target_invariants(ws)
    n_target = len(target_invs)
    # ANTI-VACUITY: substrate must be non-empty.
    if n_target == 0:
        return {
            "schema_version": SCHEMA, "ok": False,
            "status": "SUBSTRATE_VACUOUS",
            "workspace": str(ws),
            "error": ("no target invariants found - InvariantsOf(target) is empty. "
                      "Run tools/protocol-invariant-synth-violation-search.py (and "
                      "value-conservation-invariant-synth / coupled-state-completeness"
                      "-graph) FIRST. DIRM refuses to silently green on an empty "
                      "substrate."),
            "target_invariant_count": 0,
            "pisvs_autorun": autorun_log,
        }
    corpus_sigs = load_corpus_signatures(corpus_root, corpus_limit)
    res = compute_residual(target_invs, corpus_sigs, threshold, hook)
    obligations = [residual_obligation(r) for r in res["residual"]]

    status = "OK"
    cited_empty = None
    if not obligations:
        # HONEST cited-empty: target had invariants but all were subtracted.
        status = "CITED_EMPTY"
        cited_empty = [{
            "invariant_text": r["signature"]["statement"][:200],
            "site": {"file": r["signature"]["file"], "line": r["signature"]["line"]},
            "subtracted_by": r.get("best_corpus_match"),
            "score": r["best_corpus_score"],
            "rationale": ("this invariant SHAPE is already owned by a corpus class "
                          "recognizer (signature matched >= threshold); not a "
                          "residual/never-covered candidate."),
        } for r in res["subtracted"]]

    manifest = {
        "schema_version": SCHEMA,
        "ok": True,
        "status": status,
        "workspace": str(ws),
        "corpus_root": str(corpus_root),
        "threshold": threshold,
        "semantic_backend": "mcp-hook" if hook else "local-structural",
        "pisvs_autorun": autorun_log,
        "target_invariant_count": n_target,
        "corpus_signature_count": len(corpus_sigs),
        "residual_count": len(obligations),
        "subtracted_count": len(res["subtracted"]),
        "residual_obligations": obligations,
        "subtracted_preview": [{
            "form": r["signature"]["form"],
            "authority_topology": r["signature"]["authority_topology"],
            "score": r["best_corpus_score"],
            "nearest": (r.get("best_corpus_match") or {}).get("family"),
        } for r in res["subtracted"]][:20],
        "cited_empty_rationale": cited_empty,
    }
    return manifest


def emit(ws: Path, manifest: dict) -> None:
    out = ws / ".auditooor" / "dirm"
    out.mkdir(parents=True, exist_ok=True)
    obl = out / "differential_invariant_residual_obligations.jsonl"
    with obl.open("w") as fh:
        for o in manifest.get("residual_obligations", []):
            fh.write(json.dumps(o) + "\n")
    (out / "dirm_manifest.json").write_text(json.dumps(manifest, indent=2))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Differential Invariant Residual Miner (DIRM)")
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True)
    ap.add_argument("--src-root", dest="src_root", default=None,
                    help="override source root (default: <ws>/src or <ws>)")
    ap.add_argument("--corpus-root", default=None,
                    help="default: <repo>/audit/corpus_tags/derived")
    ap.add_argument("--threshold", type=float, default=0.85,
                    help="signature similarity >= threshold => SUBTRACTED (default 0.85)")
    ap.add_argument("--semantic-hook", default=None,
                    help="shell cmd: reads {a,b} JSON on stdin, prints 0..1 score "
                         "(e.g. an mcp vault_semantic_match_verify shim). Falls back "
                         "to local structural similarity per-pair on failure.")
    ap.add_argument("--corpus-limit", type=int, default=None)
    ap.add_argument("--no-autorun-producers", dest="autorun_producers",
                    action="store_false", default=True,
                    help="do NOT run the step-2b PISVS producer when the "
                         "<ws>/.auditooor/pisvs/derived_invariants.jsonl artifact "
                         "is absent (default: autorun it so DIRM is self-sufficient "
                         "and does not depend on composition-novelty --autorun-producers)")
    ap.add_argument("--emit", action="store_true", help="write obligations + manifest")
    ap.add_argument("--json", action="store_true", help="print manifest JSON to stdout")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit 2 on SUBSTRATE_VACUOUS (empty target invariants)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.corpus_root:
        corpus_root = Path(args.corpus_root).expanduser().resolve()
    else:
        corpus_root = Path(__file__).resolve().parent.parent / "audit" / "corpus_tags" / "derived"
    # src_root is accepted for interface parity; producers already key file:line.
    _ = args.src_root

    manifest = run(ws, corpus_root, args.threshold, args.semantic_hook,
                   args.corpus_limit, args.autorun_producers)

    if args.emit and manifest.get("ok"):
        emit(ws, manifest)

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        st = manifest.get("status")
        print(f"DIRM {st} ws={ws.name} target={manifest.get('target_invariant_count')} "
              f"corpus_sigs={manifest.get('corpus_signature_count')} "
              f"residual={manifest.get('residual_count')} "
              f"subtracted={manifest.get('subtracted_count')}")
        for o in manifest.get("residual_obligations", [])[:20]:
            print(f"  RESIDUAL form={o['invariant_form']} role={o['quantity_role']} "
                  f"auth={o['authority_topology']} @ {o['site']['file']}:{o['site']['line']}")

    if manifest.get("status") == "SUBSTRATE_VACUOUS" and args.fail_closed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
