#!/usr/bin/env python3
"""
rejection-classifier.py — learned model of triage outcomes (Issue #88)

Trains a lightweight classifier on the labeled corpus (Issue #86) that
predicts P(paid | dupe | rejected) for a new finding draft.

Features:
  - Embedding vector (from Issue #84 corpus_embeddings.npz)
  - Claimed severity (one-hot: HIGH/MEDIUM/LOW/INFO)
  - Quality + rarity scores (numeric)
  - Finders-count bucket (solo / small / many)
  - Tag TF-IDF (top 50 tags)

Classes mapped from outcome_labels.yaml:
  - primary_likely_paid → 'paid'
  - high_value_primary → 'paid'
  - dupe_prone_class → 'dupe'
  - unknown_*, other → 'unknown' (dropped from training)

Persists to reference/rejection_classifier.pkl

Usage:
    python3 tools/rejection-classifier.py --train
    python3 tools/rejection-classifier.py --predict <draft.md>
    python3 tools/rejection-classifier.py --retrain-incremental [--workspaces <dir>[,<dir>...]]

Incremental retrain mode (U4):
  - Loads all `<ws>/findings/*/rationale.txt` found under known workspace roots
    (auto-discovered under auditooor/_workspaces/, or --workspaces override).
  - Joins them with the outcome recorded in reference/rejection_causes.md
    (date | finding-id | workspace | detector | severity | outcome | excerpt).
  - Appends to the Solodit training corpus, retrains, reports accuracy delta,
    and writes reference/rejection_classifier_history.yaml to track evolution.
"""

import argparse
import datetime as _dt
import json
import os
import pickle
import sys
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
LABELS = AUDITOOOR_DIR / "reference" / "outcome_labels.yaml"
EMBEDDINGS = AUDITOOOR_DIR / "reference" / "corpus_embeddings.npz"
IDS_CACHE = AUDITOOOR_DIR / "reference" / "corpus_ids.json"
MODEL_OUT = AUDITOOOR_DIR / "reference" / "rejection_classifier.pkl"
HISTORY_OUT = AUDITOOOR_DIR / "reference" / "rejection_classifier_history.yaml"
REJ_CAUSES_TABLE = AUDITOOOR_DIR / "reference" / "rejection_causes_table.md"


def _load():
    try:
        import yaml, numpy as np
    except ImportError:
        print("[error] numpy + PyYAML required", file=sys.stderr)
        sys.exit(1)
    if not LABELS.exists():
        print(f"[error] {LABELS} missing — run tools/scrape-outcomes.py first",
              file=sys.stderr)
        sys.exit(1)
    labels = yaml.safe_load(LABELS.read_text())
    rows = labels.get("rows", [])
    # Load embeddings if available
    embs = None
    ids_meta = None
    if EMBEDDINGS.exists() and IDS_CACHE.exists():
        embs = np.load(EMBEDDINGS)["embeddings"]
        ids_meta = json.loads(IDS_CACHE.read_text())
    return rows, embs, ids_meta


def _outcome_class(o):
    if o in ("primary_likely_paid", "high_value_primary"):
        return "paid"
    if o == "dupe_prone_class":
        return "dupe"
    return None  # drop from training


def _build_base_corpus():
    """Return (X_text, y) lists from the Solodit outcome_labels corpus."""
    rows, _embs, _ids_meta = _load()
    X_text, y = [], []
    for r in rows:
        cls = _outcome_class(r["outcome"])
        if cls is None:
            continue
        text_parts = [r.get("title") or "", r.get("impact") or "",
                      r.get("tags") or ""]
        X_text.append(" ".join(text_parts))
        y.append(cls)
    return X_text, y


def _fit_and_score(X_text, y, tag="train"):
    from sklearn.linear_model import LogisticRegression
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report, accuracy_score
    import random

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2),
                                  stop_words="english", min_df=2)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])
    random.seed(42)
    idx = list(range(len(X_text)))
    random.shuffle(idx)
    split = int(0.8 * len(idx))
    Xtr = [X_text[i] for i in idx[:split]]
    ytr = [y[i] for i in idx[:split]]
    Xte = [X_text[i] for i in idx[split:]]
    yte = [y[i] for i in idx[split:]]
    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    acc = accuracy_score(yte, pred) if yte else 0.0
    print(f"\n[{tag}] test-set classification report (n_test={len(yte)}):")
    print(classification_report(yte, pred, zero_division=0))
    return pipe, acc, len(Xtr), len(Xte)


def train():
    try:
        import numpy as np  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError:
        print("[error] scikit-learn required: pip3 install scikit-learn",
              file=sys.stderr)
        sys.exit(1)

    X_text, y = _build_base_corpus()
    if len(X_text) < 50:
        print(f"[warn] only {len(X_text)} labeled examples — model will be weak")
    from collections import Counter
    print(f"[train] {len(X_text)} examples, classes: {dict(Counter(y))}")
    pipe, acc, n_tr, n_te = _fit_and_score(X_text, y, tag="train")

    with open(MODEL_OUT, "wb") as f:
        pickle.dump({"pipeline": pipe, "classes": pipe.classes_.tolist(),
                     "n_trained": n_tr, "accuracy": acc}, f)
    print(f"[train] saved → {MODEL_OUT}  (acc={acc:.3f})")


# ---- U4: incremental retrain with rationale corpus ------------------------

def _outcome_to_class(outcome_tag):
    """Map post-audit-review outcome tags to classifier classes."""
    t = (outcome_tag or "").strip().lower()
    if t == "paid":
        return "paid"
    if t in ("dupe", "rejected"):
        # Rejected is closer to dupe than to paid in our 2-class model.
        # (Future: introduce explicit 'rejected' class once n > 30.)
        return "dupe"
    return None  # pending / unknown — drop from training


def _discover_workspaces(overrides):
    """Yield workspace roots that contain a findings/ subtree."""
    roots = []
    if overrides:
        for p in overrides.split(","):
            p = p.strip()
            if p:
                roots.append(Path(p).expanduser())
    default_root = AUDITOOOR_DIR / "_workspaces"
    if default_root.is_dir():
        roots.append(default_root)
    seen, out = set(), []
    for r in roots:
        if not r.exists():
            continue
        # A workspace is any dir containing a findings/ child
        if (r / "findings").is_dir() and r not in seen:
            seen.add(r); out.append(r)
        for child in r.iterdir() if r.is_dir() else []:
            if (child / "findings").is_dir() and child not in seen:
                seen.add(child); out.append(child)
    return out


def _parse_rej_table():
    """Parse reference/rejection_causes.md into [(finding_id, ws, outcome), ...]."""
    rows = []
    if not REJ_CAUSES_TABLE.exists():
        return rows
    for ln in REJ_CAUSES_TABLE.read_text().splitlines():
        if not ln.startswith("| ") or ln.startswith("| date ") or ln.startswith("|---"):
            continue
        parts = [p.strip() for p in ln.strip("| ").split("|")]
        if len(parts) < 7:
            continue
        # date | finding-id | workspace | detector | severity | outcome | excerpt
        rows.append({
            "date": parts[0],
            "finding_id": parts[1],
            "workspace": parts[2],
            "detector": parts[3],
            "severity": parts[4],
            "outcome": parts[5],
            "excerpt": parts[6],
        })
    return rows


def _gather_rationale_corpus(workspaces):
    """Return list of (text, outcome_class, finding_id, ws_name) tuples.

    Joins <ws>/findings/*/rationale.txt with outcome tags from the table.
    """
    table = {(r["workspace"], r["finding_id"]): r for r in _parse_rej_table()}
    out = []
    for ws in workspaces:
        ws_name = ws.name
        findings_dir = ws / "findings"
        if not findings_dir.is_dir():
            continue
        for fdir in sorted(findings_dir.iterdir()):
            if not fdir.is_dir():
                continue
            rat = fdir / "rationale.txt"
            if not rat.exists():
                continue
            finding_id = fdir.name
            tag = table.get((ws_name, finding_id), {}).get("outcome", "")
            cls = _outcome_to_class(tag)
            if cls is None:
                continue
            text = rat.read_text(errors="ignore").strip()
            if not text:
                continue
            out.append((text, cls, finding_id, ws_name))
    return out


def retrain_incremental(workspaces_arg=None):
    try:
        import numpy as np  # noqa: F401
        import sklearn  # noqa: F401
        import yaml
    except ImportError:
        print("[error] scikit-learn + PyYAML required", file=sys.stderr)
        sys.exit(1)

    # 1. Baseline: Solodit corpus only
    X_base, y_base = _build_base_corpus()
    from collections import Counter
    print(f"[incremental] base corpus: {len(X_base)} rows, "
          f"classes={dict(Counter(y_base))}")

    base_pipe, base_acc, base_ntr, base_nte = _fit_and_score(X_base, y_base,
                                                             tag="base")

    # 2. Gather rationale rows
    workspaces = _discover_workspaces(workspaces_arg)
    rationale_rows = _gather_rationale_corpus(workspaces)
    print(f"[incremental] discovered {len(workspaces)} workspace(s), "
          f"{len(rationale_rows)} rationale.txt rows")

    # 3. Enriched corpus
    X_ext = X_base + [r[0] for r in rationale_rows]
    y_ext = y_base + [r[1] for r in rationale_rows]
    print(f"[incremental] enriched corpus: {len(X_ext)} rows, "
          f"classes={dict(Counter(y_ext))}")

    ext_pipe, ext_acc, ext_ntr, ext_nte = _fit_and_score(X_ext, y_ext,
                                                         tag="incremental")

    # 4. Vocabulary delta — TF-IDF feature names
    base_vocab = set(base_pipe.named_steps["tfidf"].get_feature_names_out())
    ext_vocab = set(ext_pipe.named_steps["tfidf"].get_feature_names_out())
    new_terms = sorted(ext_vocab - base_vocab)
    print(f"[incremental] new vocabulary learned: {len(new_terms)} terms")

    # 5. Pick a representative "top 10 new terms" — highest-weight toward the
    #    minority class (paid) in the enriched model, filtered to new_terms.
    top_new = []
    try:
        clf = ext_pipe.named_steps["clf"]
        tfidf = ext_pipe.named_steps["tfidf"]
        feat = tfidf.get_feature_names_out()
        # coef_ shape: (1, n_features) for binary, (n_classes, n_features) otherwise
        coef = clf.coef_
        classes = clf.classes_.tolist()
        if "paid" in classes:
            row = 0 if coef.shape[0] == 1 else classes.index("paid")
            weights = coef[row]
            new_idx = [i for i, t in enumerate(feat) if t in set(new_terms)]
            new_idx.sort(key=lambda i: -abs(weights[i]))
            top_new = [(feat[i], float(weights[i])) for i in new_idx[:10]]
    except Exception as e:
        print(f"[incremental] (could not derive top-new terms: {e})")

    # 6. Persist model
    with open(MODEL_OUT, "wb") as f:
        pickle.dump({
            "pipeline": ext_pipe,
            "classes": ext_pipe.classes_.tolist(),
            "n_trained": ext_ntr,
            "accuracy": ext_acc,
            "rationale_rows": len(rationale_rows),
        }, f)
    print(f"[incremental] saved → {MODEL_OUT}  "
          f"(acc: {base_acc:.3f} → {ext_acc:.3f}, Δ={ext_acc-base_acc:+.3f})")

    # 7. Append history row
    history = []
    if HISTORY_OUT.exists():
        try:
            loaded = yaml.safe_load(HISTORY_OUT.read_text()) or []
            if isinstance(loaded, list):
                history = loaded
        except Exception:
            history = []
    history.append({
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "base_rows": len(X_base),
        "rationale_rows": len(rationale_rows),
        "enriched_rows": len(X_ext),
        "base_accuracy": round(base_acc, 4),
        "enriched_accuracy": round(ext_acc, 4),
        "accuracy_delta": round(ext_acc - base_acc, 4),
        "new_vocab_count": len(new_terms),
        "top_new_terms": [{"term": t, "weight": round(w, 4)} for t, w in top_new],
    })
    HISTORY_OUT.write_text(yaml.safe_dump(history, sort_keys=False))
    print(f"[incremental] history → {HISTORY_OUT} ({len(history)} runs)")

    # 8. Surface for --retrain-incremental callers (rejection-learn.sh reads)
    print("\n=== DELTA REPORT ===")
    print(f"accuracy:        {base_acc:.4f} → {ext_acc:.4f}  "
          f"(Δ {ext_acc-base_acc:+.4f})")
    print(f"corpus:          {len(X_base)} → {len(X_ext)} rows "
          f"(+{len(rationale_rows)} rationale)")
    print(f"vocabulary:      +{len(new_terms)} new terms")
    if top_new:
        print("top-10 new terms (by |coef| toward 'paid'):")
        for t, w in top_new:
            print(f"    {t:32s}  {w:+.4f}")
    print("====================")


# ─── Hard-coded rejection heuristics (learned from local submissions) ───────
# These augment (not replace) the ML model.  Each rule returns
#   (label, confidence_boost, reason)  or  None.

_REJECTION_HEURISTICS = [
    # POLY-45: uint248 pack overflow rejected because 2^248 values are not
    # realistically achievable given token supply constraints.
    ("extreme_value_no_bounds",
     r"2\^\s*248|2\*\*\s*248|type\(uint248\)\.max|type\(uint256\)\.max\b|>=?\s*2\^\s*2[0-9]{2}",
     r"realistic(?:ally)?\s+(?:bound|supply|amount|achievable)|token\s+supply|max\s+supply|total\s+supply\s*(?:is|<=?)",
     "rejected"),
    # POLY-46: Event-only cosmetic issue (wrong indexed topic) where state is
    # correct.  Rejected because CLOB reads isOperator mapping, not events.
    ("event_only_no_state_impact",
     r"\bevent\b.*\b(topic|indexed|param|emit)\b|\bemit\b.*\bevent\b.*\b(wrong|incorrect|missing|misuse)\b",
     r"\bstate\b.*\bcorrupt|\bfund|\bloss|\bdrain|\btransfer|\bbalance|\b(exploit|attack)\b.*\b(state|fund|balance)",
     "rejected"),
    # POLY-49: Adapter event attribution — adapter MUST hold tokens to call
    # downstream.  Rejected because user's address is in TransferBatch event.
    ("adapter_event_missing_full_flow",
     r"\badapter\b.*\bevent\b|\bevent\b.*\badapter\b|\bsplitPosition\b.*\bUnwrapped\b",
     r"\bfull\s+transaction\s+flow|\bTransferBatch\b|\buser\s+address\s+captured|\bdownstream\b.*\bevent\b",
     "rejected"),
    # Snowbridge: cross-chain prefund drain rejected because operations are
    # atomic within same tx initiated from Polkadot side.
    ("cross_chain_non_atomic_claim",
     r"\b(prefund|depositToken|depositNative|Ether)\b.*\b(sweep|drain|steal)\b|\bdrain\b.*\b(balance|prefund)\b",
     r"\batomic\b.*\btransaction|\bsame\s+transaction|\bPolkadot\b.*\binitiat|\btrust\s+domain|\bcross.?chain\b.*\batomic",
     "rejected"),
    # Privileged attacker required (operator/admin) — often OOS or downgraded
    ("privileged_attacker_required",
     r"\battacker\b.*\b(operator|admin|owner)\b|\b(operator|admin|owner)\b.*\battacker\b",
     r"\bpermissionless|\bany\s+user|\bunauthorized\b.*\buser|\bno\s+role\b",
     "rejected"),
]


def heuristic_screen(text: str) -> list[tuple[str, float, str]]:
    """Run hard-coded rejection heuristics over draft text.

    Returns a list of (rule_name, confidence_penalty, reason) for any
    triggered heuristics that are NOT mitigated by their anti-pattern.
    """
    flags: list[tuple[str, float, str]] = []
    t = text.lower()
    for name, trigger_pat, anti_pat, predicted_class in _REJECTION_HEURISTICS:
        if re.search(trigger_pat, t, re.I):
            if not re.search(anti_pat, t, re.I):
                # Boost rejection probability when heuristic fires
                penalty = 0.35 if predicted_class == "rejected" else 0.20
                flags.append((name, penalty,
                              f"{name}: trigger matched but no mitigation ({anti_pat})"))
    return flags


def predict(draft_path):
    if not MODEL_OUT.exists():
        print(f"[error] model not trained — run --train first", file=sys.stderr)
        sys.exit(1)
    with open(MODEL_OUT, "rb") as f:
        m = pickle.load(f)
    pipe = m["pipeline"]
    classes = list(m["classes"])

    text = Path(draft_path).read_text(errors="ignore")
    # Extract title-like line + any severity mention
    title = next((ln for ln in text.splitlines() if ln.strip()), "")[:200]
    snippet = (title + "\n" + text[:2000])
    probs = list(pipe.predict_proba([snippet])[0])

    # Apply heuristic overrides
    heuristics = heuristic_screen(text)
    if heuristics:
        rej_idx = classes.index("rejected") if "rejected" in classes else -1
        for _name, penalty, _reason in heuristics:
            if rej_idx >= 0:
                # Shift probability mass toward rejected
                shift = min(penalty, 0.90 - probs[rej_idx])
                # Distribute the shift proportionally from other classes
                total_others = sum(p for i, p in enumerate(probs) if i != rej_idx)
                if total_others > 0:
                    for i in range(len(probs)):
                        if i != rej_idx:
                            probs[i] -= shift * (probs[i] / total_others)
                    probs[rej_idx] += shift

    print(f"  Draft: {Path(draft_path).name}")
    print(f"  Model: trained on {m.get('n_trained', '?')} examples")
    if heuristics:
        print(f"  Heuristics triggered ({len(heuristics)}):")
        for name, penalty, reason in heuristics:
            print(f"    ⚠️  {name}  (rejection boost +{penalty*100:.0f}%)")
    print(f"  Predicted distribution:")
    for cls, p in sorted(zip(classes, probs), key=lambda x: -x[1]):
        bar = "█" * int(p * 40)
        print(f"    {cls:8s}  {p*100:5.1f}%  {bar}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--predict", help="path to draft markdown")
    ap.add_argument("--retrain-incremental", action="store_true",
                    help="retrain enriched with rationale.txt files (U4)")
    ap.add_argument("--workspaces",
                    help="comma-separated workspace roots (or parents) to scan "
                         "for findings/*/rationale.txt "
                         "(defaults to auditooor/_workspaces/)")
    args = ap.parse_args()
    if args.train:
        train()
    elif args.predict:
        predict(args.predict)
    elif getattr(args, "retrain_incremental"):
        retrain_incremental(args.workspaces)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
