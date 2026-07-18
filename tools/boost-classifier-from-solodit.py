#!/usr/bin/env python3
"""
boost-classifier-from-solodit.py — synthesize rationale training data from Solodit (R48 Track C)

Motivation:
  The C2 stop-criterion for the rejection classifier requires >=90% accuracy.
  We have 7,182 labeled Solodit rows but the training corpus is currently
  title + impact + tags only (<= ~20 tokens each). The raw JSON files under
  detectors/_specs/solodit_raw/*.json contain full `content` (multi-paragraph
  description + fix + sponsor acknowledgement) and `summary` (abstractive
  summary) — these are real written rationales for each finding's disposition
  and are strongly correlated with the paid/dupe outcome label already inferred
  by heuristic in reference/outcome_labels.yaml.

Strategy:
  1. Stream every `solodit_raw/*.json` finding.
  2. Join by finding id with the existing outcome labels
     (primary_likely_paid / dupe_prone_class). Drop unknowns.
  3. For each join, build a synthetic "rationale" = title + summary + first
     N chars of content. Gives ~400-800 tokens per row vs ~20 today.
  4. Fit LogisticRegression TF-IDF (same shape as rejection-classifier.py)
     on the enriched corpus. Compare against current baseline.
  5. If enriched accuracy >= current, persist the enriched model and append
     a history row.

This is additive to the rationale-incremental pipeline — rationale.txt rows
(real post-engagement triage notes) are still the highest-signal data; this
script just backfills synthetic rationales while we only have 5 real ones.
"""

import datetime as _dt
import glob
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
LABELS = AUDITOOOR_DIR / "reference" / "outcome_labels.yaml"
RAW_DIR = AUDITOOOR_DIR / "detectors" / "_specs" / "solodit_raw"
MODEL_OUT = AUDITOOOR_DIR / "reference" / "rejection_classifier.pkl"
HISTORY_OUT = AUDITOOOR_DIR / "reference" / "rejection_classifier_history.yaml"

CONTENT_TRUNCATE = 1500  # chars — keeps TF-IDF vocab tractable

_OUTCOME_MAP = {
    "primary_likely_paid": "paid",
    "high_value_primary": "paid",
    "dupe_prone_class": "dupe",
}


def _load_label_index():
    import yaml
    data = yaml.safe_load(LABELS.read_text())
    idx = {}
    for r in data.get("rows", []):
        cls = _OUTCOME_MAP.get(r.get("outcome"))
        if cls is None:
            continue
        idx[str(r["id"])] = {
            "cls": cls,
            "title": r.get("title") or "",
            "impact": r.get("impact") or "",
            "tags": r.get("tags") or "",
        }
    return idx


def _collect_raw_findings():
    for path in sorted(glob.glob(str(RAW_DIR / "*.json"))):
        try:
            blob = json.loads(Path(path).read_text())
        except Exception as e:
            print(f"[warn] could not parse {path}: {e}", file=sys.stderr)
            continue
        for f in blob.get("findings", []):
            yield f


def _rationale_text(finding, meta):
    title = finding.get("title") or meta["title"]
    impact = (finding.get("impact") or meta["impact"]).upper()
    summary = (finding.get("summary") or "").strip()
    content = (finding.get("content") or "").strip()
    if len(content) > CONTENT_TRUNCATE:
        content = content[:CONTENT_TRUNCATE]
    # Compose into a rationale-shaped blob that mirrors the real rationale.txt
    # files written during incremental retrain.
    parts = [
        f"Severity: {impact}",
        f"Title: {title}",
    ]
    if summary:
        parts.append(f"Summary: {summary}")
    if content:
        parts.append(f"Content: {content}")
    return "\n".join(parts)


def _baseline_corpus():
    """Current base corpus — title + impact + tags only (matches rejection-classifier.py)."""
    import yaml
    rows = yaml.safe_load(LABELS.read_text()).get("rows", [])
    X, y = [], []
    for r in rows:
        cls = _OUTCOME_MAP.get(r.get("outcome"))
        if cls is None:
            continue
        text = " ".join([r.get("title") or "", r.get("impact") or "", r.get("tags") or ""])
        X.append(text); y.append(cls)
    return X, y


def _fit(X, y, tag):
    from sklearn.linear_model import LogisticRegression
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report, accuracy_score
    import random

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2),
                                  stop_words="english", min_df=2)),
        ("clf", LogisticRegression(max_iter=3000, class_weight="balanced")),
    ])
    random.seed(42)
    idx = list(range(len(X)))
    random.shuffle(idx)
    split = int(0.8 * len(idx))
    Xtr = [X[i] for i in idx[:split]]
    ytr = [y[i] for i in idx[:split]]
    Xte = [X[i] for i in idx[split:]]
    yte = [y[i] for i in idx[split:]]
    pipe.fit(Xtr, ytr)
    acc = accuracy_score(yte, pipe.predict(Xte)) if yte else 0.0
    print(f"\n[{tag}] n_train={len(Xtr)} n_test={len(Xte)} acc={acc:.4f}")
    print(classification_report(yte, pipe.predict(Xte), zero_division=0))
    return pipe, acc, len(Xtr), len(Xte)


def main():
    try:
        import numpy as np  # noqa
        import sklearn  # noqa
        import yaml
    except ImportError:
        print("[error] needs scikit-learn + PyYAML + numpy", file=sys.stderr)
        sys.exit(1)

    # Baseline
    Xb, yb = _baseline_corpus()
    print(f"[baseline] {len(Xb)} rows, classes={dict(Counter(yb))}")
    base_pipe, base_acc, base_ntr, base_nte = _fit(Xb, yb, "baseline")

    # Synthetic rationale corpus
    label_idx = _load_label_index()
    print(f"[labels] {len(label_idx)} labeled findings in outcome_labels.yaml")

    synth_X, synth_y, matched = [], [], 0
    for f in _collect_raw_findings():
        fid = str(f.get("id"))
        meta = label_idx.get(fid)
        if meta is None:
            continue
        text = _rationale_text(f, meta)
        if not text.strip():
            continue
        synth_X.append(text); synth_y.append(meta["cls"])
        matched += 1

    print(f"[synthetic] matched {matched} rationales "
          f"({Counter(synth_y)})")

    # Enriched corpus = synthetic only when available (synthetic is strictly
    # more signal than baseline title+tags). For ids missing from solodit_raw
    # we fall back to the baseline row.
    import yaml as _yaml
    label_rows = _yaml.safe_load(LABELS.read_text()).get("rows", [])
    synth_by_id = {}
    for f in _collect_raw_findings():
        fid = str(f.get("id"))
        if fid in label_idx:
            synth_by_id[fid] = f
    Xe, ye = [], []
    for r in label_rows:
        cls = _OUTCOME_MAP.get(r.get("outcome"))
        if cls is None:
            continue
        fid = str(r["id"])
        if fid in synth_by_id:
            text = _rationale_text(synth_by_id[fid], label_idx[fid])
        else:
            text = " ".join([r.get("title") or "", r.get("impact") or "",
                             r.get("tags") or ""])
        Xe.append(text); ye.append(cls)
    print(f"[enriched] {len(Xe)} rows, classes={dict(Counter(ye))} "
          f"(synthetic replaces {len(synth_by_id)} baseline rows)")
    ext_pipe, ext_acc, ext_ntr, ext_nte = _fit(Xe, ye, "enriched")

    delta = ext_acc - base_acc
    print(f"\n[delta] baseline={base_acc:.4f} enriched={ext_acc:.4f} "
          f"Δ={delta:+.4f}")

    # Persist if non-regressing
    if ext_acc + 1e-6 >= base_acc:
        with open(MODEL_OUT, "wb") as fh:
            pickle.dump({
                "pipeline": ext_pipe,
                "classes": ext_pipe.classes_.tolist(),
                "n_trained": ext_ntr,
                "accuracy": ext_acc,
                "synthetic_rationale_rows": len(synth_X),
            }, fh)
        print(f"[save] model → {MODEL_OUT}")
    else:
        print("[skip] enriched accuracy regressed — keeping prior model")

    # Append history
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
        "source": "boost-classifier-from-solodit",
        "base_rows": len(Xb),
        "synthetic_rationale_rows": len(synth_X),
        "enriched_rows": len(Xe),
        "base_accuracy": round(base_acc, 4),
        "enriched_accuracy": round(ext_acc, 4),
        "accuracy_delta": round(delta, 4),
    })
    HISTORY_OUT.write_text(yaml.safe_dump(history, sort_keys=False))
    print(f"[history] appended → {HISTORY_OUT} ({len(history)} runs)")

    # Summary for stop-criteria consumption
    target = 0.85
    c2_target = 0.90
    print("\n=== C2 CHECK ===")
    print(f"current accuracy: {ext_acc:.4f}")
    print(f"interim target:   {target:.2f}  {'PASS' if ext_acc >= target else 'MISS'}")
    print(f"C2 target:        {c2_target:.2f}  {'PASS' if ext_acc >= c2_target else 'MISS'}")
    print("================")


if __name__ == "__main__":
    main()
