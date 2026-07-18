#!/usr/bin/env python3
"""
cluster-corpus.py — embed + cluster the Solodit corpus (Issue #84)

Turns 19k individual findings into ~200 semantic clusters. Each cluster
becomes one pattern class downstream (Issue #85).

Two modes:
  --embed    : read solodit_raw/*.json + drafts/*.yaml, embed title+summary,
               write reference/corpus_embeddings.npz (numpy arrays + ids).
               First run requires sentence-transformers + numpy.
  --cluster  : HDBSCAN over the embeddings, write reference/solodit_clusters.yaml
               with per-cluster (id, size, top-5 exemplars, severity dist, tags).

Usage:
    python3 tools/cluster-corpus.py --embed
    python3 tools/cluster-corpus.py --cluster
    python3 tools/cluster-corpus.py --embed --cluster     # both
    python3 tools/cluster-corpus.py --show <cluster-id>   # dump a cluster's findings

Cost: embeddings are local (sentence-transformers/all-MiniLM-L6-v2, 80MB).
Clustering is free. No API calls required. Total runtime ~3-5 min on 19k docs.

Fixes SKILL_ISSUE #84.
"""

import argparse
import json
import sys
from pathlib import Path
from collections import Counter

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
SPECS_DIR = AUDITOOOR_DIR / "detectors" / "_specs"
SOLODIT_RAW = SPECS_DIR / "solodit_raw"
DRAFTS_SOLODIT = SPECS_DIR / "drafts_solodit"
EMBED_CACHE = AUDITOOOR_DIR / "reference" / "corpus_embeddings.npz"
CLUSTERS_OUT = AUDITOOOR_DIR / "reference" / "solodit_clusters.yaml"
IDS_CACHE = AUDITOOOR_DIR / "reference" / "corpus_ids.json"


def load_findings():
    """Read all Solodit raw JSON + drafts YAML. Yields
    {id, title, summary, severity, tags, quality, content_preview}."""
    findings = {}

    # Prefer raw JSON (original metadata)
    if SOLODIT_RAW.exists():
        for jf in sorted(SOLODIT_RAW.glob("*.json")):
            try:
                data = json.loads(jf.read_text())
            except Exception:
                continue
            for f in data.get("findings", []):
                fid = str(f.get("id") or f.get("solodit_id") or "")
                if not fid:
                    continue
                title = f.get("title", "") or ""
                summary = f.get("summary", "") or f.get("content", "") or ""
                severity = f.get("impact", "") or f.get("kind", "") or ""
                tags = f.get("tags", "") or ""
                quality = f.get("quality_score", 0) or 0
                findings[fid] = {
                    "id": fid,
                    "title": title,
                    "summary": summary[:1500],  # cap
                    "severity": severity.upper() if isinstance(severity, str) else str(severity),
                    "tags": tags if isinstance(tags, str) else ",".join(tags or []),
                    "quality": quality,
                    "source": "solodit_raw",
                }

    # Fall back to / augment with drafts_solodit YAML
    if DRAFTS_SOLODIT.exists():
        try:
            import yaml
        except ImportError:
            print("[warn] PyYAML missing — skipping drafts_solodit", file=sys.stderr)
        else:
            for yf in sorted(DRAFTS_SOLODIT.glob("*.yaml")):
                try:
                    spec = yaml.safe_load(yf.read_text()) or {}
                except Exception:
                    continue
                fid = str(spec.get("solodit_id") or spec.get("name") or yf.stem)
                if fid in findings:
                    continue
                findings[fid] = {
                    "id": fid,
                    "title": spec.get("help", "") or spec.get("wiki_title", "") or "",
                    "summary": (spec.get("wiki_description", "") or
                                spec.get("wiki_exploit_scenario", "") or "")[:1500],
                    "severity": str(spec.get("severity", "") or "").upper(),
                    "tags": spec.get("solodit_tags", "") or "",
                    "quality": spec.get("solodit_quality", 0) or 0,
                    "source": "drafts_solodit",
                }

    # Round 29: merge additional draft corpora (audit-text, defihacklabs, glider)
    # that Round 25 embed originally ignored. ~10% corpus expansion.
    EXTRA_CORPORA = [
        ("drafts_audit_text", SPECS_DIR / "drafts_audit_text"),
        ("drafts_defihacklabs", SPECS_DIR / "drafts_defihacklabs"),
        ("drafts_glider", SPECS_DIR / "drafts_glider"),
        ("drafts_glider_ast", SPECS_DIR / "drafts_glider_ast"),
    ]
    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None
    if _yaml:
        for source_name, corpus_dir in EXTRA_CORPORA:
            if not corpus_dir.exists():
                continue
            added = 0
            for yf in sorted(corpus_dir.glob("*.yaml")):
                try:
                    spec = _yaml.safe_load(yf.read_text()) or {}
                except Exception:
                    continue
                fid = (f"{source_name}:" +
                       str(spec.get("name") or spec.get("class_name") or yf.stem))
                if fid in findings:
                    continue
                title = (spec.get("help") or spec.get("wiki_title") or
                         spec.get("name") or "")
                summary = (spec.get("wiki_description") or
                           spec.get("wiki_exploit_scenario") or "")
                findings[fid] = {
                    "id": fid,
                    "title": title[:200],
                    "summary": summary[:1500],
                    "severity": str(spec.get("severity") or "").upper(),
                    "tags": str(spec.get("solodit_tags") or
                                spec.get("tags") or "")[:200],
                    "quality": 0,
                    "source": source_name,
                }
                added += 1
            if added:
                print(f"[load] +{added} findings from {source_name}")

    return list(findings.values())


def embed(findings):
    """Local embed via sentence-transformers."""
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
    except ImportError:
        print("[error] missing deps. Install: pip3 install sentence-transformers numpy",
              file=sys.stderr)
        sys.exit(1)

    print(f"[embed] loading model 'all-MiniLM-L6-v2' (~80MB, first run downloads)...")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    # Compose "title. summary. tags."
    texts = []
    for f in findings:
        parts = []
        if f["title"]:
            parts.append(f["title"].strip())
        if f["summary"]:
            parts.append(f["summary"].strip())
        if f["tags"]:
            parts.append("Tags: " + f["tags"])
        texts.append(". ".join(parts))

    print(f"[embed] encoding {len(texts)} findings (~3-5 min)...")
    import time
    t0 = time.time()
    embs = model.encode(texts, batch_size=64, show_progress_bar=True,
                        convert_to_numpy=True, normalize_embeddings=True)
    print(f"[embed] done in {time.time()-t0:.1f}s, shape={embs.shape}")

    np.savez_compressed(EMBED_CACHE, embeddings=embs)
    # Save IDs / metadata separately
    IDS_CACHE.write_text(json.dumps([
        {"id": f["id"], "title": f["title"][:200], "severity": f["severity"],
         "tags": f["tags"][:200], "quality": f["quality"], "source": f["source"]}
        for f in findings
    ]))
    print(f"[embed] saved embeddings → {EMBED_CACHE}")
    print(f"[embed] saved id index   → {IDS_CACHE}")


def cluster(use_umap=True, min_cluster_size=10, min_samples=3, umap_dim=15):
    """UMAP → HDBSCAN on embeddings → clusters (Round 26 tuned).

    Default pipeline = UMAP preprocessing (hi-dim → 15d) then HDBSCAN. This
    mirrors BERTopic-style production clustering and produces far finer
    separation than raw HDBSCAN on 384-dim MiniLM embeddings (where Round 25's
    params collapsed 43% of the corpus into one mega-cluster).

    Args:
        use_umap: preprocess with UMAP before HDBSCAN (True = Round 26 default)
        min_cluster_size: smallest cluster to keep (10 = finer than Round 25's 15)
        min_samples: HDBSCAN density threshold (3 = more permissive than Round 25's 5)
        umap_dim: UMAP target dim (15 = standard BERTopic value)
    """
    try:
        import numpy as np
        import hdbscan
        import yaml
    except ImportError as e:
        print(f"[error] missing dep {e}. Install: pip3 install hdbscan numpy pyyaml",
              file=sys.stderr)
        sys.exit(1)

    if not EMBED_CACHE.exists():
        print(f"[error] {EMBED_CACHE} missing — run --embed first", file=sys.stderr)
        sys.exit(1)

    print(f"[cluster] loading embeddings from {EMBED_CACHE}")
    data = np.load(EMBED_CACHE)
    embs = data["embeddings"]
    ids_meta = json.loads(IDS_CACHE.read_text())
    assert len(ids_meta) == embs.shape[0], "id/embed count mismatch"

    import time
    working = embs
    if use_umap:
        try:
            import umap
        except ImportError:
            print("[warn] umap-learn missing — falling back to raw HDBSCAN. "
                  "Install: pip3 install umap-learn", file=sys.stderr)
            use_umap = False

    if use_umap:
        print(f"[cluster] UMAP preprocessing {embs.shape} → ({embs.shape[0]}, {umap_dim})")
        t0 = time.time()
        reducer = umap.UMAP(
            n_neighbors=15,
            n_components=umap_dim,
            min_dist=0.0,           # tight clusters
            metric="cosine",
            random_state=42,
            verbose=False,
        )
        working = reducer.fit_transform(embs)
        print(f"[cluster] UMAP done in {time.time()-t0:.1f}s, shape={working.shape}")

    print(f"[cluster] HDBSCAN on {working.shape} (min_cluster_size={min_cluster_size}, "
          f"min_samples={min_samples})...")
    t0 = time.time()
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",  # UMAP output uses euclidean
        cluster_selection_method="eom",
    )
    labels = clusterer.fit_predict(working)
    print(f"[cluster] HDBSCAN done in {time.time()-t0:.1f}s")

    # Summarize
    label_ctr = Counter(labels.tolist())
    noise = label_ctr.get(-1, 0)
    n_clusters = len([l for l in label_ctr if l != -1])
    print(f"[cluster] found {n_clusters} clusters, {noise} noise points "
          f"({100*noise/len(labels):.1f}% of corpus)")

    # Build per-cluster summary
    clusters = {}
    for i, lab in enumerate(labels):
        lab = int(lab)
        clusters.setdefault(lab, []).append(i)

    out = {"version": 1, "n_clusters": n_clusters, "n_noise": noise,
           "n_total": len(ids_meta), "clusters": {}}

    for lab, idxs in sorted(clusters.items(), key=lambda x: -len(x[1])):
        if lab == -1:
            continue  # skip noise
        members = [ids_meta[i] for i in idxs]
        # Severity distribution
        sev_dist = Counter(m["severity"] for m in members)
        # Tag frequency
        tag_ctr = Counter()
        for m in members:
            for t in str(m["tags"]).split(","):
                t = t.strip()
                if t:
                    tag_ctr[t] += 1
        # Pick exemplars closest to cluster centroid
        centroid = embs[idxs].mean(axis=0)
        centroid /= np.linalg.norm(centroid) + 1e-9
        sims = embs[idxs] @ centroid
        top_idx = sims.argsort()[::-1][:5]
        exemplars = [{"id": members[i]["id"], "title": members[i]["title"]}
                     for i in top_idx]

        out["clusters"][f"C{lab:04d}"] = {
            "size": len(members),
            "severity_dist": dict(sev_dist.most_common()),
            "top_tags": dict(tag_ctr.most_common(10)),
            "exemplars": exemplars,
            "all_ids": [m["id"] for m in members],
        }

    # Write YAML summary (exemplars + metadata; full ids preserved)
    CLUSTERS_OUT.write_text(yaml.safe_dump(out, sort_keys=False,
                                           default_flow_style=False, width=120))
    print(f"[cluster] wrote {CLUSTERS_OUT}")

    # Print top 20 clusters
    print(f"\n  Top 20 clusters by size:")
    print(f"  {'CID':6s} {'SIZE':>5s}  {'SEVERITY':12s}  EXEMPLAR")
    print(f"  {'---':6s} {'----':>5s}  {'--------':12s}  --------")
    for i, (cid, info) in enumerate(out["clusters"].items()):
        if i >= 20:
            break
        sev = "/".join(f"{s}:{c}" for s, c in list(info["severity_dist"].items())[:2])
        ex = info["exemplars"][0]["title"][:80] if info["exemplars"] else ""
        print(f"  {cid}  {info['size']:>5d}  {sev:12s}  {ex}")


def show(cluster_id):
    """Print all findings in one cluster."""
    import yaml
    if not CLUSTERS_OUT.exists():
        print(f"[error] {CLUSTERS_OUT} missing — run --cluster first", file=sys.stderr)
        sys.exit(1)
    data = yaml.safe_load(CLUSTERS_OUT.read_text())
    cluster = data.get("clusters", {}).get(cluster_id)
    if not cluster:
        print(f"[error] cluster {cluster_id} not found. Available: "
              f"{list(data.get('clusters', {}).keys())[:10]}", file=sys.stderr)
        sys.exit(1)
    print(f"Cluster {cluster_id}: {cluster['size']} findings")
    print(f"Severity: {cluster['severity_dist']}")
    print(f"Tags: {cluster['top_tags']}")
    print(f"\nExemplars:")
    for ex in cluster["exemplars"]:
        print(f"  - [{ex['id']}] {ex['title']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embed", action="store_true", help="embed corpus")
    ap.add_argument("--cluster", action="store_true", help="cluster embeddings")
    ap.add_argument("--show", help="print one cluster's findings")
    # Round 26 tuning flags
    ap.add_argument("--no-umap", action="store_true",
                    help="skip UMAP preprocessing (Round 25 behavior, coarser clusters)")
    ap.add_argument("--min-cluster-size", type=int, default=10,
                    help="HDBSCAN min_cluster_size (default 10)")
    ap.add_argument("--min-samples", type=int, default=3,
                    help="HDBSCAN min_samples (default 3)")
    ap.add_argument("--umap-dim", type=int, default=15,
                    help="UMAP target dim (default 15)")
    args = ap.parse_args()

    if args.show:
        show(args.show)
        return
    if args.embed:
        findings = load_findings()
        print(f"[load] {len(findings)} unique findings from corpus")
        if not findings:
            print("[error] no findings found. Check detectors/_specs/solodit_raw/",
                  file=sys.stderr)
            sys.exit(1)
        embed(findings)
    if args.cluster:
        cluster(
            use_umap=(not args.no_umap),
            min_cluster_size=args.min_cluster_size,
            min_samples=args.min_samples,
            umap_dim=args.umap_dim,
        )
    if not (args.embed or args.cluster or args.show):
        ap.print_help()


if __name__ == "__main__":
    main()
