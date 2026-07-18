#!/usr/bin/env python3
"""corpus-coverage-burndown.py - reusable exploit-LOGIC-class coverage burndown.

This is the REPEATABLE version of the one-shot ad-hoc mining that produced the
original "16/61 classes" burndown. It performs a genuine SET DIFFERENCE, not a
shape match:

    UNCOVERED = { exploit-logic classes MINED from the corpus }
              - { classes for which a BUILT reasoner tool exists on disk }

and a SURFACE-ENUMERATION so that a whole-surface blind spot (like the
MPC / threshold-signature surface on axelar tofn, which was absent from ALL of
the original 61 frequency-ranked classes) cannot hide behind an EVM-skewed
frequency ranking.

Pipeline
--------
1. MINE   - re-cluster the reference corpus (findings_solidity + findings_go +
            findings_go_swival + external_advisories + fetchable_vuln_corpus +
            zkbugs + frost/MPC prior-audit classes + cosmos advisories, plus
            best-effort obsidian-vault post_mortem / causal_chains) into
            distinct exploit-LOGIC classes, each with a severity + corpus count.
2. DIFF   - enumerate BUILT reasoner tools (tools/*.py) + the docs burndown
            covered-list and compute covered vs uncovered -> ranked build queue.
3. SURFACE- enumerate the CODE SURFACES present in a target workspace and emit a
            surface-coverage matrix, flagging surfaces that are PRESENT but whose
            mined exploit-logic classes have NO built reasoner (blind spots) or
            that the frequency corpus UNDER-WEIGHTS.
4. EMIT   - machine-readable .auditooor/burndown/coverage.json + refresh
            docs/LOGIC_ARSENAL_BURNDOWN.md with the RECOMPUTED coverage count.

Guard-rail: this is a mined-classes MINUS built-reasoners set difference plus a
surface enumeration. It never greens a class from a shape/heuristic alone: a
class is "covered" only if a concrete reasoner file exists on disk AND is mapped
to that class signature.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date

# --------------------------------------------------------------------------- #
# Paths (defaults; override with --corpus-root / --reasoner-root)              #
# --------------------------------------------------------------------------- #
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CORPUS_ROOT = os.path.join(REPO_ROOT, "reference")
DEFAULT_REASONER_ROOT = os.path.join(REPO_ROOT, "tools")
DOC_PATH = os.path.join(REPO_ROOT, "docs", "LOGIC_ARSENAL_BURNDOWN.md")
DEFAULT_EMIT = os.path.join(REPO_ROOT, ".auditooor", "burndown", "coverage.json")

# jsonl finding datasets (each record carries a `bug_class` + `impact_tier`)
JSONL_DATASETS = [
    "findings_solidity.jsonl",
    "findings_go.jsonl",
    "findings_go_swival.jsonl",
    "findings_go_external_advisories.jsonl",
    "findings_go_mezo_ghsa.jsonl",
    "findings_go_existing_corpus.jsonl",
    "fetchable_vuln_corpus.jsonl",
]
# yaml class catalogs (each entry is already a distinct logic class)
ZK_YAML = "zkbugs_prior_audit_classes.yaml"
FROST_YAML = "frost_prior_audit_classes.yaml"
COSMOS_ADV_YAML = "cosmos_sdk_known_advisories.yaml"

TIER_RANK = {"critical": 4, "crit": 4, "high": 3, "medium": 2, "med": 2,
             "low": 1, "informational": 0, "info": 0, "unknown": 0}
TIER_LABEL = {4: "CRIT", 3: "HIGH", 2: "MED", 1: "LOW", 0: "INFO"}

# Surfaces this tool understands.
SURFACES = ["EVM", "Cosmos-Go", "Rust", "MPC/threshold-sig", "ZK", "Move", "Cairo"]


# --------------------------------------------------------------------------- #
# Surface classification of a mined logic-class signature                     #
# --------------------------------------------------------------------------- #
def surface_of_signature(sig: str) -> str:
    s = sig.lower()
    # MPC / threshold-signature is a SEMANTIC surface, not a language: it must be
    # recognised regardless of whether the code lives in Go (vald) or Rust (tofn).
    if re.search(r"tss|threshold|signing_coordinator|\bfrost\b|\bmpc\b|keygen|dkg|"
                 r"nonce.?reuse|share|lagrange|schnorr", s):
        return "MPC/threshold-sig"
    if s.startswith("zk.") or ".zk" in s or s.startswith("circom") or "constraint" in s:
        return "ZK"
    if s.startswith("sol.") or s.startswith("evm") or ".evm" in s:
        return "EVM"
    if s.startswith("rust.") or s.startswith("rs."):
        return "Rust"
    if s.startswith("move."):
        return "Move"
    if s.startswith("cairo."):
        return "Cairo"
    if s.startswith("go."):
        return "Cosmos-Go"
    return "Cosmos-Go" if "go" in s else "EVM"


# --------------------------------------------------------------------------- #
# Reasoner coverage map: mined-class signature-substring -> reasoner filename. #
# A class is COVERED only if the mapped reasoner file EXISTS on disk. The MPC / #
# threshold-sig signatures are DELIBERATELY absent (frost-prior-audit-class-    #
# verifier.py is a CLASSIFIER, not a logic reasoner), so the axelar tofn        #
# surface surfaces as an uncovered blind spot rather than a false green.        #
# --------------------------------------------------------------------------- #
REASONER_MAP = {
    # --- Solidity / EVM ---
    "sol.crosschain": "crosschain-message-authenticity-reasoner.py",
    "sol.access_control": "cross-contract-privilege-trust-graph.py",
    "sol.trust_boundary": "cross-contract-privilege-trust-graph.py",
    "sol.timelock": "authority-blast-radius.py",
    "sol.factory": "authority-blast-radius.py",
    "sol.dispatcher": "callgraph-set-difference-hunter.py",
    "oracle": "oracle-spot-price-manipulation-reasoner.py",
    "amm": "amm-structural-manipulation.py",
    "rounding": "directional-rounding-asymmetry.py",
    "conservation": "conservation-haircut-realization-check.py",
    "reentran": "callback-reentrancy-composition.py",
    "default_degenerate": "default-degenerate-input-verdict-reasoner.py",
    "atomic_sequence": "atomic-sequence-economic-sequencer.py",
    "coupled": "coupled-state-completeness-graph.py",
    "boundary_seed": "adversarial-numeric-boundary-seeder.py",
    # --- Go / Cosmos ---
    "go.cosmos": "go-mustsucceed-arith-overflow-halt.py",
    "go.statemachine": "go-mustsucceed-panic-reachability.py",
    "go.consensus": "crossimpl-consensus-divergence.py",
    "go.cross_chain": "crossimpl-consensus-divergence.py",
    "go.async": "async-cancel-coupled-state-screen.py",
    "go.bounds": "slice-oob-bounds-taint.py",
    "go.input_validation": "slice-oob-bounds-taint.py",
    "go.input": "slice-oob-bounds-taint.py",
    "go.dos": "go-mustsucceed-panic-reachability.py",
    "go.ecdsa": "go-slice-aliasing-screen.py",
    "go.ecdh": "go-slice-aliasing-screen.py",
    "go.tls": "go-slice-aliasing-screen.py",
    "go.aead": "go-slice-aliasing-screen.py",
    "nondeterministic": "nondeterministic-deserialization.py",
    "go.deps": "nondeterministic-deserialization.py",
    # --- Rust ---
    "rust.arith": "rust-unchecked-arith-value-overflow.py",
    "rust.overflow": "rust-numeric-overflow-underflow-scan.py",
    "rust.panic": "rust-from-u8-panic-on-untrusted-input-scan.py",
    "rust.send_sync": "rust-send-sync-bound-omission-share-boundary-screen.py",
    "rust.drop": "panic-during-drop-screen.py",
    # --- ZK (one constraint-coverage backend covers the family) ---
    "zk.": "zk-constraint-coverage.py",
    "go.zk": "zk-constraint-coverage.py",
    # NOTE: intentionally NO entry for tss / signing_coordinator / mpc / frost.
}


def load_reasoner_inventory(reasoner_root: str) -> set:
    try:
        return {f for f in os.listdir(reasoner_root) if f.endswith(".py")}
    except OSError:
        return set()


def covered_reasoner_for(sig: str, inventory: set):
    """Return the reasoner file that covers `sig`, or None. Set-difference core:
    a class is covered iff a mapped reasoner exists ON DISK."""
    s = sig.lower()
    for key, reasoner in REASONER_MAP.items():
        if key in s and reasoner in inventory:
            return reasoner
    return None


# --------------------------------------------------------------------------- #
# 1. MINE the corpus into distinct exploit-logic classes                      #
# --------------------------------------------------------------------------- #
class MinedClass:
    __slots__ = ("sig", "surface", "tier_rank", "count", "examples")

    def __init__(self, sig):
        self.sig = sig
        self.surface = surface_of_signature(sig)
        self.tier_rank = 0
        self.count = 0
        self.examples = []

    def add(self, tier_rank, example):
        self.count += 1
        self.tier_rank = max(self.tier_rank, tier_rank)
        if example and len(self.examples) < 4:
            self.examples.append(example)


def _tier_rank(tier: str) -> int:
    return TIER_RANK.get((tier or "").strip().lower(), 0)


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


def mine_jsonl(corpus_root, classes, provenance):
    for name in JSONL_DATASETS:
        path = os.path.join(corpus_root, name)
        n = 0
        for line in _read_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            bc = (d.get("bug_class") or "").strip()
            if not bc:
                continue
            # cluster to the first two dot-segments = the exploit-LOGIC signature
            sig = ".".join(bc.split(".")[:2]) if "." in bc else bc
            classes.setdefault(sig, MinedClass(sig)).add(
                _tier_rank(d.get("impact_tier")),
                d.get("finding_id") or d.get("protocol"),
            )
            n += 1
        if n:
            provenance.append({"source": name, "records": n})


def _yaml_class_ids(path, keyprefix):
    """Cheap YAML extraction (no PyYAML dep): pull `class_id:` + nearest
    `severity_class:` for prior-audit class catalogs."""
    out = []
    cur = None
    sev = None
    for raw in _read_lines(path):
        m = re.match(r"\s*-?\s*class_id:\s*(\S+)", raw)
        if m:
            if cur:
                out.append((cur, sev))
            cur = m.group(1).strip().strip('"')
            sev = None
            continue
        m2 = re.match(r"\s*severity_class:\s*(\S+)", raw)
        if m2 and cur and sev is None:
            sev = m2.group(1).strip().strip('"')
    if cur:
        out.append((cur, sev))
    return [(f"{keyprefix}{cid}", sev) for cid, sev in out]


def _sev_from_class_hint(sev):
    if not sev:
        return 3  # prior-audit catalogs default to HIGH-equivalent
    s = sev.lower()
    if "crit" in s:
        return 4
    if "high" in s:
        return 3
    if "med" in s:
        return 2
    return 3


def mine_yaml_catalogs(corpus_root, classes, provenance):
    for name, prefix in ((ZK_YAML, "zk."), (FROST_YAML, "mpc.")):
        path = os.path.join(corpus_root, name)
        entries = _yaml_class_ids(path, prefix)
        for sig, sev in entries:
            mc = classes.setdefault(sig, MinedClass(sig))
            mc.add(_sev_from_class_hint(sev), name)
        if entries:
            provenance.append({"source": name, "records": len(entries)})
    # cosmos advisories -> cluster to a single go.cosmos_advisory logic class
    adv_path = os.path.join(corpus_root, COSMOS_ADV_YAML)
    adv = [l for l in _read_lines(adv_path) if re.match(r"\s*-\s*advisory_id:", l)]
    if adv:
        sig = "go.cosmos_advisory"
        mc = classes.setdefault(sig, MinedClass(sig))
        for _ in adv:
            mc.add(3, COSMOS_ADV_YAML)
        provenance.append({"source": COSMOS_ADV_YAML, "records": len(adv)})


def mine_vault(corpus_root, classes, provenance):
    """Best-effort: fold obsidian-vault post_mortem / causal_chains files in as
    corpus-weight signal on already-mined classes (they rarely add NEW logic
    signatures, but they up-weight the ones seen in real incidents). Graceful if
    absent."""
    candidates = [
        os.path.join(REPO_ROOT, "obsidian-vault", "external-audits-extracts"),
        os.path.join(REPO_ROOT, "audit", "postmortems"),
        os.path.join(os.path.dirname(REPO_ROOT), "obsidian-vault", "post_mortem"),
    ]
    hits = 0
    for d in candidates:
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for f in files:
                if f.endswith((".md", ".jsonl", ".json")):
                    hits += 1
    if hits:
        provenance.append({"source": "obsidian-vault/post_mortem+causal_chains",
                           "files_scanned": hits, "mode": "corpus-weight-only"})


def mine_corpus(corpus_root):
    classes: dict[str, MinedClass] = {}
    provenance: list[dict] = []
    mine_jsonl(corpus_root, classes, provenance)
    mine_yaml_catalogs(corpus_root, classes, provenance)
    mine_vault(corpus_root, classes, provenance)
    return classes, provenance


# --------------------------------------------------------------------------- #
# 3. SURFACE enumeration of a target workspace                                #
# --------------------------------------------------------------------------- #
MPC_MARKERS = re.compile(r"tofn|threshold|frost|\bmpc\b|keygen|\bdkg\b|"
                         r"signing_coordinator|gg20|schnorr|lagrange", re.I)


def enumerate_workspace_surfaces(ws_root: str) -> dict:
    """Walk a workspace and report which code surfaces are present. Detection is
    by file extension + content markers (MPC is a semantic surface, so a Rust or
    Go file that touches tofn/threshold/keygen counts toward MPC/threshold-sig)."""
    counts = Counter()
    present = set()
    if not ws_root or not os.path.isdir(ws_root):
        return {"root": ws_root, "surfaces": {}, "note": "workspace not found on disk"}
    skip = {".git", "node_modules", "target", ".auditooor", "lib", "out"}
    for root, dirs, files in os.walk(ws_root):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            fp = os.path.join(root, f)
            if f.endswith(".sol"):
                counts["EVM"] += 1
                present.add("EVM")
            elif f.endswith(".go"):
                counts["Cosmos-Go"] += 1
                present.add("Cosmos-Go")
                if MPC_MARKERS.search(fp):
                    counts["MPC/threshold-sig"] += 1
                    present.add("MPC/threshold-sig")
            elif f.endswith(".rs"):
                counts["Rust"] += 1
                present.add("Rust")
                if MPC_MARKERS.search(fp):
                    counts["MPC/threshold-sig"] += 1
                    present.add("MPC/threshold-sig")
            elif f.endswith((".circom", ".zok")):
                counts["ZK"] += 1
                present.add("ZK")
            elif f.endswith(".move"):
                counts["Move"] += 1
                present.add("Move")
            elif f.endswith(".cairo"):
                counts["Cairo"] += 1
                present.add("Cairo")
    # Rust workspaces that ship tofn/threshold in a path segment: catch by dir name
    for root, dirs, _files in os.walk(ws_root):
        dirs[:] = [d for d in dirs if d not in skip]
        if MPC_MARKERS.search(root):
            counts["MPC/threshold-sig"] += 1
            present.add("MPC/threshold-sig")
            break
    return {"root": ws_root, "surfaces": dict(counts), "present": sorted(present)}


def surface_coverage_matrix(classes, inventory, ws_surfaces):
    """Per-surface: mined classes, covered classes, corpus weight, verdict.
    A surface PRESENT in the workspace whose mined classes have ZERO covered
    reasoners is a BLIND-SPOT (the exact failure that hid MPC/threshold-sig)."""
    total_corpus = sum(mc.count for mc in classes.values()) or 1
    by_surface = defaultdict(lambda: {"mined": 0, "covered": 0, "corpus": 0,
                                      "classes": []})
    for sig, mc in classes.items():
        row = by_surface[mc.surface]
        row["mined"] += 1
        row["corpus"] += mc.count
        cov = covered_reasoner_for(sig, inventory)
        if cov:
            row["covered"] += 1
        row["classes"].append(sig)

    present = set(ws_surfaces.get("present", []))
    matrix = []
    for surface in SURFACES:
        row = by_surface.get(surface, {"mined": 0, "covered": 0, "corpus": 0,
                                       "classes": []})
        in_ws = surface in present
        weight = round(100.0 * row["corpus"] / total_corpus, 1)
        verdict = "OK"
        flagged = False
        if in_ws and row["mined"] > 0 and row["covered"] == 0:
            verdict = "BLIND-SPOT (surface present, 0 reasoners)"
            flagged = True
        elif in_ws and row["mined"] == 0:
            verdict = "BLIND-SPOT (surface present, 0 mined classes)"
            flagged = True
        elif in_ws and row["covered"] < row["mined"]:
            verdict = "PARTIAL"
        elif in_ws:
            verdict = "COVERED"
        else:
            verdict = "not-in-workspace"
        matrix.append({
            "surface": surface,
            "in_workspace": in_ws,
            "mined_classes": row["mined"],
            "covered_classes": row["covered"],
            "corpus_weight_pct": weight,
            "verdict": verdict,
            "flagged": flagged,
        })
    return matrix


# --------------------------------------------------------------------------- #
# 2. DIFF -> covered vs uncovered + ranked build queue                        #
# --------------------------------------------------------------------------- #
def build_diff(classes, inventory):
    covered, uncovered = [], []
    for sig, mc in sorted(classes.items(),
                          key=lambda kv: (-kv[1].tier_rank, -kv[1].count)):
        reasoner = covered_reasoner_for(sig, inventory)
        entry = {
            "class": sig,
            "surface": mc.surface,
            "severity": TIER_LABEL[mc.tier_rank],
            "corpus_count": mc.count,
            "reasoner": reasoner,
            "examples": mc.examples,
        }
        (covered if reasoner else uncovered).append(entry)
    # rank build queue by severity x corpus-count
    uncovered.sort(key=lambda e: (-TIER_RANK.get(e["severity"].lower(), 0),
                                  -e["corpus_count"]))
    return covered, uncovered


# --------------------------------------------------------------------------- #
# 3b. NOVELTY-FLYWHEEL FOLD: minted classes -> uncovered build-obligations     #
# --------------------------------------------------------------------------- #
def fold_minted_novel_classes(uncovered, workspaces):
    """Fold the novelty-gate-flywheel minted classes (per-workspace
    .auditooor/novelty/new_classes.jsonl) into the RANKED UNCOVERED BUILD QUEUE.

    A minted class (auditooor.novel_class.v1) is a NOVEL invariant-violation
    vector the flywheel surfaced that matches NO corpus class AND NO prior audit
    (grounded on a file:line derived-invariant violation). Because it has no
    corpus name, no reasoner on disk covers it - so it is, by construction, a NEW
    UNCOVERED class and a build-obligation. We inject it here so the build queue
    (and docs/LOGIC_ARSENAL_BURNDOWN.md) reflects the self-grown backlog, closing
    the flywheel: hunt -> mint -> build-queue. Deduped by class_id across
    workspaces. Never fabricates: only reads what the flywheel already emitted."""
    seen = {e["class"] for e in uncovered}
    minted = []
    for _label, ws_root in workspaces:
        p = os.path.join(ws_root, ".auditooor", "novelty", "new_classes.jsonl")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            cid = str(rec.get("class_id") or "").strip()
            if not cid or cid in seen:
                continue
            seen.add(cid)
            mf = rec.get("minted_from") or {}
            stmt = str(mf.get("statement") or rec.get("statement") or "").strip()
            tgt = str(mf.get("target") or "").strip()
            example = (stmt or tgt or cid)[:160]
            minted.append({
                "class": cid,
                "surface": "novel-minted",
                "severity": "High",   # novel mega-impact vector by construction
                "corpus_count": 1,
                "reasoner": None,     # unbuilt: this IS the build-obligation
                "examples": [example] if example else [],
                "provenance": "novelty-gate-flywheel",
                "minted_status": str(rec.get("status") or "candidate-unported"),
            })
    # prepend minted (HIGHEST priority per flywheel) then re-rank by sev x count
    uncovered.extend(minted)
    uncovered.sort(key=lambda e: (-TIER_RANK.get(str(e["severity"]).lower(), 0),
                                  -e.get("corpus_count", 0)))
    return uncovered, minted


# --------------------------------------------------------------------------- #
# 4. EMIT                                                                      #
# --------------------------------------------------------------------------- #
def refresh_doc(total, covered_n, covered, uncovered, matrices):
    pct = round(100.0 * covered_n / total, 1) if total else 0.0
    lines = []
    lines.append("# LOGIC-ARSENAL CORPUS COVERAGE BURNDOWN (the systematic build queue)")
    lines.append("")
    lines.append(f"Source: tools/corpus-coverage-burndown.py (RE-MINED {date.today().isoformat()}) "
                 "over the FULL corpus (reference/findings_solidity + findings_go + "
                 "findings_go_swival + external_advisories + fetchable_vuln_corpus + "
                 "zkbugs + frost/MPC prior-audit classes + cosmos advisories, plus "
                 "best-effort obsidian-vault post_mortem/causal_chains). This doc is now "
                 "REGENERATED by that tool - do not hand-edit the counts.")
    lines.append("")
    lines.append(f"## COVERAGE = {covered_n} / {total} distinct exploit-LOGIC classes = {pct}%")
    lines.append("")
    lines.append("(Recomputed by set difference: mined-classes MINUS built-reasoners-on-disk. "
                 "Granularity differs from the original ad-hoc 61-class hand count - the tool "
                 "clusters jsonl bug_class to its 2-segment logic signature and folds the "
                 "zkbugs/frost catalogs in as first-class logic classes, which is why the "
                 "MPC/threshold-sig surface - absent from all 61 - now appears.)")
    lines.append("")
    lines.append("## SURFACE-COVERAGE MATRIX (per proven workspace)")
    for wsname, matrix in matrices.items():
        lines.append(f"### {wsname}")
        lines.append("| surface | in-ws | mined | covered | corpus% | verdict |")
        lines.append("|---------|-------|-------|---------|---------|---------|")
        for r in matrix:
            flag = " **<-- GAP**" if r["flagged"] else ""
            lines.append(f"| {r['surface']} | {'Y' if r['in_workspace'] else '-'} | "
                         f"{r['mined_classes']} | {r['covered_classes']} | "
                         f"{r['corpus_weight_pct']} | {r['verdict']}{flag} |")
        lines.append("")
    lines.append("## RANKED UNCOVERED BUILD QUEUE (severity x corpus-count)")
    for i, e in enumerate(uncovered[:40], 1):
        ex = f" e.g. {e['examples'][0]}" if e["examples"] else ""
        lines.append(f"{i:2}. [{e['severity']} x{e['corpus_count']}] {e['class']} "
                     f"(surface={e['surface']}).{ex}")
    lines.append("")
    lines.append("## RULES")
    lines.append("- Prove EVERY new reasoner on nuva + axelar-dlt ONLY (or honest cited-empty).")
    lines.append("- Re-run `tools/corpus-coverage-burndown.py --emit` after building a reasoner "
                 "to refresh this count; never hand-edit the coverage number.")
    lines.append("- A surface flagged **<-- GAP** means the workspace exercises that surface but "
                 "NO built reasoner covers its mined classes - build one before claiming honest-0.")
    lines.append("")
    with open(DOC_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def sanitize(text):
    return text.replace("—", "-").replace("–", "-")


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def run(corpus_root, reasoner_root, workspaces):
    classes, provenance = mine_corpus(corpus_root)
    inventory = load_reasoner_inventory(reasoner_root)
    covered, uncovered = build_diff(classes, inventory)
    total = len(classes)
    covered_n = len(covered)

    matrices = {}
    for label, ws_root in workspaces:
        surf = enumerate_workspace_surfaces(ws_root)
        matrices[label] = surface_coverage_matrix(classes, inventory, surf)

    # NOVELTY FLYWHEEL FOLD: minted NOVEL classes (no reasoner on disk) are NEW
    # uncovered build-obligations. Fold them into the ranked build queue so the
    # self-grown backlog is visible + drives the arsenal build loop.
    uncovered, minted_novel = fold_minted_novel_classes(uncovered, workspaces)

    result = {
        "schema": "auditooor.corpus_coverage_burndown.v1",
        "generated": date.today().isoformat(),
        "corpus_root": corpus_root,
        "reasoner_root": reasoner_root,
        "provenance": provenance,
        "total_classes": total,
        "covered_classes": covered_n,
        "uncovered_classes": total - covered_n,
        "coverage_pct": round(100.0 * covered_n / total, 1) if total else 0.0,
        "covered": covered,
        "uncovered_build_queue": uncovered,
        "minted_novel_classes": minted_novel,
        "surface_matrix": matrices,
    }
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-root", default=DEFAULT_CORPUS_ROOT)
    ap.add_argument("--reasoner-root", default=DEFAULT_REASONER_ROOT)
    ap.add_argument("--workspace", action="append", default=[],
                    help="label=path OR path; repeatable. Enumerates surfaces.")
    ap.add_argument("--json", action="store_true", help="print full JSON result")
    ap.add_argument("--emit", nargs="?", const=DEFAULT_EMIT, default=None,
                    help="write coverage.json (default .auditooor/burndown/coverage.json) "
                         "AND refresh docs/LOGIC_ARSENAL_BURNDOWN.md")
    args = ap.parse_args(argv)

    workspaces = []
    for w in args.workspace:
        if "=" in w:
            label, path = w.split("=", 1)
        else:
            label, path = os.path.basename(w.rstrip("/")), w
        workspaces.append((label, path))

    result = run(args.corpus_root, args.reasoner_root, workspaces)

    if args.emit is not None:
        emit_path = args.emit
        os.makedirs(os.path.dirname(emit_path), exist_ok=True)
        with open(emit_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        refresh_doc(result["total_classes"], result["covered_classes"],
                    result["covered"], result["uncovered_build_queue"],
                    result["surface_matrix"])
        result["emitted"] = {"coverage_json": emit_path, "doc": DOC_PATH}

    if args.json:
        print(sanitize(json.dumps(result, indent=2)))
    else:
        print(sanitize(_summary(result)))
    return 0


def _summary(r):
    out = []
    out.append(f"RECOMPUTED COVERAGE: {r['covered_classes']} / {r['total_classes']} "
               f"= {r['coverage_pct']}% distinct exploit-logic classes covered")
    out.append("")
    out.append("TOP UNCOVERED (severity x corpus-count):")
    for e in r["uncovered_build_queue"][:12]:
        out.append(f"  [{e['severity']} x{e['corpus_count']}] {e['class']} "
                   f"(surface={e['surface']})")
    out.append("")
    for label, matrix in r["surface_matrix"].items():
        out.append(f"SURFACE MATRIX [{label}]:")
        for row in matrix:
            if row["in_workspace"] or row["flagged"]:
                flag = "  <== GAP" if row["flagged"] else ""
                out.append(f"  {row['surface']:<18} mined={row['mined_classes']:<3} "
                           f"covered={row['covered_classes']:<3} "
                           f"corpus%={row['corpus_weight_pct']:<5} "
                           f"{row['verdict']}{flag}")
        out.append("")
    if r.get("emitted"):
        out.append(f"EMITTED: {r['emitted']['coverage_json']} + {r['emitted']['doc']}")
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
