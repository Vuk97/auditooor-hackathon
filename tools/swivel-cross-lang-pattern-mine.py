#!/usr/bin/env python3
"""Mine the swivel (Swival/security-audits) rust + go corpus and emit cross-language
go<->rust pattern-pair sidecars.

The swivel corpus is NOT in the global hackerman tag index, so the existing
cross-language-analogue tooling cannot see it. This tool reads the two swivel
corpora directly, normalizes both into a shared language-neutral attack-class
taxonomy, computes go<->rust pattern pairs (classes present in both languages
and classes present in only one), and emits sidecars.

Verification tier (Rule 37): tier-2-verified-public-archive. Every emitted row is
sourced from a verified_audit_finding in the Swival/security-audits public archive
(rust route-evidence + go crypto JSONL); no live API call, no synthetic taxonomy.

RELATED TOOLS:
  - tools/hackerman-cross-language-analogues.py : emits analogue pairs from the
    GLOBAL hackerman v1 tag index (audit/corpus_tags/tags). It cannot mine swivel
    because swivel is not in that index. This tool fills that gap by reading the
    swivel corpus directly. Output schema is intentionally distinct.
  - tools/hackerman-cross-language-lift-lane6.py : lane-6 lift over the global index.
  - tools/rust-swival-route-evidence.py / rust-swival-family-map.py : produce the
    rust-side route-evidence + family map this tool consumes as input.
  - vault_cross_language_pattern_lift MCP callable : reads the global analogue
    sidecar; the pairs this tool emits are swivel-scoped.

This is corpus ETL / mining-learning only. It emits sidecars; it does not file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_PAIRS = "auditooor.swivel_cross_lang_pairs.v1"
SCHEMA_NORM = "auditooor.swivel_normalized_classes.v1"
SCHEMA_MANIFEST = "auditooor.swivel_cross_lang_mine.manifest.v1"
VERIFICATION_TIER = "tier-2-verified-public-archive"

DEFAULT_RUST_INDEX = Path(
    "/Users/wolf/audits/base-azul/.audit_logs/rust_corpus_mining/rust_corpus_index.json"
)
DEFAULT_RUST_ROUTE = Path(
    "/Users/wolf/audits/base-azul/.audit_logs/rust_corpus_mining/rust_swival_route_evidence.json"
)
DEFAULT_GO_JSONL = Path("/Users/wolf/auditooor-mcp/reference/findings_go_swival.jsonl")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


CLASS_RULES: list[tuple[str, str]] = [
    ("length_bounds_check",
     r"unchecked.{0,20}length|oversized|length.{0,20}(slice|underflow|overflow|round)"
     r"|out[- ]of[- ]bounds|truncat|over[- ]?read|over[- ]?write|excess|exceeds buffer"
     r"|undersized|read count exceeds|unbounded (loop|directory|alloc)"
     r"|uncopied|copied bytes|overreports|reparse name|reports excess"
     r"|huge slice|string offset|string table|value access|cached power index"),
    ("integer_arith_boundary",
     r"underflow|overflow|wrap|rounding|widening|negation|division by|modulo by"
     r"|counter[_ ]wrap|signed (min|imm)|off[- ]by|offset addition"),
    ("injection_or_escaping",
     r"unescaped|injection|argument injection|interior nul|nul byte|sanitiz"
     r"|directive injection|argument name|xml attribute|trailing input"),
    ("concurrency_state",
     r"\brace\b|concurren|stale (copy|handle|state)|poison|acquire|atomic"
     r"|inter-core|notify error|wait error|spin[- ]?mutex|self[- ]referential"
     r"|state invariant|buffer state"),
    ("unsafe_memory_pointer",
     r"raw (slice|pointer)|dereference|reference over (mutable|nonexclusive)"
     r"|uninitialized|null (load|pointer)|from_raw|realloc|mismatched allocation"
     r"|memalign|global pointer|public globals|invalid reference|alias"
     r"|frame pointer|sign pointer|environ pointer|raw|from raw"),
    ("simd_cpu_feature",
     r"\bsimd\b|\bvsx\b|svld|svst|rcpc|cpuid|target feature|hwcap|avx|avxvnni|rdrand"),
    ("resource_leak",
     r"\bleak|orphan|handle (count|leak)|stdio|redirect|child leaked|listener"),
    ("panic_dos",
     r"\bpanic|stall|silently (dropped|ignored)|silently"),
    ("input_validation_accept",
     r"accepted|accepts|skips|skipped|not enforced|bypass|misapplied|mismatch accepted"
     r"|silently accepted|precondition violation|unvalidated input|approval bypass"),
    ("crypto_primitive_misuse",
     r"ecdsa|ecdh|rsa|aead|gcm|hkdf|pbkdf2|hpke|ml[_-]kem|drbg|sha-3|tls|x\.509|x509"
     r"|serial|certificate|scalar|infinity|key not enforced|psk identity|ech hash"),
]


def classify(text: str) -> list[str]:
    t = text.lower()
    out: list[str] = []
    for cls, rx in CLASS_RULES:
        if re.search(rx, t):
            out.append(cls)
    return out or ["uncategorized"]


def load_rust(index_path: Path, route_path: Path) -> list[dict[str, Any]]:
    index_by_id: dict[str, dict[str, Any]] = {}
    if index_path.exists():
        idx = json.load(index_path.open())
        for r in idx.get("records", []):
            index_by_id[r.get("item_id", "")] = r
    route = json.load(route_path.open())
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in route.get("rows", []):
        iid = r.get("item_id", "")
        if not iid.startswith("swival-rust-stdlib-"):
            continue
        if iid in seen:
            continue
        seen.add(iid)
        title = r.get("title", "")
        idx_rec = index_by_id.get(iid, {})
        category = r.get("route_family") or idx_rec.get("category", "")
        component = idx_rec.get("component", r.get("component", "unknown"))
        sev = r.get("corpus_severity") or idx_rec.get("corpus_severity", "unknown")
        text = " ".join([title, category, component])
        classes = classify(text)
        rows.append({
            "language": "rust", "finding_id": iid, "title": title,
            "corpus_category": category, "component": component, "corpus_severity": sev,
            "route_family": r.get("route_family", ""), "primary_route": r.get("primary_route", ""),
            "attack_classes": classes, "primary_attack_class": classes[0],
            "source_pointers": r.get("source_pointers", []),
            "fixture_backed": r.get("fixture_backed", False),
            "patch_backed": r.get("patch_backed", False),
        })
    return rows


def load_go(jsonl_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in jsonl_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        title = d.get("summary", "")
        bug_class = d.get("bug_class", "")
        prov = d.get("provenance", {})
        category = prov.get("category", "")
        text = " ".join([title, bug_class, category])
        classes = classify(text)
        rows.append({
            "language": "go", "finding_id": d.get("finding_id", ""),
            "title": (title[:160] + "...") if len(title) > 160 else title,
            "bug_class": bug_class, "corpus_category": category,
            "component": prov.get("affected_location", "").split(":")[0],
            "corpus_severity": prov.get("severity_label", d.get("impact_tier", "")),
            "attack_classes": classes, "primary_attack_class": classes[0],
            "source_pointers": [prov.get("report_path", "")],
            "audit_url": prov.get("audit_url", ""),
        })
    return rows


def _lift_note(cls, verdict, r_members, g_members) -> str:
    if verdict == "bidirectional-analogue":
        return (f"Class '{cls}' is attested in BOTH rust-stdlib ({len(r_members)}) and "
                f"go-stdlib-crypto ({len(g_members)}). A detector for this class should "
                f"fire across both language surfaces.")
    if verdict == "rust-only-lift-to-go-candidate":
        return (f"Class '{cls}' has {len(r_members)} rust instances but ZERO go instances "
                f"in swivel. LIFT CANDIDATE: scan go-stdlib/crypto for the same shape.")
    return (f"Class '{cls}' has {len(g_members)} go instances but ZERO rust instances "
            f"in swivel. LIFT CANDIDATE: scan rust-stdlib/crypto crates for the same shape.")


def build_pairs(rust_rows, go_rows) -> list[dict[str, Any]]:
    rust_by: dict[str, list] = defaultdict(list)
    go_by: dict[str, list] = defaultdict(list)
    for r in rust_rows:
        for c in r["attack_classes"]:
            rust_by[c].append(r)
    for g in go_rows:
        for c in g["attack_classes"]:
            go_by[c].append(g)
    pairs = []
    for cls in sorted(set(rust_by) | set(go_by)):
        rm, gm = rust_by.get(cls, []), go_by.get(cls, [])
        if rm and gm:
            verdict = "bidirectional-analogue"
        elif rm:
            verdict = "rust-only-lift-to-go-candidate"
        elif gm:
            verdict = "go-only-lift-to-rust-candidate"
        else:
            continue
        pairs.append({
            "schema": SCHEMA_PAIRS, "verification_tier": VERIFICATION_TIER,
            "attack_class": cls, "lift_verdict": verdict,
            "rust_count": len(rm), "go_count": len(gm),
            "rust_examples": [{"finding_id": m["finding_id"], "title": m["title"]} for m in rm[:5]],
            "go_examples": [{"finding_id": m["finding_id"], "title": m["title"],
                            "bug_class": m.get("bug_class", "")} for m in gm[:5]],
            "lift_note": _lift_note(cls, verdict, rm, gm),
        })
    return pairs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rust-index", type=Path, default=DEFAULT_RUST_INDEX)
    ap.add_argument("--rust-route", type=Path, default=DEFAULT_RUST_ROUTE)
    ap.add_argument("--go-jsonl", type=Path, default=DEFAULT_GO_JSONL)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    rust_rows = load_rust(args.rust_index, args.rust_route)
    go_rows = load_go(args.go_jsonl)
    pairs = build_pairs(rust_rows, go_rows)

    norm_path = args.out_dir / "swivel_normalized_classes.jsonl"
    with norm_path.open("w") as fh:
        for r in (rust_rows + go_rows):
            rec = dict(r); rec["schema"] = SCHEMA_NORM; rec["verification_tier"] = VERIFICATION_TIER
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    pairs_path = args.out_dir / "swivel_cross_lang_pairs.jsonl"
    with pairs_path.open("w") as fh:
        for p in pairs:
            fh.write(json.dumps(p, sort_keys=True) + "\n")

    bidir = [p for p in pairs if p["lift_verdict"] == "bidirectional-analogue"]
    rust_only = [p for p in pairs if p["lift_verdict"] == "rust-only-lift-to-go-candidate"]
    go_only = [p for p in pairs if p["lift_verdict"] == "go-only-lift-to-rust-candidate"]

    manifest = {
        "schema": SCHEMA_MANIFEST, "generated_at_utc": utc_now(),
        "verification_tier": VERIFICATION_TIER,
        "inputs": {"rust_index": str(args.rust_index), "rust_route": str(args.rust_route),
                   "go_jsonl": str(args.go_jsonl)},
        "counts": {"rust_findings": len(rust_rows), "go_findings": len(go_rows),
                   "total_findings": len(rust_rows) + len(go_rows), "attack_classes": len(pairs),
                   "bidirectional_analogues": len(bidir),
                   "rust_only_lift_candidates": len(rust_only),
                   "go_only_lift_candidates": len(go_only)},
        "rust_class_distribution": dict(Counter(r["primary_attack_class"] for r in rust_rows)),
        "go_class_distribution": dict(Counter(g["primary_attack_class"] for g in go_rows)),
        "bidirectional_classes": [p["attack_class"] for p in bidir],
        "rust_only_classes": [p["attack_class"] for p in rust_only],
        "go_only_classes": [p["attack_class"] for p in go_only],
        "artifacts": [str(norm_path), str(pairs_path)],
    }
    manifest["content_hash"] = stable_hash(manifest["counts"])
    manifest_path = args.out_dir / "swivel_cross_lang_mine.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        c = manifest["counts"]
        print(f"swivel cross-lang mine: rust={c['rust_findings']} go={c['go_findings']} "
              f"classes={c['attack_classes']} bidir={c['bidirectional_analogues']} "
              f"rust_only={c['rust_only_lift_candidates']} go_only={c['go_only_lift_candidates']}")
        print(f"  -> {norm_path}")
        print(f"  -> {pairs_path}")
        print(f"  -> {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
