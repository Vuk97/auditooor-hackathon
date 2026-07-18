#!/usr/bin/env python3
"""impact-mechanism-library-build - ETL that inverts the corpus impact playbooks
into the impact->mechanism library the completeness-matrix v2 mechanism axis reads.

Source of truth: audit/corpus_tags/impact_hunting_methodology.yaml (32 playbooks,
each with impact_id + applies_to_languages + critical_paths[].path - the corpus's
own mechanism descriptions). This writes audit/corpus_tags/impact_mechanism_library.json
which _load_mechanism_library() MERGES onto its curated seed, so the cell denominator
GROWS with the corpus (new post-mortems mined into the playbooks auto-expand it)
instead of a static hand list. Known mechanism slugs are wired to a real detector;
the rest carry detector=null (they surface as WARN worklist rows = the roadmap of
mechanisms still needing a detector).

Idempotent + deterministic (sorted); safe to run every corpus refresh.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_YAML = _HERE.parent / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
_OUT = _HERE.parent / "audit" / "corpus_tags" / "impact_mechanism_library.json"

_ALL_LANGS = ["solidity", "go", "rust", "move", "zk"]

# Known mechanism slug -> shipped detector module (else detector stays null = WARN).
_DETECTOR_FOR = {
    "consensus-hook-unbounded-iteration": "go_ast_consensus_hook_unbounded_iteration",
    "unbounded-loop": "sol_ast_unbounded_attacker_growable_iteration",
    "unbounded-iteration": "sol_ast_unbounded_attacker_growable_iteration",
    "block-hook": "go_ast_consensus_hook_unbounded_iteration",
    "missing-authority": "go_ast_msgserver_missing_authority_sibling_asymmetry",
    "access-control": "go_ast_msgserver_missing_authority_sibling_asymmetry",
    "cross-chain-domain": "xchain_message_domain_binding_check",
    "replay": "xchain_message_domain_binding_check",
}


def _slug(text: str) -> str:
    text = str(text).split(":", 1)[0].strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text[:60]


def _detector_for(slug: str) -> str | None:
    for key, det in _DETECTOR_FOR.items():
        if key in slug:
            return det
    return None


def build(yaml_path: Path = _YAML, max_mechs: int = 8) -> dict:
    try:
        import yaml  # optional dep
    except ImportError:
        return {}
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    lib: dict[str, list[dict]] = {}
    for pb in (data.get("playbooks") or []):
        impact = str(pb.get("impact_id") or "").strip()
        if not impact:
            continue
        langs = [l for l in (pb.get("applies_to_languages") or []) if l in _ALL_LANGS] or _ALL_LANGS
        mechs: dict[str, dict] = {}
        for cp in (pb.get("critical_paths") or []):
            txt = cp.get("path") if isinstance(cp, dict) else cp
            if not txt:
                continue
            slug = _slug(txt)
            if not slug or slug in mechs:
                continue
            mechs[slug] = {"mechanism": slug, "languages": sorted(langs),
                           "detector": _detector_for(slug), "source": "impact_hunting_methodology.yaml"}
            if len(mechs) >= max_mechs:
                break
        if mechs:
            lib[impact] = sorted(mechs.values(), key=lambda m: m["mechanism"])
    return lib


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(_OUT))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    lib = build()
    n_impacts = len(lib)
    n_mechs = sum(len(v) for v in lib.values())
    n_wired = sum(1 for v in lib.values() for m in v if m.get("detector"))
    if args.dry_run:
        print(json.dumps(lib, indent=2, sort_keys=True))
    else:
        Path(args.out).write_text(json.dumps(lib, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[impact-mechanism-library] wrote {args.out}: {n_impacts} impacts, "
              f"{n_mechs} mechanisms ({n_wired} detector-wired, {n_mechs - n_wired} WARN-roadmap)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
