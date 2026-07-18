#!/usr/bin/env python3
# r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY registered in .auditooor/agent_pathspec.json
"""LIFT-28 corpus enrichment driver.

Reads `audit/corpus_tags/derived/hacker_questions_library.jsonl` and
`audit/corpus_tags/derived/global_chain_templates.jsonl`, applies the
deterministic LIFT-28 enrichment from `tools/lib/per_function_target_patterns.py`,
and writes the enriched corpora back atomically (R67) with backup-first
discipline.

Schema additions (ADDITIVE, backward-compat):

- hacker_questions: target_function_patterns, target_function_roles,
  target_contract_patterns, target_modifier_patterns, scope_specificity.

- global_chain_templates: applicable_contract_kinds,
  applicable_function_role_patterns, min_member_invariants_matching.

Usage:
    python3 tools/lift28-enrich-corpora.py [--dry-run]
    python3 tools/lift28-enrich-corpora.py --hacker-questions-only
    python3 tools/lift28-enrich-corpora.py --templates-only

Idempotent: re-running on already-enriched records produces no diff in
the derived fields (deterministic auto-derivation from grep_patterns +
member_invariant_ids).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"failed to load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute enrichment but do not write back.")
    parser.add_argument("--hacker-questions-only", action="store_true")
    parser.add_argument("--templates-only", action="store_true")
    parser.add_argument("--hacker-questions-path", default=str(
        REPO / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"))
    parser.add_argument("--templates-path", default=str(
        REPO / "audit" / "corpus_tags" / "derived" / "global_chain_templates.jsonl"))
    parser.add_argument("--no-backup", action="store_true",
                        help="Skip backup-first (R67 enforces backup; disable only for tests).")
    args = parser.parse_args()

    enricher = _load("per_function_target_patterns",
                     REPO / "tools" / "lib" / "per_function_target_patterns.py")
    atomic = _load("atomic_corpus_writer",
                   REPO / "tools" / "lib" / "atomic_corpus_writer.py")

    summary = {"hacker_questions": {}, "templates": {}}

    if not args.templates_only:
        hq_path = Path(args.hacker_questions_path)
        if not hq_path.is_file():
            print(f"[lift28] hacker_questions path missing: {hq_path}", file=sys.stderr)
        else:
            enriched_lines: list[str] = []
            n_in = 0
            n_with_new_fields_already = 0
            for raw in hq_path.read_text(encoding="utf-8").splitlines():
                raw = raw.rstrip()
                if not raw:
                    continue
                n_in += 1
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    enriched_lines.append(raw)  # preserve unparseable lines
                    continue
                if not isinstance(rec, dict):
                    enriched_lines.append(raw)
                    continue
                if "target_function_patterns" in rec and "scope_specificity" in rec:
                    n_with_new_fields_already += 1
                enriched = enricher.enrich_hacker_question_record(rec)
                enriched_lines.append(json.dumps(enriched, sort_keys=True))
            new_content = "\n".join(enriched_lines) + "\n"
            summary["hacker_questions"] = {
                "path": str(hq_path),
                "records_in": n_in,
                "records_out": len(enriched_lines),
                "records_previously_enriched": n_with_new_fields_already,
                "bytes_out": len(new_content.encode("utf-8")),
            }
            if not args.dry_run:
                result = atomic.atomic_write_corpus_file(
                    hq_path,
                    new_content,
                    sha256_check=True,
                    backup_first=not args.no_backup,
                )
                summary["hacker_questions"]["atomic_write"] = result

    if not args.hacker_questions_only:
        tpl_path = Path(args.templates_path)
        if not tpl_path.is_file():
            print(f"[lift28] templates path missing: {tpl_path}", file=sys.stderr)
        else:
            enriched_lines2: list[str] = []
            n_in2 = 0
            n_with_new_fields_already2 = 0
            for raw in tpl_path.read_text(encoding="utf-8").splitlines():
                raw = raw.rstrip()
                if not raw:
                    continue
                n_in2 += 1
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    enriched_lines2.append(raw)
                    continue
                if not isinstance(rec, dict):
                    enriched_lines2.append(raw)
                    continue
                if "applicable_contract_kinds" in rec and "min_member_invariants_matching" in rec:
                    n_with_new_fields_already2 += 1
                enriched = enricher.enrich_global_chain_template_record(rec)
                enriched_lines2.append(json.dumps(enriched, sort_keys=True))
            new_content2 = "\n".join(enriched_lines2) + "\n"
            summary["templates"] = {
                "path": str(tpl_path),
                "records_in": n_in2,
                "records_out": len(enriched_lines2),
                "records_previously_enriched": n_with_new_fields_already2,
                "bytes_out": len(new_content2.encode("utf-8")),
            }
            if not args.dry_run:
                result2 = atomic.atomic_write_corpus_file(
                    tpl_path,
                    new_content2,
                    sha256_check=True,
                    backup_first=not args.no_backup,
                )
                summary["templates"]["atomic_write"] = result2

    summary["dry_run"] = bool(args.dry_run)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
