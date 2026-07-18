"""
storage-migration-skips-canonical-mutator — generated from reference/patterns.dsl/storage-migration-skips-canonical-mutator.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py storage-migration-skips-canonical-mutator.yaml
Source: auditooor-R68-kiln-vSuite-H3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StorageMigrationSkipsCanonicalMutator(AbstractDetector):
    ARGUMENT = "storage-migration-skips-canonical-mutator"
    HELP = "Migration function writes directly to storage slots / struct members without calling the canonical per-item mutator. If the mutator is the only place paired counters (funded totals, registry sizes, bitmap tallies) are updated, the migration silently under-counts and downstream functions diverge."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/storage-migration-skips-canonical-mutator.yaml"
    WIKI_TITLE = "Storage migration bypasses canonical mutator, leaving paired counters stale"
    WIKI_DESCRIPTION = "A `migrate` / `bulkImport` / `seed` entry point inserts legacy records into new storage layout by assigning storage slots directly (`.value[key] = ...`, `getSlot().value[...] = ...`). The protocol's normal ingestion path (a `deposit` / `addEntry` / `register` function) does the same write PLUS updates one or more paired counters (e.g., `$fundedValidators`, `totalSupply`, `registrySize`, bitmap fla"
    WIKI_EXPLOIT_SCENARIO = "A factory contract's V2 storage layout adds a `$fundedValidators` counter per withdrawal channel. The V2 code has a `depositFromRoot(...)` ingestion function that both inserts into the `$validators` mapping and increments `$fundedValidators++`. The storage-migration script copies V1 validators into V2 storage by writing the `$validators` mapping directly, skipping `depositFromRoot`. Post-migration"
    WIKI_RECOMMENDATION = "Prefer calling the canonical mutator inside the migration loop. If direct-slot writes are unavoidable for gas reasons, enumerate every paired counter / registry / bitmap update the mutator performs and replicate ALL of them inside the migration. Add a post-migration invariant test that asserts: `exp"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'migrate|migration|bulkImport|bulkMigrate|seed|importFromV1|importLegacy|upgradeFromV1'}, {'function.body_contains_regex': '\\.value\\s*\\[[^\\]]+\\]\\s*=|Slot\\s+storage\\s+[a-zA-Z_]+\\s*=\\s*[a-zA-Z_]+Storage(Lib)?\\.get'}, {'function.body_not_contains_regex': '(depositFromRoot|addEntry|pushItem|_record[A-Z]|_register[A-Z]|_addTo[A-Z]|_pushTo[A-Z])\\s*\\('}, {'function.body_not_contains_regex': '(total[A-Z][a-zA-Z]*|\\$[a-zA-Z]+Count|\\$funded[A-Z][a-zA-Z]*)\\s*(\\+=|\\s+=\\s+[a-zA-Z_.]+\\s*\\+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — storage-migration-skips-canonical-mutator: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
