"""gnark_wave1 — regex-based detectors for gnark circuits.

Wave-7 Track K-zkBugs minor frameworks. Targets gnark (Consensys's Go
ZK library, https://github.com/Consensys/gnark). Each detector is
regex-only by design and scans Go sources that import gnark packages.

Grounded in the 13-entry corpus: 12 findings from
`reference/findings_go_existing_corpus.jsonl` (gnark-zksecurity-00..0b)
plus 1 additional from the 139-bug zkBugs index.

Key corpus entries matched by these detectors:
  - gnark-zksecurity-0b: element_constructor_does_not_enforce_limb_widths
    -> `gnark_emulated_field_overflow`
  - gnark-zksecurity-09: naf_decomposition_missing_no_adjacent_nonzero_constraint
    -> `gnark_naf_decomposition_missing_constraint`
  - gnark-zksecurity-0a: padding_oracle_collision_via_zero_filled_last_block
    -> (covered as contextual note in naf detector; separate from overflow)

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "gnark_emulated_field_overflow",
    "gnark_naf_decomposition_missing_constraint",
]
