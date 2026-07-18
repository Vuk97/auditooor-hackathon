#!/usr/bin/env python3
"""
cross-lang-detector-map-check.py

Validator and query tool for reference/cross_lang_detector_map.yaml.

Usage:
    python3 tools/cross-lang-detector-map-check.py --validate
    python3 tools/cross-lang-detector-map-check.py --query <bug_class>
    python3 tools/cross-lang-detector-map-check.py --query-by-detector <detector_id>

--validate:
    Loads the YAML; for each mapping entry, verifies that every cited
    detector ID resolves to a real file on disk:
      - rust_wave1.<name>  -> detectors/rust_wave1/<name>.py
      - rust_wave2.<name>  -> detectors/rust_wave2/<name>.py
      - go_wave1.<name>    -> detectors/go_wave1/<name>.py
      - go_ast.<name>      -> tools/detectors/go_ast_<name>.py
    IDs marked "planned" in comments are skipped if the file is absent;
    IDs without a "(planned)" annotation cause a validation failure.
    Exits 0 if all present-IDs resolve, 1 otherwise.

--query <bug_class>:
    Print the full mapping entry for the given bug_class.

--query-by-detector <detector_id>:
    Print all mapping entries that cite <detector_id>.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = REPO_ROOT / "reference" / "cross_lang_detector_map.yaml"

# How to resolve detector IDs to file paths
# Format: (prefix, base_dir, suffix_template)
# suffix_template uses {name} for the name part after the prefix dot
_RESOLVER_MAP: list[tuple[str, Path, str]] = [
    ("rust_wave1.", REPO_ROOT / "detectors" / "rust_wave1", "{name}.py"),
    ("rust_wave2.", REPO_ROOT / "detectors" / "rust_wave2", "{name}.py"),
    ("go_wave1.",   REPO_ROOT / "detectors" / "go_wave1",   "{name}.py"),
    ("go_ast.",     REPO_ROOT / "tools" / "detectors",      "go_ast_{name}.py"),
]


def _resolve_detector(detector_id: str) -> tuple[Path, bool]:
    """
    Return (resolved_path, is_planned).
    is_planned = True if the ID has a comment marking it as planned.
    Note: this function only gets the canonical path; it does NOT check existence.
    """
    for prefix, base_dir, tmpl in _RESOLVER_MAP:
        if detector_id.startswith(prefix):
            name = detector_id[len(prefix):]
            return base_dir / tmpl.format(name=name), False
    # Unknown prefix — return a dummy path, mark as unresolvable
    return REPO_ROOT / "_unknown_" / detector_id, False


def _load_map() -> tuple[dict, str]:
    """Return (parsed_data, raw_text)."""
    if not MAP_PATH.exists():
        print(f"ERROR: map not found: {MAP_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(MAP_PATH, encoding="utf-8") as fh:
        raw = fh.read()
    return yaml.safe_load(raw), raw


def _is_planned_in_raw(det_id: str, raw_yaml: str) -> bool:
    """Check if a detector ID appears with a `# planned` comment in raw YAML text."""
    # Look for `- <det_id>   # planned` pattern
    pattern = re.compile(
        r"-\s+" + re.escape(det_id) + r"[^\n]*#[^\n]*\bplanned\b",
        re.IGNORECASE,
    )
    return bool(pattern.search(raw_yaml))


def _get_mappings(data: dict) -> list[dict]:
    mappings = data.get("mappings", [])
    if not isinstance(mappings, list):
        print("ERROR: 'mappings' is not a list in YAML", file=sys.stderr)
        sys.exit(2)
    return mappings


def cmd_validate(args) -> int:
    data, raw_yaml = _load_map()
    mappings = _get_mappings(data)

    errors: list[str] = []
    warnings: list[str] = []
    ok_count = 0
    skip_count = 0

    for entry in mappings:
        bug_class = entry.get("bug_class", "<unnamed>")
        all_ids: list[str] = (
            entry.get("go", []) + entry.get("rust", [])
        )
        # Also check for entries in notes that declare IDs as planned
        notes = entry.get("notes", "")
        planned_re = re.compile(r"\(planned\)")
        is_all_planned = planned_re.search(notes) is not None

        for det_id in all_ids:
            # Strip inline comments like `  # planned`
            det_id_clean = re.sub(r"\s*#.*$", "", det_id).strip()
            if not det_id_clean:
                continue

            # Check if ID is marked as planned in raw YAML text
            # (trailing comment `# planned` on the same line)
            is_planned = _is_planned_in_raw(det_id_clean, raw_yaml)

            path, _ = _resolve_detector(det_id_clean)

            if path.exists():
                ok_count += 1
                print(f"  OK      {det_id_clean} -> {path.relative_to(REPO_ROOT)}")
            elif is_planned or is_all_planned:
                skip_count += 1
                warnings.append(f"  PLANNED {det_id_clean} (not on disk yet)")
                print(warnings[-1])
            else:
                # Check for unknown prefix
                if path.parent.name == "_unknown_":
                    errors.append(
                        f"  ERROR   {det_id_clean}: unknown detector prefix "
                        f"(no resolver rule for '{det_id_clean}')"
                    )
                else:
                    errors.append(
                        f"  MISSING {det_id_clean}: expected at "
                        f"{path.relative_to(REPO_ROOT)}"
                    )
                print(errors[-1])

    print()
    print(f"Validation summary: {ok_count} OK, {skip_count} planned, {len(errors)} errors")

    if errors:
        print("\nFAILED — missing detector(s):", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    print("PASS — all present detector IDs resolve to disk files.")
    return 0


def cmd_query(args) -> int:
    data, _ = _load_map()
    mappings = _get_mappings(data)

    target = args.bug_class.lower()
    found = [m for m in mappings if m.get("bug_class", "").lower() == target]

    if not found:
        print(f"No mapping found for bug_class: {args.bug_class}", file=sys.stderr)
        # Print available classes for discoverability
        available = sorted(m.get("bug_class", "") for m in mappings)
        print("Available bug classes:", file=sys.stderr)
        for bc in available:
            print(f"  {bc}", file=sys.stderr)
        return 1

    import json
    for entry in found:
        print(yaml.dump(entry, default_flow_style=False, allow_unicode=True))
    return 0


def cmd_query_by_detector(args) -> int:
    data, _ = _load_map()
    mappings = _get_mappings(data)

    target = args.detector_id.lower()
    found = []
    for entry in mappings:
        all_ids = entry.get("go", []) + entry.get("rust", [])
        for det_id in all_ids:
            det_id_clean = re.sub(r"\s*#.*$", "", det_id).strip()
            if det_id_clean.lower() == target or det_id_clean.lower().endswith(f".{target}"):
                found.append(entry)
                break

    if not found:
        print(f"No mapping found citing detector: {args.detector_id}", file=sys.stderr)
        return 1

    for entry in found:
        print(yaml.dump(entry, default_flow_style=False, allow_unicode=True))
    return 0


def main() -> int:
    argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    if "--validate" in argv:
        class _FakeArgs:
            pass
        return cmd_validate(_FakeArgs())

    if "--query-by-detector" in argv:
        idx = argv.index("--query-by-detector")
        if idx + 1 >= len(argv):
            print("ERROR: --query-by-detector requires an argument", file=sys.stderr)
            return 1
        class _FakeArgs:
            detector_id = argv[idx + 1]
        return cmd_query_by_detector(_FakeArgs())

    if "--query" in argv:
        idx = argv.index("--query")
        if idx + 1 >= len(argv):
            print("ERROR: --query requires an argument", file=sys.stderr)
            return 1
        class _FakeArgs:
            bug_class = argv[idx + 1]
        return cmd_query(_FakeArgs())

    print(f"Unknown arguments: {argv}", file=sys.stderr)
    print("Use --validate, --query <bug_class>, or --query-by-detector <id>",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
