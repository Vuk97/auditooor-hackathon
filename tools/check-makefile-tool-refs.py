#!/usr/bin/env python3
"""Validate that Makefile references to tools/*.py and tools/*.sh exist."""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MAKEFILE = REPO / "Makefile"

TOOL_REF = re.compile(
    r"(?:python3|bash|\./)\s+"
    r"(?P<path>tools/[A-Za-z0-9_./-]+\.(?:py|sh))"
)


def main() -> int:
    text = MAKEFILE.read_text()
    refs = sorted({m.group("path") for m in TOOL_REF.finditer(text)})
    missing = [p for p in refs if not (REPO / p).exists()]

    if missing:
        print("[tool-refs] FAIL")
        print("Missing Makefile tool references:")
        for path in missing:
            print(f"  - {path}")
        return 1

    print(f"[tool-refs] OK - {len(refs)} Makefile tool refs exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
