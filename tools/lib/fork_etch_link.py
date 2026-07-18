#!/usr/bin/env python3
"""fork_etch_link.py - GENERIC offline library linker + clean/mutant deployed-
bytecode producer for fork+etch mutation-verified harnesses.

WHY THIS EXISTS (extracted from a PROVEN one-off recipe)
--------------------------------------------------------
The Beanstalk cross-function gate could only be closed by a FORK + ``vm.etch``
mutation-verified harness over the LIVE Diamond, because the in-scope facets
(a) read live Diamond storage that a from-scratch deploy cannot reconstruct and
(b) link external libraries by ``delegatecall``. The hard-won mechanics lived as
one-off python embedded in ``chimera_harnesses/XfnForkFeasibility/build_mutants.sh``
(all 5 tests pass: clean PASS -> mutant FAIL on the live arb fork). This module
EXTRACTS those mechanics into a reusable, unit-tested library so the same recipe
closes the cross-function gate for ANY Diamond / L2 workspace, not just bean.

The single hardest piece is the OFFLINE LINK: a recompiled facet's
``deployedBytecode.object`` carries ``__$<34hex>$__`` (40-char / 20-byte)
placeholders wherever it calls an external library. To etch the facet on a fork
those placeholders must be replaced (offline, no deploy) by 20-byte addresses at
which the libraries' own deployed bytecode is etched. ``vm.parseBytes`` also
REJECTS the unlinked hex (the ``$`` chars are non-hex), so linking is mandatory
before the bytecode can even be loaded by the test.

WHAT THIS MODULE DOES (pure, dependency-free, stdlib only)
----------------------------------------------------------
- ``link_bytecode(object_hex, link_references, lib_addrs)`` -> linked hex with
  NO ``__$`` residue. Validates each replacement is exactly 20 bytes and that
  every placeholder is resolved. This is the ONE piece the guard test pins.
- ``library_names(link_references)`` -> the set of external libs a facet links.
- ``assign_lib_addresses(lib_names, base)`` -> deterministic fixed addrs
  (``0x...a5110``, ``a5111``, ...) the test etches the libs at. Generic: derived
  from a base, not hardcoded per workspace.
- ``read_artifact_bytecode(artifact_path)`` -> (object_hex, link_references) from
  a forge build artifact JSON (``deployedBytecode.object`` +
  ``deployedBytecode.linkReferences``).
- ``link_artifact(...)`` / ``dump_library_bytecode(...)`` - convenience wrappers
  that read forge artifacts and emit ``0x``-prefixed linked hex strings ready to
  write to ``mutants/*.hex`` for ``vm.readFile`` + ``vm.parseBytes`` + ``vm.etch``.

This module performs NO compilation and NO network I/O. The build/mutate/restore
orchestration (running ``forge build --evm-version paris``, applying the one-line
mutation anchor, restoring the source) lives in the producer that imports this;
keeping the byte-surgery pure is what makes it unit-testable and false-green-proof.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Placeholder format emitted by solc/forge for an unresolved external library
# reference: "__$" + 34 hex chars + "$__" = 40 chars = 20 bytes.
_PLACEHOLDER_RE = re.compile(r"__\$[0-9a-fA-F]{34}\$__")

# 20 bytes -> 40 hex chars. Library reference width is always 20 bytes (an
# address) in EVM linkReferences.
ADDR_HEX_LEN = 40


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith(("0x", "0X")) else s


def _norm_addr_hex(addr) -> str:
    """Normalize an address (int or '0x..' / bare hex str) to a lowercase
    40-hex-char (20-byte) string, left-zero-padded. Raises ValueError if it does
    not fit in 20 bytes."""
    if isinstance(addr, int):
        h = f"{addr:040x}"
    else:
        h = _strip0x(str(addr)).lower()
        if not re.fullmatch(r"[0-9a-f]*", h):
            raise ValueError(f"non-hex library address: {addr!r}")
        h = h.rjust(ADDR_HEX_LEN, "0")
    if len(h) != ADDR_HEX_LEN:
        raise ValueError(
            f"library address must be 20 bytes (40 hex); got {len(h)} hex from {addr!r}"
        )
    return h


def library_names(link_references: dict) -> list[str]:
    """Return the sorted unique external-library names referenced by a
    ``linkReferences`` mapping (forge artifact shape: ``{file: {LibName: [refs]}}``)."""
    names: set[str] = set()
    for _file, libs in (link_references or {}).items():
        if isinstance(libs, dict):
            names.update(libs.keys())
    return sorted(names)


def assign_lib_addresses(lib_names, base: int = 0x000000000000000000000000000000000000A5110) -> dict:
    """Deterministically assign a fixed fork address to each library name.

    Generic (NOT workspace-specific): the first lib gets ``base`` (default
    ``0x...a5110``, the address family the proven bean harness uses), the next
    ``base+1``, etc. Returns ``{LibName: '0x<40hex>'}``. Sorted for determinism
    so the same facet always maps to the same lib addrs across runs.
    """
    out: dict = {}
    for i, name in enumerate(sorted(set(lib_names))):
        out[name] = "0x" + _norm_addr_hex(base + i)
    return out


def link_bytecode(object_hex: str, link_references: dict, lib_addrs: dict) -> str:
    """Offline-link a deployedBytecode object: replace each ``__$...$__``
    placeholder (located via ``linkReferences`` byte offsets) with the 20-byte
    address of the library it references.

    Parameters
    ----------
    object_hex : the ``deployedBytecode.object`` hex (with or without ``0x``).
    link_references : forge artifact ``deployedBytecode.linkReferences`` -
        ``{sourceFile: {LibName: [{"start": <byte>, "length": 20}, ...]}}``.
    lib_addrs : ``{LibName: <addr int|hex str>}`` covering EVERY referenced lib.

    Returns the linked hex (no ``0x`` prefix) with ZERO ``__$`` residue.

    Raises ValueError if a referenced library has no address, if a reference is
    not 20 bytes, or if any placeholder remains after linking (fail-closed:
    never emit half-linked bytecode that would silently misbehave when etched).
    """
    bc = _strip0x(object_hex)
    refs = link_references or {}
    needed = library_names(refs)
    missing = [n for n in needed if n not in lib_addrs]
    if missing:
        raise ValueError(f"no fork address provided for libraries: {missing}")

    # Replace from highest offset to lowest so earlier replacements never shift
    # later offsets (all replacements are equal width 20 bytes = 40 hex, so this
    # is belt-and-suspenders, but keeps the invariant explicit).
    flat: list[tuple[int, int, str]] = []  # (start_byte, length_byte, lib)
    for _file, libs in refs.items():
        if not isinstance(libs, dict):
            continue
        for lib, ref_list in libs.items():
            for r in ref_list:
                start = int(r["start"])
                length = int(r["length"])
                if length != 20:
                    raise ValueError(
                        f"library reference for {lib} is {length} bytes; expected 20"
                    )
                flat.append((start, length, lib))
    for start, length, lib in sorted(flat, key=lambda t: -t[0]):
        addr_hex = _norm_addr_hex(lib_addrs[lib])
        s = start * 2
        e = s + length * 2
        bc = bc[:s] + addr_hex + bc[e:]

    if _PLACEHOLDER_RE.search(bc):
        raise ValueError("unlinked __$...$__ placeholder remains after linking")
    if "__$" in bc:
        raise ValueError("residual __$ marker remains after linking")
    return bc


def read_artifact_bytecode(artifact_path) -> tuple[str, dict]:
    """Read ``(deployedBytecode.object, deployedBytecode.linkReferences)`` from a
    forge build artifact JSON."""
    d = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    db = d.get("deployedBytecode") or {}
    obj = db.get("object")
    if not isinstance(obj, str):
        raise ValueError(f"no deployedBytecode.object in {artifact_path}")
    return obj, db.get("linkReferences") or {}


def link_artifact(artifact_path, lib_addrs: dict) -> str:
    """Read a forge artifact and return its OFFLINE-LINKED deployedBytecode as a
    ``0x``-prefixed hex string ready for ``vm.parseBytes`` + ``vm.etch``."""
    obj, link_refs = read_artifact_bytecode(artifact_path)
    return "0x" + link_bytecode(obj, link_refs, lib_addrs)


def dump_library_bytecode(artifact_path) -> str:
    """Read a LIBRARY's forge artifact and return its ``deployedBytecode.object``
    as ``0x``-prefixed hex. A library that itself links to nothing has no
    placeholders; if it does link sub-libraries this raises (caller must link
    them first) - we assert no residue so a half-linked lib is never etched."""
    obj, link_refs = read_artifact_bytecode(artifact_path)
    bc = _strip0x(obj)
    if "__$" in bc:
        raise ValueError(
            f"library {Path(artifact_path).stem} has unlinked sub-library "
            f"placeholders; link those first (refs={library_names(link_refs)})"
        )
    return "0x" + bc
