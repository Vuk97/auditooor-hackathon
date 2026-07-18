"""hunt_sidecar_schema.py - the ONE canonical parser for a hunt-verdict sidecar.

WHY THIS EXISTS (24h retrospective, 2026-07-06): the SAME serving-join bug - a gate
reader hand-rolling a private field vocabulary and assuming ONE sidecar shape, so it
goes blind to the others - landed at least THREE separate times in a single day:

  * unhunted-surface-adjudicate.py  - blind to top-level ``file_line`` (2599/4935 orphaned)
  * hunt-run-health-check.py        - blind to the native flat mechanism-verdict schema
                                      (3305/4949 records misfiled "empty" -> false hunt-trust)
  * function-coverage-completeness.py - _parse_nested_sidecar_result dropped the flat schema

Every future gate that reads a sidecar is one hand-rolled parser away from re-introducing
the family. This module is the single source of truth: every reader imports
``normalize_sidecar_record`` / ``unit_key`` / ``is_engaged`` / ``is_terminal`` instead of
poking at fields itself. A schema change is edited in EXACTLY this file, and
``test_no_handrolled_sidecar_parser.py`` fails any tool that json.loads a
hunt_findings_sidecars record without importing this module.

THE THREE SCHEMAS IN THE WILD (all accepted here):
  (a) native FLAT top-level (SEI per-fn / agent_mechanism_verdicts):
        {"unit","file","function","lines","verdict","applies_to_target","cited_excerpt"}
      -- NO nested ``result`` wrapper.
  (b) nested-result (spawn-worker Sonnet residual / MIMO scoped-hunt):
        {"status","function_anchor":{"file","fn"},"result": <dict OR JSON-string>{
           "applies_to_target","file_line","code_excerpt", ...}}
  (c) file_line variant (mega / workflow-drill per-fn):
        {"file_line":"foo.go:53","code_excerpt":..., "verdict":...}

R80 (anti-coverage-theater) is PRESERVED: the normalizer EXPOSES the fields, but
``credit_ok`` (the flag consumers use to grant real-attack / terminal-clean credit) is
True only when a resolved source cite (cited_excerpt / code_excerpt) backs the verdict.
A bare-prose "no" with no excerpt parses fine but ``credit_ok`` is False - it stays hollow.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# Verdict tokens. A "clean" verdict = the function was examined and ruled out.
# A "finding" verdict = a real positive. Anything else is unknown (not terminal).
_CLEAN_VERDICTS = {
    "negative", "no-finding", "no finding", "clean", "ruled-out", "ruled out",
    "false-positive", "false positive", "fp-defended", "no-exploit", "safe", "declined",
}
_FINDING_VERDICTS = {
    "positive", "confirmed", "true-positive", "true positive", "exploitable",
    "vulnerable", "affected", "finding",
}
# Dispositions that DROP a hypothesis by reasoning without a driven result - these
# must never be credited even if they carry a cite (mirrors the R80 discard rule).
_DISCARD_RE = re.compile(r"\b(drop(ped)?|discard(ed)?|withdrawn|retracted)\b", re.IGNORECASE)
_FILE_LINE_RE = re.compile(r"[\w./-]+\.\w+:L?\d+")


def _norm(s) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()


def _basename(path: str) -> str:
    p = _norm(path).replace("\\", "/")
    if not p:
        return ""
    return PurePosixPath(p.split(":", 1)[0]).name if "/" in p or "." in p else p


@dataclass
class NormalizedVerdict:
    """A schema-agnostic view of one hunt-verdict sidecar."""
    file: str = ""
    function: str = ""
    lines: str = ""
    verdict: str = ""            # normalized lower-case token
    applies_to_target: str = ""  # "yes" | "no" | ""
    cited_excerpt: str = ""
    file_line: str = ""          # "<basename>:<line>" (present or derived)
    status: str = ""             # outer task status ("ok"/"failed"/...)
    source_schema: str = "unknown"  # flat | nested-dict | nested-jsonstr | file_line | unknown
    is_flat: bool = False
    is_nested: bool = False
    _raw_blob: str = field(default="", repr=False)

    # ---- unit identity -------------------------------------------------
    @property
    def unit_key(self) -> str | None:
        """Stable <basename(file)>::<function> key, or None when unresolvable."""
        b = _basename(self.file)
        fn = _norm(self.function).split("(")[0]
        return f"{b}::{fn}" if b else None

    # ---- classification (schema-agnostic) ------------------------------
    @property
    def is_finding(self) -> bool:
        return self.verdict in _FINDING_VERDICTS or self.applies_to_target == "yes"

    @property
    def is_clean(self) -> bool:
        return self.verdict in _CLEAN_VERDICTS or self.applies_to_target == "no"

    @property
    def _has_real_cite(self) -> bool:
        # R80: CREDIT requires a VERBATIM source excerpt (proof the code was read).
        # A file_line alone does NOT count - especially the one this module derives
        # from the subject's own file+lines, which would be a self-cite false-green
        # (the exact bug the fcc _parse_nested_sidecar false-green revert caught).
        return bool(_norm(self.cited_excerpt))

    @property
    def ran_ok(self) -> bool:
        return self.status.lower() in ("", "ok", "success", "done")

    @property
    def engaged(self) -> bool:
        """The model mechanically ENGAGED this function and returned a per-fn verdict
        (finding OR clean). True even without an excerpt - engagement != credit."""
        if not self.ran_ok:
            return False
        return bool((self.is_finding or self.is_clean) and (self.file or self.file_line))

    @property
    def terminal(self) -> bool:
        """Reached a terminal verdict (same as engaged for a per-fn hunt sidecar)."""
        return self.engaged

    @property
    def credit_ok(self) -> bool:
        """R80: grant real-attack / terminal-clean CREDIT only when a resolved source
        cite backs the verdict AND it is not a bare DROP/discard. A prose-only "no"
        with no excerpt parses but does NOT credit (stays hollow)."""
        if not self.engaged:
            return False
        if _DISCARD_RE.search(self._raw_blob) and not self.is_finding:
            return False
        return self._has_real_cite


def _inner_from_result(obj: dict):
    """Return (inner_dict, schema) for the nested-result shape, else (None, None)."""
    r = obj.get("result")
    if isinstance(r, dict):
        return r, "nested-dict"
    if isinstance(r, str) and r.strip():
        try:
            d = json.loads(r)
            if isinstance(d, dict):
                return d, "nested-jsonstr"
        except (json.JSONDecodeError, ValueError):
            return None, None
    return None, None


def normalize_sidecar_record(obj) -> NormalizedVerdict | None:
    """Parse ANY of the three hunt-verdict sidecar schemas into a NormalizedVerdict.
    Returns None only for a genuinely-unparseable / non-dict record."""
    if not isinstance(obj, dict):
        return None
    nv = NormalizedVerdict(_raw_blob=json.dumps(obj)[:4000])
    nv.status = _norm(obj.get("status"))

    inner, schema = _inner_from_result(obj)
    if inner is not None:
        nv.is_nested = True
        nv.source_schema = schema
        fa = inner.get("function_anchor") or obj.get("function_anchor") or {}
        if isinstance(fa, dict):
            nv.file = _norm(fa.get("file") or fa.get("file_path"))
            nv.function = _norm(fa.get("fn") or fa.get("function"))
        nv.applies_to_target = _norm(inner.get("applies_to_target")).lower()
        nv.file_line = _norm(inner.get("file_line") or inner.get("defending_lines"))
        nv.cited_excerpt = _norm(inner.get("code_excerpt") or inner.get("cited_excerpt")
                                 or inner.get("excerpt"))
        nv.verdict = _norm(inner.get("verdict") or obj.get("verdict")).lower()
        if not nv.file:
            nv.file = _norm(obj.get("file") or obj.get("file_path"))
        if not nv.function:
            nv.function = _norm(obj.get("function") or obj.get("unit"))
    else:
        # Flat / file_line schema: fields live at the TOP LEVEL, no result wrapper.
        # (Also the fall-through for a nested record whose result is null/failed - its
        # function_anchor still identifies the subject so the unit is not lost.)
        nv.is_flat = True
        fa = obj.get("function_anchor")
        _fa_file = _fa_fn = ""
        if isinstance(fa, dict):
            _fa_file = _norm(fa.get("file") or fa.get("file_path"))
            _fa_fn = _norm(fa.get("fn") or fa.get("function"))
        nv.file = _norm(obj.get("file") or obj.get("file_path")) or _fa_file
        nv.function = _norm(obj.get("function") or obj.get("fn") or obj.get("unit")) or _fa_fn
        nv.lines = _norm(obj.get("lines") or obj.get("line"))
        nv.verdict = _norm(obj.get("verdict") or obj.get("disposition")).lower()
        nv.applies_to_target = _norm(obj.get("applies_to_target")).lower()
        nv.cited_excerpt = _norm(obj.get("cited_excerpt") or obj.get("code_excerpt")
                                 or obj.get("excerpt"))
        nv.file_line = _norm(obj.get("file_line"))
        nv.source_schema = "file_line" if nv.file_line and not nv.file else "flat"

    # Derive file_line from file+lines when absent (never fabricates a DEFENDING
    # cite - callers gate credit on cited_excerpt via credit_ok).
    if not nv.file_line and nv.file and nv.lines:
        nv.file_line = f"{_basename(nv.file)}:{_norm(nv.lines).split('-')[0].strip()}"
    # Recover file (and lines) from a file_line-only record so the unit key resolves.
    if not nv.file and nv.file_line:
        m = _FILE_LINE_RE.search(nv.file_line)
        if m:
            _fl = m.group(0)
            nv.file = _fl.rsplit(":", 1)[0]
            if not nv.lines:
                nv.lines = _fl.rsplit(":", 1)[1].lstrip("L")
    # Map a bare verdict to applies_to_target when that field is absent.
    if not nv.applies_to_target and nv.verdict:
        if nv.verdict in _CLEAN_VERDICTS:
            nv.applies_to_target = "no"
        elif nv.verdict in _FINDING_VERDICTS:
            nv.applies_to_target = "yes"
    if not (nv.file or nv.function or nv.verdict or nv.applies_to_target):
        return None
    return nv


# ---- convenience wrappers (what consuming readers import) --------------
def unit_key(obj) -> str | None:
    nv = obj if isinstance(obj, NormalizedVerdict) else normalize_sidecar_record(obj)
    return nv.unit_key if nv else None


def is_engaged(obj) -> bool:
    nv = obj if isinstance(obj, NormalizedVerdict) else normalize_sidecar_record(obj)
    return bool(nv and nv.engaged)


def is_terminal(obj) -> bool:
    nv = obj if isinstance(obj, NormalizedVerdict) else normalize_sidecar_record(obj)
    return bool(nv and nv.terminal)


def credit_ok(obj) -> bool:
    nv = obj if isinstance(obj, NormalizedVerdict) else normalize_sidecar_record(obj)
    return bool(nv and nv.credit_ok)
