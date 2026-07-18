#!/usr/bin/env python3
"""rust-scanner-ingest.py — Wave-5 Track K-Rust step 3.

Reads per-scanner outputs from a Rust audit pass and normalizes them into a
single unified findings JSON that the per-function mindset ranker can ingest
alongside ``rust_wave1`` detector hits.

Five scanner adapters are supported:

  clippy      ``<ws>/.audit_logs/rust_scan/clippy.log`` (JSONL, one
              ``compiler-message`` object per line, ``--message-format=json``
              output)
  cargo-audit ``<ws>/.audit_logs/rust_scan/cargo-audit.log`` (full JSON doc
              from ``cargo audit --json``)
  cargo-geiger``<ws>/.audit_logs/rust_scan/geiger.log`` (JSON doc from
              ``cargo geiger --output-format Json``)
  cargo-deny  ``<ws>/.audit_logs/rust_scan/cargo-deny.log`` (JSONL, one
              diagnostic object per line, from ``cargo deny check``)
  semgrep     ``<ws>/.audit_logs/rust_scan/semgrep.sarif`` (SARIF 2.1.0
              JSON from ``semgrep --sarif``)

Plus one internal source:

  rust_wave1  ``<ws>/.auditooor/rust_findings.json`` (output from
              ``tools/rust-detector-runner.py``)

Each finding is normalized to the unified schema and optionally enriched with
per-function metadata (crate_name, module_path, fn_signature, fn_name) using
the ``_util.py`` helpers from ``detectors/rust_wave1/`` when a tree-sitter
parse is available.  If tree-sitter is not installed the enrichment silently
degrades — the core ingest still succeeds.

Output:

  ``<ws>/.auditooor/rust_findings_unified.json`` — unified findings document

Unified finding schema (per-item)::

    {
      "detector_id": "<source>.<lint-or-id>",
      "source":      "<clippy|cargo-audit|cargo-geiger|cargo-deny|semgrep|rust_wave1>",
      "file":        "<relative-or-absolute path>",
      "line":        <int, 0 if advisory/not line-pinned>,
      "severity":    "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "message":     "<human-readable message>",
      -- optional fields present when available --
      "crate_name":  "<crate>",
      "module_path": "<crate::mod>",
      "fn_signature":"<pub async fn foo(...)>",
      "fn_name":     "<foo>",
      -- source-specific extra fields --
      "package":     "<crate-name>",   # cargo-audit only
      "unsafe_count":<int>,            # cargo-geiger only
    }

Severity mapping:

  clippy level  -> MEDIUM (warning), HIGH (error), INFO (note/help)
  cargo-audit   -> maps RUSTSEC advisory.severity: critical->CRITICAL,
                   high->HIGH, medium->MEDIUM, low->LOW, <none>->INFO
  cargo-geiger  -> always INFO (telemetry)
  cargo-deny    -> error->HIGH, warning->MEDIUM, note/help->INFO
  semgrep SARIF -> error->HIGH, warning->MEDIUM, note->LOW, none->INFO

Usage::

  python3 tools/rust-scanner-ingest.py --workspace <ws>

  python3 tools/rust-scanner-ingest.py \\
      --workspace <ws> \\
      --clippy-log /path/clippy.log \\
      --audit-log  /path/cargo-audit.log \\
      --geiger-log /path/geiger.log \\
      --deny-log   /path/cargo-deny.log \\
      --semgrep-sarif /path/semgrep.sarif \\
      --wave1-findings /path/rust_findings.json \\
      --out /path/rust_findings_unified.json

Stdlib-only.  No external deps beyond what auditooor already requires.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

# stdlib datetime.UTC is available from Python 3.11+; fall back for 3.10.
_UTC = datetime.timezone.utc

# ---------------------------------------------------------------------------
# Severity normalisation helpers
# ---------------------------------------------------------------------------

_CLIPPY_LEVEL_MAP: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "INFO",
    "help": "INFO",
    "failure-note": "INFO",
}

_AUDIT_SEV_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

_DENY_LEVEL_MAP: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "INFO",
    "help": "INFO",
}

_SARIF_LEVEL_MAP: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

# Coerce wave1 detector-level strings (may already be UPPERCASE or lower).
_WAVE1_SEV_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


def _norm_sev_wave1(raw: str) -> str:
    return _WAVE1_SEV_MAP.get(raw.lower(), raw.upper())


# ---------------------------------------------------------------------------
# Clippy adapter
# ---------------------------------------------------------------------------
# ``cargo clippy --message-format=json`` emits one JSON object per line
# (JSON-Lines / JSONL).  Only ``"reason": "compiler-message"`` lines carry
# diagnostics; ``"build-finished"`` etc. are silently skipped.
#
# Clippy JSON structure (abbreviated):
#   {
#     "reason": "compiler-message",
#     "message": {
#       "level": "warning",
#       "message": "<text>",
#       "code": {"code": "clippy::unwrap_used"},
#       "spans": [
#         {
#           "file_name": "src/lib.rs",
#           "line_start": 10,
#           "is_primary": true
#         }
#       ]
#     }
#   }
#
# Older rustc/clippy versions (pre-1.49) use a slightly different shape where
# ``code`` may be null.  We handle both by falling back gracefully.
#
# The log file produced by rust-scan.sh APPENDS multiple run blocks; each
# block may contain non-JSON header lines (``### rust-scan run @``).  We skip
# non-JSON lines silently.

def _parse_clippy(log_path: Path) -> list[dict]:
    findings: list[dict] = []
    text = log_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("reason") != "compiler-message":
            continue
        msg = obj.get("message")
        if not msg or not isinstance(msg, dict):
            continue

        level = msg.get("level", "note")
        severity = _CLIPPY_LEVEL_MAP.get(level, "INFO")
        message_text = msg.get("message", "")

        code_obj = msg.get("code") or {}
        lint_code = code_obj.get("code", "") if isinstance(code_obj, dict) else ""
        # Normalize: "clippy::unwrap_used" -> "unwrap_used"; keep others as-is
        if lint_code.startswith("clippy::"):
            lint_name = lint_code[len("clippy::"):]
        elif lint_code:
            lint_name = lint_code
        else:
            # Derive a slug from the message text as fallback
            lint_name = re.sub(r"[^a-z0-9_]", "_", message_text[:40].lower()).strip("_") or "unknown"

        detector_id = f"clippy.{lint_name}"

        # Find the primary span for file/line.
        file_name = ""
        line_no = 0
        spans = msg.get("spans", [])
        for span in spans:
            if span.get("is_primary"):
                file_name = span.get("file_name", "")
                line_no = span.get("line_start", 0)
                break
        # Fallback: first span if no primary flagged
        if not file_name and spans:
            file_name = spans[0].get("file_name", "")
            line_no = spans[0].get("line_start", 0)

        finding: dict[str, Any] = {
            "detector_id": detector_id,
            "source": "clippy",
            "file": file_name,
            "line": line_no,
            "severity": severity,
            "message": message_text,
        }
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# cargo-audit adapter
# ---------------------------------------------------------------------------
# ``cargo audit --json`` emits a single JSON document (not JSONL).  The
# document may be preceded by cargo chatter lines (progress indicators) when
# run via rust-scan.sh; we look for the first ``{`` on a line and parse from
# there.
#
# Relevant structure:
#   {
#     "vulnerabilities": {
#       "list": [
#         {
#           "advisory": {
#             "id": "RUSTSEC-2023-0001",
#             "package": "old-crate",
#             "title": "...",
#             "description": "...",
#             "severity": "critical",
#             ...
#           },
#           "package": {
#             "name": "old-crate",
#             "version": "1.0.5",
#             ...
#           }
#         }
#       ]
#     }
#   }
#
# Some older versions of cargo-audit use ``"vulnerabilities"`` as a list at
# the top level instead of an object with a ``"list"`` key.  We handle both.

def _parse_cargo_audit(log_path: Path) -> list[dict]:
    findings: list[dict] = []
    text = log_path.read_text(encoding="utf-8", errors="replace")

    # Skip cargo chatter lines and find the JSON start
    doc = None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads("\n".join(lines[i:]))
                break
            except json.JSONDecodeError:
                pass
    if doc is None:
        # Try the whole text as-is
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return findings

    # Extract vulnerability list
    vulns_section = doc.get("vulnerabilities", {})
    if isinstance(vulns_section, list):
        vuln_list = vulns_section
    elif isinstance(vulns_section, dict):
        vuln_list = vulns_section.get("list", [])
    else:
        vuln_list = []

    for vuln in vuln_list:
        advisory = vuln.get("advisory", {})
        pkg_info = vuln.get("package", {})

        rustsec_id = advisory.get("id", "UNKNOWN")
        package_name = advisory.get("package", "") or pkg_info.get("name", "")
        description = advisory.get("description", advisory.get("title", ""))
        sev_raw = advisory.get("severity", "")
        severity = _AUDIT_SEV_MAP.get(sev_raw.lower() if sev_raw else "", "INFO")

        # Locate the Cargo.toml for this package: we can't know the exact path
        # without workspace inspection, so we use a placeholder.
        file_path = "Cargo.lock"

        finding: dict[str, Any] = {
            "detector_id": f"cargo-audit.{rustsec_id}",
            "source": "cargo-audit",
            "file": file_path,
            "line": 0,
            "severity": severity,
            "message": f"[{rustsec_id}] {package_name}: {description}",
            "package": package_name,
        }
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# cargo-geiger adapter
# ---------------------------------------------------------------------------
# ``cargo geiger --output-format Json`` produces a JSON document with a
# ``packages`` list.  Each entry has an ``unsafety`` block with ``used`` and
# ``unused`` sub-objects that each contain ``functions``, ``exprs``,
# ``item_impls``, ``item_traits``, ``methods`` — each a dict with ``safe``
# and ``unsafe_`` counts.
#
# We emit one finding per package that has any non-zero unsafe count.
#
# The log file may contain cargo chatter before the JSON (similar to audit).
# Additionally, ``cargo geiger`` sometimes interleaves per-crate table output
# with the JSON on stdout; we look for the first ``{`` and parse from there.

def _parse_cargo_geiger(log_path: Path) -> list[dict]:
    findings: list[dict] = []
    text = log_path.read_text(encoding="utf-8", errors="replace")

    doc = None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads("\n".join(lines[i:]))
                break
            except json.JSONDecodeError:
                pass
    if doc is None:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return findings

    packages = doc.get("packages", [])
    for pkg in packages:
        pkg_id = pkg.get("id", {})
        crate_name = pkg_id.get("name", "unknown") if isinstance(pkg_id, dict) else "unknown"

        unsafety = pkg.get("unsafety", {})
        used = unsafety.get("used", {})

        # Sum across all sub-categories
        unsafe_count = 0
        for category in ("functions", "exprs", "item_impls", "item_traits", "methods"):
            cat = used.get(category, {})
            if isinstance(cat, dict):
                unsafe_count += cat.get("unsafe_", 0)

        if unsafe_count == 0:
            continue

        finding: dict[str, Any] = {
            "detector_id": "cargo-geiger.unsafe-region",
            "source": "cargo-geiger",
            "file": f"{crate_name}/Cargo.toml",
            "line": 0,
            "severity": "INFO",
            "message": (
                f"Crate '{crate_name}' contains {unsafe_count} unsafe item(s) "
                f"(functions+exprs+impls+traits+methods, used only)"
            ),
            "crate_name": crate_name,
            "unsafe_count": unsafe_count,
        }
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# cargo-deny adapter
# ---------------------------------------------------------------------------
# ``cargo deny check`` with ``--log-level warn`` produces JSONL (one JSON
# object per line) when passed ``--format json`` OR plain-text.  The
# rust-scan.sh wrapper does NOT pass ``--format json`` — it captures the
# default output.  However, the Wave-5 spec targets a JSON JSONL shape from
# ``cargo deny``.
#
# We therefore attempt JSON-Lines parsing first; if the file has no JSON
# objects we fall back to a regex parse of the plain-text format.
#
# JSON shape (cargo-deny >=0.14 with --format json):
#   {"type":"diagnostic","fields":{"severity":"error","message":"...","code":{"code":"B003"},"graphs":{...},"labels":[{"message":"...","span":{"path":"/ws/Cargo.toml","line":{"start":12,"end":13}}}],"help":"...","url":"..."}}
#
# Plain-text shape (older / no --format):
#   error[B003]: found 1 banned crate
#     --> Cargo.toml:12
#
# We produce one finding per diagnostic.

def _parse_cargo_deny(log_path: Path) -> list[dict]:
    findings: list[dict] = []
    text = log_path.read_text(encoding="utf-8", errors="replace")

    # Attempt JSON-Lines parse first
    json_count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        json_count += 1

        # Unwrap fields — support {"type":"diagnostic","fields":{...}} shape
        # as well as flat {"severity":...} shape.
        if obj.get("type") == "diagnostic":
            fields = obj.get("fields", obj)
        else:
            fields = obj

        severity_raw = fields.get("severity", "note")
        severity = _DENY_LEVEL_MAP.get(severity_raw.lower(), "INFO")
        message_text = fields.get("message", str(fields))

        # Extract code (violation type)
        code_obj = fields.get("code", {}) or {}
        code_val = code_obj.get("code", "") if isinstance(code_obj, dict) else str(code_obj)

        # Extract file path from labels[0].span.path
        file_path = "Cargo.toml"
        line_no = 0
        labels = fields.get("labels", [])
        if labels and isinstance(labels, list):
            span = labels[0].get("span", {}) or {}
            if isinstance(span, dict):
                file_path = span.get("path", "Cargo.toml")
                line_info = span.get("line", {}) or {}
                if isinstance(line_info, dict):
                    line_no = line_info.get("start", 0)
                elif isinstance(line_info, int):
                    line_no = line_info

        # Derive violation type from code or message
        if code_val:
            deny_type = code_val.lower()
        elif "license" in message_text.lower():
            deny_type = "licenses"
        elif "ban" in message_text.lower() or "B0" in message_text:
            deny_type = "bans"
        else:
            deny_type = "advisories"

        finding: dict[str, Any] = {
            "detector_id": f"cargo-deny.{deny_type}",
            "source": "cargo-deny",
            "file": file_path,
            "line": line_no,
            "severity": severity,
            "message": message_text,
        }
        findings.append(finding)

    if json_count > 0:
        return findings

    # Fallback: plain-text regex parse
    # Matches: error[B003]: message text
    #            --> Cargo.toml:12
    error_re = re.compile(
        r"^(error|warning|note)\[([^\]]+)\]:\s*(.+)$", re.MULTILINE
    )
    path_re = re.compile(r"-->\s*(.+?):(\d+)")
    text_lines = text.splitlines()
    for i, line in enumerate(text_lines):
        m = error_re.match(line.strip())
        if not m:
            continue
        level, code, msg = m.group(1), m.group(2), m.group(3)
        severity = _DENY_LEVEL_MAP.get(level, "INFO")
        # Look for path on next line
        file_path = "Cargo.toml"
        line_no = 0
        if i + 1 < len(text_lines):
            pm = path_re.search(text_lines[i + 1])
            if pm:
                file_path = pm.group(1).strip()
                line_no = int(pm.group(2))

        deny_type = code.lower()
        finding = {
            "detector_id": f"cargo-deny.{deny_type}",
            "source": "cargo-deny",
            "file": file_path,
            "line": line_no,
            "severity": severity,
            "message": msg.strip(),
        }
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Semgrep SARIF adapter
# ---------------------------------------------------------------------------
# SARIF 2.1.0 structure:
#   {
#     "runs": [
#       {
#         "results": [
#           {
#             "ruleId": "rust.lang.security.unsafe-block-in-fn",
#             "level": "warning",
#             "message": {"text": "..."},
#             "locations": [
#               {
#                 "physicalLocation": {
#                   "artifactLocation": {"uri": "src/crypto/hash.rs"},
#                   "region": {"startLine": 88}
#                 }
#               }
#             ]
#           }
#         ]
#       }
#     ]
#   }
#
# Level can be: "error", "warning", "note", "none".
# ``ruleId`` is used as the detector_id suffix.

def _parse_semgrep_sarif(sarif_path: Path) -> list[dict]:
    findings: list[dict] = []
    try:
        doc = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return findings

    for run in doc.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "none")
            severity = _SARIF_LEVEL_MAP.get(level, "INFO")
            msg_obj = result.get("message", {})
            message_text = msg_obj.get("text", str(msg_obj)) if isinstance(msg_obj, dict) else str(msg_obj)

            # Extract file and line from first location
            file_path = ""
            line_no = 0
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                file_path = art.get("uri", "")
                region = phys.get("region", {})
                line_no = region.get("startLine", 0)

            finding: dict[str, Any] = {
                "detector_id": f"semgrep.{rule_id}",
                "source": "semgrep",
                "file": file_path,
                "line": line_no,
                "severity": severity,
                "message": message_text,
            }
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# rust_wave1 adapter
# ---------------------------------------------------------------------------
# Reads ``<ws>/.auditooor/rust_findings.json`` (output of
# ``rust-detector-runner.py``) and flattens pattern hits into unified shape.
#
# wave1 JSON structure:
#   {
#     "patterns": {
#       "<pattern_id>": {
#         "hits": [
#           {"file": "...", "line": N, "snippet": "...", "extra": {...}}
#         ]
#       }
#     }
#   }

def _parse_wave1_findings(findings_path: Path) -> list[dict]:
    findings: list[dict] = []
    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return findings

    patterns = doc.get("patterns", {})
    for pattern_id, pattern_data in patterns.items():
        if not isinstance(pattern_data, dict):
            continue
        hits = pattern_data.get("hits", [])
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            extra = hit.get("extra", {}) or {}
            # wave1 hits don't carry explicit severity; derive from pattern class
            if "high" in pattern_id or "violation" in pattern_id or "attack" in pattern_id:
                severity = "HIGH"
            elif "medium" in pattern_id or "overflow" in pattern_id:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            finding: dict[str, Any] = {
                "detector_id": f"rust_wave1.{pattern_id}",
                "source": "rust_wave1",
                "file": hit.get("file", ""),
                "line": hit.get("line", 0),
                "severity": severity,
                "message": hit.get("snippet", pattern_id),
            }
            if extra.get("function"):
                finding["fn_name"] = extra["function"]
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# _util enrichment (tree-sitter optional)
# ---------------------------------------------------------------------------
# We attempt to enrich clippy and semgrep findings with per-function metadata
# when tree-sitter-languages is installed AND the finding has a file:line that
# resolves within a function body.
#
# If tree-sitter is not available we silently skip enrichment (the ingest
# still succeeds).

def _try_enrich_with_util(
    finding: dict,
    workspace: Path,
) -> dict:
    """Attempt to add crate_name / module_path / fn_signature / fn_name fields.

    Reads the source file and uses the tree-sitter-based helpers in
    ``detectors/rust_wave1/_util.py``.  Fails silently if:
    - tree-sitter is not installed
    - file does not exist
    - line does not land within any function
    """
    file_rel = finding.get("file", "")
    line_no = finding.get("line", 0)
    if not file_rel or not line_no:
        return finding

    # Resolve file path
    if Path(file_rel).is_absolute():
        file_path = Path(file_rel)
    else:
        file_path = workspace / file_rel
    if not file_path.exists():
        return finding

    # Attempt tree-sitter import — skip if unavailable
    try:
        import tree_sitter_languages as _tsl  # type: ignore[import]
        from tree_sitter import Language, Parser  # type: ignore[import]
        lang = _tsl.get_language("rust")
        parser = Parser()
        parser.set_language(lang)
    except Exception:
        # tree-sitter not installed or error loading language
        _try_util_enrichment_regex(finding, file_path, line_no)
        return finding

    # Parse the file
    try:
        source = file_path.read_bytes()
        tree = parser.parse(source)
    except Exception:
        return finding

    # Import _util helpers (add detectors/rust_wave1 to sys.path temporarily)
    try:
        import sys as _sys
        util_dir = str(Path(__file__).resolve().parent.parent / "detectors" / "rust_wave1")
        if util_dir not in _sys.path:
            _sys.path.insert(0, util_dir)
        import importlib
        _util = importlib.import_module("_util")
    except Exception:
        return finding

    # Walk functions to find the one enclosing our line_no
    try:
        root = tree.root_node
        for fn_node in _util.function_items(root):
            fn_start = fn_node.start_point[0] + 1  # 1-based
            fn_end = fn_node.end_point[0] + 1
            if fn_start <= line_no <= fn_end:
                # Found enclosing function
                try:
                    crate = _util.crate_name_from_path(file_path)
                    if crate and crate != "unknown":
                        finding["crate_name"] = crate
                except Exception:
                    pass
                try:
                    mod = _util.fn_module_path(fn_node, source, file_path)
                    if mod:
                        finding["module_path"] = mod
                except Exception:
                    pass
                try:
                    sig = _util.fn_signature_normalized(fn_node, source)
                    if sig:
                        finding["fn_signature"] = sig
                except Exception:
                    pass
                try:
                    name = _util.fn_name(fn_node, source)
                    if name and name != "?":
                        finding["fn_name"] = name
                except Exception:
                    pass
                break
    except Exception:
        pass

    return finding


def _try_util_enrichment_regex(
    finding: dict,
    file_path: Path,
    line_no: int,
) -> None:
    """Regex-only fallback enrichment when tree-sitter is unavailable.

    Adds crate_name using the Cargo.toml walk from _util.crate_name_from_path
    logic (re-implemented here to avoid importing the full tree-sitter _util).
    """
    # Crate name: walk up to nearest Cargo.toml
    try:
        import sys as _sys
        util_dir = str(Path(__file__).resolve().parent.parent / "detectors" / "rust_wave1")
        if util_dir not in _sys.path:
            _sys.path.insert(0, util_dir)
        import importlib
        _util = importlib.import_module("_util")
        crate = _util.crate_name_from_path(file_path)
        if crate and crate != "unknown":
            finding["crate_name"] = crate
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Default log paths
# ---------------------------------------------------------------------------

def _default_log_dir(workspace: Path) -> Path:
    # rust-scan.sh writes to <ws>/audit/rust-scan/; the spec says
    # <ws>/.audit_logs/rust_scan/ — we check both and prefer the spec path.
    spec_path = workspace / ".audit_logs" / "rust_scan"
    if spec_path.is_dir():
        return spec_path
    alt_path = workspace / "audit" / "rust-scan"
    if alt_path.is_dir():
        return alt_path
    return spec_path  # return spec path even if missing (caller will handle)


# ---------------------------------------------------------------------------
# Main ingest orchestrator
# ---------------------------------------------------------------------------

_ALL_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_ALL_SOURCES = ("clippy", "cargo-audit", "cargo-geiger", "cargo-deny", "semgrep", "rust_wave1")


def ingest(
    workspace: Path,
    clippy_log: Path | None = None,
    audit_log: Path | None = None,
    geiger_log: Path | None = None,
    deny_log: Path | None = None,
    semgrep_sarif: Path | None = None,
    wave1_findings: Path | None = None,
    out_path: Path | None = None,
    enrich: bool = True,
) -> dict:
    """Run all adapters and produce the unified findings document.

    Returns the document dict (also written to ``out_path``).
    """
    workspace = workspace.resolve()
    log_dir = _default_log_dir(workspace)

    # Resolve paths with defaults
    def _resolve(explicit: Path | None, default_name: str) -> Path | None:
        if explicit is not None:
            return explicit
        candidate = log_dir / default_name
        return candidate if candidate.exists() else None

    clippy_path = _resolve(clippy_log, "clippy.log")
    audit_path = _resolve(audit_log, "cargo-audit.log")
    geiger_path = _resolve(geiger_log, "geiger.log")
    deny_path = _resolve(deny_log, "cargo-deny.log")
    sarif_path = _resolve(semgrep_sarif, "semgrep.sarif")

    wave1_path = wave1_findings
    if wave1_path is None:
        candidate = workspace / ".auditooor" / "rust_findings.json"
        wave1_path = candidate if candidate.exists() else None

    if out_path is None:
        out_path = workspace / ".auditooor" / "rust_findings_unified.json"

    # Run adapters
    all_findings: list[dict] = []
    missing_sources: list[str] = []

    def _run_adapter(source_name: str, path: Path | None, adapter_fn) -> list[dict]:
        if path is None:
            missing_sources.append(source_name)
            return []
        try:
            return adapter_fn(path)
        except Exception as exc:
            print(
                f"[rust-scanner-ingest] WARN {source_name} adapter failed: {exc}",
                file=sys.stderr,
            )
            missing_sources.append(f"{source_name}(error)")
            return []

    clippy_findings = _run_adapter("clippy", clippy_path, _parse_clippy)
    audit_findings = _run_adapter("cargo-audit", audit_path, _parse_cargo_audit)
    geiger_findings = _run_adapter("cargo-geiger", geiger_path, _parse_cargo_geiger)
    deny_findings = _run_adapter("cargo-deny", deny_path, _parse_cargo_deny)
    semgrep_findings = _run_adapter("semgrep", sarif_path, _parse_semgrep_sarif)
    wave1_list = _run_adapter("rust_wave1", wave1_path, _parse_wave1_findings)

    all_findings.extend(clippy_findings)
    all_findings.extend(audit_findings)
    all_findings.extend(geiger_findings)
    all_findings.extend(deny_findings)
    all_findings.extend(semgrep_findings)
    all_findings.extend(wave1_list)

    # Optional enrichment for sources that benefit from per-fn metadata
    if enrich:
        enrichable_sources = {"clippy", "semgrep", "rust_wave1"}
        enriched = []
        for f in all_findings:
            if f.get("source") in enrichable_sources:
                f = _try_enrich_with_util(f, workspace)
            enriched.append(f)
        all_findings = enriched

    # Build summary
    by_source: dict[str, int] = {s: 0 for s in _ALL_SOURCES}
    for f in all_findings:
        src = f.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

    by_severity: dict[str, int] = {s: 0 for s in _ALL_SEVERITIES}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    doc: dict = {
        "schema": "auditooor.rust_findings_unified.v1",
        "generated_at": datetime.datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace_path": str(workspace),
        "summary": {
            "total": len(all_findings),
            "by_source": by_source,
            "by_severity": by_severity,
            "missing_sources": missing_sources,
        },
        "findings": all_findings,
    }

    # Write output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(
        f"[rust-scanner-ingest] {len(all_findings)} unified findings "
        f"({len(missing_sources)} source(s) missing) -> {out_path}"
    )
    return doc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else "Unified Rust findings ingest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workspace", "-w", type=Path, required=True,
        help="Workspace root directory.",
    )
    p.add_argument(
        "--clippy-log", type=Path, metavar="PATH",
        help="Path to clippy.log (JSONL). Default: <ws>/.audit_logs/rust_scan/clippy.log",
    )
    p.add_argument(
        "--audit-log", type=Path, metavar="PATH",
        help="Path to cargo-audit.log (JSON). Default: <ws>/.audit_logs/rust_scan/cargo-audit.log",
    )
    p.add_argument(
        "--geiger-log", type=Path, metavar="PATH",
        help="Path to geiger.log (JSON). Default: <ws>/.audit_logs/rust_scan/geiger.log",
    )
    p.add_argument(
        "--deny-log", type=Path, metavar="PATH",
        help="Path to cargo-deny.log (JSONL or plain-text). Default: <ws>/.audit_logs/rust_scan/cargo-deny.log",
    )
    p.add_argument(
        "--semgrep-sarif", type=Path, metavar="PATH",
        help="Path to semgrep.sarif (SARIF 2.1.0). Default: <ws>/.audit_logs/rust_scan/semgrep.sarif",
    )
    p.add_argument(
        "--wave1-findings", type=Path, metavar="PATH",
        help="Path to rust_findings.json (wave1 output). Default: <ws>/.auditooor/rust_findings.json",
    )
    p.add_argument(
        "--out", type=Path, metavar="PATH",
        help="Output path for unified findings JSON. Default: <ws>/.auditooor/rust_findings_unified.json",
    )
    p.add_argument(
        "--no-enrich", action="store_true",
        help="Skip per-function metadata enrichment (faster, no tree-sitter required).",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Print the unified findings document to stdout after writing.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    p = _build_parser()
    args = p.parse_args(argv)

    ws = args.workspace
    if not ws.exists() or not ws.is_dir():
        print(f"[rust-scanner-ingest] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    doc = ingest(
        workspace=ws,
        clippy_log=args.clippy_log,
        audit_log=args.audit_log,
        geiger_log=args.geiger_log,
        deny_log=args.deny_log,
        semgrep_sarif=args.semgrep_sarif,
        wave1_findings=args.wave1_findings,
        out_path=args.out,
        enrich=not args.no_enrich,
    )

    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
