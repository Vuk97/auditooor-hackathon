#!/usr/bin/env bash
# extract-oos.sh - extract out-of-scope bullets + severity caps from SCOPE.md (new R38 tool).
#
# Until now, the skill wrote OOS into SCOPE.md but had no mechanism to
# FEED it into triage-time decisions. This tool:
#   1. Parses SCOPE.md for OOS sections (best-effort: looks for headings like
#      "Out of scope", "Prohibited", "Known issues", "Severity caps").
#   2. Writes <ws>/OOS_CHECKLIST.md - one bullet per OOS class.
#   3. Writes <ws>/SEVERITY_CAPS.md - machine-readable caps.
#
# Curated-content preservation (V5-P0-08 / Gap 18):
#   On re-run, this tool replaces ONLY the auto-generated block delimited
#   by AUDITOOOR_AUTO_OOS_BEGIN / AUDITOOOR_AUTO_OOS_END markers (and the
#   matching CAPS markers in SEVERITY_CAPS.md). Operator notes ABOVE or
#   BELOW the markers are preserved verbatim. If the file exists but has
#   no markers (legacy file produced before V5-P0-08), the existing
#   content is preserved and a fresh auto block is appended at the end
#   with markers, so a second run is safe.
#
# Agent briefs and pre-submit checks should read OOS_CHECKLIST.md to avoid
# wasting time on triaged-out classes.
#
# Usage:
#   ./tools/extract-oos.sh <workspace-dir>

set -u
WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace-dir>" >&2
  exit 2
fi

SCOPE="$WS/SCOPE.md"
if [ ! -f "$SCOPE" ]; then
  echo "[extract-oos] SCOPE.md missing at $SCOPE - run fetch-scope.sh first" >&2
  exit 1
fi

OOS="$WS/OOS_CHECKLIST.md"
CAPS="$WS/SEVERITY_CAPS.md"

# Extract lines in any "out of scope" / "known issues" / "prohibited" section.
# Heuristic: section-header regex followed by bulleted lines until next H2/H3.
python3 - "$SCOPE" "$OOS" "$CAPS" <<'PY'
import re, sys, datetime
scope, oos_path, caps_path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(scope, 'r', encoding='utf-8', errors='ignore').read()

section_headers = {
    'oos': re.compile(r'(?im)^\s*#{1,4}\s*(out\s*[- ]?of\s*[- ]?scope|not\s*in\s*scope|excluded|prohibited|known\s*issues|already\s*known)\b'),
    'caps': re.compile(r'(?im)^\s*#{1,4}\s*(severity\s*caps|severity\s*modifiers|at\s*most\s*(medium|high|critical))\b'),
}

# Find sections - each heading to the next heading of equal-or-shallower depth
def slurp_sections(text):
    lines = text.split('\n')
    sections = []
    cur_label = None
    cur_lines = []
    for ln in lines:
        # section start?
        if section_headers['oos'].match(ln):
            if cur_label: sections.append((cur_label, cur_lines))
            cur_label, cur_lines = 'oos', []
        elif section_headers['caps'].match(ln):
            if cur_label: sections.append((cur_label, cur_lines))
            cur_label, cur_lines = 'caps', []
        elif re.match(r'^\s*#{1,4}\s+\S', ln):
            if cur_label: sections.append((cur_label, cur_lines))
            cur_label, cur_lines = None, []
        else:
            if cur_label is not None: cur_lines.append(ln)
    if cur_label: sections.append((cur_label, cur_lines))
    return sections

sections = slurp_sections(text)

oos_bullets = []
cap_bullets = []

for label, lines in sections:
    target = oos_bullets if label == 'oos' else cap_bullets
    # last_idx tracks the current bullet so a WRAPPED continuation line (indented,
    # no leading '-', markdown lazy-continuation) is FOLDED into it instead of
    # dropped. Bug caught on Obyte 2026-07-09: a bullet "- Basic economic ... 51%
    # attack). Lack-of-liquidity impacts.\n  Sybil attacks. Centralization risks."
    # silently lost the "Sybil attacks" clause from OOS_CHECKLIST, so the OOS
    # pre-check nearly let a Sybil-farming finding through as fileable.
    last_idx = None
    for ln in lines:
        m = re.match(r'\s*[-*]\s+(.*\S)', ln)
        if m:
            target.append(m.group(1).strip())
            last_idx = len(target) - 1
        # also catch "Note:" / "Any issue" paragraph blocks
        elif re.match(r'\s*(Any\s|Note\s*:|Known\s*:|Issues?\s+related)', ln, re.I):
            target.append(ln.strip())
            last_idx = len(target) - 1
        elif ln.strip() == '':
            last_idx = None  # blank line ends the current bullet's continuation
        elif last_idx is not None and not re.match(r'\s*#{1,4}\s', ln):
            # a wrapped continuation line of the current bullet - fold it in so no
            # OOS clause on a wrapped line is silently lost
            target[last_idx] = (target[last_idx] + ' ' + ln.strip()).strip()

# Also catch bounty-style free-floating "Any issue ... is at most <severity>" paragraph
for m in re.finditer(r'(?im)^\s*Any\s+issue[^\n]*?(at\s+most\s+(critical|high|medium|low))[^\n]*', text):
    sentence = m.group(0).strip()
    if sentence not in cap_bullets:
        cap_bullets.append(sentence)


# ---------------------------------------------------------------------------
# V5-P0-08 / Gap 18: curated-content preservation via generated block markers.
#
# Auto-generated content is wrapped between matching BEGIN/END markers (HTML
# comments so they render invisibly in markdown). On re-run we replace only
# the bytes between the markers; anything outside is operator-curated and
# kept verbatim.
#
# Marker regex deliberately requires the literal token to appear at the
# start of a line (not inside a fenced code block by accident); we also
# pick the FIRST begin/last end pair so adversarial nested markdown
# comment blocks cannot displace the boundaries.
# ---------------------------------------------------------------------------

OOS_BEGIN = "<!-- AUDITOOOR_AUTO_OOS_BEGIN -->"
OOS_END = "<!-- AUDITOOOR_AUTO_OOS_END -->"
CAPS_BEGIN = "<!-- AUDITOOOR_AUTO_CAPS_BEGIN -->"
CAPS_END = "<!-- AUDITOOOR_AUTO_CAPS_END -->"


def render_oos_block(bullets):
    lines = []
    lines.append(OOS_BEGIN)
    lines.append("")
    lines.append(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z")
    lines.append("")
    lines.append("> Auto-generated by `tools/extract-oos.sh`. Do not hand-edit between the BEGIN/END markers - your edits will be overwritten on the next run. Operator-curated notes belong ABOVE or BELOW this block.")
    lines.append("")
    if bullets:
        for i, b in enumerate(bullets, 1):
            lines.append(f"- [ ] **OOS-{i}:** {b}")
    else:
        lines.append("_(no OOS bullets parsed - verify SCOPE.md has a clear 'Out of scope' section)_")
    lines.append("")
    lines.append(OOS_END)
    return "\n".join(lines) + "\n"


def render_caps_block(bullets):
    lines = []
    lines.append(CAPS_BEGIN)
    lines.append("")
    lines.append(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z")
    lines.append("")
    lines.append("> Auto-generated by `tools/extract-oos.sh`. Do not hand-edit between the BEGIN/END markers.")
    lines.append("")
    if bullets:
        for i, b in enumerate(bullets, 1):
            lines.append(f"- [ ] **CAP-{i}:** {b}")
    else:
        lines.append("_(no program-specific severity caps listed in SCOPE.md)_")
    lines.append("")
    lines.append(CAPS_END)
    return "\n".join(lines) + "\n"


def merge_with_markers(path, begin, end, fresh_block, header_for_fresh_file):
    """Return (final_text, mode) for writing.

    mode: 'fresh' / 'replaced' / 'appended-legacy'
    """
    import os
    if not os.path.exists(path):
        return header_for_fresh_file + fresh_block, "fresh"

    existing = open(path, 'r', encoding='utf-8', errors='ignore').read()

    # Anchor markers to start-of-line to resist partial matches in fenced
    # code blocks. We match the FIRST begin and the LAST matching end after
    # it, so adversarial nested markers cannot escape the auto block.
    begin_re = re.compile(r'(?m)^' + re.escape(begin) + r'\s*$')
    end_re = re.compile(r'(?m)^' + re.escape(end) + r'\s*$')

    bm = begin_re.search(existing)
    if bm is None:
        # Legacy file: keep operator content, append fresh auto block.
        sep = "" if existing.endswith("\n") else "\n"
        return existing + sep + "\n" + fresh_block, "appended-legacy"

    # Find last END after BEGIN.
    em = None
    for m in end_re.finditer(existing, bm.end()):
        em = m
    if em is None:
        # Unterminated marker - treat the whole tail as auto block.
        return existing[:bm.start()] + fresh_block, "replaced"

    head = existing[:bm.start()]
    tail = existing[em.end():]
    # Preserve a single newline boundary on each side.
    if head and not head.endswith("\n"):
        head += "\n"
    if tail and not tail.startswith("\n"):
        tail = "\n" + tail
    return head + fresh_block + tail, "replaced"


OOS_HEADER = (
    "# Out-of-scope checklist - auto-extracted from SCOPE.md\n\n"
    "**Purpose:** every triage decision and pre-submit check reads this list.\n"
    "Findings that match an OOS bullet are NOT submittable; agents should flag them as KNOWN-OOS.\n\n"
    "---\n\n"
)
OOS_FOOTER_HINT = (
    "\n## Triage protocol\n\n"
    "For every candidate finding, grep this file for overlapping keywords.\n"
    "If the candidate matches ANY OOS bullet semantically, mark CLOSED-OOS in FINDINGS.md with the OOS-N reference.\n"
)
CAPS_HEADER = (
    "# Severity caps - auto-extracted from SCOPE.md\n\n"
    "**Purpose:** respect bounty-specified severity caps when rating a finding.\n\n"
    "---\n\n"
)

oos_block = render_oos_block(oos_bullets)
caps_block = render_caps_block(cap_bullets)

# For a brand-new file we want headers + auto block + triage protocol footer.
oos_full_fresh_header = OOS_HEADER
oos_text, oos_mode = merge_with_markers(oos_path, OOS_BEGIN, OOS_END, oos_block, oos_full_fresh_header)
if oos_mode == "fresh":
    # Append the triage-protocol footer below the auto block on first run only.
    oos_text = oos_text + OOS_FOOTER_HINT

with open(oos_path, 'w') as f:
    f.write(oos_text)

caps_text, caps_mode = merge_with_markers(caps_path, CAPS_BEGIN, CAPS_END, caps_block, CAPS_HEADER)
with open(caps_path, 'w') as f:
    f.write(caps_text)

print(f"[extract-oos] wrote {oos_path} ({len(oos_bullets)} OOS bullets, mode={oos_mode})")
print(f"[extract-oos] wrote {caps_path} ({len(cap_bullets)} caps, mode={caps_mode})")
PY
