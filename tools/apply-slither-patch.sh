#!/usr/bin/env bash
# apply-slither-patch.sh — patch the local slither-analyzer install so it
# soft-skips three upstream assertions that abort analysis on perfectly
# legitimate source patterns. Without these patches, real audit targets
# (Centrifuge V3.1, Snowbridge V2) cannot be scanned at all.
#
# Patches shipped:
#
#   R52d — slither/slithir/convert.py :: `convert_constant_types`
#          Soft-skip when `len(types) != len(ir.arguments)` after UDVT + bool
#          literal + nested external-call-return combos. Original trigger was
#          Centrifuge's Hub.initializeHolding. Root cause is upstream in
#          propagate_type_and_convert_call; the assertion only detects the
#          corruption — aborting the whole scan over a cosmetic literal-retype
#          pass is the wrong tradeoff.
#
#   R67a — slither/slithir/operations/member.py :: `Member.__init__`
#          Soft-skip when `variable_left` is a kind not in slither's accepted
#          set (observed: `StructureTopLevel` via solc 0.8.33's
#          `this.handler{gas: ...}(params)` external self-call pattern in
#          Snowbridge Gateway). Substitute an ElementaryType placeholder so
#          downstream IR completes; that specific member access may be
#          incomplete but the rest of the analysis proceeds.
#
#   R67b — slither/slithir/variables/reference.py :: `points_to` setter
#          Sibling of R67a. When member.py substitutes an ElementaryType
#          placeholder, `find_references_origin` later assigns that
#          placeholder as `points_to` on a ReferenceVariable. The original
#          assertion explodes because ElementaryType isn't a valid lvalue;
#          we store None to indicate "points-to unknown."
#
# Usage:
#   ./tools/apply-slither-patch.sh            # apply all patches (idempotent)
#   ./tools/apply-slither-patch.sh --revert   # restore all .bak files
#   ./tools/apply-slither-patch.sh --check    # report which patches are applied

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

MODE="apply"
if [ "${1:-}" = "--revert" ]; then MODE="revert"; fi
if [ "${1:-}" = "--check" ];  then MODE="check";  fi

# Locate each target file inside the installed slither.
locate_py() {
    python3 - "$1" <<'PY'
import importlib.util, sys
spec = importlib.util.find_spec(sys.argv[1])
if spec is None or spec.origin is None:
    sys.stderr.write(f"[error] cannot import {sys.argv[1]}\n")
    sys.exit(2)
print(spec.origin)
PY
}

CONVERT_PY=$(locate_py "slither.slithir.convert") || exit 2
MEMBER_PY=$(locate_py "slither.slithir.operations.member") || exit 2
REFERENCE_PY=$(locate_py "slither.slithir.variables.reference") || exit 2

echo "[info] targets:"
echo "  convert.py   : $CONVERT_PY"
echo "  member.py    : $MEMBER_PY"
echo "  reference.py : $REFERENCE_PY"

MARKER_CONVERT="# auditooor patch (R52d)"
MARKER_MEMBER="slither-patch-R67/member"
MARKER_REFERENCE="slither-patch-R67/reference"

is_patched_convert()   { grep -q "$MARKER_CONVERT"   "$CONVERT_PY"   2>/dev/null; }
is_patched_member()    { grep -q "$MARKER_MEMBER"    "$MEMBER_PY"    2>/dev/null; }
is_patched_reference() { grep -q "$MARKER_REFERENCE" "$REFERENCE_PY" 2>/dev/null; }

backup_once() {
    local src="$1"
    local bak="${src}.auditooor.bak"
    if [ ! -f "$bak" ]; then
        cp "$src" "$bak"
        echo "[info] wrote backup: $bak"
    fi
}

revert_from_bak() {
    local src="$1"
    local bak="${src}.auditooor.bak"
    if [ ! -f "$bak" ]; then
        echo "[warn] no backup at $bak — nothing to revert for this file"
        return 1
    fi
    cp "$bak" "$src"
    echo "[ok] reverted $src from $bak"
    return 0
}

clear_pyc() {
    local py_cache="$(dirname "$1")/__pycache__"
    local base=$(basename "$1" .py)
    if [ -d "$py_cache" ]; then
        rm -f "$py_cache"/${base}.cpython-*.pyc 2>/dev/null || true
    fi
}

apply_convert_patch() {
    if is_patched_convert; then
        echo "[ok] convert.py already patched — skipping"
        return 0
    fi
    backup_once "$CONVERT_PY"
    python3 - "$CONVERT_PY" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()

target = "                assert len(types) == len(ir.arguments)\n"
if target not in src:
    m = re.search(r'(?m)^(\s+)assert len\(types\) == len\(ir\.arguments\)\s*$', src)
    if not m:
        sys.stderr.write("[error] could not locate assert — slither version drift?\n")
        sys.exit(4)
    indent = m.group(1)
    target = m.group(0) + "\n"
else:
    indent = "                "

replacement = (
    f'{indent}# auditooor patch (R52d): soft-skip on IR argument contamination\n'
    f'{indent}# triggered by UDVT + bool literal + nested external-call-return\n'
    f'{indent}# combos. Root cause is upstream in propagate_type_and_convert_call;\n'
    f'{indent}# this assertion only detects the corruption — aborting the whole\n'
    f'{indent}# scan over a cosmetic literal-retype pass is the wrong tradeoff.\n'
    f'{indent}if len(types) != len(ir.arguments):\n'
    f'{indent}    try:\n'
    f'{indent}        import logging\n'
    f'{indent}        logging.getLogger("Slither").warning(\n'
    f'{indent}            "convert_constant_types: len(types)=%d != len(ir.arguments)=%d "\n'
    f'{indent}            "for call to %r; skipping literal retype (auditooor patch)",\n'
    f'{indent}            len(types), len(ir.arguments),\n'
    f'{indent}            getattr(func, "name", "<?>"),\n'
    f'{indent}        )\n'
    f'{indent}    except Exception:\n'
    f'{indent}        pass\n'
    f'{indent}    continue\n'
    f'{indent}assert len(types) == len(ir.arguments)\n'
)
out = src.replace(target, replacement, 1)
if out == src:
    sys.stderr.write("[error] convert.py replacement no-op\n")
    sys.exit(5)
with open(path, "w") as f:
    f.write(out)
print("[ok] convert.py patched")
PY
    local rc=$?
    [ $rc -ne 0 ] && { echo "[error] convert.py patch failed rc=$rc" >&2; return $rc; }
    clear_pyc "$CONVERT_PY"
    return 0
}

apply_member_patch() {
    if is_patched_member; then
        echo "[ok] member.py already patched — skipping"
        return 0
    fi
    backup_once "$MEMBER_PY"
    python3 - "$MEMBER_PY" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Find the assertion block: `assert is_valid_rvalue(variable_left) or isinstance(`
# followed by the tuple literal of allowed kinds.
# We do a permissive multi-line match.
pat = re.compile(
    r'(\s+)assert is_valid_rvalue\(variable_left\) or isinstance\(\s*\n'
    r'\s+variable_left,\s*\n'
    r'\s+\(\s*\n'
    r'((?:\s+\w+,?\s*\n)+)'
    r'\s+\),?\s*\n'
    r'\s+\)',
    re.M,
)
m = pat.search(src)
if not m:
    sys.stderr.write("[error] member.py: could not locate assertion block — slither version drift?\n")
    sys.exit(4)
indent = m.group(1)
types_block = m.group(2)
orig = m.group(0)
replacement = (
    f'{indent}# R67 SKILL_ISSUES #167: slither-patch-R67/member soft-skip on\n'
    f'{indent}# unknown variable_left kinds (observed with solc 0.8.33\n'
    f'{indent}# `this.handler{{gas: ...}}(params)` external self-call pattern\n'
    f'{indent}# in Snowbridge Gateway). Crashing aborts the whole analysis;\n'
    f'{indent}# substitute an ElementaryType placeholder so downstream IR still\n'
    f'{indent}# completes.\n'
    f'{indent}if not (is_valid_rvalue(variable_left) or isinstance(\n'
    f'{indent}    variable_left,\n'
    f'{indent}    (\n'
    f'{types_block}'
    f'{indent}    ),\n'
    f'{indent})):\n'
    f'{indent}    import sys as _sys\n'
    f'{indent}    _sys.stderr.write(\n'
    f'{indent}        "[slither-patch-R67/member] soft-skip member access: "\n'
    f'{indent}        "variable_left=%s (%s) — substituting ElementaryType(\'bytes\') placeholder.\\n"\n'
    f'{indent}        % (type(variable_left).__name__, variable_left)\n'
    f'{indent}    )\n'
    f'{indent}    variable_left = ElementaryType("bytes")'
)
out = src.replace(orig, replacement, 1)
if out == src:
    sys.stderr.write("[error] member.py replacement no-op\n")
    sys.exit(5)
with open(path, "w") as f:
    f.write(out)
print("[ok] member.py patched")
PY
    local rc=$?
    [ $rc -ne 0 ] && { echo "[error] member.py patch failed rc=$rc" >&2; return $rc; }
    clear_pyc "$MEMBER_PY"
    return 0
}

apply_reference_patch() {
    if is_patched_reference; then
        echo "[ok] reference.py already patched — skipping"
        return 0
    fi
    backup_once "$REFERENCE_PY"
    python3 - "$REFERENCE_PY" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()

pat = re.compile(
    r'(\s+)assert is_valid_lvalue\(points_to\) or isinstance\(\s*\n'
    r'\s+points_to, \(SolidityVariable, Contract, Enum, TopLevelVariable\)\s*\n'
    r'\s+\)',
    re.M,
)
m = pat.search(src)
if not m:
    sys.stderr.write("[error] reference.py: could not locate assertion — slither version drift?\n")
    sys.exit(4)
indent = m.group(1)
orig = m.group(0)
replacement = (
    f'{indent}# R67 SKILL_ISSUES #167: slither-patch-R67/reference sibling of\n'
    f'{indent}# the member.py patch. When member.py substitutes an\n'
    f'{indent}# ElementaryType placeholder on unknown variable_left,\n'
    f'{indent}# find_references_origin later assigns that placeholder as\n'
    f'{indent}# points_to on a ReferenceVariable. Store None to indicate\n'
    f'{indent}# "points-to unknown" instead of asserting.\n'
    f'{indent}if not (is_valid_lvalue(points_to) or isinstance(\n'
    f'{indent}    points_to, (SolidityVariable, Contract, Enum, TopLevelVariable)\n'
    f'{indent})):\n'
    f'{indent}    import sys as _sys\n'
    f'{indent}    _sys.stderr.write(\n'
    f'{indent}        "[slither-patch-R67/reference] soft-skip points_to assignment: "\n'
    f'{indent}        "points_to=%s (%s) — storing None placeholder.\\n"\n'
    f'{indent}        % (type(points_to).__name__, points_to)\n'
    f'{indent}    )\n'
    f'{indent}    self._points_to = None\n'
    f'{indent}    return'
)
out = src.replace(orig, replacement, 1)
if out == src:
    sys.stderr.write("[error] reference.py replacement no-op\n")
    sys.exit(5)
with open(path, "w") as f:
    f.write(out)
print("[ok] reference.py patched")
PY
    local rc=$?
    [ $rc -ne 0 ] && { echo "[error] reference.py patch failed rc=$rc" >&2; return $rc; }
    clear_pyc "$REFERENCE_PY"
    return 0
}

case "$MODE" in
    check)
        rc=0
        echo "[check] convert.py   : $(is_patched_convert   && echo PATCHED || echo UNPATCHED)"
        echo "[check] member.py    : $(is_patched_member    && echo PATCHED || echo UNPATCHED)"
        echo "[check] reference.py : $(is_patched_reference && echo PATCHED || echo UNPATCHED)"
        is_patched_convert   || rc=1
        is_patched_member    || rc=1
        is_patched_reference || rc=1
        exit $rc
        ;;
    revert)
        revert_from_bak "$CONVERT_PY"
        revert_from_bak "$MEMBER_PY"
        revert_from_bak "$REFERENCE_PY"
        clear_pyc "$CONVERT_PY"
        clear_pyc "$MEMBER_PY"
        clear_pyc "$REFERENCE_PY"
        echo "[ok] all patches reverted"
        exit 0
        ;;
    apply)
        apply_convert_patch   || exit $?
        apply_member_patch    || exit $?
        apply_reference_patch || exit $?
        echo "[ok] all three slither patches applied (R52d + R67a + R67b)"
        exit 0
        ;;
esac
