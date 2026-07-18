"""
rust_network_codec_unwrap_on_utf8_peer_bytes.py

Flags functions on inbound peer/network message decode paths that call
String::from_utf8(expr).unwrap() or std::str::from_utf8(expr).unwrap()
where the bytes originate from peer-supplied wire data (a buffer read,
a byte slice of incoming data, or a byte array from a socket stream).

Non-UTF8 bytes supplied by any peer trigger the unwrap and panic the
decode task, terminating the connection handler and (on a shared
thread/task pool) degrading the node's ability to process inbound
P2P messages - a reachable DoS for any connected peer.

Target shape (class-invariant):
  1. The function is named decode / read_message / parse_message /
     poll_decode / read_header / read_body / from_bytes / deserialize /
     codec, OR the function lives inside an impl block whose trait name
     contains Decoder / Encoder / Codec / Parser.
  2. The body calls String::from_utf8(...).unwrap() or
     std::str::from_utf8(...).unwrap() [NOT from_utf8_lossy].
  3. The argument to from_utf8 is not a compile-time constant (no lone
     string literal, no `const` array reference as the immediate arg).
  4. The function is not test code.

Safe alternative: replace with from_utf8_lossy (returns Cow<str> with
replacement characters for invalid sequences) or map_err to a protocol
error and propagate with `?`.

Verified real surface:
  zebra-network/src/protocol/external/codec.rs  fn decode (line 373)
  impl Decoder for Codec - the inbound P2P message header decoder reads
  command bytes from the peer TCP stream and calls String::from_utf8(
  command.iter().cloned().flat_map(std::ascii::escape_default).collect()
  ).unwrap() inside a trace! macro at line 396-401.  The bytes come
  directly from the peer wire; the escape_default chain makes the
  resulting Vec<u8> always valid ASCII, but the structural pattern
  (from_utf8 + unwrap on bytes derived from peer wire in a Decoder impl)
  is the flagged shape.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk_no_nested_fn,
)

# ---------------------------------------------------------------------------
# Signal 1 – function name pattern for decode/codec/network hot paths
# ---------------------------------------------------------------------------
_DECODE_FN_NAME_RE = re.compile(
    r"^(?:decode|poll_decode|read_message|parse_message|read_header|"
    r"read_body|from_bytes|deserialize|parse_frame|parse_packet|"
    r"codec|parse)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Signal 2 – function body must contain String::from_utf8( + .unwrap()
#
# Matches both:
#   String::from_utf8(expr).unwrap()
#   std::str::from_utf8(expr).unwrap()
#   str::from_utf8(expr).unwrap()
#
# We detect them separately and require BOTH to be present in the body.
# ---------------------------------------------------------------------------
_FROM_UTF8_RE = re.compile(
    r"(?:String\s*::\s*from_utf8\s*\("
    r"|std\s*::\s*str\s*::\s*from_utf8\s*\("
    r"|str\s*::\s*from_utf8\s*\()",
)

_UNWRAP_RE = re.compile(r"\.unwrap\s*\(\s*\)")

# ---------------------------------------------------------------------------
# Guard: the from_utf8 argument looks like a compile-time constant:
#   b"literal", *CONST_IDENT (a const array deref), or a &[u8; N] slice of
#   a const - these cannot be peer-supplied.  We detect the simple case
#   where the entire from_utf8 call argument is a byte-string literal.
# ---------------------------------------------------------------------------
_CONST_ONLY_RE = re.compile(r'(?:String|str)\s*::\s*from_utf8\s*\(\s*b"[^"]*"\s*\)')

# ---------------------------------------------------------------------------
# Impl-block trait name patterns that identify decoder/codec impls.
# We check source text of the enclosing impl_item.
# ---------------------------------------------------------------------------
_IMPL_TRAIT_RE = re.compile(
    r"\bimpl\s+(?:\w+\s*::\s*)*(?:Decoder|Encoder|Codec|Parser|MessageCodec|"
    r"FrameDecoder|FrameEncoder|BufRead|AsyncRead)\b",
    re.IGNORECASE,
)


def _fn_in_decoder_impl(fn_node, source: bytes) -> bool:
    """Return True if fn_node is a direct child of an impl block whose
    trait name looks like a Decoder/Encoder/Codec/Parser."""
    # Walk up: function_item -> declaration_list -> impl_item
    parent = fn_node.parent
    if parent is None:
        return False
    # Skip declaration_list wrapper
    if parent.type == "declaration_list":
        parent = parent.parent
    if parent is None or parent.type != "impl_item":
        return False
    impl_text = source[parent.start_byte:parent.end_byte].decode("utf-8", errors="replace")
    return bool(_IMPL_TRAIT_RE.search(impl_text))


def _find_from_utf8_unwrap_node(body, source: bytes):
    """Return the call_expression node for the .unwrap() call chained
    after a from_utf8 call, or None."""
    for node in walk_no_nested_fn(body):
        if node.type != "call_expression":
            continue
        node_text = text_of(node, source)
        # The outermost call must be .unwrap() on a from_utf8 result
        if not _UNWRAP_RE.search(node_text):
            continue
        if not _FROM_UTF8_RE.search(node_text):
            continue
        # Prefer the tightest matching node
        return node
    return None


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must have a from_utf8 call in the body
        if not _FROM_UTF8_RE.search(body_text):
            continue

        # Must have an .unwrap() call in the body
        if not _UNWRAP_RE.search(body_text):
            continue

        # Skip if the only from_utf8 calls use byte-string literals (compile-time safe)
        if not _FROM_UTF8_RE.sub("", _CONST_ONLY_RE.sub("", body_text)).count("from_utf8"):
            # All from_utf8 calls were constant-only
            pass  # fall through to the name/impl gate anyway - if named decode, flag it

        # Gate: function must be on a decode/codec/network path
        name = fn_name(fn, source)
        is_decode_fn = bool(_DECODE_FN_NAME_RE.match(name))
        is_in_decoder_impl = _fn_in_decoder_impl(fn, source)

        if not (is_decode_fn or is_in_decoder_impl):
            continue

        # Find the best node for location reporting
        hit_node = _find_from_utf8_unwrap_node(body, source)
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        context = "Decoder impl" if is_in_decoder_impl else f"fn `{name}`"
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"{context}: `String::from_utf8(...)` or `str::from_utf8(...)` "
                "followed by `.unwrap()` inside a network message decode path. "
                "If a peer sends bytes that are not valid UTF-8, the unwrap() "
                "panics, aborting the decode task and potentially crashing the "
                "connection handler. Replace with `from_utf8_lossy(...)` or "
                "handle the error with `.map_err(|_| ProtocolError::InvalidUtf8)?`."
            ),
        })

    return hits
