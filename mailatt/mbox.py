"""Byte-exact mbox container splitting with explicit dialect rules.

Supported dialects (selected per source, never guessed):

* ``mboxo``    - envelope ``From `` lines delimit messages; body lines of the
                 form ``>*From `` are unescaped by removing one ``>``.  Bare
                 ``From `` body lines are not protected by this dialect and
                 may be misread as boundaries (a known mboxo limitation).
* ``mboxrd``   - same boundary and unescape rules as ``mboxo``; the writer is
                 expected to have escaped every body ``From `` line, so an
                 unescaped envelope-shaped line is trusted as a boundary.
* ``mboxcl``   - ``mboxo`` unescaping, but boundaries are proven by the
                 ``Content-Length`` header instead of envelope scanning.
* ``mboxcl2``  - ``Content-Length`` boundaries with no ``>`` unescaping.

A message is committed only when its boundary is proven by the declared
dialect.  Regions that cannot be proven are returned as quarantine segments:
``strict`` mode stops at the first ambiguity and isolates the rest of the
container, while ``recover`` mode resumes at the next boundary that proves
itself through dialect evidence (a valid envelope whose trusted
``Content-Length`` lands exactly on another envelope or the end of the
container).  Ambiguous bytes are never merged into a neighbouring message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from .util import sha256_bytes

MBOX_DIALECTS = ("mboxo", "mboxrd", "mboxcl", "mboxcl2")
MBOX_MODES = ("strict", "recover")
_CONTENT_LENGTH_DIALECTS = ("mboxcl", "mboxcl2")

# A legal envelope line: "From <sender> <ctime date>", e.g.
# "From alice@demo.invalid Mon Jan 01 00:00:00 2024".  Anything shorter or
# looser (a bare "From " line, a missing weekday) is body text, not a boundary.
_ENVELOPE_RE = re.compile(
    rb"From [^\s]+ (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    rb"[ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}(?: [+-][0-9]{4})? [0-9]{4}"
)

# RFC 5322 field name: printable ASCII except ':'.
_HEADER_NAME_RE = re.compile(rb"^[!-9;-~]+:")

# One leading ">" is removed only when the remainder is ">*From ".
_FROM_ESCAPE_RE = re.compile(rb"^>(?=>*From )")

SEGMENT_REASONS = (
    "missing_envelope",
    "headers_malformed",
    "content_length_missing",
    "content_length_mismatch",
)

_REASON_TEXT = {
    "missing_envelope": "expected an envelope 'From ' line",
    "headers_malformed": "header block is malformed or unterminated",
    "content_length_missing": "dialect requires a valid Content-Length header",
    "content_length_mismatch": "Content-Length does not end at an envelope or end of container",
}


@dataclass(frozen=True)
class MboxMessageSlice:
    """One proven message inside a container."""

    ordinal: int  # 1-based stream position, shared with quarantine segments
    offset: int  # byte offset of the message bytes (after the envelope line)
    length: int  # raw byte length of the message inside the container
    envelope_offset: int  # byte offset of the envelope "From " line
    digest: str  # sha256 of the unescaped message bytes


@dataclass(frozen=True)
class MboxSegment:
    """A container region that could not be proven and was quarantined."""

    ordinal: int  # 1-based stream position, shared with message slices
    offset: int  # byte offset where the unproven region starts
    length: int  # raw byte length of the region
    reason: str  # one of SEGMENT_REASONS
    detail: str  # stable human-readable explanation (includes the mode)
    digest: str  # sha256 of the raw segment bytes


@dataclass(frozen=True)
class MboxScan:
    messages: tuple[MboxMessageSlice, ...]
    segments: tuple[MboxSegment, ...]


def _line_at(data: bytes, offset: int) -> tuple[bytes, int]:
    """Return (content, next_offset) for the LF-delimited line at offset.

    A trailing CR is treated as part of the line terminator, so LF and CRLF
    containers are both handled without rewriting any content bytes.
    """
    newline = data.find(b"\n", offset)
    if newline < 0:
        content = data[offset:]
        next_offset = len(data)
    else:
        content = data[offset:newline]
        next_offset = newline + 1
    if content.endswith(b"\r"):
        content = content[:-1]
    return content, next_offset


def _iter_lines(data: bytes, start: int = 0) -> Iterator[tuple[int, bytes, int]]:
    """Yield (offset, content, next_offset) for each line from ``start``."""
    pos = start
    end = len(data)
    while pos < end:
        content, next_offset = _line_at(data, pos)
        yield pos, content, next_offset
        pos = next_offset


def _is_envelope(content: bytes) -> bool:
    return bool(_ENVELOPE_RE.fullmatch(content))


def _envelope_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(data):
        return False
    content, _next = _line_at(data, offset)
    return _is_envelope(content)


def unescape_message(data: bytes, dialect: str) -> bytes:
    """Reverse the declared dialect's ``>`` escaping of body ``From `` lines.

    Only lines of the form ``>*From `` lose exactly one leading ``>``; every
    other byte, including LF/CRLF terminators, is preserved.  ``mboxcl2``
    performs no unescaping because its writers never escape.  No heuristic
    rewriting is applied: anything the declared dialect did not escape is
    returned byte-for-byte.
    """
    if dialect not in MBOX_DIALECTS:
        raise ValueError(f"unknown mbox dialect: {dialect}")
    if dialect == "mboxcl2":
        return data
    parts: list[bytes] = []
    pos = 0
    end = len(data)
    while pos < end:
        newline = data.find(b"\n", pos)
        if newline < 0:
            parts.append(_FROM_ESCAPE_RE.sub(b"", data[pos:], count=1))
            break
        content = data[pos:newline]
        terminator = b"\n"
        if content.endswith(b"\r"):
            content, terminator = content[:-1], b"\r\n"
        parts.append(_FROM_ESCAPE_RE.sub(b"", content, count=1) + terminator)
        pos = newline + 1
    return b"".join(parts)


@dataclass(frozen=True)
class _Headers:
    ok: bool
    end: int = 0  # offset of the first body byte (after the blank line)
    content_length: int | None = None


def _parse_headers(data: bytes, start: int) -> _Headers:
    """Parse the header block beginning at ``start`` (after the envelope)."""
    content_length: int | None = None
    saw_header = False
    for _offset, content, next_offset in _iter_lines(data, start):
        if content == b"":
            return _Headers(ok=True, end=next_offset, content_length=content_length)
        if content[:1] in (b" ", b"\t"):
            if not saw_header:
                return _Headers(ok=False)
            continue
        if not _HEADER_NAME_RE.match(content):
            return _Headers(ok=False)
        saw_header = True
        name, _colon, value = content.partition(b":")
        if name.strip().lower() == b"content-length":
            value = value.strip()
            content_length = int(value) if value.isdigit() else None
    return _Headers(ok=False)  # EOF before the blank line


def _cl_boundary(data: bytes, header_start: int) -> tuple[tuple[int, int] | None, str]:
    """Prove a Content-Length boundary.

    Return ``((message_end, next_offset), "")`` when the declared body length
    lands exactly on the next envelope (optionally after one blank separator
    line) or on the end of the container; otherwise ``(None, reason)``.
    """
    headers = _parse_headers(data, header_start)
    if not headers.ok:
        return None, "headers_malformed"
    if headers.content_length is None:
        return None, "content_length_missing"
    landing = headers.end + headers.content_length
    if landing > len(data):
        return None, "content_length_mismatch"
    if landing == len(data):
        return (landing, landing), ""
    content, next_offset = _line_at(data, landing)
    if _is_envelope(content):
        return (landing, landing), ""
    if content == b"":
        # One optional blank separator line before the next envelope.
        if next_offset >= len(data):
            return (landing, len(data)), ""
        if _envelope_at(data, next_offset):
            return (landing, next_offset), ""
    return None, "content_length_mismatch"


def _find_next_envelope(data: bytes, start: int) -> int:
    for offset, content, _next in _iter_lines(data, start):
        if _is_envelope(content):
            return offset
    return len(data)


def _trim_separator(raw: bytes) -> bytes:
    """Drop trailing blank lines that act as separators before an envelope."""
    while raw.endswith(b"\n"):
        prev = raw.rfind(b"\n", 0, len(raw) - 1)
        line = raw[prev + 1 :]
        content = line[:-1]
        if content.endswith(b"\r"):
            content = content[:-1]
        if content:
            break
        raw = raw[: prev + 1]
    return raw


def _proven_boundary(data: bytes, offset: int, dialect: str) -> bool:
    """Dialect evidence that the envelope at ``offset`` starts a real message."""
    content, header_start = _line_at(data, offset)
    if not _is_envelope(content):
        return False
    if dialect in _CONTENT_LENGTH_DIALECTS:
        boundary, _reason = _cl_boundary(data, header_start)
        return boundary is not None
    # mboxo/mboxrd: a syntactically valid envelope line is decisive.
    return True


def _recover(data: bytes, start: int, dialect: str) -> int | None:
    """Find the next self-proving boundary at or after ``start``."""
    for offset, content, _next in _iter_lines(data, start):
        if _is_envelope(content) and _proven_boundary(data, offset, dialect):
            return offset
    return None


def _segment_detail(mode: str, offset: int, length: int, reason: str, *, resumed: bool) -> str:
    text = _REASON_TEXT.get(reason, reason)
    if mode == "strict":
        return (
            f"strict mode stopped at ambiguous boundary (byte {offset}: {text}); "
            f"quarantined {length} bytes to end of container"
        )
    if resumed:
        return (
            f"recover mode kept ambiguous region (byte {offset}: {text}); "
            f"quarantined {length} bytes and continued with proven suffix"
        )
    return (
        f"recover mode kept ambiguous region (byte {offset}: {text}); "
        f"quarantined {length} bytes to end of container"
    )


def split_mbox(data: bytes, dialect: str, mode: str = "strict") -> MboxScan:
    """Split a container into proven message slices and quarantine segments.

    Message slices carry byte offsets into the container and a digest of the
    unescaped message bytes.  Segments cover every byte that could not be
    proven; they are never merged into a neighbouring message body.
    """
    if dialect not in MBOX_DIALECTS:
        raise ValueError(f"unknown mbox dialect: {dialect}")
    if mode not in MBOX_MODES:
        raise ValueError(f"unknown mbox mode: {mode}")
    messages: list[MboxMessageSlice] = []
    segments: list[MboxSegment] = []
    ordinal = 0
    pos = 0
    end = len(data)

    def quarantine(start: int, stop: int, reason: str) -> None:
        nonlocal ordinal
        ordinal += 1
        segments.append(
            MboxSegment(
                ordinal=ordinal,
                offset=start,
                length=stop - start,
                reason=reason,
                detail=_segment_detail(mode, start, stop - start, reason, resumed=stop < end),
                digest=sha256_bytes(data[start:stop]),
            )
        )

    while pos < end:
        content, header_start = _line_at(data, pos)
        reason = ""
        boundary: tuple[int, int] | None = None  # (message_end, next_offset)
        if not _is_envelope(content):
            reason = "missing_envelope"
        elif dialect in _CONTENT_LENGTH_DIALECTS:
            boundary, reason = _cl_boundary(data, header_start)
        else:
            next_offset = _find_next_envelope(data, header_start)
            boundary = (next_offset, next_offset)
        if boundary is None:
            # The boundary cannot be proven from dialect evidence: never guess
            # a split.  Strict mode isolates the rest of the container;
            # recover mode isolates only up to the next self-proving boundary.
            if mode == "strict":
                quarantine(pos, end, reason)
                break
            resume = _recover(data, header_start, dialect)
            if resume is None:
                quarantine(pos, end, reason)
                break
            quarantine(pos, resume, reason)
            pos = resume
            continue
        message_end, next_offset = boundary
        raw = data[header_start:message_end]
        if dialect not in _CONTENT_LENGTH_DIALECTS:
            raw = _trim_separator(raw)
        ordinal += 1
        messages.append(
            MboxMessageSlice(
                ordinal=ordinal,
                offset=header_start,
                length=len(raw),
                envelope_offset=pos,
                digest=sha256_bytes(unescape_message(raw, dialect)),
            )
        )
        pos = next_offset
    return MboxScan(messages=tuple(messages), segments=tuple(segments))
