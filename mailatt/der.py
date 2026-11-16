"""Minimal, bounded DER reader used for offline CMS/S/MIME verification.

The project deliberately avoids a full ASN.1 implementation.  Only the small
subset needed to inspect a CMS SignedData structure is supported, and every
length is checked against the remaining buffer before it is used.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_DER_DEPTH = 40


class DerError(ValueError):
    """Raised when an input is not a well-formed, bounded DER value."""


@dataclass(frozen=True)
class Der:
    tag: int
    header: bytes
    value: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> tuple["Der", ...]:
        if not self.constructed:
            raise DerError("value is not constructed")
        return parse_children(self.value)

    def as_oid(self) -> str:
        if self.tag != 0x06:
            raise DerError("value is not an OID")
        return decode_oid(self.value)

    def as_integer(self) -> int:
        if self.tag != 0x02:
            raise DerError("value is not an INTEGER")
        if not self.value:
            raise DerError("empty INTEGER")
        return int.from_bytes(self.value, "big", signed=False)

    def as_octets(self) -> bytes:
        if self.tag != 0x04:
            raise DerError("value is not an OCTET STRING")
        return self.value


def read_tlv(data: bytes, offset: int = 0) -> tuple[Der, int]:
    """Read one DER TLV at *offset* and return it with the next offset."""
    start = offset
    total = len(data)
    if offset < 0 or offset >= total:
        raise DerError("truncated DER value")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form is not supported")
    if offset >= total:
        raise DerError("truncated DER length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise DerError("indefinite length is not supported")
        if count > 4:
            raise DerError("DER length is too large")
        if offset + count > total:
            raise DerError("truncated DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    if length > total - offset:
        raise DerError("DER value exceeds input")
    end = offset + length
    return Der(tag=tag, header=data[start:offset], value=data[offset:end], raw=data[start:end]), end


def parse_children(value: bytes) -> tuple[Der, ...]:
    return parse_all(value)


def parse_all(data: bytes, *, _depth: int = 0) -> tuple[Der, ...]:
    if _depth > MAX_DER_DEPTH:
        raise DerError("DER nesting is too deep")
    found: list[Der] = []
    offset = 0
    while offset < len(data):
        item, offset = read_tlv(data, offset)
        found.append(item)
    return tuple(found)


def decode_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    parts = [value[0] // 40, value[0] % 40]
    accumulator = 0
    pending = False
    for byte in value[1:]:
        accumulator = (accumulator << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            parts.append(accumulator)
            accumulator = 0
    if pending:
        raise DerError("truncated OID")
    return ".".join(str(item) for item in parts)


def decode_auto(value: bytes) -> Der:
    item, end = read_tlv(value, 0)
    if end != len(value):
        raise DerError("trailing bytes after DER value")
    return item
