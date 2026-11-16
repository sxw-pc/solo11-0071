"""Raw-byte extraction of ``multipart/signed`` layers from an .eml snapshot.

The standard library parser normalises some line endings and does not expose
the exact octets that a signature covers.  This module therefore walks the raw
snapshot with a small, defensive boundary scanner and keeps offset ranges: the
signed content bytes and the detached signature part.  Nested signed layers
(for example a signed part inside ``multipart/mixed``) are found by recursing
through raw multipart children.

The scanner never trusts MIME semantics beyond what it can delimit
unambiguously.  If delimiters cannot be located the caller is told the material
is unverifiable, never that it is valid.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser

from .models import SignatureEvidence
from .signature import (
    SignedLayer,
    aggregate_evidence,
    not_signed_evidence,
    unparsable_evidence,
    verify_layer,
)

MAX_HEADER_BYTES = 256 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
MAX_SIGNED_LAYERS = 8
MAX_MIME_DEPTH = 10
MAX_PARTS = 200

SIGNED_TYPES = {"multipart/signed"}
SIGNATURE_PROTOCOLS = {
    "application/pkcs7-signature",
    "application/x-pkcs7-signature",
    "application/pkcs7-mime",
    "application/x-pkcs7-mime",
}
MULTIPART_TYPES = {
    "multipart/mixed",
    "multipart/alternative",
    "multipart/related",
    "multipart/report",
    "multipart/digest",
    "multipart/parallel",
}


@dataclass(frozen=True)
class RawDiagnostics:
    """Structural facts recorded alongside the verdict for audit."""

    layer_count: int = 0
    first_problem: str = ""
    signature_part_size: int = 0
    nested: bool = False


def _parser(headers: bytes):
    return BytesParser(policy=email_policy.default).parsebytes(headers + b"\r\n\r\n")


def _split_head(data: bytes) -> tuple[bytes, bytes, int] | None:
    """Return (headers, body, body_offset) after the first blank line."""
    match = re.search(rb"\r?\n\r?\n", data)
    if match is None or match.start() > MAX_HEADER_BYTES:
        return None
    return data[: match.start()], data[match.end():], match.end()


def _headers(data: bytes) -> tuple[bytes, bytes, int] | None:
    return _split_head(data)


def _content_type(headers: bytes) -> str:
    try:
        return _parser(headers).get_content_type().lower()
    except Exception:
        return ""


def _boundary(headers: bytes) -> bytes | None:
    try:
        boundary = _parser(headers).get_boundary()
    except Exception:
        return None
    if not boundary or len(boundary) > 200:
        return None
    try:
        return boundary.encode("ascii")
    except UnicodeEncodeError:
        return None


def _delimiter_pattern(boundary: bytes) -> re.Pattern[bytes]:
    return re.compile(
        rb"(?:(?<=\n)|(?<=\r)|^)--" + re.escape(boundary) + rb"(--)?[ \t]*(?:\r\n|\n|\r|$)"
    )


def _strip_final_break(data: bytes) -> bytes:
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n") or data.endswith(b"\r"):
        return data[:-1]
    return data


def _micalg(headers: bytes) -> str:
    try:
        value = _parser(headers).get_param("micalg", header="content-type")
    except Exception:
        return ""
    return str(value or "").strip()


def _signature_payload(part_bytes: bytes) -> tuple[bytes, str, str]:
    """Decode the detached signature part; return bytes, protocol, problem."""
    split = _split_head(part_bytes)
    if split is None:
        return b"", "", "signature_part_headers_missing"
    _, body, _ = split
    try:
        part = BytesParser(policy=email_policy.default).parsebytes(part_bytes)
    except Exception:
        return b"", "", "signature_part_unparsable"
    protocol = part.get_content_type().lower()
    if protocol not in SIGNATURE_PROTOCOLS:
        return b"", protocol, f"signature_protocol_unsupported:{protocol}"
    encoding = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    body = body.strip(b"\r\n")
    if encoding in ("", "7bit", "8bit", "binary"):
        payload = body
    elif encoding == "base64":
        compact = re.sub(rb"[ \t\r\n]", b"", body)
        try:
            payload = base64.b64decode(compact, validate=True)
        except ValueError:
            return b"", protocol, "signature_base64_invalid"
    else:
        return b"", protocol, f"signature_encoding_unsupported:{encoding}"
    if not payload:
        return b"", protocol, "signature_material_missing"
    if len(payload) > MAX_SIGNATURE_BYTES:
        return b"", protocol, "signature_material_too_large"
    return payload, protocol, ""


def _split_parts(headers: bytes, body: bytes) -> list[bytes] | None:
    """Split a raw multipart body into child part ranges (including headers)."""
    boundary = _boundary(headers)
    if boundary is None:
        return None
    pattern = _delimiter_pattern(boundary)
    matches = list(pattern.finditer(body))
    if len(matches) < 2:
        return None
    closing = [item for item in matches if item.group(1)]
    if not closing:
        return None
    final_index = matches.index(closing[0])
    if final_index < 2:
        return None
    parts: list[bytes] = []
    previous = matches[0]
    if previous.group(1):
        return None
    for current in matches[1:final_index + 1]:
        parts.append(_strip_final_break(body[previous.end():current.start()]))
        if current.group(1):
            break
        previous = current
    return parts


def _signed_layer(headers: bytes, body: bytes) -> tuple[SignedLayer | None, RawDiagnostics]:
    boundary = _boundary(headers)
    if boundary is None:
        return None, RawDiagnostics(layer_count=1, first_problem="signed_boundary_missing")
    pattern = _delimiter_pattern(boundary)
    matches = list(pattern.finditer(body))
    if not matches:
        return None, RawDiagnostics(layer_count=1, first_problem="signed_boundary_unresolved")
    closing = [index for index, item in enumerate(matches) if item.group(1)]
    if not closing:
        return None, RawDiagnostics(layer_count=1, first_problem="signed_boundary_unterminated")
    close_index = closing[0]
    if close_index < 2:
        return None, RawDiagnostics(layer_count=1, first_problem="signed_boundary_unresolved")
    opening = matches[:close_index]
    if len(opening) != 2:
        # RFC 1847 requires exactly two body parts: signed content and
        # signature.  Extra delimited parts would be silently unverified.
        return None, RawDiagnostics(
            layer_count=1, first_problem="signed_layer_has_extra_parts"
        )
    first, second, final = opening[0], opening[1], matches[close_index]
    if first.group(1) or second.group(1):
        return None, RawDiagnostics(layer_count=1, first_problem="signed_boundary_misordered")
    content = _strip_final_break(body[first.end():second.start()])
    signature_bytes, protocol, problem = _signature_payload(body[second.end():final.start()])
    if problem:
        return None, RawDiagnostics(
            layer_count=1,
            first_problem=problem,
            signature_part_size=final.start() - second.end(),
        )
    return (
        SignedLayer(
            content=content,
            signature=signature_bytes,
            protocol=protocol,
            micalg=_micalg(headers),
        ),
        RawDiagnostics(layer_count=1, signature_part_size=len(signature_bytes)),
    )


def _walk(data: bytes, depth: int, state: dict[str, object]) -> None:
    if depth > MAX_MIME_DEPTH or int(state["parts"]) > MAX_PARTS:
        return
    split = _split_head(data)
    if split is None:
        return
    headers, body, _ = split
    ctype = _content_type(headers)
    if ctype in SIGNED_TYPES:
        layers = state["layers"]
        diagnostics = state["diagnostics"]
        assert isinstance(layers, list) and isinstance(diagnostics, list)
        if len(layers) >= MAX_SIGNED_LAYERS:
            return
        layer, found = _signed_layer(headers, body)
        state["seen_signed"] = True
        if layer is None:
            diagnostics.append(
                RawDiagnostics(
                    layer_count=int(state["count"]) + 1,
                    first_problem=found.first_problem,
                    signature_part_size=found.signature_part_size,
                    nested=depth > 0,
                )
            )
            return
        layers.append(layer)
        diagnostics.append(
            RawDiagnostics(
                layer_count=int(state["count"]) + 1,
                signature_part_size=found.signature_part_size,
                nested=depth > 0,
            )
        )
        # The signed content may itself contain attachments; keep walking it.
        inner = _split_head(layer.content)
        if inner is not None and _content_type(inner[0]) in MULTIPART_TYPES:
            state["count"] = int(state["count"]) + 1
            _walk(layer.content, depth + 1, state)
            state["count"] = int(state["count"]) - 1
        return
    if ctype in MULTIPART_TYPES:
        children = _split_parts(headers, body)
        if children is None:
            return
        state["count"] = int(state["count"]) + 1
        for child in children:
            if int(state["parts"]) > MAX_PARTS:
                break
            state["parts"] = int(state["parts"]) + 1
            _walk(child, depth + 1, state)
        state["count"] = int(state["count"]) - 1


def raw_signed_layers(data: bytes) -> tuple[list[SignedLayer], RawDiagnostics]:
    """Locate every ``multipart/signed`` layer in the raw snapshot."""
    layers: list[SignedLayer] = []
    diagnostics: list[RawDiagnostics] = []
    state: dict[str, object] = {
        "layers": layers,
        "diagnostics": diagnostics,
        "seen_signed": False,
        "count": 0,
        "parts": 0,
    }
    _walk(data, 0, state)
    if not layers and not diagnostics:
        return [], RawDiagnostics()
    problem = next((item.first_problem for item in diagnostics if item.first_problem), "")
    return (
        layers,
        RawDiagnostics(
            layer_count=max(len(layers), len(diagnostics)),
            first_problem=problem,
            signature_part_size=max((item.signature_part_size for item in diagnostics), default=0),
            nested=any(item.nested for item in diagnostics),
        ),
    )


def verify_from_raw(
    data: bytes,
    trust: object,
    moment: object,
) -> tuple[SignatureEvidence, RawDiagnostics]:
    """Split and verify all signed layers in one pass, fully offline."""
    layers, diagnostics = raw_signed_layers(data)
    if not layers:
        if diagnostics.layer_count:
            base = unparsable_evidence()
            return (
                SignatureEvidence(
                    integrity=base.integrity,
                    trust=base.trust,
                    reason_code=diagnostics.first_problem or base.reason_code,
                    reason="signed MIME layer could not be delimited from raw bytes",
                    layer_count=diagnostics.layer_count,
                ),
                diagnostics,
            )
        return not_signed_evidence(), diagnostics
    evidence_items = [verify_layer(layer, trust, moment) for layer in layers]
    # Every declared layer must be accounted for.  A layer that was found but
    # could not be delimited is unverifiable evidence, not something to drop.
    if diagnostics.first_problem:
        evidence_items.append(
            SignatureEvidence(
                integrity=unparsable_evidence().integrity,
                trust=unparsable_evidence().trust,
                reason_code=diagnostics.first_problem,
                reason="a multipart/signed layer could not be delimited from raw bytes",
            )
        )
    evidence = aggregate_evidence(
        evidence_items,
        layer_count=max(len(layers), diagnostics.layer_count),
    )
    return evidence, diagnostics
