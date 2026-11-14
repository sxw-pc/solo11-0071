"""Defensive MIME parsing and attachment candidate extraction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from email import policy as email_policy
from email.errors import (
    CloseBoundaryNotFoundDefect,
    MultipartInvariantViolationDefect,
    StartBoundaryNotFoundDefect,
)
from email.message import Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from .errors import MimeParseError
from .models import AttachmentCandidate, ParsedMessage
from .util import (
    decode_header_value,
    detect_path_traversal,
    sanitize_filename,
    sha256_bytes,
)

FATAL_DEFECTS = (
    StartBoundaryNotFoundDefect,
    CloseBoundaryNotFoundDefect,
    MultipartInvariantViolationDefect,
)


@dataclass(frozen=True)
class MimeOptions:
    allow_nested_messages: bool = True
    max_nested_depth: int = 3
    max_filename_length: int = 120


def _defects(part: Message) -> tuple[object, ...]:
    return tuple(getattr(part, "defects", ()) or ())


def _collect_defects(part: Message) -> list[object]:
    found = list(_defects(part))
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for child in payload:
                found.extend(_collect_defects(child))
    return found


def _is_attachment(part: Message) -> bool:
    filename = None
    try:
        filename = part.get_filename()
    except Exception:
        filename = None
    disposition = part.get_content_disposition()
    return bool(filename) or disposition == "attachment"


def _filename(part: Message, part_id: str) -> str:
    try:
        raw = part.get_filename()
    except Exception:
        raw = None
    decoded = decode_header_value(raw) if raw else ""
    if decoded:
        return decoded
    return f"attachment-{part_id}.bin"


def _payload_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception as exc:
        raise MimeParseError(
            f"payload decode failed: {type(exc).__name__}", code="ATTACHMENT_DECODE_FAILED"
        ) from exc
    if payload is None:
        fallback = part.get_payload()
        if isinstance(fallback, str):
            payload = fallback.encode("utf-8", errors="replace")
        elif isinstance(fallback, bytes):
            payload = fallback
        else:
            raise MimeParseError("attachment has no decodable payload", code="ATTACHMENT_DECODE_FAILED")
    return payload


class _Collector:
    def __init__(self, options: MimeOptions) -> None:
        self.options = options
        self.candidates: list[AttachmentCandidate] = []
        self.warnings: list[str] = []
        self.counter = 0

    def walk(self, part: Message, nested_depth: int = 0) -> None:
        ctype = part.get_content_type().lower()
        if ctype == "message/rfc822":
            self._walk_nested(part, nested_depth)
            return
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for child in payload:
                    self.walk(child, nested_depth)
            return
        if not _is_attachment(part):
            return
        self.counter += 1
        part_id = f"p{self.counter:03d}"
        filename = _filename(part, part_id)
        safe_name = sanitize_filename(filename, max_length=self.options.max_filename_length)
        payload = _payload_bytes(part)
        self.candidates.append(
            AttachmentCandidate(
                part_id=part_id,
                filename=filename,
                safe_filename=safe_name,
                media_type=ctype,
                disposition=part.get_content_disposition() or "",
                size=len(payload),
                sha256=sha256_bytes(payload),
                payload=payload,
                nested_depth=nested_depth,
                traversal_detected=detect_path_traversal(filename),
                warnings=tuple(sorted({type(item).__name__ for item in _defects(part)})),
            )
        )

    def _walk_nested(self, part: Message, nested_depth: int) -> None:
        if not self.options.allow_nested_messages:
            self.warnings.append("nested_message_ignored")
            return
        if nested_depth >= self.options.max_nested_depth:
            self.warnings.append("nested_message_depth_exceeded")
            return
        payload = part.get_payload()
        if not isinstance(payload, list):
            self.warnings.append("nested_message_unavailable")
            return
        for nested in payload:
            if isinstance(nested, Message):
                self.walk(nested, nested_depth + 1)


def _sender(message: Message) -> str:
    return decode_header_value(message.get("From", ""))


def _subject(message: Message) -> str:
    return decode_header_value(message.get("Subject", ""))


def _message_id(message: Message) -> str:
    return decode_header_value(message.get("Message-ID", "")).strip(" <>")[:255]


def _sent_at(message: Message) -> str:
    raw = message.get("Date")
    if not raw:
        return ""
    try:
        value = parsedate_to_datetime(str(raw))
        if value is None:
            return ""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except (TypeError, ValueError, OverflowError):
        return ""


def parse_message(data: bytes, options: MimeOptions | None = None) -> ParsedMessage:
    """Parse a raw message; malformed structure raises a stable MIME error."""
    if not data or not data.strip():
        raise MimeParseError("message file is empty", code="EMPTY_MESSAGE")
    options = options or MimeOptions()
    try:
        message = BytesParser(policy=email_policy.default).parsebytes(data)
    except Exception as exc:
        raise MimeParseError(
            f"parser rejected message: {type(exc).__name__}", code="MALFORMED_MIME"
        ) from exc

    all_defects = _collect_defects(message)
    fatal = [item for item in all_defects if isinstance(item, FATAL_DEFECTS)]
    if fatal:
        names = ", ".join(sorted({type(item).__name__ for item in fatal}))
        raise MimeParseError(f"fatal MIME defects: {names}", code="MALFORMED_MIME")

    collector = _Collector(options)
    try:
        collector.walk(message)
    except MimeParseError:
        raise
    except Exception as exc:
        raise MimeParseError(
            f"attachment extraction failed: {type(exc).__name__}", code="MALFORMED_MIME"
        ) from exc
    warnings = set(collector.warnings)
    warnings.update(
        type(item).__name__
        for item in all_defects
        if not isinstance(item, FATAL_DEFECTS)
    )
    return ParsedMessage(
        message_id=_message_id(message),
        subject=_subject(message),
        sender=_sender(message),
        sent_at=_sent_at(message),
        candidates=tuple(collector.candidates),
        warnings=tuple(sorted(warnings)),
    )
