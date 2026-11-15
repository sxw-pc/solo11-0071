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
from .models import AttachmentCandidate, ParsedMessage, RelatedReferenceIssue, RelatedRetention
from .related import (
    ISSUE_BOUNDARY_DAMAGED,
    RELATED_TYPE,
    child_path,
    content_id_of,
    display_path,
    is_inline_resource,
    normalize_retention,
    path_sort_key,
    resolve_related_container,
    resource_filename,
)
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
    related_retention: str = RelatedRetention.BODY_DEPENDENCY.value


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


def _collect_defect_pairs(part: Message) -> list[tuple[Message, object]]:
    found = [(part, item) for item in _defects(part)]
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for child in payload:
                if isinstance(child, Message):
                    found.extend(_collect_defect_pairs(child))
    return found


def _related_boundary_damaged(part: Message) -> bool:
    """True when this related container cannot be parsed reliably."""
    return part.get_content_type().lower() == RELATED_TYPE and any(
        isinstance(item, FATAL_DEFECTS) for item in _defects(part)
    )


def _is_attachment(part: Message) -> bool:
    filename = None
    try:
        filename = part.get_filename()
    except Exception:
        filename = None
    disposition = part.get_content_disposition()
    return bool(filename) or disposition == "attachment"


def _filename(part: Message, part_id: str) -> str:
    return _filename_or_none(part) or f"attachment-{part_id}.bin"


def _filename_or_none(part: Message) -> str:
    try:
        raw = part.get_filename()
    except Exception:
        raw = None
    return decode_header_value(raw) if raw else ""


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
        self.related_issues: list[RelatedReferenceIssue] = []
        self.warnings: list[str] = []
        self.counter = 0
        self.relations: dict[str, object] = {}
        self.inline_paths: set[str] = set()
        self.resource_paths: set[str] = set()
        try:
            self.retention = normalize_retention(options.related_retention)
        except ValueError as exc:
            raise MimeParseError(str(exc), code="MALFORMED_MIME") from exc

    def index_related(self, part: Message, path: str = "") -> None:
        """Resolve every related container before walking, one scope at a time."""
        ctype = part.get_content_type().lower()
        if ctype == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list):
                for index, nested in enumerate(
                    (item for item in payload if isinstance(item, Message)), 1
                ):
                    self.index_related(nested, child_path(path, index))
            return
        if ctype == RELATED_TYPE and _related_boundary_damaged(part):
            # A damaged related container is isolated: its structure cannot be
            # trusted, so no Content-ID binding is inferred from it.  Such a
            # part is often no longer ``is_multipart()``.
            self.related_issues.append(
                RelatedReferenceIssue(
                    code=ISSUE_BOUNDARY_DAMAGED,
                    related_path=path or "/",
                    detail="multipart/related boundary is missing or malformed",
                )
            )
            return
        if not part.is_multipart():
            return
        if ctype == RELATED_TYPE:
            resolution = resolve_related_container(part, path, self.retention)
            for relation in resolution.relations:
                self.relations.setdefault(relation.part_path, relation)
            for resource in resolution.resources:
                self.inline_paths.add(resource.part_path)
            for relation in resolution.relations:
                if relation.is_resource:
                    self.resource_paths.add(relation.part_path)
            self.related_issues.extend(resolution.issues)
        payload = part.get_payload()
        if isinstance(payload, list):
            for index, child in enumerate(
                (item for item in payload if isinstance(item, Message)), 1
            ):
                self.index_related(child, child_path(path, index))

    def _relation(self, path: str):
        return self.relations.get(path)

    def _annotate(self, path: str) -> dict[str, object]:
        relation = self._relation(path)
        if relation is None:
            return {}
        return {
            "related_root_path": relation.root_path,
            "related_part_path": relation.part_path,
            "related_container_path": display_path(relation.container_path),
            "content_id": relation.content_id,
            "reference_count": relation.reference_count,
            "related_status": relation.status,
            "related_issue_codes": tuple(sorted(relation.issue_codes)),
        }

    def _emit(self, part: Message, path: str, nested_depth: int, *, inline_only: bool) -> None:
        self.counter += 1
        part_id = f"p{self.counter:03d}"
        ctype = part.get_content_type().lower()
        if inline_only:
            declared = _filename_or_none(part)
            filename = declared or resource_filename(part, part_id)
            disposition = part.get_content_disposition() or "inline"
        else:
            filename = _filename(part, part_id)
            disposition = part.get_content_disposition() or ""
        safe_name = sanitize_filename(filename, max_length=self.options.max_filename_length)
        payload = _payload_bytes(part)
        self.candidates.append(
            AttachmentCandidate(
                part_id=part_id,
                filename=filename,
                safe_filename=safe_name,
                media_type=ctype,
                disposition=disposition,
                size=len(payload),
                sha256=sha256_bytes(payload),
                payload=payload,
                nested_depth=nested_depth,
                traversal_detected=detect_path_traversal(filename),
                warnings=tuple(sorted({type(item).__name__ for item in _defects(part)})),
                related_inline_only=inline_only,
                **self._annotate(path),
            )
        )

    def _emit_orphan_inline(
        self, part: Message, path: str, nested_depth: int
    ) -> None:
        """Full-forensics only: keep an inline part outside any related container."""
        self.counter += 1
        part_id = f"p{self.counter:03d}"
        ctype = part.get_content_type().lower()
        declared = _filename_or_none(part)
        filename = declared or resource_filename(part, part_id)
        safe_name = sanitize_filename(filename, max_length=self.options.max_filename_length)
        payload = _payload_bytes(part)
        self.candidates.append(
            AttachmentCandidate(
                part_id=part_id,
                filename=filename,
                safe_filename=safe_name,
                media_type=ctype,
                disposition=part.get_content_disposition() or "inline",
                size=len(payload),
                sha256=sha256_bytes(payload),
                payload=payload,
                nested_depth=nested_depth,
                traversal_detected=detect_path_traversal(filename),
                warnings=tuple(sorted({type(item).__name__ for item in _defects(part)})),
                related_inline_only=True,
                content_id=content_id_of(part),
                related_status="unreferenced",
            )
        )

    def walk(self, part: Message, nested_depth: int = 0, path: str = "") -> None:
        ctype = part.get_content_type().lower()
        if ctype == "message/rfc822":
            self._walk_nested(part, nested_depth, path)
            return
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for index, child in enumerate(
                    (item for item in payload if isinstance(item, Message)), 1
                ):
                    self.walk(child, nested_depth, child_path(path, index))
            return
        if path in self.inline_paths:
            self._emit(part, path, nested_depth, inline_only=True)
            return
        if path in self.resource_paths:
            # An inline body resource deliberately not retained by this strategy.
            return
        if not _is_attachment(part):
            if self.retention == "full-forensics" and is_inline_resource(part):
                self._emit_orphan_inline(part, path, nested_depth)
            return
        self._emit(part, path, nested_depth, inline_only=False)

    def _walk_nested(self, part: Message, nested_depth: int, path: str = "") -> None:
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
        for index, nested in enumerate(
            (item for item in payload if isinstance(item, Message)), 1
        ):
            self.walk(nested, nested_depth + 1, child_path(path, index))


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
    fatal = [
        item
        for owner, item in _collect_defect_pairs(message)
        if isinstance(item, FATAL_DEFECTS) and not _related_boundary_damaged(owner)
    ]
    if fatal:
        names = ", ".join(sorted({type(item).__name__ for item in fatal}))
        raise MimeParseError(f"fatal MIME defects: {names}", code="MALFORMED_MIME")

    collector = _Collector(options)
    try:
        collector.index_related(message)
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
    issues = sorted(
        set(collector.related_issues),
        key=lambda item: (
            path_sort_key(item.related_path),
            item.code,
            path_sort_key(item.root_path),
            item.content_id,
            tuple(path_sort_key(path) for path in item.part_paths),
            item.detail,
        ),
    )
    return ParsedMessage(
        message_id=_message_id(message),
        subject=_subject(message),
        sender=_sender(message),
        sent_at=_sent_at(message),
        candidates=tuple(collector.candidates),
        warnings=tuple(sorted(warnings)),
        related_issues=tuple(issues),
    )
