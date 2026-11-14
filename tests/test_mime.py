from __future__ import annotations

import pytest

from mailatt.errors import MimeParseError
from mailatt.mime import MimeOptions, parse_message
from mailatt.util import sha256_bytes

from conftest import FIXTURES


def fixture_bytes(relative: str) -> bytes:
    return (FIXTURES / relative).read_bytes()


def test_multipart_extracts_attachments_only() -> None:
    parsed = parse_message(fixture_bytes("maildir/cur/0001.report"))
    assert parsed.subject == "Quarterly package"
    assert parsed.message_id == "q1-0001@demo.invalid"
    assert parsed.sender.endswith("<analyst@demo.invalid>")
    assert [item.safe_filename for item in parsed.candidates] == [
        "quarterly-report.pdf",
        "signals.csv",
    ]
    assert [item.media_type for item in parsed.candidates] == ["application/pdf", "text/csv"]
    assert [item.part_id for item in parsed.candidates] == ["p001", "p002"]
    assert parsed.candidates[0].sha256 == sha256_bytes(parsed.candidates[0].payload)


def test_rfc2047_filename_is_decoded() -> None:
    parsed = parse_message(fixture_bytes("eml/rfc2047.eml"))
    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].filename == "月度报表.txt"
    assert parsed.candidates[0].safe_filename == "月度报表.txt"
    assert parsed.candidates[0].media_type == "text/plain"


def test_rfc2047_subject_and_date_are_normalized() -> None:
    parsed = parse_message(fixture_bytes("maildir/cur/0002.encoded"))
    assert parsed.subject == "月度通知"
    assert parsed.sent_at == "2023-01-02T09:31:00+00:00"
    assert parsed.candidates[0].filename == "月度报表.txt"


def test_nested_message_is_walked() -> None:
    parsed = parse_message(fixture_bytes("maildir/new/0005.nested"))
    assert [item.safe_filename for item in parsed.candidates] == ["nested-note.txt"]
    assert parsed.candidates[0].nested_depth == 1


def test_nested_depth_limit_produces_warning() -> None:
    parsed = parse_message(
        fixture_bytes("maildir/new/0005.nested"),
        MimeOptions(max_nested_depth=0),
    )
    assert parsed.candidates == ()
    assert "nested_message_depth_exceeded" in parsed.warnings


def test_path_traversal_is_flagged_and_name_sanitized() -> None:
    parsed = parse_message(fixture_bytes("maildir/cur/0003.suspicious"))
    assert parsed.candidates[0].safe_filename == "invoice.exe"
    escaped = parsed.candidates[1]
    assert escaped.filename == "../../escape.txt"
    assert escaped.safe_filename == "escape.txt"
    assert escaped.traversal_detected is True


def test_empty_message_has_stable_error() -> None:
    with pytest.raises(MimeParseError) as caught:
        parse_message(b"")
    assert caught.value.code == "EMPTY_MESSAGE"


def test_broken_multipart_has_stable_error() -> None:
    with pytest.raises(MimeParseError) as caught:
        parse_message(fixture_bytes("bad/broken-multipart.eml"))
    assert caught.value.code == "MALFORMED_MIME"
    assert "Boundary" in caught.value.detail


def test_no_attachment_message_is_ok() -> None:
    parsed = parse_message(fixture_bytes("eml/no-attachment.eml"))
    assert parsed.candidates == ()
    assert parsed.subject == "No attachment"


def test_inline_attachment_is_detected() -> None:
    parsed = parse_message(fixture_bytes("maildir/new/0006.inline"))
    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].disposition == "inline"
    assert parsed.candidates[0].media_type == "image/png"


def test_unsafe_filename_characters_are_sanitized() -> None:
    raw = b"""From: demo@demo.invalid
To: archive@demo.invalid
Subject: Unsafe name
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

body
--b
Content-Type: text/plain
Content-Disposition: attachment; filename="report?.txt"
Content-Transfer-Encoding: 7bit

payload
--b--
"""
    parsed = parse_message(raw)
    assert parsed.candidates[0].safe_filename == "report_.txt"
    assert parsed.candidates[0].filename == "report?.txt"


def test_attachment_without_filename_gets_fallback() -> None:
    raw = b"""From: demo@demo.invalid
To: archive@demo.invalid
Subject: No name
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: application/octet-stream
Content-Disposition: attachment

payload
--b--
"""
    parsed = parse_message(raw)
    assert parsed.candidates[0].safe_filename == "attachment-p001.bin"


