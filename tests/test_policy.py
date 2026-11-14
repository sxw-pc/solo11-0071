from __future__ import annotations

from dataclasses import replace

from mailatt.config import PolicyConfig
from mailatt.models import AttachmentCandidate, Decision
from mailatt.policy import assess_candidates, evaluate_candidate, extension_chain
from mailatt.util import sha256_bytes


def candidate(
    filename: str,
    *,
    body: bytes = b"synthetic attachment",
    media_type: str = "text/plain",
    disposition: str = "attachment",
    traversal: bool = False,
) -> AttachmentCandidate:
    return AttachmentCandidate(
        part_id="p001",
        filename=filename,
        safe_filename=filename,
        media_type=media_type,
        disposition=disposition,
        size=len(body),
        sha256=sha256_bytes(body),
        payload=body,
        traversal_detected=traversal,
    )


def test_accepts_clean_candidate() -> None:
    result = evaluate_candidate(candidate("note.txt"), PolicyConfig(), set())
    assert result.status == Decision.ACCEPTED
    assert result.reason_code == "accepted"


def test_quarantines_suspicious_extension() -> None:
    result = evaluate_candidate(
        candidate("invoice.exe", media_type="application/octet-stream"),
        PolicyConfig(),
        set(),
    )
    assert result.status == Decision.QUARANTINED
    assert result.reason_code == "suspicious_extension"


def test_quarantines_double_extension() -> None:
    result = evaluate_candidate(candidate("invoice.exe.pdf", media_type="application/pdf"), PolicyConfig(), set())
    assert result.status == Decision.QUARANTINED
    assert result.reason_code == "suspicious_extension_chain"
    assert extension_chain("invoice.exe.pdf") == (".exe", ".pdf")


def test_blocks_configured_extension() -> None:
    result = evaluate_candidate(candidate("shortcut.lnk"), PolicyConfig(), set())
    assert result.status == Decision.REJECTED
    assert result.reason_code == "extension_blocked"


def test_rejects_unknown_extension() -> None:
    result = evaluate_candidate(candidate("note.xyz"), PolicyConfig(), set())
    assert result.status == Decision.REJECTED
    assert result.reason_code == "extension_not_allowed"


def test_rejects_disallowed_mime() -> None:
    result = evaluate_candidate(
        candidate("note.txt", media_type="application/x-demo"),
        PolicyConfig(),
        set(),
    )
    assert result.status == Decision.REJECTED
    assert result.reason_code == "mime_not_allowed"


def test_rejects_oversize_and_undersize() -> None:
    policy = replace(PolicyConfig(), max_file_bytes=8, min_file_bytes=4)
    assert evaluate_candidate(candidate("note.txt", body=b"123456789"), policy, set()).reason_code == "size_exceeded"
    assert evaluate_candidate(candidate("note.txt", body=b"123"), policy, set()).reason_code == "size_below_minimum"


def test_rejects_path_traversal() -> None:
    result = evaluate_candidate(candidate("../note.txt", traversal=True), PolicyConfig(), set())
    assert result.status == Decision.REJECTED
    assert result.reason_code == "path_traversal"


def test_inline_can_be_disabled() -> None:
    policy = replace(PolicyConfig(), allow_inline_attachments=False)
    result = evaluate_candidate(candidate("pixel.png", media_type="image/png", disposition="inline"), policy, set())
    assert result.reason_code == "inline_not_allowed"


def test_duplicate_content_detected() -> None:
    item = candidate("note.txt")
    result = evaluate_candidate(item, PolicyConfig(), {item.sha256})
    assert result.status == Decision.DUPLICATE
    assert result.reason_code == "duplicate_content"


def test_message_count_limit_rejects_excess() -> None:
    policy = replace(PolicyConfig(), max_attachments_per_message=1)
    items = [candidate("one.txt"), candidate("two.txt", body=b"different")]
    decisions = assess_candidates(items, policy, set())
    assert [item.status for item in decisions] == [Decision.ACCEPTED, Decision.REJECTED]
    assert decisions[1].reason_code == "attachment_count_exceeded"


def test_assess_updates_duplicate_set() -> None:
    policy = PolicyConfig()
    known: set[str] = set()
    items = [candidate("one.txt"), candidate("two.txt")]
    decisions = assess_candidates(items, policy, known)
    assert [item.status for item in decisions] == [Decision.ACCEPTED, Decision.DUPLICATE]
    assert known == {items[0].sha256}


