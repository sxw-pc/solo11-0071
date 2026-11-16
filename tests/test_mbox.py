"""Tests for mbox container splitting, dialect unescaping and quarantine segments."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailatt.config import Config, PolicyConfig, SourceConfig, load_config
from mailatt.discovery import discover
from mailatt.errors import ConfigurationError
from mailatt.ledger import Ledger
from mailatt.mbox import split_mbox, unescape_message
from mailatt.runner import collect
from mailatt.storage import ObjectStore
from mailatt.util import sha256_bytes

from conftest import fixed_clock, write_config

ENV1 = b"From alice@demo.invalid Mon Jan 01 00:00:00 2024\n"
ENV2 = b"From bob@demo.invalid Tue Jan 02 00:00:00 2024\n"
ENV3 = b"From carol@demo.invalid Wed Jan 03 00:00:00 2024\n"

# The ambiguity fixture: message one's Content-Length claims a body that runs
# past an envelope-shaped "From carol" line, yet never lands on an envelope or
# the end of the container.  Two real, self-proving messages follow.
AMBIGUOUS_MBOX = (
    b"From alice@demo.invalid Mon Jan 01 00:00:00 2024\n"
    b"From: alice@demo.invalid\n"
    b"To: bob@demo.invalid\n"
    b"Subject: one\n"
    b"Content-Length: 400\n"  # wrong on purpose: lands past end of container
    b"\n"
    b"Body of one.\n"
    b"From carol@demo.invalid Tue Jan 02 00:00:00 2024\n"  # looks like an envelope
    b"still body of one.\n"
    b"From bob@demo.invalid Wed Jan 03 00:00:00 2024\n"
    b"From: bob@demo.invalid\n"
    b"Subject: two\n"
    b"Content-Length: 11\n"
    b"\n"
    b"Hello two.\n"
    b"\n"
    b"From dave@demo.invalid Thu Jan 04 00:00:00 2024\n"
    b"From: dave@demo.invalid\n"
    b"Subject: three\n"
    b"Content-Length: 7\n"
    b"\n"
    b"Three.\n"
)

MSG_ONE = b"From: a@demo.invalid\nSubject: one\n\nbody one\n"
MSG_TWO = b"From: b@demo.invalid\nSubject: two\n\nbody two\n"
MSG_THREE = b"From: c@demo.invalid\nSubject: three\n\nbody three\n"

ATTACHMENT_MSG = (
    b"From: alice@demo.invalid\n"
    b"To: bob@demo.invalid\n"
    b"Subject: report\n"
    b"MIME-Version: 1.0\n"
    b"Content-Type: multipart/mixed; boundary=mix\n"
    b"\n"
    b"--mix\n"
    b"Content-Type: text/plain\n"
    b"\n"
    b"see attached\n"
    b"--mix\n"
    b"Content-Type: text/csv; name=data.csv\n"
    b"Content-Disposition: attachment; filename=data.csv\n"
    b"\n"
    b"col,val\n1,2\n"
    b"--mix--\n"
)


def three_message_container() -> bytes:
    return ENV1 + MSG_ONE + b"\n" + ENV2 + MSG_TWO + b"\n" + ENV3 + MSG_THREE


def make_config(source: Path, workdir: Path, kind: str = "mboxrd", mode: str = "strict") -> Config:
    return Config(
        sources=(SourceConfig("box", source, kind, mode),),
        policy=PolicyConfig(),
        workdir=workdir,
    )


def make_source(tmp_path: Path, data: bytes, name: str = "box.mbox") -> Path:
    source = tmp_path / "mbox"
    source.mkdir()
    (source / name).write_bytes(data)
    return source


# ---------------------------------------------------------------------------
# Envelope recognition and byte offsets
# ---------------------------------------------------------------------------


def test_envelope_requires_full_ctime_date() -> None:
    data = (
        ENV1
        + b"From: a@demo.invalid\n\n"
        + b"From not an envelope\n"
        + b"From alice@demo.invalid Jan 01 00:00:00 2024\n"  # missing weekday
        + b"From: header-looking body line\n"
        + ENV2
        + b"From: b@demo.invalid\n\nbody\n"
    )
    scan = split_mbox(data, "mboxrd", "strict")
    assert scan.segments == ()
    assert len(scan.messages) == 2
    first = data[scan.messages[0].offset : scan.messages[0].offset + scan.messages[0].length]
    assert b"From not an envelope" in first
    assert b"From alice@demo.invalid Jan 01" in first


def test_lf_message_offsets_and_ordinals() -> None:
    data = ENV1 + MSG_ONE + ENV2 + MSG_TWO
    scan = split_mbox(data, "mboxrd", "strict")
    assert scan.segments == ()
    assert [m.ordinal for m in scan.messages] == [1, 2]
    first, second = scan.messages
    assert first.envelope_offset == 0
    assert first.offset == len(ENV1)
    assert first.length == len(MSG_ONE)
    assert second.envelope_offset == len(ENV1) + len(MSG_ONE)
    assert second.offset == len(ENV1) + len(MSG_ONE) + len(ENV2)
    assert second.length == len(MSG_TWO)
    assert data[first.offset : first.offset + first.length] == MSG_ONE
    again = split_mbox(data, "mboxrd", "strict")
    assert [m.digest for m in again.messages] == [m.digest for m in scan.messages]


def test_crlf_message_offsets_and_unescape() -> None:
    env1 = b"From alice@demo.invalid Mon Jan 01 00:00:00 2024\r\n"
    msg1 = b"From: a@demo.invalid\r\n\r\n>From quoted\r\n"
    env2 = b"From bob@demo.invalid Tue Jan 02 00:00:00 2024\r\n"
    msg2 = b"From: b@demo.invalid\r\n\r\nbody\r\n"
    data = env1 + msg1 + env2 + msg2
    scan = split_mbox(data, "mboxrd", "strict")
    assert scan.segments == ()
    assert [m.length for m in scan.messages] == [len(msg1), len(msg2)]
    first = scan.messages[0]
    assert first.offset == len(env1)
    raw = data[first.offset : first.offset + first.length]
    assert raw == msg1
    assert unescape_message(raw, "mboxrd") == b"From: a@demo.invalid\r\n\r\nFrom quoted\r\n"


def test_blank_separator_is_not_part_of_a_slice() -> None:
    data = ENV1 + MSG_ONE + b"\n" + ENV2 + MSG_TWO
    scan = split_mbox(data, "mboxrd", "strict")
    assert scan.messages[0].length == len(MSG_ONE)
    assert scan.messages[1].offset == len(ENV1) + len(MSG_ONE) + 1 + len(ENV2)


@pytest.mark.parametrize("dialect", ["mboxo", "mboxrd"])
def test_mboxo_and_mboxrd_split_identically(dialect: str) -> None:
    data = three_message_container()
    scan = split_mbox(data, dialect, "strict")
    assert len(scan.messages) == 3
    assert scan.segments == ()
    assert [m.offset for m in scan.messages] == [
        len(ENV1),
        len(ENV1) + len(MSG_ONE) + 1 + len(ENV2),
        len(ENV1) + len(MSG_ONE) + 1 + len(ENV2) + len(MSG_TWO) + 1 + len(ENV3),
    ]


# ---------------------------------------------------------------------------
# Dialect unescaping
# ---------------------------------------------------------------------------


def test_unescape_removes_exactly_one_angle_per_dialect() -> None:
    raw = b">From a\n>>From b\n> From c\nFrom d\n>Fromage\n"
    expected = b"From a\n>From b\n> From c\nFrom d\n>Fromage\n"
    for dialect in ("mboxo", "mboxrd", "mboxcl"):
        assert unescape_message(raw, dialect) == expected
    # mboxcl2 writers never escape, so nothing is rewritten.
    assert unescape_message(raw, "mboxcl2") == raw


def test_unescape_rejects_unknown_dialect() -> None:
    with pytest.raises(ValueError):
        unescape_message(b"From a\n", "bogus")


def test_escaped_from_line_is_not_a_boundary() -> None:
    msg1 = b"From: a@demo.invalid\n\n>From fake@demo.invalid Mon Jan 01 00:00:00 2024\ntext\n"
    data = ENV1 + msg1 + ENV2 + MSG_TWO
    scan = split_mbox(data, "mboxrd", "strict")
    assert scan.segments == ()
    assert len(scan.messages) == 2
    raw = data[scan.messages[0].offset : scan.messages[0].offset + scan.messages[0].length]
    assert raw == msg1
    assert unescape_message(raw, "mboxrd") == (
        b"From: a@demo.invalid\n\nFrom fake@demo.invalid Mon Jan 01 00:00:00 2024\ntext\n"
    )


# ---------------------------------------------------------------------------
# Content-Length dialects
# ---------------------------------------------------------------------------


def test_content_length_absorbs_envelope_shaped_body_line() -> None:
    body = b"From fake@demo.invalid Mon Jan 01 00:00:00 2024\nreal body\n"
    msg1 = b"From: a@demo.invalid\nContent-Length: " + str(len(body)).encode() + b"\n\n" + body
    msg2 = b"From: b@demo.invalid\nContent-Length: 7\n\nsecond\n"
    data = ENV1 + msg1 + b"\n" + ENV2 + msg2
    scan = split_mbox(data, "mboxcl2", "strict")
    assert scan.segments == ()
    assert len(scan.messages) == 2
    raw = data[scan.messages[0].offset : scan.messages[0].offset + scan.messages[0].length]
    assert b"From fake@demo.invalid" in raw  # proven to be body, not a boundary


def test_content_length_too_small_is_a_mismatch() -> None:
    msg = b"From: a@demo.invalid\nContent-Length: 5\n\nhello world\n"
    data = ENV1 + msg
    scan = split_mbox(data, "mboxcl2", "strict")
    assert scan.messages == ()
    assert [s.reason for s in scan.segments] == ["content_length_mismatch"]


def test_missing_content_length_is_ambiguous_in_cl_dialects() -> None:
    data = ENV1 + b"From: a@demo.invalid\n\nno length here\n"
    strict = split_mbox(data, "mboxcl", "strict")
    assert strict.messages == ()
    assert [s.reason for s in strict.segments] == ["content_length_missing"]
    recover = split_mbox(data, "mboxcl", "recover")
    assert recover.messages == ()
    assert len(recover.segments) == 1
    assert "to end of container" in recover.segments[0].detail


def test_mboxcl_unescapes_but_mboxcl2_preserves() -> None:
    body = b">From quoted\n"
    msg = b"From: a@demo.invalid\nContent-Length: " + str(len(body)).encode() + b"\n\n" + body
    data = ENV1 + msg
    for dialect, expected in (("mboxcl", b"From quoted\n"), ("mboxcl2", b">From quoted\n")):
        scan = split_mbox(data, dialect, "strict")
        assert len(scan.messages) == 1
        raw = data[scan.messages[0].offset : scan.messages[0].offset + scan.messages[0].length]
        assert unescape_message(raw, dialect).endswith(expected)


# ---------------------------------------------------------------------------
# Ambiguity: strict stops, recover continues with the proven suffix
# ---------------------------------------------------------------------------


def test_strict_stops_at_ambiguous_boundary() -> None:
    scan = split_mbox(AMBIGUOUS_MBOX, "mboxcl2", "strict")
    assert scan.messages == ()
    assert len(scan.segments) == 1
    segment = scan.segments[0]
    assert segment.ordinal == 1
    assert segment.offset == 0
    assert segment.length == len(AMBIGUOUS_MBOX)
    assert segment.reason == "content_length_mismatch"
    assert "strict mode stopped at ambiguous boundary" in segment.detail
    assert segment.digest == sha256_bytes(AMBIGUOUS_MBOX)


def test_recover_keeps_segment_and_continues_with_proven_suffix() -> None:
    scan = split_mbox(AMBIGUOUS_MBOX, "mboxcl2", "recover")
    assert len(scan.segments) == 1
    segment = scan.segments[0]
    env2_offset = AMBIGUOUS_MBOX.index(b"From bob@demo.invalid Wed")
    assert (segment.ordinal, segment.offset, segment.length) == (1, 0, env2_offset)
    assert segment.reason == "content_length_mismatch"
    assert "continued with proven suffix" in segment.detail

    assert [m.ordinal for m in scan.messages] == [2, 3]
    second, third = scan.messages
    assert second.envelope_offset == env2_offset
    raw2 = AMBIGUOUS_MBOX[second.offset : second.offset + second.length]
    assert raw2 == b"From: bob@demo.invalid\nSubject: two\nContent-Length: 11\n\nHello two.\n"
    raw3 = AMBIGUOUS_MBOX[third.offset : third.offset + third.length]
    assert raw3 == b"From: dave@demo.invalid\nSubject: three\nContent-Length: 7\n\nThree.\n"

    # The ambiguous bytes stay in the segment and leak into neither body.
    seg_bytes = AMBIGUOUS_MBOX[segment.offset : segment.offset + segment.length]
    assert b"From carol@demo.invalid" in seg_bytes
    assert b"Body of one." in seg_bytes
    assert b"From carol@demo.invalid" not in raw2
    assert b"From carol@demo.invalid" not in raw3


def test_strict_keeps_proven_prefix_and_quarantines_suffix() -> None:
    msg1 = b"From: a@demo.invalid\nContent-Length: 4\n\none\n"
    broken = b"From: b@demo.invalid\nContent-Length: 999\n\nshort\n"
    data = ENV1 + msg1 + b"\n" + ENV2 + broken
    scan = split_mbox(data, "mboxcl2", "strict")
    assert [m.ordinal for m in scan.messages] == [1]
    assert len(scan.segments) == 1
    segment = scan.segments[0]
    assert segment.ordinal == 2
    assert segment.offset == data.index(ENV2)
    assert segment.offset + segment.length == len(data)


def test_garbage_prefix_strict_vs_recover() -> None:
    data = b"random garbage\nnot mail\n" + ENV1 + MSG_ONE
    strict = split_mbox(data, "mboxrd", "strict")
    assert strict.messages == ()
    assert [(s.offset, s.length, s.reason) for s in strict.segments] == [
        (0, len(data), "missing_envelope")
    ]
    recover = split_mbox(data, "mboxrd", "recover")
    assert [(s.offset, s.length) for s in recover.segments] == [(0, len(b"random garbage\nnot mail\n"))]
    assert len(recover.messages) == 1
    assert recover.messages[0].ordinal == 2


def test_empty_container_has_no_slices() -> None:
    scan = split_mbox(b"", "mboxrd", "strict")
    assert scan.messages == ()
    assert scan.segments == ()


def test_split_rejects_unknown_dialect_and_mode() -> None:
    with pytest.raises(ValueError):
        split_mbox(b"", "bogus", "strict")
    with pytest.raises(ValueError):
        split_mbox(b"", "mboxrd", "guess")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovery_emits_stable_slice_identities(tmp_path: Path) -> None:
    source = make_source(tmp_path, three_message_container())
    (source / "notes.txt").write_text("ignore", encoding="utf-8")
    (source / "empty.mbox").write_bytes(b"")
    config = make_config(source, tmp_path / "work")
    first = discover(config)
    second = discover(config)
    refs = [item.relative_path for item in first.files]
    assert refs == ["box.mbox#000001", "box.mbox#000002", "box.mbox#000003"]
    assert [item.relative_path for item in second.files] == refs
    assert [item.digest for item in second.files] == [item.digest for item in first.files]
    assert all(item.absolute_path == source / "box.mbox" for item in first.files)
    assert all(item.slice_offset is not None for item in first.files)
    assert all(item.mbox_dialect == "mboxrd" for item in first.files)
    assert first.segments == ()
    offsets = [item.slice_offset for item in first.files]
    assert offsets == sorted(offsets)


def test_discovery_reports_segments_with_container_identity(tmp_path: Path) -> None:
    source = make_source(tmp_path, AMBIGUOUS_MBOX, name="broken.mbox")
    config = make_config(source, tmp_path / "work", kind="mboxcl2", mode="strict")
    outcome = discover(config)
    assert outcome.files == ()
    assert len(outcome.segments) == 1
    segment = outcome.segments[0]
    assert segment.relative_path == "broken.mbox#seg-000001"
    assert segment.source_ref == "box/broken.mbox#seg-000001"
    assert segment.byte_offset == 0
    assert segment.size == len(AMBIGUOUS_MBOX)
    assert segment.reason == "content_length_mismatch"
    assert segment.digest == sha256_bytes(AMBIGUOUS_MBOX)


# ---------------------------------------------------------------------------
# Runner end to end
# ---------------------------------------------------------------------------


def test_collect_imports_each_container_message(tmp_path: Path) -> None:
    container = (
        ENV1 + MSG_ONE + b"\n" + ENV2 + ATTACHMENT_MSG + b"\n" + ENV3 + MSG_THREE
    )
    source = make_source(tmp_path, container)
    config = make_config(source, tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    summary = result.summary
    assert summary.status == "completed"
    assert summary.messages_seen == 3
    assert summary.messages_ok == 3
    assert summary.messages_error == 0
    assert summary.mbox_segments_quarantined == 0
    assert summary.attachments_seen == 1
    assert summary.accepted == 1
    assert summary.objects_created == 1
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = {row["relative_path"]: row for row in ledger.all_messages()}
        attachments = ledger.all_attachments()
    assert set(rows) == {"box.mbox#000001", "box.mbox#000002", "box.mbox#000003"}
    assert rows["box.mbox#000001"]["subject"] == "one"
    assert rows["box.mbox#000003"]["subject"] == "three"
    assert len(attachments) == 1
    assert attachments[0]["message_path"] == "box.mbox#000002"
    assert attachments[0]["safe_filename"] == "data.csv"


def test_collect_strict_reports_incomplete_coverage(tmp_path: Path) -> None:
    source = make_source(tmp_path, AMBIGUOUS_MBOX, name="ambiguous.mbox")
    config = make_config(source, tmp_path / "work", kind="mboxcl2", mode="strict")
    result = collect(config, clock=fixed_clock)
    summary = result.summary
    assert summary.messages_seen == 0
    assert summary.messages_ok == 0
    assert summary.messages_error == 0
    assert summary.mbox_segments_quarantined == 1
    assert summary.status == "completed_with_errors"
    assert len(summary.errors) == 1
    error = summary.errors[0]
    assert error["code"] == "MBOX_SEGMENT_QUARANTINED"
    assert error["source_ref"] == "box/ambiguous.mbox#seg-000001"
    assert "strict mode stopped at ambiguous boundary" in error["detail"]
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_messages()
    assert len(rows) == 1
    assert rows[0]["relative_path"] == "ambiguous.mbox#seg-000001"
    assert rows[0]["status"] == "error"
    assert rows[0]["error_code"] == "MBOX_SEGMENT_QUARANTINED"
    assert rows[0]["size"] == len(AMBIGUOUS_MBOX)


def test_collect_recover_imports_only_the_proven_suffix(tmp_path: Path) -> None:
    source = make_source(tmp_path, AMBIGUOUS_MBOX, name="ambiguous.mbox")
    config = make_config(source, tmp_path / "work", kind="mboxcl2", mode="recover")
    result = collect(config, clock=fixed_clock)
    summary = result.summary
    assert summary.messages_seen == 2
    assert summary.messages_ok == 2
    assert summary.messages_error == 0
    assert summary.mbox_segments_quarantined == 1
    assert summary.status == "completed_with_errors"
    assert len(summary.errors) == 1
    assert "continued with proven suffix" in summary.errors[0]["detail"]
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = {row["relative_path"]: row for row in ledger.all_messages()}
    assert set(rows) == {
        "ambiguous.mbox#000002",
        "ambiguous.mbox#000003",
        "ambiguous.mbox#seg-000001",
    }
    assert rows["ambiguous.mbox#000002"]["status"] == "ok"
    assert rows["ambiguous.mbox#000002"]["subject"] == "two"
    assert rows["ambiguous.mbox#000003"]["status"] == "ok"
    assert rows["ambiguous.mbox#000003"]["subject"] == "three"
    assert rows["ambiguous.mbox#seg-000001"]["status"] == "error"
    assert rows["ambiguous.mbox#seg-000001"]["error_code"] == "MBOX_SEGMENT_QUARANTINED"


def test_recover_rerun_is_incremental_and_does_not_duplicate(tmp_path: Path) -> None:
    source = make_source(tmp_path, AMBIGUOUS_MBOX, name="ambiguous.mbox")
    config = make_config(source, tmp_path / "work", kind="mboxcl2", mode="recover")
    first = collect(config, clock=fixed_clock)
    assert first.summary.messages_ok == 2
    with Ledger(config.workdir, readonly=True) as ledger:
        counts = (ledger.count_rows("messages"), ledger.count_rows("attachments"))
    second = collect(config, clock=fixed_clock)
    assert second.summary.messages_seen == 2
    assert second.summary.messages_skipped == 2
    assert second.summary.messages_ok == 0
    assert second.summary.mbox_segments_quarantined == 1
    assert second.summary.objects_created == 0
    with Ledger(config.workdir, readonly=True) as ledger:
        assert (ledger.count_rows("messages"), ledger.count_rows("attachments")) == counts
        assert ledger.count_rows("runs") == 2


def test_appended_container_keeps_slice_identities(tmp_path: Path) -> None:
    source = tmp_path / "mbox"
    source.mkdir()
    container = source / "box.mbox"
    container.write_bytes(ENV1 + MSG_ONE + b"\n" + ENV2 + MSG_TWO)
    config = make_config(source, tmp_path / "work")
    first = collect(config, clock=fixed_clock)
    assert first.summary.messages_ok == 2
    with container.open("ab") as handle:
        handle.write(b"\n" + ENV3 + MSG_THREE)
    second = collect(config, clock=fixed_clock)
    assert second.summary.messages_seen == 3
    assert second.summary.messages_skipped == 2
    assert second.summary.messages_ok == 1
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_messages()
    assert [row["relative_path"] for row in rows] == [
        "box.mbox#000001",
        "box.mbox#000002",
        "box.mbox#000003",
    ]
    assert all(row["status"] == "ok" for row in rows)


def test_broken_slice_is_isolated_and_batch_continues(tmp_path: Path) -> None:
    data = ENV1 + ENV2 + MSG_TWO  # message one is empty: two envelopes in a row
    source = make_source(tmp_path, data)
    config = make_config(source, tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    summary = result.summary
    assert summary.messages_ok == 1
    assert summary.messages_error == 1
    assert summary.status == "completed_with_errors"
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = {row["relative_path"]: row for row in ledger.all_messages()}
    assert rows["box.mbox#000001"]["status"] == "error"
    assert rows["box.mbox#000001"]["error_code"] == "EMPTY_MESSAGE"
    assert rows["box.mbox#000002"]["status"] == "ok"


def test_empty_container_is_a_clean_noop(tmp_path: Path) -> None:
    source = make_source(tmp_path, b"", name="empty.mbox")
    config = make_config(source, tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    assert result.summary.messages_seen == 0
    assert result.summary.mbox_segments_quarantined == 0
    assert result.summary.status == "completed"
    assert result.summary.errors == []


def test_body_from_unescape_reaches_object_store(tmp_path: Path) -> None:
    part_body = b"first line\n>From looks-like-envelope\n>still quoted\n"
    message = (
        b"From: alice@demo.invalid\n"
        b"To: bob@demo.invalid\n"
        b"Subject: note\n"
        b"Content-Type: text/plain; name=note.txt\n"
        b"Content-Disposition: attachment; filename=note.txt\n"
        b"\n"
        + part_body
    )
    source = make_source(tmp_path, ENV1 + message)
    config = make_config(source, tmp_path / "work", kind="mboxrd")
    result = collect(config, clock=fixed_clock)
    assert result.summary.accepted == 1
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
    assert len(rows) == 1
    store = ObjectStore(config.workdir, create=False)
    data = store.read_bytes(rows[0]["object_path"])
    # mboxrd restores exactly one ">" per declared dialect rule.
    assert data == b"first line\nFrom looks-like-envelope\n>still quoted\n"


def test_mboxcl2_preserves_body_from_lines_in_object_store(tmp_path: Path) -> None:
    part_body = b"first line\n>From looks-like-envelope\n"
    message = (
        b"From: alice@demo.invalid\n"
        b"To: bob@demo.invalid\n"
        b"Subject: note\n"
        b"Content-Type: text/plain; name=note.txt\n"
        b"Content-Disposition: attachment; filename=note.txt\n"
        b"Content-Length: " + str(len(part_body)).encode() + b"\n"
        b"\n"
        + part_body
    )
    source = make_source(tmp_path, ENV1 + message)
    config = make_config(source, tmp_path / "work", kind="mboxcl2")
    result = collect(config, clock=fixed_clock)
    assert result.summary.accepted == 1
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
    store = ObjectStore(config.workdir, create=False)
    data = store.read_bytes(rows[0]["object_path"])
    # mboxcl2 never rewrites body bytes.
    assert data == part_body


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_mbox_kind_and_mode_are_loaded(tmp_path: Path) -> None:
    source = tmp_path / "mbox"
    source.mkdir()
    path = write_config(
        tmp_path / "cfg.yaml",
        f"""version: 1
sources:
  - name: box
    path: {source}
    kind: mboxrd
    mbox_mode: recover
""",
    )
    config = load_config(path, workdir_override=tmp_path / "work")
    assert config.sources[0].kind == "mboxrd"
    assert config.sources[0].mbox_mode == "recover"


def test_mbox_mode_defaults_to_strict(tmp_path: Path) -> None:
    source = tmp_path / "mbox"
    source.mkdir()
    path = write_config(
        tmp_path / "cfg.yaml",
        f"""version: 1
sources:
  - name: box
    path: {source}
    kind: mboxcl2
""",
    )
    config = load_config(path, workdir_override=tmp_path / "work")
    assert config.sources[0].mbox_mode == "strict"


def test_mbox_mode_rejected_for_non_mbox_kind(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "cfg.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {tmp_path}
    kind: eml
    mbox_mode: recover
""",
    )
    with pytest.raises(ConfigurationError, match="mbox_mode"):
        load_config(path, workdir_override=tmp_path / "work")


def test_invalid_mbox_mode_rejected(tmp_path: Path) -> None:
    source = tmp_path / "mbox"
    source.mkdir()
    path = write_config(
        tmp_path / "cfg.yaml",
        f"""version: 1
sources:
  - name: box
    path: {source}
    kind: mboxrd
    mbox_mode: guess
""",
    )
    with pytest.raises(ConfigurationError, match="mbox_mode"):
        load_config(path, workdir_override=tmp_path / "work")


def test_unknown_kind_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "cfg.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {tmp_path}
    kind: mbox
""",
    )
    with pytest.raises(ConfigurationError, match="kind"):
        load_config(path, workdir_override=tmp_path / "work")
