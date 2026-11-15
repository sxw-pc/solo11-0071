"""Scoped multipart/related resolution, retention strategies and audit output."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from mailatt.config import PolicyConfig, default_config_for_fixtures, load_config
from mailatt.errors import ConfigurationError
from mailatt.ledger import Ledger
from mailatt.mime import MimeOptions, parse_message
from mailatt.models import Decision
from mailatt.policy import assess_candidates, evaluate_candidate
from mailatt.runner import collect
from mailatt.util import sha256_bytes

from conftest import FIXTURES, fixed_clock

PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY"
    "42YAAAAASUVORK5CYII="
)
JPG = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
    "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAAB"
    "AAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q=="
)

GIF = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"


def message(body: str) -> bytes:
    return body.strip("\n").encode("utf-8") + b"\n"


def related_tree(
    *,
    boundary: str,
    root_html: str,
    resources: list[tuple[str, str, str]],
    root_cid: str = "",
    root_type: str = "text/html",
    start: str = "",
) -> str:
    params = f'boundary="{boundary}"'
    if start:
        params += f'; start="<{start}>"'
    lines = [f'Content-Type: multipart/related; {params}', ""]
    lines.extend(
        [
            f"--{boundary}",
            f'Content-Type: {root_type}; charset="utf-8"',
        ]
    )
    if root_cid:
        lines.append(f"Content-ID: <{root_cid}>")
    lines.extend(["", root_html])
    for cid, media_type, payload in resources:
        lines.extend(
            [
                f"--{boundary}",
                f"Content-Type: {media_type}",
                f"Content-ID: <{cid}>",
                "Content-Disposition: inline",
                "Content-Transfer-Encoding: base64",
                "",
                payload,
            ]
        )
    lines.append(f"--{boundary}--")
    return "\n".join(lines)


def wrapped(body: str) -> bytes:
    """Embed a complete MIME part as the second child of multipart/mixed."""
    return message(
        f"""From: demo@demo.invalid
To: archive@demo.invalid
Subject: Related fixture
Date: Mon, 02 Jan 2023 09:30:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: text/plain

body
--OUTER
{body}
--OUTER--
"""
    )


def two_tree_message() -> bytes:
    first = related_tree(
        boundary="R1",
        root_html='<img src="cid:image-1">',
        resources=[("image-1", "image/png", PNG)],
    )
    second = related_tree(
        boundary="R2",
        root_html='<img src="cid:image-1">',
        resources=[("image-1", "image/jpeg", JPG)],
    )
    return message(
        f"""From: demo@demo.invalid
To: archive@demo.invalid
Subject: Related fixture
Date: Mon, 02 Jan 2023 09:30:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="PAIR"

--PAIR
{first}
--PAIR
{second}
--PAIR--
"""
    )


def single_tree_message(mode_resources: list[tuple[str, str, str]], root_html: str) -> bytes:
    tree = related_tree(boundary="R", root_html=root_html, resources=mode_resources)
    return wrapped(tree)


def candidates_by_cid(parsed, cid: str):
    return [item for item in parsed.candidates if item.content_id == cid]


# ---------------------------------------------------------------------------
# Per-container resolution
# ---------------------------------------------------------------------------


def test_repeated_content_id_in_separate_related_trees_binds_locally() -> None:
    parsed = parse_message(two_tree_message())
    assert len(parsed.candidates) == 2
    first, second = parsed.candidates
    assert first.related_root_path == "1.1"
    assert first.related_part_path == "1.2"
    assert first.media_type == "image/png"
    assert second.related_root_path == "2.1"
    assert second.related_part_path == "2.2"
    assert second.media_type == "image/jpeg"
    assert first.content_id == second.content_id == "image-1"
    assert first.reference_count == second.reference_count == 1
    assert first.related_status == second.related_status == "referenced"


def test_global_cid_index_would_be_wrong_but_scoped_index_is_correct() -> None:
    parsed = parse_message(two_tree_message())
    root_to_part = {item.related_root_path: item.related_part_path for item in parsed.candidates}
    # Each related root resolves to the resource inside its own container only.
    assert root_to_part == {"1.1": "1.2", "2.1": "2.2"}
    assert len(set(root_to_part.values())) == 2
    # Distinct bytes prove the two containers were not collapsed into one bind.
    assert parsed.candidates[0].sha256 != parsed.candidates[1].sha256


def test_start_root_selects_non_first_child() -> None:
    tree = related_tree(
        boundary="R",
        root_html='<img src="cid:logo-1">',
        resources=[("logo-1", "image/png", PNG)],
        root_cid="root-9",
        start="root-9",
    )
    raw = message(
        f"""From: demo@demo.invalid
Subject: start root
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"; start="<root-9>"

{tree}"""
    )
    # Rebuild with resource first so the start root is genuinely not first.
    raw = message(
        f"""From: demo@demo.invalid
Subject: start root
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"; start="<root-9>"

--R
Content-Type: image/png
Content-ID: <logo-1>
Content-Disposition: inline
Content-Transfer-Encoding: base64

{PNG}
--R
Content-Type: text/html
Content-ID: <root-9>

<img src="cid:logo-1">
--R--
"""
    )
    parsed = parse_message(raw)
    assert len(parsed.candidates) == 1
    candidate = parsed.candidates[0]
    assert candidate.related_root_path == "2"
    assert candidate.related_part_path == "1"
    assert candidate.reference_count == 1
    assert parsed.related_issues == ()


def test_default_root_is_first_child_when_start_absent() -> None:
    tree = related_tree(
        boundary="R",
        root_html='<img src="cid:logo-1">',
        resources=[("logo-1", "image/png", PNG)],
    )
    parsed = parse_message(wrapped(tree))
    assert parsed.candidates[0].related_root_path == "2.1"
    assert parsed.candidates[0].related_part_path == "2.2"


def test_missing_start_root_is_reported_not_guessed() -> None:
    raw = message(
        f"""From: demo@demo.invalid
Subject: missing root
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"; start="<absent>"

--R
Content-Type: text/html

<img src="cid:logo-1">
--R
Content-Type: image/png
Content-ID: <logo-1>
Content-Disposition: inline
Content-Transfer-Encoding: base64

{PNG}
--R--
"""
    )
    parsed = parse_message(raw)
    assert parsed.candidates == ()
    codes = [item.code for item in parsed.related_issues]
    assert "related_start_root_missing" in codes
    issue = next(item for item in parsed.related_issues if item.code == "related_start_root_missing")
    assert issue.related_path == "/"
    assert issue.content_id == "absent"


def test_duplicate_content_id_in_one_container_is_ambiguous() -> None:
    raw = single_tree_message(
        [("logo-1", "image/png", PNG), ("logo-1", "image/png", PNG)],
        '<img src="cid:logo-1">',
    )
    parsed = parse_message(raw)
    assert len(parsed.candidates) == 2
    assert {item.related_status for item in parsed.candidates} == {"ambiguous"}
    assert all(item.reference_count == 1 for item in parsed.candidates)
    issue = next(item for item in parsed.related_issues if item.code == "related_duplicate_content_id")
    assert issue.content_id == "logo-1"
    assert issue.part_paths == ("2.2", "2.3")
    # Neither candidate claims a single resolved binding.
    assert all(item.related_issue_codes == ("related_duplicate_content_id",) for item in parsed.candidates)


def test_unreferenced_duplicate_stays_unreferenced() -> None:
    raw = single_tree_message(
        [("logo-1", "image/png", PNG), ("logo-1", "image/png", PNG)],
        "<p>no images</p>",
    )
    body_dependency = parse_message(raw, MimeOptions(related_retention="body-dependency"))
    # Nothing is referenced, so the body-dependency route retains nothing.
    assert body_dependency.candidates == ()
    assert any(
        item.code == "related_duplicate_content_id" for item in body_dependency.related_issues
    )
    forensic = parse_message(raw, MimeOptions(related_retention="full-forensics"))
    assert {item.related_status for item in forensic.candidates} == {"unreferenced"}
    assert all(item.reference_count == 0 for item in forensic.candidates)
    assert any(item.code == "related_duplicate_content_id" for item in forensic.related_issues)


def test_missing_reference_is_reported_with_tree_path() -> None:
    raw = single_tree_message([("logo-1", "image/png", PNG)], '<img src="cid:ghost-9">')
    parsed = parse_message(raw)
    issue = next(item for item in parsed.related_issues if item.code == "related_missing_reference")
    assert issue.content_id == "ghost-9"
    assert issue.related_path == "2"
    assert issue.root_path == "2.1"
    assert parsed.candidates == ()


def test_start_root_matching_multiple_children_is_ambiguous() -> None:
    raw = message(
        f"""From: demo@demo.invalid
Subject: ambiguous start
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"; start="<root>"

--R
Content-Type: text/html
Content-ID: <root>

<img src="cid:logo-1">
--R
Content-Type: text/html
Content-ID: <root>

<img src="cid:logo-1">
--R
Content-Type: image/png
Content-ID: <logo-1>
Content-Disposition: inline
Content-Transfer-Encoding: base64

{PNG}
--R--
"""
    )
    parsed = parse_message(raw)
    assert parsed.candidates == ()
    issue = next(
        item for item in parsed.related_issues
        if item.code == "related_start_root_ambiguous"
    )
    assert issue.content_id == "root"
    assert issue.part_paths == ("1", "2")


def test_empty_related_container_is_reported() -> None:
    from email.message import Message

    from mailatt.related import resolve_related_container

    container = Message()
    container["Content-Type"] = 'multipart/related; boundary="R"'
    container.set_payload([])
    resolution = resolve_related_container(container, "1")
    assert resolution.resources == ()
    assert [item.code for item in resolution.issues] == ["related_container_empty"]


def test_related_with_only_a_close_boundary_is_treated_as_damaged() -> None:
    raw = message(
        """From: demo@demo.invalid
Subject: empty related
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"

--R--
"""
    )
    parsed = parse_message(raw)
    assert parsed.candidates == ()
    assert [item.code for item in parsed.related_issues] == ["related_boundary_damaged"]


def test_non_html_root_does_not_interpret_cid() -> None:
    raw = single_tree_message([("logo-1", "image/png", PNG)], "cid:logo-1")
    tree = raw.replace(b"text/html", b"text/plain")
    parsed = parse_message(tree)
    assert parsed.candidates == ()
    codes = {item.code for item in parsed.related_issues}
    assert "related_root_not_html" in codes


def test_non_html_root_full_forensics_keeps_resource_unreferenced() -> None:
    raw = single_tree_message([("logo-1", "image/png", PNG)], "cid:logo-1")
    parsed = parse_message(
        raw.replace(b"text/html", b"text/plain"),
        MimeOptions(related_retention="full-forensics"),
    )
    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].related_status == "unreferenced"
    assert parsed.candidates[0].reference_count == 0


def test_nested_message_rfc822_is_not_bound_to_outer_related_scope() -> None:
    raw = message(
        f"""From: demo@demo.invalid
Subject: nested related
MIME-Version: 1.0
Content-Type: multipart/related; boundary="R"

--R
Content-Type: text/html

<img src="cid:outer-1">
--R
Content-Type: message/rfc822

From: nested@demo.invalid
Subject: inner
MIME-Version: 1.0
Content-Type: multipart/related; boundary="IN"

--IN
Content-Type: text/html

<img src="cid:inner-1">
--IN
Content-Type: image/png
Content-ID: <inner-1>
Content-Disposition: inline
Content-Transfer-Encoding: base64

{PNG}
--IN--
--R
Content-Type: image/png
Content-ID: <outer-1>
Content-Disposition: inline
Content-Transfer-Encoding: base64

{PNG}
--R--
"""
    )
    parsed = parse_message(raw)
    assert len(parsed.candidates) == 2
    by_cid = {item.content_id: item for item in parsed.candidates}
    # The nested message owns its own related scope at a deeper tree path.
    assert by_cid["inner-1"].related_root_path == "2.1.1"
    assert by_cid["inner-1"].related_part_path == "2.1.2"
    assert by_cid["outer-1"].related_root_path == "1"
    assert by_cid["outer-1"].related_part_path == "3"
    assert by_cid["inner-1"].nested_depth == 1


def test_damaged_related_boundary_is_isolated_not_fatal() -> None:
    raw = message(
        """From: demo@demo.invalid
Subject: broken related
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUT"

--OUT
Content-Type: multipart/related; boundary="R"

--WRONG
Content-Type: text/html

--OUT
Content-Type: text/plain
Content-Disposition: attachment; filename="note.txt"

payload
--OUT--
"""
    )
    parsed = parse_message(raw)
    assert [item.safe_filename for item in parsed.candidates] == ["note.txt"]
    assert any(item.code == "related_boundary_damaged" for item in parsed.related_issues)


# ---------------------------------------------------------------------------
# Retention strategies
# ---------------------------------------------------------------------------


LOGO_TRACKER = [
    ("logo-1", "image/png", PNG),
    ("tracker-2", "image/gif", GIF),
]
LOGO_HTML = '<img src="cid:logo-1">'


def test_body_dependency_keeps_only_referenced_resource() -> None:
    parsed = parse_message(
        single_tree_message(LOGO_TRACKER, LOGO_HTML),
        MimeOptions(related_retention="body-dependency"),
    )
    assert [item.content_id for item in parsed.candidates] == ["logo-1"]
    assert parsed.candidates[0].related_status == "referenced"


def test_full_forensics_keeps_referenced_and_tracker() -> None:
    parsed = parse_message(
        single_tree_message(LOGO_TRACKER, LOGO_HTML),
        MimeOptions(related_retention="full-forensics"),
    )
    assert [item.content_id for item in parsed.candidates] == ["logo-1", "tracker-2"]
    statuses = {item.content_id: item.related_status for item in parsed.candidates}
    assert statuses == {"logo-1": "referenced", "tracker-2": "unreferenced"}


def test_reference_count_counts_each_cid_occurrence() -> None:
    html = '<img src="cid:logo-1"><img src="cid:logo-1">'
    parsed = parse_message(single_tree_message(LOGO_TRACKER, html))
    logo = candidates_by_cid(parsed, "logo-1")[0]
    assert logo.reference_count == 2


def test_cid_match_is_exact_not_case_folded() -> None:
    html = '<img src="cid:LOGO-1">'
    parsed = parse_message(single_tree_message(LOGO_TRACKER, html))
    assert parsed.candidates == ()
    assert any(item.code == "related_missing_reference" for item in parsed.related_issues)


# ---------------------------------------------------------------------------
# Policy integration
# ---------------------------------------------------------------------------


def related_candidate(status: str, *, filename: str = "inline-p001.png", media_type: str = "image/png",
                      disposition: str = "inline", body: bytes = b"png-bytes"):
    from mailatt.models import AttachmentCandidate

    return AttachmentCandidate(
        part_id="p001",
        filename=filename,
        safe_filename=filename,
        media_type=media_type,
        disposition=disposition,
        size=len(body),
        sha256=sha256_bytes(body),
        payload=body,
        related_root_path="1.1",
        related_part_path="1.2",
        content_id="logo-1",
        reference_count=1,
        related_status=status,
        related_inline_only=True,
    )


def test_ambiguous_reference_is_quarantined_in_body_dependency_mode() -> None:
    policy = replace(PolicyConfig(), related_retention="body-dependency")
    decision = evaluate_candidate(related_candidate("ambiguous"), policy, set())
    assert decision.status == Decision.QUARANTINED
    assert decision.reason_code == "related_reference_ambiguous"


def test_ambiguous_reference_is_kept_in_full_forensics_mode() -> None:
    policy = replace(PolicyConfig(), related_retention="full-forensics")
    decision = evaluate_candidate(related_candidate("ambiguous"), policy, set())
    assert decision.status == Decision.ACCEPTED


def test_existing_gates_still_apply_to_inline_candidates() -> None:
    policy = replace(PolicyConfig(), max_file_bytes=4)
    oversized = related_candidate("referenced", body=b"way-too-many-bytes")
    assert evaluate_candidate(oversized, policy, set()).reason_code == "size_exceeded"
    blocked = replace(PolicyConfig(), allowed_extensions=(".txt",))
    assert evaluate_candidate(
        related_candidate("referenced"), blocked, set()
    ).reason_code == "extension_not_allowed"
    sized = replace(PolicyConfig(), min_file_bytes=64)
    assert evaluate_candidate(
        related_candidate("referenced"), sized, set()
    ).reason_code == "size_below_minimum"


def test_retention_config_is_validated(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  related_retention: guess-everything
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="related_retention"):
        load_config(path, workdir_override=tmp_path / "work")


def test_retention_defaults_and_affects_policy_fingerprint(tmp_path: Path) -> None:
    assert PolicyConfig().related_retention == "body-dependency"
    assert "related_retention" in PolicyConfig().as_dict()
    base = tmp_path / "a.yaml"
    base.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy: {{}}
""",
        encoding="utf-8",
    )
    forensic = tmp_path / "b.yaml"
    forensic.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  related_retention: full-forensics
""",
        encoding="utf-8",
    )
    first = load_config(base, workdir_override=tmp_path / "wa")
    second = load_config(forensic, workdir_override=tmp_path / "wb")
    assert first.policy_fingerprint != second.policy_fingerprint


# ---------------------------------------------------------------------------
# Runner: end-to-end strategy difference, ledger and manifest audit fields
# ---------------------------------------------------------------------------


def build_dataset(tmp_path: Path, retention: str) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "related.eml").write_bytes(
        single_tree_message(LOGO_TRACKER, LOGO_HTML)
    )
    config = tmp_path / f"config-{retention}.yaml"
    config.write_text(
        f"""version: 1
sources:
  - name: inbox
    path: {source}
    kind: eml
policy:
  allowed_extensions: [.png, .gif]
  allowed_media_types: [image/png, image/gif]
  max_attachments_per_message: 10
  related_retention: {retention}
""",
        encoding="utf-8",
    )
    return config, source


def test_runner_body_dependency_archives_only_referenced_resource(tmp_path: Path) -> None:
    config_path, _ = build_dataset(tmp_path, "body-dependency")
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    assert result.summary.attachments_seen == 1
    assert result.summary.accepted == 1
    assert result.summary.objects_created == 1
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["object_count"] == 1
    assert manifest["part_count"] == 1
    entry = manifest["parts"][0]
    assert entry["content_id"] == "logo-1"
    assert entry["related_root_path"] == "2.1"
    assert entry["related_part_path"] == "2.2"
    assert entry["related_container_path"] == "2"
    assert entry["reference_count"] == 1
    assert entry["related_status"] == "referenced"


def test_runner_full_forensics_archives_referenced_and_tracker(tmp_path: Path) -> None:
    config_path, _ = build_dataset(tmp_path, "full-forensics")
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    assert result.summary.attachments_seen == 2
    assert result.summary.accepted == 2
    assert result.summary.objects_created == 2
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    ids = [(item["content_id"], item["related_status"]) for item in manifest["parts"]]
    assert ids == [("logo-1", "referenced"), ("tracker-2", "unreferenced")]


def test_runner_ambiguous_duplicate_is_isolated_in_body_dependency(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "dup.eml").write_bytes(
        single_tree_message(
            [("logo-1", "image/png", PNG), ("logo-1", "image/png", PNG)],
            LOGO_HTML,
        )
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: inbox
    path: {source}
    kind: eml
policy:
  allowed_extensions: [.png]
  allowed_media_types: [image/png]
  related_retention: body-dependency
""",
        encoding="utf-8",
    )
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    assert result.summary.quarantined == 2
    assert result.summary.accepted == 0
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
        messages = ledger.all_messages()
    assert {row["related_status"] for row in rows} == {"ambiguous"}
    assert all(row["reason_code"] == "related_reference_ambiguous" for row in rows)
    assert all(row["quarantine_path"] for row in rows)
    issues = json.loads(messages[0]["related_issues_json"])
    assert [item["code"] for item in issues] == ["related_duplicate_content_id"]
    assert issues[0]["part_paths"] == ["2.2", "2.3"]


def test_runner_full_forensics_keeps_both_ambiguous_parts_unbound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "dup.eml").write_bytes(
        single_tree_message(
            [("logo-1", "image/png", PNG), ("logo-1", "image/png", PNG)],
            LOGO_HTML,
        )
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: inbox
    path: {source}
    kind: eml
policy:
  allowed_extensions: [.png]
  allowed_media_types: [image/png]
  related_retention: full-forensics
""",
        encoding="utf-8",
    )
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    # Both original parts survive, but neither is bound to a unique reference.
    assert result.summary.accepted == 1
    assert result.summary.duplicates == 1
    with Ledger(config.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
        messages = ledger.all_messages()
    assert len(rows) == 2
    assert {row["related_status"] for row in rows} == {"ambiguous"}
    assert len({row["related_part_path"] for row in rows}) == 2
    issues = json.loads(messages[0]["related_issues_json"])
    assert issues[0]["code"] == "related_duplicate_content_id"
    # The manifest keeps one object but both parts remain auditable.
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["object_count"] == 1
    assert manifest["part_count"] == 2
    assert {item["related_part_path"] for item in manifest["parts"]} == {"2.2", "2.3"}


def test_manifest_and_report_related_fields_are_stable(tmp_path: Path) -> None:
    config_path, _ = build_dataset(tmp_path, "full-forensics")
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    entries = manifest["objects"]
    keys = [(item["source_ref"], item["part_id"], item["path"]) for item in entries]
    assert keys == sorted(keys, key=lambda row: (row[2].startswith("quarantine"), row[2]))
    parts = manifest["parts"]
    assert manifest["part_count"] == len(parts) == 2
    part_keys = [
        (item["source_ref"], item["part_id"], item["related_part_path"]) for item in parts
    ]
    assert part_keys == sorted(part_keys)
    payload = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    attachment_keys = [
        (item["message_source"], item["message_path"], item["part_id"])
        for item in payload["attachments"]
    ]
    assert attachment_keys == sorted(attachment_keys)
    assert all(item["content_id"] for item in payload["attachments"])
    assert payload["policy"]["related_retention"] == "full-forensics"
    assert payload["related_issues"] == []


def test_report_surfaces_relation_issues_and_markdown_sections(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "dup.eml").write_bytes(
        single_tree_message(
            [("logo-1", "image/png", PNG), ("logo-1", "image/png", PNG)],
            LOGO_HTML,
        )
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: inbox
    path: {source}
    kind: eml
policy:
  allowed_extensions: [.png]
  allowed_media_types: [image/png]
  related_retention: body-dependency
""",
        encoding="utf-8",
    )
    config = load_config(config_path, workdir_override=tmp_path / "work")
    result = collect(config, clock=fixed_clock)
    payload = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert [item["code"] for item in payload["related_issues"]] == [
        "related_duplicate_content_id"
    ]
    assert payload["related_issues"][0]["part_paths"] == ["2.2", "2.3"]
    markdown = result.report_paths["markdown"].read_text(encoding="utf-8")
    assert "## inline 资源关系" in markdown
    assert "## inline 引用问题" in markdown
    assert "related_duplicate_content_id" in markdown
    html = result.report_paths["html"].read_text(encoding="utf-8")
    assert "inline 引用问题" in html
    assert "related_duplicate_content_id" in html


def test_policy_summary_reports_retention() -> None:
    from mailatt.policy import summarize_policy
    from mailatt.config import PolicyConfig

    summary = summarize_policy(PolicyConfig())
    assert summary["related_retention"] == "body-dependency"


def test_ledger_migrates_old_attachment_schema(tmp_path: Path) -> None:
    import sqlite3

    workdir = tmp_path / "work"
    workdir.mkdir()
    conn = sqlite3.connect(workdir / "ledger.sqlite3")
    conn.executescript(
        """CREATE TABLE attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            part_id TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            filename TEXT NOT NULL DEFAULT '',
            safe_filename TEXT NOT NULL DEFAULT '',
            media_type TEXT NOT NULL DEFAULT '',
            disposition TEXT NOT NULL DEFAULT '',
            nested_depth INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            reason_code TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            object_path TEXT NOT NULL DEFAULT '',
            quarantine_path TEXT NOT NULL DEFAULT '',
            first_seen_run TEXT NOT NULL,
            last_seen_run TEXT NOT NULL,
            UNIQUE(message_id, part_id)
        );"""
    )
    conn.commit()
    conn.close()
    with Ledger(workdir) as ledger:
        columns = {
            row[1] for row in ledger.conn.execute("PRAGMA table_info(attachments)")
        }
        message_columns = {
            row[1] for row in ledger.conn.execute("PRAGMA table_info(messages)")
        }
    assert {"related_root_path", "related_part_path", "related_container_path",
            "content_id", "reference_count", "related_status"} <= columns
    assert "related_issues_json" in message_columns
