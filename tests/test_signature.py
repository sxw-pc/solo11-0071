"""End-to-end tests for offline multipart/signed evidence verification."""

from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path
from typing import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from mailatt.config import (
    Config,
    PolicyConfig,
    SourceConfig,
    TrustAnchor,
    TrustConfig,
    load_config,
)
from mailatt.errors import ConfigurationError
from mailatt.ledger import Ledger
from mailatt.mime import MimeOptions, parse_message
from mailatt.models import SignatureIntegrity, SignatureTrust
from mailatt.rawmime import raw_signed_layers, verify_from_raw
from mailatt.runner import collect
from mailatt.storage import ObjectStore
from mailatt.verify import verify_workdir
from mailatt.web import create_app

from conftest import FIXTURES, fixed_clock
from signature_helpers import (
    Identity,
    NOW,
    attachment_entity,
    make_ca,
    make_leaf,
    make_self_signed,
    sign_detached,
    signed_message,
    text_entity,
    wrap_signed_message,
)

SIGNED_MAIL = FIXTURES / "signed" / "mail"


def anchor_for(identity: Identity, name: str = "test-root") -> TrustAnchor:
    return TrustAnchor(
        name=name,
        fingerprint_sha256=identity.certificate.fingerprint(hashes.SHA256()).hex(),
        path=f"{name}.pem",
        certificate=identity.certificate,
    )


def trust_for(identity: Identity) -> TrustConfig:
    return TrustConfig(anchors=(anchor_for(identity),), fingerprint="test")


@pytest.fixture(scope="module")
def authorities() -> Iterator[dict[str, Identity]]:
    ca = make_ca()
    trusted = make_leaf(ca, "Trusted Sender", "trusted@demo.invalid")
    other_ca = make_ca("unrelated root")
    self_signed = make_self_signed("Self Signed", "self@demo.invalid")
    yield {
        "ca": ca,
        "trusted": trusted,
        "other_ca": other_ca,
        "self_signed": self_signed,
    }


@pytest.fixture()
def signed_config(tmp_path: Path) -> Config:
    return load_config(
        FIXTURES / "policy" / "signed.yaml", workdir_override=tmp_path / "work"
    )


def test_fixture_anchors_are_local_ca_certificates(signed_config: Config) -> None:
    assert len(signed_config.trust.anchors) == 1
    anchor = signed_config.trust.anchors[0]
    assert anchor.name == "demo-root"
    assert len(anchor.fingerprint_sha256) == 64
    assert b"PRIVATE KEY" not in (FIXTURES / "signed" / "certs" / "demo-root.pem").read_bytes()


def test_same_bytes_trusted_and_untrusted_differ(signed_config: Config) -> None:
    """Two messages share signed bytes; only the local anchor separates trust."""
    trusted = (SIGNED_MAIL / "0001.trusted.eml").read_bytes()
    self_signed = (SIGNED_MAIL / "0002.self-signed.eml").read_bytes()
    trusted_parsed = parse_message(
        trusted, MimeOptions(trust=signed_config.trust, signature_time=NOW)
    )
    self_parsed = parse_message(
        self_signed, MimeOptions(trust=signed_config.trust, signature_time=NOW)
    )
    assert trusted_parsed.signature.integrity is SignatureIntegrity.VALID
    assert self_parsed.signature.integrity is SignatureIntegrity.VALID
    assert trusted_parsed.signature.trust is SignatureTrust.TRUSTED
    assert self_parsed.signature.trust is SignatureTrust.UNTRUSTED
    assert trusted_parsed.signature.verdict == "trusted"
    assert self_parsed.signature.verdict == "integrity_valid_but_untrusted"
    assert self_parsed.signature.signer is not None
    assert self_parsed.signature.signer.self_issued is True
    # The signed MIME payload is byte-identical in both messages.
    assert (
        trusted_parsed.signature.signed_content_sha256
        == self_parsed.signature.signed_content_sha256
    )


def test_valid_signature_from_unknown_ca_is_not_trusted(authorities) -> None:
    entity = attachment_entity()
    message = signed_message(authorities["trusted"], entity=entity)
    parsed = parse_message(
        message, MimeOptions(trust=trust_for(authorities["other_ca"]), signature_time=NOW)
    )
    assert parsed.signature.integrity is SignatureIntegrity.VALID
    assert parsed.signature.trust is SignatureTrust.UNTRUSTED
    assert parsed.signature.trust_reason_code == "unknown_anchor"
    assert parsed.signature.verdict == "integrity_valid_but_untrusted"
    assert parsed.signature.anchor_fingerprint == ""


def test_no_anchors_means_no_trust(authorities) -> None:
    message = signed_message(authorities["trusted"])
    parsed = parse_message(
        message, MimeOptions(trust=TrustConfig(), signature_time=NOW)
    )
    assert parsed.signature.integrity is SignatureIntegrity.VALID
    assert parsed.signature.trust is SignatureTrust.UNTRUSTED
    assert parsed.signature.verdict == "integrity_valid_but_untrusted"


def test_tampered_signed_bytes_become_invalid(authorities) -> None:
    message = signed_message(authorities["trusted"])
    tampered = message.replace(b"Signed body", b"Signed BODY")
    parsed = parse_message(
        tampered, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert parsed.signature.integrity is SignatureIntegrity.INVALID
    assert parsed.signature.trust is SignatureTrust.NOT_APPLICABLE
    assert parsed.signature.reason_code == "signed_content_digest_mismatch"


def test_tampered_signature_bytes_become_invalid(authorities) -> None:
    message = signed_message(authorities["trusted"])
    marker = b"Content-Type: application/pkcs7-signature"
    start = message.index(marker)
    body_start = message.index(b"\r\n\r\n", start) + 4
    # Flip one base64 character inside the detached signature.
    tampered = bytearray(message)
    for index in range(body_start, len(tampered)):
        if chr(tampered[index]).isalnum():
            tampered[index] = ord("A") if tampered[index] != ord("A") else ord("B")
            break
    parsed = parse_message(
        bytes(tampered), MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert parsed.signature.integrity is not SignatureIntegrity.VALID
    assert parsed.signature.integrity in (
        SignatureIntegrity.INVALID,
        SignatureIntegrity.UNVERIFIABLE,
    )


def test_missing_signature_material_is_unverifiable() -> None:
    message = (SIGNED_MAIL / "0004.missing-material.eml").read_bytes()
    parsed = parse_message(message, MimeOptions(signature_time=NOW))
    assert parsed.signature.integrity is SignatureIntegrity.UNVERIFIABLE
    assert parsed.signature.verdict == "unverifiable"
    assert parsed.signature.reason_code == "signature_material_missing"


def test_unsupported_signature_protocol_is_unverifiable(authorities) -> None:
    entity = text_entity()
    signature = sign_detached(entity, authorities["trusted"])
    message = wrap_signed_message(
        entity, signature, signature_type="application/pgp-signature"
    )
    parsed = parse_message(
        message, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    # A PGP signature is not CMS; the tool refuses to call it valid.
    assert parsed.signature.integrity is not SignatureIntegrity.VALID
    assert parsed.signature.verdict in ("invalid", "unverifiable")


def test_unsigned_message_is_not_signed(authorities) -> None:
    parsed = parse_message(b"From: a@demo.invalid\nSubject: x\n\nbody\n")
    assert parsed.signature.integrity is SignatureIntegrity.NOT_SIGNED
    assert parsed.signature.trust is SignatureTrust.NOT_APPLICABLE
    assert parsed.signature.verdict == "not_signed"


def test_signature_part_is_not_offered_as_attachment(authorities) -> None:
    message = signed_message(authorities["trusted"], entity=attachment_entity())
    parsed = parse_message(
        message, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert [item.safe_filename for item in parsed.candidates] == ["note.txt"]


def test_raw_split_preserves_exact_signed_bytes(authorities) -> None:
    entity = attachment_entity(payload=b"signed\x00binary bytes")
    signature = sign_detached(entity, authorities["trusted"])
    message = wrap_signed_message(entity, signature)
    layers, diagnostics = raw_signed_layers(message)
    assert diagnostics.layer_count == 1
    assert diagnostics.first_problem == ""
    assert len(layers) == 1
    # The splitter returns exactly the entity that was signed, not a
    # re-serialized variant.
    assert layers[0].content == entity


def test_nested_signed_layer_is_found(authorities) -> None:
    inner = signed_message(authorities["trusted"])
    assert raw_signed_layers(inner)[1].layer_count == 1
    # Wrap the signed message as a message/rfc822-style outer multipart child.
    outer = (
        b"From: outer@demo.invalid\r\n"
        b"Subject: nested\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n"
        b"--outer\r\n"
        b"Content-Type: text/plain\r\n\r\nouter body\r\n"
        b"--outer\r\n"
        + inner.replace(b"\r\n", b"\r\n")
        + b"\r\n--outer--\r\n"
    )
    layers, diagnostics = raw_signed_layers(outer)
    assert len(layers) >= 1


def test_layers_are_verified_without_network(
    authorities, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args, **kwargs):  # pragma: no cover - only runs if code goes online
        raise AssertionError("network access attempted during signature verification")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    message = signed_message(authorities["trusted"], entity=attachment_entity())
    parsed = parse_message(
        message, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert parsed.signature.verdict == "trusted"


def test_collection_binds_evidence_to_source_bytes(signed_config: Config) -> None:
    result = collect(signed_config, clock=fixed_clock)
    assert result.summary.messages_ok == 4
    assert result.summary.signature_verdicts == {
        "trusted": 1,
        "integrity_valid_but_untrusted": 1,
        "invalid": 1,
        "unverifiable": 1,
    }
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        rows = {row["relative_path"]: row for row in ledger.all_messages()}
    trusted = rows["0001.trusted.eml"]
    self_signed = rows["0002.self-signed.eml"]
    tampered = rows["0003.tampered.eml"]
    assert trusted["signature_verdict"] == "trusted"
    assert trusted["signature_trust"] == "trusted"
    assert trusted["signature_anchor_fingerprint"]
    assert len(trusted["evidence_hash"]) == 64
    assert self_signed["signature_verdict"] == "integrity_valid_but_untrusted"
    assert self_signed["signature_integrity"] == "valid"
    assert self_signed["signature_trust"] == "untrusted"
    assert self_signed["signature_anchor_fingerprint"] == ""
    assert tampered["signature_verdict"] == "invalid"
    assert tampered["signature_signed_digest"]


def test_invalid_signature_attachments_are_quarantined(signed_config: Config) -> None:
    collect(signed_config, clock=fixed_clock)
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        rows = {row["message_path"]: row for row in ledger.all_attachments()}
    trusted = rows["0001.trusted.eml"]
    tampered = rows["0003.tampered.eml"]
    untrusted = rows["0002.self-signed.eml"]
    assert trusted["status"] == "accepted"
    assert trusted["signature_status"] == "none"
    assert tampered["status"] == "quarantined"
    assert tampered["object_path"] == ""
    assert tampered["quarantine_path"].startswith("quarantine/")
    assert tampered["signature_status"] == "signature_invalid"
    assert tampered["signature_reason_code"] == "message_signature_invalid"
    assert untrusted["signature_status"] == "untrusted_signer"


def test_download_never_serves_invalid_or_untrusted_claim(signed_config: Config) -> None:
    collect(signed_config, clock=fixed_clock)
    client = create_app(signed_config.workdir).test_client()
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        rows = {row["message_path"]: row for row in ledger.all_attachments()}
    tampered = client.get(f"/download/{rows['0003.tampered.eml']['id']}")
    assert tampered.status_code == 404
    trusted = client.get(f"/download/{rows['0001.trusted.eml']['id']}")
    assert trusted.status_code == 200
    assert trusted.headers["X-Mailatt-Signature-Verdict"] == "trusted"
    untrusted = client.get(f"/download/{rows['0002.self-signed.eml']['id']}")
    assert untrusted.status_code == 200
    assert (
        untrusted.headers["X-Mailatt-Signature-Verdict"]
        == "integrity_valid_but_untrusted"
    )


def test_report_exposes_evidence_and_no_private_keys(signed_config: Config) -> None:
    result = collect(signed_config, clock=fixed_clock)
    payload = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert payload["signature_policy"]["offline_only"] is True
    assert payload["signature_policy"]["anchor_count"] == 1
    assert payload["summary"]["signatures"]["trusted"] == 1
    assert payload["summary"]["signatures"]["integrity_valid_but_untrusted"] == 1
    assert payload["summary"]["signatures"]["invalid"] == 1
    anchors = payload["signature_policy"]["anchors"]
    assert anchors[0]["name"] == "demo-root"
    assert len(anchors[0]["fingerprint_sha256"]) == 64
    assert "certificate" not in anchors[0]
    verdicts = {
        item["relative_path"]: item["signature"]["verdict"]
        for item in payload["messages"]
    }
    assert verdicts["0001.trusted.eml"] == "trusted"
    assert verdicts["0002.self-signed.eml"] == "integrity_valid_but_untrusted"
    assert verdicts["0003.tampered.eml"] == "invalid"
    for path in result.report_paths.values():
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text
    markdown = result.report_paths["markdown"].read_text(encoding="utf-8")
    assert "## 来源认证证据" in markdown
    assert "integrity_valid_but_untrusted" in markdown
    assert "## 签名邮件台账" in markdown


def test_web_message_signature_json(signed_config: Config) -> None:
    collect(signed_config, clock=fixed_clock)
    client = create_app(signed_config.workdir).test_client()
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        rows = {row["relative_path"]: row for row in ledger.all_messages()}
    payload = client.get(f"/api/messages/{rows['0001.trusted.eml']['id']}/signature")
    assert payload.status_code == 200
    data = payload.get_json()
    assert data["integrity"] == "valid"
    assert data["trust"] == "trusted"
    assert data["verdict"] == "trusted"
    assert data["trusted_identity"] is True
    assert data["anchor_fingerprint"]
    assert len(data["signer"]["fingerprint_sha256"]) == 64
    untrusted = client.get(
        f"/api/messages/{rows['0002.self-signed.eml']['id']}/signature"
    ).get_json()
    assert untrusted["integrity"] == "valid"
    assert untrusted["verdict"] == "integrity_valid_but_untrusted"
    assert untrusted["trusted_identity"] is False
    page = client.get(f"/messages/{rows['0002.self-signed.eml']['id']}").get_data(as_text=True)
    assert "integrity_valid_but_untrusted" in page
    assert "来源认证" in page


def test_rerun_is_idempotent_and_keeps_evidence(signed_config: Config) -> None:
    first = collect(signed_config, clock=fixed_clock)
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        before = {
            row["relative_path"]: (
                row["signature_verdict"],
                row["evidence_hash"],
                row["signature_blob_sha256"],
            )
            for row in ledger.all_messages()
        }
        counts_before = (
            ledger.count_rows("runs"),
            ledger.count_rows("messages"),
            ledger.count_rows("attachments"),
        )
    second = collect(signed_config, clock=fixed_clock)
    assert second.summary.messages_skipped == 4
    with Ledger(signed_config.workdir, readonly=True) as ledger:
        after = {
            row["relative_path"]: (
                row["signature_verdict"],
                row["evidence_hash"],
                row["signature_blob_sha256"],
            )
            for row in ledger.all_messages()
        }
        counts_after = (
            ledger.count_rows("runs"),
            ledger.count_rows("messages"),
            ledger.count_rows("attachments"),
        )
    assert before == after
    assert counts_after == (counts_before[0] + 1, counts_before[1], counts_before[2])
    assert verify_workdir(signed_config.workdir).ok


def test_source_change_forces_reverification(
    signed_config: Config, tmp_path: Path
) -> None:
    collect(signed_config, clock=fixed_clock)
    trusted_path = signed_config.sources[0].path / "0001.trusted.eml"
    original = trusted_path.read_bytes()
    tampered = original.replace(b"signed attachment payload", b"signed attachment PAYLOAD")
    try:
        trusted_path.write_bytes(tampered)
        second = collect(signed_config, clock=fixed_clock)
        assert second.summary.messages_skipped == 3
        with Ledger(signed_config.workdir, readonly=True) as ledger:
            row = next(
                item
                for item in ledger.all_messages()
                if item["relative_path"] == "0001.trusted.eml"
            )
            attachment = next(
                item
                for item in ledger.attachments_for_message(row["id"])
            )
        assert row["signature_verdict"] == "invalid"
        assert row["signature_integrity"] == "invalid"
        # The previously trusted attachment must no longer be downloadable.
        assert attachment["status"] in ("quarantined", "rejected")
        if attachment["status"] == "quarantined":
            assert attachment["quarantine_path"].startswith("quarantine/")
    finally:
        trusted_path.write_bytes(original)


def test_anchor_change_forces_reverification_without_byte_change(
    tmp_path: Path,
) -> None:
    """Adding a trust anchor must re-evaluate existing valid signatures."""
    source = tmp_path / "mail"
    source.mkdir()
    for name in ("0001.trusted.eml", "0002.self-signed.eml"):
        shutil.copy(SIGNED_MAIL / name, source / name)
    trust = load_config(
        FIXTURES / "policy" / "signed.yaml", workdir_override=tmp_path / "work"
    )
    no_anchor = Config(
        sources=trust.sources,
        policy=trust.policy,
        workdir=trust.workdir,
        trust=TrustConfig(),
    )
    collect(no_anchor, clock=fixed_clock)
    with Ledger(no_anchor.workdir, readonly=True) as ledger:
        initial = {
            row["relative_path"]: row["signature_verdict"]
            for row in ledger.all_messages()
        }
    assert initial["0001.trusted.eml"] == "integrity_valid_but_untrusted"
    augmented = Config(
        sources=trust.sources,
        policy=trust.policy,
        workdir=trust.workdir,
        trust=trust.trust,
    )
    assert augmented.evidence_fingerprint != no_anchor.evidence_fingerprint
    second = collect(augmented, clock=fixed_clock)
    assert second.summary.messages_skipped == 0
    with Ledger(augmented.workdir, readonly=True) as ledger:
        after = {
            row["relative_path"]: row["signature_verdict"]
            for row in ledger.all_messages()
        }
    assert after["0001.trusted.eml"] == "trusted"
    assert after["0002.self-signed.eml"] == "integrity_valid_but_untrusted"


def test_verify_flags_invalid_signature_attachment(tmp_path: Path) -> None:
    config = load_config(
        FIXTURES / "policy" / "signed.yaml", workdir_override=tmp_path / "work"
    )
    collect(config, clock=fixed_clock)
    with Ledger(config.workdir) as ledger:
        run_id = ledger.begin_run("2024-05-17T12:00:00+00:00", "manual")
        row = next(
            item
            for item in ledger.all_messages()
            if item["relative_path"] == "0003.tampered.eml"
        )
        ledger.conn.execute(
            "UPDATE attachments SET status='accepted', object_path=sha256 WHERE message_id=?",
            (row["id"],),
        )
        ledger.conn.commit()
    result = verify_workdir(config.workdir)
    codes = {issue["code"] for issue in result.issues}
    assert "INVALID_SIGNATURE_ATTACHMENT_ACCEPTED" in codes


def test_config_rejects_private_key_anchor(tmp_path: Path, authorities) -> None:
    key_path = tmp_path / "anchor.pem"
    key_path.write_bytes(
        authorities["ca"].private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {SIGNED_MAIL}
trust:
  anchors:
    - name: bad
      certificate: ./anchor.pem
policy: {{}}
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError) as caught:
        load_config(config_path, workdir_override=tmp_path / "work")
    assert caught.value.code in ("TRUST_ANCHOR_UNSAFE", "CONFIG_INVALID")


def test_config_rejects_leaf_certificate_as_anchor(tmp_path: Path, authorities) -> None:
    leaf_path = tmp_path / "leaf.pem"
    leaf_path.write_bytes(authorities["trusted"].certificate.public_bytes(serialization.Encoding.PEM))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {SIGNED_MAIL}
trust:
  anchors:
    - name: leaf
      certificate: ./leaf.pem
policy: {{}}
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_config(config_path, workdir_override=tmp_path / "work")


def test_config_rejects_unknown_trust_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""version: 1
sources:
  - name: demo
    path: {SIGNED_MAIL}
trust:
  fetch_online: true
policy: {{}}
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="fetch_online"):
        load_config(config_path, workdir_override=tmp_path / "work")


def test_ledger_migrates_legacy_messages_table(tmp_path: Path) -> None:
    """A ledger created by the older schema upgrades without losing rows."""
    import sqlite3

    workdir = tmp_path / "legacy"
    workdir.mkdir()
    conn = sqlite3.connect(workdir / "ledger.sqlite3")
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE,
            started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
            policy_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL, relative_path TEXT NOT NULL,
            digest TEXT NOT NULL, size INTEGER NOT NULL,
            message_id TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
            sender TEXT NOT NULL DEFAULT '', sent_at TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '',
            error_detail TEXT NOT NULL DEFAULT '',
            warnings_json TEXT NOT NULL DEFAULT '[]',
            policy_hash TEXT NOT NULL, first_seen_run TEXT NOT NULL,
            last_seen_run TEXT NOT NULL, UNIQUE(source_name, relative_path)
        );
        CREATE TABLE attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            part_id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
            filename TEXT NOT NULL DEFAULT '', safe_filename TEXT NOT NULL DEFAULT '',
            media_type TEXT NOT NULL DEFAULT '', disposition TEXT NOT NULL DEFAULT '',
            nested_depth INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
            reason_code TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
            object_path TEXT NOT NULL DEFAULT '',
            quarantine_path TEXT NOT NULL DEFAULT '',
            first_seen_run TEXT NOT NULL, last_seen_run TEXT NOT NULL,
            UNIQUE(message_id, part_id)
        );
        INSERT INTO messages(
            source_name, relative_path, digest, size, status, policy_hash,
            first_seen_run, last_seen_run)
        VALUES ('demo', 'legacy.eml', 'deadbeef', 12, 'ok', 'p', 'run-000001', 'run-000001');
        """
    )
    conn.commit()
    conn.close()
    with Ledger(workdir) as ledger:
        row = ledger.all_messages()[0]
        assert row["signature_integrity"] == "unverifiable"
        assert row["signature_trust"] == "not_applicable"
        assert row["signature_reason_code"] == "pre_signature_schema"
        assert ledger.message_state("demo", "legacy.eml")["evidence_hash"] == ""


def test_malformed_cms_is_unverifiable_not_valid(authorities) -> None:
    entity = text_entity()
    signature = sign_detached(entity, authorities["trusted"])
    corrupted = signature[:-16]
    message = wrap_signed_message(entity, corrupted)
    parsed = parse_message(
        message, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert parsed.signature.integrity is SignatureIntegrity.UNVERIFIABLE
    assert parsed.signature.verdict == "unverifiable"


def test_extra_signed_parts_are_unverifiable(authorities) -> None:
    """A signed layer with a third body part is refused, not partially trusted."""
    entity = text_entity()
    signature = sign_detached(entity, authorities["trusted"])
    message = wrap_signed_message(entity, signature)
    tampered = message.replace(
        b"\r\n--signed-boundary--\r\n",
        b"\r\n--signed-boundary\r\nContent-Type: text/plain\r\n\r\nsmuggled\r\n"
        b"--signed-boundary--\r\n",
    )
    parsed = parse_message(
        tampered, MimeOptions(trust=trust_for(authorities["ca"]), signature_time=NOW)
    )
    assert parsed.signature.integrity is SignatureIntegrity.UNVERIFIABLE
    assert parsed.signature.reason_code == "signed_layer_has_extra_parts"


def test_mixed_valid_and_broken_layers_stay_unverifiable(authorities) -> None:
    """A second, undelimitable signed layer must not be silently ignored."""
    valid = signed_message(authorities["trusted"], entity=text_entity())
    broken = (
        b"Content-Type: multipart/signed; boundary=broken\r\n\r\n"
        b"--broken\r\nContent-Type: text/plain\r\n\r\nno closing boundary\r\n"
    )
    outer = (
        b"From: outer@demo.invalid\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
        b"--outer\r\n" + broken + b"\r\n--outer\r\n"
        + valid + b"\r\n--outer--\r\n"
    )
    evidence, diagnostics = verify_from_raw(
        outer, trust_for(authorities["ca"]), NOW
    )
    assert diagnostics.first_problem
    assert evidence.integrity is SignatureIntegrity.UNVERIFIABLE


def test_verification_can_be_disabled(authorities) -> None:
    message = signed_message(authorities["trusted"])
    parsed = parse_message(
        message,
        MimeOptions(
            trust=trust_for(authorities["ca"]),
            signature_time=NOW,
            verify_signatures=False,
        ),
    )
    assert parsed.signature.integrity is SignatureIntegrity.UNVERIFIABLE
    assert parsed.signature.reason_code == "signature_verification_disabled"
