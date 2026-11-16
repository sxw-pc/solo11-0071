"""Integration tests for the signed fixture shipped with the repository.

These exercise the acceptance scenario end to end through the public CLI and
confirm the offline, no-private-key, no-network properties of the demo assets.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

from mailatt.cli import main
from mailatt.config import load_config
from mailatt.ledger import Ledger

from conftest import FIXTURES


SIGNED_CONFIG = FIXTURES / "policy" / "signed.yaml"
SIGNED_MAIL = FIXTURES / "signed" / "mail"


def test_signed_fixture_files_are_synthetic_and_keyless() -> None:
    for path in sorted((FIXTURES / "signed").rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert b"PRIVATE KEY" not in data, path
    assert {item.name for item in SIGNED_MAIL.iterdir()} == {
        "0001.trusted.eml",
        "0002.self-signed.eml",
        "0003.tampered.eml",
        "0004.missing-material.eml",
    }


def test_two_signed_messages_share_bytes_but_differ_in_trust() -> None:
    from mailatt.mime import MimeOptions, parse_message

    config = load_config(SIGNED_CONFIG, workdir_override=Path("/tmp/signature-check"))
    trusted = parse_message(
        (SIGNED_MAIL / "0001.trusted.eml").read_bytes(),
        MimeOptions(trust=config.trust),
    )
    untrusted = parse_message(
        (SIGNED_MAIL / "0002.self-signed.eml").read_bytes(),
        MimeOptions(trust=config.trust),
    )
    assert trusted.signature.signed_content_sha256 == untrusted.signature.signed_content_sha256
    assert trusted.signature.integrity.value == untrusted.signature.integrity.value == "valid"
    assert trusted.signature.verdict == "trusted"
    assert untrusted.signature.verdict == "integrity_valid_but_untrusted"


def test_cli_signature_command_reports_verdicts(tmp_path: Path, capsys) -> None:
    code = main(
        [
            "signature",
            "--eml",
            str(SIGNED_MAIL / "0001.trusted.eml"),
            "--config",
            str(SIGNED_CONFIG),
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["integrity"] == "valid"
    assert payload["trust"] == "trusted"
    assert payload["verdict"] == "trusted"
    assert payload["anchors"]

    code = main(
        [
            "signature",
            "--eml",
            str(SIGNED_MAIL / "0002.self-signed.eml"),
            "--config",
            str(SIGNED_CONFIG),
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["integrity"] == "valid"
    assert payload["trust"] == "untrusted"
    assert payload["verdict"] == "integrity_valid_but_untrusted"
    assert payload["signer"]["self_issued"] is True


def test_cli_signature_rejects_unreadable_file(tmp_path: Path, capsys) -> None:
    code = main(["signature", "--eml", str(tmp_path / "missing.eml")])
    assert code == 1
    assert "MESSAGE_FAILED" in capsys.readouterr().err


def test_signed_run_is_offline(tmp_path: Path, monkeypatch, capsys) -> None:
    def deny(*args, **kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    workdir = tmp_path / "signed-work"
    assert (
        main(
            [
                "run",
                "--config",
                str(SIGNED_CONFIG),
                "--workdir",
                str(workdir),
            ]
        )
        == 0
    )
    # The run plus its report render must not need the network.
    with Ledger(workdir, readonly=True) as ledger:
        verdicts = {
            row["relative_path"]: row["signature_verdict"]
            for row in ledger.all_messages()
        }
    assert verdicts == {
        "0001.trusted.eml": "trusted",
        "0002.self-signed.eml": "integrity_valid_but_untrusted",
        "0003.tampered.eml": "invalid",
        "0004.missing-material.eml": "unverifiable",
    }
    assert (workdir / "reports" / "report.html").is_file()
