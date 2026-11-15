"""Helpers for recoverable-commit tests: synthetic mail sources and configs."""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import yaml

from mailatt.config import Config, load_config


def build_email(
    *,
    subject: str = "Synthetic",
    message_id: str = "synth@demo.invalid",
    attachments: tuple[tuple[str, str, bytes], ...] = (),
) -> bytes:
    """Build a multipart/mixed message with (filename, media_type, payload) parts."""
    message = EmailMessage()
    message["From"] = "sender@demo.invalid"
    message["To"] = "archive@demo.invalid"
    message["Subject"] = subject
    message["Date"] = "Mon, 02 Jan 2023 09:30:00 +0000"
    message["Message-ID"] = f"<{message_id}>"
    message.set_content("Synthetic body for recovery tests.")
    for filename, media_type, payload in attachments:
        maintype, subtype = media_type.split("/", 1)
        message.add_attachment(
            payload,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
        )
    return message.as_bytes()


def write_source(
    tmp_path: Path,
    *,
    files: dict[str, bytes],
    source_name: str = "mail",
) -> tuple[Path, Path]:
    """Create a source tree and a YAML config pointing at it; return both."""
    source = tmp_path / "source"
    source.mkdir(parents=True)
    for relative, data in files.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    workdir = tmp_path / "work"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "sources": [
                    {"name": source_name, "path": str(source), "kind": "eml"}
                ],
                "workdir": str(workdir),
                "policy": {
                    "allowed_extensions": [".txt", ".pdf", ".csv", ".json", ".png"],
                    "allowed_media_types": [
                        "text/plain",
                        "application/pdf",
                        "text/csv",
                        "application/json",
                        "image/png",
                        "application/octet-stream",
                    ],
                    "quarantine_extensions": [".exe"],
                    "blocked_extensions": [".lnk"],
                    "max_file_bytes": 8 * 1024 * 1024,
                    "max_message_bytes": 32 * 1024 * 1024,
                    "max_attachments_per_message": 20,
                },
            }
        ),
        encoding="utf-8",
    )
    return config_path, workdir


def load_test_config(config_path: Path) -> Config:
    return load_config(config_path)


def staging_journals(workdir: Path) -> list[Path]:
    staging = workdir / "staging"
    if not staging.is_dir():
        return []
    return sorted(staging.glob("*/journal.json"))


def uncommitted_entries(workdir: Path) -> list[Path]:
    root = workdir / "uncommitted"
    if not root.is_dir():
        return []
    return sorted(path for path in root.iterdir() if path.is_dir())
