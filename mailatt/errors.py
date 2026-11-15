"""Stable error codes and exception types for mailatt."""

from __future__ import annotations

from typing import Any


ERROR_MESSAGES: dict[str, str] = {
    "CONFIG_INVALID": "configuration is invalid",
    "CONFIG_NOT_FOUND": "configuration file was not found",
    "SOURCE_NOT_FOUND": "configured source directory was not found",
    "SOURCE_UNSAFE": "source or work directory failed the path-safety check",
    "DISCOVERY_FAILED": "mail discovery failed",
    "EMPTY_MESSAGE": "message file is empty",
    "MALFORMED_MIME": "message MIME structure is malformed",
    "ATTACHMENT_DECODE_FAILED": "attachment payload could not be decoded",
    "MESSAGE_TOO_LARGE": "message exceeds the configured size limit",
    "MESSAGE_FAILED": "message processing failed",
    "STORAGE_FAILED": "content-addressed storage operation failed",
    "STORAGE_UNSAFE_PATH": "object path failed the safety check",
    "STORAGE_MISMATCH": "an existing object does not match its content hash",
    "STAGING_MISSING": "a staged payload needed for commit recovery is missing",
    "STAGING_CORRUPT": "a staged payload fails its recorded digest check",
    "COMMIT_JOURNAL_INVALID": "a commit journal cannot be parsed or fails validation",
    "RECOVERY_FAILED": "commit recovery could not reach a consistent terminal state",
    "LEDGER_FAILED": "SQLite ledger operation failed",
    "LEDGER_NOT_FOUND": "ledger database was not found",
    "VERIFY_FAILED": "archive verification failed",
    "WEB_NOT_READY": "work directory is not ready for inspection",
    "INVALID_ARGUMENT": "command-line argument is invalid",
}


class MailattError(Exception):
    """Base class carrying a stable code and a safe user-facing detail."""

    code = "MESSAGE_FAILED"

    def __init__(self, detail: str = "", *, code: str | None = None) -> None:
        if code:
            self.code = code
        self.detail = detail
        super().__init__(detail or ERROR_MESSAGES.get(self.code, self.code))

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": ERROR_MESSAGES.get(self.code, self.code),
            "detail": self.detail,
        }


class ConfigurationError(MailattError):
    code = "CONFIG_INVALID"


class DiscoveryError(MailattError):
    code = "DISCOVERY_FAILED"


class MimeParseError(MailattError):
    code = "MALFORMED_MIME"


class StorageError(MailattError):
    code = "STORAGE_FAILED"


class LedgerError(MailattError):
    code = "LEDGER_FAILED"


class VerificationError(MailattError):
    code = "VERIFY_FAILED"


def normalize_error(exc: BaseException) -> MailattError:
    """Convert arbitrary failures into a stable message-level error."""

    if isinstance(exc, MailattError):
        return exc
    if isinstance(exc, OSError):
        return MailattError(f"{type(exc).__name__}: {exc}", code="MESSAGE_FAILED")
    return MailattError(f"{type(exc).__name__}: {exc}", code="MESSAGE_FAILED")
