"""Small deterministic utilities shared by the collector modules."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
WINDOWS_INVALID_RE = re.compile(r'[<>:"|?*]')
RESERVED_WINDOWS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    """Return one canonical timestamp representation."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def decode_header_value(value: Any) -> str:
    """Decode RFC 2047 header text without ever raising for broken input."""
    if value is None:
        return ""
    raw = str(value)
    try:
        pieces = decode_header(raw)
    except Exception:
        return raw.strip()
    output: list[str] = []
    for piece, charset in pieces:
        if isinstance(piece, bytes):
            try:
                output.append(piece.decode(charset or "utf-8", errors="replace"))
            except LookupError:
                output.append(piece.decode("utf-8", errors="replace"))
        else:
            output.append(piece)
    return "".join(output).strip()


def detect_path_traversal(name: str) -> bool:
    """Detect unsafe path syntax in an untrusted attachment name."""
    if not name:
        return False
    if "\x00" in name or "/" in name or "\\" in name:
        return True
    if re.match(r"^[A-Za-z]:", name.strip()):
        return True
    return any(part == ".." for part in re.split(r"[/\\]", name))


def sanitize_filename(name: str, *, fallback: str = "attachment.bin", max_length: int = 120) -> str:
    """Create a display/download name that is never used as an archive path."""
    candidate = (name or "").strip()
    candidate = CONTROL_RE.sub("", candidate)
    candidate = candidate.replace("\\", "/")
    candidate = PurePosixPath(candidate).name
    candidate = WINDOWS_INVALID_RE.sub("_", candidate).strip(" .")
    if not candidate:
        candidate = fallback
    stem, suffix = os.path.splitext(candidate)
    if stem.upper() in RESERVED_WINDOWS:
        candidate = f"_{candidate}"
        stem = f"_{stem}"
    if max_length > 0 and len(candidate) > max_length:
        available = max(8, max_length - len(suffix))
        candidate = f"{stem[:available]}{suffix}"
    return candidate or fallback


def safe_relative_path(path: str) -> bool:
    """Accept only normalized POSIX relative paths used in the manifest."""
    if not path or "\\" in path or path.startswith("/"):
        return False
    pure = PurePosixPath(path)
    return bool(pure.parts) and all(part not in ("", ".", "..") for part in pure.parts)


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write bytes with a same-directory temporary file and atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    atomic_write(path, text.encode("utf-8"), mode=mode)


def atomic_write_json(path: Path, payload: Any) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, text)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted(set(values))
