"""Content-addressed object storage with atomic writes and no original names."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from .errors import StorageError
from .models import StorageKind, StoredObject
from .util import SHA256_RE, atomic_write, is_within, sha256_bytes

OBJECT_REL_RE = re.compile(r"^(objects|quarantine)/[0-9a-f]{2}/[0-9a-f]{64}$")

KIND_ROOTS = {
    StorageKind.OBJECT: "objects",
    StorageKind.QUARANTINE: "quarantine",
}


class ObjectStore:
    """Store raw attachment bytes under their SHA-256 digest."""

    def __init__(self, workdir: Path, *, create: bool = True) -> None:
        self.workdir = workdir.resolve(strict=False)
        if create:
            for name in ("objects", "quarantine", "reports"):
                directory = self.workdir / name
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                    try:
                        os.chmod(directory, 0o700)
                    except OSError:
                        pass
                except OSError as exc:
                    raise StorageError(f"cannot create {directory}: {exc}") from exc

    def relative_path(self, kind: StorageKind, digest: str) -> str:
        if not SHA256_RE.fullmatch(digest):
            raise StorageError("invalid SHA-256 digest", code="STORAGE_UNSAFE_PATH")
        return f"{KIND_ROOTS[kind]}/{digest[:2]}/{digest}"

    def _absolute(self, relative_path: str, *, existing: bool) -> Path:
        if not OBJECT_REL_RE.fullmatch(relative_path):
            raise StorageError(
                f"unsafe object path: {relative_path}", code="STORAGE_UNSAFE_PATH"
            )
        pure = PurePosixPath(relative_path)
        target = self.workdir.joinpath(*pure.parts)
        if not is_within(target, self.workdir):
            raise StorageError(
                f"object path escapes workdir: {relative_path}", code="STORAGE_UNSAFE_PATH"
            )
        if not is_within(target.parent, self.workdir):
            raise StorageError(
                f"object parent escapes workdir: {relative_path}", code="STORAGE_UNSAFE_PATH"
            )
        if existing:
            try:
                if target.is_symlink() or not target.is_file():
                    raise StorageError(
                        f"object is not a regular file: {relative_path}",
                        code="STORAGE_UNSAFE_PATH",
                    )
            except OSError as exc:
                raise StorageError(f"cannot inspect {relative_path}: {exc}") from exc
        return target

    def put(
        self,
        kind: StorageKind,
        data: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> StoredObject:
        digest = sha256_bytes(data)
        if expected_sha256 is not None and digest != expected_sha256:
            raise StorageError("attachment digest changed before write", code="STORAGE_MISMATCH")
        relative = self.relative_path(kind, digest)
        target = self._absolute(relative, existing=False)
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise StorageError(
                    f"object path is not a regular file: {relative}",
                    code="STORAGE_UNSAFE_PATH",
                )
            try:
                current_size = target.stat().st_size
            except OSError as exc:
                raise StorageError(f"cannot stat {relative}: {exc}") from exc
            if current_size != len(data):
                raise StorageError(
                    f"existing object size differs from digest content: {digest}",
                    code="STORAGE_MISMATCH",
                )
            return StoredObject(digest, len(data), relative, kind, created=False)
        try:
            atomic_write(target, data, mode=0o600)
        except OSError as exc:
            raise StorageError(f"cannot write object {digest}: {exc}") from exc
        return StoredObject(digest, len(data), relative, kind, created=True)

    def exists(self, kind: StorageKind, digest: str) -> bool:
        relative = self.relative_path(kind, digest)
        try:
            target = self._absolute(relative, existing=True)
            return target.is_file() and not target.is_symlink()
        except StorageError:
            return False

    def _iter_kind(self, kind: StorageKind) -> list[StoredObject]:
        root = self.workdir / KIND_ROOTS[kind]
        if not root.is_dir() or root.is_symlink():
            return []
        found: list[StoredObject] = []
        try:
            prefixes = sorted(
                (entry for entry in os.scandir(root) if entry.is_dir(follow_symlinks=False)),
                key=lambda entry: entry.name,
            )
        except OSError as exc:
            raise StorageError(f"cannot list object store: {exc}") from exc
        for prefix_entry in prefixes:
            prefix = prefix_entry.name
            if not re.fullmatch(r"[0-9a-f]{2}", prefix):
                continue
            try:
                entries = sorted(os.scandir(prefix_entry.path), key=lambda item: item.name)
            except OSError as exc:
                raise StorageError(f"cannot list {prefix_entry.path}: {exc}") from exc
            for entry in entries:
                digest = entry.name
                if not SHA256_RE.fullmatch(digest) or not digest.startswith(prefix):
                    continue
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError as exc:
                    raise StorageError(f"cannot stat {entry.path}: {exc}") from exc
                relative = f"{KIND_ROOTS[kind]}/{prefix}/{digest}"
                found.append(StoredObject(digest, size, relative, kind, created=False))
        return found

    def list_files(self) -> list[StoredObject]:
        files = self._iter_kind(StorageKind.OBJECT) + self._iter_kind(StorageKind.QUARANTINE)
        return sorted(files, key=lambda item: (item.kind.value, item.relative_path))

    def accepted_digests(self) -> set[str]:
        return {item.sha256 for item in self._iter_kind(StorageKind.OBJECT)}

    def read_bytes(self, relative_path: str) -> bytes:
        target = self._absolute(relative_path, existing=True)
        try:
            return target.read_bytes()
        except OSError as exc:
            raise StorageError(f"cannot read {relative_path}: {exc}") from exc

    def resolve_file(self, relative_path: str) -> Path:
        return self._absolute(relative_path, existing=True)
