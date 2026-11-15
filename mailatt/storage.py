"""Content-addressed object storage with atomic writes and no original names."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from .errors import StorageError
from .models import StorageKind, StoredObject
from .util import SHA256_RE, atomic_write, is_within, sha256_bytes

OBJECT_REL_RE = re.compile(r"^(objects|quarantine)/[0-9a-f]{2}/[0-9a-f]{64}$")
STAGING_REL_RE = re.compile(r"^staging/[0-9a-f]{64}/[0-9a-f]{64}$")
COMMIT_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
STAGED_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
UNCOMMITTED_ID_RE = re.compile(r"^[0-9a-f]{64}$")

KIND_ROOTS = {
    StorageKind.OBJECT: "objects",
    StorageKind.QUARANTINE: "quarantine",
}


class ObjectStore:
    """Store raw attachment bytes under their SHA-256 digest."""

    def __init__(self, workdir: Path, *, create: bool = True) -> None:
        self.workdir = workdir.resolve(strict=False)
        if create:
            for name in ("objects", "quarantine", "reports", "staging", "uncommitted"):
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

    # ------------------------------------------------------------------
    # Two-phase commit support: staging area and uncommitted quarantine.
    # ------------------------------------------------------------------

    @staticmethod
    def validate_commit_key(commit_key: str) -> None:
        if not COMMIT_KEY_RE.fullmatch(commit_key):
            raise StorageError("invalid commit key", code="STORAGE_UNSAFE_PATH")

    def staging_relative(self, commit_key: str, digest: str) -> str:
        self.validate_commit_key(commit_key)
        if not STAGED_DIGEST_RE.fullmatch(digest):
            raise StorageError("invalid staged digest", code="STORAGE_UNSAFE_PATH")
        return f"staging/{commit_key}/{digest}"

    def staging_path(self, commit_key: str, digest: str) -> Path:
        relative = self.staging_relative(commit_key, digest)
        target = self.workdir / relative
        if not is_within(target, self.workdir):
            raise StorageError(
                f"staging path escapes workdir: {relative}", code="STORAGE_UNSAFE_PATH"
            )
        return target

    def staging_dir(self, commit_key: str) -> Path:
        self.validate_commit_key(commit_key)
        target = self.workdir / "staging" / commit_key
        if not is_within(target, self.workdir / "staging"):
            raise StorageError(
                f"staging directory escapes workdir: {commit_key}", code="STORAGE_UNSAFE_PATH"
            )
        return target

    def put_staged(self, commit_key: str, data: bytes, *, expected_sha256: str) -> str:
        """Stage attachment bytes under staging/<commit-key>/<sha256>; idempotent."""
        digest = sha256_bytes(data)
        if digest != expected_sha256:
            raise StorageError("attachment digest changed before staging", code="STORAGE_MISMATCH")
        target = self.staging_path(commit_key, digest)
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise StorageError(
                    f"staged path is not a regular file: {target.name}",
                    code="STORAGE_UNSAFE_PATH",
                )
            try:
                if target.stat().st_size != len(data):
                    raise StorageError(
                        f"staged object size differs from digest content: {digest}",
                        code="STORAGE_MISMATCH",
                    )
            except OSError as exc:
                raise StorageError(f"cannot stat staged {digest}: {exc}") from exc
        else:
            try:
                atomic_write(target, data, mode=0o600)
            except OSError as exc:
                raise StorageError(f"cannot stage object {digest}: {exc}") from exc
        return self.staging_relative(commit_key, digest)

    def staged_exists(self, commit_key: str, digest: str) -> bool:
        target = self.staging_path(commit_key, digest)
        return target.is_file() and not target.is_symlink()

    def list_staged(self, commit_key: str) -> list[str]:
        directory = self.staging_dir(commit_key)
        if not directory.is_dir() or directory.is_symlink():
            return []
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise StorageError(f"cannot list staging directory: {exc}") from exc
        return [
            entry.name
            for entry in entries
            if STAGED_DIGEST_RE.fullmatch(entry.name)
            and entry.is_file(follow_symlinks=False)
            and not entry.is_symlink()
        ]

    def list_commit_keys(self) -> list[str]:
        root = self.workdir / "staging"
        if not root.is_dir() or root.is_symlink():
            return []
        try:
            entries = sorted(os.scandir(root), key=lambda item: item.name)
        except OSError as exc:
            raise StorageError(f"cannot list staging area: {exc}") from exc
        return [
            entry.name
            for entry in entries
            if COMMIT_KEY_RE.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False)
        ]

    def read_staged(self, commit_key: str, digest: str) -> bytes:
        target = self.staging_path(commit_key, digest)
        if not target.is_file() or target.is_symlink():
            raise StorageError(
                f"staged object is missing: {digest}", code="STAGING_MISSING"
            )
        try:
            return target.read_bytes()
        except OSError as exc:
            raise StorageError(f"cannot read staged {digest}: {exc}") from exc

    def promote_staged(
        self,
        commit_key: str,
        digest: str,
        kind: StorageKind,
        *,
        expected_size: int | None = None,
    ) -> StoredObject:
        """Move a staged payload to its content-addressed final location.

        Re-promotion is a no-op when the final object already exists.
        """
        source = self.staging_path(commit_key, digest)
        if not source.is_file() or source.is_symlink():
            # Fall back to an already-promoted object: the staged copy may be
            # gone when promotion succeeded before an interruption.
            if target.exists() and target.is_file() and not target.is_symlink():
                try:
                    size = target.stat().st_size
                except OSError as exc:
                    raise StorageError(f"cannot stat {relative}: {exc}") from exc
                if expected_size is not None and size != expected_size:
                    raise StorageError(
                        f"existing object size differs from journal: {digest}",
                        code="STORAGE_MISMATCH",
                    )
                try:
                    if sha256_file(target) != digest:
                        raise StorageError(
                            f"promoted object does not match its content hash: {digest}",
                            code="STORAGE_MISMATCH",
                        )
                except OSError as exc:
                    raise StorageError(f"cannot read {relative}: {exc}") from exc
                return StoredObject(digest, size, relative, kind, created=False)
            raise StorageError(
                f"staged object is missing: {digest}", code="STAGING_MISSING"
            )
        relative = self.relative_path(kind, digest)
        target = self._absolute(relative, existing=False)
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise StorageError(
                    f"object path is not a regular file: {relative}",
                    code="STORAGE_UNSAFE_PATH",
                )
            try:
                size = target.stat().st_size
            except OSError as exc:
                raise StorageError(f"cannot stat {relative}: {exc}") from exc
            if expected_size is not None and size != expected_size:
                raise StorageError(
                    f"existing object size differs from staged content: {digest}",
                    code="STORAGE_MISMATCH",
                )
            return StoredObject(digest, size, relative, kind, created=False)
        try:
            data = source.read_bytes()
        except OSError as exc:
            raise StorageError(f"cannot read staged {digest}: {exc}") from exc
        if sha256_bytes(data) != digest:
            raise StorageError(
                f"staged content hash does not match its name: {digest}",
                code="STORAGE_MISMATCH",
            )
        if expected_size is not None and len(data) != expected_size:
            raise StorageError(
                f"staged object size differs from journal: {digest}",
                code="STORAGE_MISMATCH",
            )
        try:
            atomic_write(target, data, mode=0o600)
        except OSError as exc:
            raise StorageError(f"cannot promote object {digest}: {exc}") from exc
        return StoredObject(digest, len(data), relative, kind, created=True)

    def remove_staged(self, commit_key: str, digest: str | None = None) -> None:
        """Remove one staged payload or the whole staging directory (best effort)."""
        target = (
            self.staging_path(commit_key, digest)
            if digest is not None
            else self.staging_dir(commit_key)
        )
        try:
            if target.is_symlink() or not target.exists():
                return
            if target.is_dir():
                for child in sorted(target.rglob("*"), reverse=True):
                    if child.is_file() and not child.is_symlink():
                        child.unlink()
                    elif child.is_dir() and not child.is_symlink():
                        child.rmdir()
                target.rmdir()
            else:
                target.unlink()
        except OSError as exc:
            raise StorageError(f"cannot remove staging path: {exc}") from exc

    # ------------------------------------------------------------------
    # Uncommitted-object quarantine (manual follow-up area).
    # ------------------------------------------------------------------

    def uncommitted_dir(self, commit_key: str) -> Path:
        self.validate_commit_key(commit_key)
        target = self.workdir / "uncommitted" / commit_key
        if not is_within(target, self.workdir / "uncommitted"):
            raise StorageError(
                f"uncommitted path escapes workdir: {commit_key}", code="STORAGE_UNSAFE_PATH"
            )
        return target

    def list_uncommitted(self) -> list[str]:
        root = self.workdir / "uncommitted"
        if not root.is_dir() or root.is_symlink():
            return []
        try:
            entries = sorted(os.scandir(root), key=lambda item: item.name)
        except OSError as exc:
            raise StorageError(f"cannot list uncommitted area: {exc}") from exc
        return [
            entry.name
            for entry in entries
            if UNCOMMITTED_ID_RE.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False)
        ]

    def quarantine_uncommitted(
        self,
        commit_key: str,
        source: Path,
        digest: str,
        *,
        origin: str,
    ) -> str:
        """Preserve an uncommitted payload under uncommitted/<commit-key>/.

        ``origin`` is "staged" or "promoted". Copy semantics keep staged journals
        and shared content-addressed objects untouched.
        """
        if origin not in {"staged", "promoted"}:
            raise StorageError("invalid uncommitted origin", code="STORAGE_UNSAFE_PATH")
        if not STAGED_DIGEST_RE.fullmatch(digest):
            raise StorageError("invalid uncommitted digest", code="STORAGE_UNSAFE_PATH")
        directory = self.uncommitted_dir(commit_key)
        payloads = directory / "objects"
        try:
            payloads.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageError(f"cannot create uncommitted directory: {exc}") from exc
        target = payloads / digest
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise StorageError(
                    f"uncommitted path is not a regular file: {digest}",
                    code="STORAGE_UNSAFE_PATH",
                )
            return f"uncommitted/{commit_key}/objects/{digest}"
        try:
            data = source.read_bytes()
        except OSError as exc:
            raise StorageError(f"cannot read uncommitted source: {exc}") from exc
        if sha256_bytes(data) != digest:
            raise StorageError(
                f"uncommitted content hash does not match: {digest}", code="STORAGE_MISMATCH"
            )
        try:
            atomic_write(target, data, mode=0o600)
        except OSError as exc:
            raise StorageError(f"cannot preserve uncommitted object: {exc}") from exc
        return f"uncommitted/{commit_key}/objects/{digest}"

    def delete_object(self, relative_path: str) -> None:
        """Delete a single content-addressed object after reference checks."""
        target = self._absolute(relative_path, existing=True)
        try:
            target.unlink()
        except OSError as exc:
            raise StorageError(f"cannot delete object {relative_path}: {exc}") from exc
