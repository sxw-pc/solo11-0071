"""Stable local mail discovery for .eml trees, Maildir directories and mbox containers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator

from .config import Config, SourceConfig
from .errors import DiscoveryError
from .mbox import MBOX_DIALECTS, split_mbox
from .models import DiscoveredFile, DiscoveredSegment, DiscoveryOutcome
from .util import sha256_file


def _kind(source: SourceConfig) -> str:
    if source.kind != "auto":
        return source.kind
    if (source.path / "cur").is_dir() or (source.path / "new").is_dir():
        return "maildir"
    return "eml"


def _safe_entries(directory: Path) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(directory) as iterator:
            return sorted(iterator, key=lambda entry: entry.name)
    except OSError as exc:
        raise DiscoveryError(f"cannot list {directory}: {exc}") from exc


def _walk_suffix(root: Path, current: Path, stats: dict[str, int], suffix: str) -> Iterator[Path]:
    for entry in _safe_entries(current):
        try:
            if entry.is_symlink():
                stats["symlinks"] += 1
                continue
            if entry.is_dir(follow_symlinks=False):
                yield from _walk_suffix(root, Path(entry.path), stats, suffix)
            elif entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(suffix):
                yield Path(entry.path)
        except OSError as exc:
            raise DiscoveryError(f"cannot inspect {entry.path}: {exc}") from exc


def _walk_eml(root: Path, current: Path, stats: dict[str, int]) -> Iterator[Path]:
    yield from _walk_suffix(root, current, stats, ".eml")


def _walk_mbox(root: Path, current: Path, stats: dict[str, int]) -> Iterator[Path]:
    yield from _walk_suffix(root, current, stats, ".mbox")


def _walk_maildir(root: Path, stats: dict[str, int]) -> Iterator[Path]:
    found_box = False
    for subdir in ("cur", "new"):
        directory = root / subdir
        if not directory.is_dir():
            continue
        found_box = True
        for entry in _safe_entries(directory):
            try:
                if entry.is_symlink():
                    stats["symlinks"] += 1
                    continue
                if entry.is_file(follow_symlinks=False) and not entry.name.startswith("."):
                    yield Path(entry.path)
            except OSError as exc:
                raise DiscoveryError(f"cannot inspect {entry.path}: {exc}") from exc
    if not found_box:
        raise DiscoveryError(f"Maildir source has no cur/ or new/ directory: {root}")


def _digest(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError:
        # Keep the file in the batch so the runner can record a per-message error.
        return ""


def _file_for_path(source: SourceConfig, path: Path) -> DiscoveredFile:
    try:
        relative = path.relative_to(source.path).as_posix()
        size = path.stat().st_size
    except OSError as exc:
        raise DiscoveryError(f"cannot stat {path}: {exc}") from exc
    return DiscoveredFile(
        source_name=source.name,
        relative_path=relative,
        absolute_path=path,
        size=size,
        digest=_digest(path),
    )


def _iter_mbox(
    source: SourceConfig, dialect: str, stats: dict[str, int]
) -> Iterator[DiscoveredFile | DiscoveredSegment]:
    """Split each container into proven message slices and quarantine segments.

    A container is never reported as a single message: every slice keeps the
    container path plus a stable 1-based stream ordinal, and every byte range
    that cannot be proven under the declared dialect becomes a segment.
    """
    for path in _walk_mbox(source.path, source.path, stats):
        try:
            relative = path.relative_to(source.path).as_posix()
            size = path.stat().st_size
        except OSError as exc:
            raise DiscoveryError(f"cannot stat {path}: {exc}") from exc
        try:
            data = path.read_bytes()
        except OSError:
            # Keep the container as a failing whole-file entry so the runner
            # records a per-container error instead of aborting discovery.
            yield DiscoveredFile(
                source_name=source.name,
                relative_path=relative,
                absolute_path=path,
                size=size,
                digest="",
            )
            continue
        scan = split_mbox(data, dialect, source.mbox_mode)
        for message in scan.messages:
            yield DiscoveredFile(
                source_name=source.name,
                relative_path=f"{relative}#{message.ordinal:06d}",
                absolute_path=path,
                size=message.length,
                digest=message.digest,
                slice_offset=message.offset,
                mbox_dialect=dialect,
            )
        for segment in scan.segments:
            yield DiscoveredSegment(
                source_name=source.name,
                relative_path=f"{relative}#seg-{segment.ordinal:06d}",
                absolute_path=path,
                byte_offset=segment.offset,
                size=segment.length,
                digest=segment.digest,
                reason=segment.reason,
                detail=segment.detail,
            )


def _iter_source(
    source: SourceConfig, stats: dict[str, int]
) -> Iterator[DiscoveredFile | DiscoveredSegment]:
    kind = _kind(source)
    if kind == "maildir":
        for path in _walk_maildir(source.path, stats):
            yield _file_for_path(source, path)
    elif kind == "eml":
        for path in _walk_eml(source.path, source.path, stats):
            yield _file_for_path(source, path)
    elif kind in MBOX_DIALECTS:
        yield from _iter_mbox(source, kind, stats)
    else:
        raise DiscoveryError(f"unknown source kind: {kind}")


def discover(
    config: Config,
    *,
    is_unchanged: Callable[[DiscoveredFile], bool] | None = None,
) -> DiscoveryOutcome:
    """Discover configured mail, sorted by source name and POSIX relative path."""
    stats = {"symlinks": 0}
    files: list[DiscoveredFile] = []
    segments: list[DiscoveredSegment] = []
    for source in sorted(config.sources, key=lambda item: item.name):
        if not source.path.is_dir():
            raise DiscoveryError(f"source is not a directory: {source.path}")
        for item in _iter_source(source, stats):
            if isinstance(item, DiscoveredSegment):
                segments.append(item)
            else:
                files.append(item)
    files.sort(key=lambda item: (item.source_name, item.relative_path))
    segments.sort(key=lambda item: (item.source_name, item.relative_path))

    skipped = 0
    selected: list[DiscoveredFile] = []
    for item in files:
        if is_unchanged is not None and is_unchanged(item):
            skipped += 1
        else:
            selected.append(item)
    return DiscoveryOutcome(
        files=tuple(selected),
        skipped_count=skipped,
        ignored_symlinks=stats["symlinks"],
        segments=tuple(segments),
    )
