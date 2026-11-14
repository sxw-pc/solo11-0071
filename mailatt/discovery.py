"""Stable local mail discovery for .eml trees and Maildir directories."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator

from .config import Config, SourceConfig
from .errors import DiscoveryError
from .models import DiscoveredFile, DiscoveryOutcome
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


def _walk_eml(root: Path, current: Path, stats: dict[str, int]) -> Iterator[Path]:
    for entry in _safe_entries(current):
        try:
            if entry.is_symlink():
                stats["symlinks"] += 1
                continue
            if entry.is_dir(follow_symlinks=False):
                yield from _walk_eml(root, Path(entry.path), stats)
            elif entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".eml"):
                yield Path(entry.path)
        except OSError as exc:
            raise DiscoveryError(f"cannot inspect {entry.path}: {exc}") from exc


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


def _iter_source(source: SourceConfig, stats: dict[str, int]) -> Iterator[Path]:
    kind = _kind(source)
    if kind == "maildir":
        yield from _walk_maildir(source.path, stats)
    else:
        yield from _walk_eml(source.path, source.path, stats)


def _digest(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError:
        # Keep the file in the batch so the runner can record a per-message error.
        return ""


def discover(
    config: Config,
    *,
    is_unchanged: Callable[[DiscoveredFile], bool] | None = None,
) -> DiscoveryOutcome:
    """Discover configured mail, sorted by source name and POSIX relative path."""
    stats = {"symlinks": 0}
    buffered: list[tuple[SourceConfig, Path]] = []
    for source in sorted(config.sources, key=lambda item: item.name):
        if not source.path.is_dir():
            raise DiscoveryError(f"source is not a directory: {source.path}")
        buffered.extend((source, path) for path in _iter_source(source, stats))

    discovered: list[DiscoveredFile] = []
    for source, path in buffered:
        try:
            relative = path.relative_to(source.path).as_posix()
            size = path.stat().st_size
        except OSError as exc:
            raise DiscoveryError(f"cannot stat {path}: {exc}") from exc
        discovered.append(
            DiscoveredFile(
                source_name=source.name,
                relative_path=relative,
                absolute_path=path,
                size=size,
                digest=_digest(path),
            )
        )
    discovered.sort(key=lambda item: (item.source_name, item.relative_path))

    skipped = 0
    selected: list[DiscoveredFile] = []
    for item in discovered:
        if is_unchanged is not None and is_unchanged(item):
            skipped += 1
        else:
            selected.append(item)
    return DiscoveryOutcome(
        files=tuple(selected),
        skipped_count=skipped,
        ignored_symlinks=stats["symlinks"],
    )
