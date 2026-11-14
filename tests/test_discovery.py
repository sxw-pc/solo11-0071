from __future__ import annotations

import os
from pathlib import Path

import pytest

from mailatt.config import Config, PolicyConfig, SourceConfig
from mailatt.discovery import discover
from mailatt.errors import DiscoveryError

from conftest import FIXTURES


def make_config(sources: list[SourceConfig], workdir: Path) -> Config:
    return Config(sources=tuple(sources), policy=PolicyConfig(), workdir=workdir)


def test_demo_discovery_is_stable_and_complete(tmp_path: Path) -> None:
    config = make_config(
        [
            SourceConfig("maildir", FIXTURES / "maildir", "maildir"),
            SourceConfig("eml", FIXTURES / "eml", "eml"),
            SourceConfig("bad", FIXTURES / "bad", "eml"),
        ],
        tmp_path / "work",
    )
    first = discover(config)
    second = discover(config)
    paths = [item.source_ref for item in first.files]
    assert len(paths) == 11
    assert paths == sorted(paths)
    assert paths == [item.source_ref for item in second.files]
    assert "maildir/cur/0001.report" in paths
    assert "maildir/new/0006.inline" in paths
    assert all(len(item.digest) == 64 for item in first.files if item.size > 0)
    assert first.skipped_count == 0


def test_incremental_skip_counts_files(tmp_path: Path) -> None:
    config = make_config([SourceConfig("eml", FIXTURES / "eml", "eml")], tmp_path / "work")
    all_files = discover(config).files
    target = all_files[0].source_ref
    outcome = discover(
        config,
        is_unchanged=lambda item: item.source_ref == target,
    )
    assert outcome.skipped_count == 1
    assert len(outcome.files) == len(all_files) - 1
    assert target not in {item.source_ref for item in outcome.files}


def test_only_eml_files_are_selected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.eml").write_text("From: a@demo.invalid\n\nbody\n", encoding="utf-8")
    (source / "two.EML").write_text("From: b@demo.invalid\n\nbody\n", encoding="utf-8")
    (source / "ignore.txt").write_text("not mail", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    (nested / "three.eml").write_text("From: c@demo.invalid\n\nbody\n", encoding="utf-8")
    config = make_config([SourceConfig("box", source, "eml")], tmp_path / "work")
    refs = [item.relative_path for item in discover(config).files]
    assert refs == ["nested/three.eml", "one.eml", "two.EML"]


def test_maildir_uses_cur_and_new_only(tmp_path: Path) -> None:
    root = tmp_path / "maildir"
    (root / "cur").mkdir(parents=True)
    (root / "new").mkdir()
    (root / "tmp").mkdir()
    (root / "cur" / "a").write_text("From: a@demo.invalid\n\nx\n", encoding="utf-8")
    (root / "new" / "b").write_text("From: b@demo.invalid\n\nx\n", encoding="utf-8")
    (root / "tmp" / "c").write_text("not selected", encoding="utf-8")
    (root / ".hidden").write_text("ignored", encoding="utf-8")
    config = make_config([SourceConfig("box", root, "maildir")], tmp_path / "work")
    refs = [item.relative_path for item in discover(config).files]
    assert refs == ["cur/a", "new/b"]


def test_explicit_maildir_without_boxes_fails(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    config = make_config([SourceConfig("box", root, "maildir")], tmp_path / "work")
    with pytest.raises(DiscoveryError, match="cur/"):
        discover(config)


def test_symlinks_are_ignored(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = source / "real.eml"
    target.write_text("From: a@demo.invalid\n\nx\n", encoding="utf-8")
    link = source / "link.eml"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available in this environment")
    config = make_config([SourceConfig("box", source, "eml")], tmp_path / "work")
    outcome = discover(config)
    assert [item.relative_path for item in outcome.files] == ["real.eml"]
    assert outcome.ignored_symlinks == 1


