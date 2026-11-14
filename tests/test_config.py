from __future__ import annotations

from pathlib import Path

import pytest

from mailatt.config import load_config
from mailatt.errors import ConfigurationError

from conftest import FIXTURES, write_config


def test_demo_config_paths_and_fingerprint(demo_config) -> None:
    assert [source.name for source in demo_config.sources] == ["maildir", "eml", "bad"]
    assert demo_config.sources[0].path == (FIXTURES / "maildir").resolve()
    assert demo_config.workdir.name == "work"
    assert len(demo_config.policy_fingerprint) == 64
    assert demo_config.policy_fingerprint == demo_config.policy_fingerprint
    assert demo_config.policy.max_file_bytes == 8192


def test_unknown_top_level_key_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "bad.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy: {{}}
surprise: true
""",
    )
    with pytest.raises(ConfigurationError) as caught:
        load_config(path, workdir_override=tmp_path / "work")
    assert caught.value.code == "CONFIG_INVALID"
    assert "surprise" in caught.value.detail


def test_invalid_policy_range_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "bad.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  min_file_bytes: 100
  max_file_bytes: 10
""",
    )
    with pytest.raises(ConfigurationError, match="min_file_bytes"):
        load_config(path, workdir_override=tmp_path / "work")


def test_unknown_policy_key_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "bad.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  magic_mode: true
""",
    )
    with pytest.raises(ConfigurationError, match="magic_mode"):
        load_config(path, workdir_override=tmp_path / "work")


def test_workdir_inside_source_is_unsafe(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    path = write_config(
        tmp_path / "config.yaml",
        """version: 1
sources:
  - name: demo
    path: ./source
policy: {}
""",
    )
    with pytest.raises(ConfigurationError) as caught:
        load_config(path, workdir_override=source / "work")
    assert caught.value.code == "SOURCE_UNSAFE"


def test_missing_source_fails(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "config.yaml",
        """version: 1
sources:
  - name: missing
    path: ./does-not-exist
policy: {}
""",
    )
    with pytest.raises(ConfigurationError) as caught:
        load_config(path, workdir_override=tmp_path / "work")
    assert caught.value.code == "SOURCE_NOT_FOUND"


def test_duplicate_source_name_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path / "config.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
  - name: demo
    path: {FIXTURES / "bad"}
policy: {{}}
""",
    )
    with pytest.raises(ConfigurationError, match="duplicate source"):
        load_config(path, workdir_override=tmp_path / "work")


def test_policy_fingerprint_changes_with_policy(tmp_path: Path) -> None:
    first = write_config(
        tmp_path / "a.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  max_file_bytes: 100
""",
    )
    second = write_config(
        tmp_path / "b.yaml",
        f"""version: 1
sources:
  - name: demo
    path: {FIXTURES / "eml"}
policy:
  max_file_bytes: 200
""",
    )
    a = load_config(first, workdir_override=tmp_path / "wa")
    b = load_config(second, workdir_override=tmp_path / "wb")
    assert a.policy_fingerprint != b.policy_fingerprint


