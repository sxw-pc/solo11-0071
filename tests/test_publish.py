"""Generation-scoped publication contracts: readers, switches and fault injection."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from mailatt.config import default_config_for_fixtures
from mailatt.errors import PublicationError, PublicationNotDeliverable, StorageError
from mailatt.ledger import Ledger
from mailatt.publish import (
    ARTIFACT_MANIFEST,
    ARTIFACT_REPORT_HTML,
    ARTIFACT_REPORT_JSON,
    ARTIFACT_REPORT_MARKDOWN,
    ARTIFACTS,
    ARTIFACT_FILENAMES,
    FAIL_GEN_WRITE,
    FAIL_POINTER_SWITCH,
    FAIL_STATIC_REPLACE,
    GENERATIONS_DIRNAME,
    STATIC_GENERATION_MISMATCH,
    ArtifactBundle,
    Publisher,
    generation_dir,
    generation_for_run,
    inspect_publication,
    load_published,
    pointer_path,
    resolve_static_paths,
    stamp_artifact,
    static_path,
)
from mailatt.report import build_report_bundle
from mailatt.runner import collect
from mailatt import runner as runner_module
from mailatt import publish as publish_module
from mailatt import util as util_module

from conftest import FIXTURES, fixed_clock

BASELINE_RUNS = 10
NEXT_RUN = "run-000011"
PREV_RUN = "run-000010"
ALL_ARTIFACTS = (
    ARTIFACT_MANIFEST,
    ARTIFACT_REPORT_JSON,
    ARTIFACT_REPORT_MARKDOWN,
    ARTIFACT_REPORT_HTML,
)
STATIC_LABELS = {
    ARTIFACT_MANIFEST: "manifest.json",
    ARTIFACT_REPORT_JSON: "reports/report.json",
    ARTIFACT_REPORT_MARKDOWN: "reports/report.md",
    ARTIFACT_REPORT_HTML: "reports/report.html",
}


def _fault_env(phase: str, artifact: str) -> str:
    return f"{phase}:{artifact}"


@pytest.fixture()
def fault_injector(monkeypatch: pytest.MonkeyPatch):
    """Inject one fault into the Publisher used by runner.collect."""
    real_publisher = publish_module.Publisher

    def factory(phase: str, artifact: str) -> None:
        marker = _fault_env(phase, artifact)

        class FailingPublisher(real_publisher):  # type: ignore[misc, valid-type]
            def __init__(self, workdir, contract, *, on_fail=None):
                def injected(stage, name):
                    if f"{stage}:{name}" == marker:
                        raise OSError(f"injected failure at {stage}/{name}")
                    if on_fail is not None:
                        on_fail(stage, name)

                super().__init__(workdir, contract, on_fail=injected)

        monkeypatch.setattr(runner_module, "Publisher", FailingPublisher)

    return factory


@pytest.fixture()
def baseline(tmp_path: Path) -> dict[str, Path]:
    """A work directory that already completed run-000010 with a full set."""
    config = default_config_for_fixtures(FIXTURES, tmp_path / "work")
    for _ in range(BASELINE_RUNS):
        collect(config, clock=fixed_clock)
    return {"workdir": config.workdir, "config": config}


def _marker_of(path: Path, artifact: str) -> tuple[str, str]:
    if artifact in (ARTIFACT_MANIFEST, ARTIFACT_REPORT_JSON):
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload["generation"], payload["run_id"]
    text = path.read_text(encoding="utf-8")
    head = text.splitlines()[0]
    payload = json.loads(head.split("mailatt-generation=", 1)[1].rstrip(" -->"))
    return payload["generation"], payload["run_id"]


def _static_run_ids(workdir: Path) -> dict[str, str]:
    return {
        artifact: _marker_of(static_path(workdir, artifact), artifact)[1]
        for artifact in ALL_ARTIFACTS
    }


# ---------------------------------------------------------------------------
# happy path: both contracts publish a same-generation four-piece set
# ---------------------------------------------------------------------------


def test_generation_layout_contains_four_pieces_and_pointer(baseline) -> None:
    workdir = baseline["workdir"]
    current = json.loads(pointer_path(workdir).read_text(encoding="utf-8"))
    assert current["run_id"] == PREV_RUN
    assert current["generation"] == generation_for_run(PREV_RUN)
    assert current["contract"] == "atomic"
    assert current["complete"] is True
    directory = generation_dir(workdir, PREV_RUN)
    assert directory.is_dir()
    for artifact in ALL_ARTIFACTS:
        assert (directory / ARTIFACT_FILENAMES[artifact]).is_file()
    meta = json.loads((directory / "generation.json").read_text(encoding="utf-8"))
    assert meta["run_id"] == PREV_RUN
    assert meta["complete"] is True
    assert set(meta["digests"]) == {ARTIFACT_FILENAMES[a] for a in ALL_ARTIFACTS}


def test_every_artifact_carries_same_generation_and_run_marker(baseline) -> None:
    workdir = baseline["workdir"]
    expected = (generation_for_run(PREV_RUN), PREV_RUN)
    for artifact in ALL_ARTIFACTS:
        generation_path = generation_dir(workdir, PREV_RUN) / ARTIFACT_FILENAMES[artifact]
        static = static_path(workdir, artifact)
        assert _marker_of(generation_path, artifact) == expected
        assert _marker_of(static, artifact) == expected


def test_progressive_and_atomic_have_identical_successful_sets(
    tmp_path: Path,
) -> None:
    atomic_config = default_config_for_fixtures(FIXTURES, tmp_path / "atomic")
    progressive_config = replace(
        default_config_for_fixtures(FIXTURES, tmp_path / "progressive"),
        publish_contract="progressive",
    )
    atomic_result = collect(atomic_config, clock=fixed_clock)
    progressive_result = collect(progressive_config, clock=fixed_clock)

    atomic_pub = load_published(atomic_config.workdir)
    progressive_pub = load_published(progressive_config.workdir)
    assert atomic_pub["run_id"] == progressive_pub["run_id"] == "run-000001"
    assert (
        atomic_pub["manifest"]["object_count"]
        == progressive_pub["manifest"]["object_count"]
        == 7
    )
    assert (
        atomic_pub["report_json"]["summary"]["objects"]["total"]
        == progressive_pub["report_json"]["summary"]["objects"]["total"]
        == 7
    )
    for artifact in ALL_ARTIFACTS:
        name = ARTIFACT_FILENAMES[artifact]
        atomic_bytes = (generation_dir(atomic_config.workdir, "run-000001") / name).read_bytes()
        progressive_bytes = (
            generation_dir(progressive_config.workdir, "run-000001") / name
        ).read_bytes()
        assert atomic_bytes == progressive_bytes
    status_a = inspect_publication(atomic_config.workdir)
    status_p = inspect_publication(progressive_config.workdir)
    assert status_a.deliverable and status_p.deliverable
    assert status_a.static_consistent and status_p.static_consistent
    assert atomic_result.report_paths["json"].name == "report.json"
    assert progressive_result.report_paths["html"].name == "report.html"


def test_progressive_full_pipeline_is_deliverable(tmp_path: Path) -> None:
    config = replace(
        default_config_for_fixtures(FIXTURES, tmp_path / "work"),
        publish_contract="progressive",
    )
    collect(config, clock=fixed_clock)
    status = inspect_publication(config.workdir)
    assert status.contract == "progressive"
    assert status.deliverable is True
    assert status.pointer_run_id == "run-000001"
    assert load_published(config.workdir)["run_id"] == "run-000001"


# ---------------------------------------------------------------------------
# the run-000010 -> run-000011 HTML replacement failure from the brief
# ---------------------------------------------------------------------------


def test_progressive_html_failure_exposes_incomplete_run_000011(
    baseline, fault_injector
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_STATIC_REPLACE, ARTIFACT_REPORT_HTML)

    with pytest.raises(StorageError) as caught:
        collect(config, clock=fixed_clock)
    assert caught.value.code == "PUBLICATION_FAILED"

    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert status.pointer_run_id == NEXT_RUN
    assert status.head_run_id == NEXT_RUN
    # Under progressive publication the generation dir is complete; the
    # incompatibility is exposed on the legacy static surface.
    assert status.head_complete is True
    assert status.static_consistent is False
    codes = status.issue_codes()
    assert "STATIC_GENERATION_MISMATCH" in codes
    mismatch = [
        issue for issue in status.issues if issue["code"] == "STATIC_GENERATION_MISMATCH"
    ]
    assert {issue["path"] for issue in mismatch} == {"reports/report.html"}
    static_runs = _static_run_ids(workdir)
    assert static_runs[ARTIFACT_REPORT_HTML] == PREV_RUN
    assert static_runs[ARTIFACT_MANIFEST] == NEXT_RUN
    assert static_runs[ARTIFACT_REPORT_JSON] == NEXT_RUN
    assert static_runs[ARTIFACT_REPORT_MARKDOWN] == NEXT_RUN
    with pytest.raises(PublicationNotDeliverable) as not_deliverable:
        load_published(workdir)
    assert not_deliverable.value.issues
    with pytest.raises(PublicationNotDeliverable):
        # Legacy static paths must not resolve file by file to the old run.

        resolve_static_paths(workdir)
    # The ledger still recorded run-000011 as a completed run.

    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.last_run()["run_id"] == NEXT_RUN
        assert ledger.last_run()["status"] in ("completed", "completed_with_errors")


def test_atomic_html_failure_keeps_run_000010_complete(baseline, fault_injector) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_GEN_WRITE, ARTIFACT_REPORT_HTML)

    with pytest.raises(StorageError) as caught:
        collect(config, clock=fixed_clock)
    assert caught.value.code == "PUBLICATION_FAILED"

    status = inspect_publication(workdir)
    assert status.deliverable is True
    assert status.static_consistent is True
    assert status.pointer_run_id == PREV_RUN
    assert status.head_run_id == NEXT_RUN
    assert status.head_complete is False
    assert status.issue_codes() == [
        "ARTIFACT_MISSING",
    ]
    published = load_published(workdir)
    assert published["run_id"] == PREV_RUN
    assert published["manifest"]["run_id"] == PREV_RUN
    # Every legacy static path still resolves to the old generation only.

    paths = resolve_static_paths(workdir)
    for artifact in ALL_ARTIFACTS:
        assert _marker_of(paths[artifact], artifact)[1] == PREV_RUN
    assert _static_run_ids(workdir) == {artifact: PREV_RUN for artifact in ALL_ARTIFACTS}

    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.last_run()["run_id"] == NEXT_RUN


# ---------------------------------------------------------------------------
# every replacement boundary for all three report formats and the manifest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("artifact", ALL_ARTIFACTS)
def test_progressive_fails_at_every_static_boundary(
    baseline, fault_injector, artifact
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_STATIC_REPLACE, artifact)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert status.pointer_run_id == NEXT_RUN
    static_runs = _static_run_ids(workdir)
    if artifact == ARTIFACT_MANIFEST:
        # First boundary: the fault fires before any static replacement, so
        # the legacy surface still shows the previous complete generation.
        assert all(run == PREV_RUN for run in static_runs.values())
        mismatches = [
            issue
            for issue in status.issues
            if issue["code"] == "STATIC_GENERATION_MISMATCH"
        ]
        # Every static path is older than the head generation the pointer
        # already names; the set as a whole cannot be merged into run-000011.
        assert len(mismatches) == len(ALL_ARTIFACTS)
        assert not status.static_consistent
    else:
        assert static_runs[artifact] == PREV_RUN
        mismatches = {
            issue["path"]
            for issue in status.issues
            if issue["code"] == "STATIC_GENERATION_MISMATCH"
        }
        assert STATIC_LABELS[artifact] in mismatches


@pytest.mark.parametrize("artifact", ALL_ARTIFACTS)
def test_atomic_fails_at_every_generation_boundary(
    baseline, fault_injector, artifact
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_GEN_WRITE, artifact)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    assert status.deliverable is True
    assert status.pointer_run_id == PREV_RUN
    assert _static_run_ids(workdir) == {a: PREV_RUN for a in ALL_ARTIFACTS}
    assert status.head_run_id == NEXT_RUN
    assert status.head_complete is False


@pytest.mark.parametrize("artifact", ALL_ARTIFACTS)
def test_atomic_static_replacement_after_switch_does_not_break_canonical_set(
    baseline, fault_injector, artifact
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_STATIC_REPLACE, artifact)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    # Pointer already switched: the canonical generation set is complete...
    assert status.pointer_run_id == NEXT_RUN
    assert status.head_complete is True
    # ...but the legacy static surface no longer resolves to one generation.
    assert status.static_consistent is False
    assert status.deliverable is False

    with pytest.raises(PublicationNotDeliverable):
        resolve_static_paths(workdir)
    # The legacy static surface is a prefix of the new generation: every
    # replacement from the failed boundary onward still belongs to the old run.
    static_runs = _static_run_ids(workdir)
    failed_index = ALL_ARTIFACTS.index(artifact)
    for index, name in enumerate(ALL_ARTIFACTS):
        expected_run = NEXT_RUN if index < failed_index else PREV_RUN
        assert static_runs[name] == expected_run


def test_progressive_pointer_switch_failure_keeps_old_generation(
    baseline, fault_injector
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    # Fault at the very first pointer switch of run-000011.
    fault_injector(FAIL_POINTER_SWITCH, NEXT_RUN)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    assert status.pointer_run_id == PREV_RUN
    assert status.deliverable is True
    assert load_published(workdir)["run_id"] == PREV_RUN


def test_atomic_pointer_switch_failure_keeps_old_generation(
    baseline, fault_injector
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    fault_injector(FAIL_POINTER_SWITCH, NEXT_RUN)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    assert status.deliverable is True
    assert status.pointer_run_id == PREV_RUN
    assert status.head_run_id == NEXT_RUN
    assert status.head_complete is True
    assert load_published(workdir)["run_id"] == PREV_RUN
    assert _static_run_ids(workdir) == {a: PREV_RUN for a in ALL_ARTIFACTS}


def test_real_os_replace_failure_during_pointer_switch(baseline, monkeypatch) -> None:
    """Exercise the actual os.replace boundary instead of the injected seam."""
    config = baseline["config"]
    workdir = baseline["workdir"]
    real_replace = os.replace
    target_pointer = pointer_path(workdir)

    def flaky_replace(src, dst, *args, **kwargs):
        if Path(dst) == target_pointer:
            raise OSError("injected os.replace failure on current.json")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(util_module.os, "replace", flaky_replace)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    assert inspect_publication(workdir).pointer_run_id == PREV_RUN
    assert load_published(workdir)["run_id"] == PREV_RUN


# ---------------------------------------------------------------------------
# reader semantics: unique generation, no per-file fallback
# ---------------------------------------------------------------------------


def test_reader_rejects_deleted_artifact_without_per_file_fallback(baseline) -> None:
    workdir = baseline["workdir"]
    (workdir / "reports" / "report.html").unlink()
    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert "STATIC_MISSING" in status.issue_codes()
    with pytest.raises(PublicationNotDeliverable):
        load_published(workdir)


def test_reader_rejects_foreign_generation_file(baseline) -> None:
    workdir = baseline["workdir"]
    foreign = generation_dir(workdir, "run-000009") / "report.html"
    # Plant the older generation's HTML at the static path.
    static_target = static_path(workdir, ARTIFACT_REPORT_HTML)
    static_target.write_bytes(foreign.read_bytes())
    status = inspect_publication(workdir)
    assert status.deliverable is False
    mismatch = [
        issue
        for issue in status.issues
        if issue["code"] == STATIC_GENERATION_MISMATCH
    ]
    assert mismatch
    with pytest.raises(PublicationNotDeliverable):
        load_published(workdir)


def test_reader_detects_tampered_generation_digest(baseline) -> None:
    workdir = baseline["workdir"]
    directory = generation_dir(workdir, PREV_RUN)
    # Valid JSON without the generation marker: the recorded digest no longer
    # matches, which must be reported independently of marker parsing.
    (directory / "report.json").write_text(
        json.dumps({"tampered": True, "run": {}}), encoding="utf-8"
    )
    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert "ARTIFACT_DIGEST_MISMATCH" in status.issue_codes()
    with pytest.raises(PublicationNotDeliverable):
        load_published(workdir)


def test_reader_reports_missing_pointer_on_fresh_workdir(tmp_path: Path) -> None:
    status = inspect_publication(tmp_path / "empty")
    assert status.deliverable is False
    assert status.issue_codes() == ["POINTER_MISSING"]
    with pytest.raises(PublicationNotDeliverable):
        load_published(tmp_path / "empty")


def test_reader_rejects_invalid_pointer(baseline) -> None:
    workdir = baseline["workdir"]
    pointer_path(workdir).write_text("{not json", encoding="utf-8")
    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert "POINTER_INVALID" in status.issue_codes()


def test_reader_rejects_dangling_pointer(baseline) -> None:
    workdir = baseline["workdir"]
    pointer_path(workdir).write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "contract": "atomic",
                "generation": "gen-999999",
                "run_id": "run-999999",
                "complete": True,
                "artifacts": {},
            }
        ),
        encoding="utf-8",
    )
    status = inspect_publication(workdir)
    assert status.deliverable is False
    assert "POINTER_DANGLING" in status.issue_codes()


def test_resolve_static_paths_returns_single_generation(baseline) -> None:

    workdir = baseline["workdir"]
    paths = resolve_static_paths(workdir)
    for artifact, path in paths.items():
        assert _marker_of(path, artifact)[1] == PREV_RUN
    assert paths[ARTIFACT_MANIFEST] == workdir / "manifest.json"
    assert paths[ARTIFACT_REPORT_JSON] == workdir / "reports" / "report.json"


# ---------------------------------------------------------------------------
# lower-level Publisher / marker behaviour
# ---------------------------------------------------------------------------


def test_publisher_rejects_unknown_contract(tmp_path: Path) -> None:
    with pytest.raises(PublicationError):
        Publisher(tmp_path, "blue-green")


def test_stamp_artifact_embeds_marker_in_each_format(tmp_path: Path) -> None:
    json_stamped = stamp_artifact(
        ARTIFACT_REPORT_JSON, {"a": 1}, "gen-000003", "run-000003"
    )
    assert json_stamped["generation"] == "gen-000003"
    assert json_stamped["run_id"] == "run-000003"
    md_stamped = stamp_artifact(
        ARTIFACT_REPORT_MARKDOWN, "# title", "gen-000003", "run-000003"
    )
    assert md_stamped.startswith("<!-- mailatt-generation=")
    assert "run-000003" in md_stamped.splitlines()[0]
    html_stamped = stamp_artifact(
        ARTIFACT_REPORT_HTML, "<!doctype html>", "gen-000003", "run-000003"
    )
    assert html_stamped.splitlines()[0].startswith("<!-- mailatt-generation=")


def test_progressive_partial_progress_points_at_new_run(baseline, tmp_path: Path) -> None:
    """Direct Publisher call: after two artifacts, pointer names the new run."""
    workdir = baseline["workdir"]
    config = replace(baseline["config"], publish_contract="progressive")

    with Ledger(workdir) as ledger:
        manifest = json.loads(
            (generation_dir(workdir, PREV_RUN) / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        bundle = build_report_bundle(config, ledger, manifest, NEXT_RUN, fixed_clock)

    seen: list[str] = []

    def on_fail(phase: str, artifact: str) -> None:
        seen.append(f"{phase}:{artifact}")
        if phase == FAIL_STATIC_REPLACE and artifact == ARTIFACT_REPORT_MARKDOWN:
            raise OSError("stop after json artifacts")

    with pytest.raises(StorageError):
        Publisher(workdir, "progressive", on_fail=on_fail).publish(bundle)
    status = inspect_publication(workdir)
    assert status.pointer_run_id == NEXT_RUN
    assert status.deliverable is False
    assert _static_run_ids(workdir)[ARTIFACT_REPORT_JSON] == NEXT_RUN
    assert _static_run_ids(workdir)[ARTIFACT_REPORT_HTML] == PREV_RUN


def test_followup_successful_run_restores_deliverable_set(
    baseline, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = baseline["config"]
    workdir = baseline["workdir"]
    real_publisher = publish_module.Publisher
    marker = _fault_env(FAIL_GEN_WRITE, ARTIFACT_REPORT_HTML)
    fired = {"count": 0}

    class OneShotPublisher(real_publisher):  # type: ignore[misc, valid-type]
        def __init__(self, wd, contract, *, on_fail=None) -> None:
            def injected(stage: str, name: str) -> None:
                if f"{stage}:{name}" == marker and fired["count"] == 0:
                    fired["count"] += 1
                    raise OSError("transient generation write failure")
                if on_fail is not None:
                    on_fail(stage, name)

            super().__init__(wd, contract, on_fail=injected)

    monkeypatch.setattr(runner_module, "Publisher", OneShotPublisher)
    with pytest.raises(StorageError):
        collect(config, clock=fixed_clock)
    # The next run no longer hits the one-shot fault and rebuilds fully.
    result = collect(config, clock=fixed_clock)
    status = inspect_publication(workdir)
    assert status.deliverable is True
    assert status.static_consistent is True
    published = load_published(workdir)
    assert published["run_id"] == result.summary.run_id == "run-000012"
    assert published["manifest"]["object_count"] == 7
    assert published["report_json"]["summary"]["objects"]["total"] == 7
    for artifact in ALL_ARTIFACTS:
        assert _marker_of(
            static_path(workdir, artifact), artifact
        )[1] == "run-000012"


def test_atomic_verifies_digests_before_switch(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    bundle = ArtifactBundle(
        run_id="run-000001",
        manifest_payload={"schema_version": "1.0", "run_id": "run-000001", "objects": []},
        report_payload={"run": {"run_id": "run-000001"}},
        report_markdown="# report\n",
        report_html="<!doctype html>\n",
    )
    paths = Publisher(workdir, "atomic").publish(bundle)
    assert set(paths) == set(ARTIFACTS)
    status = inspect_publication(workdir)
    assert status.deliverable is True
    assert (workdir / GENERATIONS_DIRNAME / "gen-000001").is_dir()
    assert json.loads(pointer_path(workdir).read_text())["complete"] is True
