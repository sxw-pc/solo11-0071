"""Generation-scoped publication contracts for the four-piece audit set.

Every run produces exactly four artifacts:

* ``manifest.json``
* ``reports/report.json``
* ``reports/report.md``
* ``reports/report.html``

Two publication contracts are supported:

``progressive``
    Each artifact may be swapped into its legacy static path ahead of the next
    one, but ``current.json`` is advanced after every artifact so the pointer
    always names the most recent generation whose prefix was made visible.
    Readers never merge artifacts across generations: a mixed or incomplete
    surface is reported as *not deliverable*.

``atomic``
    All four artifacts are written into an isolated generation directory and
    verified against ``generation.json`` digests before ``current.json`` is
    switched once. Any failure before that single switch leaves readers
    observing the previous, fully complete generation.

Both contracts stamp every artifact with the same ``generation`` and
``run_id`` pair. Static legacy paths are only resolved as one set against a
single generation; there is deliberately no per-file fallback.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import PUBLISH_CONTRACTS
from .errors import PublicationError, PublicationNotDeliverable, StorageError
from .util import atomic_write_json, atomic_write_text, read_json, sha256_file

GENERATIONS_DIRNAME = "generations"
POINTER_FILENAME = "current.json"
GENERATION_META_FILENAME = "generation.json"
POINTER_SCHEMA = "1.0"
GENERATION_SCHEMA = "1.0"

# Canonical four-piece set: logical name -> file name inside a generation dir.
ARTIFACT_MANIFEST = "manifest"
ARTIFACT_REPORT_JSON = "report_json"
ARTIFACT_REPORT_MARKDOWN = "report_markdown"
ARTIFACT_REPORT_HTML = "report_html"
ARTIFACTS: tuple[str, ...] = (
    ARTIFACT_MANIFEST,
    ARTIFACT_REPORT_JSON,
    ARTIFACT_REPORT_MARKDOWN,
    ARTIFACT_REPORT_HTML,
)
ARTIFACT_FILENAMES: dict[str, str] = {
    ARTIFACT_MANIFEST: "manifest.json",
    ARTIFACT_REPORT_JSON: "report.json",
    ARTIFACT_REPORT_MARKDOWN: "report.md",
    ARTIFACT_REPORT_HTML: "report.html",
}
# Legacy static paths relative to the work directory.
STATIC_RELATIVE_PATHS: dict[str, Path] = {
    ARTIFACT_MANIFEST: Path("manifest.json"),
    ARTIFACT_REPORT_JSON: Path("reports") / "report.json",
    ARTIFACT_REPORT_MARKDOWN: Path("reports") / "report.md",
    ARTIFACT_REPORT_HTML: Path("reports") / "report.html",
}
JSON_ARTIFACTS = frozenset({ARTIFACT_MANIFEST, ARTIFACT_REPORT_JSON})

RUN_ID_RE = re.compile(r"^run-(\d{6})$")
MARKER_RE = re.compile(
    r"mailatt-generation=(?P<payload>\{.*?\})", re.DOTALL
)

# Issue codes reported by readers.
POINTER_MISSING = "POINTER_MISSING"
POINTER_INVALID = "POINTER_INVALID"
POINTER_DANGLING = "POINTER_DANGLING"
GENERATION_META_MISSING = "GENERATION_META_MISSING"
GENERATION_META_INVALID = "GENERATION_META_INVALID"
ARTIFACT_MISSING = "ARTIFACT_MISSING"
ARTIFACT_DIGEST_MISMATCH = "ARTIFACT_DIGEST_MISMATCH"
ARTIFACT_MARKER_MISSING = "ARTIFACT_MARKER_MISSING"
ARTIFACT_MARKER_MISMATCH = "ARTIFACT_MARKER_MISMATCH"
STATIC_MISSING = "STATIC_MISSING"
STATIC_MARKER_MISSING = "STATIC_MARKER_MISSING"
STATIC_GENERATION_MISMATCH = "STATIC_GENERATION_MISMATCH"

# Fault injection labels (in pipeline order).
FAIL_GEN_WRITE = "gen_write"
FAIL_STATIC_REPLACE = "static_replace"
FAIL_POINTER_SWITCH = "pointer_switch"

FailCallback = Callable[[str, str], None]


@dataclass(frozen=True)
class ArtifactBundle:
    """Unstamped content of one run's four-piece set."""

    run_id: str
    manifest_payload: dict[str, Any]
    report_payload: dict[str, Any]
    report_markdown: str
    report_html: str

    def content(self, artifact: str) -> Any:
        if artifact == ARTIFACT_MANIFEST:
            return self.manifest_payload
        if artifact == ARTIFACT_REPORT_JSON:
            return self.report_payload
        if artifact == ARTIFACT_REPORT_MARKDOWN:
            return self.report_markdown
        if artifact == ARTIFACT_REPORT_HTML:
            return self.report_html
        raise KeyError(artifact)


@dataclass
class ArtifactState:
    artifact: str
    path: Path
    present: bool
    generation: str = ""
    run_id: str = ""
    digest_ok: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "path": str(self.path),
            "present": self.present,
            "generation": self.generation,
            "run_id": self.run_id,
            "digest_ok": self.digest_ok,
        }


@dataclass
class PublicationStatus:
    """Reader-side view of what is currently visible in a work directory."""

    contract: str = ""
    pointer_run_id: str = ""
    pointer_generation: str = ""
    head_run_id: str = ""
    head_complete: bool = False
    deliverable: bool = False
    static_consistent: bool = False
    generation_dir: Path | None = None
    pointer_path: Path | None = None
    artifacts: list[ArtifactState] = field(default_factory=list)
    issues: list[dict[str, str]] = field(default_factory=list)

    def issue_codes(self) -> list[str]:
        return [item["code"] for item in self.issues]

    def artifact(self, name: str) -> ArtifactState | None:
        for state in self.artifacts:
            if state.artifact == name:
                return state
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "pointer_run_id": self.pointer_run_id,
            "pointer_generation": self.pointer_generation,
            "head_run_id": self.head_run_id,
            "head_complete": self.head_complete,
            "deliverable": self.deliverable,
            "static_consistent": self.static_consistent,
            "generation_dir": str(self.generation_dir) if self.generation_dir else "",
            "pointer_path": str(self.pointer_path) if self.pointer_path else "",
            "artifacts": [state.as_dict() for state in self.artifacts],
            "issues": list(self.issues),
        }


def _issue(issues: list[dict[str, str]], code: str, path: str, detail: str) -> None:
    issues.append({"code": code, "path": path, "detail": detail})


def generation_for_run(run_id: str) -> str:
    """Return the directory generation label for a run id (falls back safely)."""
    match = RUN_ID_RE.fullmatch(run_id)
    return f"gen-{int(match.group(1)):06d}" if match else run_id


def generation_dir(workdir: Path, run_id: str) -> Path:
    return Path(workdir) / GENERATIONS_DIRNAME / generation_for_run(run_id)


def pointer_path(workdir: Path) -> Path:
    return Path(workdir) / POINTER_FILENAME


def static_path(workdir: Path, artifact: str) -> Path:
    return Path(workdir) / STATIC_RELATIVE_PATHS[artifact]


def _marker_comment(generation: str, run_id: str) -> str:
    payload = json.dumps(
        {"generation": generation, "run_id": run_id},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"<!-- mailatt-generation={payload} -->"


def stamp_artifact(artifact: str, content: Any, generation: str, run_id: str) -> Any:
    """Return artifact content carrying the generation/run_id marker."""
    if artifact in JSON_ARTIFACTS:
        if not isinstance(content, dict):
            raise PublicationError(f"{artifact} payload must be a JSON object")
        stamped = dict(content)
        stamped["generation"] = generation
        stamped["run_id"] = run_id
        return stamped
    text = str(content)
    return f"{_marker_comment(generation, run_id)}\n{text}"


def _read_marker(path: Path, artifact: str) -> tuple[str, str]:
    """Read the (generation, run_id) marker from an artifact on disk."""
    if artifact in JSON_ARTIFACTS:
        payload = read_json(path)
        if not isinstance(payload, dict):
            raise PublicationError(f"marker missing in {path}")
        generation = payload.get("generation")
        run_id = payload.get("run_id")
        if not isinstance(generation, str) or not isinstance(run_id, str):
            raise PublicationError(f"marker missing in {path}")
        return generation, run_id
    match = MARKER_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise PublicationError(f"marker missing in {path}")
    payload = json.loads(match.group("payload"))
    return str(payload["generation"]), str(payload["run_id"])


def _serialize(artifact: str, stamped: Any) -> bytes:
    if artifact in JSON_ARTIFACTS:
        text = json.dumps(stamped, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        return text.encode("utf-8")
    return str(stamped).encode("utf-8")


def _read_pointer(workdir: Path, issues: list[dict[str, str]]) -> dict[str, Any] | None:
    path = pointer_path(workdir)
    if not path.is_file():
        _issue(issues, POINTER_MISSING, POINTER_FILENAME, "current.json pointer is missing")
        return None
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        _issue(issues, POINTER_INVALID, POINTER_FILENAME, str(exc))
        return None
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("run_id"), str)
        or not isinstance(payload.get("generation"), str)
        or payload.get("contract") not in PUBLISH_CONTRACTS
    ):
        _issue(issues, POINTER_INVALID, POINTER_FILENAME, "pointer fields are invalid")
        return None
    return payload


def _read_generation_meta(
    directory: Path, issues: list[dict[str, str]]
) -> dict[str, Any] | None:
    meta_path = directory / GENERATION_META_FILENAME
    if not meta_path.is_file():
        _issue(
            issues,
            GENERATION_META_MISSING,
            str(meta_path),
            "generation summary is missing",
        )
        return None
    try:
        meta = read_json(meta_path)
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        _issue(issues, GENERATION_META_INVALID, str(meta_path), str(exc))
        return None
    if (
        not isinstance(meta, dict)
        or not isinstance(meta.get("digests"), dict)
        or not isinstance(meta.get("run_id"), str)
        or not isinstance(meta.get("generation"), str)
    ):
        _issue(issues, GENERATION_META_INVALID, str(meta_path), "meta fields are invalid")
        return None
    return meta


def _inspect_generation(
    directory: Path,
    expected_generation: str,
    expected_run_id: str,
    digests: dict[str, Any] | None,
    issues: list[dict[str, str]],
) -> list[ArtifactState]:
    states: list[ArtifactState] = []
    for artifact in ARTIFACTS:
        path = directory / ARTIFACT_FILENAMES[artifact]
        if not path.is_file():
            _issue(issues, ARTIFACT_MISSING, str(path), f"{artifact} is missing from generation")
            states.append(ArtifactState(artifact, path, present=False))
            continue
        marker_generation = marker_run = ""
        try:
            marker_generation, marker_run = _read_marker(path, artifact)
        except (OSError, json.JSONDecodeError, UnicodeError, PublicationError) as exc:
            _issue(issues, ARTIFACT_MARKER_MISSING, str(path), str(exc))
        # Digest verification is independent of marker parsing so tampering is
        # always reported against the recorded generation summary.
        digest_ok = True
        if digests is not None:
            expected_digest = digests.get(ARTIFACT_FILENAMES[artifact])
            if not isinstance(expected_digest, str):
                digest_ok = False
                _issue(
                    issues,
                    GENERATION_META_INVALID,
                    str(directory / GENERATION_META_FILENAME),
                    f"digest for {artifact} is missing",
                )
            else:
                digest_ok = sha256_file(path) == expected_digest
                if not digest_ok:
                    _issue(
                        issues,
                        ARTIFACT_DIGEST_MISMATCH,
                        str(path),
                        "artifact content does not match generation digest",
                    )
        if marker_generation or marker_run:
            if (marker_generation, marker_run) != (expected_generation, expected_run_id):
                digest_ok = False
                _issue(
                    issues,
                    ARTIFACT_MARKER_MISMATCH,
                    str(path),
                    f"marker {marker_generation}/{marker_run} "
                    f"!= {expected_generation}/{expected_run_id}",
                )
        else:
            digest_ok = False
        states.append(
            ArtifactState(
                artifact, path, True, marker_generation, marker_run, digest_ok
            )
        )
    return states


def _inspect_static_surface(
    workdir: Path, expected_run_id: str, issues: list[dict[str, str]]
) -> bool:
    consistent = True
    for artifact in ARTIFACTS:
        path = static_path(workdir, artifact)
        relative = STATIC_RELATIVE_PATHS[artifact].as_posix()
        if not path.is_file():
            _issue(issues, STATIC_MISSING, relative, "legacy static path is missing")
            consistent = False
            continue
        try:
            _, run_id = _read_marker(path, artifact)
        except (OSError, json.JSONDecodeError, UnicodeError, PublicationError):
            _issue(
                issues,
                STATIC_MARKER_MISSING,
                relative,
                "legacy static path has no generation marker",
            )
            consistent = False
            continue
        if run_id != expected_run_id:
            _issue(
                issues,
                STATIC_GENERATION_MISMATCH,
                relative,
                f"static path belongs to {run_id}, expected {expected_run_id}",
            )
            consistent = False
    return consistent


def inspect_publication(workdir: Path | str) -> PublicationStatus:
    """Inspect on-disk publication state without ever merging generations."""
    workdir = Path(workdir)
    status = PublicationStatus(pointer_path=pointer_path(workdir))
    pointer = _read_pointer(workdir, status.issues)

    generations_root = workdir / GENERATIONS_DIRNAME
    head_directory: Path | None = None
    if generations_root.is_dir():
        candidates = sorted(
            entry
            for entry in generations_root.iterdir()
            if entry.is_dir() and not entry.is_symlink()
        )
        if candidates:
            head_directory = candidates[-1]

    if head_directory is not None:
        # Generation labels are gen-NNNNNN; map them back to run-NNNNNN.
        status.head_run_id = (
            f"run-{head_directory.name[4:]}"
            if head_directory.name.startswith("gen-")
            else head_directory.name
        )
        head_meta = _read_generation_meta(head_directory, status.issues)
        head_generation = (
            head_meta.get("generation")
            if head_meta
            else generation_for_run(status.head_run_id)
        )
        head_states = _inspect_generation(
            head_directory,
            str(head_generation),
            status.head_run_id,
            head_meta.get("digests") if head_meta else None,
            status.issues,
        )
        status.head_complete = bool(head_states) and all(
            state.present and state.digest_ok for state in head_states
        )

    if pointer is None:
        status.static_consistent = False
        return status

    status.contract = str(pointer["contract"])
    status.pointer_run_id = str(pointer["run_id"])
    status.pointer_generation = str(pointer["generation"])
    target_directory = generation_dir(workdir, status.pointer_run_id)
    status.generation_dir = target_directory
    if not target_directory.is_dir():
        _issue(
            status.issues,
            POINTER_DANGLING,
            str(target_directory),
            f"pointer targets missing generation {status.pointer_run_id}",
        )
        status.static_consistent = False
        return status

    meta = _read_generation_meta(target_directory, status.issues)
    status.artifacts = _inspect_generation(
        target_directory,
        status.pointer_generation,
        status.pointer_run_id,
        meta.get("digests") if meta else None,
        status.issues,
    )
    generation_complete = bool(status.artifacts) and all(
        state.present and state.digest_ok for state in status.artifacts
    )
    # Progressive publications expose files as they are written, so the
    # legacy static surface must match the newest generation on disk. Atomic
    # publications only switch the pointer once, so the surface matches the
    # pointer generation; a later failed run never moved the pointer.
    static_expected_run = (
        status.head_run_id
        if status.contract == "progressive" and status.head_run_id
        else status.pointer_run_id
    )
    status.static_consistent = _inspect_static_surface(
        workdir, static_expected_run, status.issues
    )
    status.deliverable = generation_complete and status.static_consistent
    return status


def load_published(workdir: Path | str) -> dict[str, Any]:
    """Resolve the unique published generation and return its four artifacts.

    Raises ``PublicationNotDeliverable`` when no complete, same-generation set
    exists. Readers never fall back file by file.
    """
    workdir = Path(workdir)
    status = inspect_publication(workdir)
    if not status.deliverable or status.generation_dir is None:
        raise PublicationNotDeliverable(
            "no complete same-generation artifact set is deliverable",
            status.issues,
        )
    loaded: dict[str, Any] = {
        "run_id": status.pointer_run_id,
        "generation": status.pointer_generation,
        "contract": status.contract,
        "generation_dir": status.generation_dir,
        "paths": {
            artifact: status.generation_dir / ARTIFACT_FILENAMES[artifact]
            for artifact in ARTIFACTS
        },
    }
    for artifact in JSON_ARTIFACTS:
        loaded[artifact] = read_json(loaded["paths"][artifact])
    return loaded


def resolve_static_paths(workdir: Path | str) -> dict[str, Path]:
    """Resolve legacy static paths to one unique generation, or raise.

    All four paths are validated against the same pointer generation. A single
    missing or foreign artifact rejects the whole set; there is no per-file
    fallback to an older generation.
    """
    workdir = Path(workdir)
    status = inspect_publication(workdir)
    if not status.deliverable:
        raise PublicationNotDeliverable(
            "legacy static paths do not resolve to one complete generation",
            status.issues,
        )
    return {artifact: static_path(workdir, artifact) for artifact in ARTIFACTS}


class Publisher:
    """Writes one generation and publishes it under a chosen contract."""

    def __init__(
        self,
        workdir: Path | str,
        contract: str,
        *,
        on_fail: FailCallback | None = None,
    ) -> None:
        if contract not in PUBLISH_CONTRACTS:
            raise PublicationError(
                f"unknown publish contract: {contract}", code="INVALID_ARGUMENT"
            )
        self.workdir = Path(workdir)
        self.contract = contract
        self._on_fail = on_fail

    def _fail(self, label: str, artifact: str) -> None:
        if self._on_fail is not None:
            self._on_fail(label, artifact)

    def _write_generation_artifact(
        self, directory: Path, artifact: str, stamped: Any
    ) -> Path:
        target = directory / ARTIFACT_FILENAMES[artifact]
        try:
            self._fail(FAIL_GEN_WRITE, artifact)
            if artifact in JSON_ARTIFACTS:
                atomic_write_json(target, stamped)
            else:
                atomic_write_text(target, str(stamped))
        except OSError as exc:
            raise StorageError(
                f"cannot write generation artifact {artifact}: {exc}",
                code="PUBLICATION_FAILED",
            ) from exc
        return target

    def _replace_static(self, artifact: str, source: Path) -> Path:
        target = static_path(self.workdir, artifact)
        try:
            self._fail(FAIL_STATIC_REPLACE, artifact)
            data = source.read_bytes()
            atomic_write_text(target, data.decode("utf-8"))
        except OSError as exc:
            raise StorageError(
                f"cannot replace static path for {artifact}: {exc}",
                code="PUBLICATION_FAILED",
            ) from exc
        return target

    def _write_pointer(self, run_id: str, generation: str, complete: bool) -> Path:
        payload = {
            "schema_version": POINTER_SCHEMA,
            "contract": self.contract,
            "generation": generation,
            "run_id": run_id,
            "complete": complete,
            "artifacts": {
                artifact: ARTIFACT_FILENAMES[artifact] for artifact in ARTIFACTS
            },
        }
        try:
            self._fail(FAIL_POINTER_SWITCH, run_id)
            atomic_write_json(pointer_path(self.workdir), payload)
        except OSError as exc:
            raise StorageError(
                f"cannot switch current pointer: {exc}", code="PUBLICATION_FAILED"
            ) from exc
        return pointer_path(self.workdir)

    def _stamped(self, bundle: ArtifactBundle, artifact: str, generation: str) -> Any:
        return stamp_artifact(
            artifact, bundle.content(artifact), generation, bundle.run_id
        )

    def publish(self, bundle: ArtifactBundle) -> dict[str, Path]:
        generation = generation_for_run(bundle.run_id)
        directory = generation_dir(self.workdir, bundle.run_id)
        try:
            directory.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            # Re-publishing the same run id rebuilds it deterministically.
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageError(
                f"cannot create generation directory: {exc}", code="PUBLICATION_FAILED"
            ) from exc

        if self.contract == "progressive":
            return self._publish_progressive(bundle, generation, directory)
        return self._publish_atomic(bundle, generation, directory)

    def _publish_progressive(
        self, bundle: ArtifactBundle, generation: str, directory: Path
    ) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        digests: dict[str, str] = {}
        for artifact in ARTIFACTS:
            stamped = self._stamped(bundle, artifact, generation)
            written = self._write_generation_artifact(directory, artifact, stamped)
            digests[ARTIFACT_FILENAMES[artifact]] = sha256_file(written)
            self._write_generation_meta(
                directory, generation, bundle.run_id, digests, complete=False
            )
            # Each artifact becomes visible immediately; the pointer advances
            # with it so a reader never silently stitches generations together.
            self._replace_static(artifact, written)
            paths[artifact] = static_path(self.workdir, artifact)
            self._write_pointer(bundle.run_id, generation, complete=False)
        self._write_generation_meta(
            directory, generation, bundle.run_id, digests, complete=True
        )
        self._write_pointer(bundle.run_id, generation, complete=True)
        return paths

    def _publish_atomic(
        self, bundle: ArtifactBundle, generation: str, directory: Path
    ) -> dict[str, Path]:
        digests: dict[str, str] = {}
        # Phase 1: isolated generation directory, nothing visible yet. The
        # generation summary is maintained after every artifact so a single
        # failed write leaves an inspectable, explicitly incomplete generation.
        for artifact in ARTIFACTS:
            stamped = self._stamped(bundle, artifact, generation)
            written = self._write_generation_artifact(directory, artifact, stamped)
            digests[ARTIFACT_FILENAMES[artifact]] = sha256_file(written)
            self._write_generation_meta(
                directory, generation, bundle.run_id, digests, complete=False
            )
        self._verify_generation(directory, generation, bundle.run_id, digests)
        # Phase 2: the single visibility switch.
        self._write_pointer(bundle.run_id, generation, complete=True)
        # Phase 3: refresh legacy static paths from the now-current generation.
        paths: dict[str, Path] = {}
        for artifact in ARTIFACTS:
            written = directory / ARTIFACT_FILENAMES[artifact]
            self._replace_static(artifact, written)
            paths[artifact] = static_path(self.workdir, artifact)
        self._write_generation_meta(
            directory, generation, bundle.run_id, digests, complete=True
        )
        return paths

    def _write_generation_meta(
        self,
        directory: Path,
        generation: str,
        run_id: str,
        digests: dict[str, str],
        *,
        complete: bool,
    ) -> Path:
        payload = {
            "schema_version": GENERATION_SCHEMA,
            "contract": self.contract,
            "generation": generation,
            "run_id": run_id,
            "complete": complete,
            "artifacts": {
                artifact: ARTIFACT_FILENAMES[artifact] for artifact in ARTIFACTS
            },
            "digests": dict(sorted(digests.items())),
        }
        meta_path = directory / GENERATION_META_FILENAME
        try:
            atomic_write_json(meta_path, payload)
        except OSError as exc:
            raise StorageError(
                f"cannot write generation summary: {exc}", code="PUBLICATION_FAILED"
            ) from exc
        return meta_path

    def _verify_generation(
        self,
        directory: Path,
        generation: str,
        run_id: str,
        digests: dict[str, str],
    ) -> None:
        """Re-open every artifact and verify marker and recorded digest."""
        for artifact in ARTIFACTS:
            path = directory / ARTIFACT_FILENAMES[artifact]
            if not path.is_file():
                raise StorageError(
                    f"generation verification missing {artifact}",
                    code="PUBLICATION_FAILED",
                )
            try:
                marker_generation, marker_run = _read_marker(path, artifact)
            except (OSError, json.JSONDecodeError, UnicodeError, PublicationError) as exc:
                raise StorageError(
                    f"generation verification cannot read marker of {artifact}: {exc}",
                    code="PUBLICATION_FAILED",
                ) from exc
            if (marker_generation, marker_run) != (generation, run_id):
                raise StorageError(
                    f"generation verification marker mismatch for {artifact}",
                    code="PUBLICATION_FAILED",
                )
            if sha256_file(path) != digests.get(ARTIFACT_FILENAMES[artifact]):
                raise StorageError(
                    f"generation verification digest mismatch for {artifact}",
                    code="PUBLICATION_FAILED",
                )
