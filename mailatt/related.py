"""Scoped resolution of inline ``cid:`` resources inside multipart/related.

The resolver never builds a message-global Content-ID index.  Each
``multipart/related`` subtree is handled independently: the root is chosen from
that container's ``start`` parameter (falling back to its first child), and only
parts inside the same container participate in the Content-ID index.  Duplicate
or dangling identifiers are reported as tree-path-anchored issues instead of
being guessed.
"""

from __future__ import annotations

import mimetypes
import re
from collections import Counter
from dataclasses import dataclass, field
from email.message import Message

from .models import RelatedReferenceIssue, RelatedRetention

HTML_TYPE = "text/html"
MESSAGE_TYPE = "message/rfc822"
RELATED_TYPE = "multipart/related"

STATUS_REFERENCED = "referenced"
STATUS_UNREFERENCED = "unreferenced"
STATUS_AMBIGUOUS = "ambiguous"

RETENTION_BODY_DEPENDENCY = RelatedRetention.BODY_DEPENDENCY.value
RETENTION_FULL_FORENSICS = RelatedRetention.FULL_FORENSICS.value
VALID_RETENTIONS = (RETENTION_BODY_DEPENDENCY, RETENTION_FULL_FORENSICS)

ISSUE_CONTAINER_EMPTY = "related_container_empty"
ISSUE_START_ROOT_MISSING = "related_start_root_missing"
ISSUE_START_ROOT_AMBIGUOUS = "related_start_root_ambiguous"
ISSUE_ROOT_NOT_HTML = "related_root_not_html"
ISSUE_DUPLICATE_CONTENT_ID = "related_duplicate_content_id"
ISSUE_MISSING_REFERENCE = "related_missing_reference"
ISSUE_BOUNDARY_DAMAGED = "related_boundary_damaged"


def normalize_retention(value: object) -> str:
    """Accept the documented retention names; reject anything else."""
    text = str(value or "").strip().lower()
    if text in VALID_RETENTIONS:
        return text
    raise ValueError(f"unknown related retention mode: {value!r}")


# ``cid:`` appears in HTML attributes, CSS ``url()`` values and quoted/unquoted
# forms.  Trailing punctuation is stripped after the match.
CID_REF_RE = re.compile(r"cid:\s*([^\s\"'<>()]+)", re.IGNORECASE)
CID_TRAILING = ".,;:)]}"

EXTENSION_OVERRIDES = {
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/bmp": ".bmp",
    "text/css": ".css",
}


def path_sort_key(path: str) -> tuple[int, ...]:
    """Sort MIME tree paths numerically: ``1.2`` precedes ``1.10``."""
    if not path:
        return (0,)
    try:
        return tuple(int(segment) for segment in path.split("."))
    except ValueError:
        return (0,)


ROOT_PATH_DISPLAY = "/"


def display_path(path: str) -> str:
    """Render a tree path; the empty path denotes the message root."""
    return path or ROOT_PATH_DISPLAY


def child_path(parent: str, index: int) -> str:
    """Return the stable tree path of the 1-based ``index`` child."""
    segment = str(index)
    return f"{parent}.{segment}" if parent else segment


def normalize_content_id(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    return text


def content_id_of(part: Message) -> str:
    try:
        return normalize_content_id(part.get("Content-ID"))
    except Exception:
        return ""


def parse_cid_references(text: str) -> Counter[str]:
    """Count exact ``cid:`` targets in an HTML body without guessing case."""
    counts: Counter[str] = Counter()
    for match in CID_REF_RE.finditer(text or ""):
        target = match.group(1).rstrip(CID_TRAILING)
        if target:
            counts[target] += 1
    return counts


def _payload_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        raw = part.get_payload()
        if isinstance(raw, str):
            payload = raw.encode("utf-8", errors="replace")
        elif isinstance(raw, bytes):
            payload = raw
        else:
            return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _children(part: Message) -> list[Message]:
    payload = part.get_payload()
    if isinstance(payload, list):
        return [child for child in payload if isinstance(child, Message)]
    return []


def _content_type(part: Message) -> str:
    try:
        return part.get_content_type().lower()
    except Exception:
        return "application/octet-stream"


def is_inline_resource(part: Message) -> bool:
    """An *unnamed* leaf that acts as an embedded resource of the related body.

    Named parts keep their pre-existing attachment semantics; unnamed parts are
    only visible through the related container and therefore need this resolver.
    """
    if not isinstance(part, Message):
        return False
    if part.is_multipart() or _content_type(part) == MESSAGE_TYPE:
        return False
    if _content_type(part) == HTML_TYPE:
        return False
    try:
        if part.get_filename():
            return False
    except Exception:
        pass
    try:
        disposition = part.get_content_disposition()
    except Exception:
        disposition = None
    if disposition == "attachment":
        return False
    return disposition == "inline" or bool(content_id_of(part))


def resource_filename(part: Message, part_id: str) -> str:
    """Deterministic display name for an unnamed inline resource.

    The suffix follows the declared media type so the existing extension policy
    can evaluate the candidate on the same footing as a named attachment.
    """
    ctype = _content_type(part)
    suffix = EXTENSION_OVERRIDES.get(ctype, "")
    if not suffix:
        guessed = mimetypes.guess_extension(ctype, strict=False) or ""
        suffix = guessed.lower()
        if suffix in {".jpe", ".jpeg"}:
            suffix = ".jpg"
    return f"inline-{part_id}{suffix or '.bin'}"


@dataclass(frozen=True)
class RelatedRelation:
    """Auditable relation metadata for one leaf part in a related container."""

    related_path: str
    root_path: str
    part_path: str
    content_id: str
    reference_count: int
    status: str
    container_path: str = ""
    issue_codes: tuple[str, ...] = ()
    is_resource: bool = False


@dataclass(frozen=True)
class RelatedResource:
    """An inline resource selected for candidate emission."""

    related_path: str
    root_path: str
    part_path: str
    content_id: str
    reference_count: int
    status: str
    part: Message = field(repr=False, compare=False)
    issue_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelatedContainerResolution:
    related_path: str
    root_path: str
    root_is_html: bool
    relations: tuple[RelatedRelation, ...] = ()
    resources: tuple[RelatedResource, ...] = ()
    suppressed_paths: tuple[str, ...] = ()
    issues: tuple[RelatedReferenceIssue, ...] = ()


def _iter_leaves(part: Message, path: str):
    """Yield leaf parts below a non-root child without crossing related scopes."""
    ctype = _content_type(part)
    if ctype == MESSAGE_TYPE:
        # An attached message is opaque to the surrounding related scope.
        return
    if part.is_multipart():
        if ctype == RELATED_TYPE:
            # A nested related container is resolved independently by the walker.
            return
        for index, child in enumerate(_children(part), 1):
            yield from _iter_leaves(child, child_path(path, index))
        return
    yield part, path


def _issue(code: str, related_path: str, *, root_path: str = "", content_id: str = "",
           part_paths: tuple[str, ...] = (), detail: str = "") -> RelatedReferenceIssue:
    return RelatedReferenceIssue(
        code=code,
        related_path=display_path(related_path),
        root_path=root_path,
        content_id=content_id,
        part_paths=part_paths,
        detail=detail,
    )


def _children_with_paths(part: Message, related_path: str) -> list[tuple[int, Message, str]]:
    return [
        (index, child, child_path(related_path, index))
        for index, child in enumerate(_children(part), 1)
    ]


def _select_root(
    part: Message, related_path: str, children: list[tuple[int, Message, str]]
) -> tuple[Message | None, str, int | None, list[RelatedReferenceIssue]]:
    """Select the root by ``start`` or first child; never guess on ambiguity."""
    issues: list[RelatedReferenceIssue] = []
    if not children:
        issues.append(_issue(ISSUE_CONTAINER_EMPTY, related_path,
                             detail="multipart/related has no child parts"))
        return None, "", None, issues

    try:
        raw_start = part.get_param("start", header="content-type")
    except Exception:
        raw_start = None
    start = normalize_content_id(raw_start)

    if not start:
        _, root, root_path = children[0]
        return root, root_path, children[0][0], issues

    matches = [
        (index, child, path)
        for index, child, path in children
        if content_id_of(child) == start
    ]
    if not matches:
        issues.append(
            _issue(
                ISSUE_START_ROOT_MISSING,
                related_path,
                content_id=start,
                detail="start Content-ID does not match any direct child",
            )
        )
        return None, "", None, issues
    if len(matches) > 1:
        issues.append(
            _issue(
                ISSUE_START_ROOT_AMBIGUOUS,
                related_path,
                content_id=start,
                part_paths=tuple(path for _, _, path in matches),
                detail="start Content-ID matches multiple direct children",
            )
        )
        return None, "", None, issues
    _, root, root_path = matches[0]
    return root, root_path, matches[0][0], issues


def resolve_related_container(
    part: Message,
    related_path: str,
    retention: str = RelatedRetention.BODY_DEPENDENCY.value,
) -> RelatedContainerResolution:
    """Resolve one multipart/related container in isolation.

    ``retention`` selects which inline resources become candidates:

    * ``body-dependency``: only resources referenced from this container's HTML
      root.  References whose Content-ID is duplicated in this container stay as
      ambiguous candidates so the policy can isolate them.
    * ``full-forensics``: every inline resource in the container, referenced or
      not.  Ambiguous relations are still reported, never silently bound.
    """
    children = _children_with_paths(part, related_path)
    root, root_path, root_index, issues = _select_root(part, related_path, children)

    references: Counter[str] = Counter()
    root_is_html = False
    if root is not None:
        root_is_html = _content_type(root) == HTML_TYPE
        if root_is_html:
            references = parse_cid_references(_payload_text(root))
        else:
            issues.append(
                _issue(
                    ISSUE_ROOT_NOT_HTML,
                    related_path,
                    root_path=root_path,
                    detail="related root is not text/html; cid: references are not interpreted",
                )
            )

    leaves: list[tuple[Message, str]] = []
    for index, child, path in children:
        if root_index is not None and index == root_index:
            continue
        leaves.extend(_iter_leaves(child, path))
    leaves.sort(key=lambda item: path_sort_key(item[1]))

    cid_index: dict[str, list[str]] = {}
    cids: dict[str, str] = {}
    for leaf, path in leaves:
        cid = content_id_of(leaf)
        cids[path] = cid
        if cid:
            cid_index.setdefault(cid, []).append(path)

    duplicate_ids = {
        cid: tuple(sorted(paths, key=path_sort_key))
        for cid, paths in cid_index.items()
        if len(paths) > 1
    }
    for cid, paths in duplicate_ids.items():
        issues.append(
            _issue(
                ISSUE_DUPLICATE_CONTENT_ID,
                related_path,
                root_path=root_path,
                content_id=cid,
                part_paths=paths,
                detail="Content-ID is not unique inside this related container",
            )
        )

    for cid in sorted(references):
        if cid not in cid_index:
            issues.append(
                _issue(
                    ISSUE_MISSING_REFERENCE,
                    related_path,
                    root_path=root_path,
                    content_id=cid,
                    detail="HTML references a Content-ID absent from this related container",
                )
            )

    relations: list[RelatedRelation] = []
    resources: list[RelatedResource] = []
    suppressed: list[str] = []
    full_forensics = retention == RETENTION_FULL_FORENSICS
    for leaf, path in leaves:
        cid = cids[path]
        reference_count = references.get(cid, 0) if cid else 0
        duplicated = cid in duplicate_ids
        # A duplicated identifier only makes the *reference* ambiguous; an
        # unreferenced duplicate stays unreferenced and is still reported.
        ambiguous = duplicated and reference_count > 0
        issue_codes: tuple[str, ...] = ()
        if ambiguous:
            status = STATUS_AMBIGUOUS
            issue_codes = (ISSUE_DUPLICATE_CONTENT_ID,)
        elif reference_count > 0:
            status = STATUS_REFERENCED
        else:
            status = STATUS_UNREFERENCED
        relation = RelatedRelation(
            related_path=related_path,
            root_path=root_path,
            part_path=path,
            content_id=cid,
            reference_count=reference_count,
            status=status,
            container_path=related_path,
            issue_codes=issue_codes,
            is_resource=is_inline_resource(leaf),
        )
        relations.append(relation)
        if not relation.is_resource:
            continue
        if full_forensics or reference_count > 0:
            resources.append(
                RelatedResource(
                    related_path=related_path,
                    root_path=root_path,
                    part_path=path,
                    content_id=cid,
                    reference_count=reference_count,
                    status=status,
                    issue_codes=issue_codes,
                    part=leaf,
                )
            )
        else:
            suppressed.append(path)

    issues.sort(
        key=lambda item: (
            path_sort_key(item.related_path),
            item.code,
            path_sort_key(item.root_path),
            item.content_id,
            tuple(path_sort_key(path) for path in item.part_paths),
            item.detail,
        )
    )
    relations.sort(key=lambda item: path_sort_key(item.part_path))
    resources.sort(key=lambda item: path_sort_key(item.part_path))
    suppressed.sort(key=path_sort_key)
    return RelatedContainerResolution(
        related_path=display_path(related_path),
        root_path=root_path,
        root_is_html=root_is_html,
        relations=tuple(relations),
        resources=tuple(resources),
        suppressed_paths=tuple(suppressed),
        issues=tuple(issues),
    )
