"""Declarative attachment gates: type, size, count, name and duplicates."""

from __future__ import annotations

from pathlib import Path

from .config import PolicyConfig
from .models import AttachmentCandidate, Decision, PolicyDecision


def extension_of(filename: str) -> str:
    return Path(filename).suffix.lower()


def extension_chain(filename: str) -> tuple[str, ...]:
    return tuple(item.lower() for item in Path(filename).suffixes)


def media_type_allowed(media_type: str, allowed: tuple[str, ...]) -> bool:
    media_type = media_type.lower()
    for rule in allowed:
        if rule == media_type:
            return True
        if rule.endswith("/*") and media_type.startswith(rule[:-1]):
            return True
    return False


def _decision(status: Decision, code: str, reason: str) -> PolicyDecision:
    return PolicyDecision(status=status, reason_code=code, reason=reason)


def evaluate_candidate(
    candidate: AttachmentCandidate,
    policy: PolicyConfig,
    known_hashes: set[str],
    *,
    count_exceeded: bool = False,
) -> PolicyDecision:
    """Apply gates in a fixed, documented order."""
    if candidate.traversal_detected and policy.reject_path_traversal:
        return _decision(Decision.REJECTED, "path_traversal", "filename contains path syntax")
    if count_exceeded:
        return _decision(
            Decision.REJECTED, "attachment_count_exceeded", "per-message attachment limit exceeded"
        )
    if candidate.disposition == "inline" and not policy.allow_inline_attachments:
        return _decision(Decision.REJECTED, "inline_not_allowed", "inline attachment is disabled")
    if candidate.size < policy.min_file_bytes:
        return _decision(Decision.REJECTED, "size_below_minimum", "attachment is smaller than minimum")
    if candidate.size > policy.max_file_bytes:
        return _decision(Decision.REJECTED, "size_exceeded", "attachment exceeds maximum size")

    chain = extension_chain(candidate.safe_filename)
    extension = extension_of(candidate.safe_filename)
    if extension in policy.quarantine_extensions:
        return _decision(Decision.QUARANTINED, "suspicious_extension", "extension is quarantined")
    if any(item in policy.quarantine_extensions for item in chain[:-1]):
        return _decision(
            Decision.QUARANTINED, "suspicious_extension_chain", "double extension is quarantined"
        )
    if extension in policy.blocked_extensions:
        return _decision(Decision.REJECTED, "extension_blocked", "extension is blocked")
    if not extension or extension not in policy.allowed_extensions:
        return _decision(Decision.REJECTED, "extension_not_allowed", "extension is not allowed")
    if not media_type_allowed(candidate.media_type, policy.allowed_media_types):
        return _decision(Decision.REJECTED, "mime_not_allowed", "media type is not allowed")
    if policy.skip_duplicate_content and candidate.sha256 in known_hashes:
        return _decision(Decision.DUPLICATE, "duplicate_content", "content already archived")
    return _decision(Decision.ACCEPTED, "accepted", "passed all attachment gates")


def assess_candidates(
    candidates: tuple[AttachmentCandidate, ...] | list[AttachmentCandidate],
    policy: PolicyConfig,
    known_hashes: set[str],
) -> list[PolicyDecision]:
    """Assess a message's candidates in stable order and update the dedupe set."""
    decisions: list[PolicyDecision] = []
    for index, candidate in enumerate(candidates):
        decision = evaluate_candidate(
            candidate,
            policy,
            known_hashes,
            count_exceeded=index >= policy.max_attachments_per_message,
        )
        decisions.append(decision)
        if decision.status == Decision.ACCEPTED:
            known_hashes.add(candidate.sha256)
    return decisions


def summarize_policy(policy: PolicyConfig) -> dict[str, object]:
    """Report-only policy view with deterministic list ordering."""
    return {
        "allowed_extensions": sorted(policy.allowed_extensions),
        "allowed_media_types": sorted(policy.allowed_media_types),
        "quarantine_extensions": sorted(policy.quarantine_extensions),
        "blocked_extensions": sorted(policy.blocked_extensions),
        "max_file_bytes": policy.max_file_bytes,
        "min_file_bytes": policy.min_file_bytes,
        "max_attachments_per_message": policy.max_attachments_per_message,
        "max_nested_depth": policy.max_nested_depth,
        "max_message_bytes": policy.max_message_bytes,
        "max_filename_length": policy.max_filename_length,
        "allow_nested_messages": policy.allow_nested_messages,
        "allow_inline_attachments": policy.allow_inline_attachments,
        "reject_path_traversal": policy.reject_path_traversal,
        "skip_duplicate_content": policy.skip_duplicate_content,
    }
