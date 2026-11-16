"""Offline verification of S/MIME ``multipart/signed`` evidence.

This module separates two questions that are often conflated:

* **Integrity** -- do the exact signed MIME bytes match the digest and the
  CMS signature carried with them?
* **Trust** -- is the signing certificate accepted by a certificate anchor that
  was explicitly configured on this machine?

A mathematically valid signature from a self-signed or unknown certificate is
reported as ``integrity=valid`` with ``trust=untrusted``.  Nothing here ever
fetches certificates, CRLs or OCSP responses, and no private key is needed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from .config import TrustAnchor, TrustConfig
from .der import Der, DerError, decode_auto
from .models import (
    SignatureEvidence,
    SignatureIntegrity,
    SignatureTrust,
    SignerIdentity,
)
from .util import sha256_bytes, utc_now

DEFAULT_SIGNATURE_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_CERT_CHAIN_DEPTH = 8

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"

DIGEST_OIDS: dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.5": "sha512_224",
    "2.16.840.1.101.3.4.2.6": "sha512_256",
    "2.16.840.1.101.3.4.2.7": "sha3_224",
    "2.16.840.1.101.3.4.2.8": "sha3_256",
    "2.16.840.1.101.3.4.2.9": "sha3_384",
    "2.16.840.1.101.3.4.2.10": "sha3_512",
}

HASH_OBJECTS = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

RSA_SIGNATURE_OIDS: dict[str, str | None] = {
    "1.2.840.113549.1.1.1": None,
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
PSS_OID = "1.2.840.113549.1.1.10"
EC_SIGNATURE_OIDS: dict[str, str] = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
ED25519_OID = "1.3.101.112"


class SignatureFormatError(ValueError):
    """The CMS or certificate material cannot be interpreted safely."""


@dataclass(frozen=True)
class SignedLayer:
    """Exact bytes of one ``multipart/signed`` layer from the raw snapshot."""

    content: bytes
    signature: bytes | None
    protocol: str
    micalg: str
    problem: str = ""

    @property
    def signed_content_sha256(self) -> str:
        return sha256_bytes(self.content)


def _integrity(
    value: SignatureIntegrity,
    reason_code: str,
    reason: str,
    layer_count: int = 0,
    *,
    content: bytes = b"",
    signature: bytes | None = None,
    protocol: str = "",
    micalg: str = "",
) -> SignatureEvidence:
    return SignatureEvidence(
        integrity=value,
        trust=SignatureTrust.NOT_APPLICABLE,
        reason_code=reason_code,
        reason=reason,
        signed_content_sha256=sha256_bytes(content) if content else "",
        signature_sha256=sha256_bytes(signature) if signature else "",
        protocol=protocol,
        micalg=micalg,
        layer_count=layer_count,
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _valid_at(cert: x509.Certificate, moment: datetime) -> bool:
    try:
        return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc
    except (ValueError, TypeError):
        return False


def _self_issued(cert: x509.Certificate) -> bool:
    try:
        return cert.subject.public_bytes() == cert.issuer.public_bytes()
    except (ValueError, AttributeError):
        return False


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _signer_identity(cert: x509.Certificate) -> SignerIdentity:
    return SignerIdentity(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        fingerprint_sha256=_fingerprint(cert),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        self_issued=_self_issued(cert),
    )


def _hash_factory(name: str):
    return HASH_OBJECTS.get(name)


def _digest(name: str, data: bytes) -> bytes:
    try:
        return hashlib.new(name, data).digest()
    except (ValueError, TypeError) as exc:
        raise SignatureFormatError(f"unsupported digest {name}") from exc


def _attribute_values(attribute: Der) -> tuple[Der, ...]:
    fields = attribute.children()
    if len(fields) != 2 or fields[0].tag != 0x06 or fields[1].tag != 0x31:
        raise SignatureFormatError("malformed signed attribute")
    return fields[1].children()


def _signed_attributes(attrs: Der) -> dict[str, tuple[Der, ...]]:
    found: dict[str, tuple[Der, ...]] = {}
    for item in attrs.children():
        if item.tag != 0x30:
            raise SignatureFormatError("malformed signed attributes set")
        fields = item.children()
        if len(fields) != 2 or fields[0].tag != 0x06:
            raise SignatureFormatError("malformed attribute")
        oid = fields[0].as_oid()
        found.setdefault(oid, _attribute_values(item))
    return found


def _single_octets(values: Sequence[Der]) -> bytes | None:
    for value in values:
        if value.tag == 0x04:
            return value.value
    return None


def _single_oid(values: Sequence[Der]) -> str | None:
    for value in values:
        if value.tag == 0x06:
            return value.as_oid()
    return None


def _parse_algorithm(algorithm: Der) -> tuple[str, Der | None]:
    fields = algorithm.children()
    if not fields or fields[0].tag != 0x06:
        raise SignatureFormatError("malformed algorithm identifier")
    return fields[0].as_oid(), (fields[1] if len(fields) > 1 else None)


def _algorithm_hash(oid: str, parameters: Der | None) -> str | None:
    if oid in DIGEST_OIDS:
        return DIGEST_OIDS[oid]
    if oid in RSA_SIGNATURE_OIDS:
        return RSA_SIGNATURE_OIDS[oid]
    if oid in EC_SIGNATURE_OIDS:
        return EC_SIGNATURE_OIDS[oid]
    return None


def _pss_hash(parameters: Der | None) -> str:
    if parameters is None:
        return "sha1"
    try:
        values = parameters.children()
    except DerError as exc:
        raise SignatureFormatError("malformed PSS parameters") from exc
    for item in values:
        if item.tag == 0xA0:
            inner = item.children()
            if inner and inner[0].tag == 0x30:
                oid, _ = _parse_algorithm(inner[0])
                return DIGEST_OIDS.get(oid, "sha1")
    return "sha1"


def _pss_salt_length(parameters: Der | None, digest_name: str) -> int:
    if parameters is None:
        return 20
    try:
        for item in parameters.children():
            if item.tag == 0xA2:
                inner = item.children()
                if inner and inner[0].tag == 0x02:
                    return inner[0].as_integer()
    except (DerError, ValueError):
        pass
    return hashlib.new(digest_name).digest_size


@dataclass(frozen=True)
class _SignerMaterial:
    digest_name: str
    signature_algorithm: str
    signature: bytes
    signed_attrs: Der | None
    certificate: x509.Certificate
    signer_fingerprint: str
    certificates: tuple[x509.Certificate, ...] = ()


def _find_certificate(
    sid: Der,
    candidates: Iterable[x509.Certificate],
) -> x509.Certificate | None:
    pool = list(candidates)
    if sid.tag == 0x30:
        fields = sid.children()
        if len(fields) != 2 or fields[0].tag != 0x30 or fields[1].tag != 0x02:
            raise SignatureFormatError("malformed issuer and serial signer identifier")
        issuer_der = fields[0].raw
        serial = fields[1].as_integer()
        for cert in pool:
            if cert.serial_number != serial:
                continue
            try:
                if cert.issuer.public_bytes() == issuer_der:
                    return cert
            except (ValueError, AttributeError):
                continue
        return None
    if sid.tag == 0x80:
        key_id = sid.value
        for cert in pool:
            try:
                extension = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
            except x509.ExtensionNotFound:
                continue
            if extension.value.digest == key_id:
                return cert
        return None
    raise SignatureFormatError("unsupported signer identifier")


def _parse_signed_data(raw: bytes) -> tuple[list[x509.Certificate], list[tuple[Der, Der, Der, Der | None, Der]]]:
    """Return embedded certificates and raw SignerInfo field tuples."""
    content_info = decode_auto(raw)
    if content_info.tag != 0x30:
        raise SignatureFormatError("CMS ContentInfo is not a sequence")
    info = content_info.children()
    if len(info) < 2 or info[0].tag != 0x06 or info[1].tag != 0xA0:
        raise SignatureFormatError("CMS ContentInfo is malformed")
    if info[0].as_oid() != OID_SIGNED_DATA:
        raise SignatureFormatError("CMS content type is not signedData")
    wrapped = info[1].children()
    if len(wrapped) != 1 or wrapped[0].tag != 0x30:
        raise SignatureFormatError("CMS signedData is malformed")
    fields = wrapped[0].children()
    if len(fields) < 4:
        raise SignatureFormatError("CMS signedData is incomplete")
    certificates: list[x509.Certificate] = []
    try:
        certificates = list(pkcs7.load_der_pkcs7_certificates(raw))
    except (ValueError, UnsupportedAlgorithm, TypeError) as exc:
        raise SignatureFormatError("CMS certificates are malformed") from exc
    signer_infos: Der | None = None
    for item in fields[2:]:
        if item.tag == 0x31:
            signer_infos = item
    if signer_infos is None:
        raise SignatureFormatError("CMS signerInfos are missing")
    signers: list[tuple[Der, Der, Der, Der | None, Der]] = []
    for signer in signer_infos.children():
        if signer.tag != 0x30:
            raise SignatureFormatError("CMS SignerInfo is malformed")
        parts = signer.children()
        if len(parts) < 5:
            raise SignatureFormatError("CMS SignerInfo is incomplete")
        sid = parts[1]
        digest_algorithm = parts[2]
        index = 3
        signed_attrs: Der | None = None
        if parts[index].tag == 0xA0:
            signed_attrs = parts[index]
            index += 1
        if len(parts) < index + 2:
            raise SignatureFormatError("CMS SignerInfo is incomplete")
        signature_algorithm = parts[index]
        signature_value = parts[index + 1]
        if signature_value.tag != 0x04:
            raise SignatureFormatError("CMS signature is not an octet string")
        signers.append(
            (sid, digest_algorithm, signature_algorithm, signed_attrs, signature_value)
        )
    return certificates, signers


def _verify_signature(
    cert: x509.Certificate,
    signature_algorithm: str,
    parameters: Der | None,
    digest_name: str,
    signature: bytes,
    signed_bytes: bytes,
) -> None:
    public_key = cert.public_key()
    hash_object = _hash_factory(digest_name)
    if signature_algorithm in RSA_SIGNATURE_OIDS:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise SignatureFormatError("RSA signature used with a non-RSA key")
        if hash_object is None:
            raise SignatureFormatError(f"unsupported RSA digest {digest_name}")
        public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_object())
        return
    if signature_algorithm == PSS_OID:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise SignatureFormatError("PSS signature used with a non-RSA key")
        pss_digest = _pss_hash(parameters)
        pss_hash = _hash_factory(pss_digest)
        if pss_hash is None:
            raise SignatureFormatError(f"unsupported PSS digest {pss_digest}")
        salt_length = _pss_salt_length(parameters, pss_digest)
        public_key.verify(
            signature,
            signed_bytes,
            padding.PSS(mgf=padding.MGF1(pss_hash()), salt_length=salt_length),
            pss_hash(),
        )
        return
    if signature_algorithm in EC_SIGNATURE_OIDS:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise SignatureFormatError("ECDSA signature used with a non-EC key")
        ec_digest = EC_SIGNATURE_OIDS[signature_algorithm]
        ec_hash = _hash_factory(ec_digest)
        if ec_hash is None:
            raise SignatureFormatError(f"unsupported ECDSA digest {ec_digest}")
        public_key.verify(signature, signed_bytes, ec.ECDSA(ec_hash()))
        return
    if signature_algorithm == ED25519_OID:
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise SignatureFormatError("Ed25519 signature used with a non-Ed25519 key")
        public_key.verify(signature, signed_bytes)
        return
    raise SignatureFormatError("unsupported signature algorithm")


def _signer_material(
    signed_data: bytes,
    content: bytes,
    candidates: Sequence[x509.Certificate],
) -> _SignerMaterial:
    certificates, signers = _parse_signed_data(signed_data)
    if len(signers) != 1:
        raise SignatureFormatError("exactly one CMS signer is supported")
    sid, digest_algorithm, signature_algorithm, signed_attrs, signature_value = signers[0]
    digest_oid, _ = _parse_algorithm(digest_algorithm)
    digest_name = _algorithm_hash(digest_oid, None)
    if digest_name is None:
        raise SignatureFormatError(f"unsupported digest algorithm {digest_oid}")
    certificate = _find_certificate(sid, [*certificates, *candidates])
    if certificate is None:
        raise SignatureFormatError("signer certificate is not available")
    signature_oid, signature_parameters = _parse_algorithm(signature_algorithm)
    signature_bytes = signature_value.as_octets()
    if signed_attrs is not None:
        attrs = _signed_attributes(signed_attrs)
        digest_values = attrs.get(OID_MESSAGE_DIGEST)
        if digest_values is None:
            raise _MissingMessageDigest()
        expected = _single_octets(digest_values)
        if expected is None:
            raise SignatureFormatError("messageDigest attribute is malformed")
        actual = _digest(digest_name, content)
        # Re-encode the implicit [0] SignedAttributes as an explicit SET OF.
        signed_bytes = b"\x31" + signed_attrs.header[1:] + signed_attrs.value
        if expected != actual:
            raise _ContentMismatch(certificate, signature_oid)
        content_type_values = attrs.get(OID_CONTENT_TYPE)
        if content_type_values is not None:
            declared_oid = _single_oid(content_type_values)
            if declared_oid is None:
                raise SignatureFormatError("contentType attribute is malformed")
            if declared_oid != OID_DATA:
                raise _ContentTypeMismatch()
    else:
        signed_bytes = content
    try:
        _verify_signature(
            certificate,
            signature_oid,
            signature_parameters,
            digest_name,
            signature_bytes,
            signed_bytes,
        )
    except InvalidSignature as exc:
        raise _SignatureMismatch(certificate, signature_oid) from exc
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        if isinstance(exc, (SignatureFormatError, _SignatureMismatch)):
            raise
        raise SignatureFormatError(str(exc)) from exc
    return _SignerMaterial(
        digest_name=digest_name,
        signature_algorithm=signature_oid,
        signature=signature_bytes,
        signed_attrs=signed_attrs,
        certificate=certificate,
        signer_fingerprint=_fingerprint(certificate),
        certificates=tuple(certificates),
    )


class _ContentMismatch(Exception):
    def __init__(
        self,
        certificate: x509.Certificate | None = None,
        signature_algorithm: str = "",
    ) -> None:
        super().__init__()
        self.certificate = certificate
        self.signature_algorithm = signature_algorithm


class _SignatureMismatch(Exception):
    def __init__(
        self,
        certificate: x509.Certificate | None = None,
        signature_algorithm: str = "",
    ) -> None:
        super().__init__()
        self.certificate = certificate
        self.signature_algorithm = signature_algorithm


class _ContentTypeMismatch(Exception):
    pass


class _MissingMessageDigest(Exception):
    pass


def _signing_time(signed_attrs: Der | None) -> datetime | None:
    """Read the CMS signingTime attribute if present.

    Certificate validity is judged at this claimed time only when the message
    itself provided one; otherwise the caller's verification clock is used.
    The value is untrusted input, but it can only narrow validity, and the
    signature over the attributes is still verified before it is trusted.
    """
    if signed_attrs is None:
        return None
    try:
        attrs = _signed_attributes(signed_attrs)
    except DerError:
        return None
    values = attrs.get(OID_SIGNING_TIME)
    if not values:
        return None
    for value in values:
        if value.tag not in (0x17, 0x18):  # UTCTime / GeneralizedTime
            continue
        try:
            text = value.value.decode("ascii")
        except UnicodeDecodeError:
            continue
        for pattern in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
            try:
                parsed = datetime.strptime(text, pattern)
            except ValueError:
                continue
            return parsed.replace(tzinfo=timezone.utc)
    return None


def _is_ca(cert: x509.Certificate, *, anchor: bool) -> bool:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return anchor
    if not constraints.ca:
        return False
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return bool(usage.key_cert_sign)


def _chain_to_anchor(
    certificate: x509.Certificate,
    candidates: Sequence[x509.Certificate],
    anchors: dict[str, TrustAnchor],
    moment: datetime,
    seen: frozenset[str],
    depth: int = 0,
) -> TrustAnchor | None:
    fingerprint = _fingerprint(certificate)
    if fingerprint in anchors:
        return anchors[fingerprint]
    if depth >= MAX_CERT_CHAIN_DEPTH or fingerprint in seen:
        return None
    seen = seen | {fingerprint}
    for candidate in candidates:
        candidate_fingerprint = _fingerprint(candidate)
        if candidate_fingerprint in seen:
            continue
        try:
            if certificate.issuer.public_bytes() != candidate.subject.public_bytes():
                continue
            if not _is_ca(candidate, anchor=candidate_fingerprint in anchors):
                continue
            if not _valid_at(candidate, moment):
                continue
            certificate.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, AttributeError, InvalidSignature):
            continue
        anchor = _chain_to_anchor(
            candidate, candidates, anchors, moment, seen, depth + 1
        )
        if anchor is not None:
            return anchor
    return None


def _trust_outcome(
    certificate: x509.Certificate,
    candidates: Sequence[x509.Certificate],
    trust: TrustConfig,
    moment: datetime,
) -> tuple[SignatureTrust, str, str, str]:
    anchors = {anchor.fingerprint_sha256: anchor for anchor in trust.anchors}
    fingerprint = _fingerprint(certificate)
    if not _valid_at(certificate, moment):
        return (
            SignatureTrust.UNTRUSTED,
            "signer_certificate_outside_validity",
            "signing certificate is not valid at the verification time",
            "",
        )
    if fingerprint in anchors:
        anchor = anchors[fingerprint]
        return (
            SignatureTrust.TRUSTED,
            "trusted_anchor",
            "signing certificate is a locally pinned trust anchor",
            anchor.fingerprint_sha256,
        )
    if _self_issued(certificate):
        return (
            SignatureTrust.UNTRUSTED,
            "self_signed_certificate",
            "signer used a self-signed certificate that is not a local anchor",
            "",
        )
    pool = [*candidates, *(anchor.certificate for anchor in trust.anchors)]
    anchor = _chain_to_anchor(certificate, pool, anchors, moment, frozenset())
    if anchor is not None:
        return (
            SignatureTrust.TRUSTED,
            "trusted_chain",
            "signing certificate chains to a local trust anchor",
            anchor.fingerprint_sha256,
        )
    return (
        SignatureTrust.UNTRUSTED,
        "unknown_anchor",
        "signing certificate does not chain to any local trust anchor",
        "",
    )


def verify_signed_layer(
    layer: SignedLayer,
    trust: TrustConfig,
    moment: datetime,
) -> SignatureEvidence:
    """Verify one detached S/MIME signature without any network access."""
    return _verify_signed_layer(layer, trust, moment, layer_count=0)


def verify_layer(layer: SignedLayer, trust: TrustConfig, moment: datetime) -> SignatureEvidence:
    return _verify_signed_layer(layer, trust, moment, layer_count=1)


def _verify_signed_layer(
    layer: SignedLayer,
    trust: TrustConfig,
    moment: datetime | None,
    *,
    layer_count: int,
) -> SignatureEvidence:
    moment = utc_now() if moment is None else _aware(moment)
    base = dict(
        content=layer.content,
        signature=layer.signature,
        protocol=layer.protocol,
        micalg=layer.micalg,
    )
    if layer.problem:
        return _integrity(
            SignatureIntegrity.UNVERIFIABLE, layer.problem,
            "signature material is missing or unsupported", layer_count, **base,
        )
    if layer.signature is None:
        return _integrity(
            SignatureIntegrity.UNVERIFIABLE, "signature_material_missing",
            "the signature part has no decodable payload", layer_count, **base,
        )
    content_variants = [("exact", layer.content)]
    canonical = _canonical_crlf(layer.content)
    if canonical != layer.content:
        content_variants.append(("crlf", canonical))
    last_error: Exception | None = None
    material: _SignerMaterial | None = None
    variant = "exact"
    for name, candidate in content_variants:
        try:
            material = _signer_material(layer.signature, candidate, [])
        except _ContentMismatch as exc:
            last_error = exc
            continue
        except _SignatureMismatch as exc:
            last_error = exc
            continue
        except _ContentTypeMismatch as exc:
            return _integrity(
                SignatureIntegrity.INVALID, "signed_content_type_mismatch",
                "signed contentType attribute does not identify CMS data",
                layer_count, **base,
            )
        except _MissingMessageDigest:
            return _integrity(
                SignatureIntegrity.UNVERIFIABLE, "missing_message_digest",
                "signed attributes do not bind the MIME content digest",
                layer_count, **base,
            )
        except SignatureFormatError as exc:
            return _integrity(
                SignatureIntegrity.UNVERIFIABLE, "signature_format_unsupported",
                str(exc), layer_count, **base,
            )
        except (DerError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            return _integrity(
                SignatureIntegrity.UNVERIFIABLE, "signature_material_invalid",
                f"signature material could not be parsed: {type(exc).__name__}",
                layer_count, **base,
            )
        variant = name
        break
    if material is None:
        if isinstance(last_error, _ContentMismatch):
            evidence = _integrity(
                SignatureIntegrity.INVALID, "signed_content_digest_mismatch",
                "signed MIME bytes do not match the messageDigest attribute",
                layer_count, **base,
            )
        else:
            evidence = _integrity(
                SignatureIntegrity.INVALID, "signature_verification_failed",
                "CMS signature does not match the signed MIME bytes", layer_count, **base,
            )
        signer_cert = getattr(last_error, "certificate", None)
        if signer_cert is not None:
            evidence = SignatureEvidence(
                **{
                    **evidence.__dict__,
                    "signer": _signer_identity(signer_cert),
                    "signature_type": _signature_type(
                        getattr(last_error, "signature_algorithm", "")
                    ),
                }
            )
        return evidence

    trust_value, trust_code, trust_reason, anchor_fingerprint = _trust_outcome(
        material.certificate, material.certificates, trust, moment
    )
    if trust_code == "signer_certificate_outside_validity":
        claimed = _signing_time(material.signed_attrs)
        if claimed is not None and _valid_at(material.certificate, claimed):
            # The certificate was valid at the claimed signing time; note that
            # this is an assertion inside the signed attributes, not a trusted
            # timestamp, so trust still requires a local anchor.
            trust_value, trust_code, trust_reason, anchor_fingerprint = _trust_outcome(
                material.certificate, material.certificates, trust, claimed
            )
            if trust_value is SignatureTrust.TRUSTED:
                trust_reason = (
                    trust_reason + " (certificate valid at the claimed signing time)"
                )
    reason_code = "signature_valid" if variant == "exact" else "signature_valid_crlf_canonicalized"
    reason = "CMS signature covers the exact signed MIME bytes"
    if variant != "exact":
        reason = "CMS signature covers the CRLF-canonicalized signed MIME bytes"
    return SignatureEvidence(
        integrity=SignatureIntegrity.VALID,
        trust=trust_value,
        reason_code=reason_code,
        reason=f"{reason}; {trust_reason}",
        signed_content_sha256=sha256_bytes(layer.content),
        signature_sha256=sha256_bytes(layer.signature),
        protocol=layer.protocol,
        micalg=layer.micalg,
        signer=_signer_identity(material.certificate),
        anchor_fingerprint=anchor_fingerprint,
        signature_type=_signature_type(material.signature_algorithm),
        digest_algorithm=material.digest_name,
        trust_reason_code=trust_code,
        layer_count=layer_count,
    )


def _signature_type(oid: str) -> str:
    if oid in RSA_SIGNATURE_OIDS:
        return "rsa-pkcs1v15"
    if oid == PSS_OID:
        return "rsa-pss"
    if oid in EC_SIGNATURE_OIDS:
        return "ecdsa"
    if oid == ED25519_OID:
        return "ed25519"
    return "unknown"


def _canonical_crlf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def not_signed_evidence() -> SignatureEvidence:
    return SignatureEvidence(
        integrity=SignatureIntegrity.NOT_SIGNED,
        trust=SignatureTrust.NOT_APPLICABLE,
        reason_code="not_multipart_signed",
        reason="message has no multipart/signed layer",
    )


def unparsable_evidence() -> SignatureEvidence:
    return SignatureEvidence(
        integrity=SignatureIntegrity.UNVERIFIABLE,
        trust=SignatureTrust.NOT_APPLICABLE,
        reason_code="signature_structure_unparsable",
        reason="a multipart/signed layer was present but its raw bytes could not be split",
    )


def aggregate_evidence(
    items: Sequence[SignatureEvidence], *, layer_count: int,
) -> SignatureEvidence:
    """Collapse several signed layers conservatively.

    Any invalid layer makes the message invalid.  Otherwise, if every layer is
    valid, the message is valid and trusted only when *all* signers chain to a
    local anchor.  Anything unverifiable stays unverifiable.
    """
    if not items:
        return not_signed_evidence()
    invalid = [item for item in items if item.integrity is SignatureIntegrity.INVALID]
    if invalid:
        return SignatureEvidence(
            integrity=SignatureIntegrity.INVALID,
            trust=SignatureTrust.NOT_APPLICABLE,
            reason_code=invalid[0].reason_code,
            reason=invalid[0].reason,
            signed_content_sha256=invalid[0].signed_content_sha256,
            signature_sha256=invalid[0].signature_sha256,
            protocol=invalid[0].protocol,
            micalg=invalid[0].micalg,
            layer_count=layer_count,
        )
    unverifiable = [
        item for item in items if item.integrity is SignatureIntegrity.UNVERIFIABLE
    ]
    if unverifiable:
        return SignatureEvidence(
            integrity=SignatureIntegrity.UNVERIFIABLE,
            trust=SignatureTrust.NOT_APPLICABLE,
            reason_code=unverifiable[0].reason_code,
            reason=unverifiable[0].reason,
            signed_content_sha256=unverifiable[0].signed_content_sha256,
            signature_sha256=unverifiable[0].signature_sha256,
            protocol=unverifiable[0].protocol,
            micalg=unverifiable[0].micalg,
            layer_count=layer_count,
        )
    first = items[0]
    trusted = all(item.trust is SignatureTrust.TRUSTED for item in items)
    return SignatureEvidence(
        integrity=SignatureIntegrity.VALID,
        trust=SignatureTrust.TRUSTED if trusted else SignatureTrust.UNTRUSTED,
        reason_code=first.reason_code,
        reason=first.reason if trusted else (
            "every signature is cryptographically valid, but at least one signer is "
            "not covered by a local trust anchor"
        ),
        signed_content_sha256=first.signed_content_sha256,
        signature_sha256=sha256_bytes(
            b"".join(bytes.fromhex(item.signature_sha256) for item in items)
        ),
        protocol=first.protocol,
        micalg=first.micalg,
        signer=first.signer,
        anchor_fingerprint=first.anchor_fingerprint,
        signature_type=first.signature_type,
        trust_reason_code=(
            first.trust_reason_code if trusted else "unknown_anchor"
        ),
        layer_count=layer_count,
    )
