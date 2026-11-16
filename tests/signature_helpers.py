"""Synthetic certificates and S/MIME messages used only by the tests.

Keys are generated in memory for each test session.  Nothing in this module is
loaded by the application at runtime, and no private key is ever written to a
report, the ledger, or a fixture that ships with the package.
"""

from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = dt.datetime(2024, 5, 17, 12, 0, 0, tzinfo=dt.timezone.utc)
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass(frozen=True)
class Identity:
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def _name(common_name: str, email: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mailatt synthetic test"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]
    )


def make_ca(common_name: str = "mailatt test root") -> Identity:
    subject = _name(common_name, "ca@demo.invalid")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(RSA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(RSA_KEY.public_key()),
            critical=False,
        )
    )
    return Identity(builder.sign(RSA_KEY, hashes.SHA256()), RSA_KEY)


def make_leaf(ca: Identity, common_name: str, email: str) -> Identity:
    subject = _name(common_name, email)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(RSA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca.certificate.public_key()
            ),
            critical=False,
        )
    )
    return Identity(builder.sign(ca.private_key, hashes.SHA256()), RSA_KEY)


def make_self_signed(common_name: str, email: str) -> Identity:
    subject = _name(common_name, email)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(RSA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(RSA_KEY.public_key()),
            critical=False,
        )
    )
    return Identity(builder.sign(RSA_KEY, hashes.SHA256()), RSA_KEY)


def sign_detached(content: bytes, identity: Identity, *, extra: list[Identity] | None = None) -> bytes:
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(identity.certificate, identity.private_key, hashes.SHA256())
    )
    for item in extra or []:
        builder = builder.add_certificate(item.certificate)
    return builder.sign(
        serialization.Encoding.DER,
        [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
    )


def text_entity(body: str = "Signed body") -> bytes:
    return (
        b"Content-Type: text/plain; charset=us-ascii\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"\r\n"
        + body.encode("ascii")
    )


def attachment_entity(
    filename: str = "note.txt",
    payload: bytes = b"attachment bytes",
    boundary: bytes = b"inner-boundary",
) -> bytes:
    return b"".join(
        [
            b"Content-Type: multipart/mixed; boundary=\"",
            boundary,
            b"\"\r\n\r\n",
            b"--", boundary, b"\r\n",
            b"Content-Type: text/plain; charset=us-ascii\r\n\r\n",
            b"Signed message body",
            b"\r\n--", boundary, b"\r\n",
            b"Content-Type: text/plain; name=\"", filename.encode("ascii"), b"\"\r\n",
            b"Content-Disposition: attachment; filename=\"", filename.encode("ascii"), b"\"\r\n",
            b"Content-Transfer-Encoding: 7bit\r\n\r\n",
            payload,
            b"\r\n--", boundary, b"--\r\n",
        ]
    )


def wrap_signed_message(
    signed_entity: bytes,
    signature: bytes,
    *,
    sender: str = "trusted@demo.invalid",
    subject: str = "Signed demo",
    boundary: bytes = b"signed-boundary",
    signature_type: str = "application/pkcs7-signature",
    signature_payload: bytes | None = None,
) -> bytes:
    """Build a CRLF ``multipart/signed`` message around exact signed bytes."""
    encoded = base64.encodebytes(signature_payload if signature_payload is not None else signature)
    encoded = encoded.replace(b"\n", b"\r\n").rstrip(b"\r\n")
    headers = (
        b"From: " + sender.encode("ascii") + b"\r\n"
        b"To: archive@demo.invalid\r\n"
        b"Subject: " + subject.encode("ascii") + b"\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/signed; protocol=\"" + signature_type.encode("ascii")
        + b"\"; micalg=\"sha-256\"; boundary=\"" + boundary + b"\"\r\n"
        b"\r\n"
    )
    return b"".join(
        [
            headers,
            b"Preface text\r\n\r\n",
            b"--", boundary, b"\r\n",
            signed_entity,
            b"\r\n--", boundary, b"\r\n",
            b"Content-Type: ", signature_type.encode("ascii"), b"; name=\"smime.p7s\"\r\n",
            b"Content-Transfer-Encoding: base64\r\n",
            b"Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n",
            encoded,
            b"\r\n--", boundary, b"--\r\n",
        ]
    )


def signed_message(
    identity: Identity,
    *,
    entity: bytes | None = None,
    extra: list[Identity] | None = None,
    **kwargs,
) -> bytes:
    entity = text_entity() if entity is None else entity
    signature = sign_detached(entity, identity, extra=extra)
    return wrap_signed_message(entity, signature, **kwargs)
