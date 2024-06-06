"""Internal implementation module for `pypi-attestation-models`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Annotated, Any, Literal, NewType

import sigstore.errors
from annotated_types import MinLen  # noqa: TCH002
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import Base64Bytes, BaseModel
from pydantic_core import ValidationError
from sigstore._utils import _sha256_streaming
from sigstore.dsse import Envelope as DsseEnvelope
from sigstore.dsse import _DigestSet, _Statement, _StatementBuilder, _Subject
from sigstore.models import Bundle, LogEntry
from sigstore_protobuf_specs.io.intoto import Envelope as _Envelope
from sigstore_protobuf_specs.io.intoto import Signature as _Signature

if TYPE_CHECKING:
    from pathlib import Path  # pragma: no cover

    from sigstore.sign import Signer  # pragma: no cover
    from sigstore.verify import Verifier  # pragma: no cover
    from sigstore.verify.policy import VerificationPolicy  # pragma: no cover


class AttestationError(ValueError):
    """Base error for all APIs."""


class ConversionError(AttestationError):
    """The base error for all errors during conversion."""


class VerificationError(AttestationError):
    """The PyPI Attestation failed verification."""

    def __init__(self: VerificationError, msg: str) -> None:
        """Initialize an `VerificationError`."""
        super().__init__(f"Verification failed: {msg}")


TransparencyLogEntry = NewType("TransparencyLogEntry", dict[str, Any])


class VerificationMaterial(BaseModel):
    """Cryptographic materials used to verify attestation objects."""

    certificate: Base64Bytes
    """
    The signing certificate, as `base64(DER(cert))`.
    """

    transparency_entries: Annotated[list[TransparencyLogEntry], MinLen(1)]
    """
    One or more transparency log entries for this attestation's signature
    and certificate.
    """


class Attestation(BaseModel):
    """Attestation object as defined in PEP 740."""

    version: Literal[1]
    """
    The attestation format's version, which is always 1.
    """

    verification_material: VerificationMaterial
    """
    Cryptographic materials used to verify `message_signature`.
    """

    envelope: Envelope
    """
    The enveloped attestation statement and signature.
    """

    @classmethod
    def sign(cls, signer: Signer, dist: Path) -> Attestation:
        """Create an envelope, with signature, from a distribution file."""
        with dist.open(mode="rb", buffering=0) as io:
            # Replace this with `hashlib.file_digest()` once
            # our minimum supported Python is >=3.11
            digest = _sha256_streaming(io).hex()

        stmt = (
            _StatementBuilder()
            .subjects([_Subject(name=dist.name, digest=_DigestSet(root={"sha256": digest}))])
            .predicate_type("https://docs.pypi.org/attestations/publish/v1")
            .build()
        )
        bundle = signer.sign_dsse(stmt)

        return sigstore_to_pypi(bundle)

    def verify(self, verifier: Verifier, policy: VerificationPolicy, dist: Path) -> None:
        """Verify against an existing Python artifact.

        On failure, raises an appropriate subclass of `AttestationError`.
        """
        with dist.open(mode="rb", buffering=0) as io:
            # Replace this with `hashlib.file_digest()` once
            # our minimum supported Python is >=3.11
            expected_digest = _sha256_streaming(io).hex()

        bundle = pypi_to_sigstore(self)
        try:
            type_, payload = verifier.verify_dsse(bundle, policy)
        except sigstore.errors.VerificationError as err:
            raise VerificationError(str(err)) from err

        if type_ != DsseEnvelope._TYPE:  # noqa: SLF001
            raise VerificationError(f"expected JSON envelope, got {type_}")

        try:
            statement = _Statement.model_validate_json(payload)
        except ValidationError as e:
            raise VerificationError(f"invalid statement: {str(e)}")

        if len(statement.subjects) != 1:
            raise VerificationError("too many subjects in statement (must be exactly one)")

        subject = statement.subjects[0]
        if subject.name != dist.name:
            raise VerificationError(
                f"subject does not match distribution name: {subject.name} != {dist.name}"
            )

        digest = subject.digest.root.get("sha256")
        if digest is None or digest != expected_digest:
            raise VerificationError("subject does not match distribution digest")


class Envelope(BaseModel):
    """The attestation envelope, containing the attested-for payload and its signature."""

    statement: Base64Bytes
    """
    The attestation statement.

    This is represented as opaque bytes on the wire (encoded as base64),
    but it MUST be an JSON in-toto v1 Statement.
    """

    signature: Base64Bytes
    """
    A signature for the above statement, encoded as base64.
    """


def sigstore_to_pypi(sigstore_bundle: Bundle) -> Attestation:
    """Convert a Sigstore Bundle into a PyPI attestation as defined in PEP 740."""
    certificate = sigstore_bundle.signing_certificate.public_bytes(
        encoding=serialization.Encoding.DER
    )

    envelope = sigstore_bundle._inner.dsse_envelope  # noqa: SLF001

    if len(envelope.signatures) != 1:
        raise ConversionError(f"expected exactly one signature, got {len(envelope.signatures)}")

    return Attestation(
        version=1,
        verification_material=VerificationMaterial(
            certificate=base64.b64encode(certificate),
            transparency_entries=[TransparencyLogEntry(sigstore_bundle.log_entry._to_dict_rekor())],  # noqa: SLF001
        ),
        envelope=Envelope(
            statement=base64.b64encode(envelope.payload),
            signature=base64.b64encode(envelope.signatures[0].sig),
        ),
    )


def pypi_to_sigstore(pypi_attestation: Attestation) -> Bundle:
    """Convert a PyPI attestation object as defined in PEP 740 into a Sigstore Bundle."""
    cert_bytes = pypi_attestation.verification_material.certificate
    statement = pypi_attestation.envelope.statement
    signature = pypi_attestation.envelope.signature

    evp = DsseEnvelope(
        _Envelope(
            payload=statement,
            payload_type=DsseEnvelope._TYPE,  # noqa: SLF001
            signatures=[_Signature(sig=signature)],
        )
    )

    tlog_entry = pypi_attestation.verification_material.transparency_entries[0]
    try:
        certificate = x509.load_der_x509_certificate(cert_bytes)
    except ValueError as err:
        raise ConversionError(str(err)) from err

    try:
        log_entry = LogEntry._from_dict_rekor(tlog_entry)  # noqa: SLF001
    except (ValidationError, sigstore.errors.Error) as err:
        raise ConversionError(str(err)) from err

    return Bundle._from_parts(  # noqa: SLF001
        cert=certificate,
        content=evp,
        log_entry=log_entry,
    )
