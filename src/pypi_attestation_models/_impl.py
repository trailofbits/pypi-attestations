"""Internal implementation module for `pypi-attestation-models`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import binascii
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import TYPE_CHECKING, Annotated, Any, Literal, NewType

import rfc8785
from annotated_types import MinLen  # noqa: TCH002
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel
from sigstore.models import Bundle, LogEntry

if TYPE_CHECKING:
    from pathlib import Path  # pragma: no cover


class ConversionError(ValueError):
    """The base error for all errors during conversion."""


class InvalidAttestationError(ConversionError):
    """The PyPI Attestation given as input is not valid."""

    def __init__(self: InvalidAttestationError, msg: str) -> None:
        """Initialize an `InvalidAttestationError`."""
        super().__init__(f"Could not convert input Attestation: {msg}")


TransparencyLogEntry = NewType("TransparencyLogEntry", dict[str, Any])


class VerificationMaterial(BaseModel):
    """Cryptographic materials used to verify attestation objects."""

    certificate: str
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

    message_signature: str
    """
    The attestation's signature, as `base64(raw-sig)`, where `raw-sig`
    is the raw bytes of the signing operation over the attestation payload.
    """


class AttestationPayload(BaseModel):
    """Attestation Payload object as defined in PEP 740."""

    distribution: str
    """
    The file name of the Python package distribution.
    """

    digest: str
    """
    The SHA-256 digest of the distribution's contents, as a hexadecimal string.
    """

    @classmethod
    def from_dist(cls, dist: Path) -> AttestationPayload:
        """Create an `AttestationPayload` from a distribution file."""
        return AttestationPayload(
            distribution=dist.name,
            digest=sha256(dist.read_bytes()).hexdigest(),
        )

    def __bytes__(self: AttestationPayload) -> bytes:
        """Convert to bytes using a canonicalized JSON representation (from RFC8785)."""
        return rfc8785.dumps(self.model_dump())


def sigstore_to_pypi(sigstore_bundle: Bundle) -> Attestation:
    """Convert a Sigstore Bundle into a PyPI attestation as defined in PEP 740."""
    certificate = sigstore_bundle.signing_certificate.public_bytes(
        encoding=serialization.Encoding.DER
    )

    signature = sigstore_bundle._inner.message_signature.signature  # noqa: SLF001
    return Attestation(
        version=1,
        verification_material=VerificationMaterial(
            certificate=b64encode(certificate).decode("ascii"),
            transparency_entries=[sigstore_bundle.log_entry._to_dict_rekor()],  # noqa: SLF001
        ),
        message_signature=b64encode(signature).decode("ascii"),
    )


def pypi_to_sigstore(pypi_attestation: Attestation) -> Bundle:
    """Convert a PyPI attestation object as defined in PEP 740 into a Sigstore Bundle."""
    try:
        certificate_bytes = b64decode(pypi_attestation.verification_material.certificate)
        signature_bytes = b64decode(pypi_attestation.message_signature)
    except binascii.Error as err:
        raise InvalidAttestationError(str(err)) from err

    tlog_entry = pypi_attestation.verification_material.transparency_entries[0]

    return Bundle.from_parts(
        cert=x509.load_der_x509_certificate(certificate_bytes),
        sig=signature_bytes,
        log_entry=LogEntry._from_dict_rekor(tlog_entry),  # noqa: SLF001
    )
