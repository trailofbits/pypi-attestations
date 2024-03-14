"""Internal implementation module for `pypi-attestation-models`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import binascii
import json
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass
from typing import Any, Literal

import sigstore_protobuf_specs.dev.sigstore.bundle.v1 as sigstore
from sigstore_protobuf_specs.dev.sigstore.common.v1 import MessageSignature, X509Certificate
from sigstore_protobuf_specs.dev.sigstore.rekor.v1 import TransparencyLogEntry

_NO_CERTIFICATES_ERROR_MESSAGE = "No certificates found in Sigstore Bundle"


class ConversionError(ValueError):
    """The base error for all errors during conversion."""


class InvalidBundleError(ConversionError):
    """The Sigstore Bundle given as input is not valid."""

    def __init__(self: InvalidBundleError, msg: str) -> None:
        """Initialize an `InvalidBundleError`."""
        super().__init__(f"Could not convert input Bundle: {msg}")


class InvalidAttestationError(ConversionError):
    """The PyPI Attestation given as input is not valid."""

    def __init__(self: InvalidAttestationError, msg: str) -> None:
        """Initialize an `InvalidAttestationError`."""
        super().__init__(f"Could not convert input Attestation: {msg}")


@dataclass
class VerificationMaterial:
    """Cryptographic materials used to verify attestation objects."""

    certificate: str
    """
    The signing certificate, as `base64(DER(cert))`.
    """

    transparency_entries: list[dict[str, Any]]
    """
    One or more transparency log entries for this attestation's signature
    and certificate.
    """

    @staticmethod
    def from_dict(dict_input: dict[str, Any]) -> VerificationMaterial:
        """Create a VerificationMaterial object from a dict."""
        return VerificationMaterial(
            certificate=dict_input["certificate"],
            transparency_entries=dict_input["transparency_entries"],
        )


@dataclass
class Attestation:
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
    is the raw bytes of the signing operation.
    """

    def to_json(self: Attestation) -> str:
        """Serialize the attestation object into JSON."""
        return json.dumps(asdict(self))

    @staticmethod
    def from_dict(dict_input: dict[str, Any]) -> Attestation:
        """Create an Attestation object from a dict."""
        return Attestation(
            version=dict_input["version"],
            verification_material=VerificationMaterial.from_dict(
                dict_input["verification_material"],
            ),
            message_signature=dict_input["message_signature"],
        )


@dataclass
class Provenance:
    """Provenance object as defined in PEP 740."""

    version: Literal[1]
    """
    The provenance object's version, which is always 1.
    """

    publisher: object | None
    """
    An optional open-ended JSON object, specific to the kind of Trusted
    Publisher used to publish the file, if one was used.
    """

    attestations: list[Attestation]
    """
    One or more attestation objects.
    """


def sigstore_to_pypi(sigstore_bundle: sigstore.Bundle) -> Attestation:
    """Convert a Sigstore Bundle into a PyPI attestation object, as defined in PEP 740."""
    certificate = sigstore_bundle.verification_material.certificate.raw_bytes
    if certificate == b"":
        # If there's no single certificate, we check for a leaf certificate in the
        # x509_certificate_chain.certificates` field.
        certificates = sigstore_bundle.verification_material.x509_certificate_chain.certificates
        if not certificates:
            raise InvalidBundleError(_NO_CERTIFICATES_ERROR_MESSAGE)
        # According to the spec, the first member of the sequence MUST be the leaf certificate
        # conveying the signing key
        certificate = certificates[0].raw_bytes

    certificate = b64encode(certificate).decode("ascii")
    tlog_entries = [t.to_dict() for t in sigstore_bundle.verification_material.tlog_entries]
    verification_material = VerificationMaterial(
        certificate=certificate,
        transparency_entries=tlog_entries,
    )

    return Attestation(
        version=1,
        verification_material=verification_material,
        message_signature=b64encode(sigstore_bundle.message_signature.signature).decode("ascii"),
    )


def pypi_to_sigstore(pypi_attestation: Attestation) -> sigstore.Bundle:
    """Convert a PyPI attestation object as defined in PEP 740 into a Sigstore Bundle."""
    try:
        certificate_bytes = b64decode(pypi_attestation.verification_material.certificate)
        signature_bytes = b64decode(pypi_attestation.message_signature)
    except binascii.Error as err:
        raise InvalidAttestationError(str(err)) from err

    certificate = X509Certificate(raw_bytes=certificate_bytes)
    tlog_entries = [
        TransparencyLogEntry().from_dict(x)
        for x in pypi_attestation.verification_material.transparency_entries
    ]

    verification_material = sigstore.VerificationMaterial(
        certificate=certificate,
        tlog_entries=tlog_entries,
    )
    return sigstore.Bundle(
        media_type="application/vnd.dev.sigstore.bundle+json;version=0.3",
        verification_material=verification_material,
        message_signature=MessageSignature(signature=signature_bytes),
    )
