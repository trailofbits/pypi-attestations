"""The `pypi-attestation-models` APIs."""

__version__ = "0.0.1rc2"

from ._impl import (
    Attestation,
    AttestationPayload,
    ConversionError,
    InvalidAttestationError,
    TransparencyLogEntry,
    VerificationError,
    VerificationMaterial,
    pypi_to_sigstore,
    sigstore_to_pypi,
)

__all__ = [
    "Attestation",
    "AttestationPayload",
    "ConversionError",
    "InvalidAttestationError",
    "TransparencyLogEntry",
    "VerificationError",
    "VerificationMaterial",
    "pypi_to_sigstore",
    "sigstore_to_pypi",
]
