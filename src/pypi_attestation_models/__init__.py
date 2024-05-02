"""The `pypi-attestation-models` APIs."""

__version__ = "0.0.1rc1"

from ._impl import (
    Attestation,
    AttestationPayload,
    ConversionError,
    InvalidAttestationError,
    VerificationMaterial,
    pypi_to_sigstore,
    sigstore_to_pypi,
)

__all__ = [
    "Attestation",
    "AttestationPayload",
    "ConversionError",
    "InvalidAttestationError",
    "VerificationMaterial",
    "pypi_to_sigstore",
    "sigstore_to_pypi",
]
