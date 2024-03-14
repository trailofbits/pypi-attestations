"""The `pypi-attestation-models` APIs."""

__version__ = "0.0.1"

from ._impl import (
    Attestation,
    ConversionError,
    InvalidAttestationError,
    InvalidBundleError,
    VerificationMaterial,
    pypi_to_sigstore,
    sigstore_to_pypi,
)

__all__ = [
    "Attestation",
    "ConversionError",
    "InvalidAttestationError",
    "InvalidBundleError",
    "VerificationMaterial",
    "pypi_to_sigstore",
    "sigstore_to_pypi",
]
