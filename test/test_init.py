"""Initial testing module."""

import pypi_attestation_models


def test_version() -> None:
    version = getattr(pypi_attestation_models, "__version__", None)
    assert version is not None
    assert isinstance(version, str)
