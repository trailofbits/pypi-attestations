"""Initial testing module."""

import pypi_attestations


def test_version() -> None:
    version = getattr(pypi_attestations, "__version__", None)
    assert version is not None
    assert isinstance(version, str)
