"""Internal implementation tests."""

import json
from pathlib import Path

import pypi_attestation_models._impl as impl
import pytest
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

artifact_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl"
bundle_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.sigstore"
attestation_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.json"


def test_sigstore_to_pypi() -> None:
    # Load an existing Sigstore bundle, convert it to a PyPI attestation,
    # and check that the result is what we expect.
    with bundle_path.open("rb") as f:
        sigstore_bundle = Bundle.from_json(f.read())
    attestation = impl.sigstore_to_pypi(sigstore_bundle)
    with attestation_path.open("rb") as expected_file:
        assert json.loads(attestation.model_dump_json()) == json.load(expected_file)


def test_pypi_to_sigstore() -> None:
    # Load an existing PyPI attestation, convert it to a Sigstore bundle,
    # and check that the result matches the original Sigstore bundle used
    # to generate the attestation
    with attestation_path.open("rb") as f:
        attestation = impl.Attestation.model_validate_json(f.read())
    bundle = impl.pypi_to_sigstore(attestation)
    with bundle_path.open("rb") as original_bundle_file:
        original_bundle = Bundle.from_json(original_bundle_file.read())

    # Sigstore Bundle -> PyPI attestation is a lossy operation, so when we go backwards
    # the resulting Bundle will have fewer fields than the original Bundle.
    assert bundle._inner.media_type == original_bundle._inner.media_type  # noqa: SLF001
    assert bundle._inner.verification_material == original_bundle._inner.verification_material  # noqa: SLF001
    assert (
        bundle._inner.message_signature.signature  # noqa: SLF001
        == original_bundle._inner.message_signature.signature  # noqa: SLF001
    )
    assert bundle.log_entry == original_bundle.log_entry
    assert bundle.signing_certificate == original_bundle.signing_certificate


def test_pypi_to_sigstore_invalid_certificate_base64() -> None:
    with attestation_path.open("rb") as f:
        attestation = impl.Attestation.model_validate_json(f.read())
    attestation.verification_material.certificate = "invalid base64 @@@@ string"
    with pytest.raises(impl.InvalidAttestationError):
        impl.pypi_to_sigstore(attestation)


def test_verification_roundtrip() -> None:
    # Load an existing Sigstore bundle, check that verification passes,
    # convert it to a PyPI attestation and then back again to a Sigstore
    # bundle, and check that verification still passes.
    with bundle_path.open("rb") as f:
        sigstore_bundle = Bundle.from_json(f.read())

    verifier = Verifier.production()
    with artifact_path.open("rb") as f:
        verifier.verify_artifact(
            f.read(),
            sigstore_bundle,
            policy.Identity(
                identity="facundo.tuesca@trailofbits.com", issuer="https://accounts.google.com"
            ),
        )

    attestation = impl.sigstore_to_pypi(sigstore_bundle)
    roundtrip_bundle = impl.pypi_to_sigstore(attestation)
    with artifact_path.open("rb") as f:
        verifier.verify_artifact(
            f.read(),
            roundtrip_bundle,
            policy.Identity(
                identity="facundo.tuesca@trailofbits.com", issuer="https://accounts.google.com"
            ),
        )
