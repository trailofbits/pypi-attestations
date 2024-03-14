"""Internal implementation tests."""

import json
from pathlib import Path

import pypi_attestation_models._impl as impl
import pytest
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle

bundle_path = Path(__file__).parent / "assets" / "rfc8785-0.0.2-py3-none-any.whl.sigstore"
attestation_path = Path(__file__).parent / "assets" / "rfc8785-0.0.2-py3-none-any.whl.json"


def test_sigstore_to_pypi() -> None:
    with bundle_path.open("rb") as f:
        sigstore_bundle = Bundle().from_json(f.read())
    attestation = impl.sigstore_to_pypi(sigstore_bundle)
    with attestation_path.open("rb") as expected_file:
        assert json.loads(attestation.to_json()) == json.load(expected_file)


def test_sigstore_to_pypi_empty_certs() -> None:
    with bundle_path.open("rb") as f:
        sigstore_bundle = Bundle().from_json(f.read())
    sigstore_bundle.verification_material.certificate.raw_bytes = b""
    sigstore_bundle.verification_material.x509_certificate_chain.certificates = []

    with pytest.raises(impl.InvalidBundleError):
        impl.sigstore_to_pypi(sigstore_bundle)


def test_pypi_to_sigstore() -> None:
    with attestation_path.open("rb") as f:
        attestation = impl.Attestation.from_dict(json.load(f))
    bundle = impl.pypi_to_sigstore(attestation)
    with bundle_path.open("rb") as original_bundle_file:
        original_bundle = Bundle().from_json(original_bundle_file.read())

    # Sigstore Bundle -> PyPI attestation is a lossy operation, so when we go backwards
    # the resulting Bundle will have fewer fields than the original Bundle. Not only that,
    # but the fields present might be different (e.g: the original bundle might have a
    # `x509_certificate_chain` field, but the converted bundle will use the `certificate` field
    # instead).
    assert bundle.media_type == "application/vnd.dev.sigstore.bundle+json;version=0.3"
    assert bundle.message_signature.signature == original_bundle.message_signature.signature
    assert (
        bundle.verification_material.tlog_entries
        == original_bundle.verification_material.tlog_entries
    )
    if original_bundle.verification_material.certificate.raw_bytes != b"":
        assert (
            bundle.verification_material.certificate
            == original_bundle.verification_material.certificate
        )
    else:
        assert (
            bundle.verification_material.certificate
            == original_bundle.verification_material.x509_certificate_chain.certificates[0]
        )


def test_pypi_to_sigstore_invalid_certificate_base64() -> None:
    with attestation_path.open("rb") as f:
        attestation = impl.Attestation.from_dict(json.load(f))
    attestation.verification_material.certificate = "invalid base64 @@@@ string"
    with pytest.raises(impl.InvalidAttestationError):
        impl.pypi_to_sigstore(attestation)
