"""Internal implementation tests."""

import hashlib
import json
from pathlib import Path

import pretend
import pypi_attestation_models._impl as impl
import pytest
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

artifact_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl"
bundle_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.sigstore"
attestation_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.attestation"


class TestSigningAndVerifying:
    def test_payload_sign(self) -> None:
        # Call sign on a new AttestationPayload, but mock the underlying call to
        # sigstore.Signer.sign() to check that it's called with the correct argument.
        sigstore_bundle = Bundle.from_json(bundle_path.read_bytes())
        payload = impl.AttestationPayload.from_dist(artifact_path)
        signer = pretend.stub(sign_artifact=pretend.call_recorder(lambda _input: sigstore_bundle))
        payload.sign(signer)

        # Sigstore sign operation should have been called with the AttestationPayload
        # corresponding to the Python artifact
        assert signer.sign_artifact.calls == [pretend.call(bytes(payload))]

    def test_attestation_verify(self) -> None:
        # Call verify on an existing attestation, but mock the underlying call to
        # sigstore.Verifier.verify() to check that it's called with the correct arguments.
        attestation = impl.Attestation.model_validate_json(attestation_path.read_bytes())
        verifier = pretend.stub(
            verify_artifact=pretend.call_recorder(lambda _input, _bundle, _policy: None)
        )
        policy_stub = pretend.stub()
        attestation.verify(verifier, policy_stub, artifact_path)

        # This is the input `verify_artifact` should have been called with
        # (the bytes of the `AttestationPayload`, not the artifact itself)
        expected_payload = bytes(impl.AttestationPayload.from_dist(artifact_path))

        # This is the bundle `verify_artifact` should have been caled with
        # (the Sigstore Bundle corresponding to the input Attestation)
        expected_bundle = impl.pypi_to_sigstore(attestation)

        assert len(verifier.verify_artifact.calls) == 1
        verify_args = verifier.verify_artifact.calls[0].args
        assert verify_args[0] == expected_payload
        assert verify_args[1].to_json() == expected_bundle.to_json()
        assert verify_args[2] == policy_stub


class TestModelConversions:
    def test_sigstore_to_pypi(self) -> None:
        # Load an existing Sigstore bundle, convert it to a PyPI attestation,
        # and check that the result is what we expect.
        with bundle_path.open("rb") as f:
            sigstore_bundle = Bundle.from_json(f.read())
        attestation = impl.sigstore_to_pypi(sigstore_bundle)
        with attestation_path.open("rb") as expected_file:
            assert json.loads(attestation.model_dump_json()) == json.load(expected_file)

    def test_pypi_to_sigstore(self) -> None:
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

    def test_pypi_to_sigstore_invalid_certificate_base64(self) -> None:
        with attestation_path.open("rb") as f:
            attestation = impl.Attestation.model_validate_json(f.read())
        attestation.verification_material.certificate = "invalid base64 @@@@ string"
        with pytest.raises(impl.InvalidAttestationError):
            impl.pypi_to_sigstore(attestation)

    def test_pypi_to_sigstore_invalid_certificate(self) -> None:
        with attestation_path.open("rb") as f:
            attestation = impl.Attestation.model_validate_json(f.read())
        new_cert = attestation.verification_material.certificate.replace("M", "x")
        attestation.verification_material.certificate = new_cert
        with pytest.raises(impl.InvalidAttestationError):
            impl.pypi_to_sigstore(attestation)

    def test_pypi_to_sigstore_invalid_log_entry(self) -> None:
        with attestation_path.open("rb") as f:
            attestation = impl.Attestation.model_validate_json(f.read())
        new_log_entry = attestation.verification_material.transparency_entries[0]
        del new_log_entry["inclusionProof"]
        attestation.verification_material.transparency_entries = [new_log_entry]
        with pytest.raises(impl.InvalidAttestationError):
            impl.pypi_to_sigstore(attestation)

    def test_verification_roundtrip(self) -> None:
        # Load an existing Sigstore bundle, check that verification passes,
        # convert it to a PyPI attestation and then back again to a Sigstore
        # bundle, and check that verification still passes.
        with bundle_path.open("rb") as f:
            sigstore_bundle = Bundle.from_json(f.read())

        verifier = Verifier.production()
        with artifact_path.open("rb") as f:
            payload = impl.AttestationPayload.from_dist(artifact_path)
            verifier.verify_artifact(
                bytes(payload),
                sigstore_bundle,
                policy.Identity(
                    identity="facundo.tuesca@trailofbits.com", issuer="https://accounts.google.com"
                ),
            )

        attestation = impl.sigstore_to_pypi(sigstore_bundle)
        roundtrip_bundle = impl.pypi_to_sigstore(attestation)
        with artifact_path.open("rb") as f:
            verifier.verify_artifact(
                bytes(payload),
                roundtrip_bundle,
                policy.Identity(
                    identity="facundo.tuesca@trailofbits.com", issuer="https://accounts.google.com"
                ),
            )

    def test_attestation_payload(self) -> None:
        payload = impl.AttestationPayload.from_dist(artifact_path)

        assert payload.digest == hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        assert payload.distribution == artifact_path.name

        expected = f'{{"digest":"{payload.digest}","distribution":"{payload.distribution}"}}'

        assert bytes(payload) == bytes(expected, "utf-8")
