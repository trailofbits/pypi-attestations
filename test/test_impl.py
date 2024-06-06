"""Internal implementation tests."""

import os
from pathlib import Path

import pypi_attestation_models._impl as impl
import pytest
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

ONLINE_TESTS = "CI" in os.environ or "TEST_INTERACTIVE" in os.environ

online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")

artifact_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl"
bundle_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.sigstore"
attestation_path = Path(__file__).parent / "assets" / "rfc8785-0.1.2-py3-none-any.whl.attestation"


class TestAttestation:
    @online
    def test_roundtrip(self, id_token: IdentityToken) -> None:
        sign_ctx = SigningContext.staging()
        verifier = Verifier.staging()

        with sign_ctx.signer(id_token) as signer:
            attestation = impl.Attestation.sign(signer, artifact_path)

        attestation.verify(verifier, policy.UnsafeNoOp(), artifact_path)

        # converting to a bundle and verifying as a bundle also works
        bundle = impl.pypi_to_sigstore(attestation)
        verifier.verify_dsse(bundle, policy.UnsafeNoOp())

        # converting back also works
        roundtripped_attestation = impl.sigstore_to_pypi(bundle)
        roundtripped_attestation.verify(verifier, policy.UnsafeNoOp(), artifact_path)

    def test_verify(self) -> None:
        verifier = Verifier.staging()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())
        attestation.verify(verifier, policy.UnsafeNoOp(), artifact_path)

        # convert the attestation to a bundle and verify it that way too
        bundle = impl.pypi_to_sigstore(attestation)
        verifier.verify_dsse(bundle, policy.UnsafeNoOp())
