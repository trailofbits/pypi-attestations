"""Internal implementation tests."""

import os
from pathlib import Path

import pretend
import pypi_attestations._impl as impl
import pytest
from sigstore.dsse import _DigestSet, _StatementBuilder, _Subject
from sigstore.models import Bundle
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

ONLINE_TESTS = "CI" in os.environ or "TEST_INTERACTIVE" in os.environ

online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

artifact_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl"
bundle_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore"
attestation_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.attestation"

# produced by actions/attest@v1
gh_signed_artifact_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz"
gh_signed_bundle_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz.sigstore"


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

    def test_sign_invalid_dist_filename(self, tmp_path: Path) -> None:
        bad_dist = tmp_path / "invalid-name.tar.gz"
        bad_dist.write_bytes(b"junk")

        with pytest.raises(
            impl.AttestationError,
            match=r"Invalid sdist filename \(invalid version\): invalid-name\.tar\.gz",
        ):
            impl.Attestation.sign(pretend.stub(), bad_dist)

    def test_verify_github_attested(self) -> None:
        verifier = Verifier.production()
        pol = policy.AllOf(
            [
                policy.OIDCSourceRepositoryURI(
                    "https://github.com/trailofbits/pypi-attestation-models"
                ),
                policy.OIDCIssuerV2("https://token.actions.githubusercontent.com"),
            ]
        )

        bundle = Bundle.from_json(gh_signed_bundle_path.read_bytes())
        attestation = impl.sigstore_to_pypi(bundle)

        predicate_type, predicate = attestation.verify(verifier, pol, gh_signed_artifact_path)
        assert predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert predicate == {}

    def test_verify(self) -> None:
        verifier = Verifier.staging()
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())
        predicate_type, predicate = attestation.verify(verifier, pol, artifact_path)

        assert predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert predicate is None

        # convert the attestation to a bundle and verify it that way too
        bundle = impl.pypi_to_sigstore(attestation)
        verifier.verify_dsse(bundle, policy.UnsafeNoOp())

    def test_verify_digest_mismatch(self, tmp_path: Path) -> None:
        verifier = Verifier.staging()
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        modified_artifact_path = tmp_path / artifact_path.name
        modified_artifact_path.write_bytes(b"nothing")

        # attestation has the correct filename, but a mismatching digest.
        with pytest.raises(
            impl.VerificationError, match="subject does not match distribution digest"
        ):
            attestation.verify(verifier, pol, modified_artifact_path)

    def test_verify_filename_mismatch(self, tmp_path: Path) -> None:
        verifier = Verifier.staging()
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        modified_artifact_path = tmp_path / "wrong_name-0.1.2-py3-none-any.whl"
        modified_artifact_path.write_bytes(artifact_path.read_bytes())

        # attestation has the correct digest, but a mismatching filename.
        with pytest.raises(
            impl.VerificationError, match="subject does not match distribution name"
        ):
            attestation.verify(verifier, pol, modified_artifact_path)

    def test_verify_policy_mismatch(self) -> None:
        verifier = Verifier.staging()
        # Wrong identity.
        pol = policy.Identity(identity="fake@example.com", issuer="https://github.com/login/oauth")

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match=r"Certificate's SANs do not match"):
            attestation.verify(verifier, pol, artifact_path)

    def test_verify_wrong_envelope(self) -> None:
        verifier = pretend.stub(
            verify_dsse=pretend.call_recorder(lambda bundle, policy: ("fake-type", None))
        )
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="expected JSON envelope, got fake-type"):
            attestation.verify(verifier, pol, artifact_path)

    def test_verify_bad_payload(self) -> None:
        verifier = pretend.stub(
            verify_dsse=pretend.call_recorder(
                lambda bundle, policy: ("application/vnd.in-toto+json", b"invalid json")
            )
        )
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid statement"):
            attestation.verify(verifier, pol, artifact_path)

    def test_verify_too_many_subjects(self) -> None:
        statement = (
            _StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    _Subject(name="foo", digest=_DigestSet(root={"sha256": "abcd"})),
                    _Subject(name="bar", digest=_DigestSet(root={"sha256": "1234"})),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        verifier = pretend.stub(
            verify_dsse=pretend.call_recorder(
                lambda bundle, policy: ("application/vnd.in-toto+json", statement.encode())
            )
        )
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="too many subjects in statement"):
            attestation.verify(verifier, pol, artifact_path)

    def test_verify_subject_missing_name(self) -> None:
        statement = (
            _StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    _Subject(name=None, digest=_DigestSet(root={"sha256": "abcd"})),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        verifier = pretend.stub(
            verify_dsse=pretend.call_recorder(
                lambda bundle, policy: ("application/vnd.in-toto+json", statement.encode())
            )
        )
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid subject: missing name"):
            attestation.verify(verifier, pol, artifact_path)

    def test_verify_subject_invalid_name(self) -> None:
        statement = (
            _StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    _Subject(
                        name="foo-bar-invalid-wheel.whl", digest=_DigestSet(root={"sha256": "abcd"})
                    ),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        verifier = pretend.stub(
            verify_dsse=pretend.call_recorder(
                lambda bundle, policy: ("application/vnd.in-toto+json", statement.encode())
            )
        )
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid subject: Invalid wheel filename"):
            attestation.verify(verifier, pol, artifact_path)


def test_sigstore_to_pypi_missing_signatures() -> None:
    bundle = Bundle.from_json(bundle_path.read_bytes())
    bundle._inner.dsse_envelope.signatures = []  # noqa: SLF001

    with pytest.raises(impl.ConversionError, match="expected exactly one signature, got 0"):
        impl.sigstore_to_pypi(bundle)


def test_pypi_to_sigstore_invalid_cert() -> None:
    attestation = impl.Attestation.model_validate_json(attestation_path.read_bytes())
    attestation.verification_material.certificate = b"foo"

    with pytest.raises(impl.ConversionError, match="invalid X.509 certificate"):
        impl.pypi_to_sigstore(attestation)


def test_pypi_to_sigstore_invalid_tlog_entry() -> None:
    attestation = impl.Attestation.model_validate_json(attestation_path.read_bytes())
    attestation.verification_material.transparency_entries[0].clear()

    with pytest.raises(impl.ConversionError, match="invalid transparency log entry"):
        impl.pypi_to_sigstore(attestation)


class TestPackaging:
    """Behavioral backstops for our dependency on `packaging`."""

    def test_exception_types(self) -> None:
        from packaging.utils import InvalidSdistFilename, InvalidWheelFilename

        assert issubclass(InvalidSdistFilename, ValueError)
        assert issubclass(InvalidWheelFilename, ValueError)


@pytest.mark.parametrize(
    ("input", "normalized"),
    [
        # wheel: fully normalized, no changes
        ("foo-1.0-py3-none-any.whl", "foo-1.0-py3-none-any.whl"),
        # wheel: dist name is not case normalized
        ("Foo-1.0-py3-none-any.whl", "foo-1.0-py3-none-any.whl"),
        ("FOO-1.0-py3-none-any.whl", "foo-1.0-py3-none-any.whl"),
        ("FoO-1.0-py3-none-any.whl", "foo-1.0-py3-none-any.whl"),
        # wheel: dist name contains alternate separators
        ("foo.bar-1.0-py3-none-any.whl", "foo_bar-1.0-py3-none-any.whl"),
        ("foo_bar-1.0-py3-none-any.whl", "foo_bar-1.0-py3-none-any.whl"),
        # wheel: dist version is not normalized
        ("foo-1.0beta1-py3-none-any.whl", "foo-1.0b1-py3-none-any.whl"),
        ("foo-1.0beta.1-py3-none-any.whl", "foo-1.0b1-py3-none-any.whl"),
        ("foo-01.0beta.1-py3-none-any.whl", "foo-1.0b1-py3-none-any.whl"),
        # wheel: build tag works as expected
        ("foo-1.0-1whatever-py3-none-any.whl", "foo-1.0-1whatever-py3-none-any.whl"),
        # wheel: compressed tag sets are sorted, even when conflicting or nonsense
        ("foo-1.0-py3.py2-none-any.whl", "foo-1.0-py2.py3-none-any.whl"),
        ("foo-1.0-py3.py2-none.abi3.cp37-any.whl", "foo-1.0-py2.py3-abi3.cp37.none-any.whl"),
        (
            "foo-1.0-py3.py2-none.abi3.cp37-linux_x86_64.any.whl",
            "foo-1.0-py2.py3-abi3.cp37.none-any.linux_x86_64.whl",
        ),
        # wheel: verbose compressed tag sets are re-compressed
        ("foo-1.0-py3.py2.py3-none-any.whl", "foo-1.0-py2.py3-none-any.whl"),
        ("foo-1.0-py3-none.none.none-any.whl", "foo-1.0-py3-none-any.whl"),
        # sdist: fully normalized, no changes
        ("foo-1.0.tar.gz", "foo-1.0.tar.gz"),
        # sdist: dist name is not case normalized
        ("Foo-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("FOO-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("FoO-1.0.tar.gz", "foo-1.0.tar.gz"),
        # sdist: dist name contains alternate separators, including
        # `-` despite being forbidden by PEP 625
        ("foo-bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo-bar-baz-1.0.tar.gz", "foo_bar_baz-1.0.tar.gz"),
        ("foo--bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo.bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo..bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo.bar.baz-1.0.tar.gz", "foo_bar_baz-1.0.tar.gz"),
        # sdist: dist version is not normalized
        ("foo-1.0beta1.tar.gz", "foo-1.0b1.tar.gz"),
        ("foo-01.0beta1.tar.gz", "foo-1.0b1.tar.gz"),
    ],
)
def test_ultranormalize_dist_filename(input: str, normalized: str) -> None:
    # normalization works as expected
    assert impl._ultranormalize_dist_filename(input) == normalized

    # normalization is a fixpoint, and normalized names are valid dist names
    assert impl._ultranormalize_dist_filename(normalized) == normalized


@pytest.mark.parametrize(
    "input",
    [
        # completely invalid
        "foo",
        # suffixes must be lowercase
        "foo-1.0.TAR.GZ",
        "foo-1.0-py3-none-any.WHL",
        # wheel: invalid separator in dist name
        "foo-bar-1.0-py3-none-any.whl",
        "foo__bar-1.0-py3-none-any.whl",
        # wheel: invalid version
        "foo-charmander-py3-none-any.whl",
        "foo-1charmander-py3-none-any.whl",
        # sdist: invalid version
        "foo-charmander.tar.gz",
        "foo-1charmander.tar.gz",
    ],
)
def test_ultranormalize_dist_filename_invalid(input: str) -> None:
    with pytest.raises(ValueError):
        impl._ultranormalize_dist_filename(input)
