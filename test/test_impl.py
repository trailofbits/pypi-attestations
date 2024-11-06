"""Internal implementation tests."""

import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any, Optional

import pretend
import pytest
import sigstore
from pydantic import BaseModel, TypeAdapter, ValidationError
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.models import Bundle
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

import pypi_attestations._impl as impl

ONLINE_TESTS = "CI" in os.environ or "TEST_INTERACTIVE" in os.environ

online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

dist_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl"
dist = impl.Distribution.from_file(dist_path)
dist_bundle_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore"
dist_attestation_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.attestation"

# produced by actions/attest@v1
gh_signed_dist_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz"
gh_signed_dist = impl.Distribution.from_file(gh_signed_dist_path)
gh_signed_dist_bundle_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz.sigstore"


class TestDistribution:
    def test_from_file_nonexistent(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "foo-1.2.3.tar.gz"
        with pytest.raises(OSError):
            impl.Distribution.from_file(nonexistent)

    def test_invalid_sdist_name(self) -> None:
        with pytest.raises(ValidationError, match="Invalid sdist filename"):
            impl.Distribution(name="invalid-name.tar.gz", digest=sha256(b"lol").hexdigest())

    def test_invalid_wheel_name(self) -> None:
        with pytest.raises(ValidationError, match="Invalid wheel filename"):
            impl.Distribution(name="invalid-name.whl", digest=sha256(b"lol").hexdigest())

    def test_invalid_unknown_dist(self) -> None:
        with pytest.raises(ValidationError, match="unknown distribution format"):
            impl.Distribution(name="complete.nonsense", digest=sha256(b"lol").hexdigest())


class TestAttestation:
    @online
    def test_roundtrip(self, id_token: IdentityToken) -> None:
        sign_ctx = SigningContext.staging()

        with sign_ctx.signer(id_token) as signer:
            attestation = impl.Attestation.sign(signer, dist)

        attestation.verify(policy.UnsafeNoOp(), dist, staging=True)

        # converting to a bundle and verifying as a bundle also works
        bundle = attestation.to_bundle()
        Verifier.staging().verify_dsse(bundle, policy.UnsafeNoOp())

        # converting back also works
        roundtripped_attestation = impl.Attestation.from_bundle(bundle)
        roundtripped_attestation.verify(policy.UnsafeNoOp(), dist, staging=True)

    def test_wrong_predicate_raises_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def dummy_predicate(self_: StatementBuilder, _: str) -> StatementBuilder:
            # wrong type here to have a validation error
            self_._predicate_type = False  # type: ignore[assignment]
            return self_

        monkeypatch.setattr(sigstore.dsse.StatementBuilder, "predicate_type", dummy_predicate)
        with pytest.raises(impl.AttestationError, match="invalid statement"):
            impl.Attestation.sign(pretend.stub(), dist)

    @online
    def test_expired_certificate(
        self, id_token: IdentityToken, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def in_validity_period(_: IdentityToken) -> bool:
            return False

        monkeypatch.setattr(IdentityToken, "in_validity_period", in_validity_period)

        sign_ctx = SigningContext.staging()
        with sign_ctx.signer(id_token, cache=False) as signer:
            with pytest.raises(impl.AttestationError):
                impl.Attestation.sign(signer, dist)

    @online
    def test_multiple_signatures(
        self, id_token: IdentityToken, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def get_bundle(*_: Any) -> Bundle:
            # Duplicate the signature to trigger a Conversion error
            bundle = Bundle.from_json(gh_signed_dist_bundle_path.read_bytes())
            bundle._inner.dsse_envelope.signatures.append(bundle._inner.dsse_envelope.signatures[0])
            return bundle

        monkeypatch.setattr(sigstore.sign.Signer, "sign_dsse", get_bundle)

        sign_ctx = SigningContext.staging()

        with pytest.raises(impl.AttestationError):
            with sign_ctx.signer(id_token) as signer:
                impl.Attestation.sign(signer, dist)

    def test_verify_github_attested(self) -> None:
        pol = policy.AllOf(
            [
                policy.OIDCSourceRepositoryURI(
                    "https://github.com/trailofbits/pypi-attestation-models"
                ),
                policy.OIDCIssuerV2("https://token.actions.githubusercontent.com"),
            ]
        )

        bundle = Bundle.from_json(gh_signed_dist_bundle_path.read_bytes())
        attestation = impl.Attestation.from_bundle(bundle)

        predicate_type, predicate = attestation.verify(pol, gh_signed_dist)
        assert predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert predicate == {}

    @pytest.mark.parametrize("claims", (None, {}, {"ref": "refs/tags/v0.0.4a2"}))
    def test_verify_from_github_publisher(self, claims: Optional[dict]) -> None:
        publisher = impl.GitHubPublisher(
            repository="trailofbits/pypi-attestation-models",
            workflow="release.yml",
            claims=claims,
        )

        bundle = Bundle.from_json(gh_signed_dist_bundle_path.read_bytes())
        attestation = impl.Attestation.from_bundle(bundle)

        predicate_type, predicate = attestation.verify(publisher, gh_signed_dist)
        assert predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert predicate == {}

    def test_verify_from_github_publisher_wrong(self) -> None:
        publisher = impl.GitHubPublisher(
            repository="trailofbits/pypi-attestation-models",
            workflow="wrong.yml",
        )

        bundle = Bundle.from_json(gh_signed_dist_bundle_path.read_bytes())
        attestation = impl.Attestation.from_bundle(bundle)

        with pytest.raises(impl.VerificationError, match=r"Build Config URI .+ does not match"):
            attestation.verify(publisher, gh_signed_dist)

    def test_verify(self) -> None:
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())
        predicate_type, predicate = attestation.verify(pol, dist, staging=True)

        assert predicate_type == "https://docs.pypi.org/attestations/publish/v1"
        assert predicate is None

        # convert the attestation to a bundle and verify it that way too
        bundle = attestation.to_bundle()
        Verifier.staging().verify_dsse(bundle, policy.UnsafeNoOp())

    def test_verify_digest_mismatch(self, tmp_path: Path) -> None:
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        modified_dist_path = tmp_path / dist_path.name
        modified_dist_path.write_bytes(b"nothing")

        modified_dist = impl.Distribution.from_file(modified_dist_path)

        # attestation has the correct filename, but a mismatching digest.
        with pytest.raises(
            impl.VerificationError, match="subject does not match distribution digest"
        ):
            attestation.verify(pol, modified_dist, staging=True)

    def test_verify_filename_mismatch(self, tmp_path: Path) -> None:
        # Our checked-in asset has this identity.
        pol = policy.Identity(
            identity="william@yossarian.net", issuer="https://github.com/login/oauth"
        )

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        modified_dist_path = tmp_path / "wrong_name-0.1.2-py3-none-any.whl"
        modified_dist_path.write_bytes(dist_path.read_bytes())

        different_name_dist = impl.Distribution.from_file(modified_dist_path)

        # attestation has the correct digest, but a mismatching filename.
        with pytest.raises(
            impl.VerificationError, match="subject does not match distribution name"
        ):
            attestation.verify(pol, different_name_dist, staging=True)

    def test_verify_policy_mismatch(self) -> None:
        # Wrong identity.
        pol = policy.Identity(identity="fake@example.com", issuer="https://github.com/login/oauth")

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match=r"Certificate's SANs do not match"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_wrong_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(lambda bundle, policy: ("fake-type", None))
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="expected JSON envelope, got fake-type"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_bad_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(
                    lambda bundle, policy: ("application/vnd.in-toto+json", b"invalid json")
                )
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid statement"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_too_many_subjects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        statement = (
            StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    Subject(name="foo", digest=DigestSet(root={"sha256": "abcd"})),
                    Subject(name="bar", digest=DigestSet(root={"sha256": "1234"})),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(
                    lambda bundle, policy: (
                        "application/vnd.in-toto+json",
                        statement.encode(),
                    )
                )
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="too many subjects in statement"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_subject_missing_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        statement = (
            StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    Subject(name=None, digest=DigestSet(root={"sha256": "abcd"})),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(
                    lambda bundle, policy: (
                        "application/vnd.in-toto+json",
                        statement.encode(),
                    )
                )
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid subject: missing name"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_subject_invalid_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        statement = (
            StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    Subject(
                        name="foo-bar-invalid-wheel.whl",
                        digest=DigestSet(root={"sha256": "abcd"}),
                    ),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(
                    lambda bundle, policy: (
                        "application/vnd.in-toto+json",
                        statement.encode(),
                    )
                )
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="invalid subject: Invalid wheel filename"):
            attestation.verify(pol, dist, staging=True)

    def test_verify_unknown_attestation_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        statement = (
            StatementBuilder()  # noqa: SLF001
            .subjects(
                [
                    Subject(
                        name="rfc8785-0.1.2-py3-none-any.whl",
                        digest=DigestSet(
                            root={
                                "sha256": (
                                    "c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201"
                                ),
                            }
                        ),
                    ),
                ]
            )
            .predicate_type("foo")
            .build()
            ._inner.model_dump_json()
        )

        staging = pretend.call_recorder(
            lambda: pretend.stub(
                verify_dsse=pretend.call_recorder(
                    lambda bundle, policy: (
                        "application/vnd.in-toto+json",
                        statement.encode(),
                    )
                )
            )
        )
        monkeypatch.setattr(impl.Verifier, "staging", staging)
        pol = pretend.stub()

        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_text())

        with pytest.raises(impl.VerificationError, match="unknown attestation type: foo"):
            attestation.verify(pol, dist, staging=True)


def test_from_bundle_missing_signatures() -> None:
    bundle = Bundle.from_json(dist_bundle_path.read_bytes())
    bundle._inner.dsse_envelope.signatures = []  # noqa: SLF001

    with pytest.raises(impl.ConversionError, match="expected exactly one signature, got 0"):
        impl.Attestation.from_bundle(bundle)


def test_to_bundle_invalid_cert() -> None:
    attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_bytes())
    attestation.verification_material.certificate = b"foo"

    with pytest.raises(impl.ConversionError, match="invalid X.509 certificate"):
        attestation.to_bundle()


def test_to_bundle_invalid_tlog_entry() -> None:
    attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_bytes())
    attestation.verification_material.transparency_entries[0].clear()

    with pytest.raises(impl.ConversionError, match="invalid transparency log entry"):
        attestation.to_bundle()


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
        (
            "foo-1.0-py3.py2-none.abi3.cp37-any.whl",
            "foo-1.0-py2.py3-abi3.cp37.none-any.whl",
        ),
        (
            "foo-1.0-py3.py2-none.abi3.cp37-linux_x86_64.any.whl",
            "foo-1.0-py2.py3-abi3.cp37.none-any.linux_x86_64.whl",
        ),
        # wheel: verbose compressed tag sets are re-compressed
        ("foo-1.0-py3.py2.py3-none-any.whl", "foo-1.0-py2.py3-none-any.whl"),
        ("foo-1.0-py3-none.none.none-any.whl", "foo-1.0-py3-none-any.whl"),
        # sdist: fully normalized, no changes
        ("foo-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("foo-1.0.zip", "foo-1.0.zip"),
        # sdist: dist name is not case normalized
        ("Foo-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("FOO-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("FoO-1.0.tar.gz", "foo-1.0.tar.gz"),
        ("Foo-1.0.zip", "foo-1.0.zip"),
        ("FOO-1.0.zip", "foo-1.0.zip"),
        ("FoO-1.0.zip", "foo-1.0.zip"),
        # sdist: dist name contains alternate separators, including
        # `-` despite being forbidden by PEP 625
        ("foo-bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo-bar-baz-1.0.tar.gz", "foo_bar_baz-1.0.tar.gz"),
        ("foo--bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo.bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo..bar-1.0.tar.gz", "foo_bar-1.0.tar.gz"),
        ("foo.bar.baz-1.0.tar.gz", "foo_bar_baz-1.0.tar.gz"),
        ("foo-bar-1.0.zip", "foo_bar-1.0.zip"),
        ("foo-bar-baz-1.0.zip", "foo_bar_baz-1.0.zip"),
        ("foo--bar-1.0.zip", "foo_bar-1.0.zip"),
        ("foo.bar-1.0.zip", "foo_bar-1.0.zip"),
        ("foo..bar-1.0.zip", "foo_bar-1.0.zip"),
        ("foo.bar.baz-1.0.zip", "foo_bar_baz-1.0.zip"),
        # sdist: dist version is not normalized
        ("foo-1.0beta1.tar.gz", "foo-1.0b1.tar.gz"),
        ("foo-01.0beta1.tar.gz", "foo-1.0b1.tar.gz"),
        ("foo-1.0beta1.zip", "foo-1.0b1.zip"),
        ("foo-01.0beta1.zip", "foo-1.0b1.zip"),
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
        "foo-1.0.ZIP",
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
        "foo-charmander.zip",
        "foo-1charmander.zip",
        # sdist: nonsense suffixes
        "foo-1.2.3.junk.zip",
        "foo-1.2.3.junk.tar.gz",
        "foo-1.2.3.zip.tar.gz",
        "foo-1.2.3.tar.gz.zip",
    ],
)
def test_ultranormalize_dist_filename_invalid(input: str) -> None:
    with pytest.raises(ValueError):
        impl._ultranormalize_dist_filename(input)


class TestPublisher:
    def test_discriminator(self) -> None:
        gh_raw = {"kind": "GitHub", "repository": "foo/bar", "workflow": "publish.yml"}
        gh: impl.Publisher = TypeAdapter(impl.Publisher).validate_python(gh_raw)

        assert isinstance(gh, impl.GitHubPublisher)
        assert gh.repository == "foo/bar"
        assert gh.workflow == "publish.yml"
        assert TypeAdapter(impl.Publisher).validate_json(json.dumps(gh_raw)) == gh

        gl_raw = {"kind": "GitLab", "repository": "foo/bar/baz", "environment": "publish"}
        gl: impl.Publisher = TypeAdapter(impl.Publisher).validate_python(gl_raw)
        assert isinstance(gl, impl.GitLabPublisher)
        assert gl.repository == "foo/bar/baz"
        assert gl.environment == "publish"
        assert TypeAdapter(impl.Publisher).validate_json(json.dumps(gl_raw)) == gl

    def test_wrong_kind(self) -> None:
        with pytest.raises(ValueError, match="Input should be 'GitHub'"):
            impl.GitHubPublisher(kind="wrong", repository="foo/bar", workflow="publish.yml")

        with pytest.raises(ValueError, match="Input should be 'GitLab'"):
            impl.GitLabPublisher(kind="GitHub", repository="foo/bar")

    def test_claims(self) -> None:
        raw = {
            "kind": "GitHub",
            "repository": "foo/bar",
            "workflow": "publish.yml",
            "claims": {
                "this": "is-preserved",
                "this-too": 123,
            },
        }
        pub: impl.Publisher = TypeAdapter(impl.Publisher).validate_python(raw)

        assert pub.claims == {
            "this": "is-preserved",
            "this-too": 123,
        }


class TestGitLabPublisher:
    def test_as_policy(self) -> None:
        publisher = impl.GitLabPublisher(repository="fake/fake", claims={"ref": "refs/heads/main"})
        pol: policy.AllOf = publisher._as_policy()  # type: ignore[assignment]

        assert len(pol._children) == 3

    @pytest.mark.parametrize("claims", [None, {}, {"something": "unrelated"}, {"ref": None}])
    def test_as_policy_invalid(self, claims: Optional[dict]) -> None:
        publisher = impl.GitLabPublisher(repository="fake/fake", claims=claims)

        with pytest.raises(impl.VerificationError, match="refusing to build a policy"):
            publisher._as_policy()


class TestProvenance:
    def test_version(self) -> None:
        attestation = impl.Attestation.model_validate_json(dist_attestation_path.read_bytes())
        provenance = impl.Provenance(
            attestation_bundles=[
                impl.AttestationBundle(
                    publisher=impl.GitHubPublisher(repository="foo/bar", workflow="publish.yml"),
                    attestations=[attestation],
                )
            ]
        )
        assert provenance.version == 1

        # Setting any other version doesn't work.
        with pytest.raises(ValueError):
            provenance = impl.Provenance(
                version=2,
                attestation_bundles=[
                    impl.AttestationBundle(
                        publisher=impl.GitHubPublisher(
                            repository="foo/bar", workflow="publish.yml"
                        ),
                        attestations=[attestation],
                    )
                ],
            )


class DummyModel(BaseModel):
    base64_bytes: impl.Base64Bytes


class TestBase64Bytes:
    # See the docstrings for `_impl.Base64Bytes` for more details
    def test_decoding(self) -> None:
        # This raises when using our custom type. When using Pydantic's Base64Bytes,
        # this succeeds
        # The exception message is different in Python 3.9 vs >=3.10
        with pytest.raises(ValueError, match="Non-base64 digit found|Only base64 data is allowed"):
            DummyModel(base64_bytes=b"a\n\naaa")

    def test_encoding(self) -> None:
        model = DummyModel(base64_bytes=b"aaaa" * 76)
        assert "\\n" not in model.model_dump_json()
