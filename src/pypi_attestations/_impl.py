"""Internal implementation module for `pypi-attestations`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import base64
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Any, Literal, NewType

import sigstore.errors
from annotated_types import MinLen  # noqa: TCH002
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from packaging.utils import parse_sdist_filename, parse_wheel_filename
from pydantic import Base64Encoder, BaseModel, ConfigDict, EncodedBytes, Field, field_validator
from pydantic.alias_generators import to_snake
from pydantic_core import ValidationError
from sigstore._utils import _sha256_streaming
from sigstore.dsse import DigestSet, StatementBuilder, Subject, _Statement
from sigstore.dsse import Envelope as DsseEnvelope
from sigstore.dsse import Error as DsseError
from sigstore.models import Bundle, LogEntry
from sigstore.sign import ExpiredCertificate, ExpiredIdentity
from sigstore_protobuf_specs.io.intoto import Envelope as _Envelope
from sigstore_protobuf_specs.io.intoto import Signature as _Signature

if TYPE_CHECKING:
    from pathlib import Path  # pragma: no cover

    from sigstore.sign import Signer  # pragma: no cover
    from sigstore.verify import Verifier  # pragma: no cover
    from sigstore.verify.policy import VerificationPolicy  # pragma: no cover


class Base64EncoderSansNewline(Base64Encoder):
    r"""A Base64Encoder that doesn't insert newlines when encoding.

    Pydantic's Base64Bytes type inserts newlines b'\n' every 76 characters because they
    use `base64.encodebytes()` instead of `base64.b64encode()`. Pydantic maintainers
    have stated that they won't fix this, and that users should work around it by
    defining their own Base64 type with a custom encoder.
    See https://github.com/pydantic/pydantic/issues/9072 for more details.
    """

    @classmethod
    def encode(cls, value: bytes) -> bytes:
        """Encode bytes to base64."""
        return base64.b64encode(value)

    @classmethod
    def decode(cls, value: bytes) -> bytes:
        """Decode base64 bytes."""
        return base64.b64decode(value, validate=True)


Base64Bytes = Annotated[bytes, EncodedBytes(encoder=Base64EncoderSansNewline)]


class Distribution(BaseModel):
    """Represents a Python package distribution.

    A distribution is identified by its (sdist or wheel) filename, which
    provides the package name and version (at a minimum) plus a SHA-256
    digest, which uniquely identifies its contents.
    """

    name: str
    digest: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        return _ultranormalize_dist_filename(v)

    @classmethod
    def from_file(cls, dist: Path) -> Distribution:
        """Construct a `Distribution` from the given path."""
        name = dist.name
        with dist.open(mode="rb", buffering=0) as io:
            # Replace this with `hashlib.file_digest()` once
            # our minimum supported Python is >=3.11
            digest = _sha256_streaming(io).hex()

        return cls(name=name, digest=digest)


class AttestationType(str, Enum):
    """Attestation types known to PyPI."""

    SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
    PYPI_PUBLISH_V1 = "https://docs.pypi.org/attestations/publish/v1"


class AttestationError(ValueError):
    """Base error for all APIs."""


class ConversionError(AttestationError):
    """The base error for all errors during conversion."""


class VerificationError(AttestationError):
    """The PyPI Attestation failed verification."""

    def __init__(self: VerificationError, msg: str) -> None:
        """Initialize an `VerificationError`."""
        super().__init__(f"Verification failed: {msg}")


TransparencyLogEntry = NewType("TransparencyLogEntry", dict[str, Any])


class VerificationMaterial(BaseModel):
    """Cryptographic materials used to verify attestation objects."""

    certificate: Base64Bytes
    """
    The signing certificate, as `base64(DER(cert))`.
    """

    transparency_entries: Annotated[list[TransparencyLogEntry], MinLen(1)]
    """
    One or more transparency log entries for this attestation's signature
    and certificate.
    """


class Attestation(BaseModel):
    """Attestation object as defined in PEP 740."""

    version: Literal[1]
    """
    The attestation format's version, which is always 1.
    """

    verification_material: VerificationMaterial
    """
    Cryptographic materials used to verify `message_signature`.
    """

    envelope: Envelope
    """
    The enveloped attestation statement and signature.
    """

    @classmethod
    def sign(cls, signer: Signer, dist: Distribution) -> Attestation:
        """Create an envelope, with signature, from the given Python distribution.

        On failure, raises `AttestationError`.
        """
        try:
            stmt = (
                StatementBuilder()
                .subjects(
                    [
                        Subject(
                            name=dist.name,
                            digest=DigestSet(root={"sha256": dist.digest}),
                        )
                    ]
                )
                .predicate_type(AttestationType.PYPI_PUBLISH_V1)
                .build()
            )
        except DsseError as e:
            raise AttestationError(str(e))

        try:
            bundle = signer.sign_dsse(stmt)
        except (ExpiredCertificate, ExpiredIdentity) as e:
            raise AttestationError(str(e))

        try:
            return Attestation.from_bundle(bundle)
        except ConversionError as e:
            raise AttestationError(str(e))

    def verify(
        self,
        verifier: Verifier,
        policy: VerificationPolicy,
        dist: Distribution,
    ) -> tuple[str, dict[str, Any] | None]:
        """Verify against an existing Python distribution.

        On failure, raises an appropriate subclass of `AttestationError`.
        """
        bundle = self.to_bundle()
        try:
            type_, payload = verifier.verify_dsse(bundle, policy)
        except sigstore.errors.VerificationError as err:
            raise VerificationError(str(err)) from err

        if type_ != DsseEnvelope._TYPE:  # noqa: SLF001
            raise VerificationError(f"expected JSON envelope, got {type_}")

        try:
            statement = _Statement.model_validate_json(payload)
        except ValidationError as e:
            raise VerificationError(f"invalid statement: {str(e)}")

        if len(statement.subjects) != 1:
            raise VerificationError("too many subjects in statement (must be exactly one)")
        subject = statement.subjects[0]

        if not subject.name:
            raise VerificationError("invalid subject: missing name")

        try:
            # We always ultranormalize when signing, but other signers may not.
            subject_name = _ultranormalize_dist_filename(subject.name)
        except ValueError as e:
            raise VerificationError(f"invalid subject: {str(e)}")

        if subject_name != dist.name:
            raise VerificationError(
                f"subject does not match distribution name: {subject_name} != {dist.name}"
            )

        digest = subject.digest.root.get("sha256")
        if digest is None or digest != dist.digest:
            raise VerificationError("subject does not match distribution digest")

        try:
            AttestationType(statement.predicate_type)
        except ValueError:
            raise VerificationError(f"unknown attestation type: {statement.predicate_type}")

        return statement.predicate_type, statement.predicate

    def to_bundle(self) -> Bundle:
        """Convert a PyPI attestation object as defined in PEP 740 into a Sigstore Bundle."""
        cert_bytes = self.verification_material.certificate
        statement = self.envelope.statement
        signature = self.envelope.signature

        evp = DsseEnvelope(
            _Envelope(
                payload=statement,
                payload_type=DsseEnvelope._TYPE,  # noqa: SLF001
                signatures=[_Signature(sig=signature)],
            )
        )

        tlog_entry = self.verification_material.transparency_entries[0]
        try:
            certificate = x509.load_der_x509_certificate(cert_bytes)
        except ValueError as err:
            raise ConversionError("invalid X.509 certificate") from err

        try:
            log_entry = LogEntry._from_dict_rekor(tlog_entry)  # noqa: SLF001
        except (ValidationError, sigstore.errors.Error) as err:
            raise ConversionError("invalid transparency log entry") from err

        return Bundle._from_parts(  # noqa: SLF001
            cert=certificate,
            content=evp,
            log_entry=log_entry,
        )

    @classmethod
    def from_bundle(cls, sigstore_bundle: Bundle) -> Attestation:
        """Convert a Sigstore Bundle into a PyPI attestation as defined in PEP 740."""
        certificate = sigstore_bundle.signing_certificate.public_bytes(
            encoding=serialization.Encoding.DER
        )

        envelope = sigstore_bundle._inner.dsse_envelope  # noqa: SLF001

        if len(envelope.signatures) != 1:
            raise ConversionError(f"expected exactly one signature, got {len(envelope.signatures)}")

        return cls(
            version=1,
            verification_material=VerificationMaterial(
                certificate=base64.b64encode(certificate),
                transparency_entries=[
                    sigstore_bundle.log_entry._to_rekor().to_dict()  # noqa: SLF001
                ],
            ),
            envelope=Envelope(
                statement=base64.b64encode(envelope.payload),
                signature=base64.b64encode(envelope.signatures[0].sig),
            ),
        )


class Envelope(BaseModel):
    """The attestation envelope, containing the attested-for payload and its signature."""

    statement: Base64Bytes
    """
    The attestation statement.

    This is represented as opaque bytes on the wire (encoded as base64),
    but it MUST be an JSON in-toto v1 Statement.
    """

    signature: Base64Bytes
    """
    A signature for the above statement, encoded as base64.
    """


def _ultranormalize_dist_filename(dist: str) -> str:
    """Return an "ultranormalized" form of the given distribution filename.

    This form is equivalent to the normalized form for sdist and wheel
    filenames, with the additional stipulation that compressed tag sets,
    if present, are also sorted alphanumerically.

    Raises `ValueError` on any invalid distribution filename.
    """
    # NOTE: .whl and .tar.gz are assumed lowercase, since `packaging`
    # already rejects non-lowercase variants.
    if dist.endswith(".whl"):
        # `parse_wheel_filename` raises a supertype of ValueError on failure.
        name, ver, build, tags = parse_wheel_filename(dist)

        # The name has been normalized to replace runs of `[.-_]+` with `-`,
        # which then needs to be replaced with `_` for the wheel.
        name = name.replace("-", "_")

        # `parse_wheel_filename` normalizes the name and version for us,
        # so all we need to do is re-compress the tag set in a canonical
        # order.
        # NOTE(ww): This is written in a not very efficient manner, since
        # I wasn't feeling smart.
        impls, abis, platforms = set(), set(), set()
        for tag in tags:
            impls.add(tag.interpreter)
            abis.add(tag.abi)
            platforms.add(tag.platform)

        impl_tag = ".".join(sorted(impls))
        abi_tag = ".".join(sorted(abis))
        platform_tag = ".".join(sorted(platforms))

        if build:
            parts = "-".join(
                [name, str(ver), f"{build[0]}{build[1]}", impl_tag, abi_tag, platform_tag]
            )
        else:
            parts = "-".join([name, str(ver), impl_tag, abi_tag, platform_tag])

        return f"{parts}.whl"

    elif dist.endswith(".tar.gz"):
        # `parse_sdist_filename` raises a supertype of ValueError on failure.
        name, ver = parse_sdist_filename(dist)
        name = name.replace("-", "_")
        return f"{name}-{ver}.tar.gz"
    else:
        raise ValueError(f"unknown distribution format: {dist}")


class _PublisherBase(BaseModel):
    model_config = ConfigDict(alias_generator=to_snake)

    kind: str
    claims: dict[str, Any] | None = None


class GitHubPublisher(_PublisherBase):
    """A GitHub-based Trusted Publisher."""

    kind: Literal["GitHub"] = "GitHub"

    repository: str
    """
    The fully qualified publishing repository slug, e.g. `foo/bar` for
    repository `bar` owned by `foo`.
    """

    workflow: str
    """
    The filename of the GitHub Actions workflow that performed the publishing
    action.
    """

    environment: str | None = None
    """
    The optional name GitHub Actions environment that the publishing
    action was performed from.
    """


class GitLabPublisher(_PublisherBase):
    """A GitLab-based Trusted Publisher."""

    kind: Literal["GitLab"] = "GitLab"

    repository: str
    """
    The fully qualified publishing repository slug, e.g. `foo/bar` for
    repository `bar` owned by `foo` or `foo/baz/bar` for repository
    `bar` owned by group `foo` and subgroup `baz`.
    """

    environment: str | None = None
    """
    The optional environment that the publishing action was performed from.
    """


Publisher = Annotated[GitHubPublisher | GitLabPublisher, Field(discriminator="kind")]


class AttestationBundle(BaseModel):
    """AttestationBundle object as defined in PEP 740."""

    publisher: Publisher
    """
    The publisher associated with this set of attestations.
    """

    attestations: list[Attestation]
    """
    The list of attestations included in this bundle.
    """


class Provenance(BaseModel):
    """Provenance object as defined in PEP 740."""

    version: Literal[1] = 1
    """
    The provenance object's version, which is always 1.
    """

    attestation_bundles: list[AttestationBundle]
    """
    One or more attestation "bundles".
    """
