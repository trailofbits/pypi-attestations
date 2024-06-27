"""Internal implementation module for `pypi-attestations`.

This module is NOT a public API, and is not considered stable.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Annotated, Any, Literal, NewType

import sigstore.errors
from annotated_types import MinLen  # noqa: TCH002
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from packaging.utils import parse_sdist_filename, parse_wheel_filename
from pydantic import Base64Bytes, BaseModel
from pydantic_core import ValidationError
from sigstore._utils import _sha256_streaming
from sigstore.dsse import Envelope as DsseEnvelope
from sigstore.dsse import _DigestSet, _Statement, _StatementBuilder, _Subject
from sigstore.models import Bundle, LogEntry
from sigstore_protobuf_specs.io.intoto import Envelope as _Envelope
from sigstore_protobuf_specs.io.intoto import Signature as _Signature

if TYPE_CHECKING:
    from pathlib import Path  # pragma: no cover

    from sigstore.sign import Signer  # pragma: no cover
    from sigstore.verify import Verifier  # pragma: no cover
    from sigstore.verify.policy import VerificationPolicy  # pragma: no cover


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
    def sign(cls, signer: Signer, dist: Path) -> Attestation:
        """Create an envelope, with signature, from a distribution file.

        On failure, raises `AttestationError` or an appropriate subclass.
        """
        with dist.open(mode="rb", buffering=0) as io:
            # Replace this with `hashlib.file_digest()` once
            # our minimum supported Python is >=3.11
            digest = _sha256_streaming(io).hex()

        try:
            name = _ultranormalize_dist_filename(dist.name)
        except ValueError as e:
            raise AttestationError(str(e))

        stmt = (
            _StatementBuilder()
            .subjects(
                [
                    _Subject(
                        name=name,
                        digest=_DigestSet(root={"sha256": digest}),
                    )
                ]
            )
            .predicate_type("https://docs.pypi.org/attestations/publish/v1")
            .build()
        )
        bundle = signer.sign_dsse(stmt)

        return Attestation.from_bundle(bundle)

    def verify(
        self, verifier: Verifier, policy: VerificationPolicy, dist: Path
    ) -> tuple[str, dict[str, Any] | None]:
        """Verify against an existing Python artifact.

        Returns a tuple of the in-toto predicate type and optional deserialized JSON predicate.

        On failure, raises an appropriate subclass of `AttestationError`.
        """
        with dist.open(mode="rb", buffering=0) as io:
            # Replace this with `hashlib.file_digest()` once
            # our minimum supported Python is >=3.11
            expected_digest = _sha256_streaming(io).hex()

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

        normalized = _ultranormalize_dist_filename(dist.name)
        if subject_name != normalized:
            raise VerificationError(
                f"subject does not match distribution name: {subject_name} != {normalized}"
            )

        digest = subject.digest.root.get("sha256")
        if digest is None or digest != expected_digest:
            raise VerificationError("subject does not match distribution digest")

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
                    TransparencyLogEntry(sigstore_bundle.log_entry._to_dict_rekor())  # noqa: SLF001
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
