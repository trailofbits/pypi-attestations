from __future__ import annotations

import argparse
import json
import logging
import typing
from pathlib import Path

import sigstore.oidc
from cryptography import x509
from pydantic import ValidationError
from sigstore.oidc import IdentityError, IdentityToken, Issuer
from sigstore.sign import SigningContext
from sigstore.verify import policy

from pypi_attestations import Attestation, AttestationError, VerificationError, __version__
from pypi_attestations._impl import Distribution

if typing.TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import NoReturn

logging.basicConfig(format="%(message)s", datefmt="[%X]", handlers=[logging.StreamHandler()])
_logger = logging.getLogger(__name__)
_logger.setLevel(logging.INFO)


def _parser() -> argparse.ArgumentParser:
    parent_parser = argparse.ArgumentParser(add_help=False)

    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Run with additional debug logging; supply multiple times to increase verbosity",
    )

    parser = argparse.ArgumentParser(
        prog="python -m pypi_attestations",
        description="Sign, inspect or verify PEP 740 attestations",
        parents=[parent_parser],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pypi-attestations {__version__}",
    )

    subcommands = parser.add_subparsers(
        required=True,
        dest="subcommand",
        metavar="COMMAND",
        help="The operation to perform",
    )

    sign_command = subcommands.add_parser(
        name="sign", help="Sign one or more inputs", parents=[parent_parser]
    )

    sign_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    sign_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    verify_command = subcommands.add_parser(
        name="verify",
        help="Verify one or more inputs",
        parents=[parent_parser],
    )

    verify_command.add_argument(
        "--identity",
        type=str,
        required=True,
        help="Signer identity",
    )

    verify_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    verify_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    inspect_command = subcommands.add_parser(
        name="inspect",
        help="Inspect one or more inputs",
        parents=[parent_parser],
    )

    inspect_command.add_argument(
        "--dump-bytes",
        action="store_true",
        default=False,
        help="Dump the bytes of the signature",
    )

    inspect_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    return parser


def _die(message: str) -> NoReturn:
    """Handle errors and terminate the program with an error code."""
    _logger.error(message)
    raise SystemExit(1)


def _validate_files(files: Iterable[Path], should_exist: bool = True) -> None:
    """Validate that the list of files exists or not.

    This function exits the program if the condition is not met.
    """
    for file_path in files:
        if file_path.is_file() != should_exist:
            if should_exist:
                _die(f"{file_path} is not a file.")
            else:
                _die(f"{file_path} already exists.")


def get_identity_token(args: argparse.Namespace) -> IdentityToken:
    """Generate an Identity Token.

    This method uses the following order of precedence:
    - An ambient credential
    - An OAuth-2 flow
    """
    # Ambient credential detection
    oidc_token = sigstore.oidc.detect_credential()
    if oidc_token is not None:
        return IdentityToken(oidc_token)

    # Fallback to interactive OAuth-2 Flow
    issuer: Issuer = Issuer.staging() if args.staging else Issuer.production()
    return issuer.identity_token()


def _sign(args: argparse.Namespace) -> None:
    """Sign the files passed as argument."""
    try:
        identity = get_identity_token(args)
    except IdentityError as identity_error:
        _die(f"Failed to detect identity: {identity_error}")

    signing_ctx = SigningContext.staging() if args.staging else SigningContext.production()

    # Validates that every file we want to sign exist but none of their attestations
    _validate_files(args.files, should_exist=True)
    _validate_files(
        (Path(f"{file_path}.publish.attestation") for file_path in args.files),
        should_exist=False,
    )

    with signing_ctx.signer(identity, cache=True) as signer:
        for file_path in args.files:
            _logger.debug(f"Signing {file_path}")

            try:
                dist = Distribution.from_file(file_path)
            except ValidationError as e:
                _die(f"Invalid Python package distribution: {e}")

            try:
                attestation = Attestation.sign(signer, dist)
            except AttestationError as e:
                _die(f"Failed to sign: {e}")

            signature_path = Path(f"{file_path}.publish.attestation")
            signature_path.write_text(attestation.model_dump_json())
            _logger.debug("Attestation for %s saved in %s", file_path, signature_path)


def _inspect(args: argparse.Namespace) -> None:
    """Inspect attestations.

    Warning: The information displayed from the attestations are not verified.
    """
    _validate_files(args.files, should_exist=True)
    for file_path in args.files:
        try:
            attestation = Attestation.model_validate_json(file_path.read_text())
        except ValidationError as validation_error:
            _die(f"Invalid attestation ({file_path}): {validation_error}")

        _logger.info(
            "Warning: The information displayed below are not verified, they are only "
            "displayed. Use the verify command to verify them."
        )

        _logger.info(f"File: {file_path}")
        _logger.info(f"Version: {attestation.version}")

        decoded_statement = json.loads(attestation.envelope.statement.decode())

        _logger.info("Statement:")
        _logger.info(f"\tType: {decoded_statement['_type']}")
        _logger.info("\tSubject:")
        for subject in decoded_statement["subject"]:
            _logger.info(f"\t\t{subject['name']} (digest: {subject['digest']['sha256']})")

        _logger.info(f"\tPredicate type: {decoded_statement['predicateType']}")
        _logger.info(f"\tPredicate: {decoded_statement['predicate']}")

        if args.dump_bytes:
            _logger.info(f"Signature: {attestation.envelope.signature!r}")

        # Verification Material
        verification_material = attestation.verification_material

        # Certificate
        certificate = x509.load_der_x509_certificate(verification_material.certificate)
        _logger.info("Certificate:")
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        _logger.info(
            f"\tSubjects (suitable for `--identity`): {[name.value for name in san.value]}"
        )
        _logger.info(f"\tIssuer: {certificate.issuer.rfc4514_string()}")
        _logger.info(f"\tValidity: {certificate.not_valid_after_utc}")

        # Transparency Log
        _logger.info(
            f"Transparency Log ({len(verification_material.transparency_entries)} entries):"
        )
        for idx, entry in enumerate(verification_material.transparency_entries):
            _logger.info(f"\tLog Index: {entry['logIndex']}")


def _verify(args: argparse.Namespace) -> None:
    """Verify the files passed as argument."""
    pol = policy.Identity(identity=args.identity)

    # Validate that both the attestations and files exists
    _validate_files(args.files, should_exist=True)
    _validate_files(
        (Path(f"{file_path}.publish.attestation") for file_path in args.files),
        should_exist=True,
    )

    inputs: list[Path] = []
    for file_path in args.files:
        # Collect only the inputs themselves, not their attestations.
        # Attestation paths are inferred subsequently.
        if file_path.name.endswith(".publish.attestation"):
            _logger.warning(f"skipping attestation path while collecting file inputs: {file_path}")
            continue
        inputs.append(file_path)

    if not inputs:
        _die("No inputs given; make sure you passed distributions and not attestations as inputs")

    for input in inputs:
        attestation_path = Path(f"{input}.publish.attestation")
        try:
            attestation = Attestation.model_validate_json(attestation_path.read_text())
        except ValidationError as validation_error:
            _die(f"Invalid attestation ({attestation_path}): {validation_error}")

        try:
            dist = Distribution.from_file(input)
        except ValidationError as e:
            _die(f"Invalid Python package distribution: {e}")

        try:
            attestation.verify(pol, dist, staging=args.staging)
        except VerificationError as verification_error:
            _die(f"Verification failed for {input}: {verification_error}")

        _logger.info(f"OK: {attestation_path}")


def main() -> None:
    parser = _parser()
    args: argparse.Namespace = parser.parse_args()

    if args.verbose >= 1:
        _logger.setLevel("DEBUG")
    if args.verbose >= 2:
        logging.getLogger().setLevel("DEBUG")

    _logger.debug(args)

    args._parser = parser  # noqa: SLF001.

    if args.subcommand == "sign":
        _sign(args)
    elif args.subcommand == "verify":
        _verify(args)
    elif args.subcommand == "inspect":
        _inspect(args)
