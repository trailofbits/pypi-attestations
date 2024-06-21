from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import NoReturn

from cryptography import x509
from pydantic import ValidationError
from sigstore.oidc import IdentityError, IdentityToken, Issuer, detect_credential
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

from pypi_attestation_models import __version__
from pypi_attestation_models._impl import Attestation, VerificationError

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
        help="run with additional debug logging; supply multiple times to increase verbosity",
    )

    parser = argparse.ArgumentParser(
        prog="pypi-attestation-models",
        description="TODO",
        parents=[parent_parser],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pypi-attestation-models {__version__}",
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
        "--identity-token",
        type=str,
        help="Identity token to use",
        required=False,
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
        help="TODO",
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


def _die(args: argparse.Namespace, message: str) -> NoReturn:
    """Handle argument parsing errors and terminate the program.

    Fix up the type hints on our use of `ArgumentParser.error`.
    """
    args._parser.error(message)  # noqa: SLF001.
    raise ValueError("unreachable")


def get_identity_token(args: argparse.Namespace) -> IdentityToken:
    """Generate an Identity Token.

    This method uses the following order of precedence:
    - A token passed as an argument
    - An ambient credential
    - An OAuth-2 flow
    """
    # First, check if a token was supplied
    if args.identity_token:
        return IdentityToken(args.identity_token)

    # Ambient credential detection
    oidc_token = detect_credential()
    if oidc_token is not None:
        return IdentityToken(oidc_token)

    # Finally, OAuth-2 Flow
    if args.staging:
        issuer = Issuer.staging()
    else:
        issuer = Issuer.production()

    return issuer.identity_token()


def _sign(args: argparse.Namespace) -> None:
    """Sign the files passed as argument."""
    try:
        identity = get_identity_token(args)
    except IdentityError as identity_error:
        _die(args, f"Failed to detect identity: {identity_error}")

    if args.staging:
        signing_ctx = SigningContext.staging()
    else:
        signing_ctx = SigningContext.production()

    with signing_ctx.signer(identity, cache=True) as signer:
        for file_path in args.files:
            _logger.debug(f"Signing {file_path}")

            if not file_path.is_file():
                _die(args, f"{file_path} is not a file.")

            signature_path = Path(f"{file_path}.publish.attestation")
            if signature_path.is_file():
                _die(args, f"Signature already exists for {file_path}")

            attestation = Attestation.sign(signer, file_path)
            _logger.debug("Attestation saved for %s saved in %s", file_path, signature_path)

            signature_path.write_text(attestation.model_dump_json())


def _inspect(args: argparse.Namespace) -> None:
    """Inspect attestations.

    Warning: The information displayed from the attestations are not verified.
    """
    for file_path in args.files:
        if not file_path.is_file():
            _die(args, f"{file_path} is not a file.")

        try:
            attestation = Attestation.model_validate_json(file_path.read_text())
        except ValidationError as validation_error:
            _die(args, f"Invalid attestation ({file_path}): {validation_error}")

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
            _logger.info(f"Signature: {attestation.envelope.signature}")

        # Verification Material
        verification_material = attestation.verification_material

        # Certificate
        certificate = x509.load_der_x509_certificate(verification_material.certificate)
        _logger.info("Certificate:")
        _logger.info(f"\tSubject: {certificate.subject.rfc4514_string()}")
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
    if args.staging:
        verifier = Verifier.staging()
    else:
        verifier = Verifier.production()

    pol = policy.Identity(identity=args.identity)

    for file_path in args.files:
        if not file_path.is_file():
            _die(args, f"{file_path} is not a file.")

        attestation_path = Path(f"{file_path}.publish.attestation")
        if not attestation_path.is_file():
            _die(args, f"Missing attestation file for {file_path}")

        try:
            attestation = Attestation.model_validate_json(attestation_path.read_text())
        except ValidationError as validation_error:
            _die(args, f"Invalid attestation ({file_path}): {validation_error}")

        try:
            attestation.verify(verifier, pol, file_path)
        except VerificationError as verification_error:
            _logger.error("Verification failed for %s: %s", file_path, verification_error)
            continue

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
    else:
        _die(args, f"Unknown subcommand: {args.subcommand}")
