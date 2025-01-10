"""Implementation of the CLI for pypi-attestations."""

from __future__ import annotations

import argparse
import json
import logging
import typing
from pathlib import Path
from tempfile import TemporaryDirectory

import requests
import sigstore.oidc
from cryptography import x509
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from pydantic import ValidationError
from rfc3986 import exceptions, uri_reference, validators
from sigstore.oidc import IdentityError, IdentityToken, Issuer
from sigstore.sign import SigningContext
from sigstore.verify import policy

from pypi_attestations import Attestation, AttestationError, VerificationError, __version__
from pypi_attestations._impl import (
    Distribution,
    GitHubPublisher,
    Provenance,
    Publisher,
)

if typing.TYPE_CHECKING:  # pragma: no cover
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
        prog="pypi-attestations",
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

    verify_subcommands = verify_command.add_subparsers(
        required=True,
        dest="verification_type",
        metavar="VERIFICATION_TYPE",
        help="The type of verification",
    )
    verify_attestation_command = verify_subcommands.add_parser(
        name="attestation", help="Verify a PEP-740 attestation"
    )

    verify_attestation_command.add_argument(
        "--identity",
        type=str,
        required=True,
        help="Signer identity",
    )

    verify_attestation_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    verify_attestation_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    verify_pypi_command = verify_subcommands.add_parser(name="pypi", help="Verify a PyPI release")

    verify_pypi_command.add_argument(
        "distribution_url",
        metavar="URL_PYPI_FILE",
        type=str,
        help='URL of the PyPI file to verify, i.e: "https://files.pythonhosted.org/..."',
    )

    verify_pypi_command.add_argument(
        "--repository",
        type=str,
        required=True,
        help="URL of the publishing GitHub or GitLab repository",
    )

    verify_pypi_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
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


def _download_file(url: str, dest: Path) -> None:
    """Download a file into a given path."""
    response = requests.get(url, stream=True)
    try:
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.HTTPError as e:
        _die(f"Error downloading file: {e}")

    with open(dest, "wb") as f:
        try:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
        except requests.RequestException as e:
            _die(f"Error downloading file: {e}")


def _get_provenance_from_pypi(filename: str) -> Provenance:
    """Use PyPI's integrity API to get a distribution's provenance."""
    try:
        if filename.endswith(".tar.gz") or filename.endswith(".zip"):
            name, version = parse_sdist_filename(filename)
        elif filename.endswith(".whl"):
            name, version, _, _ = parse_wheel_filename(filename)
        else:
            _die("URL should point to a wheel (*.whl) or a source distribution (*.zip or *.tar.gz)")
    except (InvalidSdistFilename, InvalidWheelFilename) as e:
        _die(f"Invalid distribution filename: {e}")

    provenance_url = f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance"
    response = requests.get(provenance_url)
    if response.status_code == 403:
        _die("Access to provenance is temporarily disabled by PyPI administrators")
    elif response.status_code == 404:
        _die(f'Provenance for file "{filename}" was not found')
    elif response.status_code != 200:
        _die(
            f"Unexpected error while downloading provenance file from PyPI, Integrity API "
            f"returned status code: {response.status_code}"
        )

    try:
        return Provenance.model_validate_json(response.text)
    except ValidationError as validation_error:
        _die(f"Invalid provenance: {validation_error}")


def _check_repository_identity(expected_repository_url: str, publisher: Publisher) -> None:
    """Check that a repository url matches the given publisher's identity."""
    validator = (
        validators.Validator()
        .allow_schemes("https")
        .allow_hosts("github.com", "gitlab.com")
        .require_presence_of("scheme", "host")
    )
    try:
        expected_uri = uri_reference(expected_repository_url)
        validator.validate(expected_uri)
    except exceptions.RFC3986Exception as e:
        _die(f"Unsupported/invalid URL: {e}")

    actual_host = "github.com" if isinstance(publisher, GitHubPublisher) else "gitlab.com"
    expected_host = expected_uri.host
    if actual_host != expected_host:
        _die(
            f"Verification failed: provenance was signed by a {actual_host} repository, but "
            f"expected a {expected_host} repository"
        )

    actual_repository = publisher.repository
    # '/owner/repo' -> 'owner/repo'
    expected_repository = expected_uri.path.lstrip("/")
    if actual_repository != expected_repository:
        _die(
            f'Verification failed: provenance was signed by repository "{actual_repository}", '
            f'expected "{expected_repository}"'
        )


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


def _verify_attestation(args: argparse.Namespace) -> None:
    """Verify the files passed as argument."""
    pol = policy.Identity(identity=args.identity)

    # Validate that both the attestations and files exist
    _validate_files(args.files, should_exist=True)
    _validate_files(
        (Path(f"{file_path}.publish.attestation") for file_path in args.files),
        should_exist=True,
    )

    inputs: list[Path] = []
    for file_path in args.files:
        inputs.append(file_path)

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


def _verify_pypi(args: argparse.Namespace) -> None:
    """Verify a distribution hosted on PyPI.

    The distribution is downloaded and verified. The verification is against
    the provenance file hosted on PyPI (if any), and against the repository URL
    passed by the user as a CLI argument.
    """
    validator = (
        validators.Validator()
        .allow_schemes("https")
        .allow_hosts("files.pythonhosted.org")
        .require_presence_of("scheme", "host")
    )
    try:
        pypi_url = uri_reference(args.distribution_url)
        validator.validate(pypi_url)
    except exceptions.RFC3986Exception as e:
        _die(f"Unsupported/invalid URL: {e}")

    with TemporaryDirectory() as temp_dir:
        dist_filename = pypi_url.path.split("/")[-1]
        dist_path = Path(temp_dir) / dist_filename
        _download_file(url=pypi_url.unsplit(), dest=dist_path)
        provenance = _get_provenance_from_pypi(dist_filename)
        dist = Distribution.from_file(dist_path)
        try:
            for attestation_bundle in provenance.attestation_bundles:
                publisher = attestation_bundle.publisher
                _check_repository_identity(
                    expected_repository_url=args.repository, publisher=publisher
                )
                policy = publisher._as_policy()  # noqa: SLF001.
                for attestation in attestation_bundle.attestations:
                    attestation.verify(policy, dist, staging=args.staging)
        except VerificationError as verification_error:
            _die(f"Verification failed for {dist_filename}: {verification_error}")

    _logger.info(f"OK: {dist_filename}")


def main() -> None:
    """Dispatch the CLI subcommand."""
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
        if args.verification_type == "attestation":
            _verify_attestation(args)
        elif args.verification_type == "pypi":
            _verify_pypi(args)
    elif args.subcommand == "inspect":
        _inspect(args)
