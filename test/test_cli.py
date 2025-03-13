from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
import requests
import sigstore.oidc
from pretend import raiser, stub
from sigstore.oidc import IdentityError

import pypi_attestations._cli
from pypi_attestations._cli import (
    _logger,
    _validate_files,
    get_identity_token,
    main,
)
from pypi_attestations._impl import Attestation, AttestationError, ConversionError, Distribution

ONLINE_TESTS = (
    "CI" in os.environ or "TEST_INTERACTIVE" in os.environ
) and "TEST_OFFLINE" not in os.environ

online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

artifact_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz"
publish_attestation_identity = "https://github.com/trailofbits/pypi-attestations/.github/workflows/release.yml@refs/tags/v0.0.19"
publish_attestation_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz.publish.attestation"
slsa_attestation_path = _ASSETS / "pypi_attestations-0.0.19.tar.gz.slsa.attestation"

pypi_wheel_url = "https://files.pythonhosted.org/packages/fb/f2/3e026065773b84c5b2345e2548a08b10105d324b9b95c72643f57a25fcbb/pypi_attestations-0.0.19-py3-none-any.whl"
pypi_sdist_url = "https://files.pythonhosted.org/packages/c5/4d/a114bdd186903426bd9c1e9c3700761ec5eaac260fa3dfdef14bf84b751b/pypi_attestations-0.0.19.tar.gz"
pypi_wheel_filename = pypi_wheel_url.split("/")[-1]
pypi_sdist_filename = pypi_sdist_url.split("/")[-1]
pypi_wheel_abbrev = f"pypi-attestations/{pypi_wheel_filename}"
pypi_sdist_abbrev = f"pypi-attestations/{pypi_sdist_filename}"
pypi_sdist_path = _ASSETS / pypi_sdist_filename
pypi_sdist_provenance_path = _ASSETS / f"{pypi_sdist_filename}.provenance"

sigstore_bundle_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz.sigstore"
converted_sigstore_bundle_path = _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz.attestation"


def run_main_with_command(cmd: list[str]) -> None:
    """Helper method to run the main function with a given command."""
    sys.argv[1:] = cmd
    main()


def test_main_verbose_level(monkeypatch: pytest.MonkeyPatch) -> None:
    def default_sign(_: argparse.Namespace) -> None:
        return

    monkeypatch.setattr(pypi_attestations._cli, "_sign", default_sign)

    run_main_with_command(["sign", "-v", ""])
    assert _logger.level == logging.DEBUG

    run_main_with_command(["sign", "-v", "-v", ""])
    assert logging.getLogger().level == logging.DEBUG

    with pytest.raises(SystemExit) as exc_info:
        run_main_with_command(["not-a-command"])

    assert exc_info.value.code == 2


@online
def test_get_identity_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Happy paths
    identity_token = get_identity_token(argparse.Namespace(staging=True))
    assert identity_token.in_validity_period()

    # Failure path
    def return_invalid_token() -> str:
        return "invalid-token"

    monkeypatch.setattr(sigstore.oidc, "detect_credential", return_invalid_token)

    # Invalid token
    with pytest.raises(IdentityError, match="Identity token is malformed"):
        get_identity_token(argparse.Namespace(staging=True))


@online
def test_sign_command(tmp_path: Path) -> None:
    # Happy path
    copied_artifact = tmp_path / artifact_path.name
    shutil.copy(artifact_path, copied_artifact)

    run_main_with_command(
        [
            "sign",
            "--staging",
            copied_artifact.as_posix(),
        ]
    )
    copied_artifact_attestation = Path(f"{copied_artifact}.publish.attestation")
    assert copied_artifact_attestation.is_file()

    attestation = Attestation.model_validate_json(copied_artifact_attestation.read_bytes())
    assert attestation.version


@online
def test_sign_missing_file(caplog: pytest.LogCaptureFixture) -> None:
    # Missing file
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "sign",
                "--staging",
                "not_exist.txt",
            ]
        )

    assert "not_exist.txt is not a file" in caplog.text


@online
def test_sign_signature_already_exists(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    artifact = tmp_path / artifact_path.with_suffix(".copy2.whl").name
    artifact.touch(exist_ok=False)

    artifact_attestation = Path(f"{artifact}.publish.attestation")
    artifact_attestation.touch(exist_ok=False)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "sign",
                "--staging",
                artifact.as_posix(),
            ]
        )

    assert "already exists" in caplog.text
    caplog.clear()


@online
def test_sign_invalid_token(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def return_invalid_token() -> str:
        return "invalid-token"

    monkeypatch.setattr(sigstore.oidc, "detect_credential", return_invalid_token)

    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "sign",
                "--staging",
                artifact_path.as_posix(),
            ]
        )

    assert "Failed to detect identity" in caplog.text


@online
def test_sign_invalid_artifact(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    artifact = tmp_path / "pkg-1.0.0.exe"
    artifact.touch(exist_ok=False)

    with pytest.raises(SystemExit):
        run_main_with_command(["sign", "--staging", artifact.as_posix()])

    assert "Invalid Python package distribution" in caplog.text


@online
def test_sign_fail_to_sign(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    monkeypatch.setattr(pypi_attestations._cli, "Attestation", stub(sign=raiser(AttestationError)))
    copied_artifact = tmp_path / artifact_path.name
    shutil.copy(artifact_path, copied_artifact)

    with pytest.raises(SystemExit):
        run_main_with_command(["sign", "--staging", copied_artifact.as_posix()])

    assert "Failed to sign:" in caplog.text


def test_inspect_command(caplog: pytest.LogCaptureFixture) -> None:
    # Happy path
    run_main_with_command(["inspect", publish_attestation_path.as_posix()])
    assert publish_attestation_path.as_posix() in caplog.text
    assert "CN=sigstore-intermediate,O=sigstore.dev" in caplog.text

    run_main_with_command(["inspect", "--dump-bytes", publish_attestation_path.as_posix()])
    assert "Signature:" in caplog.text

    # Failure paths
    caplog.clear()

    # Failure because not an attestation
    with tempfile.NamedTemporaryFile(suffix=".publish.attestation") as f:
        f.write(b"not an attestation")
        f.flush()

        with pytest.raises(SystemExit):
            run_main_with_command(["inspect", f.name])

        assert "Invalid attestation" in caplog.text


def test_verify_attestation_command(caplog: pytest.LogCaptureFixture) -> None:
    # Happy path
    run_main_with_command(
        [
            "verify",
            "attestation",
            "--offline",
            "--identity",
            publish_attestation_identity,
            artifact_path.as_posix(),
        ]
    )
    assert f"OK: {publish_attestation_path.as_posix()}" in caplog.text
    assert f"OK: {slsa_attestation_path.as_posix()}" in caplog.text

    caplog.clear()

    with pytest.raises(SystemExit):
        # Failure from the Sigstore environment
        run_main_with_command(
            [
                "verify",
                "attestation",
                "--staging",
                "--offline",
                "--identity",
                publish_attestation_identity,
                artifact_path.as_posix(),
            ]
        )
    assert (
        "Verification failed: failed to build chain: unable to get local issuer certificate"
        in caplog.text
    )
    assert "OK:" not in caplog.text


def test_verify_attestation_invalid_attestation(caplog: pytest.LogCaptureFixture) -> None:
    # Failure because not an attestation
    with pytest.raises(SystemExit):
        with tempfile.NamedTemporaryFile(suffix=".publish.attestation") as f:
            fake_package_name = Path(f.name.removesuffix(".publish.attestation"))
            fake_package_name.touch()

            run_main_with_command(
                [
                    "verify",
                    "attestation",
                    "--offline",
                    "--identity",
                    publish_attestation_identity,
                    fake_package_name.as_posix(),
                ]
            )
    assert "Invalid attestation" in caplog.text


def test_verify_attestation_missing_artifact(caplog: pytest.LogCaptureFixture) -> None:
    # Failure because missing package file
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "attestation",
                "--offline",
                "--identity",
                publish_attestation_identity,
                "not_a_file.txt",
            ]
        )

    assert "not_a_file.txt is not a file." in caplog.text


def test_verify_attestation_missing_attestation(caplog: pytest.LogCaptureFixture) -> None:
    # Failure because missing attestation file
    with pytest.raises(SystemExit):
        with tempfile.NamedTemporaryFile() as f:
            run_main_with_command(
                [
                    "verify",
                    "attestation",
                    "--offline",
                    "--identity",
                    publish_attestation_identity,
                    f.name,
                ]
            )

    assert f"Couldn't find attestations for file {f.name}" in caplog.text


def test_verify_attestation_invalid_artifact(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    copied_artifact = tmp_path / artifact_path.with_suffix(".whl2").name
    shutil.copy(artifact_path, copied_artifact)
    copied_attestation = tmp_path / artifact_path.with_suffix(".whl2.publish.attestation").name
    shutil.copy(publish_attestation_path, copied_attestation)

    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "attestation",
                "--offline",
                "--identity",
                publish_attestation_identity,
                copied_artifact.as_posix(),
            ]
        )
    assert "Invalid Python package distribution" in caplog.text


def test_get_identity_token_oauth_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    # If no ambient credential is available, default to the OAuth2 flow
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: None)
    identity_token = stub()

    class MockIssuer:
        @staticmethod
        def staging() -> stub:
            return stub(identity_token=lambda: identity_token)

    monkeypatch.setattr(pypi_attestations._cli, "Issuer", MockIssuer)

    assert pypi_attestations._cli.get_identity_token(stub(staging=True)) == identity_token


def test_validate_files(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # Happy path
    file_1_exist = tmp_path / "file1"
    file_1_exist.touch()

    file_2_exist = tmp_path / "file2"
    file_2_exist.touch()

    _validate_files([file_1_exist, file_2_exist], should_exist=True)
    assert True  # No exception raised

    file_1_missing = tmp_path / "file3"
    file_2_missing = tmp_path / "file4"
    _validate_files([file_1_missing, file_2_missing], should_exist=False)
    assert True

    # Failure paths
    with pytest.raises(SystemExit):
        _validate_files([file_1_missing, file_2_exist], should_exist=True)

    assert f"{file_1_missing} is not a file." in caplog.text

    caplog.clear()
    with pytest.raises(SystemExit):
        _validate_files([file_1_missing, file_2_exist], should_exist=False)

    assert f"{file_2_exist} already exists." in caplog.text


@online
@pytest.mark.parametrize(
    "url_argument, filename",
    [
        (pypi_wheel_url, pypi_wheel_filename),
        (pypi_sdist_url, pypi_sdist_filename),
        (f"pypi:{pypi_wheel_filename}", pypi_wheel_filename),
        (f"pypi:{pypi_sdist_filename}", pypi_sdist_filename),
    ],
)
def test_verify_pypi_command(
    caplog: pytest.LogCaptureFixture, url_argument: str, filename: str
) -> None:
    # Happy path
    run_main_with_command(
        [
            "verify",
            "pypi",
            "--repository",
            "https://github.com/trailofbits/pypi-attestations",
            url_argument,
        ]
    )
    assert f"OK: {filename}" in caplog.text


def test_verify_pypi_command_with_local_files(caplog: pytest.LogCaptureFixture) -> None:
    run_main_with_command(
        [
            "verify",
            "pypi",
            "--offline",
            "--repository",
            "https://github.com/trailofbits/pypi-attestations",
            "--provenance-file",
            pypi_sdist_provenance_path.as_posix(),
            pypi_sdist_path.as_posix(),
        ]
    )
    assert f"OK: {pypi_sdist_filename}" in caplog.text


def test_verify_pypi_command_offline_without_local_dist(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--offline",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "--provenance-file",
                pypi_sdist_provenance_path.as_posix(),
                pypi_sdist_url,
            ]
        )
    assert "The '--offline' option can only be used with local files" in caplog.text


def test_verify_pypi_command_offline_without_local_provenance(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--offline",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_sdist_path.as_posix(),
            ]
        )
    assert "The '--offline' option can only be used with local files" in caplog.text


@online
def test_verify_pypi_command_env_fail(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        # Failure from the Sigstore environment
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--staging",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url,
            ]
        )
    assert (
        "Verification failed: failed to build chain: unable to get local issuer certificate"
        in caplog.text
    )
    assert "OK:" not in caplog.text


@online
def test_verify_pypi_command_failure_download(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Failure because URL does not exist
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url + "invalid",
            ]
        )
    assert "Error downloading file: 404 Client Error" in caplog.text

    caplog.clear()

    # Download fails
    response = stub(
        raise_for_status=lambda: None, iter_content=raiser(requests.RequestException("myerror"))
    )
    monkeypatch.setattr(requests, "get", lambda url, stream: response)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url,
            ]
        )
    assert "Error downloading file: myerror" in caplog.text


def test_verify_pypi_invalid_url(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Failure because file is not hosted on PyPI
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "https://example.com/mypkg-1.2.0.tar.gz",
            ]
        )
    assert "Unsupported/invalid URL" in caplog.text


def test_verify_pypi_invalid_sdist_filename_pypi(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Failure because file is neither a wheer nor a sdist
    monkeypatch.setattr(pypi_attestations._cli, "_download_file", lambda url, dest: None)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                f"pypi:{pypi_wheel_filename}.invalid_ext",
            ]
        )
    assert (
        "File should be a wheel (*.whl) or a source distribution (*.zip or *.tar.gz)" in caplog.text
    )

    caplog.clear()

    """Test that invalid sdist filenames are properly handled."""
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "pypi:invalid-sdist-name.tar.gz",  # Invalid sdist filename format
            ]
        )
    assert "Invalid distribution filename:" in caplog.text


@online
def test_verify_pypi_validation_fails(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Replace the actual wheel with another file
    def _download_file(url: str, dest: Path) -> None:
        with open(dest, "w", encoding="utf-8") as f:
            f.write("random wheel file")

    monkeypatch.setattr(pypi_attestations._cli, "_download_file", _download_file)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url,
            ]
        )
    assert f"Verification failed for {pypi_wheel_filename}" in caplog.text


@pytest.mark.parametrize(
    "status_code,expected_error",
    [
        (403, "Access to provenance is temporarily disabled by PyPI administrators"),
        (404, f'Provenance for file "{pypi_wheel_filename}" was not found'),
        (
            500,
            "Unexpected error while downloading provenance file from PyPI, Integrity API "
            "returned status code: 500",
        ),
    ],
)
def test_verify_pypi_error_getting_provenance(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_error: str,
) -> None:
    # Failure to get provenance from PyPI
    monkeypatch.setattr(
        pypi_attestations._cli,
        "_get_distribution_from_arg",
        lambda arg, offline: Distribution(name=pypi_wheel_filename, digest="a"),
    )
    response = requests.Response()
    response.status_code = status_code
    monkeypatch.setattr(requests, "get", lambda url: response)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url,
            ]
        )
    assert expected_error in caplog.text


def test_verify_pypi_error_finding_package_info(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = stub(raise_for_status=raiser(requests.HTTPError("myerror")))
    monkeypatch.setattr(requests, "get", lambda url, headers: response)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "pypi:somefile-1.0.0.tar.gz",
            ]
        )
    assert "Error trying to get information for 'somefile' from PyPI: myerror" in caplog.text


def test_verify_pypi_error_finding_artifact_url(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = stub(raise_for_status=lambda: None, json=lambda: {"files": []})
    monkeypatch.setattr(requests, "get", lambda url, headers: response)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "pypi:somefile-1.0.0.tar.gz",
            ]
        )
    assert "Could not find the artifact 'somefile-1.0.0.tar.gz' on PyPI" in caplog.text


def test_verify_pypi_error_validating_provenance(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Failure to validate provenance JSON
    monkeypatch.setattr(
        pypi_attestations._cli,
        "_get_distribution_from_arg",
        lambda arg, offline: Distribution(name=pypi_wheel_filename, digest="a"),
    )
    response = stub(status_code=200, raise_for_status=lambda: None, text="not json")
    response.status_code = 200
    monkeypatch.setattr(requests, "get", lambda url: response)
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                pypi_wheel_url,
            ]
        )
    assert "Invalid provenance: 1 validation error for Provenance" in caplog.text

    caplog.clear()


@online
@pytest.mark.parametrize(
    "repository,expected_error",
    [
        (
            "https://gitlab.com/trailofbits/pypi-attestations",
            "Verification failed: provenance was signed by a github.com repository, but expected "
            "a gitlab.com repository",
        ),
        (
            "https://github.com/other/repo",
            "Verification failed: provenance was signed by repository "
            '"trailofbits/pypi-attestations", expected "other/repo"',
        ),
    ],
)
def test_verify_pypi_command_publisher_doesnt_match_user_repository(
    caplog: pytest.LogCaptureFixture,
    repository: str,
    expected_error: str,
) -> None:
    # Failure because URL does not exist
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                repository,
                pypi_wheel_url,
            ]
        )

    assert expected_error in caplog.text


@online
@pytest.mark.parametrize(
    "repository,expected_error",
    [
        # Only github.com or gitlab.com allowed
        ("https://example.com/trailofbits/pypi-attestations", "Unsupported/invalid URL"),
        # Only HTTPS allowed
        ("http://github.com/other/repo", "Unsupported/invalid URL"),
    ],
)
def test_verify_pypi_command_invalid_repository_argument(
    caplog: pytest.LogCaptureFixture,
    repository: str,
    expected_error: str,
) -> None:
    # Failure because URL does not exist
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--repository",
                repository,
                pypi_wheel_url,
            ]
        )

    assert expected_error in caplog.text


def test_verify_pypi_command_local_nonexistent_artifact(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--offline",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "--provenance-file",
                pypi_sdist_provenance_path.as_posix(),
                "nonexistent-artifact.whl",
            ]
        )
    assert "File does not exist: nonexistent-artifact.whl" in caplog.text


def test_verify_pypi_command_local_nonexistent_provenance(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "pypi",
                "--offline",
                "--repository",
                "https://github.com/trailofbits/pypi-attestations",
                "--provenance-file",
                "nonexistent-provenance.json",
                pypi_sdist_path.as_posix(),
            ]
        )
    assert "Provenance file does not exist: nonexistent-provenance.json" in caplog.text


def test_verify_pypi_command_local_invalid_provenance(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        pypi_attestations._cli,
        "_get_distribution_from_arg",
        lambda arg, offline: Distribution(name=pypi_sdist_filename, digest="a"),
    )

    with tempfile.NamedTemporaryFile(suffix=".provenance") as f:
        f.write(b"not a valid provenance")
        f.flush()
        with pytest.raises(SystemExit):
            run_main_with_command(
                [
                    "verify",
                    "pypi",
                    "--offline",
                    "--repository",
                    "https://github.com/trailofbits/pypi-attestations",
                    "--provenance-file",
                    f.name,
                    pypi_sdist_path.as_posix(),
                ]
            )

    assert "Invalid provenance" in caplog.text


def test_convert_command(caplog: pytest.LogCaptureFixture) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        output_attestation_path = Path(tmpdir) / "temp.attestation"
        run_main_with_command(
            [
                "convert",
                "--output-file",
                output_attestation_path.as_posix(),
                sigstore_bundle_path.as_posix(),
            ]
        )
        assert output_attestation_path.is_file()
        converted_attestation = Attestation.model_validate_json(
            output_attestation_path.read_bytes()
        )
        known_good_attestation = Attestation.model_validate_json(
            converted_sigstore_bundle_path.read_bytes()
        )

        assert converted_attestation.version == 1
        assert (
            converted_attestation.verification_material
            == known_good_attestation.verification_material
        )
        assert converted_attestation.envelope == known_good_attestation.envelope


def test_convert_command_invalid_bundle(caplog: pytest.LogCaptureFixture) -> None:
    with tempfile.NamedTemporaryFile(suffix=".sigstore") as f:
        f.write(b"not a valid bundle")
        f.flush()
        with pytest.raises(SystemExit):
            run_main_with_command(
                [
                    "convert",
                    "--output-file",
                    "temp.attestation",
                    f.name,
                ]
            )

    assert not Path("temp.attestation").exists()
    assert "Invalid Sigstore bundle" in caplog.text


def test_convert_command_conversion_error(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        pypi_attestations._cli, "Attestation", stub(from_bundle=raiser(ConversionError))
    )

    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "convert",
                "--output-file",
                "temp.attestation",
                sigstore_bundle_path.as_posix(),
            ]
        )

    assert not Path("temp.attestation").exists()
    assert "Failed to convert Sigstore bundle" in caplog.text


def test_convert_command_nonexistent_bundle(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "convert",
                "--output-file",
                "temp.attestation",
                "temp.sigstore",
            ]
        )

    assert not Path("temp.attestation").exists()
    assert "Bundle file does not exist" in caplog.text


def test_convert_command_existent_output_file(caplog: pytest.LogCaptureFixture) -> None:
    with tempfile.NamedTemporaryFile(suffix=".attestation") as f:
        output_attestation_path = Path(f.name)
        assert output_attestation_path.exists()
        with pytest.raises(SystemExit):
            run_main_with_command(
                [
                    "convert",
                    "--output-file",
                    output_attestation_path.as_posix(),
                    sigstore_bundle_path.as_posix(),
                ]
            )

    assert "Output file already exists" in caplog.text
