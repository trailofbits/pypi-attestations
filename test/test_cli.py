from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
import sigstore.oidc
from sigstore.oidc import IdentityError

import pypi_attestations._cli
from pypi_attestations._cli import (
    _logger,
    _validate_files,
    get_identity_token,
    main,
)
from pypi_attestations._impl import Attestation

ONLINE_TESTS = "CI" in os.environ or "TEST_INTERACTIVE" in os.environ
online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")


_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

artifact_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl"
attestation_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.publish.attestation"


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
    copied_artifact = tmp_path / artifact_path.with_suffix(".copy.whl").name
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

    attestation = Attestation.model_validate_json(copied_artifact_attestation.read_text())
    assert attestation.version


@online
def test_sign_command_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
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
    caplog.clear()

    # Signature already exists
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

    # Invalid token
    def return_invalid_token() -> str:
        return "invalid-token"

    monkeypatch.setattr(sigstore.oidc, "detect_credential", return_invalid_token)

    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "sign",
                "--staging",
                artifact.as_posix(),
            ]
        )

    assert "Failed to detect identity" in caplog.text


def test_inspect_command(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    # Happy path
    run_main_with_command(["inspect", attestation_path.as_posix()])
    assert attestation_path.as_posix() in caplog.text
    assert "CN=sigstore-intermediate,O=sigstore.dev" in caplog.text

    run_main_with_command(["inspect", "--dump-bytes", attestation_path.as_posix()])
    assert "Signature:" in caplog.text

    # Failure paths
    caplog.clear()

    # Failure because not an attestation
    with tempfile.NamedTemporaryFile(suffix=".publish.attestation") as f:
        fake_package_name = Path(f.name.removesuffix(".publish.attestation"))
        fake_package_name.touch()

        with pytest.raises(SystemExit):
            run_main_with_command(["inspect", fake_package_name.as_posix()])

        assert "Invalid attestation" in caplog.text

    # Failure because file is missing
    caplog.clear()
    with pytest.raises(SystemExit):
        run_main_with_command(["inspect", "not_a_file.txt"])

    assert "not_a_file.txt is not a file." in caplog.text


def test_verify_command(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    # Happy path
    run_main_with_command(
        [
            "verify",
            "--staging",
            "--identity",
            "william@yossarian.net",
            artifact_path.as_posix(),
        ]
    )
    assert f"OK: {attestation_path.as_posix()}" in caplog.text

    caplog.clear()

    with pytest.raises(SystemExit):
        # Failure from the Sigstore environment
        run_main_with_command(
            [
                "verify",
                "--identity",
                "william@yossarian.net",
                artifact_path.as_posix(),
            ]
        )
    assert (
        "Verification failed: failed to build chain: unable to get local issuer certificate"
        in caplog.text
    )
    assert "OK:" not in caplog.text


def test_verify_command_failures(caplog: pytest.LogCaptureFixture) -> None:
    # Failure because not an attestation
    with pytest.raises(SystemExit):
        with tempfile.NamedTemporaryFile(suffix=".publish.attestation") as f:
            fake_package_name = Path(f.name.removesuffix(".publish.attestation"))
            fake_package_name.touch()

            run_main_with_command(
                [
                    "verify",
                    "--staging",
                    "--identity",
                    "william@yossarian.net",
                    fake_package_name.as_posix(),
                ]
            )
    assert "Invalid attestation" in caplog.text

    # Failure because missing package file
    caplog.clear()
    with pytest.raises(SystemExit):
        run_main_with_command(
            [
                "verify",
                "--staging",
                "--identity",
                "william@yossarian.net",
                "not_a_file.txt",
            ]
        )

    assert "not_a_file.txt is not a file." in caplog.text

    # Failure because missing attestation file
    caplog.clear()
    with pytest.raises(SystemExit):
        with tempfile.NamedTemporaryFile() as f:
            run_main_with_command(
                [
                    "verify",
                    "--staging",
                    "--identity",
                    "william@yossarian.net",
                    f.name,
                ]
            )

    assert "is not a file." in caplog.text


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
