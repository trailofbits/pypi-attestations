from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pypi_attestation_models._cli
import pytest
from pypi_attestation_models._cli import _logger, get_identity_token, main
from pypi_attestation_models._impl import Attestation
from sigstore.oidc import IdentityError, IdentityToken

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


def _die_test(_: argparse.Namespace, message: str) -> None:
    """Placeholder for the _die function."""
    raise SystemExit(message)


def test_main_verbose_level(monkeypatch: pytest.MonkeyPatch) -> None:
    def default_sign(_: argparse.Namespace) -> None:
        return

    monkeypatch.setattr(pypi_attestation_models._cli, "_sign", default_sign)

    run_main_with_command(["sign", "-v", ""])
    assert _logger.level == logging.DEBUG

    run_main_with_command(["sign", "-v", "-v", ""])
    assert logging.getLogger().level == logging.DEBUG

    with pytest.raises(SystemExit) as exc_info:
        run_main_with_command(["not-a-command"])

    assert exc_info.value.code == 2


def test_get_identity_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Failure path
    monkeypatch.setattr(pypi_attestation_models._cli, "_die", _die_test)

    # Invalid token
    with pytest.raises(IdentityError, match="Identity token is malformed"):
        get_identity_token(argparse.Namespace(identity_token="INVALID"))

    # Happy paths tests missing


@online
def test_sign_command(tmp_path: Path, id_token: IdentityToken) -> None:
    # Happy path
    copied_artifact = tmp_path / artifact_path.with_suffix(".copy.whl").name
    shutil.copy(artifact_path, copied_artifact)

    run_main_with_command(
        [
            "sign",
            "--staging",
            "--identity-token",
            id_token._raw_token,
            copied_artifact.as_posix(),
        ]
    )
    copied_artifact_attestation = Path(f"{copied_artifact}.publish.attestation")
    assert copied_artifact_attestation.is_file()

    attestation = Attestation.model_validate_json(copied_artifact_attestation.read_text())
    assert attestation.version


@online
def test_sign_command_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, id_token: IdentityToken
) -> None:
    monkeypatch.setattr(pypi_attestation_models._cli, "_die", _die_test)

    # Missing file
    with pytest.raises(SystemExit, match="not_exist.txt is not a file"):
        run_main_with_command(
            [
                "sign",
                "--staging",
                "--identity-token",
                id_token._raw_token,
                "not_exist.txt",
            ]
        )

    # Signature already exists
    artifact = tmp_path / artifact_path.with_suffix(".copy2.whl").name
    artifact.touch(exist_ok=False)

    artifact_attestation = Path(f"{artifact}.publish.attestation")
    artifact_attestation.touch(exist_ok=False)
    with pytest.raises(SystemExit, match="Signature already exists"):
        run_main_with_command(
            [
                "sign",
                "--staging",
                "--identity-token",
                id_token._raw_token,
                artifact.as_posix(),
            ]
        )


def test_inspect_command(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    # Happy path
    run_main_with_command(["inspect", attestation_path.as_posix()])
    assert attestation_path.as_posix() in caplog.text
    assert "CN=sigstore-intermediate,O=sigstore.dev" in caplog.text

    run_main_with_command(["inspect", "--dump-bytes", attestation_path.as_posix()])
    assert "Signature:" in caplog.text

    # Failure paths
    monkeypatch.setattr(pypi_attestation_models._cli, "_die", _die_test)

    # Failure because not an attestation
    with tempfile.NamedTemporaryFile(suffix=".publish.attestation") as f:
        fake_package_name = Path(f.name.removesuffix(".publish.attestation"))
        fake_package_name.touch()

        with pytest.raises(SystemExit, match="Invalid attestation"):
            run_main_with_command(["inspect", fake_package_name.as_posix()])

    # Failure because file is missing
    with pytest.raises(SystemExit, match="not_a_file.txt is not a file."):
        run_main_with_command(["inspect", "not_a_file.txt"])


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


def test_verify_command_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    # Hook the `_die` function to raise directly an exception instead of using the argparse errors
    # This helps recover the message raised as an error
    monkeypatch.setattr(pypi_attestation_models._cli, "_die", _die_test)

    # Failure because not an attestation
    with pytest.raises(SystemExit, match="Invalid attestation"):
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

    # Failure because missing package file
    with pytest.raises(SystemExit, match="not_a_file.txt is not a file."):
        run_main_with_command(
            [
                "verify",
                "--staging",
                "--identity",
                "william@yossarian.net",
                "not_a_file.txt",
            ]
        )

    # Failure because missing attestation file
    with pytest.raises(SystemExit, match="Missing attestation"):
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
