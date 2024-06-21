from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

import pypi_attestation_models._cli
import pytest
from pypi_attestation_models._cli import _logger, main

ONLINE_TESTS = "CI" in os.environ or "TEST_INTERACTIVE" in os.environ
online = pytest.mark.skipif(not ONLINE_TESTS, reason="online tests not enabled")


_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

artifact_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl"
attestation_path = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.publish.attestation"


def run_main_with_command(cmd: list[str]) -> None:
    sys.argv[1:] = cmd
    main()


def test_main_verbose_level(monkeypatch) -> None:
    def default_sign(*args) -> None:
        return

    monkeypatch.setattr(pypi_attestation_models._cli, "_sign", default_sign)

    run_main_with_command(["sign", "-v", ""])
    assert _logger.level == logging.DEBUG

    run_main_with_command(["sign", "-v", "-v", ""])
    assert logging.getLogger().level == logging.DEBUG


# @online
# def test_sign_command(id_token: IdentityToken) -> None:
#     sys.argv[1:] = ["sign", artifact_path.as_posix()]
#     main()
#


def test_inspect_command(caplog) -> None:
    # Happy path
    run_main_with_command(["inspect", attestation_path.as_posix()])
    assert attestation_path.as_posix() in caplog.text
    assert "CN=sigstore-intermediate,O=sigstore.dev" in caplog.text

    run_main_with_command(["inspect", "--dump-bytes", attestation_path.as_posix()])
    assert "Signature:" in caplog.text


def test_verify_command(caplog) -> None:
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

    caplog.clear()

    # Failure because not an attestation
    with pytest.raises(SystemExit) as exc_info:
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
    assert "Verification failed" in caplog.text
