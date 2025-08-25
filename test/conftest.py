import os

import pytest
from sigstore import oidc


@pytest.fixture(scope="session")
def id_token() -> oidc.IdentityToken:
    if "EXTREMELY_DANGEROUS_PUBLIC_OIDC_BEACON" in os.environ:
        import requests

        resp = requests.get(
            "https://raw.githubusercontent.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/refs/heads/current-token/oidc-token.txt"
        )
        resp.raise_for_status()
        id_token = resp.text.strip()
        return oidc.IdentityToken(id_token)

    if "CI" in os.environ:
        token = oidc.detect_credential()
        if token is None:
            pytest.fail("misconfigured CI: no ambient OIDC credential")
        return oidc.IdentityToken(token)

    pytest.fail("no OIDC token available for tests")
