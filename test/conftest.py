import os

import pytest
from sigstore import oidc


@pytest.fixture(scope="session")
def id_token() -> oidc.IdentityToken:
    if "CI" in os.environ:
        token = oidc.detect_credential()
        if token is None:
            pytest.fail("misconfigured CI: no ambient OIDC credential")
        return oidc.IdentityToken(token)
    else:
        return oidc.Issuer.staging().identity_token()
