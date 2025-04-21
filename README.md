# pypi-attestations

<!--- BADGES: START --->
[![CI](https://github.com/trailofbits/pypi-attestations/actions/workflows/tests.yml/badge.svg)](https://github.com/trailofbits/pypi-attestations/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/pypi-attestations.svg)](https://pypi.org/project/pypi-attestations)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pypi-attestations.svg)](https://repology.org/project/python:pypi-attestations/versions)
<!--- BADGES: END --->

A library to generate and convert between Sigstore Bundles and [PEP 740]
Attestation objects.

> [!IMPORTANT]
> This library is an implementation detail within the reference implementation
> of [PEP 740]. Most users should not need to interact with it directly;
> see the [PyPI documentation] for full details.

## Installation

```bash
python -m pip install pypi-attestations
```

## Usage as a library

See the full API documentation [here].

### Signing and verification

Use these APIs to create a PEP 740-compliant `Attestation` object by signing a Python artifact
(i.e: sdist or wheel files), and to verify an `Attestation` object against a Python artifact.

```python
from pathlib import Path

from pypi_attestations import Attestation, Distribution
from sigstore.oidc import Issuer
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

dist = Distribution.from_file(Path("test_package-0.0.1-py3-none-any.whl"))

# Sign a Python artifact
issuer = Issuer.production()
identity_token = issuer.identity_token()
signing_ctx = SigningContext.production()
with signing_ctx.signer(identity_token, cache=True) as signer:
    attestation = Attestation.sign(signer, dist)

print(attestation.model_dump_json())

# Verify an attestation against a Python artifact
attestation_path = Path("test_package-0.0.1-py3-none-any.whl.attestation")
attestation = Attestation.model_validate_json(attestation_path.read_bytes())
identity = policy.Identity(identity="example@gmail.com", issuer="https://accounts.google.com")
attestation.verify(identity=identity, dist=dist)
```

### Low-level model conversions

These conversions assume that any Sigstore Bundle used as an input was created
by signing a distribution file.

```python
from pathlib import Path
from pypi_attestations import Attestation
from sigstore.models import Bundle

# Sigstore Bundle -> PEP 740 Attestation object
bundle_path = Path("test_package-0.0.1-py3-none-any.whl.sigstore")
with bundle_path.open("rb") as f:
    sigstore_bundle = Bundle.from_json(f.read())
attestation_object = Attestation.from_bundle(sigstore_bundle)
print(attestation_object.model_dump_json())

# PEP 740 Attestation object -> Sigstore Bundle
attestation_path = Path("attestation.json")
with attestation_path.open("rb") as f:
    attestation = Attestation.model_validate_json(f.read())
bundle = attestation.to_bundle()
print(bundle.to_json())
```

## Usage as a command line tool

> [!IMPORTANT]
> The `pypi-attestations` CLI is intended primarily for
> experimentation, and is not considered a stable interface for
> generating or verifying attestations. Users are encouraged to
> generate attestations using [the official PyPA publishing action]
> or via this package's [public Python APIs].

````bash
pypi-attestations --help
usage: pypi-attestation [-h] [-v] [-V] COMMAND ...

Sign, inspect or verify PEP 740 attestations

positional arguments:
  COMMAND        The operation to perform
    sign         Sign one or more inputs
    verify       Verify one or more inputs
    inspect      Inspect one or more inputs
    convert      Convert a Sigstore bundle into a PEP 740 attestation

options:
  -h, --help     show this help message and exit
  -v, --verbose  run with additional debug logging; supply multiple times to
                 increase verbosity (default: 0)
  -V, --version  show program's version number and exit
````

### Signing a package

> [!NOTE]
> If run locally (i.e. not within GitHub Actions or another source of
> ambient OIDC credentials), this will open a browser window to perform
> the Sigstore OAuth flow.

```bash
# Generate a whl file
make package
pypi-attestations sign dist/pypi_attestations-*.whl
```

### Inspecting a PEP 740 Attestation

> [!WARNING]
> Inspecting does not mean verifying. It only prints the structure of
> the attestation.

```bash
pypi-attestations inspect dist/pypi_attestations-*.whl.publish.attestation
```

### Verifying a PEP 740 Attestation

```bash
pypi-attestations verify attestation  \
  --identity https://github.com/trailofbits/pypi-attestations/.github/workflows/release.yml@refs/tags/v0.0.19 \
  test/assets/pypi_attestations-0.0.19.tar.gz
```

### Verifying a PyPI package

> [!IMPORTANT]
> This subcommand supports publish attestations from GitHub and GitLab.
> It **does not currently support** Google Cloud-based publish attestations.

> [!NOTE]
> The package to verify can be passed either as a path to a local file, a
> `pypi:` prefixed filename (e.g: 'pypi:sampleproject-1.0.0-py3-none-any.whl'),
> or as a direct URL to the artifact hosted by PyPI.

```bash
# Download the artifact (and its provenance) from PyPI and verify it
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  pypi:sigstore-3.6.1-py3-none-any.whl

# or alternatively, using the direct URL:
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  https://files.pythonhosted.org/packages/70/f5/324edb6a802438e97e289992a41f81bb7a58a1cda2e49439e7e48896649e/sigstore-3.6.1-py3-none-any.whl

# Verify the artifact and its provenance using local files
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  --provenance-file ~/Downloads/sigstore-3.6.1-py3-none-any.whl.provenance \
  ~/Downloads/sigstore-3.6.1-py3-none-any.whl
```

This command downloads the artifact and its provenance from PyPI. The artifact
is then verified against the provenance, while also checking that the provenance's
signing identity matches the repository specified by the user.

### Converting a Sigstore bundle into a PEP 740 Attestation

```bash
pypi-attestations convert --output-file /tmp/rfc8785-0.1.2-py3-none-any.whl.publish.attestation  \
  test/assets/rfc8785-0.1.2-py3-none-any.whl.sigstore
```


[PEP 740]: https://peps.python.org/pep-0740/

[here]: https://trailofbits.github.io/pypi-attestations

[public Python APIs]: https://trailofbits.github.io/pypi-attestations

[the official PyPA publishing action]: https://github.com/pypa/gh-action-pypi-publish

[PyPI documentation]: https://docs.pypi.org/attestations
