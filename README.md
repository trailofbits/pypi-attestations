# PyPI Attestation Models

<!--- BADGES: START --->
[![CI](https://github.com/trailofbits/pypi-attestation-models/actions/workflows/tests.yml/badge.svg)](https://github.com/trailofbits/pypi-attestation-models/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/pypi-attestation-models.svg)](https://pypi.org/project/pypi-attestation-models)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pypi-attestation-models.svg)](https://repology.org/project/python:pypi-attestation-models/versions)
<!--- BADGES: END --->

A library to convert between Sigstore Bundles and PEP-740 Attestation objects

## Installation

```bash
python -m pip install pypi-attestation-models
```

## Usage

See the full API documentation [here].

```python
from pathlib import Path
from pypi_attestation_models import pypi_to_sigstore, sigstore_to_pypi, Attestation
from sigstore.models import Bundle

# Sigstore Bundle -> PEP 740 Attestation object
bundle_path = Path("test_package-0.0.1-py3-none-any.whl.sigstore")
with bundle_path.open("rb") as f:
    sigstore_bundle = Bundle.from_json(f.read())
attestation_object = sigstore_to_pypi(sigstore_bundle)
print(attestation_object.model_dump_json())


# PEP 740 Attestation object -> Sigstore Bundle
attestation_path = Path("attestation.json")
with attestation_path.open("rb") as f:
    attestation = Attestation.model_validate_json(f.read())
bundle = pypi_to_sigstore(attestation)
print(bundle.to_json())
```

[here]: https://trailofbits.github.io/pypi-attestation-models
