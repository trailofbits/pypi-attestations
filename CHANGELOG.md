# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.14]

### Fixed

- The `Distribution` API now handles ZIP source distributions
  (those ending with `.zip`) instead of rejecting them as invalid
  ([#68](https://github.com/trailofbits/pypi-attestations/pull/68))

## [0.0.13]

### Changed

- The minimum Python version required has been brought back to `3.9`
  ([#64](https://github.com/trailofbits/pypi-attestations/pull/64)).

- The `Attestation.verify(...)` API has been changed to remove the `Verifier`
  argument in favor of an optional `staging: bool` kwarg to select the
  Sigstore instance
  ([#62](https://github.com/trailofbits/pypi-attestations/pull/62))

- The `Attestation.verify(...)` API has been changed to accept both `Publisher`
  and `VerificationPolicy` objects as a policy. The publisher object is internally
  converted to an appropriate verification policy.

### Fixed

- `python -m pypi_attestations verify` now handles inputs like `dist/*`
  gracefully, by pre-filtering any attestation paths from the inputs.

- `python -m pypi_attestations verify` now exits with a non-zero exit code
  if the verification step fails
  ([#57](https://github.com/trailofbits/pypi-attestations/pull/57))

## [0.0.12]

### Fixed

- Base64-encoded bytes inside Attestation objects contained newline characters
  every 76 characters due to a bug in Pydantic's Base64Bytes type. Those
  newlines were also (incorrectly) ignored by Pydantic during decoding
  ([#48](https://github.com/trailofbits/pypi-attestations/pull/48)).

## [0.0.11]

### Changed

- The minimum version of sigstore-python is now `3.2.0`, owing to private
  API changes ([#45](https://github.com/trailofbits/pypi-attestations/pull/45))

## [0.0.10]

### Changed

- The minimum Python version required has been bumped to `3.11`
  ([#37](https://github.com/trailofbits/pypi-attestations/pull/37))

### Added

- The `Provenance`, `Publisher`, `GitHubPublisher`, `GitLabPublisher`, and
  `AttestationBundle` types have been added
  ([#36](https://github.com/trailofbits/pypi-attestations/pull/36)).

## [0.0.9]

### Added

- The `Distribution` type and APIs have been added, allowing a user to supply
  a pre-computed digest instead of performing I/O
  ([#34](https://github.com/trailofbits/pypi-attestations/pull/34))

### Changed

- `sign` and `verify` no longer perform I/O
  ([#34](https://github.com/trailofbits/pypi-attestations/pull/34))


### Fixed

- `verify`: catch another leaky error case
  ([#32](https://github.com/trailofbits/pypi-attestations/pull/32))


## [0.0.8]

### Fixed

- `AttestationType` is now re-exported at the top-level as a public API
  ([#31](https://github.com/trailofbits/pypi-attestations/pull/31))

## [0.0.7]

### Added

- `AttestationType` has been added, as an enumeration of all currently known
  attestation types (by URL)
  ([#29](https://github.com/trailofbits/pypi-attestations/pull/29))

### Changed

- `Attestation.verify` now checks the attestation's type against
  `AttestationType` before returning it
  ([#29](https://github.com/trailofbits/pypi-attestations/pull/29))

### Fixed

- `Attestation.sign` now only returns `AttestationError` when failing to sign a
  distribution file
  ([#28](https://github.com/trailofbits/pypi-attestations/pull/28))

## [0.0.6]

### Added

- The `python -m pypi_attestations` CLI has been added. This CLI is primarily
  intended for local development, and not for external use. Its flags and
  commands are not subject to stabilization unless explicitly documented
  in a future release
  ([#22](https://github.com/trailofbits/pypi-attestations/pull/22))

### Changed

- The name of this project is now `pypi-attestations`, renamed from
  `pypi-attestion-models` ([#25](https://github.com/trailofbits/pypi-attestations/pull/25))

- The model conversion functions have been moved into the `Attestation` class
  ([#24](https://github.com/trailofbits/pypi-attestations/pull/24))

## [0.0.5] - 2024-06-20

### Added

- `Attestation.verify` now returns the inner statement's predicate components
  ([#20](https://github.com/trailofbits/pypi-attestations/pull/20))

## [0.0.4] - 2024-06-11

### Changed

- Switch to in-toto statements ([#18](https://github.com/trailofbits/pypi-attestations/pull/18))

## [0.0.3] - 2024-06-10

- No functional changes.

## [0.0.2] - 2024-05-16

### Changed

- Update `sigstore` to 3.0.0

## [0.0.1] - 2024-05-15

### Added

- Initial implementation

[Unreleased]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.14...HEAD
[0.0.14]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.13...v0.0.14
[0.0.13]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.12...v0.0.13
[0.0.12]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.11...v0.0.12
[0.0.11]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/trailofbits/pypi-attestation-models/releases/tag/v0.0.1
