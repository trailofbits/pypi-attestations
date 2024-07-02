# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `Attestation.sign` now only returns `AttestationError` when failing to sign a distribution file ([#28](https://github.com/trailofbits/pypi-attestations/pull/28))

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

[unreleased]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.1...HEAD
[0.0.6]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/trailofbits/pypi-attestation-models/releases/tag/v0.0.1
