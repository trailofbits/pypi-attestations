# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.27]

### Fixed

- Verification now compares the distribution filenames of artifacts
  and attestations by parsing them first and comparing its components
  (i.e. normalized name, version, tags) instead of doing a filename
  string comparison. This fixes an issue where verification would fail
  due to the artifact filename having the wheel tags in a different
  order than the ones in the attestation.
  ([#127](https://github.com/trailofbits/pypi-attestations/pull/127))

## [0.0.26]

### Fixed

- This library no longer enforces distribution name "ultranormalization,"
  which went above the requirements specified in PEP 740
  ([#124](https://github.com/trailofbits/pypi-attestations/pull/124))

## [0.0.25]

### Fixed

- Make the `GooglePublisher` type and APIs public
  ([#117](https://github.com/trailofbits/pypi-attestations/pull/117))

## [0.0.24]

### Added

- The `GooglePublisher` type has been added to support
  Google Cloud-based Trusted Publishers
  ([#114](https://github.com/trailofbits/pypi-attestations/pull/114))

## [0.0.23]

### Added

- The CLI has a new subcommand `convert`, which takes a Sigstore bundle
  and converts it to a PEP 740 attestation.

### Changed

- The `Attestation.verify(...)` API has been changed to accept an `offline`
  parameter that, when True, disables TUF refreshes.
- The CLI `verify` commands now also accept an `--offline` flag that disables
  TUF refreshes. Additionally, when used with the `verify pypi` subcommand, the
  `--offline` flag enforces that the distribution and provenance file arguments
  must be local file paths.

### Fixed

- Fixed a bug where `GitHubPublisher` policy verification would fail
  if the `Source Repository Ref` or `Source Repository Digest` claim
  was missing from the attestation's certificate. We require at least
  one of the two claims, but not necessarily both
  ([#109](https://github.com/trailofbits/pypi-attestations/pull/109))

## [0.0.22]

### Changed

- The `inspect` subcommand now ignores inputs that don't match `*.attestation`,
  rather than failing on them
  ([#93](https://github.com/trailofbits/pypi-attestations/pull/93))

### Added

- The CLI subcommand `verify attestation` now supports `.slsa.attestation`
  files. When verifying an artifact, both `.publish.attestation` and
  `.slsa.attestation` files are used (if present).
- The CLI subcommand `verify pypi` now supports a friendlier
  syntax to specify the artifact to verify. The artifact can now be
  specified with a `pypi:` prefix followed by the filename, e.g:
  `pypi:sampleproject-1.0.0.tar.gz`. The old way (passing
  the direct URL) is still supported.
- The CLI subcommand `verify pypi` now supports passing the local paths
  to the artifact and its provenance file, allowing the user to verify
  files already downloaded from PyPI. The artifact path is passed as
  usual, whereas the provenance file path is passed using the
  `--provenance-file` option.

## [0.0.21]

### Changed

- The CLI entrypoint is now `pypi-attestations`
  ([#82](https://github.com/trailofbits/pypi-attestations/pull/82))
- The CLI `verify` subcommand has been changed to `verify attestation`,
  as in `pypi-attestations verify attestation --identity ...`
  ([#82](https://github.com/trailofbits/pypi-attestations/pull/82))

### Added

- The CLI has a new subcommand `verify pypi`, which takes a URL to a
  PyPI distribution (either a wheel or a source distribution) and a
  GitHub/GitLab repository. The command verifies the distribution by
  downloading it and its provenance from PyPI, verifying them using
  `sigstore` and checking that the repository matches the one in the
  PyPI provenance file.
  ([#82](https://github.com/trailofbits/pypi-attestations/pull/82))

## [0.0.20]

### Changed

- Explicitly support sigstore-python 3.6
  ([#79](https://github.com/trailofbits/pypi-attestations/pull/79))

## [0.0.19]

This is a corrective release for [0.0.18].

## [0.0.18]

### Added

- The `Attestation` type now has a `certificate_claims` property to expose
  underlying Fulcio signing certificate extensions
  ([#70](https://github.com/trailofbits/pypi-attestations/pull/70))

## [0.0.17]

### Fixed

- The `GitLabPublisher` policy now takes the workflow file path in order to
  verify attestations, rathen than assuming it will always be `gitlab-ci.yml`
  ([#71](https://github.com/trailofbits/pypi-attestations/pull/71)).
- The `GitLabPublisher` now longer expects claims being passed during construction,
  rather the `ref` and `sha` claims are extracted from the certificate's extensions,
  similar to `GitHubPublisher`'s behavior
  ([#71](https://github.com/trailofbits/pypi-attestations/pull/71)).


### Changed

- Publisher classes (`GitLabPublisher` and `GitHubPublisher`) no longer take a claims
  dictionary during construction
  ([#72](https://github.com/trailofbits/pypi-attestations/pull/72)).

## [0.0.16]

### Added

- `Attestation.statement` has been added as a convenience API for accessing
  the attestation's enveloped statement as a dictionary

## [0.0.15]

This is a corrective release for [0.0.14].

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

[Unreleased]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.27...HEAD
[0.0.27]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.26...v0.0.27
[0.0.26]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.25...v0.0.26
[0.0.25]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.24...v0.0.25
[0.0.24]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.23...v0.0.24
[0.0.23]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.22...v0.0.23
[0.0.22]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.21...v0.0.22
[0.0.21]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.20...v0.0.21
[0.0.20]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.19...v0.0.20
[0.0.19]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.18...v0.0.19
[0.0.18]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.17...v0.0.18
[0.0.17]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.16...v0.0.17
[0.0.16]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.15...v0.0.16
[0.0.15]: https://github.com/trailofbits/pypi-attestation-models/compare/v0.0.14...v0.0.15
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
