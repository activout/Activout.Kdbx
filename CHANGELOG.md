# Changelog

All notable changes are documented here. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Fixed

- Argon2id databases, KeePassXC's default, failed with `NotSupportedException: Unsupported KDF`: the Argon2id KDF UUID was wrong.

## [0.1.0] - 2026-11-04

### Added

- `AddKdbxFile` and `AddKdbxStream` configuration sources for KDBX 3.1 and 4.x databases.
