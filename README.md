# OAuth Library for Go

[![Go Version](https://img.shields.io/badge/Go-1.26.0-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/lumeweb/oauth/actions/workflows/go.yml/badge.svg)](https://github.com/lumeweb/oauth/actions/workflows/go.yml)

A shared OAuth 2.1 authorization server domain-logic and storage library for
Go. It is the extracted, framework-agnostic core so multiple consumers
implement the same OAuth invariants.

## Packages

- Root `oauth` — stdlib-only domain logic and the `AuthorizationServer` facade
- `storage/gorm` — GORM-backed `Storage` adapter (default production)
- `storage/memory` — in-memory `Storage` for tests and dev

## License

MIT
