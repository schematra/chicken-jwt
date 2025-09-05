# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CHICKEN Scheme JWT (JSON Web Token) library that implements HS256 (HMAC-SHA256) token creation and validation. The library provides a clean separation between token decoding and validation:

- `make-jwt-hs256`: Creates JWT tokens with HMAC-SHA256 signing
- `jwt-decode`: Decodes JWT structure without validation (unsafe - for inspection only)  
- `jwt-validate-hs256`: Full token validation including signature and claims verification

## Core Architecture

**Main module** (`jwt.scm`):
- Single module file containing all JWT functionality
- Dependencies: `base64.urlsafe`, `openssl.hmac`, `medea` (JSON), standard CHICKEN modules
- Uses `medea`'s `read-json` which returns alists with symbol keys (always use `alist-ref` for key lookup)
- Claims validation includes: exp (expiration), nbf (not-before), iat (issued-at), iss (issuer), aud (audience)

**Key design decisions**:
- `jwt-validate-hs256` internally calls `jwt-decode` to avoid code duplication
- All validation errors use `(error ...)` for consistent error handling
- Time-based claims support configurable leeway for clock skew
- Audience claim supports both string and vector formats

## Development Commands

**Build the extension**:
```bash
chicken-install -n
```

**Install (before running tests)**
```bash
chicken-install
```

**Run tests**:
```bash
csi -s tests/run.scm
```

**Interactive development**:
```bash
csi -e "(import jwt)"
```

## Test Structure

Tests use CHICKEN's built-in `test` module and are located in `tests/run.scm`. The test suite includes:
- Token creation and round-trip validation
- Error cases (expired tokens, malformed tokens, signature verification failures)
- Uses helper function `build-jwt` for creating test tokens with relative timestamps

**Note**: Test file currently uses deprecated `jwt-decode-hs256` function name - update tests when making API changes.

## Dependencies

Defined in `jwt.egg`:
- `base64.urlsafe`: Base64 URL-safe encoding/decoding
- `openssl.hmac`: HMAC-SHA256 signature generation/verification  
- `medea`: JSON parsing (returns symbol-keyed alists)
- `test`: Testing framework (test dependency only)

## CHICKEN Scheme Specifics

- Extension follows standard CHICKEN Scheme packaging with `.egg` file
- Uses `#!key` syntax for optional parameters
- Returns multiple values with `(values header payload)` pattern
- Error handling uses CHICKEN's `(error ...)` function
