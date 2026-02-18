# Test fixtures (RS256)

These PEM files are test-only fixtures used by `src/jwt_test.v` to validate RS256 signing and verification flows.

## Files

- `rs256_private.pem`: private key used to sign test JWTs.
- `rs256_public.pem`: matching public key used for successful verification.
- `rs256_public_wrong.pem`: unrelated public key used to assert verification failure.

## Origin

The main pair (`rs256_private.pem` + `rs256_public.pem`) comes from the previously inlined constants that already existed in this repository's tests, moved into stable fixtures for reuse.

The `rs256_public_wrong.pem` key is a separate RSA public key fixture added only to simulate invalid verification scenarios.

## Usage notes

- Fixtures are intentionally static and deterministic.
- They are **not** production secrets and must only be used in tests.
