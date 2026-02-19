# JWT
Simple JWT implementation for V.

![Brazil](https://flagcdn.com/w20/br.webp) [Leia em Português](./readme_pt-br.md)

> Note: **HS256** flow and payload parsing/validation are self-contained. **RS256** flow depends on OpenSSL in the environment.

This library supports:
- **HS256** (HMAC + SHA-256)
- **RS256** (RSA + SHA-256)

## Installation

In your `v.mod`:

```v
Module {
	dependencies: ['https://github.com/Ddiidev/jwt']
}
```

Or via VPM:

```bash
v install https://github.com/Ddiidev/jwt
```

## Simple Usage (Backward Compatible, HS256)

This is the same usage style as before:

```v
import jwt

const secret = 'secret-key'

pub struct Credential {
	user string
	pass string
}

fn main() {
	payload := jwt.Payload[Credential]{
		sub: '1234567890'
		ext: Credential{
			user: 'splashsky'
			pass: 'password'
		}
	}

	// Simple API (legacy/compatible)
	token := jwt.Token.new(payload, secret)
	token_str := token.str()

	parsed := jwt.from_str[Credential](token_str)!
	if parsed.valid(secret) {
		println('valid HS256 token')
	}
}
```

## Practical Example with RS256

For RS256, sign with **PEM private key** and validate with **PEM public key**:

```v
import os
import jwt

pub struct Claims {
	role string
}

fn main() {
	private_key := os.read_file('private.pem')!
	public_key := os.read_file('public.pem')!

	payload := jwt.Payload[Claims]{
		sub: 'user-123'
		ext: Claims{role: 'admin'}
	}

	// Signs with RS256
	token := jwt.Token.new_rs256(payload, private_key)
	token_str := token.str()

	// Validates with public key
	parsed := jwt.from_str[Claims](token_str)!
	if parsed.valid_rs256(public_key) {
		println('valid RS256 token')
	}
}
```

## Options API (Recommended)

If you want to avoid any algorithm ambiguity, use the explicit options API:

```v
// HS256 Signing
token_hs := jwt.Token.new_with_options(payload, jwt.Hs256SigningOptions{secret: secret})!

// RS256 Signing
token_rs := jwt.Token.new_with_options(payload, jwt.Rs256SigningOptions{private_key_pem: private_key})!

// HS256 Validation
ok_hs := token_hs.valid_with_options(jwt.Hs256ValidationOptions{secret: secret})

// RS256 Validation
ok_rs := token_rs.valid_with_options(jwt.Rs256ValidationOptions{public_key_pem: public_key})
```

## Claims and Expiration

The `Payload[T]` struct supports standard JWT fields (`iss`, `sub`, `aud`, `exp`, `iat`) and custom claims in `ext`.

Validation (`valid*`) also checks if the token is expired (`exp`).

## Tests

```bash
v -cc gcc test src
```

RS256 tests use fixtures in `testdata/`.

On Windows, during development, always prefer using `gcc`:

```bash
v -cc gcc run your_file.v
v -cc gcc test src/custom_test.v
```

If you encounter a link error related to `GC_init` when switching compilers/flags, clear the V cache and run again with `-cc gcc`.

## Current Limitations

- **RS256 requires OpenSSL**: headers, libs, and DLLs must be available in the environment.
- **Windows + tcc**: currently may fail to run tests with error `0xC0000135` (missing DLL). On Linux it usually works; on Windows, use `-cc gcc`.
- **Claim validation is minimal**: the `valid*` API validates signature, algorithm, and `exp`; it does not validate semantic rules for `iss`, `aud`, and `sub`.
- **No native support for `nbf` and `jti`**: if needed, handle these rules in the application layer.
- **No JWK/JWKS/kid**: current RS256 flow works directly with PEM (private/public key in text).


## Claims for GitHub App (NumericDate)

When generating JWT for GitHub App, `iss` must be the App ID and `iat`/`exp` must be NumericDate (seconds since epoch).

`Payload[T]` now accepts `iat` and `exp` as `i64` **or** `string`, so you can use Unix seconds directly:

```v
import time
import jwt

const app_id = '123456'

payload := jwt.Payload[map[string]string]{
	iss: app_id
	iat: time.now().unix()
	exp: time.now().add_seconds(540).unix()
	ext: {}
}

// RS256 Example
token := jwt.Token.new_rs256(payload, private_key_pem)
```
