module jwt

import encoding.base64
import json
import os
import time

const no_secret = 'pass secret'
const secret = 'secret'
const claims = {
	'name':  'John Doe'
	'admin': 'true'
}

fn fixture_path(name string) string {
	return os.join_path(os.dir(os.dir(@FILE)), 'testdata', name)
}

fn load_fixture(name string) string {
	return os.read_file(fixture_path(name)) or { panic('failed to load fixture `${name}`: ${err.msg()}') }
}

fn test_valid() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new(payload, jwt.secret)

	assert token.valid(jwt.secret)
}

fn test_invalid() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new(payload, jwt.secret)

	assert !token.valid(jwt.no_secret)
}

fn test_expired() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
		exp: '2019-01-01 00:00:00'
	}
	token := Token.new(payload, jwt.secret)

	assert !token.valid(jwt.secret)
	assert token.expired()
}

fn test_no_expired() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
		exp: time.now().add_seconds(10).str()
	}
	token := Token.new(payload, jwt.secret)

	assert token.valid(jwt.secret)
	assert !token.expired()
}

fn test_from_str() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	payload2 := Payload[map[string]string]{
		sub: '0987654321'
		ext: jwt.claims
	}

	token := Token.new(payload, jwt.secret)
	token2 := from_str[map[string]string](token.str())!
	token3 := Token.new(payload2, jwt.secret)

	assert token2 == token
	assert token2 != token3
}

fn test_new_with_options_sets_header_algorithm() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_with_options(payload, Hs256SigningOptions{secret: jwt.secret})!
	header := json.decode(Header, base64.url_decode_str(token.header))!

	assert header.alg == 'HS256'
	assert header.typ == 'JWT'
}

fn test_valid_with_options_uses_algorithm() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_hs256(payload, jwt.secret)

	assert token.valid_with_options(Hs256ValidationOptions{secret: jwt.secret})
	assert !token.valid_with_options(Rs256ValidationOptions{public_key_pem: jwt.secret})
}

fn test_rs256_create_and_validate_with_fixture_keys() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	private_key := load_fixture('rs256_private.pem')
	public_key := load_fixture('rs256_public.pem')
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: private_key})!

	assert token.signature.len > 0
	assert token.valid_with_options(Rs256ValidationOptions{public_key_pem: public_key})
}

fn test_rs256_fails_with_wrong_public_key_fixture() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	private_key := load_fixture('rs256_private.pem')
	wrong_public_key := load_fixture('rs256_public_wrong.pem')
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: private_key})!

	assert !token.valid_with_options(Rs256ValidationOptions{public_key_pem: wrong_public_key})
}

fn test_rs256_fails_with_tampered_signature() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	private_key := load_fixture('rs256_private.pem')
	public_key := load_fixture('rs256_public.pem')
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: private_key})!
	parts := token.str().split('.')
	broken_signature := parts[2][0..parts[2].len - 1] + if parts[2].ends_with('A') { 'B' } else { 'A' }
	broken_token := from_str[map[string]string]('${parts[0]}.${parts[1]}.${broken_signature}')!

	assert !broken_token.valid_with_options(Rs256ValidationOptions{public_key_pem: public_key})
}

fn test_hs256_regression_still_works() {
	payload := Payload[map[string]string]{
		sub: 'legacy-subject'
		ext: jwt.claims
	}
	token := Token.new(payload, jwt.secret)
	parsed := from_str[map[string]string](token.str())!

	assert parsed.valid(jwt.secret)
	assert parsed.valid_hs256(jwt.secret)
}

fn test_from_str_preserves_rs256_header_algorithm() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	private_key := load_fixture('rs256_private.pem')
	public_key := load_fixture('rs256_public.pem')
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: private_key})!
	parsed := from_str[map[string]string](token.str())!
	header := json.decode(Header, base64.url_decode_str(parsed.header))!

	assert header.alg == 'RS256'
	assert parsed.valid_with_options(Rs256ValidationOptions{public_key_pem: public_key})
}

fn test_rs256_rejects_invalid_public_pem() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	private_key := load_fixture('rs256_private.pem')
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: private_key})!

	assert !token.valid_with_options(Rs256ValidationOptions{public_key_pem: 'not-a-pem'})
}

fn test_verify_rs256_signature_errors_for_invalid_public_pem() {
	signature := base64.url_decode('ZmFrZS1zaWduYXR1cmU') or { []u8{} }

	_ := verify_rs256_signature('header.payload', signature, 'not-a-pem') or {
		assert err.msg().contains('unable to parse PEM public key')
		return
	}
	assert false
}

fn test_verify_rs256_signature_errors_for_empty_public_pem() {
	_ := verify_rs256_signature('header.payload', []u8{}, '') or {
		assert err.msg().contains('PEM public key cannot be empty')
		return
	}
	assert false
}

fn test_rs256_rejects_empty_pem() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}

	_ := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: ''}) or {
		assert err.msg().contains('PEM private key cannot be empty')
		return
	}
	assert false
}

fn test_rs256_rejects_invalid_pem() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}

	_ := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: 'not-a-pem'}) or {
		assert err.msg().contains('invalid PEM private key format')
		return
	}
	assert false
}

fn test_rs256_rejects_pem_without_end_marker() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	invalid_pem := '-----BEGIN PRIVATE KEY-----
abc'

	_ := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: invalid_pem}) or {
		assert err.msg().contains('missing END PRIVATE KEY marker')
		return
	}
	assert false
}
