module jwt

import encoding.base64
import json
import time

const no_secret = 'pass secret'
const secret = 'secret'
const claims = {
	'name':  'John Doe'
	'admin': 'true'
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
	token := Token.new_with_options(payload, SigningOptions{alg: .hs256, key_material: jwt.secret})!
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

	assert token.valid_with_options(SigningOptions{alg: .hs256, key_material: jwt.secret})
	assert !token.valid_with_options(SigningOptions{alg: .rs256, key_material: jwt.secret})
}
