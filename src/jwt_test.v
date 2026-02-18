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
const rsa_private_key = '"""
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALfKh8YY59j47ByW
NqL7IP4JRHQKpuUQf4Csx6u4jEmxRcXxt/MnYKT4mM7xBNmIJY5jrpYvNSk9M9Qx
vfzL9lnb81I6fA4j4IgqpV4yVQPr+7z4TNg+bBfM0wMDDhprK7I/N6+JkhynMUP2
qfmfM6cv7piA5Y8v5d8Shs7M7WgHAgMBAAECgYEArf1KhIftT4xA/8GPr27S2w7p
nPV0JXUXh4wfN14R4d4LslN6A90x0JkKsAN6YfUtgSmAuiZgaZODG8xjP6M9n44M
D2JEo4QY6f9L5lN2hax2SGM4LhRiMBSk9dP+K2kqAf+ep6zkBdtSDzwbYjLifAnl
Pl8oI3hG4N7xRjbCjrECQQDzW8cu0S/Uq8hQJjQvjicT6Nid6EaWKfQEdxUp6jdG
NwWdrQvYskE7S48C84D8xQu+Uad2+aYf2xVhAcv8wBzPAkEAww7vG9P8FXQF8Mx2
xPJX6QZ9xA8Nzyf6nKFl3Qm6STp5D5B9Y0hQO6Qb1MmVfLoPAxwRNj5VCl6AotQe
XQGfNQJBAIbO6xms3n8bLn2MtRWrfwYb5X+9gXkM11Jq2S8F3IkxKyW4y5eA5Hkl
B5q4WpL5rIQ54OrFQ9pRkQLeZNhPWrECQDzX+E4Gt+Q4whwEDwQG1xkBsNf4NHQm
xCcPz0rD+LhJmFrSPuRjv1kVIpYVqL4h0Cr4Lm5M1Qq+X9mPXGVmJmUCQF4LKn8i
wjVf7wB6qU9wsMJKyQd84mmfi8P9dv9U+MTQ6MTLf3X3I9vv68sW6l0Y3zYv0sLr
vJ4i8d9xE5mAwHw=
-----END PRIVATE KEY-----
"""'
const rsa_public_key = '"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3yofGGOfY+Owcljai+yD+CUR0
CqblEH+ArMeruIxJsUXF8bfzJ2Ck+JjO8QTZiCWOY66WLzUpPTPUMb38y/ZZ2/NS
OnwOI+CIKqVeMlUD6/u8+EzYPmwXzNMDAw4aayuyPzeviZIcpzFD9qn5nzOnL+6Y
gOWPL+XfEobOzO1oBwIDAQAB
-----END PUBLIC KEY-----
"""'
const rsa_public_key_pkcs1 = '"""
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALfKh8YY59j47ByWNqL7IP4JRHQKpuUQf4Csx6u4jEmxRcXxt/MnYKT4
mM7xBNmIJY5jrpYvNSk9M9QxvfzL9lnb81I6fA4j4IgqpV4yVQPr+7z4TNg+bBfM
0wMDDhprK7I/N6+JkhynMUP2qfmfM6cv7piA5Y8v5d8Shs7M7WgHAgMBAAE=
-----END RSA PUBLIC KEY-----
"""'

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

fn test_new_with_options_rs256() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: jwt.rsa_private_key})!

	assert token.signature.len > 0
	assert token.valid_with_options(Rs256ValidationOptions{public_key_pem: jwt.rsa_public_key})
}

fn test_rs256_validates_pkcs1_public_key() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: jwt.rsa_private_key})!

	assert token.valid_with_options(Rs256ValidationOptions{public_key_pem: jwt.rsa_public_key_pkcs1})
}

fn test_rs256_rejects_invalid_signature_with_public_key() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: jwt.rsa_private_key})!
	parts := token.str().split('.')
	broken_signature := parts[2][0..parts[2].len - 1] + if parts[2].ends_with('A') { 'B' } else { 'A' }
	broken_token := from_str[map[string]string]('${parts[0]}.${parts[1]}.${broken_signature}')!

	assert !broken_token.valid_with_options(Rs256ValidationOptions{public_key_pem: jwt.rsa_public_key})
}

fn test_rs256_rejects_invalid_public_pem() {
	payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	token := Token.new_with_options(payload, Rs256SigningOptions{private_key_pem: jwt.rsa_private_key})!

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

fn test_valid_hs256_and_valid_rs256_helpers() {
	hs_payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	hs_token := Token.new_hs256(hs_payload, jwt.secret)
	assert hs_token.valid_hs256(jwt.secret)
	assert !hs_token.valid_rs256(jwt.rsa_public_key)

	rs_payload := Payload[map[string]string]{
		sub: '1234567890'
		ext: jwt.claims
	}
	rs_token := Token.new_rs256(rs_payload, jwt.rsa_private_key)
	assert rs_token.valid_rs256(jwt.rsa_public_key)
	assert !rs_token.valid_hs256(jwt.secret)
}
