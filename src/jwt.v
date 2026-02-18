module jwt

import crypto.hmac
import crypto.sha256
import encoding.base64
import json
import time

pub enum Algorithm {
	hs256
	rs256
}

pub fn (a Algorithm) jwt_name() string {
	return match a {
		.hs256 { 'HS256' }
		.rs256 { 'RS256' }
	}
}

pub fn algorithm_from_jwt_name(name string) !Algorithm {
	return match name {
		'HS256' { .hs256 }
		'RS256' { .rs256 }
		else { error('Unsupported algorithm: ${name}') }
	}
}

pub struct Hs256SigningOptions {
pub:
	secret string
}

pub struct Rs256SigningOptions {
pub:
	private_key_pem string
}

pub type SigningOptions = Hs256SigningOptions | Rs256SigningOptions

pub struct Hs256ValidationOptions {
pub:
	secret string
}

pub struct Rs256ValidationOptions {
pub:
	public_key_pem string
}

pub type ValidationOptions = Hs256ValidationOptions | Rs256ValidationOptions

pub struct Token[T] {
	header      string
	payload_b64 string
	signature   string
pub:
	payload Payload[T]
}

pub fn Token.new[T](payload Payload[T], secret string) Token[T] {
	return Token.new_hs256[T](payload, secret)
}

pub fn Token.new_hs256[T](payload Payload[T], secret string) Token[T] {
	return Token.new_with_options[T](payload, Hs256SigningOptions{ secret: secret }) or {
		panic(err.msg())
	}
}

pub fn Token.new_rs256[T](payload Payload[T], private_key_pem string) Token[T] {
	return Token.new_with_options[T](payload, Rs256SigningOptions{ private_key_pem: private_key_pem }) or {
		panic(err.msg())
	}
}

pub fn Token.new_with_options[T](payload Payload[T], options SigningOptions) !Token[T] {
	header := b64url_encode_no_padding(json.encode(new_header(HeaderOptions{
		alg: signing_algorithm(options)
	})).bytes())
	payload_b64 := b64url_encode_no_padding(json.encode(payload).bytes())
	signature := sign_payload(options, '${header}.${payload_b64}')!

	return Token[T]{
		header:      header
		payload_b64: payload_b64
		payload:     payload
		signature:   signature
	}
}

pub fn from_str[T](token string) !Token[T] {
	parts := token.split('.')
	if parts.len != 3 {
		return error('Invalid token')
	}

	return Token[T]{
		header:      parts[0]
		payload_b64: parts[1]
		payload:     json.decode(Payload[T], base64.url_decode_str(parts[1]))!
		signature:   parts[2]
	}
}

fn (t Token[T]) payload_segment() string {
	if t.payload_b64.len > 0 {
		return t.payload_b64
	}

	return b64url_encode_no_padding(json.encode(t.payload).bytes())
}

pub fn (t Token[T]) str() string {
	return t.header + '.' + t.payload_segment() + '.' + t.signature
}

pub fn (t Token[T]) valid(secret string) bool {
	return t.valid_hs256(secret)
}

pub fn (t Token[T]) valid_hs256(secret string) bool {
	return t.valid_with_options(Hs256ValidationOptions{ secret: secret })
}

pub fn (t Token[T]) valid_rs256(public_key_pem string) bool {
	return t.valid_with_options(Rs256ValidationOptions{ public_key_pem: public_key_pem })
}

pub fn (t Token[T]) valid_with_options(options ValidationOptions) bool {
	if t.expired() {
		return false
	}

	parts := t.str().split('.')
	if parts.len != 3 {
		return false
	}

	header := json.decode(Header, base64.url_decode_str(parts[0])) or { return false }
	header_alg := algorithm_from_jwt_name(header.alg) or { return false }
	if header_alg != validation_algorithm(options) {
		return false
	}

	message := '${parts[0]}.${parts[1]}'
	return match options {
		Hs256ValidationOptions {
			expected_signature := sign_hs256(message, options.secret)
			parts[2] == expected_signature
		}
		Rs256ValidationOptions {
			signature := b64url_decode_with_padding(parts[2])
			verify_rs256_signature(message, signature, options.public_key_pem) or { return false }
		}
	}
}

pub fn (t Token[T]) expired() bool {
	return t.payload.exp_time() or { return false } < time.now()
}

fn signing_algorithm(options SigningOptions) Algorithm {
	return match options {
		Hs256SigningOptions { .hs256 }
		Rs256SigningOptions { .rs256 }
	}
}

fn validation_algorithm(options ValidationOptions) Algorithm {
	return match options {
		Hs256ValidationOptions { .hs256 }
		Rs256ValidationOptions { .rs256 }
	}
}

fn b64url_decode_with_padding(value string) []u8 {
	mut padded := value
	rem := value.len % 4
	if rem > 0 {
		padded += '='.repeat(4 - rem)
	}
	return base64.url_decode(padded)
}

fn b64url_encode_no_padding(data []u8) string {
	return base64.url_encode(data).trim_right('=')
}

fn sign_hs256(value string, secret string) string {
	return b64url_encode_no_padding(hmac.new(secret.bytes(), value.bytes(), sha256.sum,
		sha256.block_size).bytestr().bytes())
}

fn sign_payload(options SigningOptions, value string) !string {
	return match options {
		Hs256SigningOptions {
			sign_hs256(value, options.secret)
		}
		Rs256SigningOptions {
			signed := sign_rs256_bytes(value.bytes(), options.private_key_pem)!
			b64url_encode_no_padding(signed)
		}
	}
}
