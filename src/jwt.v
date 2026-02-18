module jwt

import encoding.base64
import json
import crypto.hmac
import crypto.sha256
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

pub struct SigningOptions {
pub:
	alg          Algorithm = .hs256
	key_material string
}

pub struct Token[T] {
	header    string
	signature string
pub:
	payload Payload[T]
}

pub fn Token.new[T](payload Payload[T], secret string) Token[T] {
	return Token.new_hs256(payload, secret)
}

pub fn Token.new_hs256[T](payload Payload[T], secret string) Token[T] {
	return Token.new_with_options(payload, SigningOptions{alg: .hs256, key_material: secret}) or {
		panic(err.msg())
	}
}

pub fn Token.new_with_options[T](payload Payload[T], options SigningOptions) !Token[T] {
	header := base64.url_encode(json.encode(new_header(HeaderOptions{alg: options.alg})).bytes())
	payload_string := base64.url_encode(json.encode(payload).bytes())
	signature := sign_payload(options.alg, options.key_material, '${header}.${payload_string}')!

	return Token[T]{
		header: header
		payload: payload
		signature: signature
	}
}

pub fn from_str[T](token string) !Token[T] {
	parts := token.split('.')
	if parts.len != 3 {
		return error('Invalid token')
	}

	return Token[T]{
		header: parts[0]
		payload: json.decode(Payload[T], base64.url_decode_str(parts[1]))!
		signature: parts[2]
	}
}

pub fn (t Token[T]) str() string {
	payload := base64.url_encode(json.encode(t.payload).bytes())
	return t.header + '.' + payload + '.' + t.signature
}

pub fn (t Token[T]) valid(secret string) bool {
	return t.valid_with_options(SigningOptions{alg: .hs256, key_material: secret})
}

pub fn (t Token[T]) valid_with_options(options SigningOptions) bool {
	if t.expired() {
		return false
	}

	parts := t.str().split('.')
	if parts.len != 3 {
		return false
	}

	header := json.decode(Header, base64.url_decode_str(parts[0])) or { return false }
	header_alg := algorithm_from_jwt_name(header.alg) or { return false }
	if header_alg != options.alg {
		return false
	}

	expected_signature := sign_payload(options.alg, options.key_material, '${parts[0]}.${parts[1]}') or {
		return false
	}

	return parts[2] == expected_signature
}

pub fn (t Token[T]) expired() bool {
	return t.payload.exp.time() or { return false } < time.now()
}

fn sign_payload(alg Algorithm, key_material string, value string) !string {
	return match alg {
		.hs256 {
			base64.url_encode(hmac.new(key_material.bytes(), value.bytes(), sha256.sum, sha256.block_size).bytestr().bytes())
		}
		.rs256 {
			error('RS256 signing is not implemented yet')
		}
	}
}
