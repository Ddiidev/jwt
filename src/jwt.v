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
	payload_b64 string
	signature string
pub:
	payload Payload[T]
}

fn sign_hs256(message string, secret string) string {
	return base64.url_encode(hmac.new(secret.bytes(), message.bytes(), sha256.sum, sha256.block_size).bytestr().bytes())
}

fn verify_hs256(message string, signature string, secret string) bool {
	return sign_hs256(message, secret) == signature
}

fn sign_rs256(message string, private_key_pem string) !string {
	_ := message
	_ := private_key_pem
	return error('RS256 signing is not supported in this build')
}

fn verify_rs256(message string, signature string, public_key_pem string) !bool {
	_ := message
	_ := signature
	_ := public_key_pem
	return error('RS256 verification is not supported in this build')
}

fn sign_by_alg(alg string, message string, key string) !string {
	return match alg {
		'HS256' { sign_hs256(message, key) }
		'RS256' { sign_rs256(message, key)! }
		else { return error('Unsupported algorithm: ${alg}') }
	}
}

fn verify_by_alg(alg string, message string, signature string, key string) !bool {
	return match alg {
		'HS256' { verify_hs256(message, signature, key) }
		'RS256' { verify_rs256(message, signature, key)! }
		else { return error('Unsupported algorithm: ${alg}') }
	}
}

fn header_alg(header string) !string {
	header_json := base64.url_decode_str(header)
	return json.decode(Header, header_json)!.alg
}

pub fn Token.new[T](payload Payload[T], secret string) Token[T] {
	header_obj := Header{}
	header := base64.url_encode(json.encode(header_obj).bytes())
	payload_b64 := base64.url_encode(json.encode(payload).bytes())
	message := '${header}.${payload_b64}'
	signature := sign_by_alg(header_obj.alg, message, secret) or { panic(err) }
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
		payload_b64: payload_b64
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
		payload_b64: parts[1]
		payload: json.decode(Payload[T], base64.url_decode_str(parts[1]))!
		signature: parts[2]
	}
}

fn (t Token[T]) payload_segment() string {
	if t.payload_b64.len > 0 {
		return t.payload_b64
	}

	return base64.url_encode(json.encode(t.payload).bytes())
}

pub fn (t Token[T]) str() string {
	return t.header + '.' + t.payload_segment() + '.' + t.signature
}

pub fn (t Token[T]) valid(secret string) bool {
	return t.valid_with_options(SigningOptions{alg: .hs256, key_material: secret})
}

pub fn (t Token[T]) valid_with_options(options SigningOptions) bool {
	if t.expired() {
		return false
	}

	if t.header.len == 0 || t.signature.len == 0 {
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
