module jwt

import encoding.base64
import json
import crypto.hmac
import crypto.sha256
import time

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

pub fn (t Token[T]) str() string {
	return t.header + '.' + t.payload_b64 + '.' + t.signature
}

pub fn (t Token[T]) valid(secret string) bool {
	if t.expired() {
		return false
	}

	if t.header.len == 0 || t.payload_b64.len == 0 || t.signature.len == 0 {
		return false
	}

	alg := header_alg(t.header) or {
		return false
	}

	return verify_by_alg(alg, '${t.header}.${t.payload_b64}', t.signature, secret) or {
		false
	}
}

pub fn (t Token[T]) expired() bool {
	return t.payload.exp.time() or { return false } < time.now()
}
