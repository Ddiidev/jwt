module jwt

#flag linux -lssl -lcrypto
#flag darwin -lssl -lcrypto
#flag freebsd -lssl -lcrypto
#flag windows -lssl -lcrypto
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

@[typedef]
struct C.BIO {}

@[typedef]
struct C.RSA {}

fn C.BIO_new_mem_buf(buf voidptr, len int) &C.BIO
fn C.BIO_free(bio &C.BIO) int
fn C.ERR_get_error() u64
fn C.ERR_error_string_n(e u64, buf &u8, len usize)
fn C.PEM_read_bio_RSAPrivateKey(bp &C.BIO, x &&C.RSA, cb voidptr, u voidptr) &C.RSA
fn C.PEM_read_bio_RSAPublicKey(bp &C.BIO, x &&C.RSA, cb voidptr, u voidptr) &C.RSA
fn C.PEM_read_bio_RSA_PUBKEY(bp &C.BIO, x &&C.RSA, cb voidptr, u voidptr) &C.RSA
fn C.RSA_free(rsa &C.RSA)
fn C.RSA_size(rsa &C.RSA) int
fn C.RSA_sign(type_ int, m &u8, m_len u32, sigret &u8, siglen &u32, rsa &C.RSA) int
fn C.RSA_verify(type_ int, m &u8, m_len u32, sigbuf &u8, siglen u32, rsa &C.RSA) int
fn C.SHA256(d &u8, n usize, md &u8) &u8

fn openssl_error(message string) IError {
	err_code := C.ERR_get_error()
	if err_code == 0 {
		return error(message)
	}

	mut buf := []u8{len: 256, init: 0}
	unsafe {
		C.ERR_error_string_n(err_code, &buf[0], buf.len)
	}
	details := unsafe { (&char(&buf[0])).vstring() }
	return error('${message}: ${details}')
}

fn validate_private_key_pem_format(private_key_pem string) ! {
	trimmed := private_key_pem.trim_space()
	if trimmed.len == 0 {
		return error('RS256 signing failed: PEM private key cannot be empty')
	}

	has_pkcs1 := trimmed.contains('-----BEGIN RSA PRIVATE KEY-----')
	has_pkcs8 := trimmed.contains('-----BEGIN PRIVATE KEY-----')
	if !has_pkcs1 && !has_pkcs8 {
		return error('RS256 signing failed: invalid PEM private key format (expected BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)')
	}

	if has_pkcs1 && !trimmed.contains('-----END RSA PRIVATE KEY-----') {
		return error('RS256 signing failed: invalid PEM private key format (missing END RSA PRIVATE KEY marker)')
	}

	if has_pkcs8 && !trimmed.contains('-----END PRIVATE KEY-----') {
		return error('RS256 signing failed: invalid PEM private key format (missing END PRIVATE KEY marker)')
	}
}

fn validate_public_key_pem_format(public_key_pem string) !string {
	trimmed := public_key_pem.trim_space()
	if trimmed.len == 0 {
		return error('RS256 verification failed: PEM public key cannot be empty')
	}

	return trimmed
}

fn new_bio_from_pem(pem string) !&C.BIO {
	bio := C.BIO_new_mem_buf(pem.str, pem.len)
	if bio == unsafe { nil } {
		return openssl_error('unable to allocate OpenSSL BIO for PEM')
	}
	return bio
}

fn parse_rsa_private_key(private_key_pem string) !&C.RSA {
	mut bio := new_bio_from_pem(private_key_pem)!
	defer {
		C.BIO_free(bio)
	}

	mut rsa := C.PEM_read_bio_RSAPrivateKey(bio, unsafe { nil }, unsafe { nil }, unsafe { nil })
	if rsa != unsafe { nil } {
		return rsa
	}

	return openssl_error('RS256 signing failed: unable to parse PEM private key')
}

fn parse_rsa_public_key(public_key_pem string) !&C.RSA {
	mut primary_bio := new_bio_from_pem(public_key_pem)!
	defer {
		C.BIO_free(primary_bio)
	}

	mut rsa := C.PEM_read_bio_RSA_PUBKEY(primary_bio, unsafe { nil }, unsafe { nil },
		unsafe { nil })
	if rsa != unsafe { nil } {
		return rsa
	}

	mut fallback_bio := new_bio_from_pem(public_key_pem)!
	defer {
		C.BIO_free(fallback_bio)
	}

	rsa = C.PEM_read_bio_RSAPublicKey(fallback_bio, unsafe { nil }, unsafe { nil }, unsafe { nil })
	if rsa == unsafe { nil } {
		return openssl_error('RS256 verification failed: unable to parse PEM public key (expected BEGIN PUBLIC KEY or BEGIN RSA PUBLIC KEY)')
	}

	return rsa
}

fn sha256_digest(input []u8) ![]u8 {
	mut digest := []u8{len: 32, init: 0}
	if C.SHA256(input.data, usize(input.len), digest.data) == unsafe { nil } {
		return openssl_error('unable to compute SHA-256 digest')
	}
	return digest
}

pub fn verify_rs256_signature(message string, signature []u8, public_key_pem string) !bool {
	trimmed_pem := validate_public_key_pem_format(public_key_pem)!
	rsa := parse_rsa_public_key(trimmed_pem)!
	defer {
		C.RSA_free(rsa)
	}

	digest := sha256_digest(message.bytes())!
	verify_result := C.RSA_verify(C.NID_sha256, digest.data, u32(digest.len), signature.data,
		u32(signature.len), rsa)
	return verify_result == 1
}

fn sign_rs256_bytes(message []u8, private_key_pem string) ![]u8 {
	trimmed_pem := private_key_pem.trim_space()
	validate_private_key_pem_format(trimmed_pem)!
	rsa := parse_rsa_private_key(trimmed_pem)!
	defer {
		C.RSA_free(rsa)
	}

	digest := sha256_digest(message)!
	rsa_size := C.RSA_size(rsa)
	if rsa_size <= 0 {
		return openssl_error('RS256 signing failed: unable to determine RSA signature size')
	}

	mut signature := []u8{len: rsa_size, init: 0}
	mut sig_len := u32(0)
	if C.RSA_sign(C.NID_sha256, digest.data, u32(digest.len), signature.data, &sig_len,
		rsa) != 1 {
		return openssl_error('RS256 signing failed: OpenSSL RSA signing operation failed')
	}

	return signature[..int(sig_len)]
}
