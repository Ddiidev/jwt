module jwt

#flag linux -lssl -lcrypto
#flag darwin -lssl -lcrypto
#flag freebsd -lssl -lcrypto
#flag windows -lssl -lcrypto
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

fn C.BIO_new_mem_buf(buf voidptr, len int) &C.BIO
fn C.BIO_free(bio &C.BIO) int
fn C.ERR_get_error() u64
fn C.ERR_error_string_n(e u64, buf &u8, len usize)
fn C.EVP_DigestSignFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen &usize) int
fn C.EVP_DigestSignInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, typ &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) int
fn C.EVP_DigestSignUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt usize) int
fn C.EVP_MD_CTX_free(ctx &C.EVP_MD_CTX)
fn C.EVP_MD_CTX_new() &C.EVP_MD_CTX
fn C.EVP_PKEY_free(pkey &C.EVP_PKEY)
fn C.EVP_PKEY_get0_RSA(pkey &C.EVP_PKEY) &C.RSA
fn C.EVP_sha256() &C.EVP_MD
fn C.PEM_read_bio_PrivateKey(bp &C.BIO, x &&C.EVP_PKEY, cb voidptr, u voidptr) &C.EVP_PKEY

fn openssl_error(message string) IError {
	err_code := C.ERR_get_error()
	if err_code == 0 {
		return error(message)
	}

	mut buf := []u8{len: 256, init: 0}
	C.ERR_error_string_n(err_code, &buf[0], buf.len)
	details := (&char(&buf[0])).vstring()
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

fn sign_rs256_bytes(message []u8, private_key_pem string) ![]u8 {
	trimmed_pem := private_key_pem.trim_space()
	validate_private_key_pem_format(trimmed_pem)!

	key_bio := C.BIO_new_mem_buf(trimmed_pem.str, trimmed_pem.len)
	if key_bio == unsafe { nil } {
		return openssl_error('RS256 signing failed: unable to allocate OpenSSL BIO for PEM')
	}
	defer {
		C.BIO_free(key_bio)
	}

	pkey := C.PEM_read_bio_PrivateKey(key_bio, unsafe { nil }, unsafe { nil }, unsafe { nil })
	if pkey == unsafe { nil } {
		return openssl_error('RS256 signing failed: unable to parse PEM private key')
	}
	defer {
		C.EVP_PKEY_free(pkey)
	}

	if C.EVP_PKEY_get0_RSA(pkey) == unsafe { nil } {
		return error('RS256 signing failed: PEM key is not an RSA private key')
	}

	ctx := C.EVP_MD_CTX_new()
	if ctx == unsafe { nil } {
		return openssl_error('RS256 signing failed: unable to allocate OpenSSL digest context')
	}
	defer {
		C.EVP_MD_CTX_free(ctx)
	}

	if C.EVP_DigestSignInit(ctx, unsafe { nil }, C.EVP_sha256(), unsafe { nil }, pkey) != 1 {
		return openssl_error('RS256 signing failed: unable to initialize RSA-SHA256 signer')
	}

	if C.EVP_DigestSignUpdate(ctx, message.data, message.len) != 1 {
		return openssl_error('RS256 signing failed: unable to hash JWT signing input')
	}

	mut sig_len := usize(0)
	if C.EVP_DigestSignFinal(ctx, unsafe { nil }, &sig_len) != 1 {
		return openssl_error('RS256 signing failed: unable to determine signature size')
	}

	mut signature := []u8{len: int(sig_len)}
	if C.EVP_DigestSignFinal(ctx, signature.data, &sig_len) != 1 {
		return openssl_error('RS256 signing failed: OpenSSL RSA signing operation failed')
	}

	return signature[..int(sig_len)]
}
