module jwt

pub struct Header {
pub:
	alg string
	typ string
}

pub struct HeaderOptions {
pub:
	alg Algorithm = .hs256
	typ string    = 'JWT'
}

pub fn new_header(opts HeaderOptions) Header {
	return Header{
		alg: opts.alg.jwt_name()
		typ: opts.typ
	}
}
