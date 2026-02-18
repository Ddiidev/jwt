module jwt

import time

pub type JsTime = i64 | string

pub struct Payload[T] {
pub:
	iss ?string @[omitempty]
	sub ?string @[omitempty]
	aud ?string @[omitempty]
	exp ?JsTime @[omitempty]
	iat ?JsTime @[omitempty]
	ext T       @[omitempty]
}

pub fn (jst JsTime) time() ?time.Time {
	return match jst {
		string {
			time.parse(jst) or { return none }
		}
		i64 {
			time.unix(jst)
		}
	}
}

pub fn (p Payload[T]) exp_time() ?time.Time {
	exp := p.exp or { return none }
	return exp.time()
}
