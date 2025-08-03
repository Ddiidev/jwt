module jwt

import time

type JsTime = string

pub struct Payload[T] {
pub:
	iss ?string @[omitempty]
	sub ?string @[omitempty]
	aud ?string @[omitempty]
	exp JsTime  @[omitempty]
	iat JsTime  @[omitempty]
	ext T       @[omitempty]
}

pub fn (jst JsTime) time() ?time.Time {
	return time.parse(jst) or { return none }
}
