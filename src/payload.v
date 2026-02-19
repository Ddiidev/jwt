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

fn parse_jstime_string(value string) ?time.Time {
	trimmed := value.trim_space()
	if trimmed.len == 0 {
		return none
	}

	looks_like_iso8601 := trimmed.contains('T')
	looks_like_utc_suffix := trimmed.ends_with('Z')
	looks_like_offset_suffix := trimmed.len >= 6 && trimmed[trimmed.len - 3] == `:`
		&& (trimmed[trimmed.len - 6] == `+` || trimmed[trimmed.len - 6] == `-`)
	if looks_like_iso8601 || looks_like_utc_suffix || looks_like_offset_suffix {
		if parsed_rfc3339 := time.parse_rfc3339(trimmed) {
			return parsed_rfc3339
		}
		if parsed_iso8601 := time.parse_iso8601(trimmed) {
			return parsed_iso8601
		}
	}

	// `time.parse` interprets naive timestamps as UTC; JWT exp strings in this project
	// are expected to be local wall clock values (same format as `time.now().str()`).
	parsed := time.parse(trimmed) or { return none }
	return parsed.as_local()
}

pub fn (jst JsTime) time() ?time.Time {
	return match jst {
		string {
			parse_jstime_string(jst)
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
