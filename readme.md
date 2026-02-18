# JWT
A simple, self-contained module for making and verifying JWTs using HMAC SHA256. Built to be simple!

## Example
```v
import jwt

const secret = 'secret-key'

pub struct Credential {
	user string
	pass string
}

fn main() {
	// Create a new token
	payload := jwt.Payload[Credential]{
		sub: '1234567890'
		ext: Credential{
			user: 'splashsky'
			pass: 'password'
		}
	}
	token := jwt.Token.new(payload, secret)
	receive_token_from_web := token.str()

	// Validate a token from the web
	obj_token := jwt.from_str[Credential](receive_token_from_web)!
	if obj_token.valid_hs256(secret) {
		println('token valid!')
		dump(obj_token.payload.ext)
	}
}
```


## Algoritmos e credenciais

Use opções específicas por algoritmo para evitar ambiguidades:

```v
// Assinatura HS256
token_hs := jwt.Token.new_with_options(payload, jwt.Hs256SigningOptions{secret: secret})!

// Assinatura RS256
token_rs := jwt.Token.new_with_options(payload, jwt.Rs256SigningOptions{private_key_pem: private_key})!

// Validação HS256
ok_hs := token_hs.valid_with_options(jwt.Hs256ValidationOptions{secret: secret})

// Validação RS256
ok_rs := token_rs.valid_with_options(jwt.Rs256ValidationOptions{public_key_pem: public_key})
```
