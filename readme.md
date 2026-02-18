# JWT
Simple and self-contained JWT implementation for V.

This library supports:
- **HS256** (HMAC + SHA-256)
- **RS256** (RSA + SHA-256)

## Instalação

No seu `v.mod`:

```v
Module {
	dependencies: ['jwt']
}
```

Ou via VPM:

```bash
v install jwt
```

## Uso simples (compatível com versão anterior, HS256)

Esse é o mesmo estilo de uso que já existia antes:

```v
import jwt

const secret = 'secret-key'

pub struct Credential {
	user string
	pass string
}

fn main() {
	payload := jwt.Payload[Credential]{
		sub: '1234567890'
		ext: Credential{
			user: 'splashsky'
			pass: 'password'
		}
	}

	// API simples (legada/compatível)
	token := jwt.Token.new(payload, secret)
	token_str := token.str()

	parsed := jwt.from_str[Credential](token_str)!
	if parsed.valid(secret) {
		println('token HS256 válido')
	}
}
```

## Exemplo prático com RS256

Para RS256, assine com **chave privada PEM** e valide com **chave pública PEM**:

```v
import os
import jwt

pub struct Claims {
	role string
}

fn main() {
	private_key := os.read_file('private.pem')!
	public_key := os.read_file('public.pem')!

	payload := jwt.Payload[Claims]{
		sub: 'user-123'
		ext: Claims{role: 'admin'}
	}

	// Assina com RS256
	token := jwt.Token.new_rs256(payload, private_key)
	token_str := token.str()

	// Valida com chave pública
	parsed := jwt.from_str[Claims](token_str)!
	if parsed.valid_rs256(public_key) {
		println('token RS256 válido')
	}
}
```

## API por opções (recomendado)

Se quiser evitar qualquer ambiguidade de algoritmo, use a API explícita por opções:

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

## Claims e expiração

A struct `Payload[T]` suporta campos padrão JWT (`iss`, `sub`, `aud`, `exp`, `iat`) e claims customizadas em `ext`.

A validação (`valid*`) também verifica se o token está expirado (`exp`).

## Testes

```bash
v test .
```

Os testes de RS256 usam fixtures em `testdata/`.
