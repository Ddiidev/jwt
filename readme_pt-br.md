# JWT
Simple JWT implementation for V.

![English](https://flagcdn.com/w20/us.webp) [Read in English](./readme.md)

> Note: **HS256** flow and payload parsing/validation are self-contained. **RS256** flow depends on OpenSSL in the environment.

This library supports:
- **HS256** (HMAC + SHA-256)
- **RS256** (RSA + SHA-256)

## Instalação

No seu `v.mod`:

```v
Module {
	dependencies: ['https://github.com/Ddiidev/jwt']
}
```

Ou via VPM:

```bash
v install https://github.com/Ddiidev/jwt
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
v -cc gcc test src
```

Os testes de RS256 usam fixtures em `testdata/`.

No Windows, durante desenvolvimento, prefira usar sempre `gcc`:

```bash
v -cc gcc run seu_arquivo.v
v -cc gcc test src/custom_test.v
```

Se você encontrar erro de link relacionado a `GC_init` ao trocar compilador/flags, limpe o cache do V e rode novamente com `-cc gcc`.

## Limitações atuais

- **RS256 requer OpenSSL**: headers, libs e DLLs precisam estar disponíveis no ambiente.
- **Windows + tcc**: atualmente pode falhar na execução de testes com erro `0xC0000135` (DLL ausente). Em Linux costuma funcionar; no Windows, use `-cc gcc`.
- **Validação de claims é mínima**: a API `valid*` valida assinatura, algoritmo e `exp`; não valida regras semânticas de `iss`, `aud` e `sub`.
- **Sem suporte nativo a `nbf` e `jti`**: se necessário, trate essas regras em camada de aplicação.
- **Sem JWK/JWKS/kid**: o fluxo RS256 atual trabalha diretamente com PEM (chave privada/pública em texto).


## Claims para GitHub App (NumericDate)

Quando precisar gerar JWT para GitHub App, `iss` deve ser o App ID e `iat`/`exp` devem ser NumericDate (segundos desde epoch).

A `Payload[T]` agora aceita `iat` e `exp` como `i64` **ou** `string`, então você pode usar os segundos Unix diretamente:

```v
import time
import jwt

const app_id = '123456'

payload := jwt.Payload[map[string]string]{
	iss: app_id
	iat: time.now().unix()
	exp: time.now().add_seconds(540).unix()
	ext: {}
}

// Exemplo RS256
token := jwt.Token.new_rs256(payload, private_key_pem)
```
