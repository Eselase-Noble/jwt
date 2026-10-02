# JWE design notes (planned for 0.3.0)

This captures the plan for encrypted tokens (JSON Web Encryption, RFC 7516/7518) so
the work is ready to pick up. It is not implemented yet. The goal is a secure,
correct subset rather than every algorithm the spec allows.

## Scope for the first cut

Content encryption (the `enc` header), all AEAD via the JDK:

- `A128GCM`, `A192GCM`, `A256GCM` (AES-GCM). 96-bit IV, 128-bit tag.

Key management (the `alg` header):

- `dir`: a shared symmetric key is used directly as the content encryption key (CEK). No wrapped key. Good for service-to-service with a shared secret.
- `RSA-OAEP-256`: a random CEK is wrapped with an RSA public key and unwrapped with the private key. Good for public-key encryption.

Out of scope for the first cut (add later if needed): `ECDH-ES`, AES key wrap (`A128KW`/`A256KW`), AES-CBC-HMAC `enc` methods, and PBES2.

## Compact serialization

Five Base64URL parts:

```
BASE64URL(protected header) . BASE64URL(encrypted key) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
```

For `dir`, the encrypted-key segment is empty. The protected header is the AES-GCM
additional authenticated data (AAD), so tampering with it fails decryption.

## Proposed API (mirrors the signing API)

Encrypt claims (confidentiality only):

```java
String jwe = Nobleson.encrypter()
        .subject("user-123")
        .claim("ssn", "...")
        .expiresIn(Duration.ofMinutes(5))
        .encryptWith(Encryption.dir(aesKey), EncryptionMethod.A256GCM)
        .generate();

Jwt jwt = Nobleson.decrypter()
        .decryptWith(Encryption.dir(aesKey))
        .parse(jwe);
```

Public-key variant: `Encryption.rsaOaep256(publicKey)` to encrypt, `Encryption.rsaOaep256(privateKey)` to decrypt.

## The important security point: encryption is not authentication

A JWE gives confidentiality and content integrity, but not sender authenticity:

- With `dir`, anyone holding the shared key can mint a token.
- With `RSA-OAEP-256`, anyone holding the public key can encrypt a token.

When you need both authenticity and confidentiality, use the nested pattern:
sign first, then encrypt the signed token.

```java
String signed = Nobleson.builder().subject("user").signWith(Algorithms.rs256(priv)).generate();
String jwe    = Nobleson.encrypter().content(signed)         // sets cty=JWT
                        .encryptWith(Encryption.rsaOaep256(pub), EncryptionMethod.A256GCM)
                        .generate();

String inner = Nobleson.decrypter().decryptWith(Encryption.rsaOaep256(priv)).decryptToString(jwe);
Jwt jwt      = Nobleson.parser().verifyWith(Algorithms.rs256(pub2)).parse(inner);
```

The README will lead with the nested pattern for anything carrying a trust decision.

## Implementation checklist

- `io.nobleson.jwt.jwe`
  - `EncryptionMethod` enum (name, CEK byte length).
  - `Encryption` sealed type with factories `dir`, `rsaOaep256(public/private/KeyPair)`.
    - `DirectEncryption`: CEK is the provided key; reject a key whose length does not match the `enc`.
    - `RsaOaepEncryption`: use `OAEPParameterSpec` with SHA-256 and MGF1-SHA-256 explicitly (the `"...OAEPWithSHA-256AndMGF1Padding"` string defaults MGF1 to SHA-1 on some providers, which would be wrong for RSA-OAEP-256).
  - `AesGcm` helper: encrypt/decrypt with CEK, IV, and AAD.
- `JweBuilder` (claim setters shared in spirit with `JwtBuilder`, plus `content(...)` for nested and `encryptWith(enc, method)`).
- `JweParser` (`decryptWith`, `clockSkew`, `parse` to `Jwt` for claim payloads, `decryptToString` for nested). Reject a header `alg` that does not match the configured key. Read `enc` from the header and map it to a supported method.
- `Nobleson.encrypter()` / `Nobleson.decrypter()`.
- `JweException extends JwtException` for decryption and crypto failures.
- `Keys.aesKey(int bits)` for generating a direct-mode key.

## Tests to write

- Round trip for `dir` with A128/192/256GCM, and for `RSA-OAEP-256`.
- Wrong key fails decryption; wrong-length `dir` key fails on encrypt.
- Tampered ciphertext and tampered header (AAD) both fail the auth tag.
- `alg` mismatch between token and configured key is rejected.
- Nested sign-then-encrypt: decrypt to the inner token, then verify it.
- `exp` on an encrypted claim payload is enforced.

## Release

Land on `main` as `0.3.0-SNAPSHOT`, document in the README (new section plus roadmap
move), then `mvn clean deploy -Prelease` and tag `v0.3.0` when ready.
