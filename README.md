# Nobleson

**JWT for Java, without the ceremony.**

Working with JSON Web Tokens in Java usually means stitching together Base64URL
encoding, a JSON library, the `javax.crypto` / `java.security` signing APIs, and
a pile of manual checks for expiry, issuer, and audience. Python has `PyJWT` and
JavaScript has `jsonwebtoken` — one call and you're done. Nobleson brings that
same feeling to Java: build a token, sign it, verify it, all in a single fluent
chain, with the security defaults already in place.

```java
String token = Nobleson.builder()
        .subject("user-123")
        .issuer("my-app")
        .claim("role", "admin")
        .issuedNow()
        .expiresIn(Duration.ofHours(1))
        .signWith(Algorithms.hs256(secret))
        .generate();
```

That's a complete, signed, expiring JWT.

---

## Table of contents

- [Why Nobleson](#why-nobleson)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Creating tokens](#creating-tokens)
- [Verifying tokens](#verifying-tokens)
- [Reading claims](#reading-claims)
- [Algorithms](#algorithms)
- [Generating keys](#generating-keys)
- [Error handling](#error-handling)
- [Using Nobleson in Spring Boot](#using-nobleson-in-spring-boot)
- [Security notes](#security-notes)
- [Requirements](#requirements)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why Nobleson

- **One chain to a token.** No helper classes to wire up, no builders inside
  builders. Set your claims, say how to sign, call `.generate()`.
- **Safe by default.** The parser rejects algorithm-confusion attacks, checks
  `exp` / `nbf` for you, and compares HMAC signatures in constant time. There is
  no `none` algorithm — on purpose.
- **Every common algorithm.** HMAC, RSA, and ECDSA, in the 256/384/512 flavours.
- **Small surface.** A handful of classes you can learn in a sitting. The only
  runtime dependency is Jackson for JSON.

## Installation

Nobleson is a standard Maven artifact. Add it to your `pom.xml`:

```xml
<dependency>
    <groupId>io.nobleson</groupId>
    <artifactId>nobleson-jwt</artifactId>
    <version>0.1.0</version>
</dependency>
```

Using Gradle:

```groovy
implementation 'io.nobleson:nobleson-jwt:0.1.0'
```

## Quick start

```java
import io.nobleson.jwt.Nobleson;
import io.nobleson.jwt.Jwt;
import io.nobleson.jwt.Keys;
import io.nobleson.jwt.algorithm.Algorithms;

import javax.crypto.SecretKey;
import java.time.Duration;

// A signing key. In production, load a stable secret from config — don't
// generate a fresh one on every start, or yesterday's tokens stop verifying.
SecretKey secret = Keys.hmacSecret();

// Create
String token = Nobleson.builder()
        .subject("user-123")
        .expiresIn(Duration.ofHours(1))
        .signWith(Algorithms.hs256(secret.getEncoded()))
        .generate();

// Verify
Jwt jwt = Nobleson.parser()
        .verifyWith(Algorithms.hs256(secret.getEncoded()))
        .parse(token);

System.out.println(jwt.subject()); // user-123
```

## Creating tokens

Start from `Nobleson.builder()`. Registered claims have their own methods;
anything else goes through `claim(name, value)`.

```java
String token = Nobleson.builder()
        .issuer("my-app")                       // iss
        .subject("user-123")                    // sub
        .audience("my-api")                     // aud
        .id("f1e2d3c4")                         // jti
        .issuedNow()                            // iat = now
        .notBefore(Instant.now())               // nbf
        .expiresIn(Duration.ofMinutes(15))      // exp = now + 15m
        .claim("role", "admin")                 // custom claim
        .claim("scopes", List.of("read", "write"))
        .keyId("2024-signing-key")              // kid header
        .signWith(Algorithms.hs256(secret))
        .generate();
```

- `issuedNow()` sets `iat` to the current instant.
- `expiresIn(Duration)` sets `exp` relative to now; `expiration(Instant)` sets it absolutely.
- `claim(name, null)` removes a claim.
- `signWith(...)` is required — calling `generate()` without it throws.

## Verifying tokens

Start from `Nobleson.parser()`. The verifying algorithm is required; everything
else is optional.

```java
Jwt jwt = Nobleson.parser()
        .verifyWith(Algorithms.hs256(secret))
        .requireIssuer("my-app")
        .requireAudience("my-api")
        .require("role", "admin")               // any claim, any value
        .clockSkew(Duration.ofSeconds(30))      // tolerate minor clock drift
        .parse(token);
```

`parse(...)` runs these checks in order and throws on the first failure:

1. The token has three Base64URL parts that decode to JSON — else `MalformedJwtException`.
2. The header `alg` equals the verifier's algorithm — else `SignatureException`.
3. The signature matches — else `SignatureException`.
4. `exp` is not in the past and `nbf` is not in the future, within `clockSkew` —
   else `ExpiredJwtException` / `PrematureJwtException`.
5. Every `require(...)` expectation holds — else `InvalidClaimException`.

If `parse` returns, the token is trustworthy.

## Reading claims

```java
Jwt jwt = Nobleson.parser().verifyWith(alg).parse(token);

// Registered claims, typed.
String  sub = jwt.subject();
String  iss = jwt.issuer();
Instant exp = jwt.claims().expiration();

// Custom claims, typed by you.
String role = jwt.claims().get("role", String.class);
Integer n   = jwt.claims().get("count", Integer.class);

// Everything, raw.
Map<String, Object> all = jwt.claims().asMap();

// Header fields.
String kid = jwt.header().keyId();
```

Date claims (`exp`, `nbf`, `iat`) are stored as seconds since the epoch per the
spec and handed back as `Instant`.

## Algorithms

Pick an algorithm from `Algorithms`. The same factory serves signing and
verifying — pass a secret or private key to sign, a public key to verify.

| Family | Methods                       | Key type            |
|--------|-------------------------------|---------------------|
| HMAC   | `hs256` `hs384` `hs512`       | shared secret (`byte[]` or `String`) |
| RSA    | `rs256` `rs384` `rs512`       | `KeyPair` / `PrivateKey` / `PublicKey` |
| ECDSA  | `es256` `es384` `es512`       | `KeyPair` / `PrivateKey` / `PublicKey` |

```java
// HMAC — one shared secret signs and verifies.
Algorithm hmac = Algorithms.hs256("a-long-shared-secret");

// RSA / EC — sign with the private key, verify with the public key.
KeyPair pair = Keys.rsaKeyPair();
String token = Nobleson.builder().subject("u").signWith(Algorithms.rs256(pair.getPrivate())).generate();
Jwt jwt      = Nobleson.parser().verifyWith(Algorithms.rs256(pair.getPublic())).parse(token);
```

For ECDSA, Nobleson transparently converts between the JDK's DER signature
encoding and the `R || S` form the JWT spec requires (RFC 7518 §3.4), so ES256/
384/512 tokens interoperate with other compliant libraries.

## Generating keys

Need a key and don't have one yet? `Keys` makes strong ones in a single call.

```java
SecretKey secret = Keys.hmacSecret();          // 256-bit, for HS256
SecretKey big    = Keys.hmacSecret(512);        // for HS512

KeyPair rsa      = Keys.rsaKeyPair();           // 2048-bit, for RS*
KeyPair ec256    = Keys.ecKeyPair();            // P-256, for ES256
KeyPair ec512    = Keys.ecKeyPair("secp521r1"); // P-521, for ES512
```

Generate keys once and store them. A key minted at startup only verifies tokens
from that same run.

## Error handling

Every failure is an unchecked exception under `io.nobleson.jwt.exception`. Catch
the base type for a blanket "invalid token", or a specific type when you want to
react differently.

```java
import io.nobleson.jwt.exception.*;

try {
    Jwt jwt = Nobleson.parser().verifyWith(alg).parse(token);
    // ... trusted ...
} catch (ExpiredJwtException e) {
    // prompt a refresh
} catch (JwtException e) {
    // malformed, bad signature, wrong claim — reject
}
```

| Exception                | Meaning                                            |
|--------------------------|----------------------------------------------------|
| `MalformedJwtException`  | Not three parts, bad Base64URL, or bad JSON        |
| `SignatureException`     | Signature mismatch, or `alg` doesn't match verifier |
| `ExpiredJwtException`    | `exp` is in the past                               |
| `PrematureJwtException`  | `nbf` is in the future                             |
| `InvalidClaimException`  | A `require(...)` expectation failed                |
| `JwtException`           | Base type of all of the above                      |

## Security notes

- **No `none` algorithm.** Unsigned tokens are a classic footgun; Nobleson simply
  doesn't offer them.
- **Algorithm confusion is blocked.** The parser insists the token's `alg` header
  matches the algorithm you chose to verify with, so an attacker can't hand you an
  HMAC token signed with your public RSA key as the secret.
- **Constant-time HMAC comparison** via `MessageDigest.isEqual`, so signature
  checks don't leak timing information.
- **Pick keys to match.** Use a secret of at least the hash length for HMAC
  (≥ 256 bits for HS256), ≥ 2048-bit RSA, and the matching curve for EC.
- **Always set `exp`.** Short-lived tokens limit the blast radius of a leak.

## Using Nobleson in Spring Boot

Nobleson is a plain Maven jar with no servlet dependency, so it drops into any
Spring or Spring Boot project without conflicts — and the same artifact works on
**Spring Boot 2** (`javax.servlet`) and **Spring Boot 3** (`jakarta.servlet`);
just match the import to your version. Here is the whole JWT setup for a stateless
REST API — a token service and a short filter, instead of a pile of boilerplate.

**1. Expose the algorithm as a bean** (secret comes from `application.yml`):

```java
@Configuration
public class JwtConfig {

    @Bean
    public Algorithm jwtAlgorithm(@Value("${app.jwt.secret}") String secret) {
        return Algorithms.hs256(secret);   // swap for rs256(...) to use RSA keys
    }
}
```

```yaml
# application.yml
app:
  jwt:
    secret: ${JWT_SECRET:change-me-to-a-long-random-value}
```

**2. A service to issue and verify tokens:**

```java
@Service
public class JwtService {

    private final Algorithm algorithm;

    public JwtService(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String issue(String username, Collection<String> roles) {
        return Nobleson.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedNow()
                .expiresIn(Duration.ofHours(1))
                .signWith(algorithm)
                .generate();
    }

    public Jwt verify(String token) {
        return Nobleson.parser().verifyWith(algorithm).parse(token);
    }
}
```

**3. A filter that authenticates the request** — this is the piece that usually
sprawls. With Nobleson it's a few lines (Spring Boot 3 / `jakarta` imports shown):

```java
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwt;

    public JwtAuthFilter(JwtService jwt) {
        this.jwt = jwt;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            try {
                Jwt token = jwt.verify(header.substring(7));

                @SuppressWarnings("unchecked")
                List<String> roles = token.claims().get("roles", List.class);
                var authorities = (roles == null ? List.<String>of() : roles).stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                var auth = new UsernamePasswordAuthenticationToken(
                        token.subject(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (JwtException e) {
                // Invalid/expired token: stay unauthenticated; the chain returns 401/403.
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }
}
```

**4. Wire it into the security chain:**

```java
@Bean
public SecurityFilterChain security(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
    return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/**").permitAll()
                    .anyRequest().authenticated())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
}
```

That's the entire integration. Your login endpoint calls `jwtService.issue(...)`,
every other endpoint is protected automatically, and `@PreAuthorize("hasRole('ADMIN')")`
works off the roles claim.

> **Spring Boot 2?** Use the same code with `javax.servlet.*` imports instead of
> `jakarta.servlet.*`. The Nobleson side is identical.

## Requirements

- Java 17 or newer.
- Jackson (`jackson-databind`), pulled in transitively — it's already on most
  classpaths.

## Roadmap

Planned for later releases:

- Encrypted tokens (JWE).
- JWK / JWKS parsing and remote key sets.
- RSA-PSS (`PS256` / `PS384` / `PS512`).

## License

Apache License 2.0.
